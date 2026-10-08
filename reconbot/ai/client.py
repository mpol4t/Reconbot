from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import UTC, datetime
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .models import AIConfig, AIConnectionState, AIStatus, ChatMessage, ChatResponse
from .redaction import redact_provider_error_payload, redact_provider_error_text, redact_text
from .request_planner import (
    MAX_CHAT_ATTEMPTS,
    RUNTIME_CAPABILITY_DISCOVERY_TIMEOUT_SEC,
    classify_model_profile,
    reasoning_fields_from_metadata,
)


REASONING_WITHOUT_FINAL_TR = (
    "Model final cevap üretmedi.\n"
    "Seçili model cevabı reasoning/thinking alanına yazıyor, fakat final message.content boş döndü. "
    "ReconBot düşünme çıktısını chat cevabı olarak göstermez. Thinking/Reasoning kapatmayı, "
    "max output token artırmayı veya final content döndüren bir instruct model seçmeyi dene. "
    "Bu bir bağlantı hatası değil; model cevap formatı uyumsuzluğu olabilir."
)


class ResponseParserError(ValueError):
    def __init__(self, parser_reason: str, user_message: str, debug: dict[str, Any]) -> None:
        super().__init__(parser_reason)
        self.parser_reason = parser_reason
        self.user_message = user_message
        self.debug = debug


def _has_reasoning_content(message: dict[str, Any]) -> bool:
    for key in ("reasoning_content", "reasoning", "thinking", "thinking_content"):
        value = message.get(key)
        if isinstance(value, str) and value.strip():
            return True
        if isinstance(value, dict) and value:
            return True
        if isinstance(value, list) and value:
            return True
    return False


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for item in content:
        if isinstance(item, str):
            parts.append(item)
            continue
        if not isinstance(item, dict):
            continue
        text = item.get("text")
        if isinstance(text, str):
            parts.append(text)
            continue
        nested_content = item.get("content")
        if isinstance(nested_content, str):
            parts.append(nested_content)
    return "".join(parts)


def _provider_messages_for_diagnostics(payload: dict[str, Any]) -> list[dict[str, str]]:
    """Expose the actual final request messages without content masking."""
    result: list[dict[str, str]] = []
    messages = payload.get("messages") if isinstance(payload, dict) else None
    if not isinstance(messages, list):
        return result
    for item in messages:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "")
        content = item.get("content")
        if role not in {"system", "user", "assistant"} or not isinstance(content, str):
            continue
        result.append({"role": role, "content": content})
    return result


def _fold_system_messages(messages: list[ChatMessage]) -> list[ChatMessage]:
    system_parts = [message.content.strip() for message in messages if message.role == "system" and message.content.strip()]
    non_system = [message for message in messages if message.role != "system"]
    if not system_parts:
        return non_system

    instruction = ChatMessage(role="user", content="SYSTEM INSTRUCTIONS:\n" + "\n\n".join(system_parts))
    # Some local templates reject the system role but still require alternating
    # user/assistant messages. Keep the latest user's text byte-for-byte as the
    # final message instead of wrapping it inside compatibility instructions.
    if not non_system:
        return [instruction]
    first = non_system[0]
    if first.role == "assistant":
        return [instruction, *non_system]
    return [instruction, ChatMessage(role="assistant", content="Talimatlar alındı."), *non_system]


def _debug_fields(
    config: AIConfig,
    *,
    http_status: int = 0,
    endpoint_path: str = "",
    returned_model: str = "",
    finish_reason: str = "",
    has_message_content: bool = False,
    has_reasoning_content: bool = False,
    content_length: int = 0,
    parser_reason: str = "",
    request_id: str = "",
    provider_message: str = "",
    provider_error_type: str = "",
    provider_error_code: str = "",
    provider_error_param: str = "",
    http_400_category: str = "",
    provider_payload_fields: list[str] | None = None,
    reasoning_fields_sent: list[str] | None = None,
    provider_temperature: float | None = None,
) -> dict[str, Any]:
    return {
        "httpStatus": http_status,
        "endpointPath": endpoint_path,
        "requestedModel": config.model,
        "returnedModel": returned_model,
        "finishReason": finish_reason,
        "hasMessageContent": has_message_content,
        "hasReasoningContent": has_reasoning_content,
        "contentLength": content_length,
        "requestId": request_id,
        "parserReason": parser_reason,
        "providerMessage": redact_provider_error_text(provider_message)[:700],
        "providerErrorType": redact_provider_error_text(provider_error_type)[:200],
        "providerErrorCode": redact_provider_error_text(provider_error_code)[:200],
        "providerErrorParam": redact_provider_error_text(provider_error_param)[:200],
        "http400Category": http_400_category,
        "providerPayloadFields": provider_payload_fields or [],
        "reasoningFieldsSent": reasoning_fields_sent or [],
        "providerTemperature": config.temperature if provider_temperature is None else provider_temperature,
    }


def _checked_at() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _status(
    config: AIConfig,
    connection: AIConnectionState,
    user_message_tr: str,
    operator_action_tr: str,
    setup_hint_tr: str,
    can_chat: bool = False,
    available_models: list[str] | None = None,
    selected_model_available: bool | None = None,
    reason: str = "",
    endpoint_debug: dict[str, Any] | None = None,
) -> AIStatus:
    return AIStatus(
        enabled=config.enabled,
        provider=config.provider,
        baseUrl=config.baseUrl,
        model=config.model,
        connection=connection,
        ready=connection == "ready" and can_chat,
        can_chat=can_chat,
        user_message_tr=user_message_tr,
        operator_action_tr=operator_action_tr,
        setup_hint_tr=setup_hint_tr,
        checked_at=_checked_at(),
        available_models=available_models or [],
        effective_model=config.model,
        tested_model=config.model if connection == "ready" else "",
        selected_model_available=selected_model_available,
        reason=reason or connection,
        endpoint_debug=endpoint_debug or {},
    )


class OpenAICompatibleClient:
    def __init__(self, config: AIConfig) -> None:
        self.config = config
        self.model_metadata: dict[str, Any] = {}

    def set_model_metadata(self, metadata: dict[str, Any] | None) -> None:
        self.model_metadata = dict(metadata or {})

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self.config.apiKeyEnv:
            api_key = os.environ.get(self.config.apiKeyEnv, "")
            if api_key:
                headers["authorization"] = f"Bearer {api_key}"
        return headers

    def _classify_transport_error(self, error: BaseException) -> AIStatus:
        text = redact_text(str(error))
        lowered = text.lower()
        parsed_url = urllib.parse.urlparse(self.config.baseUrl)
        endpoint_label = parsed_url.netloc or self.config.baseUrl.rstrip("/")
        if isinstance(error, TimeoutError) or "timed out" in lowered or "timeout" in lowered:
            return _status(
                self.config,
                "timeout",
                "AI endpoint zaman aşımına uğradı. Model yükleniyor olabilir veya sistem yoğun olabilir.",
                "Biraz bekleyip Bağlantıyı Test Et butonuna tekrar bas. Gerekirse Settings > AI timeout değerini artır.",
                "Local server çalışıyor olabilir ama model yanıt vermiyor. LM Studio'da modelin tamamen yüklendiğini kontrol et.",
            )
        if "connection refused" in lowered or "connection reset" in lowered or "failed to establish" in lowered or "errno 61" in lowered:
            return _status(
                self.config,
                "endpoint_unreachable",
                f"{endpoint_label} üzerinde AI server çalışmıyor görünüyor. LM Studio Local Server'ı başlat.",
                "LM Studio veya OpenAI-compatible local server'ı başlat ve base URL değerini kontrol et.",
                "ReconBot normal çalışmaya devam eder; AI sohbeti için local modeli başlatman gerekir.",
            )
        return _status(
            self.config,
            "endpoint_unreachable",
            "Yerel AI endpoint'e ulaşılamıyor.",
            "Base URL ve local server durumunu kontrol et.",
            "LM Studio Local Server veya llama.cpp server başlatıldıktan sonra Bağlantıyı Test Et.",
        )

    def _http_json(
        self,
        path: str,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        timeout_sec: int | None = None,
    ) -> tuple[str, Any, int]:
        url = path if path.startswith(("http://", "https://")) else self.config.baseUrl.rstrip("/") + path
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            with urllib.request.urlopen(request, timeout=max(1, int(timeout_sec or self.config.timeout))) as response:
                raw = response.read().decode("utf-8", errors="replace")
                try:
                    return "ok", json.loads(raw) if raw else {}, int(response.status)
                except json.JSONDecodeError:
                    return "invalid_json", raw[:500], int(response.status)
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")[:700]
            return "http_error", redact_provider_error_payload(body), int(error.code)
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            return "transport_error", error, 0

    def _chat_payload(self, messages: list[ChatMessage], max_tokens: int | None = None, include_reasoning_controls: bool = True) -> dict[str, Any]:
        output_tokens = max(1, int(max_tokens if max_tokens is not None else self.config.maxOutputTokens))
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": [message.__dict__ for message in messages],
            "temperature": self.config.temperature,
            "max_tokens": output_tokens,
            "stream": False,
        }
        supported_reasoning_fields = reasoning_fields_from_metadata(self.config, self.model_metadata)
        if include_reasoning_controls and not self.config.disableReasoning:
            if "reasoning_effort" in supported_reasoning_fields:
                payload["reasoning_effort"] = "medium"
            if "reasoning" in supported_reasoning_fields:
                payload["reasoning"] = {
                    "enabled": True,
                    **({"max_tokens": self.config.maxReasoningTokens} if self.config.maxReasoningTokens > 0 else {}),
                }
        return payload

    def _lm_studio_models_url(self) -> str:
        parsed = urllib.parse.urlparse(self.config.baseUrl)
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/api/v1/models", "", "", ""))

    def discover_runtime_model_metadata(self) -> tuple[dict[str, Any], str]:
        kind, payload, _code = self._http_json(
            self._lm_studio_models_url(),
            timeout_sec=RUNTIME_CAPABILITY_DISCOVERY_TIMEOUT_SEC,
        )
        if kind != "ok":
            return {}, "lm_studio_runtime_unavailable"
        metadata = _match_lm_studio_runtime_model(payload, self.config.model)
        return metadata, str(metadata.get("contextMetadataSource") or "lm_studio_runtime_unavailable")

    def _parse_chat_response(self, parsed: Any, *, endpoint_path: str = "/chat/completions", http_status: int = 200) -> ChatResponse:
        returned_model = str(parsed.get("model") or self.config.model) if isinstance(parsed, dict) else self.config.model
        if not isinstance(parsed, dict):
            raise ResponseParserError(
                "non_object_response",
                "Endpoint OpenAI chat completions formatına uymayan cevap döndürdü.",
                _debug_fields(self.config, http_status=http_status, endpoint_path=endpoint_path, returned_model=returned_model, parser_reason="non_object_response"),
            )
        choices = parsed.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ResponseParserError(
                "missing_choices",
                "Endpoint OpenAI chat completions formatına uymayan cevap döndürdü.",
                _debug_fields(self.config, http_status=http_status, endpoint_path=endpoint_path, returned_model=returned_model, parser_reason="missing_choices"),
            )
        first_choice = choices[0]
        message = first_choice.get("message") if isinstance(first_choice, dict) else None
        if not isinstance(message, dict):
            raise ResponseParserError(
                "missing_message",
                "Endpoint OpenAI chat completions formatına uymayan cevap döndürdü.",
                _debug_fields(self.config, http_status=http_status, endpoint_path=endpoint_path, returned_model=returned_model, parser_reason="missing_message"),
            )
        finish_reason = str(first_choice.get("finish_reason") or "") if isinstance(first_choice, dict) else ""
        content_text = _content_to_text(message.get("content"))
        content_length = len(content_text.strip())
        has_message_content = content_length > 0
        has_reasoning_content = _has_reasoning_content(message)
        debug = _debug_fields(
            self.config,
            http_status=http_status,
            endpoint_path=endpoint_path,
            returned_model=returned_model,
            finish_reason=finish_reason,
            has_message_content=has_message_content,
            has_reasoning_content=has_reasoning_content,
            content_length=content_length,
            parser_reason="ok" if has_message_content else "empty_message_content",
        )
        if has_message_content:
            raw_content = content_text.strip()
            debug["rawProviderContent"] = raw_content
            debug["providerContentRedacted"] = False
            return ChatResponse(
                ok=True,
                answer=raw_content,
                model=self.config.model,
                status="ready",
                finish_reason=finish_reason,
                output_truncated=finish_reason == "length",
                endpoint_debug=debug,
            )
        if has_reasoning_content:
            debug["parserReason"] = "reasoning_without_final"
            return ChatResponse(
                ok=False,
                answer="Model sadece reasoning_content üretti, final cevap üretmedi. /no_think veya daha yüksek max_tokens dene.\n" + REASONING_WITHOUT_FINAL_TR,
                model=self.config.model,
                unavailable=True,
                error="reasoning_without_final",
                status="reasoning_without_final",
                finish_reason=finish_reason,
                endpoint_debug=debug,
            )
        if finish_reason == "length":
            debug["parserReason"] = "length_without_content"
            return ChatResponse(
                ok=False,
                answer="Cevap token limitine takıldı: finish_reason=length. Endpoint final message.content döndürmeden durdu.",
                model=self.config.model,
                unavailable=True,
                error="length_without_content",
                status="invalid_response",
                finish_reason=finish_reason,
                output_truncated=True,
                endpoint_debug=debug,
            )
        if message.get("tool_calls"):
            debug["parserReason"] = "tool_calls_without_content"
            return ChatResponse(
                ok=False,
                answer="Endpoint tool_calls döndürdü ama final message.content boş geldi. ReconBot AI terminal komutu veya araç çağrısı çalıştırmaz.",
                model=self.config.model,
                unavailable=True,
                error="tool_calls_without_content",
                status="invalid_response",
                finish_reason=finish_reason,
                endpoint_debug=debug,
            )
        return ChatResponse(
            ok=False,
            answer="Endpoint cevap verdi fakat message.content boş geldi.",
            model=self.config.model,
            unavailable=True,
            error="empty_message_content",
            status="invalid_response",
            finish_reason=finish_reason,
            endpoint_debug=debug,
        )

    def _chat_http_error_response(self, payload: Any, code: int) -> ChatResponse:
        body = str(payload or "")[:500]
        lowered = body.lower()
        http_400_category = classify_http_400(payload) if code == 400 else ""
        provider_error = _provider_error_details(payload)
        if code in {404, 422} or ("model" in lowered and any(marker in lowered for marker in ("not found", "missing", "unknown", "does not exist"))):
            return ChatResponse(
                ok=False,
                answer=f"Seçili model endpoint üzerinde hazır görünmüyor: {self.config.model}. Settings > AI içinden yüklü modeli seç.",
                model=self.config.model,
                unavailable=True,
                error=redact_text(f"HTTP {code}: {body}"),
                status="model_missing",
                endpoint_debug=_debug_fields(self.config, http_status=code, endpoint_path="/chat/completions", parser_reason="model_missing"),
            )
        if "model" in lowered and any(marker in lowered for marker in ("not loaded", "not running", "not available", "failed to load")):
            return ChatResponse(
                ok=False,
                answer=f"Endpoint çalışıyor ama seçili model chat için yüklü görünmüyor: {self.config.model}.",
                model=self.config.model,
                unavailable=True,
                error=redact_text(f"HTTP {code}: {body}"),
                status="model_not_loaded",
                endpoint_debug=_debug_fields(self.config, http_status=code, endpoint_path="/chat/completions", parser_reason="model_not_loaded"),
            )
        if code in {408, 429, 503} or any(marker in lowered for marker in ("busy", "queue", "queued", "loading", "overloaded")):
            return ChatResponse(
                ok=False,
                answer="Model meşgul veya sırada görünüyor. Mevcut isteği bekle, iptal et veya LM Studio kuyruğunu kontrol et.",
                model=self.config.model,
                unavailable=True,
                error=redact_text(f"HTTP {code}: {body}"),
                status="model_busy",
                endpoint_debug=_debug_fields(self.config, http_status=code, endpoint_path="/chat/completions", parser_reason="model_busy"),
            )
        return ChatResponse(
            ok=False,
            answer=(
                f"Endpoint chat isteğini reddetti: HTTP {code}. Provider mesajı Teknik detaylarda korundu."
                if code == 400
                else f"Endpoint cevap verdi fakat chat isteğini reddetti: HTTP {code}."
            ),
            model=self.config.model,
            unavailable=True,
            error=redact_text(f"HTTP {code}: {body}"),
            status="invalid_response",
            endpoint_debug=_debug_fields(
                self.config,
                http_status=code,
                endpoint_path="/chat/completions",
                parser_reason=http_400_category or "http_error",
                provider_message=provider_error["message"],
                provider_error_type=provider_error["type"],
                provider_error_code=provider_error["code"],
                provider_error_param=provider_error["param"],
                http_400_category=http_400_category,
            ),
        )

    def _chat_transport_error_response(self, error: BaseException) -> ChatResponse:
        text = redact_text(str(error))
        lowered = text.lower()
        if isinstance(error, TimeoutError) or "timed out" in lowered or "timeout" in lowered:
            return ChatResponse(
                ok=False,
                answer="Model çalışıyor ama yanıt süresi uzun. Context boyutu fazla olabilir veya LM Studio kuyruğu dolmuş olabilir.",
                model=self.config.model,
                unavailable=True,
                error=text,
                status="model_timeout",
                endpoint_debug=_debug_fields(self.config, endpoint_path="/chat/completions", parser_reason="model_timeout"),
            )
        return ChatResponse(
            ok=False,
            answer="Yerel AI endpoint'e ulaşılamıyor.",
            model=self.config.model,
            unavailable=True,
            error=text,
            status="endpoint_unreachable",
            endpoint_debug=_debug_fields(self.config, endpoint_path="/chat/completions", parser_reason="endpoint_unreachable"),
        )

    def status(self) -> AIStatus:
        if not self.config.enabled:
            return _status(
                self.config,
                "disabled",
                "AI devre dışı.",
                "AI kullanmak için Settings > AI içinden etkinleştir.",
                "ReconBot AI opsiyoneldir; ReconBot tarama ve rapor özellikleri AI olmadan normal çalışır.",
            )
        if self.config.provider != "openai_compatible":
            return _status(
                self.config,
                "error",
                "AI provider desteklenmiyor.",
                "Settings > AI provider değerini openai_compatible olarak bırak.",
                "ReconBot şu anda local OpenAI-compatible endpoint bekler.",
            )

        models_kind, models_payload, models_code = self._http_json("/models")
        models_debug = _debug_fields(
            self.config,
            http_status=models_code,
            endpoint_path="/models",
            returned_model="",
            parser_reason=str(models_kind),
        )
        if models_kind == "transport_error":
            return self._classify_transport_error(models_payload)
        if models_kind == "ok":
            pass
        elif models_code in {401, 403}:
            return _status(
                self.config,
                "error",
                "AI endpoint kimlik doğrulama istedi.",
                "API key gerekiyorsa Settings > AI içinde yalnız env var adını yapılandır; raw key değeri girme.",
                "Env var değerini işletim sistemi ortamında tut, ReconBot içine yazma.",
                reason="auth_required",
                endpoint_debug=models_debug,
            )
        elif models_kind == "invalid_json":
            return _status(
                self.config,
                "invalid_response",
                "Endpoint /models için geçersiz JSON döndürdü.",
                "Base URL'nin OpenAI-compatible /v1 endpoint olduğundan emin ol.",
                "Health check chat çağrısı yapmaz; model kuyruğunu doldurmadan sadece /models metadata okur.",
                reason="invalid_models_json",
                endpoint_debug=models_debug,
            )
        elif models_code in {404, 405}:
            return _status(
                self.config,
                "invalid_response",
                "Endpoint /models metadata endpoint'ini desteklemiyor gibi görünüyor.",
                "OpenAI-compatible base URL değerini kontrol et; genelde /v1 ile biter.",
                "ReconBot health check sırasında /chat/completions çağırmaz, bu yüzden model kuyruğu etkilenmez.",
                reason="models_endpoint_missing",
                endpoint_debug=models_debug,
            )
        elif models_kind == "http_error":
            return _status(
                self.config,
                "error",
                "Endpoint cevap verdi ama /models isteğini kabul etmedi.",
                "Base URL, local server logları ve varsa env var tabanlı auth ayarını kontrol et.",
                "API key gerekiyorsa ReconBot içine raw key değil, sadece env var adı yaz.",
                reason="models_http_error",
                endpoint_debug=models_debug,
            )

        model_ids = _model_ids(models_payload)
        if model_ids is None:
            return _status(
                self.config,
                "invalid_response",
                "Endpoint OpenAI-compatible model listesi döndürmedi.",
                "LM Studio veya local server /v1/models çıktısını kontrol et.",
                "Beklenen format: data içinde id alanı bulunan model listesi.",
                reason="models_shape_invalid",
                endpoint_debug={**models_debug, "parserReason": "models_shape_invalid"},
            )
        available_models = sorted(model_ids)
        if self.config.model not in model_ids:
            return _status(
                self.config,
                "model_missing",
                f"Seçili model endpoint üzerinde görünmüyor: {self.config.model}.",
                "Yüklü modellerden birini seç veya Settings > AI içinden model adını düzelt.",
                "Model listesi geldiyse chat çağrısı yapılmadı; eksik modeli yüklemeden inference başlatılmaz.",
                available_models=available_models,
                selected_model_available=False,
                reason="selected_model_missing",
                endpoint_debug={**models_debug, "parserReason": "selected_model_missing"},
            )
        model_entries = _model_entries(models_payload)
        selected_metadata = model_entries.get(self.config.model, {})
        runtime_metadata, _runtime_source = self.discover_runtime_model_metadata()
        selected_metadata = {**selected_metadata, **runtime_metadata}
        if runtime_metadata and runtime_metadata.get("loadedState") is False:
            return _status(
                self.config,
                "model_not_loaded",
                f"Endpoint çalışıyor ama seçili model yüklü değil: {self.config.model}.",
                "LM Studio içinde seçili modeli yükle ve Bağlantıyı Test Et.",
                "Modelin teorik context değeri, yüklü instance context değeri yerine kullanılmaz.",
                available_models=available_models,
                selected_model_available=True,
                reason="selected_model_not_loaded",
                endpoint_debug={**models_debug, "parserReason": "selected_model_not_loaded", "modelMetadata": selected_metadata},
            )
        model_profile = classify_model_profile(self.config.model, selected_metadata)
        if model_profile == "non_chat":
            return _status(
                self.config,
                "model_incompatible",
                f"Seçili model chat modeli değil: {self.config.model}.",
                "Embedding/reranker yerine instruct veya chat-completions modeli seç.",
                "ReconBot non-chat modellerine chat isteği göndermez; uygulamanın diğer bölümleri normal çalışır.",
                available_models=available_models,
                selected_model_available=True,
                reason="selected_model_non_chat",
                endpoint_debug={**models_debug, "parserReason": "selected_model_non_chat", "modelMetadata": selected_metadata, "modelProfile": model_profile},
            )
        return _status(
            self.config,
            "ready",
            "Bağlantı başarılı. Yerel model hazır.",
            "AI sohbeti ve rapor açıklama özelliklerini kullanabilirsin.",
            "Health check /v1/models ve varsa LM Studio runtime metadata endpointini okudu; inference kuyruğuna prompt eklenmedi.",
            can_chat=True,
            available_models=available_models,
            selected_model_available=True,
            reason="ready",
            endpoint_debug={**models_debug, "parserReason": "ready", "modelMetadata": selected_metadata, "modelProfile": model_profile},
        )

    def chat(
        self,
        messages: list[ChatMessage],
        max_tokens: int | None = None,
        *,
        compact_messages: list[ChatMessage] | None = None,
        request_timeout_sec: int | None = None,
        max_attempts: int = MAX_CHAT_ATTEMPTS,
        known_compatibility_notes: list[str] | None = None,
    ) -> ChatResponse:
        if not self.config.enabled:
            return ChatResponse(ok=False, answer="", model=self.config.model, unavailable=True, error="AI disabled in settings.", status="disabled")
        if self.config.provider != "openai_compatible":
            return ChatResponse(ok=False, answer="", model=self.config.model, unavailable=True, error="Unsupported AI provider.", status="error")
        response_endpoint = "/chat/completions"
        attempt_count = 0
        prior_notes = known_compatibility_notes or []
        compatibility_notes: list[str] = list(dict.fromkeys(str(note) for note in prior_notes if str(note).strip()))
        reasoning_controls_removed = any("unsupported_reasoning_fields" in note for note in prior_notes)
        system_folded = any("system_role_rejected" in note for note in prior_notes)
        context_compacted = False
        effective_messages = _fold_system_messages(messages) if system_folded else messages

        last_request_payload: dict[str, Any] = {}

        def perform(current_messages: list[ChatMessage], include_reasoning_controls: bool) -> tuple[str, Any, int]:
            nonlocal attempt_count
            nonlocal last_request_payload
            attempt_count += 1
            request_payload = self._chat_payload(
                current_messages,
                max_tokens=max_tokens,
                include_reasoning_controls=include_reasoning_controls,
            )
            last_request_payload = request_payload
            if request_timeout_sec is None:
                return self._http_json(response_endpoint, method="POST", payload=request_payload)
            try:
                return self._http_json(response_endpoint, method="POST", payload=request_payload, timeout_sec=request_timeout_sec)
            except TypeError as error:
                # Preserve compatibility with focused test/provider subclasses that implement the older hook.
                if "timeout_sec" not in str(error):
                    raise
                return self._http_json(response_endpoint, method="POST", payload=request_payload)

        kind, payload, code = perform(effective_messages, not reasoning_controls_removed)
        while attempt_count < max(1, max_attempts):
            http_400_category = classify_http_400(payload) if kind == "http_error" and code == 400 else ""
            if kind == "http_error" and http_400_category == "context_length_exceeded" and compact_messages and not context_compacted:
                effective_messages = compact_messages
                context_compacted = True
                compatibility_notes.append("context_length_exceeded: compact ReconBot context ile bir kez yeniden denendi")
                kind, payload, code = perform(effective_messages, not reasoning_controls_removed)
                continue
            sent_reasoning_fields = [field for field in ("reasoning", "reasoning_effort") if field in last_request_payload]
            if kind == "http_error" and http_400_category == "unsupported_parameter" and sent_reasoning_fields and not reasoning_controls_removed:
                reasoning_controls_removed = True
                compatibility_notes.append("unsupported_reasoning_fields: optional reasoning alanları kaldırıldı")
                kind, payload, code = perform(effective_messages, False)
                continue
            if kind == "http_error" and http_400_category == "invalid_role" and any(message.role == "system" for message in effective_messages) and not system_folded:
                folded_messages = _fold_system_messages(effective_messages)
                if folded_messages != effective_messages:
                    effective_messages = folded_messages
                    system_folded = True
                    compatibility_notes.append("system_role_rejected: system talimatı user prompt içine katlandı")
                    kind, payload, code = perform(effective_messages, False if self.config.disableReasoning else True)
                    continue
            break
        if kind == "http_error":
            http_400_category = classify_http_400(payload) if code == 400 else ""
            provider_error = _provider_error_details(payload)
            provider_message = provider_error["message"]
            if http_400_category == "context_length_exceeded" or _is_context_length_error(payload):
                return ChatResponse(
                    ok=False,
                    answer="Konuşma bağlamı modelin yüklü context sınırını aştı. Bağlamı küçültüp tekrar dene veya Yeni sohbet ile yalnız Copilot geçmişini temizle.",
                    model=self.config.model,
                    unavailable=True,
                    error="context_length_exceeded",
                    status="context_length_exceeded",
                    lm_request_sent=True,
                    endpoint_debug={
                        **_debug_fields(
                            self.config,
                            http_status=code,
                            endpoint_path=response_endpoint,
                            parser_reason="context_length_exceeded",
                            provider_message=provider_message,
                            provider_error_type=provider_error["type"],
                            provider_error_code=provider_error["code"],
                            provider_error_param=provider_error["param"],
                            http_400_category="context_length_exceeded",
                            provider_payload_fields=list(last_request_payload),
                            reasoning_fields_sent=[field for field in ("reasoning", "reasoning_effort") if field in last_request_payload],
                        ),
                        "providerMessages": _provider_messages_for_diagnostics(last_request_payload),
                    },
                    attempt_count=attempt_count,
                    transport_attempt_count=attempt_count,
                    compatibility_notes=compatibility_notes,
                )
            failed = self._chat_http_error_response(payload, code)
            return replace(
                failed,
                lm_request_sent=True,
                attempt_count=attempt_count,
                transport_attempt_count=attempt_count,
                compatibility_notes=compatibility_notes,
                endpoint_debug={
                    **failed.endpoint_debug,
                    "providerMessage": provider_message,
                    "providerErrorType": provider_error["type"],
                    "providerErrorCode": provider_error["code"],
                    "providerErrorParam": provider_error["param"],
                    "http400Category": http_400_category,
                    "providerPayloadFields": list(last_request_payload),
                    "providerMessages": _provider_messages_for_diagnostics(last_request_payload),
                    "reasoningFieldsSent": [field for field in ("reasoning", "reasoning_effort") if field in last_request_payload],
                    "providerTemperature": self.config.temperature,
                },
            )
        if kind == "transport_error":
            return replace(self._chat_transport_error_response(payload), lm_request_sent=True, attempt_count=attempt_count, transport_attempt_count=attempt_count, compatibility_notes=compatibility_notes)
        if kind == "invalid_json":
            return ChatResponse(
                ok=False,
                answer="Endpoint OpenAI chat completions formatına uymayan cevap döndürdü.",
                model=self.config.model,
                unavailable=True,
                error="invalid_json",
                status="invalid_response",
                lm_request_sent=True,
                endpoint_debug=_debug_fields(self.config, http_status=code, endpoint_path=response_endpoint, parser_reason="invalid_json"),
                attempt_count=attempt_count,
                transport_attempt_count=attempt_count,
                compatibility_notes=compatibility_notes,
            )
        try:
            parsed_response = self._parse_chat_response(payload, endpoint_path=response_endpoint, http_status=code)
            if (
                not parsed_response.ok
                and parsed_response.endpoint_debug.get("parserReason") in {"reasoning_without_final", "empty_message_content", "length_without_content"}
                and compact_messages
                and attempt_count < max(1, max_attempts)
            ):
                compatibility_notes.append("empty_or_reasoning_only: final-only compact prompt ile bir kez yeniden denendi")
                retry_kind, retry_payload, retry_code = perform(compact_messages, True)
                if retry_kind == "ok":
                    parsed_response = self._parse_chat_response(retry_payload, endpoint_path=response_endpoint, http_status=retry_code)
                elif retry_kind == "transport_error":
                    return replace(self._chat_transport_error_response(retry_payload), lm_request_sent=True, attempt_count=attempt_count, transport_attempt_count=attempt_count, compatibility_notes=compatibility_notes)
                elif retry_kind == "http_error":
                    failed = self._chat_http_error_response(retry_payload, retry_code)
                    return replace(failed, lm_request_sent=True, attempt_count=attempt_count, transport_attempt_count=attempt_count, compatibility_notes=compatibility_notes)
            debug = {
                **parsed_response.endpoint_debug,
                "providerPayloadFields": list(last_request_payload),
                "providerMessages": _provider_messages_for_diagnostics(last_request_payload),
                "reasoningFieldsSent": [field for field in ("reasoning", "reasoning_effort") if field in last_request_payload],
                "providerTemperature": self.config.temperature,
            }
            return replace(parsed_response, lm_request_sent=True, attempt_count=attempt_count, transport_attempt_count=attempt_count, compatibility_notes=compatibility_notes, endpoint_debug=debug)
        except ResponseParserError as error:
            return ChatResponse(
                ok=False,
                answer=error.user_message,
                model=self.config.model,
                unavailable=True,
                error=redact_text(error.parser_reason),
                status="invalid_response",
                lm_request_sent=True,
                endpoint_debug=error.debug,
                attempt_count=attempt_count,
                transport_attempt_count=attempt_count,
                compatibility_notes=compatibility_notes,
            )
        except (ValueError, AttributeError) as error:
            return ChatResponse(
                ok=False,
                answer="Endpoint OpenAI chat completions formatına uymayan cevap döndürdü.",
                model=self.config.model,
                unavailable=True,
                error=redact_text(str(error)),
                status="invalid_response",
                lm_request_sent=True,
                endpoint_debug=_debug_fields(self.config, http_status=code, endpoint_path=response_endpoint, parser_reason="parser_exception"),
                attempt_count=attempt_count,
                transport_attempt_count=attempt_count,
                compatibility_notes=compatibility_notes,
            )


def _model_ids(payload: Any) -> set[str] | None:
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if not isinstance(data, list):
        return None
    ids: set[str] = set()
    for item in data:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            ids.add(item["id"])
        elif isinstance(item, str):
            ids.add(item)
    return ids


def _model_entries(payload: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        return {}
    entries: dict[str, dict[str, Any]] = {}
    for item in payload["data"]:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            entries[item["id"]] = item
    return entries


def _json_object_suffix(value: str) -> Any:
    for index, character in enumerate(value):
        if character != "{":
            continue
        try:
            return json.loads(value[index:])
        except json.JSONDecodeError:
            continue
    return None


def _provider_error_details(payload: Any) -> dict[str, str]:
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return {"message": redact_provider_error_text(payload)[:700], "type": "", "code": "", "param": ""}
    else:
        parsed = payload
    message: Any = ""
    error_type: Any = ""
    error_code: Any = ""
    error_param: Any = ""
    if isinstance(parsed, dict):
        error = parsed.get("error")
        if isinstance(error, dict):
            message = error.get("message") or error.get("detail") or error.get("type") or ""
            error_type = error.get("type") or ""
            error_code = error.get("code") or ""
            error_param = error.get("param") or ""
        elif isinstance(error, str):
            message = error
        else:
            message = parsed.get("message") or parsed.get("detail") or ""
            error_type = parsed.get("type") or ""
            error_code = parsed.get("code") or ""
            error_param = parsed.get("param") or ""
    if isinstance(message, str):
        nested = _json_object_suffix(message)
        if nested is not None:
            nested_details = _provider_error_details(nested)
            if nested_details["message"]:
                message = nested_details["message"]
            error_type = nested_details["type"] or error_type
            error_code = nested_details["code"] or error_code
            error_param = nested_details["param"] or error_param
    return {
        "message": redact_provider_error_text(message or payload)[:700],
        "type": redact_provider_error_text(error_type)[:200],
        "code": redact_provider_error_text(error_code)[:200],
        "param": redact_provider_error_text(error_param)[:200],
    }


def _provider_error_message(payload: Any) -> str:
    return _provider_error_details(payload)["message"]


def classify_http_400(payload: Any) -> str:
    lowered = _provider_error_message(payload).lower()
    context_markers = (
        "context length exceeded",
        "prompt tokens exceed context",
        "number of tokens exceeds context window",
        "requested tokens exceed context size",
        "n_ctx",
        "n_keep",
        "prompt too long",
        "prompt is too long",
        "input exceeds available context",
        "max_tokens plus prompt tokens",
        "cannot fit prompt",
        "context overflow",
        "input is too long",
        "too many tokens",
        "maximum context length",
    )
    if any(marker in lowered for marker in context_markers):
        return "context_length_exceeded"
    if "model" in lowered and any(marker in lowered for marker in ("not found", "unknown", "does not exist", "invalid model")):
        return "invalid_model"
    if any(marker in lowered for marker in (
        "system role",
        "role system",
        "only user and assistant roles",
        "invalid role",
        "unsupported role",
    )):
        return "invalid_role"
    if any(marker in lowered for marker in (
        "unable to generate parser for this template",
        "chat template",
        "jinja exception",
        "template rendering",
        "error rendering prompt",
    )):
        return "chat_template_error"
    if any(marker in lowered for marker in (
        "roles must alternate",
        "conversation roles",
        "expected user role",
        "expected assistant role",
    )):
        return "invalid_role"
    if any(marker in lowered for marker in ("unsupported parameter", "unsupported field", "unknown parameter", "unrecognized field", "extra fields not permitted", "reasoning_effort", "reasoning field")):
        return "unsupported_parameter"
    if any(marker in lowered for marker in ("invalid payload", "malformed payload", "invalid request body", "messages is required", "json schema")):
        return "invalid_payload"
    if any(marker in lowered for marker in (
        "invalid message content",
        "message content must be",
        "content must be a string",
        "content cannot be null",
    )):
        return "invalid_message_content"
    return "unknown_http_400"


def _match_lm_studio_runtime_model(payload: Any, selected_model: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
        return {}
    selected = str(selected_model or "").strip()
    for raw_model in payload["models"]:
        if not isinstance(raw_model, dict):
            continue
        loaded_instances = raw_model.get("loaded_instances") if isinstance(raw_model.get("loaded_instances"), list) else []
        identifiers = {
            str(value).strip()
            for value in (
                raw_model.get("key"),
                raw_model.get("id"),
                raw_model.get("model"),
                raw_model.get("identifier"),
                raw_model.get("selected_variant"),
            )
            if value
        }
        variants = raw_model.get("variants")
        if isinstance(variants, list):
            identifiers.update(str(value).strip() for value in variants if value)
        for instance in loaded_instances:
            if isinstance(instance, dict) and instance.get("id"):
                identifiers.add(str(instance["id"]).strip())
        if selected not in identifiers:
            continue
        selected_instance: dict[str, Any] = {}
        for instance in loaded_instances:
            if not isinstance(instance, dict):
                continue
            if str(instance.get("id") or "").strip() == selected:
                selected_instance = instance
                break
            if not selected_instance:
                selected_instance = instance
        instance_config = selected_instance.get("config") if isinstance(selected_instance.get("config"), dict) else {}
        loaded_context = int(instance_config.get("context_length") or 0)
        theoretical = int(raw_model.get("max_context_length") or 0)
        capabilities = raw_model.get("capabilities") if isinstance(raw_model.get("capabilities"), dict) else {}
        supported_fields = raw_model.get("supported_reasoning_fields") or capabilities.get("reasoning_fields") or []
        return {
            "id": selected,
            "key": raw_model.get("key") or selected,
            "type": raw_model.get("type"),
            "loadedState": bool(loaded_instances),
            "loadedContextLength": loaded_context,
            "modelMaxContextLength": theoretical,
            "contextMetadataSource": "lm_studio_loaded_instance" if loaded_context else "lm_studio_model_metadata",
            "conservativeContextFallbackUsed": not bool(loaded_context),
            "capabilities": capabilities,
            "supportedReasoningFields": supported_fields if isinstance(supported_fields, list) else [],
            "loaded_instances": loaded_instances,
            "max_context_length": theoretical,
        }
    return {}


def _is_context_length_error(payload: Any) -> bool:
    return classify_http_400(payload) == "context_length_exceeded"


def _valid_chat_response(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return False
    first = choices[0]
    if not isinstance(first, dict):
        return False
    message = first.get("message")
    return isinstance(message, dict) and bool(_content_to_text(message.get("content")).strip())
