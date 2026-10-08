from __future__ import annotations

import json
import math
import re
from dataclasses import replace
from typing import Any

from .models import AIConfig, ChatMessage, ResolvedAIRequestPlan
from .redaction import redact_text
from .settings_contract import runtime_limit


MAX_CHAT_ATTEMPTS = int(runtime_limit("maximumTransportCompatibilityAttempts"))
MAX_ANSWER_REPAIR_ATTEMPTS = int(runtime_limit("maximumAnswerRepairAttempts"))
RUNTIME_CAPABILITY_DISCOVERY_TIMEOUT_SEC = int(runtime_limit("runtimeCapabilityDiscoveryTimeoutSeconds"))
PROCESS_OVERHEAD_SEC = int(runtime_limit("processOverheadSeconds"))
ELECTRON_WATCHDOG_OVERHEAD_SEC = int(runtime_limit("electronWatchdogOverheadSeconds"))
CHARS_PER_TOKEN_ESTIMATE = int(runtime_limit("charsPerTokenEstimate"))
SYSTEM_PROMPT_TOKEN_RESERVE = int(runtime_limit("systemPromptTokenReserve"))
COMPACT_SYSTEM_PROMPT_TOKEN_RESERVE = int(runtime_limit("compactSystemPromptTokenReserve"))
MAX_HISTORY_TURNS = int(runtime_limit("maximumHistoryTurns"))
UNKNOWN_MODEL_CONTEXT_TOKENS = int(runtime_limit("unknownModelContextTokens"))
MIN_CONTEXT_TOKENS = int(runtime_limit("minimumAcceptedContextTokens"))
MAX_CONTEXT_TOKENS = int(runtime_limit("maximumAcceptedContextTokens"))
MIN_SAFETY_MARGIN_TOKENS = int(runtime_limit("minimumSafetyMarginTokens"))
SAFETY_MARGIN_FRACTION = float(runtime_limit("safetyMarginFraction"))
HARD_MAX_OUTPUT_TOKENS = int(runtime_limit("hardMaximumOutputTokens"))

_NON_CHAT_MODEL = re.compile(
    r"(?:^|[/_.-])(embed(?:ding)?|rerank(?:er)?|cross[-_]?encoder|sentence[-_]?transformer|clip|whisper|tts)(?:$|[/_.-])",
    re.IGNORECASE,
)
_REASONING_MODEL = re.compile(r"qwen3|qwq|reason(?:ing)?|think(?:ing)?|deepseek[-_]?r1|o[13](?:$|[-_.])", re.IGNORECASE)
_INSTRUCT_MODEL = re.compile(r"mistral|instruct|llama|gemma|phi|qwen2(?:\.5)?|chat", re.IGNORECASE)


def estimate_tokens_from_chars(chars: int) -> int:
    return max(1, (max(0, int(chars)) + CHARS_PER_TOKEN_ESTIMATE - 1) // CHARS_PER_TOKEN_ESTIMATE)


def plan_serialized_messages(plan: ResolvedAIRequestPlan, messages: list[ChatMessage]) -> ResolvedAIRequestPlan:
    """Budget the actual outgoing request, including repair instructions/quotes."""
    input_tokens = sum(estimate_tokens_from_chars(len(message.content) + 16) for message in messages)
    available = plan.estimated_context_window_tokens - plan.reserved_safety_margin_tokens - input_tokens
    output = max(1, min(plan.effective_max_output_tokens, available))
    limited = output < plan.effective_max_output_tokens
    limit_reason = plan.output_limit_reason
    if limited and "loaded_context_window_and_request_input" not in limit_reason:
        limit_reason = ",".join(filter(None, [limit_reason, "loaded_context_window_and_request_input"]))
    return replace(
        plan,
        estimated_input_tokens=input_tokens,
        effective_max_output_tokens=output,
        reserved_output_tokens=output,
        estimated_total_tokens=input_tokens + output,
        user_message_fits=bool(plan.user_message_fits and available >= 1),
        history_turns_sent=max(0, len(messages) - 2),
        history_was_compacted=plan.history_was_compacted or len(messages) - 2 < plan.history_turns_sent,
        estimated_history_tokens=sum(estimate_tokens_from_chars(len(message.content) + 16) for message in messages[1:-1]),
        output_limit_reason=limit_reason,
        output_budget_reason=("Output reduced to fit serialized provider messages." if limited else plan.output_budget_reason),
    )


def prepare_conversation_history(
    conversation_history: Any,
    latest_user_message: str,
    *,
    max_chars: int | None = None,
    max_turns: int = MAX_HISTORY_TURNS,
) -> tuple[list[dict[str, str]], bool, int]:
    """Normalize and bound LM-facing conversation turns without masking content.

    The current user message is deliberately excluded because build_messages always
    appends it once, as the final message. When a budget is tight, whole oldest
    turns are dropped instead of silently truncating the latest question.
    """
    source = conversation_history if isinstance(conversation_history, list) else []
    valid: list[dict[str, str]] = []
    for item in source:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "")
        content = item.get("content")
        if role not in {"user", "assistant"} or not isinstance(content, str) or not content.strip():
            continue
        valid.append({"role": role, "content": redact_text(content, mode="ai_prompt_redaction")})
    received = len(valid)
    compacted = received != len(source)
    if valid and valid[-1]["role"] == "user" and valid[-1]["content"].strip() == redact_text(latest_user_message).strip():
        valid.pop()
        compacted = True
    if len(valid) > max(0, max_turns):
        valid = valid[-max_turns:]
        compacted = True

    def history_chars(turns: list[dict[str, str]]) -> int:
        return sum(len(turn["content"]) + 16 for turn in turns)

    if max_chars is not None:
        budget = max(0, int(max_chars))
        while valid and history_chars(valid) > budget:
            valid.pop(0)
            compacted = True
    return valid, compacted, received


def classify_model_profile(model: str, model_metadata: dict[str, Any] | None = None) -> str:
    metadata = model_metadata or {}
    capabilities = metadata.get("capabilities") if isinstance(metadata.get("capabilities"), dict) else {}
    lowered_capabilities = {str(key).lower(): value for key, value in capabilities.items()}
    if lowered_capabilities.get("chat") is False or lowered_capabilities.get("chat_completions") is False:
        return "non_chat"
    if lowered_capabilities.get("embedding") is True and not any(lowered_capabilities.get(key) for key in ("chat", "chat_completions", "completion")):
        return "non_chat"
    if _NON_CHAT_MODEL.search(str(model or "")):
        return "non_chat"
    if lowered_capabilities.get("reasoning") is True or _REASONING_MODEL.search(str(model or "")):
        return "reasoning"
    if lowered_capabilities.get("chat") is True or lowered_capabilities.get("chat_completions") is True or _INSTRUCT_MODEL.search(str(model or "")):
        return "lightweight_instruct"
    return "unknown_chat"


def _positive_int(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed > 0 else 0


def context_window_from_metadata(
    model_metadata: dict[str, Any] | None,
    model_profile: str,
) -> tuple[int, int, str, bool, list[str]]:
    metadata = model_metadata or {}
    loaded_candidates: list[tuple[str, Any]] = [
        ("lm_studio_loaded_instance", metadata.get("loadedContextLength")),
        ("lm_studio_loaded_instance", metadata.get("loaded_context_length")),
        ("provider_runtime_metadata", metadata.get("runtime_context_length")),
        ("provider_runtime_metadata", metadata.get("context_length")),
        ("provider_runtime_metadata", metadata.get("context_window")),
    ]
    loaded_instances = metadata.get("loaded_instances")
    if isinstance(loaded_instances, list):
        for instance in loaded_instances:
            if not isinstance(instance, dict):
                continue
            config = instance.get("config") if isinstance(instance.get("config"), dict) else {}
            loaded_candidates.append(("lm_studio_loaded_instance", config.get("context_length")))
    capabilities = metadata.get("capabilities")
    if isinstance(capabilities, dict):
        loaded_candidates.extend([
            ("provider_runtime_metadata", capabilities.get("context_length")),
            ("provider_runtime_metadata", capabilities.get("context_window")),
        ])
    theoretical_candidates: list[Any] = [
        metadata.get("modelMaxContextLength"),
        metadata.get("model_max_context_length"),
        metadata.get("max_context_length"),
        metadata.get("context_length"),
        metadata.get("context_window"),
        metadata.get("max_position_embeddings"),
    ]
    theoretical = next((value for value in (_positive_int(item) for item in theoretical_candidates) if MIN_CONTEXT_TOKENS <= value <= MAX_CONTEXT_TOKENS), 0)
    for source, raw_value in loaded_candidates:
        parsed = _positive_int(raw_value)
        if MIN_CONTEXT_TOKENS <= parsed <= MAX_CONTEXT_TOKENS:
            model_max = max(theoretical, parsed)
            return parsed, model_max, source, False, [f"Loaded runtime context {parsed} token olarak {source} metadata'sından çözüldü."]
    return (
        UNKNOWN_MODEL_CONTEXT_TOKENS,
        theoretical,
        "conservative_fallback",
        True,
        [f"Yüklü runtime context metadata yok; konservatif {UNKNOWN_MODEL_CONTEXT_TOKENS} token fallback kullanıldı."],
    )


def reasoning_fields_from_metadata(config: AIConfig, model_metadata: dict[str, Any] | None) -> list[str]:
    if config.disableReasoning:
        return []
    metadata = model_metadata or {}
    capabilities = metadata.get("capabilities") if isinstance(metadata.get("capabilities"), dict) else {}
    reasoning_supported = capabilities.get("reasoning") is True or metadata.get("reasoningSupported") is True
    raw_fields = metadata.get("supportedReasoningFields") or metadata.get("supported_reasoning_fields") or capabilities.get("reasoning_fields")
    if not reasoning_supported or not isinstance(raw_fields, list):
        return []
    allowed = {"reasoning", "reasoning_effort"}
    return [str(item) for item in raw_fields if str(item) in allowed]


def _mode_context_fraction(response_mode: str) -> float:
    if response_mode == "fast_operator":
        return 0.45
    if response_mode == "deep_analysis":
        return 1.0
    return 0.75


def _minimum_relevant_context_chars(context_profile: str, context_chars: int, configured_chars: int) -> int:
    minimum_by_profile = {
        "ai_failure_diagnostics": 2400,
        "settings": 3600,
        "settings_advice": 3600,
        "settings_recommendation": 3600,
        "logs": 3000,
        "log_troubleshooting": 3000,
        "finding_question": 2400,
        "report_qa": 2400,
        "report_summary": 1800,
        "quick_report_summary": 1800,
        "trust": 2400,
        "continuation": 600,
        "operational_question": 1800,
    }
    requested = minimum_by_profile.get(context_profile, 0)
    return min(max(0, context_chars), max(0, configured_chars), requested)


def resolve_ai_request_plan(
    config: AIConfig,
    *,
    answer_intent: str,
    context_profile: str,
    user_message: str,
    injected_context: Any,
    conversation_history: Any = None,
    model_metadata: dict[str, Any] | None = None,
    serialized_context_chars: int | None = None,
) -> ResolvedAIRequestPlan:
    model_profile = classify_model_profile(config.model, model_metadata)
    context_window, model_max_context, context_source, fallback_used, notes = context_window_from_metadata(model_metadata, model_profile)
    user_chars = len(user_message or "")
    context_chars = (
        max(0, int(serialized_context_chars))
        if serialized_context_chars is not None
        else len(json.dumps(injected_context or {}, ensure_ascii=False, separators=(",", ":")))
    )
    normalized_history, history_initially_compacted, history_turns_received = prepare_conversation_history(
        conversation_history,
        user_message,
    )
    configured_output = max(1, int(config.maxOutputTokens))
    provider_output_cap = _positive_int((model_metadata or {}).get("max_output_tokens"))
    technical_output_cap = min(HARD_MAX_OUTPUT_TOKENS, provider_output_cap or HARD_MAX_OUTPUT_TOKENS)
    output_ceiling = min(configured_output, technical_output_cap)
    request_timeout = max(1, int(config.timeout))
    retry_policy = {
        "maxAttempts": MAX_CHAT_ATTEMPTS,
        "unsupportedReasoningFields": 1,
        "systemRoleFolding": 1,
        "contextLengthCompaction": 1,
        "reasoningOnlyFinalRetry": 1,
        "unknownHttp400Retries": 0,
        "transportTimeoutRetries": 0,
    }
    watchdog = (
        request_timeout * (MAX_CHAT_ATTEMPTS + MAX_ANSWER_REPAIR_ATTEMPTS)
        + RUNTIME_CAPABILITY_DISCOVERY_TIMEOUT_SEC
        + PROCESS_OVERHEAD_SEC
        + ELECTRON_WATCHDOG_OVERHEAD_SEC
    )
    safety_margin = max(MIN_SAFETY_MARGIN_TOKENS, int(math.ceil(context_window * SAFETY_MARGIN_FRACTION)))
    question_tokens = estimate_tokens_from_chars(user_chars)
    configured_context_chars = max(0, int(config.maxContextChars))
    desired_context_chars = min(
        context_chars,
        int(configured_context_chars * _mode_context_fraction(config.responseMode)),
    )
    initial_history_chars = sum(len(turn["content"]) + 16 for turn in normalized_history)
    full_prompt_projection = (
        SYSTEM_PROMPT_TOKEN_RESERVE
        + question_tokens
        + output_ceiling
        + (estimate_tokens_from_chars(initial_history_chars) if initial_history_chars else 0)
        + (estimate_tokens_from_chars(desired_context_chars) if desired_context_chars else 0)
        + safety_margin
    )
    compact_system_prompt = full_prompt_projection > context_window
    system_prompt_reserve = COMPACT_SYSTEM_PROMPT_TOKEN_RESERVE if compact_system_prompt else SYSTEM_PROMPT_TOKEN_RESERVE
    fixed_input_tokens = system_prompt_reserve + question_tokens
    user_message_fits = fixed_input_tokens + safety_margin + 1 <= context_window
    immediate_history = normalized_history[-2:]
    immediate_history_chars = sum(len(turn["content"]) + 16 for turn in immediate_history)
    immediate_history_tokens = estimate_tokens_from_chars(immediate_history_chars) if immediate_history_chars else 0
    minimum_context_chars = _minimum_relevant_context_chars(context_profile, context_chars, configured_context_chars)
    minimum_context_tokens = estimate_tokens_from_chars(minimum_context_chars) if minimum_context_chars else 0
    max_output_for_loaded_window = max(
        0,
        context_window - safety_margin - fixed_input_tokens - immediate_history_tokens - minimum_context_tokens,
    )
    output_tokens = min(output_ceiling, max_output_for_loaded_window)
    if output_tokens < 1:
        output_tokens = 1
    output_limit_reasons: list[str] = []
    if configured_output > HARD_MAX_OUTPUT_TOKENS:
        output_limit_reasons.append("documented_hard_upper_bound")
    if provider_output_cap and configured_output > provider_output_cap:
        output_limit_reasons.append("provider_capability")
    if output_tokens < output_ceiling:
        output_limit_reasons.append("loaded_context_window_and_request_input")
    output_limit_reason = ",".join(output_limit_reasons)
    output_budget_reason = (
        f"Configured ceiling {configured_output}; effective {output_tokens}; source user_settings; "
        f"limit {output_limit_reason or 'none'}."
    )
    available_input_tokens = max(0, context_window - safety_margin - output_tokens - fixed_input_tokens)
    remaining_input_chars = available_input_tokens * CHARS_PER_TOKEN_ESTIMATE
    renderer_history_cap_chars = min(12_000, int(context_window * CHARS_PER_TOKEN_ESTIMATE * 0.18))
    history_available_chars = max(0, remaining_input_chars - minimum_context_chars)
    planned_history, history_budget_compacted, _ = prepare_conversation_history(
        normalized_history,
        user_message,
        max_chars=min(history_available_chars, renderer_history_cap_chars),
    )
    history_chars = sum(len(turn["content"]) + 16 for turn in planned_history)
    # Preserve the immediately relevant exchange when it fits; oldest turns
    # remain the first material removed from a tight loaded model window.
    while len(planned_history) > len(immediate_history) and history_chars > remaining_input_chars:
        planned_history.pop(0)
        history_budget_compacted = True
        history_chars = sum(len(turn["content"]) + 16 for turn in planned_history)
    history_budget_chars = history_chars
    mode_context_ceiling = int(max(0, int(config.maxContextChars)) * _mode_context_fraction(config.responseMode))
    mode_window_context_ceiling = int(max(0, remaining_input_chars - history_chars) * _mode_context_fraction(config.responseMode))
    available_context_chars = max(0, remaining_input_chars - history_chars)
    context_budget_chars = min(
        context_chars,
        available_context_chars,
        max(minimum_context_chars, min(mode_context_ceiling, mode_window_context_ceiling)),
    )
    context_was_compacted = context_chars > context_budget_chars
    effective_context_chars = context_budget_chars
    estimated_input_tokens = (
        system_prompt_reserve
        + question_tokens
        + (estimate_tokens_from_chars(history_chars) if history_chars else 0)
        + estimate_tokens_from_chars(effective_context_chars)
    )
    estimated_history_tokens = estimate_tokens_from_chars(history_chars) if history_chars else 0
    estimated_total_with_margin = estimated_input_tokens + output_tokens + safety_margin
    if estimated_total_with_margin > context_window:
        overflow = estimated_total_with_margin - context_window
        output_tokens = max(1, output_tokens - overflow)
        output_limit_reason = output_limit_reason or "loaded_context_window_and_request_input"
        output_budget_reason = (
            f"Configured ceiling {configured_output}; effective {output_tokens}; source user_settings; "
            f"limit {output_limit_reason}."
        )
    compatible = model_profile != "non_chat"
    incompatibility_reason = ""
    if not compatible:
        incompatibility_reason = "Seçili model embedding/reranker veya başka bir non-chat model gibi görünüyor; chat completions için instruct/chat model seç."
        notes.append(incompatibility_reason)
    if context_was_compacted:
        notes.append("Injected ReconBot context, kullanıcı sorusu ve cevap rezervini korumak için compact edilecek.")
    history_was_compacted = history_initially_compacted or history_budget_compacted or len(planned_history) < history_turns_received
    if history_was_compacted:
        notes.append("Eski konuşma turları, son soru ve cevap rezervini korumak için önce düşürüldü.")
    if not user_message_fits:
        notes.append("Kullanıcı mesajı tek başına tahmini model penceresine sığmıyor; mesaj gönderilmeden taslak korunmalı.")
    reasoning_fields = reasoning_fields_from_metadata(config, model_metadata)
    reasoning_configuration_reason = (
        "disabled_by_user"
        if config.disableReasoning
        else "supported_fields_sent"
        if reasoning_fields
        else "unsupported_by_selected_model_or_provider"
    )
    provider_payload_fields = ["model", "messages", "temperature", "max_tokens", "stream", *reasoning_fields]
    return ResolvedAIRequestPlan(
        model_profile=model_profile,
        answer_intent=answer_intent,
        context_profile=context_profile,
        user_message_chars=user_chars,
        injected_context_chars=context_chars,
        estimated_input_tokens=estimated_input_tokens,
        effective_max_output_tokens=output_tokens,
        effective_request_timeout_sec=request_timeout,
        total_process_watchdog_sec=watchdog,
        disable_reasoning=bool(config.disableReasoning),
        retry_policy=retry_policy,
        context_was_compacted=context_was_compacted,
        compatibility_notes=notes,
        estimated_context_window_tokens=context_window,
        context_budget_chars=context_budget_chars,
        compatible=compatible,
        incompatibility_reason=incompatibility_reason,
        user_message_fits=user_message_fits,
        history_turns_received=history_turns_received,
        history_turns_sent=len(planned_history),
        history_was_compacted=history_was_compacted,
        history_budget_chars=history_budget_chars,
        output_budget_reason=output_budget_reason,
        system_prompt_reserve_tokens=system_prompt_reserve,
        compact_system_prompt=compact_system_prompt,
        reserved_output_tokens=output_tokens,
        estimated_total_tokens=estimated_input_tokens + output_tokens,
        configured_max_output_tokens=configured_output,
        configured_max_context_chars=max(0, int(config.maxContextChars)),
        effective_injected_context_chars=effective_context_chars,
        configured_timeout_sec=max(1, int(config.timeout)),
        loaded_context_length=context_window,
        model_max_context_length=model_max_context,
        context_metadata_source=context_source,
        conservative_context_fallback_used=fallback_used,
        reserved_safety_margin_tokens=safety_margin,
        output_value_source="user_settings",
        output_limit_reason=output_limit_reason,
        timeout_value_source="user_settings",
        timeout_limit_reason="",
        provider_temperature=float(config.temperature),
        reasoning_fields_sent=reasoning_fields,
        provider_payload_fields=provider_payload_fields,
        estimated_history_tokens=estimated_history_tokens,
        reasoning_configuration_reason=reasoning_configuration_reason,
    )
