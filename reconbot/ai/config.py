from __future__ import annotations

from dataclasses import fields
from typing import Any

from .models import AIConfig
from .settings_contract import AI_SETTING_DEFAULTS


DEFAULT_AI_MODEL = str(AI_SETTING_DEFAULTS["model"])


def default_ai_config() -> AIConfig:
    return AIConfig()


def normalize_base_url(value: str) -> str:
    text = str(value or "").strip() or "http://127.0.0.1:1234/v1"
    text = text.rstrip("/")
    if text.endswith("/v1"):
        return text
    if "/v1/" in text:
        return text.split("/v1/", 1)[0].rstrip("/") + "/v1"
    return text + "/v1"


def _coerce_bool(value: Any, fallback: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return fallback


def _coerce_int(value: Any, fallback: int) -> int:
    try:
        parsed = int(value)
        return parsed if parsed >= 0 else fallback
    except (TypeError, ValueError):
        return fallback


def _coerce_float(value: Any, fallback: float) -> float:
    try:
        parsed = float(value)
        return parsed if parsed >= 0 else fallback
    except (TypeError, ValueError):
        return fallback


def ai_config_from_mapping(source: dict[str, Any] | None) -> AIConfig:
    base = default_ai_config()
    if not source:
        return base
    allowed = {field.name for field in fields(AIConfig)}
    values: dict[str, Any] = {}
    model_override = source.get("selectedModel") or source.get("manualModelName") or source.get("model") or source.get("effectiveModel")
    for key, value in source.items():
        if key not in allowed:
            continue
        current = getattr(base, key)
        if isinstance(current, bool):
            values[key] = _coerce_bool(value, current)
        elif isinstance(current, int):
            values[key] = _coerce_int(value, current)
        elif isinstance(current, float):
            values[key] = _coerce_float(value, current)
        elif key == "provider":
            values[key] = "openai_compatible"
        elif key == "responseMode":
            requested_mode = str(value).strip()
            values[key] = requested_mode if requested_mode in {"adaptive", "fast_operator", "deep_analysis"} else "adaptive"
        else:
            values[key] = str(value or "").strip()
    if model_override:
        values["model"] = str(model_override).strip()
    if not values.get("model"):
        values["model"] = DEFAULT_AI_MODEL
    values["effectiveModel"] = values["model"]
    values["baseUrl"] = normalize_base_url(values.get("baseUrl") or base.baseUrl)
    return AIConfig(**{**base.__dict__, **values})


def ai_config_dict(config: AIConfig) -> dict[str, Any]:
    return dict(config.__dict__)
