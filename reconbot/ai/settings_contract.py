from __future__ import annotations

import json
from pathlib import Path
from typing import Any


_CONTRACT_PATH = Path(__file__).with_name("settings_contract.json")


def _load_contract() -> dict[str, Any]:
    with _CONTRACT_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict) or not isinstance(payload.get("defaults"), dict):
        raise RuntimeError(f"Invalid AI settings contract: {_CONTRACT_PATH}")
    return payload


AI_SETTINGS_CONTRACT = _load_contract()
AI_SETTING_DEFAULTS: dict[str, Any] = dict(AI_SETTINGS_CONTRACT["defaults"])
AI_RUNTIME_LIMITS: dict[str, Any] = dict(AI_SETTINGS_CONTRACT.get("runtimeLimits") or {})


def runtime_limit(name: str) -> int | float:
    if name not in AI_RUNTIME_LIMITS:
        raise KeyError(f"AI runtime limit is not declared in settings_contract.json: {name}")
    return AI_RUNTIME_LIMITS[name]
