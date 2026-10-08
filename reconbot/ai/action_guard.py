from __future__ import annotations

import re
from typing import Any

from .settings_contract import AI_SETTINGS_CONTRACT


# These checks validate settings actions; they never mask AI content.
SECRET_KEY_PATTERN = re.compile(
    r"(?i)\b("
    r"api[-_ ]?key|apikey|authorization|bearer|cookie|set-cookie|session(?:id)?|"
    r"password|passwd|pwd|token|access[-_ ]?token|refresh[-_ ]?token|secret|private[-_ ]?key"
    r")\b"
)
LONG_SECRET_PATTERN = re.compile(r"\b(?=[A-Za-z0-9+/=_-]{28,}\b)(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9+/=_-]{28,}\b")


ACTION_SETTING_SCHEMAS = AI_SETTINGS_CONTRACT["actionSettings"]
ALLOWED_SETTING_PATHS = set(ACTION_SETTING_SCHEMAS)

FORBIDDEN_PATH_WORDS = re.compile(r"(?i)(target|output|risk|score|secret|token|cookie|password|private|dump|credential|onion|tor|darkweb|provider|collector|artifact|report)")
SAFE_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,80}$")


def _is_allowed_env_value(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if value == "":
        return True
    return bool(SAFE_ENV_NAME.fullmatch(value))


def validate_setting_change(change: dict[str, Any]) -> tuple[bool, str]:
    path = str(change.get("path") or "")
    if path not in ALLOWED_SETTING_PATHS:
        return False, f"Path is not allowed: {path}"
    if path != "tool_settings.osint.sources.githubCodeSearch.apiKeyEnv" and FORBIDDEN_PATH_WORDS.search(path):
        return False, f"Forbidden path category: {path}"
    proposed = change.get("proposed")
    schema = ACTION_SETTING_SCHEMAS[path]
    kind = schema["type"]
    if kind == "integer":
        if type(proposed) is not int or not schema["minimum"] <= proposed <= schema["maximum"]:
            return False, f"{path}: integer {schema['minimum']}–{schema['maximum']} required."
    elif kind == "boolean":
        if type(proposed) is not bool:
            return False, f"{path}: boolean required."
    elif kind == "enum":
        if not isinstance(proposed, str) or proposed not in schema["values"]:
            return False, f"{path}: unsupported value."
    elif kind == "severity":
        if not isinstance(proposed, str) or not proposed.strip() or any(part.strip() not in schema["values"] for part in proposed.split(",")):
            return False, f"{path}: valid comma-separated severity names required."
    if path.endswith("apiKeyEnv"):
        if not _is_allowed_env_value(proposed):
            return False, "Only an environment variable name may be stored for API keys."
        return True, ""
    if isinstance(proposed, str):
        if SECRET_KEY_PATTERN.search(path) or LONG_SECRET_PATTERN.search(proposed):
            return False, "Secret-like value rejected."
        lowered = proposed.lower()
        if ".onion" in lowered or "tor" == lowered or "onion" in lowered:
            return False, "Tor/onion crawling is unsupported."
    return True, ""


def validate_action_plan(plan: dict[str, Any], approved: bool = False) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(plan, dict):
        return False, ["Action plan must be an object."]
    if plan.get("type") != "settings_recommendation":
        errors.append("Only settings_recommendation action plans are supported.")
    if plan.get("requires_user_approval") is not True:
        errors.append("Settings changes must require user approval.")
    impact = plan.get("risk_score_impact", 0)
    if type(impact) is not int or impact != 0:
        errors.append("AI settings recommendations cannot change risk score impact.")
    changes = plan.get("changes")
    if not isinstance(changes, list) or not changes or len(changes) > 64:
        errors.append("Action plan has no changes.")
    else:
        seen: set[str] = set()
        for change in changes:
            if not isinstance(change, dict):
                errors.append("Invalid change row.")
                continue
            ok, error = validate_setting_change(change)
            if not ok:
                errors.append(error)
            path = str(change.get("path") or "")
            if path in seen:
                errors.append(f"Duplicate setting path: {path}")
            seen.add(path)
    if approved is not True:
        errors.append("Explicit user approval is required before applying settings.")
    return not errors, errors
