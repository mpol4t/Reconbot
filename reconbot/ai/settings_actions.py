from __future__ import annotations

import copy
from typing import Any

from .action_guard import validate_action_plan
from .redaction import redact_for_ui


def _get_path(source: dict[str, Any], path: str) -> Any:
    current: Any = source
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _set_path(source: dict[str, Any], path: str, value: Any) -> None:
    current: dict[str, Any] = source
    parts = path.split(".")
    for part in parts[:-1]:
        next_value = current.get(part)
        if not isinstance(next_value, dict):
            next_value = {}
            current[part] = next_value
        current = next_value
    current[parts[-1]] = value


def apply_settings_action(settings: dict[str, Any], plan: dict[str, Any], approved: bool = False) -> dict[str, Any]:
    ok, errors = validate_action_plan(plan, approved=approved)
    if not ok:
        return {"ok": False, "errors": errors, "settings": redact_for_ui(settings)}
    next_settings = copy.deepcopy(settings)
    applied: list[dict[str, Any]] = []
    for change in plan.get("changes", []):
        path = str(change["path"])
        before = _get_path(next_settings, path)
        _set_path(next_settings, path, change.get("proposed"))
        applied.append(
            {
                "path": path,
                "old": redact_for_ui(before),
                "new": redact_for_ui(change.get("proposed")),
                "reason_tr": str(change.get("reason_tr") or ""),
            }
        )
    return {
        "ok": True,
        "settings": redact_for_ui(next_settings),
        "applied": applied,
        "log_message": "user-approved AI settings change",
    }
