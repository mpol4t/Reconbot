from __future__ import annotations

import json
import re
from typing import Any

from .action_guard import validate_action_plan
from .redaction import redact_obj


JSON_BLOCK_PATTERN = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def extract_action_plan(text: str) -> dict[str, Any] | None:
    candidates = [match.group(1) for match in JSON_BLOCK_PATTERN.finditer(text)]
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        candidates.append(stripped)
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and parsed.get("type") == "settings_recommendation":
            ok, _errors = validate_action_plan(parsed, approved=True)
            if ok:
                return redact_obj(parsed)
    return None
