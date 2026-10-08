"""Compatibility helpers: AI content is preserved without secret masking.

The old redact_* entry points remain for callers, but all modes preserve values.
Placeholder detection is a separate evidence-integrity check, not redaction.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any, Literal


REDACTION_MARK = "[REDACTED]"
RedactionMode = Literal["ai_prompt_redaction", "ui_display_redaction", "config_storage"]

UNRESOLVED_PLACEHOLDER_TOKEN_PATTERN = re.compile(
    r"(?:"
    r"<\s*(?:URL|LINK|PAYLOAD|IP|HOST|ENDPOINT)\s*>|"
    r"\[\s*(?:URL|LINK|PAYLOAD|IP|HOST|ENDPOINT)\s*\]|"
    r"\{\{\s*(?:URL|LINK|PAYLOAD|IP|HOST|ENDPOINT)\s*\}\}|"
    r"\$\{\s*(?:URL|LINK|PAYLOAD|IP|HOST|ENDPOINT)\s*\}"
    r")",
    re.IGNORECASE,
)
GENERIC_ANGLE_PLACEHOLDER_PATTERN = re.compile(r"<\s*[A-Z][A-Z0-9_-]{1,31}\s*>")
STANDALONE_ANGLE_PLACEHOLDER_VALUE_PATTERN = re.compile(
    r"(?im)^\s*(?:[-*•]\s*)?(?:[^:\n]{1,80}:\s*)?(<\s*[A-Z][A-Z0-9_-]{1,31}\s*>)[\s.,;]*$"
)


def redact_text(value: str, mode: RedactionMode = "ai_prompt_redaction") -> str:
    """Preserve text verbatim; mode is accepted for caller compatibility only."""
    return value


def redact_value(key: str, value: Any, mode: RedactionMode = "ai_prompt_redaction", path: tuple[str, ...] = ()) -> Any:
    return deepcopy(value)


def redact_obj(value: Any, mode: RedactionMode = "ai_prompt_redaction", _path: tuple[str, ...] = ()) -> Any:
    """Copy structured content without changing keys, values or container types."""
    return deepcopy(value)


def redact_for_prompt(value: Any) -> Any:
    return deepcopy(value)


def redact_for_ui(value: Any) -> Any:
    return deepcopy(value)


def redact_provider_error_text(value: Any) -> str:
    return str(value or "")


def redact_provider_error_payload(value: str) -> Any:
    """Parse diagnostic JSON without altering provider fields or messages."""
    text = str(value or "")
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text


def preserve_for_config_storage(value: Any) -> Any:
    return deepcopy(value)


def unresolved_placeholder_values(value: str) -> list[str]:
    """Return conservative unresolved value placeholders from visible answer text."""
    text = str(value or "")
    matches = [match.group(0) for match in UNRESOLVED_PLACEHOLDER_TOKEN_PATTERN.finditer(text)]
    matches.extend(match.group(1) for match in STANDALONE_ANGLE_PLACEHOLDER_VALUE_PATTERN.finditer(text))
    generic_angle_matches = [match.group(0) for match in GENERIC_ANGLE_PLACEHOLDER_PATTERN.finditer(text)]
    if len(generic_angle_matches) >= 2:
        matches.extend(generic_angle_matches)
    return list(dict.fromkeys(match.strip() for match in matches if match.strip()))


def contains_unresolved_placeholder_values(value: str) -> bool:
    return bool(unresolved_placeholder_values(value))
