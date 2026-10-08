"""Central safety checks for metadata-only darkweb inputs."""

from __future__ import annotations

from reconbot.orchestration.osint_core.domains import registered_domain

import re
from typing import Any
from urllib.parse import urlsplit

from reconbot.orchestration.osint_core.leak_sources.redaction import detect_sensitive_categories


RAW_DUMP_LINE_RE = re.compile(r"(?m)^[^,\n]{1,80},[^,\n]{1,120},[^,\n]{1,120}(?:,[^,\n]{0,120}){1,}$")
CSV_HEADER_RE = re.compile(r"(?i)\b(email|username|user|password|hash|token|cookie)\b.*[,;].*\b(password|hash|token|cookie|email)\b")


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        values: list[str] = []
        for nested in value.values():
            values.extend(_string_values(nested))
        return values
    if isinstance(value, (list, tuple)):
        values: list[str] = []
        for nested in value:
            values.extend(_string_values(nested))
        return values
    return []


def sensitive_categories(value: Any) -> set[str]:
    categories: set[str] = set()
    for text in _string_values(value):
        categories.update(detect_sensitive_categories(text))
        lines = [line for line in text.splitlines() if line.strip()]
        if len(lines) >= 3 and (CSV_HEADER_RE.search(text) or sum(1 for line in lines if RAW_DUMP_LINE_RE.search(line)) >= 2):
            categories.add("raw_dump")
            categories.add("raw_leaked_records")
    return categories


def is_safe_metadata_item(item: Any) -> tuple[bool, set[str]]:
    categories = sensitive_categories(item)
    return not categories, categories


def safe_reference_url(url: str) -> tuple[bool, bool, str, str]:
    raw = str(url or "").strip()
    parsed = urlsplit(raw)
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "https" and parsed.netloc and not host.endswith(".onion"):
        return True, True, host, _registered_domain(host)
    if host.endswith(".onion") or parsed.scheme == "onion":
        return False, False, host, ""
    return False, False, host, _registered_domain(host)


def _registered_domain(host: str) -> str:
    return registered_domain(str(host or ""))

