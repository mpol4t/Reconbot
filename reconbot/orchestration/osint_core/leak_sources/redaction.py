"""Redaction helpers for future metadata-only leak-source collectors."""

from __future__ import annotations

import re


PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
LABELED_HASH_RE = re.compile(r"(?i)\b(password[_-]?hash|hash)\s*[:=]\s*['\"]?[A-Fa-f0-9$./+]{16,}['\"]?")
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
LONG_BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{48,}={0,2}|[A-Za-z0-9_-]{48,})\b")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|secret|client[_-]?secret|authorization)\s*[:=]\s*['\"]?[^'\"\s;,&]{6,}"
)
PASSWORD_ASSIGNMENT_RE = re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s;,&]{3,}")
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{10,}")
COOKIE_RE = re.compile(
    r"(?i)\b(session(?:id)?|session[_-]?token|cookie|set-cookie|connect\.sid)\s*[:=]\s*['\"]?[^'\"\s;,&]{6,}"
)
EMAIL_PASSWORD_PAIR_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}:[^\s;,&]{3,}\b"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\w)(\+\d{1,3})[\s.-]*(\d)\d{2}[\s.-]*\d{3}[\s.-]*\d{2}(\d{2})(?!\w)")


SENSITIVE_CATEGORY_MARKERS = {
    "private_key": "[redacted_private_key]",
    "api_key": "[redacted]",
    "access_token": "[redacted]",
    "password": "[redacted_password]",
    "password_hash": "[redacted_hash]",
    "credential_pair": "[redacted_credential_pair]",
    "session_cookie": "[redacted_session]",
    "long_secret_blob": "[redacted_blob]",
}


def redact_email(value: str, *, public_contact_context: bool = False) -> str:
    text = str(value or "")
    if public_contact_context:
        return text

    def replace(match: re.Match[str]) -> str:
        email = match.group(0)
        local, domain = email.split("@", 1)
        if not local:
            return f"***@{domain}"
        return f"{local[:1]}***@{domain}"

    return EMAIL_RE.sub(replace, text)


def redact_phone(value: str) -> str:
    text = str(value or "")
    return PHONE_RE.sub(lambda match: f"{match.group(1)} {match.group(2)}** *** **{match.group(3)}", text)


def detect_sensitive_categories(value: str) -> set[str]:
    text = str(value or "")
    categories: set[str] = set()
    if PRIVATE_KEY_RE.search(text):
        categories.add("private_key")
    if SECRET_ASSIGNMENT_RE.search(text) or BEARER_RE.search(text):
        lowered = text.lower()
        categories.add("access_token" if "token" in lowered or "bearer" in lowered else "api_key")
    if PASSWORD_ASSIGNMENT_RE.search(text):
        categories.add("password")
    if LABELED_HASH_RE.search(text):
        categories.add("password_hash")
    if COOKIE_RE.search(text):
        categories.add("session_cookie")
    if EMAIL_PASSWORD_PAIR_RE.search(text):
        categories.add("credential_pair")
    if LONG_HEX_RE.search(text) or LONG_BASE64_RE.search(text):
        categories.add("long_secret_blob")
    return categories


def marker_for_category(category: str) -> str:
    return SENSITIVE_CATEGORY_MARKERS.get(str(category or ""), "[redacted]")


def redact_text(value: str, *, public_contact_context: bool = False) -> str:
    text = str(value or "")
    text = PRIVATE_KEY_RE.sub("[redacted_private_key]", text)
    text = LABELED_HASH_RE.sub(lambda match: f"{match.group(1)}=[redacted_hash]", text)
    text = SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[redacted]", text)
    text = PASSWORD_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[redacted_password]", text)
    text = BEARER_RE.sub("Bearer [redacted]", text)
    text = COOKIE_RE.sub(lambda match: f"{match.group(1)}=[redacted_session]", text)
    text = EMAIL_PASSWORD_PAIR_RE.sub("[redacted_credential_pair]", text)
    text = LONG_HEX_RE.sub("[redacted_hash]", text)
    text = LONG_BASE64_RE.sub("[redacted_blob]", text)
    text = redact_email(text, public_contact_context=public_contact_context)
    return redact_phone(text)
