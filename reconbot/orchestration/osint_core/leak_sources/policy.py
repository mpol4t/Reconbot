"""Safety policy for future leak-source collectors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

from .models import SuppressedSensitiveItem
from .redaction import detect_sensitive_categories, marker_for_category, redact_text


SAFETY_BOUNDARY = {
    "allowed": [
        "public breach catalog metadata",
        "public report URLs",
        "breach names",
        "breach dates",
        "affected account counts",
        "compromised data class names",
        "redacted snippets",
        "source availability/status",
        "browser-safe manual review links",
    ],
    "forbidden": [
        "passwords",
        "password hashes",
        "API keys",
        "access tokens",
        "private keys",
        "session cookies",
        "full database dumps",
        "personal records",
        "credential validation",
        "login attempts",
        "buying or selling data",
        "scraping private forums requiring unauthorized access",
        "storing raw leaked material",
    ],
}


SAFE_REFERENCE_INPUT_FIELDS = {
    "title",
    "reference_url",
    "source_provider",
    "provider_id",
    "provider_display_name",
    "observed_at",
    "matched_entities",
    "match_type",
    "confidence",
    "confidence_reason",
    "scope_origin",
    "applies_to_target",
    "applies_to_parent_org",
    "requested_target_host",
    "requested_registered_domain",
    "observed_on_host",
    "observed_on_registered_domain",
    "scope_caveat",
    "evidence_type",
    "breach_date",
    "added_date",
    "published_at",
    "affected_accounts",
    "compromised_data_classes",
    "redacted_snippet",
    "recommended_action",
    "browser_safe",
    "render_as_clickable",
}


@dataclass(frozen=True)
class LeakSourceClassification:
    source_type: str
    description: str
    enabled_by_default: bool
    metadata_only: bool
    raw_content_allowed: bool
    notes: str


LEAK_SOURCE_CLASSIFICATIONS = {
    "public_breach_catalog": LeakSourceClassification(
        source_type="public_breach_catalog",
        description="HIBP-style public breach catalog metadata.",
        enabled_by_default=True,
        metadata_only=True,
        raw_content_allowed=False,
        notes="Metadata only: breach name, date, public report URL, account counts, and data class names.",
    ),
    "leak_metadata_api": LeakSourceClassification(
        source_type="leak_metadata_api",
        description="Authenticated or unauthenticated metadata API.",
        enabled_by_default=False,
        metadata_only=True,
        raw_content_allowed=False,
        notes="API keys may be required; collectors must never store returned secrets or validate accounts.",
    ),
    "paste_metadata": LeakSourceClassification(
        source_type="paste_metadata",
        description="Paste metadata source.",
        enabled_by_default=False,
        metadata_only=True,
        raw_content_allowed=False,
        notes="Title, URL, and timestamp only unless content can be safely summarized and redacted.",
    ),
    "darkweb_index": LeakSourceClassification(
        source_type="darkweb_index",
        description="Darkweb index metadata source.",
        enabled_by_default=False,
        metadata_only=True,
        raw_content_allowed=False,
        notes="Disabled by default, requires explicit opt-in, metadata only, no dumps or credential material.",
    ),
    "manual_review_source": LeakSourceClassification(
        source_type="manual_review_source",
        description="Browser-safe manual review link.",
        enabled_by_default=False,
        metadata_only=True,
        raw_content_allowed=False,
        notes="Suggestion only, not a finding, and not counted as a live source request.",
    ),
}


def is_browser_safe_manual_url(url: str) -> bool:
    parsed = urlsplit(str(url or "").strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def safety_note_for_category(category: str) -> str:
    return (
        f"Suppressed {category}; ReconBot stores only a redaction marker and category, "
        "never raw leaked material or credential values."
    )


def sanitize_reference_payload(payload: Mapping[str, Any], *, source_provider: str = "") -> tuple[dict[str, Any], list[SuppressedSensitiveItem]]:
    """Return a safe metadata payload plus suppression markers.

    Unknown raw fields are dropped. Known display fields are redacted before
    storage. Credential/secret flags are forced false regardless of input.
    """

    safe: dict[str, Any] = {}
    suppressed: list[SuppressedSensitiveItem] = []
    for key, value in payload.items():
        if key not in SAFE_REFERENCE_INPUT_FIELDS:
            text = str(value or "")
            for category in sorted(detect_sensitive_categories(text)):
                suppressed.append(
                    SuppressedSensitiveItem(
                        category=category,
                        redaction_marker=marker_for_category(category),
                        safety_note=safety_note_for_category(category),
                        source_provider=source_provider,
                    )
                )
            continue
        if isinstance(value, str):
            categories = detect_sensitive_categories(value)
            if categories:
                for category in sorted(categories):
                    suppressed.append(
                        SuppressedSensitiveItem(
                            category=category,
                            redaction_marker=marker_for_category(category),
                            safety_note=safety_note_for_category(category),
                            source_provider=source_provider,
                        )
                    )
                safe[key] = redact_text(value)
            else:
                safe[key] = redact_text(value)
        else:
            safe[key] = value
    safe["raw_secret_collected"] = False
    safe["credential_material_collected"] = False
    safe["account_validated"] = False
    safe["risk_score_impact"] = 0
    return safe, suppressed
