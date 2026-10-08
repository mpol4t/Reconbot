"""Typed metadata-only leak-source result shapes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


LeakSourceType = Literal[
    "public_breach_catalog",
    "leak_metadata_api",
    "paste_metadata",
    "darkweb_index",
    "manual_review_source",
]
LeakSourceStatus = Literal[
    "completed",
    "no_match",
    "partial",
    "timeout",
    "auth_required",
    "provider_unavailable",
    "disabled",
    "not_configured",
    "invalid_config",
    "not_implemented",
    "error",
]
LeakScopeOrigin = Literal[
    "exact_target_host",
    "registered_domain",
    "parent_organization",
    "official_affiliate_domain",
    "external_verified_source",
    "manual_fallback",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class SuppressedSensitiveItem:
    """Sensitive item marker without raw leaked material."""

    category: str
    redaction_marker: str
    safety_note: str
    source_provider: str = ""
    count: int = 1
    raw_value_stored: bool = False
    risk_score_impact: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "redaction_marker": self.redaction_marker,
            "safety_note": self.safety_note,
            "source_provider": self.source_provider,
            "count": self.count,
            "raw_value_stored": False,
            "risk_score_impact": 0,
        }


@dataclass
class LeakSourceReference:
    """Public metadata reference for a future leak-source collector.

    Defaults are intentionally conservative: public third-party references are
    external context, not proof that the exact target is affected.
    """

    title: str
    reference_url: str = ""
    browser_safe: bool = False
    render_as_clickable: bool = False
    source_provider: str = ""
    provider_id: str = ""
    provider_display_name: str = ""
    observed_at: str = field(default_factory=utc_now_iso)
    matched_entities: dict[str, Any] = field(default_factory=dict)
    match_type: str = "metadata_match"
    confidence: str = "low"
    confidence_reason: str = "Metadata-only public reference; manual relevance review required."
    scope_origin: LeakScopeOrigin = "external_verified_source"
    applies_to_target: bool | str = "unknown"
    applies_to_parent_org: bool = False
    requested_target_host: str = ""
    requested_registered_domain: str = ""
    observed_on_host: str = ""
    observed_on_registered_domain: str = ""
    scope_caveat: str = "External verified public source; relevance to the exact target must be reviewed manually."
    evidence_type: str = "public_breach_metadata"
    breach_date: str = ""
    added_date: str = ""
    published_at: str = ""
    affected_accounts: int | str = ""
    compromised_data_classes: list[str] = field(default_factory=list)
    redacted_snippet: str = ""
    raw_secret_collected: bool = False
    credential_material_collected: bool = False
    account_validated: bool = False
    risk_score_impact: int = 0
    recommended_action: str = "manual relevance review"

    def __post_init__(self) -> None:
        self.raw_secret_collected = False
        self.credential_material_collected = False
        self.account_validated = False
        self.risk_score_impact = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "reference_url": self.reference_url,
            "browser_safe": bool(self.browser_safe),
            "render_as_clickable": bool(self.render_as_clickable),
            "source_provider": self.source_provider,
            "provider_id": self.provider_id,
            "provider_display_name": self.provider_display_name,
            "observed_at": self.observed_at,
            "matched_entities": dict(self.matched_entities),
            "match_type": self.match_type,
            "confidence": self.confidence,
            "confidence_reason": self.confidence_reason,
            "scope_origin": self.scope_origin,
            "applies_to_target": self.applies_to_target,
            "applies_to_parent_org": bool(self.applies_to_parent_org),
            "requested_target_host": self.requested_target_host,
            "requested_registered_domain": self.requested_registered_domain,
            "observed_on_host": self.observed_on_host,
            "observed_on_registered_domain": self.observed_on_registered_domain,
            "scope_caveat": self.scope_caveat,
            "evidence_type": self.evidence_type,
            "breach_date": self.breach_date,
            "added_date": self.added_date,
            "published_at": self.published_at,
            "affected_accounts": self.affected_accounts,
            "compromised_data_classes": list(self.compromised_data_classes),
            "redacted_snippet": self.redacted_snippet,
            "raw_secret_collected": False,
            "credential_material_collected": False,
            "account_validated": False,
            "risk_score_impact": 0,
            "recommended_action": self.recommended_action,
        }


@dataclass
class LeakSourceResult:
    """Collector output contract for future metadata-only leak sources."""

    source_name: str
    source_type: LeakSourceType
    status: LeakSourceStatus
    observed_references: list[LeakSourceReference] = field(default_factory=list)
    suppressed_sensitive_items: list[SuppressedSensitiveItem] = field(default_factory=list)
    source_health_row: dict[str, Any] = field(default_factory=dict)
    operator_notes: list[str] = field(default_factory=list)
    risk_score_impact: int = 0

    def __post_init__(self) -> None:
        self.risk_score_impact = 0
        if not self.source_health_row:
            self.source_health_row = {
                "source": self.source_name,
                "endpoint": "",
                "status": "unknown" if self.status != "disabled" else "disabled",
                "source_status": self.status,
                "latency_ms": None,
                "error": "",
                "error_class": "",
                "user_message": "",
                "browser_safe": False,
                "render_as_clickable": False,
                "risk_score_impact": 0,
            }
        self.source_health_row["render_as_clickable"] = False
        self.source_health_row["risk_score_impact"] = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "source_type": self.source_type,
            "status": self.status,
            "observed_references": [item.to_dict() for item in self.observed_references],
            "suppressed_sensitive_items": [item.to_dict() for item in self.suppressed_sensitive_items],
            "source_health_row": dict(self.source_health_row),
            "operator_notes": list(self.operator_notes),
            "risk_score_impact": 0,
        }
