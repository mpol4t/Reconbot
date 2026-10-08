"""Protocol and construction helpers for future leak-source collectors."""

from __future__ import annotations

from typing import Protocol

from .models import LeakSourceResult, LeakSourceType


DISABLED_PLACEHOLDER_NOTE = "Leak-source collectors are not enabled. No darkweb collection was performed."


class LeakSourceCollector(Protocol):
    """Metadata-only collector interface.

    Implementations must not perform credential validation, collect raw leaked
    material, download dumps, or store secrets. Live collectors are intentionally
    absent from this package.
    """

    source_name: str
    source_type: LeakSourceType
    enabled_by_default: bool

    def collect_metadata_only(self, *, target_host: str, target_registered_domain: str, timeout: int) -> LeakSourceResult:
        """Return redacted metadata only."""
        ...


def build_source_health_row(
    *,
    source_name: str,
    status: str,
    source_status: str,
    endpoint: str = "",
    provider: str = "",
    latency_ms: int | None = None,
    error: str = "",
    error_class: str = "",
    user_message: str = "",
    browser_safe: bool = False,
    render_as_clickable: bool = False,
) -> dict[str, object]:
    return {
        "source": source_name,
        "provider": provider,
        "endpoint": endpoint,
        "status": status,
        "source_status": source_status,
        "latency_ms": latency_ms,
        "error": error,
        "error_class": error_class,
        "user_message": user_message,
        "browser_safe": bool(browser_safe),
        "render_as_clickable": bool(render_as_clickable) and False,
        "risk_score_impact": 0,
    }


def build_disabled_result(
    *,
    source_name: str,
    source_type: LeakSourceType,
    reason: str = DISABLED_PLACEHOLDER_NOTE,
) -> LeakSourceResult:
    return LeakSourceResult(
        source_name=source_name,
        source_type=source_type,
        status="disabled",
        observed_references=[],
        suppressed_sensitive_items=[],
        source_health_row=build_source_health_row(
            source_name=source_name,
            status="disabled",
            source_status="disabled",
            user_message=reason,
            browser_safe=False,
            render_as_clickable=False,
        ),
        operator_notes=[reason],
        risk_score_impact=0,
    )


def build_manual_review_health_row(*, source_name: str, link_label: str = "Manual review link") -> dict[str, object]:
    return build_source_health_row(
        source_name=source_name,
        status="suggestion_only",
        source_status="suggestions_generated",
        endpoint="manual",
        provider=link_label,
        user_message="Manual review link only; not a finding and not counted as a live provider request.",
        browser_safe=True,
        render_as_clickable=False,
    )
