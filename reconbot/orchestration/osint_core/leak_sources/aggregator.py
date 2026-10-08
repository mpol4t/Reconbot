"""Aggregate metadata-only leak-source collector output for OSINT JSON."""

from __future__ import annotations

from typing import Any

from .models import LeakSourceResult, SuppressedSensitiveItem
from .metadata_feed import result_from_metadata_feed
from .policy import safety_note_for_category
from .redaction import detect_sensitive_categories, marker_for_category, redact_text
from .public_breach_catalog import result_from_known_breach_metadata


SENSITIVE_MATERIAL_BOUNDARY = (
    "ReconBot did not collect credentials, passwords, hashes, tokens, private keys, "
    "session cookies, raw dumps, or raw leaked records. Leak-source results are "
    "metadata-only and require manual relevance validation."
)


ACTIVE_STATUSES = {"completed", "no_match", "partial", "timeout", "auth_required", "provider_unavailable", "error"}
PROBLEM_STATUSES = {"partial", "timeout", "auth_required", "provider_unavailable", "invalid_config", "not_implemented", "error"}


def _result_status(results: list[dict[str, Any]], enabled: bool) -> str:
    if not enabled:
        return "disabled"
    if not results:
        return "no_match"
    statuses = [str(result.get("status") or "") for result in results]
    active_statuses = [status for status in statuses if status in ACTIVE_STATUSES]
    if any(status == "completed" for status in statuses) and any(status in PROBLEM_STATUSES for status in statuses):
        return "partial"
    if any(status == "completed" for status in statuses):
        return "completed"
    if any(status == "partial" for status in statuses):
        return "partial"
    if any(status == "invalid_config" for status in statuses):
        return "invalid_config"
    if any(status == "not_implemented" for status in statuses):
        return "not_implemented"
    if active_statuses and all(status == "no_match" for status in active_statuses):
        return "no_match"
    if any(status == "timeout" for status in statuses):
        return "timeout"
    if any(status == "auth_required" for status in statuses):
        return "auth_required"
    if any(status == "provider_unavailable" for status in statuses):
        return "provider_unavailable"
    if any(status == "error" for status in statuses):
        return "error"
    if any(status == "not_configured" for status in statuses):
        return "not_configured"
    return "no_match"


def _suppressed_item(category: str, source_provider: str = "") -> dict[str, Any]:
    return SuppressedSensitiveItem(
        category=category,
        redaction_marker=marker_for_category(category),
        safety_note=safety_note_for_category(category),
        source_provider=source_provider,
    ).to_dict()


def _sanitize_tree(value: Any, suppressed: list[dict[str, Any]], *, source_provider: str = "") -> Any:
    if isinstance(value, str):
        categories = detect_sensitive_categories(value)
        if categories:
            for category in sorted(categories):
                suppressed.append(_suppressed_item(category, source_provider=source_provider))
            return redact_text(value)
        return redact_text(value)
    if isinstance(value, list):
        return [_sanitize_tree(item, suppressed, source_provider=source_provider) for item in value]
    if isinstance(value, dict):
        return {
            str(key): _sanitize_tree(item, suppressed, source_provider=source_provider)
            for key, item in value.items()
            if str(key) not in {"raw_dump", "raw_content", "password", "password_hash", "api_key", "token", "private_key"}
        }
    return value


def _safe_result_dict(result: LeakSourceResult) -> dict[str, Any]:
    serialized = result.to_dict()
    suppressed: list[dict[str, Any]] = []
    source_provider = ""
    for reference in serialized.get("observed_references", []):
        if isinstance(reference, dict):
            source_provider = str(reference.get("source_provider") or source_provider)
    safe = _sanitize_tree(serialized, suppressed, source_provider=source_provider)
    safe["risk_score_impact"] = 0
    for reference in safe.get("observed_references", []) if isinstance(safe.get("observed_references"), list) else []:
        if not isinstance(reference, dict):
            continue
        reference["raw_secret_collected"] = False
        reference["credential_material_collected"] = False
        reference["account_validated"] = False
        reference["risk_score_impact"] = 0
    existing = safe.get("suppressed_sensitive_items") if isinstance(safe.get("suppressed_sensitive_items"), list) else []
    safe["suppressed_sensitive_items"] = existing + suppressed
    return safe


def build_leak_intelligence(
    *,
    enabled: bool,
    signals: list[dict[str, Any]],
    sources: list[dict[str, Any]],
    requested_target_host: str,
    requested_registered_domain: str,
    organization_aliases: list[str] | None = None,
    metadata_feed_config: dict[str, Any] | None = None,
    known_breach_enabled: bool | None = None,
) -> dict[str, Any]:
    known_enabled = bool(enabled if known_breach_enabled is None else known_breach_enabled)
    known_source = next(
        (item for item in sources if isinstance(item, dict) and str(item.get("name") or "") == "known_breach_catalog"),
        None,
    )
    results: list[LeakSourceResult] = []
    if known_enabled and known_source is not None:
        results.append(
            result_from_known_breach_metadata(
                signals=signals,
                source=known_source,
                requested_target_host=requested_target_host,
                requested_registered_domain=requested_registered_domain,
            )
        )
    results.append(
        result_from_metadata_feed(
            config=metadata_feed_config or {},
            requested_target_host=requested_target_host,
            requested_registered_domain=requested_registered_domain,
            organization_aliases=organization_aliases or [],
        )
    )
    serialized_results = [_safe_result_dict(result) for result in results]
    observed_count = sum(
        len(result.get("observed_references", []) if isinstance(result.get("observed_references"), list) else [])
        for result in serialized_results
    )
    suppressed_count = sum(
        len(result.get("suppressed_sensitive_items", []) if isinstance(result.get("suppressed_sensitive_items"), list) else [])
        for result in serialized_results
    )
    source_health = [
        result.get("source_health_row")
        for result in serialized_results
        if isinstance(result.get("source_health_row"), dict)
    ]
    enabled_collectors_count = sum(
        1
        for result in serialized_results
        if str(result.get("status") or "") not in {"disabled"}
    )
    active_collection_performed = any(
        str(result.get("status") or "") in ACTIVE_STATUSES
        for result in serialized_results
    )
    overall_enabled = bool(enabled or enabled_collectors_count)
    status = _result_status(serialized_results, enabled=overall_enabled)
    return {
        "enabled": overall_enabled,
        "status": status,
        "live_collection_performed": active_collection_performed,
        "enabled_collectors_count": enabled_collectors_count,
        "summary": {
            "observed_references": observed_count,
            "suppressed_sensitive_items": suppressed_count,
            "credential_material_collected": False,
            "raw_secret_collected": False,
            "risk_score_impact": "none",
        },
        "results": serialized_results,
        "source_health": source_health,
        "safety_boundary": SENSITIVE_MATERIAL_BOUNDARY,
    }
