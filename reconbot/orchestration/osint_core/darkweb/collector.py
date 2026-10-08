"""Aggregate safe metadata-only darkweb intelligence for OSINT output."""

from __future__ import annotations

from reconbot.orchestration.osint_core.domains import registered_domain

import os
from typing import Any, Mapping

from .manual_import import collect_manual_metadata_import
from .models import SAFETY_BOUNDARY_TR, empty_summary, observed_reference, source_record, tor_onion_crawling_status
from .provider_registry import (
    CUSTOM_HTTPS_DARKWEB_METADATA_PROVIDER,
    TOR_ONION_CRAWL_UNSUPPORTED,
    validate_custom_https_provider,
)
from .safety import safe_reference_url


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _registered_domain(host: str) -> str:
    return registered_domain(str(host or ""))


def _status_from_leak_status(status: str) -> str:
    mapping = {
        "completed": "completed",
        "no_match": "no_match",
        "completed_no_match": "completed_no_match",
        "disabled": "disabled",
        "not_configured": "not_configured",
        "invalid_config": "invalid_config",
        "auth_required": "auth_required",
        "provider_unavailable": "provider_unavailable",
        "timeout": "timeout",
        "error": "error",
        "partial": "partial",
        "not_implemented": "not_configured",
    }
    return mapping.get(status, status or "error")


def _coverage_impact(status: str, *, default_disabled_low: bool = False) -> str:
    if status in {"completed", "completed_no_match", "no_match"}:
        return "none"
    if status in {"disabled", "not_configured"}:
        return "low" if default_disabled_low else "medium"
    if status in {"timeout", "provider_unavailable", "auth_required", "invalid_config", "error", "partial"}:
        return "medium"
    return "low"


def _finding_impact(status: str) -> str:
    if status in {"completed", "completed_no_match", "no_match", "disabled"}:
        return "none"
    if status in {"not_configured", "invalid_config"}:
        return "manual_review_needed"
    return "may_hide_findings"


def _message_for_source(source_id: str, status: str) -> str:
    if source_id == "known_breach_catalog" and status in {"no_match", "completed_no_match"}:
        return "Herkese açık ihlal kataloğunda eşleşen metadata referansı görülmedi."
    if source_id == "known_breach_catalog" and status == "completed":
        return "Herkese açık ihlal kataloğu metadata referansı gözlemledi."
    if source_id == "leak_metadata_feed" and status == "disabled":
        return "Metadata feed sağlayıcısı kapalı; Settings > OSINT > Darkweb / Leak / Breach Metadata Feed üzerinden etkinleştirilebilir."
    if status == "not_configured":
        return "Kaynak açık ama yapılandırılmamış."
    if status == "disabled":
        return "Kaynak kurulu ama kapalı."
    if status == "timeout":
        return "Kaynak zaman aşımına uğradı; kapsam kısmi kaldı."
    if status == "provider_unavailable":
        return "Kaynağa bu çalıştırmada erişilemedi; kapsam kısmi kaldı."
    if status == "auth_required":
        return "Kaynak kimlik doğrulama gerektiriyor; API token/env yapılandırılmalı."
    if status == "completed":
        return "Kaynak metadata-only olarak tamamlandı."
    if status in {"no_match", "completed_no_match"}:
        return "Kaynak tamamlandı; eşleşen metadata referansı görülmedi."
    return "Kaynak durumu operator tarafından incelenmeli."


def _action_for_status(status: str) -> str:
    if status in {"completed", "completed_no_match", "no_match", "disabled"}:
        return "Aksiyon yok." if status != "disabled" else "Gerekliyse kaynağı etkinleştir."
    if status in {"not_configured", "auth_required"}:
        return "Sağlayıcı ayarlarını ve gerekli env var adını yapılandır."
    if status in {"timeout", "provider_unavailable"}:
        return "Daha sonra tekrar dene."
    return "Kaynak ayarlarını ve sağlayıcı durumunu kontrol et."


def _source_from_leak_result(result: Mapping[str, Any]) -> dict[str, Any]:
    source_name = _clean(result.get("source_name"))
    source_type = _clean(result.get("source_type"))
    status = _status_from_leak_status(_clean(result.get("status")))
    health = _as_dict(result.get("source_health_row"))
    source_id = "known_breach_catalog" if source_name == "known_breach_catalog" else "leak_metadata_feed"
    display = "Known Breach Catalog" if source_id == "known_breach_catalog" else "Metadata feed sağlayıcısı"
    api_key_env = _clean(health.get("api_key_env") or health.get("apiKeyEnv"))
    row = source_record(
        source_id=source_id,
        display_name_tr=display,
        source_type="public_breach_catalog" if source_id == "known_breach_catalog" else "metadata_feed",
        status=status,
        coverage_impact=_coverage_impact(status, default_disabled_low=source_id == "leak_metadata_feed"),
        finding_impact=_finding_impact(status),
        user_message_tr=_message_for_source(source_id, status),
        operator_action_tr=_action_for_status(status),
        requires_api_key=bool(api_key_env),
        api_key_env=api_key_env,
        api_key_configured=bool(api_key_env and os.environ.get(api_key_env)),
        items_loaded_count=int(health.get("items_loaded_count") or 0),
        items_matched_count=len(_as_list(result.get("observed_references"))),
        items_suppressed_count=len(_as_list(result.get("suppressed_sensitive_items"))),
    )
    row["collector_name"] = _clean(health.get("collector_name") or health.get("collector"))
    row["provider_id"] = _clean(health.get("provider_id"))
    row["provider_display_name"] = _clean(health.get("provider_display_name"))
    row["provider_validation_message"] = _clean(health.get("provider_validation_message"))
    row["provider_validation_status"] = _clean(health.get("provider_validation_status"))
    row["runtime_source_name"] = source_name
    return row


def _reference_from_leak(reference: Mapping[str, Any], *, source_name: str) -> dict[str, Any]:
    url = _clean(reference.get("reference_url"))
    browser_safe, clickable, observed_host, observed_registered = safe_reference_url(url)
    data_classes = _as_list(reference.get("compromised_data_classes") or reference.get("data_classes"))
    source_channel = "public_breach_catalog" if source_name == "known_breach_catalog" else "darkweb_metadata_index"
    return observed_reference(
        title=_clean(reference.get("title")) or "Darkweb metadata reference",
        source_provider=_clean(reference.get("source_provider")) or source_name,
        source_name=source_name,
        source_channel=source_channel,
        reference_url=url,
        browser_safe=browser_safe,
        render_as_clickable=clickable,
        published_at=_clean(reference.get("published_at") or reference.get("added_date")),
        breach_date=_clean(reference.get("breach_date")),
        affected_accounts=reference.get("affected_accounts") if reference.get("affected_accounts") not in ("", None) else None,
        data_classes=[str(item) for item in data_classes if str(item or "").strip()],
        matched_entities=_as_dict(reference.get("matched_entities")),
        match_type=_clean(reference.get("match_type")) or "metadata_match",
        confidence=_clean(reference.get("confidence")) or "medium",
        confidence_reason_tr="Metadata-only referans; kurum ilişkisi manuel doğrulanmalıdır.",
        scope_origin=_clean(reference.get("scope_origin")) or "external_verified_source",
        applies_to_target=reference.get("applies_to_target", "unknown"),
        applies_to_parent_org=bool(reference.get("applies_to_parent_org")),
        requested_target_host=_clean(reference.get("requested_target_host")),
        requested_registered_domain=_clean(reference.get("requested_registered_domain")),
        observed_on_host=observed_host or _clean(reference.get("observed_on_host")),
        observed_on_registered_domain=observed_registered or _clean(reference.get("observed_on_registered_domain")) or _registered_domain(observed_host),
    )


def _custom_https_source(settings: Mapping[str, Any]) -> dict[str, Any]:
    status, message = validate_custom_https_provider(dict(settings))
    api_key_env = _clean(settings.get("apiKeyEnv") or settings.get("api_key_env")) or "DARKWEB_METADATA_TOKEN"
    return source_record(
        source_id=CUSTOM_HTTPS_DARKWEB_METADATA_PROVIDER,
        display_name_tr="Custom HTTPS darkweb metadata sağlayıcısı",
        source_type="trusted_metadata_provider",
        status=status,
        coverage_impact=_coverage_impact(status, default_disabled_low=True),
        finding_impact=_finding_impact(status),
        user_message_tr=message,
        operator_action_tr="Yalnızca güvenilir metadata-only HTTPS sağlayıcı yapılandır.",
        requires_api_key=bool(api_key_env),
        api_key_env=api_key_env,
        api_key_configured=bool(api_key_env and os.environ.get(api_key_env)),
    )


def _tor_source() -> dict[str, Any]:
    return source_record(
        source_id=TOR_ONION_CRAWL_UNSUPPORTED,
        display_name_tr="Tor/onion crawling",
        source_type="unsupported_tor_crawl",
        status="not_supported",
        metadata_only=False,
        coverage_impact="low",
        finding_impact="none",
        user_message_tr="Tor/onion crawling desteklenmiyor ve bu çalıştırmada yapılmadı.",
        operator_action_tr="Aksiyon yok; ReconBot safe mode Tor/onion crawling yapmaz.",
    )


def _overall_status(enabled: bool, sources: list[dict[str, Any]], observed_count: int) -> str:
    if not enabled:
        return "disabled"
    statuses = {str(item.get("status") or "") for item in sources}
    if any(status in statuses for status in {"invalid_config"}):
        return "invalid_config"
    if any(status in statuses for status in {"timeout", "provider_unavailable", "auth_required", "error", "partial"}):
        return "partial"
    if observed_count:
        return "completed"
    if statuses and statuses.issubset({"disabled", "not_supported"}):
        return "disabled"
    if any(status in statuses for status in {"not_configured"}):
        return "not_configured"
    return "no_match"


def _summary_from_sources(sources: list[dict[str, Any]], references: list[dict[str, Any]], suppressed: list[dict[str, Any]]) -> dict[str, Any]:
    summary = empty_summary()
    checked_statuses = {"completed", "completed_no_match", "no_match", "partial", "timeout", "provider_unavailable", "auth_required", "error"}
    summary["observed_references"] = len(references)
    summary["metadata_sources_checked"] = sum(1 for item in sources if item.get("status") in checked_statuses)
    summary["metadata_sources_completed"] = sum(1 for item in sources if item.get("status") in {"completed", "completed_no_match", "no_match"})
    summary["metadata_sources_disabled"] = sum(1 for item in sources if item.get("status") == "disabled")
    summary["metadata_sources_not_configured"] = sum(1 for item in sources if item.get("status") == "not_configured")
    summary["metadata_sources_failed"] = sum(1 for item in sources if item.get("status") in {"partial", "timeout", "provider_unavailable", "auth_required", "invalid_config", "error"})
    summary["suppressed_sensitive_items"] = len(suppressed)
    return summary


def build_darkweb_intelligence(
    *,
    enabled: bool,
    target_context: Mapping[str, Any],
    leak_intelligence: Mapping[str, Any] | None,
    settings: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    cfg = settings if isinstance(settings, Mapping) else {}
    leak = leak_intelligence if isinstance(leak_intelligence, Mapping) else {}
    sources: list[dict[str, Any]] = []
    references: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []

    for result in _as_list(leak.get("results")):
        if not isinstance(result, Mapping):
            continue
        source_name = _clean(result.get("source_name"))
        sources.append(_source_from_leak_result(result))
        for reference in _as_list(result.get("observed_references")):
            if isinstance(reference, Mapping):
                references.append(_reference_from_leak(reference, source_name=source_name))
        for item in _as_list(result.get("suppressed_sensitive_items")):
            if isinstance(item, dict):
                suppressed.append({**item, "raw_value_stored": False, "risk_score_impact": 0})

    manual = collect_manual_metadata_import(
        config=_as_dict(cfg.get("manualMetadataImport") or cfg.get("manual_metadata_import")),
        requested_target_host=_clean(target_context.get("target_host") or target_context.get("target_domain")),
        requested_registered_domain=_clean(target_context.get("target_registered_domain")),
        organization_aliases=[str(item) for item in _as_list(target_context.get("organization_aliases"))],
    )
    sources.append(_as_dict(manual.get("source")))
    references.extend([item for item in _as_list(manual.get("observed_references")) if isinstance(item, dict)])
    suppressed.extend([item for item in _as_list(manual.get("suppressed_sensitive_items")) if isinstance(item, dict)])

    custom_cfg = _as_dict(cfg.get("customHttpsProvider") or cfg.get("custom_https_provider"))
    sources.append(_custom_https_source(custom_cfg))
    sources.append(_tor_source())

    summary = _summary_from_sources(sources, references, suppressed)
    status = _overall_status(bool(enabled), sources, len(references))
    return {
        "enabled": bool(enabled),
        "status": status,
        "mode": "metadata_only",
        "tor_onion_crawling": tor_onion_crawling_status(),
        "summary": summary,
        "sources": sources,
        "observed_references": references,
        "suppressed_sensitive_items": suppressed,
        "safety_boundary_tr": SAFETY_BOUNDARY_TR,
    }
