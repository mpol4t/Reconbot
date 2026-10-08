"""Normalized models for metadata-only darkweb intelligence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


SAFETY_BOUNDARY_TR = (
    "ReconBot kimlik bilgisi, parola, hash, token, private key, session cookie, raw dump "
    "veya ham sızıntı kaydı toplamadı. Darkweb/sızıntı sonuçları sadece metadata’dır ve "
    "kurumla ilişkisi manuel doğrulanmalıdır."
)

TOR_ONION_MESSAGE_TR = (
    "ReconBot güvenli modda Tor/onion crawling yapmaz. Yalnızca metadata-only kaynaklar kullanılır."
)

REFERENCE_SCOPE_CAVEAT_TR = "Bu metadata referansı hedef sistemde aktif zafiyet olduğu anlamına gelmez."
REFERENCE_ACTION_TR = "Kurumla gerçekten ilişkili olup olmadığını manuel doğrula; kimlik bilgisi toplama."


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def empty_summary() -> dict[str, Any]:
    return {
        "observed_references": 0,
        "metadata_sources_checked": 0,
        "metadata_sources_completed": 0,
        "metadata_sources_disabled": 0,
        "metadata_sources_not_configured": 0,
        "metadata_sources_failed": 0,
        "suppressed_sensitive_items": 0,
        "credential_material_collected": False,
        "raw_secret_collected": False,
        "raw_dump_collected": False,
        "raw_leaked_records_collected": False,
        "credential_validation_performed": False,
        "risk_score_impact": "none",
    }


def tor_onion_crawling_status() -> dict[str, Any]:
    return {
        "enabled": False,
        "supported": False,
        "status": "not_supported",
        "user_message_tr": TOR_ONION_MESSAGE_TR,
    }


def source_record(
    *,
    source_id: str,
    display_name_tr: str,
    source_type: str,
    status: str,
    metadata_only: bool = True,
    coverage_impact: str = "none",
    finding_impact: str = "none",
    user_message_tr: str = "",
    operator_action_tr: str = "",
    requires_api_key: bool = False,
    api_key_env: str = "",
    api_key_configured: bool = False,
    items_loaded_count: int = 0,
    items_matched_count: int = 0,
    items_suppressed_count: int = 0,
) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "display_name_tr": display_name_tr,
        "source_type": source_type,
        "status": status,
        "metadata_only": bool(metadata_only),
        "collects_credentials": False,
        "collects_raw_dumps": False,
        "collects_raw_records": False,
        "performs_credential_validation": False,
        "coverage_impact": coverage_impact,
        "finding_impact": finding_impact,
        "user_message_tr": user_message_tr,
        "operator_action_tr": operator_action_tr,
        "requires_api_key": bool(requires_api_key),
        "api_key_env": api_key_env,
        "api_key_configured": bool(api_key_configured),
        "api_key_value_serialized": False,
        "items_loaded_count": int(items_loaded_count or 0),
        "items_matched_count": int(items_matched_count or 0),
        "items_suppressed_count": int(items_suppressed_count or 0),
        "risk_score_impact": 0,
    }


def suppressed_item(*, category: str, source_provider: str = "", count: int = 1) -> dict[str, Any]:
    return {
        "category": str(category or "sensitive_material"),
        "redaction_marker": "[redacted]",
        "safety_note_tr": (
            "Hassas içerik bastırıldı; ReconBot ham değer yerine yalnızca kategori bilgisini saklar."
        ),
        "source_provider": str(source_provider or ""),
        "count": int(count or 1),
        "raw_value_stored": False,
        "risk_score_impact": 0,
    }


def observed_reference(
    *,
    title: str,
    source_provider: str,
    source_name: str,
    source_channel: str,
    reference_url: str,
    browser_safe: bool,
    render_as_clickable: bool,
    published_at: str = "",
    breach_date: str = "",
    affected_accounts: Any = None,
    data_classes: list[str] | None = None,
    matched_entities: dict[str, Any] | None = None,
    match_type: str = "manual_metadata_match",
    confidence: str = "medium",
    confidence_reason_tr: str = "Metadata-only referans; kurum ilişkisi manuel doğrulanmalıdır.",
    scope_origin: str = "manual_metadata_import",
    applies_to_target: bool | str = "unknown",
    applies_to_parent_org: bool = False,
    requested_target_host: str = "",
    requested_registered_domain: str = "",
    observed_on_host: str = "",
    observed_on_registered_domain: str = "",
) -> dict[str, Any]:
    return {
        "title": title,
        "source_provider": source_provider,
        "source_name": source_name,
        "source_channel": source_channel,
        "reference_url": reference_url,
        "browser_safe": bool(browser_safe),
        "render_as_clickable": bool(render_as_clickable),
        "published_at": published_at,
        "breach_date": breach_date,
        "affected_accounts": affected_accounts,
        "data_classes": list(data_classes or []),
        "matched_entities": dict(matched_entities or {}),
        "match_type": match_type,
        "confidence": confidence,
        "confidence_reason_tr": confidence_reason_tr,
        "scope_origin": scope_origin,
        "applies_to_target": applies_to_target,
        "applies_to_parent_org": bool(applies_to_parent_org),
        "requested_target_host": requested_target_host,
        "requested_registered_domain": requested_registered_domain,
        "observed_on_host": observed_on_host,
        "observed_on_registered_domain": observed_on_registered_domain,
        "scope_caveat_tr": REFERENCE_SCOPE_CAVEAT_TR,
        "raw_secret_collected": False,
        "credential_material_collected": False,
        "raw_dump_collected": False,
        "raw_leaked_records_collected": False,
        "account_validated": False,
        "risk_score_impact": 0,
        "recommended_action_tr": REFERENCE_ACTION_TR,
    }
