"""Metadata-only adapter for the existing public known-breach catalog flow."""

from __future__ import annotations

from reconbot.orchestration.osint_core.domains import registered_domain

from typing import Any
from urllib.parse import urlsplit

from reconbot.orchestration.osint_core import source_health as _source_health

from .collector_contract import build_source_health_row
from .models import LeakSourceReference, LeakSourceResult, SuppressedSensitiveItem
from .policy import is_browser_safe_manual_url, sanitize_reference_payload


SOURCE_NAME = "known_breach_catalog"
SOURCE_TYPE = "public_breach_catalog"
SOURCE_PROVIDER = "haveibeenpwned"
RECOMMENDED_ACTION = "Manually validate organization relevance; do not collect credentials."


def _status_from_source(source: dict[str, Any] | None, observed_count: int) -> str:
    if observed_count:
        return "partial" if source and str(source.get("status") or "") == "partial" else "completed"
    status = str((source or {}).get("status") or "")
    health_status = _source_health.source_health_status(source or {})
    if status in {"completed_no_match", "no_match"} or health_status == "no_match":
        return "no_match"
    if status == "timeout" or health_status == "timeout":
        return "timeout"
    if status == "auth_required_fallback" or health_status == "auth_required":
        return "auth_required"
    if status in {"unavailable", "rate_limited_fallback"} or health_status in {"provider_unavailable", "rate_limited"}:
        return "provider_unavailable"
    if status == "partial":
        return "partial"
    if status == "error" or health_status == "error":
        return "error"
    return "no_match"


def _source_health_row(source: dict[str, Any] | None, status: str) -> dict[str, object]:
    source = source or {}
    health_status = _source_health.source_health_status(source) if source else status
    if status == "provider_unavailable":
        health_status = "provider_unavailable"
    elif status == "auth_required":
        health_status = "auth_required"
    elif status in {"completed", "no_match", "partial", "timeout", "error"}:
        health_status = "ok" if status == "completed" else status
    errors = [str(item) for item in source.get("errors", []) if str(item or "").strip()]
    return build_source_health_row(
        source_name=SOURCE_NAME,
        status=health_status,
        source_status=status,
        endpoint=str(source.get("endpoint_url") or "https://haveibeenpwned.com/api/v3/breaches"),
        provider=SOURCE_PROVIDER,
        latency_ms=int(source.get("duration_ms") or 0) or None,
        error="; ".join(errors),
        error_class=str(source.get("error_class") or ""),
        user_message=str(source.get("user_message") or ""),
        browser_safe=False,
        render_as_clickable=False,
    )


def _matched_entity_alias(signal: dict[str, Any]) -> str:
    alias = str(signal.get("matched_alias") or "").strip()
    if alias:
        return alias
    entities = signal.get("matched_entities") if isinstance(signal.get("matched_entities"), dict) else {}
    keywords = entities.get("keywords") if isinstance(entities.get("keywords"), list) else []
    return str(next((item for item in keywords if str(item or "").strip()), "") or "")


def _reference_host(reference_url: str, source_provider: str) -> str:
    parsed = urlsplit(str(reference_url or "").strip())
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        return parsed.hostname.lower()
    provider = str(source_provider or "").strip().lower()
    if provider in {"haveibeenpwned", "hibp"}:
        return "haveibeenpwned.com"
    return ""


def _registered_domain_from_host(host: str) -> str:
    return registered_domain(str(host or ""))


def _reference_from_signal(
    signal: dict[str, Any],
    *,
    requested_target_host: str,
    requested_registered_domain: str,
) -> tuple[LeakSourceReference | None, list[SuppressedSensitiveItem]]:
    source_url = str(signal.get("source_url") or signal.get("provider_reference") or "").strip()
    snippet = ""
    evidence = signal.get("evidence") if isinstance(signal.get("evidence"), dict) else {}
    if evidence:
        snippet = str(evidence.get("snippet") or "")
    if not snippet:
        snippet = str(signal.get("snippet") or "")
    matched_alias = _matched_entity_alias(signal)
    source_provider = str(signal.get("source_provider") or SOURCE_PROVIDER)
    observed_host = _reference_host(source_url, source_provider)
    observed_registered_domain = _registered_domain_from_host(observed_host)
    payload = {
        "title": str(signal.get("breach_name") or signal.get("title") or "Public breach catalog reference"),
        "reference_url": source_url,
        "browser_safe": is_browser_safe_manual_url(source_url),
        "render_as_clickable": is_browser_safe_manual_url(source_url),
        "source_provider": source_provider,
        "matched_entities": signal.get("matched_entities") if isinstance(signal.get("matched_entities"), dict) else {},
        "match_type": str(signal.get("match_type") or "metadata_match"),
        "confidence": str(signal.get("confidence") or "medium"),
        "confidence_reason": str(signal.get("confidence_reason") or "Public breach metadata matched a generated organization alias."),
        "scope_origin": "external_verified_source",
        "requested_target_host": requested_target_host,
        "requested_registered_domain": requested_registered_domain,
        "observed_on_host": observed_host,
        "observed_on_registered_domain": observed_registered_domain,
        "applies_to_target": "unknown",
        "applies_to_parent_org": False,
        "scope_caveat": "Public third-party breach metadata may describe a parent brand, historical incident, subsidiary, or unrelated organization with a similar name.",
        "evidence_type": "public_breach_metadata",
        "breach_date": str(signal.get("breach_date") or ""),
        "added_date": str(signal.get("added_date") or ""),
        "affected_accounts": signal.get("affected_accounts") or "",
        "compromised_data_classes": [
            str(item)
            for item in (signal.get("compromised_data_classes") if isinstance(signal.get("compromised_data_classes"), list) else [])
            if str(item or "").strip()
        ],
        "redacted_snippet": snippet,
        "recommended_action": RECOMMENDED_ACTION,
    }
    if matched_alias:
        payload["matched_entities"] = dict(payload["matched_entities"])
        payload["matched_entities"]["matched_alias"] = matched_alias
    safe, suppressed = sanitize_reference_payload(payload, source_provider=SOURCE_PROVIDER)
    if not str(safe.get("reference_url") or "").strip():
        return None, suppressed
    reference = LeakSourceReference(**safe)
    reference.raw_secret_collected = False
    reference.credential_material_collected = False
    reference.account_validated = False
    reference.risk_score_impact = 0
    return reference, suppressed


def result_from_known_breach_metadata(
    *,
    signals: list[dict[str, Any]],
    source: dict[str, Any] | None,
    requested_target_host: str,
    requested_registered_domain: str,
) -> LeakSourceResult:
    references: list[LeakSourceReference] = []
    suppressed: list[SuppressedSensitiveItem] = []
    for signal in signals:
        if not isinstance(signal, dict) or str(signal.get("category") or "") != "known_breach_reference":
            continue
        reference, items = _reference_from_signal(
            signal,
            requested_target_host=requested_target_host,
            requested_registered_domain=requested_registered_domain,
        )
        suppressed.extend(items)
        if reference:
            references.append(reference)
    status = _status_from_source(source, len(references))
    notes = [
        "Metadata-only public breach catalog adapter.",
        "No credential material, raw dumps, or leaked records were collected.",
    ]
    if status == "no_match":
        notes.append("No public breach/leak metadata reference was observed from the known breach catalog.")
    elif status in {"partial", "timeout", "auth_required", "provider_unavailable", "error"}:
        source_note = str((source or {}).get("notes") or "").strip()
        if source_note:
            notes.append(source_note)
    result = LeakSourceResult(
        source_name=SOURCE_NAME,
        source_type=SOURCE_TYPE,
        status=status,
        observed_references=references,
        suppressed_sensitive_items=suppressed,
        source_health_row=_source_health_row(source, status),
        operator_notes=notes,
        risk_score_impact=0,
    )
    return result
