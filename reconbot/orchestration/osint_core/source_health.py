"""Centralized OSINT source-health row and counter aggregation."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


LIVE_SOURCE_NAMES = {"certificate_transparency", "historical_urls", "public_code_search", "known_breach_catalog"}
MAJOR_SOURCE_NAMES = {"certificate_transparency", "historical_urls", "public_code_search", "known_breach_catalog"}
ENDPOINT_MAP = {
    "certificate_transparency": "https://crt.sh/",
    "historical_urls": "https://web.archive.org/cdx",
    "public_code_search": "https://api.github.com/search/code",
    "known_breach_catalog": "https://haveibeenpwned.com/api/v3/breaches",
    "safe_search_dorks": "manual",
    "leak_metadata_feed": "manual",
    "organization_intelligence": "manual",
    "infrastructure_intelligence": "manual",
}
DISPLAY_NAMES = {
    "certificate_transparency": "crt.sh / Certificate Transparency",
    "historical_urls": "Wayback CDX",
    "public_code_search": "GitHub Code Search",
    "known_breach_catalog": "Known Breach Catalog",
    "safe_search_dorks": "Safe Search Dorks",
    "leak_metadata_feed": "Metadata Feed",
    "organization_intelligence": "Organization Intelligence",
    "infrastructure_intelligence": "Infrastructure Intelligence",
}
CATEGORIES = {
    "certificate_transparency": "ct",
    "historical_urls": "archive",
    "public_code_search": "code_search",
    "known_breach_catalog": "breach_metadata",
    "safe_search_dorks": "manual_suggestions",
    "leak_metadata_feed": "breach_metadata",
    "organization_intelligence": "entity_intelligence",
    "infrastructure_intelligence": "infrastructure",
}
API_KEY_ENV = {
    "public_code_search": "GITHUB_TOKEN",
}
COVERAGE_IMPACT_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
STATUS_ALIASES = {
    "ok": "completed",
    "slow": "completed",
    "no_match": "completed_no_match",
    "unavailable": "provider_unavailable",
    "auth_required_fallback": "auth_required",
    "rate_limited_fallback": "partial",
    "suggestions_generated": "suggestions_only",
}


def provider_issue_details(source: dict[str, Any]) -> dict[str, str]:
    providers = source.get("provider_results") if isinstance(source.get("provider_results"), list) else []
    status_priority = {"provider_unavailable": 3, "timeout": 2, "error": 1}
    best_status = ""
    error_classes: list[str] = []
    messages: list[str] = []
    for provider in providers:
        if not isinstance(provider, dict):
            continue
        provider_status = str(provider.get("status") or "")
        if provider_status == "unavailable":
            candidate_status = "provider_unavailable"
        elif provider_status == "timeout":
            candidate_status = "timeout"
        elif provider_status == "error":
            candidate_status = "error"
        else:
            candidate_status = ""
        if candidate_status and status_priority.get(candidate_status, 0) > status_priority.get(best_status, 0):
            best_status = candidate_status
        error_class = str(provider.get("error_class") or "").strip()
        if error_class and error_class not in error_classes:
            error_classes.append(error_class)
        user_message = str(provider.get("user_message") or "").strip()
        if user_message and user_message not in messages:
            messages.append(user_message)
    return {
        "status": best_status,
        "error_class": ", ".join(error_classes),
        "user_message": " ".join(messages),
    }


def source_health_status(source: dict[str, Any]) -> str:
    status = str(source.get("status") or "")
    errors = " ".join(str(item) for item in source.get("errors", []) if str(item or "").strip()).lower()
    if status in {"completed", "completed_matched"}:
        duration = int(source.get("duration_ms") or 0)
        return "slow" if duration > 5000 else "ok"
    if status in {"no_match", "completed_no_match"}:
        return "no_match"
    if status == "timeout":
        return "timeout"
    if status == "unavailable":
        return "provider_unavailable"
    if status == "partial":
        provider_status = provider_issue_details(source).get("status")
        if provider_status:
            return str(provider_status)
        return "timeout" if "timeout" in errors else "error" if errors else "unknown"
    if status == "error":
        if "429" in errors or "rate" in errors:
            return "rate_limited"
        return "error"
    if status == "auth_required_fallback":
        return "auth_required"
    if status == "rate_limited_fallback":
        return "rate_limited"
    if status == "suggestions_generated":
        return "suggestions_generated"
    if status == "skipped":
        return "unknown"
    return "unknown"


def _configured_api_key(env_name: str) -> bool:
    import os

    return bool(env_name and os.environ.get(env_name))


def _provider_http_status(source: dict[str, Any]) -> int:
    providers = source.get("provider_results") if isinstance(source.get("provider_results"), list) else []
    for provider in providers:
        if not isinstance(provider, dict):
            continue
        try:
            value = int(provider.get("http_status") or 0)
        except Exception:
            value = 0
        if value:
            return value
    try:
        return int(source.get("http_status") or 0)
    except Exception:
        return 0


def _normalize_status(source: dict[str, Any], health_status: str) -> str:
    raw_status = str(source.get("status") or source.get("source_status") or "")
    if raw_status == "partial" and health_status in {"timeout", "provider_unavailable", "error"}:
        return health_status
    if health_status in STATUS_ALIASES:
        return STATUS_ALIASES[health_status]
    if raw_status in STATUS_ALIASES:
        return STATUS_ALIASES[raw_status]
    if raw_status in {
        "completed",
        "completed_no_match",
        "partial",
        "timeout",
        "auth_required",
        "provider_unavailable",
        "disabled",
        "skipped",
        "suggestions_only",
        "error",
    }:
        return raw_status
    if raw_status == "no_match":
        return "completed_no_match"
    if raw_status == "unavailable":
        return "provider_unavailable"
    if raw_status == "suggestions_generated":
        return "suggestions_only"
    return "skipped" if raw_status == "skipped" else "error" if health_status == "error" else "skipped"


def _default_coverage_impact(source_name: str, status: str) -> str:
    if status in {"completed", "completed_no_match"}:
        return "none"
    if source_name == "public_code_search" and status == "auth_required":
        return "high"
    if source_name in {"certificate_transparency", "historical_urls"} and status in {"partial", "timeout", "provider_unavailable", "error"}:
        return "medium"
    if source_name == "known_breach_catalog" and status in {"partial", "timeout", "provider_unavailable", "error"}:
        return "medium"
    if source_name in {"safe_search_dorks", "leak_metadata_feed"} and status in {"disabled", "suggestions_only", "skipped"}:
        return "low"
    if status in {"disabled", "skipped"}:
        return "low"
    return "medium" if status in {"partial", "timeout", "provider_unavailable", "auth_required", "error"} else "low"


def _finding_impact(status: str) -> str:
    if status in {"completed", "completed_no_match", "disabled", "skipped", "suggestions_only"}:
        return "none" if status in {"completed", "completed_no_match", "disabled", "skipped"} else "manual_review_needed"
    if status in {"auth_required", "timeout", "provider_unavailable", "partial", "error"}:
        return "may_hide_findings"
    return "none"


def _messages(source_name: str, status: str) -> tuple[str, str]:
    if source_name == "certificate_transparency" and status == "timeout":
        return (
            "crt.sh bu çalıştırmada zaman aşımına uğradı; Certificate Transparency kapsamı kısmi kaldı.",
            "Daha sonra tekrar dene veya OSINT timeout değerini artır.",
        )
    if source_name == "certificate_transparency" and status in {"provider_unavailable", "partial", "error"}:
        return (
            "crt.sh bu çalıştırmada erişilemedi; CT sertifika kapsamı kısmi kaldı.",
            "Daha sonra tekrar dene.",
        )
    if source_name == "historical_urls" and status in {"timeout", "provider_unavailable", "partial", "error"}:
        return (
            "Wayback CDX zaman aşımına uğradı; geçmiş URL bulunmaması kesin olarak yok anlamına gelmez.",
            "Daha sonra tekrar dene veya OSINT timeout değerini artır.",
        )
    if source_name == "public_code_search" and status == "auth_required":
        return (
            "GitHub canlı kod araması kimlik doğrulama gerektiriyor; GitHub token yoksa sadece manuel arama önerileri üretildi.",
            "GitHub token değerini GITHUB_TOKEN ortam değişkeniyle ver; token değerini ayara veya rapora yazma.",
        )
    if source_name == "known_breach_catalog" and status == "completed_no_match":
        return (
            "Herkese açık ihlal kataloğunda eşleşen metadata referansı görülmedi.",
            "Aksiyon yok.",
        )
    if source_name == "leak_metadata_feed" and status in {"disabled", "skipped"}:
        return (
            "Metadata feed sağlayıcısı kapalı; Settings > OSINT > Darkweb / Leak / Breach Metadata Feed üzerinden etkinleştirilebilir.",
            "Gerekliyse metadata-only provider ayarını etkinleştir.",
        )
    if source_name == "safe_search_dorks" and status == "suggestions_only":
        return (
            "Yalnızca operatörün manuel çalıştıracağı güvenli arama önerileri üretildi; bunlar bulgu değildir.",
            "Manuel önerileri bulgu olarak raporlama; gerekiyorsa operatör kontrol listesi olarak kullan.",
        )
    if status == "completed":
        return ("Kaynak başarıyla çalıştı.", "Aksiyon yok.")
    if status == "completed_no_match":
        return ("Kaynak çalıştı; eşleşme görülmedi.", "Aksiyon yok.")
    if status == "disabled":
        return ("Kaynak bu çalıştırmada kapalıydı.", "Gerekliyse ayarlardan etkinleştir.")
    if status == "skipped":
        return ("Kaynak bu hedef veya ayar için atlandı.", "Ayarları ve hedef tipini kontrol et.")
    if status == "suggestions_only":
        return ("Yalnızca manuel öneriler üretildi; bunlar bulgu değildir.", "Manuel önerileri ayrı değerlendir.")
    return ("Kaynak kısmi veya hatalı sonuç verdi; kapsam eksik olabilir.", "Kaynak hatasını gider veya daha sonra tekrar dene.")


def _operator_action_for_config(source_name: str, status: str, api_key_env: str) -> str:
    if source_name == "public_code_search" and status == "auth_required":
        return f"{api_key_env or 'GITHUB_TOKEN'} ortam değişkeniyle GitHub token ekle."
    return _messages(source_name, status)[1]


def normalized_source_health_row(source: dict[str, Any]) -> dict[str, Any]:
    name = str(source.get("name") or source.get("source") or "")
    endpoint = str(source.get("endpoint_url") or source.get("endpoint") or ENDPOINT_MAP.get(name, ""))
    raw_status = str(source.get("status") or source.get("source_status") or "")
    errors = [str(item) for item in source.get("errors", []) if str(item or "").strip()]
    provider_issue = provider_issue_details(source)
    health_status = source_health_status(source)
    normalized_status = _normalize_status(source, health_status)
    api_key_env = str(source.get("api_key_env") or API_KEY_ENV.get(name, ""))
    requires_api_key = bool(api_key_env or source.get("requires_api_key"))
    configured = bool(source.get("api_key_configured")) if "api_key_configured" in source else _configured_api_key(api_key_env)
    message, action = _messages(name, normalized_status)
    coverage_impact = str(source.get("coverage_impact") or _default_coverage_impact(name, normalized_status))
    finding_impact = str(source.get("finding_impact") or _finding_impact(normalized_status))
    error_class = str(source.get("error_class") or provider_issue.get("error_class") or "")
    http_status = _provider_http_status(source)
    can_retry = normalized_status in {"timeout", "provider_unavailable", "partial", "error"}
    return {
        "source": name,
        "display_name": DISPLAY_NAMES.get(name, name or "Unknown OSINT source"),
        "category": CATEGORIES.get(name, "manual_suggestions"),
        "status": normalized_status,
        "coverage_impact": coverage_impact,
        "finding_impact": finding_impact,
        "user_message_tr": str(source.get("user_message_tr") or message),
        "operator_action_tr": str(source.get("operator_action_tr") or _operator_action_for_config(name, normalized_status, api_key_env) or action),
        "requires_api_key": requires_api_key,
        "api_key_env": api_key_env,
        "api_key_configured": configured if requires_api_key else False,
        "can_retry": can_retry,
        "retry_recommended": can_retry and coverage_impact in {"medium", "high"},
        "latency_ms": int(source.get("duration_ms") or source.get("latency_ms") or 0),
        "http_status": http_status,
        "error_class": error_class,
        "risk_score_impact": 0,
        "endpoint": endpoint,
        "url_role": "diagnostic_endpoint" if endpoint and endpoint != "manual" else "",
        "url_status": str(source.get("endpoint_url_status") or source.get("url_status") or "not_checked"),
        "browser_safe": False,
        "render_as_clickable": False,
        "source_status": raw_status,
        "legacy_health_status": health_status,
        "error": "; ".join(errors),
        "user_message": str(source.get("user_message") or provider_issue.get("user_message") or ""),
    }


def source_health_rows_from_sources(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in sources:
        rows.append(normalized_source_health_row(source))
    return rows


def source_health_summary_from_rows(rows: list[dict[str, Any]]) -> dict[str, int]:
    health = {
        "attempted_live_sources": 0,
        "completed": 0,
        "partial": 0,
        "error": 0,
        "timeout": 0,
        "unavailable": 0,
        "provider_unavailable": 0,
        "provider_unavailable_count": 0,
        "auth_required_fallback": 0,
        "auth_required_fallback_count": 0,
        "rate_limited_fallback": 0,
        "rate_limited_fallback_count": 0,
        "suggestions_only": 0,
        "suggestions_generated_count": 0,
        "no_match": 0,
        "no_match_count": 0,
        "timeout_count": 0,
        "skipped": 0,
    }
    for row in rows:
        source = str(row.get("source") or "")
        status = str(row.get("status") or "")
        source_status = str(row.get("source_status") or "")
        if status == "suggestions_only" or source_status == "suggestions_generated":
            health["suggestions_only"] += 1
            health["suggestions_generated_count"] += 1
            continue
        if source_status in {"skipped", "disabled"} or status in {"disabled", "skipped"}:
            health["skipped"] += 1
            continue
        if source in LIVE_SOURCE_NAMES:
            health["attempted_live_sources"] += 1
        if status == "partial" or source_status == "partial":
            health["partial"] += 1
        if status == "completed":
            health["completed"] += 1
        elif status == "completed_no_match":
            health["no_match"] += 1
            health["no_match_count"] += 1
        elif status == "timeout":
            health["timeout"] += 1
            health["timeout_count"] += 1
        elif status == "provider_unavailable":
            health["unavailable"] += 1
            health["provider_unavailable"] += 1
            health["provider_unavailable_count"] += 1
        elif status == "auth_required":
            health["auth_required_fallback"] += 1
            health["auth_required_fallback_count"] += 1
            health["suggestions_only"] += 1
        elif status == "rate_limited":
            health["rate_limited_fallback"] += 1
            health["rate_limited_fallback_count"] += 1
            health["suggestions_only"] += 1
        elif status == "error":
            health["error"] += 1
    return health


def source_health_diagnostic_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    live_rows = [row for row in rows if str(row.get("source") or "") in LIVE_SOURCE_NAMES]
    completed = len([row for row in live_rows if str(row.get("status") or "") in {"completed", "completed_no_match"}])
    partial_or_failed_rows = [
        row
        for row in live_rows
        if str(row.get("status") or "") in {"partial", "timeout", "provider_unavailable", "auth_required", "error"}
    ]
    auth_required = len([row for row in live_rows if str(row.get("status") or "") == "auth_required"])
    timeout = len([row for row in live_rows if str(row.get("status") or "") == "timeout"])
    major_failed = len([row for row in partial_or_failed_rows if str(row.get("source") or "") in MAJOR_SOURCE_NAMES])
    github_auth = any(
        str(row.get("source") or "") == "public_code_search" and str(row.get("status") or "") == "auth_required"
        for row in rows
    )
    if not live_rows:
        confidence = "low"
        note = "Canlı ana OSINT kaynağı çalıştırılmadı; kanıt yokluğu temiz sonuç değildir."
    elif major_failed >= 2 or (github_auth and major_failed >= 1):
        confidence = "low"
        note = "İki veya daha fazla ana OSINT kaynağı eksik kaldı; temiz sonuç çıkarılamaz."
    elif major_failed == 1:
        confidence = "medium"
        note = "Bir ana OSINT kaynağı eksik kaldı; sonuç kısmi yorumlanmalıdır."
    else:
        confidence = "high"
        note = "Etkin ana OSINT kaynakları tamamlandı veya güvenilir eşleşme yok sonucu döndürdü."
    return {
        "live_sources_total": len(live_rows),
        "completed": completed,
        "partial_or_failed": len(partial_or_failed_rows),
        "auth_required": auth_required,
        "timeout": timeout,
        "coverage_confidence": confidence,
        "coverage_note": note,
    }


def source_health_summary(sources: list[dict[str, Any]]) -> dict[str, int]:
    return source_health_summary_from_rows(source_health_rows_from_sources(sources))


def diagnostics_from_sources(sources: list[dict[str, Any]]) -> dict[str, Any]:
    source_rows = source_health_rows_from_sources(sources)
    checked_hosts: list[str] = []
    checked_endpoints: list[str] = []
    http_errors: list[str] = []
    for row in source_rows:
        endpoint = str(row.get("endpoint") or "")
        if endpoint and endpoint != "manual":
            checked_endpoints.append(endpoint)
            parsed = urlsplit(endpoint)
            if parsed.hostname:
                checked_hosts.append(parsed.hostname)
        if str(row.get("status") or "") in {"error", "timeout", "provider_unavailable"}:
            error = str(row.get("error") or "")
            if error:
                http_errors.append(error)
    summary = source_health_summary_from_rows(source_rows)
    live_records = summary["attempted_live_sources"]
    live_ok = summary["completed"] + summary["partial"] + summary["no_match"]
    live_fallback = summary["auth_required_fallback"] + summary["rate_limited_fallback"]
    if live_records == 0:
        network_available: bool | str = "unknown"
        http_status = "partial" if checked_endpoints else "error"
    else:
        network_available = live_ok > 0
        http_status = "ok" if live_ok == live_records else "partial" if live_ok else "error"
    return {
        "network_available": network_available,
        "dns_resolution": {
            "status": "ok" if checked_hosts else "skipped",
            "checked_hosts": sorted(set(checked_hosts)),
            "errors": [],
        },
        "http_connectivity": {
            "status": http_status,
            "checked_endpoints": checked_endpoints,
            "errors": http_errors,
        },
        "source_health": source_rows,
        "osint_source_health_summary": source_health_diagnostic_summary(source_rows),
    }
