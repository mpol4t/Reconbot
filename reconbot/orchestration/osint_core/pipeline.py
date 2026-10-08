from __future__ import annotations

from reconbot.orchestration.osint_core.domains import registered_domain

import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from reconbot.orchestration.osint_core import source_health as _source_health_core
from reconbot.orchestration.osint_core.darkweb.collector import build_darkweb_intelligence
from reconbot.orchestration.osint_core.leak_sources.aggregator import build_leak_intelligence
from reconbot.orchestration.osint_core.organization import mail_dns as _mail_dns_core


_CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
_TRANSIENT_HTTP_CODES = {429, 502, 503, 504}
_KNOWN_MULTI_LABEL_SUFFIXES = {
    "com.tr",
    "org.tr",
    "net.tr",
    "gov.tr",
    "edu.tr",
    "co.uk",
    "org.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
}
_SECRETISH_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|secret|password|passwd|authorization)\b\s*[:=]\s*['\"]?[^'\"\s]{6,}"
)
_GENERIC_OR_RESERVED_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "localhost",
    "local",
    "invalid",
}
_CT_INTERESTING_LABELS = {
    "dev",
    "staging",
    "test",
    "qa",
    "admin",
    "api",
    "internal",
    "vpn",
    "sso",
    "auth",
    "backup",
    "config",
    "debug",
    "portal",
}
_CDN_PROVIDER_KEYWORDS = [
    ("cloudflare", "Cloudflare"),
    ("akamai", "Akamai"),
    ("fastly", "Fastly"),
    ("cloudfront", "Amazon CloudFront"),
    ("google", "Google"),
    ("azure", "Microsoft Azure"),
    ("microsoft", "Microsoft"),
    ("imperva", "Imperva"),
    ("incapsula", "Imperva Incapsula"),
    ("vercel", "Vercel"),
    ("netlify", "Netlify"),
]
_CLOUDFLARE_IPV4_RANGES = (
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/12",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
)
_INFRASTRUCTURE_CAVEAT = "This IP may represent CDN/proxy/edge infrastructure and may not be the target origin."
_ORG_OFFICIAL_PATHS: tuple[tuple[str, str], ...] = (
    ("/", "homepage"),
    ("/about", "about"),
    ("/about-us", "about"),
    ("/team", "people"),
    ("/leadership", "people"),
    ("/management", "people"),
    ("/contact", "contact"),
    ("/contact-us", "contact"),
    ("/support", "support"),
    ("/abuse", "security"),
    ("/security", "security"),
    ("/.well-known/security.txt", "security_txt"),
    ("/security.txt", "security_txt"),
    ("/privacy", "privacy"),
    ("/legal", "legal"),
    ("/careers", "careers"),
    ("/jobs", "careers"),
    ("/press", "press"),
    ("/media", "press"),
    ("/investor-relations", "legal"),
    ("/sitemap.xml", "sitemap"),
    ("/robots.txt", "robots"),
)
_ORG_SPECIAL_CHECK_PATHS = {"/.well-known/security.txt", "/security.txt", "/sitemap.xml", "/robots.txt"}
_ORG_ROLE_CONTACTS = (
    "security",
    "abuse",
    "postmaster",
    "hostmaster",
    "webmaster",
    "privacy",
    "legal",
    "support",
    "contact",
    "info",
    "press",
    "media",
    "careers",
    "jobs",
)
_SECURITY_TXT_FIELDS = {
    "contact": "Contact",
    "policy": "Policy",
    "hiring": "Hiring",
    "acknowledgments": "Acknowledgments",
    "acknowledgements": "Acknowledgments",
    "preferred-languages": "Preferred-Languages",
    "expires": "Expires",
    "canonical": "Canonical",
}
_SOFT_ERROR_PATH_MARKERS = ("/error/", "/404", "/400", "/not-found", "/notfound")
_SOFT_ERROR_QUERY_MARKERS = ("aspxerrorpath=", "errorpath=", "error=")
_SOFT_ERROR_TEXT_MARKERS = (
    "hata",
    "error",
    "404",
    "400",
    "not found",
    "page not found",
    "sayfa bulunamadı",
    "bad request",
)
_TRACKING_QUERY_PARAMS = {
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "msclkid",
    "ref",
    "ref_src",
    "utm_campaign",
    "utm_content",
    "utm_medium",
    "utm_source",
    "utm_term",
}
_NON_ACTIONABLE_URL_STATUSES = {
    "checked_not_found",
    "checked_soft_error",
    "checked_unexpected_content",
    "checked_duplicate",
    "timeout",
    "connection_error",
    "tls_error",
}
_DOCUMENT_EXTENSIONS = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".xml", ".json")
_DOCUMENT_CONTENT_TYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "text/plain",
    "text/csv",
    "application/xml",
    "text/xml",
    "application/json",
}
_SOCIAL_PROFILE_HOSTS = {
    "github.com": "github",
    "www.github.com": "github",
    "linkedin.com": "linkedin",
    "www.linkedin.com": "linkedin",
    "x.com": "x",
    "www.x.com": "x",
    "twitter.com": "x",
    "www.twitter.com": "x",
    "facebook.com": "facebook",
    "www.facebook.com": "facebook",
    "instagram.com": "instagram",
    "www.instagram.com": "instagram",
    "youtube.com": "youtube",
    "www.youtube.com": "youtube",
    "youtu.be": "youtube",
    "tiktok.com": "tiktok",
    "www.tiktok.com": "tiktok",
    "medium.com": "medium",
    "www.medium.com": "medium",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _emit_osint_log(output_dir: Path | str | None, message: str) -> None:
    print(message, flush=True)
    if output_dir is None:
        return
    try:
        run_dir = Path(output_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        with (run_dir / "reconbot.log").open("a", encoding="utf-8") as handle:
            handle.write(f"{_now_iso()} {message}\n")
    except Exception:
        pass


def _emit_osint_event(
    events: list[dict[str, str]] | None,
    output_dir: Path | str | None,
    level: str,
    source: str,
    message: str,
) -> None:
    source_name = str(source or "osint")
    safe_message = str(message or "")[:500]
    if events is not None:
        events.append(
            {
                "ts": _now_iso(),
                "level": str(level or "info"),
                "source": source_name,
                "message": safe_message,
            }
        )
    display_source = {
        "certificate_transparency": "certificate transparency",
        "historical_urls": "wayback",
        "public_code_search": "github",
        "known_breach_catalog": "known breach catalog",
        "safe_search_dorks": "dorks",
    }.get(source_name, source_name)
    if display_source == "osint":
        _emit_osint_log(output_dir, f"[osint] {safe_message}")
    else:
        _emit_osint_log(output_dir, f"[osint] {display_source}: {safe_message}")


def _record_osint_event(
    events: list[dict[str, str]] | None,
    level: str,
    source: str,
    message: str,
) -> None:
    if events is None:
        return
    events.append(
        {
            "ts": _now_iso(),
            "level": str(level or "info"),
            "source": str(source or "osint"),
            "message": str(message or "")[:500],
        }
    )


def _osint_settings(tool_settings: dict[str, Any] | None) -> dict[str, Any]:
    settings = tool_settings if isinstance(tool_settings, dict) else {}
    value = settings.get("osint")
    return value if isinstance(value, dict) else {}


def _setting_bool(settings: dict[str, Any], snake: str, camel: str, default: bool) -> bool:
    if snake in settings:
        return bool(settings.get(snake))
    if camel in settings:
        return bool(settings.get(camel))
    return default


def _setting_int(settings: dict[str, Any], snake: str, camel: str, default: int) -> int:
    value = settings.get(snake, settings.get(camel, default))
    try:
        parsed = int(value)
    except Exception:
        return default
    return max(0, parsed)


def _nested_setting(settings: dict[str, Any], *keys: str) -> dict[str, Any]:
    current: Any = settings
    for key in keys:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return dict(current) if isinstance(current, dict) else {}


def _source_setting(settings: dict[str, Any], camel: str, snake: str) -> dict[str, Any]:
    sources = _nested_setting(settings, "sources")
    if not sources:
        sources = _nested_setting(settings, "osintSources")
    value = sources.get(camel) if isinstance(sources, dict) else None
    if not isinstance(value, dict) and isinstance(sources, dict):
        value = sources.get(snake)
    return dict(value) if isinstance(value, dict) else {}


def _metadata_feed_settings(settings: dict[str, Any]) -> dict[str, Any]:
    leak_sources = settings.get("leakSources")
    if not isinstance(leak_sources, dict):
        leak_sources = settings.get("leak_sources")
    if not isinstance(leak_sources, dict):
        return {}
    metadata_feed = leak_sources.get("metadataFeed")
    if not isinstance(metadata_feed, dict):
        metadata_feed = leak_sources.get("metadata_feed")
    return dict(metadata_feed) if isinstance(metadata_feed, dict) else {}


def _darkweb_settings(settings: dict[str, Any]) -> dict[str, Any]:
    darkweb = settings.get("darkweb")
    if not isinstance(darkweb, dict):
        darkweb = settings.get("darkwebIntelligence")
    return dict(darkweb) if isinstance(darkweb, dict) else {}


def _sanitized_metadata_feed_settings(config: dict[str, Any]) -> dict[str, Any]:
    feed_path = str(config.get("feedPath") or config.get("feed_path") or "")
    return {
        "enabled": bool(config.get("enabled", False)),
        "providerId": str(config.get("providerId") or config.get("provider_id") or ""),
        "sourceName": str(config.get("sourceName") or config.get("source_name") or ""),
        "sourceType": str(config.get("sourceType") or config.get("source_type") or ""),
        "feedPath": Path(feed_path).expanduser().name if feed_path else "",
        "feedUrl": str(config.get("feedUrl") or config.get("feed_url") or ""),
        "apiKeyEnvConfigured": bool(config.get("apiKeyEnv") or config.get("api_key_env")),
        "timeout": _setting_int(config, "timeout", "timeout", 10) or 10,
        "maxResults": _setting_int(config, "max_results", "maxResults", 25) or 25,
    }


def _sanitized_darkweb_settings(config: dict[str, Any]) -> dict[str, Any]:
    manual = config.get("manualMetadataImport")
    if not isinstance(manual, dict):
        manual = config.get("manual_metadata_import")
    if not isinstance(manual, dict):
        manual = {}
    custom = config.get("customHttpsProvider")
    if not isinstance(custom, dict):
        custom = config.get("custom_https_provider")
    if not isinstance(custom, dict):
        custom = {}
    file_path = str(manual.get("filePath") or manual.get("file_path") or "")
    api_key_env = str(custom.get("apiKeyEnv") or custom.get("api_key_env") or "DARKWEB_METADATA_TOKEN").strip()
    return {
        "enabled": bool(config.get("enabled", False)),
        "manualMetadataImport": {
            "enabled": bool(manual.get("enabled", False)),
            "sourceName": str(manual.get("sourceName") or manual.get("source_name") or ""),
            "filePath": Path(file_path).expanduser().name if file_path else "",
            "maxResults": _setting_int(dict(manual), "max_results", "maxResults", 25) or 25,
        },
        "customHttpsProvider": {
            "enabled": bool(custom.get("enabled", False)),
            "providerUrlConfigured": bool(str(custom.get("providerUrl") or custom.get("provider_url") or "").strip()),
            "apiKeyEnv": api_key_env,
            "apiKeyConfigured": bool(api_key_env and os.environ.get(api_key_env)),
            "maxResults": _setting_int(dict(custom), "max_results", "maxResults", 25) or 25,
            "timeout": _setting_int(dict(custom), "timeout", "timeout", 10) or 10,
        },
    }


def _target_domain(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw.split("/", 1)[0].split(":", 1)[0]
    return _normalize_hostname(host)


def _registered_domain(host: str) -> str | None:
    return registered_domain(str(host or "")) or None


def _target_context(target: str) -> dict[str, Any]:
    host = _target_domain(target)
    registered = _registered_domain(host)
    return {
        "target_domain": host,
        "target_host": host,
        "target_registered_domain": registered,
        "scope_mode": "exact_host",
        "parent_domain_expansion": False,
        "generic_or_reserved_domain": _is_generic_or_reserved_domain(host, registered),
        "organization_aliases": _organization_aliases(host, registered),
    }


def _looks_like_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or "") or ":" in (host or ""))


def _is_generic_or_reserved_domain(host: str, registered_domain: str | None = None) -> bool:
    normalized = _normalize_hostname(host)
    registered = _normalize_hostname(registered_domain or "")
    return normalized in _GENERIC_OR_RESERVED_DOMAINS or bool(
        registered and registered in _GENERIC_OR_RESERVED_DOMAINS
    )


def _normalize_hostname(value: str) -> str:
    host = str(value or "").strip().lower()
    host = host.replace("*.", "").strip(".")
    if not host or "/" in host or "@" in host:
        return ""
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        return ""
    return host


def _display_token(token: str) -> str:
    value = str(token or "").strip()
    if not value:
        return ""
    if value.isdigit():
        return value
    return value[:1].upper() + value[1:].lower()


def _organization_aliases(host: str, registered_domain: str | None = None) -> list[str]:
    normalized_host = _normalize_hostname(host)
    registered = _normalize_hostname(registered_domain or "") or _registered_domain(normalized_host) or ""
    aliases: list[str] = []

    def add(value: str) -> None:
        text = str(value or "").strip()
        if text and text not in aliases:
            aliases.append(text)

    add(normalized_host)
    if registered and registered != normalized_host:
        add(registered)

    domain_for_brand = registered or normalized_host
    labels = [label for label in domain_for_brand.split(".") if label]
    if labels and not _looks_like_ip(domain_for_brand):
        brand_label = labels[0]
        tokens = [token for token in re.split(r"[-_]+", brand_label) if token]
        if tokens:
            hyphen_alias = "-".join(_display_token(token) for token in tokens)
            add(hyphen_alias)
            if len(tokens) > 1:
                add(" ".join(_display_token(token) for token in tokens))

    return aliases[:6]


def _in_domain(candidate: str, domain: str) -> bool:
    candidate = _normalize_hostname(candidate)
    domain = _normalize_hostname(domain)
    return bool(candidate and domain and (candidate == domain or candidate.endswith(f".{domain}")))


def _signal_id(category: str, key: str) -> str:
    digest = hashlib.sha1(f"{category}:{key}".encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"osint-{category}-{digest}"


def _redact_snippet(value: str) -> str:
    return _SECRETISH_RE.sub(lambda match: f"{match.group(1)}=[redacted]", str(value or ""))[:320]


def _source_record(
    name: str,
    status: str,
    count: int,
    notes: str,
    source_url: str = "",
    *,
    raw_count: int | None = None,
    suppressed_count: int = 0,
    errors: list[str] | None = None,
    duration_ms: int = 0,
    provider_results: list[dict[str, Any]] | None = None,
    asset_identity_count: int = 0,
) -> dict[str, Any]:
    record = {
        "name": name,
        "status": status,
        "signal_count": int(count),
        "raw_count": int(count if raw_count is None else raw_count),
        "suppressed_count": int(suppressed_count),
        "notes": notes,
        "source_url": source_url,
        "errors": list(errors or []),
        "duration_ms": int(duration_ms),
        "asset_identity_count": int(asset_identity_count),
        "risk_score_impact": 0,
    }
    if provider_results is not None:
        record["provider_results"] = provider_results
    return record


def _error_note(prefix: str, exc: BaseException) -> str:
    if isinstance(exc, HTTPError):
        return f"{prefix}: HTTPError {exc.code}"
    return f"{prefix}: {type(exc).__name__}"


def _error_label(exc: BaseException) -> str:
    if isinstance(exc, HTTPError):
        return f"HTTPError {exc.code}"
    return type(exc).__name__


def _error_class(exc: BaseException) -> str:
    if isinstance(exc, HTTPError):
        return f"http_{exc.code}"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, URLError):
        return "url_error"
    if isinstance(exc, json.JSONDecodeError):
        return "parse_error"
    return type(exc).__name__.lower()


def _close_http_error(exc: BaseException) -> None:
    if isinstance(exc, HTTPError):
        try:
            exc.close()
        except Exception:
            pass


def _base_signal(
    *,
    category: str,
    title: str,
    status: str,
    confidence: str,
    confidence_score: int,
    source_name: str,
    source_url: str,
    matched_entities: dict[str, list[str]],
    snippet: str,
    validation_notes: list[str],
    recommended_action: str,
    exposure_priority: str,
    false_positive_notes: list[str] | None = None,
    source_provider: str | None = None,
    provider_reference: str | None = None,
) -> dict[str, Any]:
    signal = {
        "id": _signal_id(category, f"{source_name}:{title}:{snippet}"),
        "category": category,
        "title": title,
        "status": status,
        "confidence": confidence,
        "confidence_score": int(confidence_score),
        "source_name": source_name,
        "source_url": source_url,
        "observed_at": _now_iso(),
        "matched_entities": {
            "domains": matched_entities.get("domains", []),
            "subdomains": matched_entities.get("subdomains", []),
            "emails": matched_entities.get("emails", []),
            "urls": matched_entities.get("urls", []),
            "keywords": matched_entities.get("keywords", []),
            "file_names": matched_entities.get("file_names", []),
        },
        "evidence": {
            "snippet": _redact_snippet(snippet),
            "redaction_applied": True,
        },
        "validation_notes": validation_notes,
        "false_positive_notes": false_positive_notes
        or [
            "Passive OSINT signal only; it may be stale, unrelated, duplicated, or out of scope.",
        ],
        "recommended_action": recommended_action,
        "exposure_priority": exposure_priority,
        "risk_score_impact": 0,
    }
    if source_provider:
        signal["source_provider"] = source_provider
    if provider_reference:
        signal["provider_reference"] = provider_reference
    return signal


def _append_signal(signals: list[dict[str, Any]], suppressed: list[dict[str, Any]], signal: dict[str, Any], max_signals: int) -> None:
    if len(signals) < max_signals:
        signals.append(signal)
        return
    suppressed_signal = dict(signal)
    suppressed_signal["status"] = "suppressed"
    suppressed_signal["validation_notes"] = list(signal.get("validation_notes", [])) + [
        "Suppressed because OSINT maxSignals was reached.",
    ]
    suppressed.append(suppressed_signal)


def _operator_task_id(source_name: str, query: str) -> str:
    digest = hashlib.sha1(f"{source_name}:{query}".encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"osint-task-{digest}"


def _base_operator_search_task(
    *,
    source_name: str,
    query: str,
    link: str,
    purpose: str,
    safety_note: str,
    quality: str = "medium_signal",
    category: str = "general",
    query_scope: str = "exact_host",
    link_label: str | None = None,
) -> dict[str, Any]:
    return {
        "id": _operator_task_id(source_name, query),
        "source_name": source_name,
        "query": query,
        "link": link,
        "purpose": purpose,
        "safety_note": safety_note,
        "quality": quality,
        "category": category,
        "query_scope": query_scope,
        "link_label": link_label or _manual_search_link_label(source_name, category, query),
        "status": "suggestion_only",
        "check_policy": "manual_only",
        "validation_method": "not_applicable",
        "url_status": "manual_only",
        "final_url": "",
        "content_type": "",
        "http_status": None,
        "validation_error": "",
        "risk_score_impact": 0,
    }


def _manual_search_link_label(source_name: str, category: str, query: str) -> str:
    source = str(source_name or "").strip().lower()
    cat = str(category or "").strip().lower()
    text = str(query or "").strip().lower()
    if source == "public_code_search":
        if ".env" in text:
            return "Open GitHub .env search"
        if "filename:config" in text or "config" in text:
            return "Open GitHub config search"
        return "Open GitHub code search"
    if source == "safe_search_dorks":
        if cat == "api_docs":
            if "swagger" in text:
                return "Open Google Swagger search"
            return "Open Google API docs search"
        if cat == "config_terms":
            return "Open Google config search"
        if cat == "documents":
            if "filetype:pdf" in text:
                return "Open Google PDF search"
            return "Open Google document search"
        if cat == "emails":
            return "Open Google email-pattern search"
        return "Open Google search"
    if source == "known_breach_catalog":
        return "Open manual breach catalog review"
    return "Open manual search suggestion"


def _is_browser_safe_osint_url(url: str) -> bool:
    parsed = urlsplit(str(url or ""))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    host = parsed.hostname or ""
    if host in {"api.github.com", "api.certspotter.com"}:
        return False
    if host == "haveibeenpwned.com" and parsed.path.startswith("/api/"):
        return False
    if host == "web.archive.org" and parsed.path.startswith("/cdx"):
        return False
    if host == "crt.sh" and "output=json" in parsed.query:
        return False
    return True


def _osint_url_audit(url: str, role: str, status: str = "not_checked") -> dict[str, Any]:
    text = str(url or "").strip()
    browser_safe = _is_browser_safe_osint_url(text)
    normalized_status = str(status or "not_checked")
    if normalized_status == "generated_candidate":
        check_policy = "generated_candidate"
        validation_method = "not_applicable"
    elif role in {"passive_infrastructure_lookup", "machine_endpoint", "diagnostic_endpoint"}:
        check_policy = "api_required"
        validation_method = "api"
    elif role in {
        "manual_search_suggestion",
        "passive_lookup_shortcut",
        "organization_lookup_shortcut",
        "public_document_search",
        "location_lookup_shortcut",
        "people_lookup_shortcut",
    }:
        check_policy = "manual_only"
        validation_method = "not_applicable"
    elif role in {"official_page", "security_txt", "observed_evidence_link", "source_report_link", "validated_public_document"}:
        check_policy = "auto_check_allowed"
        validation_method = "get_only"
    else:
        check_policy = "manual_only"
        validation_method = "not_applicable"
    render_as_clickable = bool(
        text
        and browser_safe
        and normalized_status not in _NON_ACTIONABLE_URL_STATUSES
        and (
            (role == "observed_evidence_link" and normalized_status == "validated")
            or (role == "source_report_link" and normalized_status == "validated")
            or role == "manual_search_suggestion"
            or role == "passive_infrastructure_lookup"
            or role == "passive_lookup_shortcut"
            or role in {
                "official_page",
                "security_txt",
                "validated_public_document",
                "organization_lookup_shortcut",
                "public_document_search",
                "location_lookup_shortcut",
                "people_lookup_shortcut",
            }
        )
    )
    return {
        "url": text,
        "url_role": role,
        "url_status": normalized_status,
        "browser_safe": browser_safe,
        "render_as_clickable": render_as_clickable,
        "check_policy": check_policy,
        "validation_method": validation_method,
        "final_url": "",
        "content_type": "",
        "http_status": None,
        "validation_error": "",
    }


def _url_hostname(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    return _normalize_hostname(parsed.hostname or "")


def _registered_domain_for_observed_host(host: str, requested_registered_domain: str) -> str:
    observed = _normalize_hostname(host)
    requested = _normalize_hostname(requested_registered_domain)
    if requested and (observed == requested or observed.endswith(f".{requested}")):
        return requested
    return _registered_domain(observed) or observed


def _scope_caveat(scope_origin: str) -> str:
    if scope_origin == "exact_target_host":
        return "Observed on the exact requested target host."
    if scope_origin == "registered_domain":
        return "Observed on the requested registered domain, not a separate external source."
    if scope_origin == "parent_organization":
        return "Observed on the registered/parent organization domain, not necessarily on the exact target host."
    if scope_origin == "official_affiliate_domain":
        return "Observed through official affiliate-domain evidence linked or redirected from an official source."
    if scope_origin == "external_verified_source":
        return "Observed through an external verified public source, not directly on the target host."
    if scope_origin == "manual_fallback":
        return "Manual fallback shortcut or generated suggestion; not observed evidence."
    return "Scope relationship could not be determined automatically."


def _scope_provenance(
    *,
    source_url: str,
    requested_target_host: str,
    requested_registered_domain: str,
    observed: bool,
    manual_fallback: bool = False,
    official_affiliate: bool = False,
    external_verified: bool = False,
) -> dict[str, Any]:
    requested_host = _normalize_hostname(requested_target_host)
    requested_registered = _normalize_hostname(requested_registered_domain)
    observed_host = _url_hostname(source_url)
    observed_registered = _registered_domain_for_observed_host(observed_host, requested_registered)
    if manual_fallback or not observed:
        scope_origin = "manual_fallback"
        applies_to_target: bool | str = False
        applies_to_parent_org = False
    elif official_affiliate:
        scope_origin = "official_affiliate_domain"
        applies_to_target = "unknown"
        applies_to_parent_org = False
    elif observed_host and requested_host and observed_host == requested_host:
        scope_origin = "exact_target_host"
        applies_to_target = True
        applies_to_parent_org = False
    elif observed_host and requested_registered and (
        observed_host == requested_registered or observed_host.endswith(f".{requested_registered}")
    ):
        if requested_host == requested_registered and observed_host == requested_registered:
            scope_origin = "registered_domain"
            applies_to_target = True
        else:
            scope_origin = "parent_organization"
            applies_to_target = False
        applies_to_parent_org = True
    elif external_verified or observed_host:
        scope_origin = "external_verified_source"
        applies_to_target = "unknown"
        applies_to_parent_org = False
    else:
        scope_origin = "manual_fallback"
        applies_to_target = False
        applies_to_parent_org = False
    return {
        "scope_origin": scope_origin,
        "observed_on_host": observed_host,
        "observed_on_registered_domain": observed_registered,
        "requested_target_host": requested_host,
        "requested_registered_domain": requested_registered,
        "applies_to_target": applies_to_target,
        "applies_to_parent_org": applies_to_parent_org,
        "scope_caveat": _scope_caveat(scope_origin),
    }


def _item_scope_url(item: dict[str, Any], keys: tuple[str, ...] = ("source_url", "final_url", "url", "link")) -> str:
    for key in keys:
        value = str(item.get(key) or "").strip()
        if value:
            return value
    return ""


def _apply_scope_provenance(
    item: dict[str, Any],
    *,
    requested_target_host: str,
    requested_registered_domain: str,
    url_keys: tuple[str, ...] = ("source_url", "final_url", "url", "link"),
    observed: bool | None = None,
    manual_fallback: bool | None = None,
    external_verified: bool = False,
) -> dict[str, Any]:
    observed_value = bool(item.get("observed")) if observed is None else bool(observed)
    status = str(item.get("status") or item.get("url_status") or "")
    check_policy = str(item.get("check_policy") or "")
    role = str(item.get("url_role") or "")
    manual_value = (
        manual_fallback
        if manual_fallback is not None
        else check_policy in {"manual_only", "generated_candidate"}
        or status in {"suggestion_only", "generated_guess"}
        or (
            not observed_value
            and role
            in {
                "manual_search_suggestion",
                "organization_lookup_shortcut",
                "location_lookup_shortcut",
                "public_document_search",
                "people_lookup_shortcut",
            }
        )
    )
    official_affiliate = (
        str(item.get("domain_relationship") or "") == "official_affiliate_domain"
        or str(item.get("url_status") or "") == "checked_official_affiliate_redirect"
    )
    primary_url = _item_scope_url(item, url_keys)
    primary_host = _url_hostname(primary_url)
    source_host = _url_hostname(str(item.get("source_url") or ""))
    requested_registered = _normalize_hostname(requested_registered_domain)
    if (
        not official_affiliate
        and observed_value
        and primary_host
        and source_host
        and requested_registered
        and (source_host == requested_registered or source_host.endswith(f".{requested_registered}"))
        and not (primary_host == requested_registered or primary_host.endswith(f".{requested_registered}"))
    ):
        official_affiliate = True
    item.update(
        _scope_provenance(
            source_url=primary_url,
            requested_target_host=requested_target_host,
            requested_registered_domain=requested_registered_domain,
            observed=observed_value,
            manual_fallback=bool(manual_value),
            official_affiliate=official_affiliate,
            external_verified=external_verified,
        )
    )
    return item


def _scope_count(items: list[dict[str, Any]], scope_origin: str, *, contact_type: str | None = None) -> int:
    total = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        if contact_type is not None and str(item.get("contact_type") or "") != contact_type:
            continue
        if str(item.get("scope_origin") or "") == scope_origin:
            total += 1
    return total


def _target_scope_count(items: list[dict[str, Any]], *, contact_type: str | None = None) -> int:
    total = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        if contact_type is not None and str(item.get("contact_type") or "") != contact_type:
            continue
        if item.get("applies_to_target") is True and str(item.get("scope_origin") or "") == "exact_target_host":
            total += 1
    return total


def _decorate_payload_scope(payload: dict[str, Any], *, requested_target_host: str, requested_registered_domain: str) -> None:
    for signal in (payload.get("signals", []) if isinstance(payload.get("signals"), list) else []):
        if isinstance(signal, dict):
            _apply_scope_provenance(
                signal,
                requested_target_host=requested_target_host,
                requested_registered_domain=requested_registered_domain,
                url_keys=("source_url", "url"),
                observed=True,
                external_verified=True,
            )
    for task in (payload.get("operator_search_tasks", []) if isinstance(payload.get("operator_search_tasks"), list) else []):
        if isinstance(task, dict):
            _apply_scope_provenance(
                task,
                requested_target_host=requested_target_host,
                requested_registered_domain=requested_registered_domain,
                url_keys=("link", "url"),
                observed=False,
                manual_fallback=True,
            )
    organization = payload.get("organization_intelligence") if isinstance(payload.get("organization_intelligence"), dict) else {}
    for key in ("official_pages", "organization_lookup_links", "location_lookup_links", "public_document_searches"):
        for item in (organization.get(key, []) if isinstance(organization.get(key), list) else []):
            if isinstance(item, dict):
                _apply_scope_provenance(
                    item,
                    requested_target_host=requested_target_host,
                    requested_registered_domain=requested_registered_domain,
                    observed=bool(item.get("observed") or item.get("page_found")),
                )
    security_txt = organization.get("security_txt") if isinstance(organization.get("security_txt"), dict) else {}
    if security_txt:
        _apply_scope_provenance(
            security_txt,
            requested_target_host=requested_target_host,
            requested_registered_domain=requested_registered_domain,
            url_keys=("found_url", "final_url", "url"),
            observed=bool(security_txt.get("found")),
        )
    contact_intel = organization.get("contact_intelligence") if isinstance(organization.get("contact_intelligence"), dict) else {}
    contact_items: list[dict[str, Any]] = []
    for key in ("observed_email_addresses", "observed_phone_numbers", "observed_contact_urls", "observed_contact_forms", "generated_role_email_guesses", "suppressed_contacts", "rejected_contact_candidates"):
        for item in (contact_intel.get(key, []) if isinstance(contact_intel.get(key), list) else []):
            if isinstance(item, dict):
                _apply_scope_provenance(
                    item,
                    requested_target_host=requested_target_host,
                    requested_registered_domain=requested_registered_domain,
                    observed=bool(item.get("observed")),
                )
                if item.get("observed"):
                    contact_items.append(item)
    for item in (organization.get("role_contacts", []) if isinstance(organization.get("role_contacts"), list) else []):
        if isinstance(item, dict):
            _apply_scope_provenance(
                item,
                requested_target_host=requested_target_host,
                requested_registered_domain=requested_registered_domain,
                observed=bool(item.get("observed")),
            )
            if item.get("observed") and item not in contact_items:
                contact_items.append(item)
    location_intel = organization.get("location_intelligence") if isinstance(organization.get("location_intelligence"), dict) else {}
    locations = [item for item in (location_intel.get("observed_locations", []) if isinstance(location_intel.get("observed_locations"), list) else []) if isinstance(item, dict)]
    for key in ("observed_locations", "official_location_pages", "external_location_candidates", "rejected_location_candidates", "location_lookup_shortcuts"):
        for item in (location_intel.get(key, []) if isinstance(location_intel.get(key), list) else []):
            if isinstance(item, dict):
                _apply_scope_provenance(
                    item,
                    requested_target_host=requested_target_host,
                    requested_registered_domain=requested_registered_domain,
                    observed=bool(item.get("observed") or item.get("page_found")),
                )
    docs_intel = organization.get("public_document_intelligence") if isinstance(organization.get("public_document_intelligence"), dict) else {}
    docs = [item for item in (docs_intel.get("validated_public_documents", []) if isinstance(docs_intel.get("validated_public_documents"), list) else []) if isinstance(item, dict)]
    for key in ("validated_public_documents", "document_candidates", "rejected_document_candidates", "manual_document_search_shortcuts"):
        for item in (docs_intel.get(key, []) if isinstance(docs_intel.get(key), list) else []):
            if isinstance(item, dict):
                _apply_scope_provenance(
                    item,
                    requested_target_host=requested_target_host,
                    requested_registered_domain=requested_registered_domain,
                    url_keys=("source_url", "url", "final_url"),
                    observed=bool(item.get("observed")),
                )
    people = organization.get("people_organization_presence") if isinstance(organization.get("people_organization_presence"), dict) else {}
    profiles = [item for item in (people.get("observed_official_social_profiles", []) if isinstance(people.get("observed_official_social_profiles"), list) else []) if isinstance(item, dict)]
    for key in ("observed_official_social_profiles", "rejected_social_candidates", "official_people_pages", "leadership_page_candidates", "company_profile_lookup_shortcuts"):
        for item in (people.get(key, []) if isinstance(people.get(key), list) else []):
            if isinstance(item, dict):
                _apply_scope_provenance(
                    item,
                    requested_target_host=requested_target_host,
                    requested_registered_domain=requested_registered_domain,
                    url_keys=("url", "source_url", "final_url"),
                    observed=bool(item.get("observed") or item.get("page_found")),
                )
    org_summary = organization.get("summary") if isinstance(organization.get("summary"), dict) else {}
    if org_summary is not None:
        org_summary.update(
            {
                "target_observed_public_contacts": _target_scope_count(contact_items),
                "parent_org_observed_public_contacts": _scope_count(contact_items, "parent_organization"),
                "affiliate_observed_public_contacts": _scope_count(contact_items, "official_affiliate_domain"),
                "target_observed_phone_numbers": _target_scope_count(contact_items, contact_type="phone"),
                "parent_org_observed_phone_numbers": _scope_count(contact_items, "parent_organization", contact_type="phone"),
                "target_observed_locations": _target_scope_count(locations),
                "parent_org_observed_locations": _scope_count(locations, "parent_organization"),
                "affiliate_observed_locations": _scope_count(locations, "official_affiliate_domain")
                + _scope_count(locations, "external_verified_source"),
                "target_validated_public_documents": _target_scope_count(docs),
                "parent_org_validated_public_documents": _scope_count(docs, "parent_organization"),
                "affiliate_validated_public_documents": _scope_count(docs, "official_affiliate_domain"),
                "target_observed_social_profiles": _target_scope_count(profiles),
                "parent_org_observed_social_profiles": _scope_count(profiles, "parent_organization"),
                "affiliate_observed_social_profiles": _scope_count(profiles, "official_affiliate_domain"),
            }
        )


def _source_detail_id(source_name: str) -> str:
    mapping = {
        "certificate_transparency": "osint-source-certificate-transparency",
        "historical_urls": "osint-source-historical-urls",
        "public_code_search": "osint-source-public-code-search",
        "known_breach_catalog": "osint-source-known-breach-catalog",
        "safe_search_dorks": "osint-source-safe-search-dorks",
    }
    normalized = str(source_name or "").strip()
    return mapping.get(normalized, f"osint-source-{re.sub(r'[^a-z0-9]+', '-', normalized.lower()).strip('-') or 'unknown'}")


def _source_browser_lookup_links(
    *,
    source_name: str,
    target_host: str,
    target_registered_domain: str | None,
) -> list[dict[str, Any]]:
    host = _normalize_hostname(target_host)
    registered = _normalize_hostname(target_registered_domain or "")
    links: list[tuple[str, str]] = []
    source = str(source_name or "").strip()
    if source == "certificate_transparency" and host:
        links.append(("Open crt.sh browser search", f"https://crt.sh/?q={quote(host)}"))
        if registered and registered != host:
            links.append(("Open crt.sh browser search", f"https://crt.sh/?q={quote(registered)}"))
    elif source == "historical_urls" and host:
        links.append(("Open Wayback browser search", f"https://web.archive.org/web/*/{host}/*"))
    elif source == "public_code_search" and host:
        links.append(("Open GitHub web code search suggestion", f"https://github.com/search?q=%22{quote_plus(host)}%22&type=code"))
    return [
        {
            "label": label,
            "url": url,
            "url_role": "passive_lookup_shortcut",
            "url_status": "manual_only",
            "check_policy": "manual_only",
            "validation_method": "not_applicable",
            "final_url": "",
            "content_type": "",
            "http_status": None,
            "validation_error": "",
            "browser_safe": True,
            "render_as_clickable": True,
            "status": "suggestion_only",
            "risk_score_impact": 0,
        }
        for label, url in links
    ]


def _decorate_osint_url_audit(payload: dict[str, Any]) -> dict[str, Any]:
    audit_entries: list[dict[str, Any]] = []
    normalization = payload.get("normalization") if isinstance(payload.get("normalization"), dict) else {}
    target_host = str(normalization.get("target_host") or normalization.get("target_domain") or "")
    registered_domain = str(normalization.get("target_registered_domain") or "")
    _decorate_payload_scope(payload, requested_target_host=target_host, requested_registered_domain=registered_domain)
    for signal in (payload.get("signals", []) if isinstance(payload.get("signals"), list) else []):
        if not isinstance(signal, dict):
            continue
        url = str(signal.get("source_url") or "")
        status = "validated" if _is_browser_safe_osint_url(url) else "not_checked"
        audit = _osint_url_audit(url, "observed_evidence_link", status)
        signal.update({key: audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
        signal["url_audit"] = audit
        if url:
            audit_entries.append(audit)
    for observation in (payload.get("asset_identity_observations", []) if isinstance(payload.get("asset_identity_observations"), list) else []):
        if not isinstance(observation, dict):
            continue
        url = str(observation.get("source_url") or "")
        role = "source_report_link" if _is_browser_safe_osint_url(url) else "machine_endpoint"
        audit = _osint_url_audit(url, role, "not_checked")
        observation.update({key: audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
        observation["url_audit"] = audit
        if url:
            audit_entries.append(audit)
    for candidate in (payload.get("asset_discovery_candidates", []) if isinstance(payload.get("asset_discovery_candidates"), list) else []):
        if not isinstance(candidate, dict):
            continue
        url = str(candidate.get("source_url") or "")
        role = "passive_source_reference" if _is_browser_safe_osint_url(url) else "machine_endpoint"
        audit = _osint_url_audit(url, role, "not_checked")
        audit["render_as_clickable"] = False
        candidate.update({key: audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
        candidate["url_audit"] = audit
        if url:
            audit_entries.append(audit)
    for item in (payload.get("historical_url_context", []) if isinstance(payload.get("historical_url_context"), list) else []):
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "")
        audit = _osint_url_audit(url, "historical_url", str(item.get("url_status") or "archived_not_live_checked"))
        audit["browser_safe"] = bool(url and _is_browser_safe_osint_url(url))
        audit["render_as_clickable"] = False
        audit["check_policy"] = "archive_metadata_only"
        audit["validation_method"] = "not_fetched_live"
        item.update({key: audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
        item["url_audit"] = audit
        if url:
            audit_entries.append(audit)
    for source in (payload.get("sources", []) if isinstance(payload.get("sources"), list) else []):
        if not isinstance(source, dict):
            continue
        source_name = str(source.get("name") or "")
        source["detail_id"] = _source_detail_id(source_name)
        lookup_links = _source_browser_lookup_links(
            source_name=source_name,
            target_host=target_host,
            target_registered_domain=registered_domain,
        )
        if lookup_links:
            source["browser_lookup_links"] = lookup_links
            for link in lookup_links:
                if not isinstance(link, dict):
                    continue
                url = str(link.get("url") or "")
                audit = _osint_url_audit(url, str(link.get("url_role") or "passive_lookup_shortcut"), str(link.get("url_status") or "manual_only"))
                audit["render_as_clickable"] = bool(url and audit["browser_safe"])
                link.update({key: audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
                link["check_policy"] = str(link.get("check_policy") or "manual_only")
                link["validation_method"] = str(link.get("validation_method") or "not_applicable")
                link["status"] = "suggestion_only"
                link["risk_score_impact"] = 0
                link["url_audit"] = audit
                if url:
                    audit_entries.append(audit)
        report_url = str(source.get("report_url") or source.get("source_url") or "")
        report_status = str(source.get("report_url_status") or ("validated" if _is_browser_safe_osint_url(report_url) else "not_checked"))
        report_role = "source_report_link" if _is_browser_safe_osint_url(report_url) else "machine_endpoint"
        report_audit = _osint_url_audit(report_url, report_role, report_status)
        source.update({key: report_audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
        source["url_audit"] = report_audit
        if report_url:
            audit_entries.append(report_audit)
        endpoint_url = str(source.get("endpoint_url") or "")
        if endpoint_url:
            endpoint_audit = _osint_url_audit(endpoint_url, "machine_endpoint", str(source.get("endpoint_url_status") or "not_checked"))
            endpoint_audit["browser_safe"] = False
            endpoint_audit["render_as_clickable"] = False
            source["endpoint_url_audit"] = endpoint_audit
            audit_entries.append(endpoint_audit)
    for task in (payload.get("operator_search_tasks", []) if isinstance(payload.get("operator_search_tasks"), list) else []):
        if not isinstance(task, dict):
            continue
        url = str(task.get("link") or "")
        audit = _osint_url_audit(url, "manual_search_suggestion", str(task.get("url_status") or "manual_only"))
        task.update({key: audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
        task["check_policy"] = str(task.get("check_policy") or "manual_only")
        task["validation_method"] = str(task.get("validation_method") or "not_applicable")
        task["url_audit"] = audit
        if url:
            audit_entries.append(audit)
    infrastructure = payload.get("infrastructure") if isinstance(payload.get("infrastructure"), dict) else {}
    for link in (infrastructure.get("passive_lookup_links", []) if isinstance(infrastructure.get("passive_lookup_links"), list) else []):
        if not isinstance(link, dict):
            continue
        url = str(link.get("url") or "")
        audit = _osint_url_audit(url, "passive_infrastructure_lookup", str(link.get("url_status") or "api_key_missing"))
        audit["browser_safe"] = True if url and _is_browser_safe_osint_url(url) else audit["browser_safe"]
        audit["render_as_clickable"] = bool(url and audit["browser_safe"])
        link.update({key: audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
        link["check_policy"] = str(link.get("check_policy") or "api_required")
        link["validation_method"] = str(link.get("validation_method") or "api")
        link["status"] = "suggestion_only"
        link["risk_score_impact"] = 0
        link["url_audit"] = audit
        if url:
            audit_entries.append(audit)
    organization = payload.get("organization_intelligence") if isinstance(payload.get("organization_intelligence"), dict) else {}
    for collection_name, default_role in (
        ("official_pages", "official_page"),
        ("organization_lookup_links", "organization_lookup_shortcut"),
        ("location_lookup_links", "location_lookup_shortcut"),
        ("public_document_searches", "public_document_search"),
    ):
        for item in (organization.get(collection_name, []) if isinstance(organization.get(collection_name), list) else []):
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "")
            role = str(item.get("url_role") or default_role)
            status = str(item.get("url_status") or "not_checked")
            audit = _osint_url_audit(url, role, status)
            audit["browser_safe"] = bool(url and _is_browser_safe_osint_url(url))
            audit["render_as_clickable"] = bool(
                url
                and audit["browser_safe"]
                and status not in _NON_ACTIONABLE_URL_STATUSES
                and item.get("render_as_clickable", True)
            )
            if collection_name == "official_pages" and status in _NON_ACTIONABLE_URL_STATUSES:
                item["page_found"] = False
            item.update({key: audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
            item["status"] = str(item.get("status") or "suggestion_only")
            item["risk_score_impact"] = 0
            item["url_audit"] = audit
            if url:
                audit_entries.append(audit)
    location_intelligence = organization.get("location_intelligence") if isinstance(organization.get("location_intelligence"), dict) else {}
    for item in (
        location_intelligence.get("location_lookup_shortcuts", [])
        if isinstance(location_intelligence.get("location_lookup_shortcuts"), list)
        else []
    ):
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "")
        audit = _osint_url_audit(url, "location_lookup_shortcut", str(item.get("url_status") or "manual_only"))
        audit["render_as_clickable"] = bool(url and audit["browser_safe"] and item.get("render_as_clickable", True))
        item.update({key: audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
        item["check_policy"] = str(item.get("check_policy") or "manual_only")
        item["validation_method"] = str(item.get("validation_method") or "not_applicable")
        item["status"] = str(item.get("status") or "suggestion_only")
        item["risk_score_impact"] = 0
        item["url_audit"] = audit
        if url:
            audit_entries.append(audit)
    public_document_intelligence = organization.get("public_document_intelligence") if isinstance(organization.get("public_document_intelligence"), dict) else {}
    for collection_name in ("validated_public_documents", "document_candidates", "rejected_document_candidates", "manual_document_search_shortcuts"):
        for item in (
            public_document_intelligence.get(collection_name, [])
            if isinstance(public_document_intelligence.get(collection_name), list)
            else []
        ):
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "")
            item_status = str(item.get("status") or "")
            is_validated_public_document = collection_name == "validated_public_documents" or item_status == "validated_public_document"
            role = str(item.get("url_role") or ("validated_public_document" if is_validated_public_document else "public_document_search"))
            status = str(item.get("url_status") or "not_checked")
            audit = _osint_url_audit(url, role, status)
            for field in ("check_policy", "validation_method", "final_url", "content_type", "http_status", "validation_error"):
                if field in item and item.get(field) not in (None, ""):
                    audit[field] = item.get(field)
            audit["render_as_clickable"] = bool(
                url
                and audit["browser_safe"]
                and status not in _NON_ACTIONABLE_URL_STATUSES
                and item.get("render_as_clickable", True)
                and (is_validated_public_document or collection_name == "manual_document_search_shortcuts")
            )
            item.update({key: audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
            item["check_policy"] = str(audit.get("check_policy") or item.get("check_policy") or "")
            item["validation_method"] = str(audit.get("validation_method") or item.get("validation_method") or "")
            item["risk_score_impact"] = 0
            item["url_audit"] = audit
            if url:
                audit_entries.append(audit)
    people_presence = organization.get("people_organization_presence") if isinstance(organization.get("people_organization_presence"), dict) else {}
    for item in (
        people_presence.get("company_profile_lookup_shortcuts", [])
        if isinstance(people_presence.get("company_profile_lookup_shortcuts"), list)
        else []
    ):
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "")
        audit = _osint_url_audit(url, "people_lookup_shortcut", str(item.get("url_status") or "manual_only"))
        audit["render_as_clickable"] = bool(url and audit["browser_safe"] and item.get("render_as_clickable", True))
        item.update({key: audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
        item["check_policy"] = str(item.get("check_policy") or "manual_only")
        item["validation_method"] = str(item.get("validation_method") or "not_applicable")
        item["status"] = str(item.get("status") or "suggestion_only")
        item["risk_score_impact"] = 0
        item["url_audit"] = audit
        if url:
            audit_entries.append(audit)
    for item in (
        people_presence.get("observed_official_social_profiles", [])
        if isinstance(people_presence.get("observed_official_social_profiles"), list)
        else []
    ):
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "")
        audit = _osint_url_audit(url, "observed_official_social_profile", str(item.get("url_status") or "checked_ok"))
        audit["check_policy"] = "auto_check_allowed"
        audit["validation_method"] = "linked_from_official_source"
        audit["render_as_clickable"] = bool(url and audit["browser_safe"])
        item.update({key: audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
        item["risk_score_impact"] = 0
        item["url_audit"] = audit
        if url:
            audit_entries.append(audit)
    security_txt = organization.get("security_txt") if isinstance(organization.get("security_txt"), dict) else {}
    found_url = str(security_txt.get("found_url") or "")
    if found_url:
        audit = _osint_url_audit(found_url, "security_txt", str(security_txt.get("url_status") or security_txt.get("status") or "checked_ok"))
        audit["render_as_clickable"] = bool(found_url and audit["browser_safe"])
        security_txt.update({key: audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
        security_txt["risk_score_impact"] = 0
        security_txt["url_audit"] = audit
        audit_entries.append(audit)
    diagnostics = payload.get("diagnostics") if isinstance(payload.get("diagnostics"), dict) else {}
    for item in (diagnostics.get("source_health", []) if isinstance(diagnostics.get("source_health"), list) else []):
        if not isinstance(item, dict):
            continue
        url = str(item.get("endpoint") or "")
        audit = _osint_url_audit(url, "diagnostic_endpoint", str(item.get("url_status") or "not_checked"))
        audit["browser_safe"] = False
        audit["render_as_clickable"] = False
        item.update({key: audit[key] for key in ("url_role", "url_status", "browser_safe", "render_as_clickable")})
        item["url_audit"] = audit
        if url:
            audit_entries.append(audit)
    payload["url_audit"] = audit_entries
    return payload


def _fetch_json(url: str, timeout: int, *, api_key_env: str = "GITHUB_TOKEN") -> Any:
    headers = {"User-Agent": "ReconBot-OSINT-MVP/1.0"}
    if url.startswith("https://api.github.com/"):
        headers["Accept"] = "application/vnd.github+json"
        token = os.environ.get(str(api_key_env or "GITHUB_TOKEN"))
        if token:
            headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=max(1, timeout)) as response:
        raw = response.read(3_000_000)
    return json.loads(raw.decode("utf-8", errors="replace"))


def _fetch_text(url: str, timeout: int) -> str:
    request = Request(url, headers={"User-Agent": "ReconBot-OSINT-MVP/1.0"})
    with urlopen(request, timeout=max(1, timeout)) as response:
        raw = response.read(1_500_000)
    return raw.decode("utf-8", errors="replace")


def _fetch_text_response(url: str, timeout: int) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": "ReconBot-OSINT-MVP/1.0"})
    with urlopen(request, timeout=max(1, timeout)) as response:
        raw = response.read(1_500_000)
        status = int(getattr(response, "status", 0) or response.getcode() or 0)
        final_url = str(response.geturl() or url)
    return {"text": raw.decode("utf-8", errors="replace"), "status": status, "final_url": final_url}


def _fetch_limited_response(url: str, timeout: int, *, method: str = "GET", max_bytes: int = 262_144) -> dict[str, Any]:
    request = Request(
        url,
        headers={
            "User-Agent": "ReconBot-OSINT-MVP/1.0",
            "Accept": "text/html,text/plain,application/xml,text/xml,*/*;q=0.5",
        },
        method=method,
    )
    with urlopen(request, timeout=max(1, timeout)) as response:
        status = int(getattr(response, "status", 0) or response.getcode() or 0)
        final_url = str(response.geturl() or url)
        content_type = str(response.headers.get("Content-Type") or "")
        raw = b""
        if method.upper() != "HEAD":
            raw = response.read(max(0, int(max_bytes or 0)))
    return {
        "text": raw.decode("utf-8", errors="replace") if raw else "",
        "status": status,
        "final_url": final_url,
        "content_type": content_type,
    }


def _fetch_json_with_retries(
    url: str,
    *,
    timeout: int,
    deadline: float,
    output_dir: Path | str | None,
    log_prefix: str,
    events: list[dict[str, str]] | None = None,
    event_source: str = "osint",
    retries: int = 2,
    api_key_env: str = "GITHUB_TOKEN",
) -> Any:
    attempt = 0
    while True:
        try:
            if str(api_key_env or "GITHUB_TOKEN") == "GITHUB_TOKEN":
                return _fetch_json(url, _remaining_timeout(deadline, timeout))
            return _fetch_json(url, _remaining_timeout(deadline, timeout), api_key_env=api_key_env)
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            transient = isinstance(exc, TimeoutError)
            if isinstance(exc, HTTPError):
                transient = exc.code in _TRANSIENT_HTTP_CODES
            elif isinstance(exc, URLError):
                transient = True
            label = _error_label(exc)
            if attempt >= retries or not transient:
                _close_http_error(exc)
                raise
            attempt += 1
            _record_osint_event(events, "warn", event_source, f"retry {attempt} after {label}")
            _close_http_error(exc)
            time.sleep(min(0.1 * attempt, 0.3))


def _fetch_text_with_retries(
    url: str,
    *,
    timeout: int,
    deadline: float,
    output_dir: Path | str | None,
    log_prefix: str,
    events: list[dict[str, str]] | None = None,
    event_source: str = "osint",
    retries: int = 1,
) -> str:
    attempt = 0
    while True:
        try:
            return _fetch_text(url, _remaining_timeout(deadline, timeout))
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            transient = isinstance(exc, TimeoutError)
            if isinstance(exc, HTTPError):
                transient = exc.code in _TRANSIENT_HTTP_CODES
            elif isinstance(exc, URLError):
                transient = True
            label = _error_label(exc)
            if attempt >= retries or not transient:
                _close_http_error(exc)
                raise
            attempt += 1
            _record_osint_event(events, "warn", event_source, f"retry {attempt} after {label}")
            _close_http_error(exc)
            time.sleep(min(0.1 * attempt, 0.3))


def _fetch_text_response_with_retries(
    url: str,
    *,
    timeout: int,
    deadline: float,
    output_dir: Path | str | None,
    log_prefix: str,
    events: list[dict[str, str]] | None = None,
    event_source: str = "osint",
    retries: int = 1,
) -> dict[str, Any]:
    attempt = 0
    while True:
        try:
            return _fetch_text_response(url, _remaining_timeout(deadline, timeout))
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            transient = isinstance(exc, TimeoutError)
            if isinstance(exc, HTTPError):
                transient = exc.code in _TRANSIENT_HTTP_CODES
            elif isinstance(exc, URLError):
                transient = True
            label = _error_label(exc)
            if attempt >= retries or not transient:
                _close_http_error(exc)
                raise
            attempt += 1
            _record_osint_event(events, "warn", event_source, f"retry {attempt} after {label}")
            _close_http_error(exc)
            time.sleep(min(0.1 * attempt, 0.3))


def _remaining_timeout(deadline: float, configured_timeout: int) -> int:
    remaining = max(1.0, deadline - time.monotonic())
    return max(1, int(min(float(configured_timeout or 10), remaining)))


def _cname_chain(host: str, timeout: int) -> list[str]:
    normalized = _normalize_hostname(host)
    if not normalized or _looks_like_ip(normalized):
        return []
    chain: list[str] = []
    try:
        import dns.resolver  # type: ignore[import-not-found]

        resolver = dns.resolver.Resolver()
        resolver.lifetime = max(1, min(int(timeout or 3), 5))
        resolver.timeout = max(1, min(int(timeout or 3), 5))
        current = normalized
        for _index in range(8):
            answers = resolver.resolve(current, "CNAME")
            next_name = ""
            for answer in answers:
                next_name = _normalize_hostname(str(getattr(answer, "target", answer)).rstrip("."))
                if next_name:
                    break
            if not next_name or next_name in chain:
                break
            chain.append(next_name)
            current = next_name
    except Exception:
        return chain
    return chain


def _query_dns_records(name: str, record_type: str, timeout: int) -> dict[str, Any]:
    normalized = str(name or "").strip().lower().strip(".")
    rrtype = str(record_type or "").strip().upper()
    base_result = {"resolver_method": "dnspython"}
    if "/" in normalized or "@" in normalized or not re.fullmatch(r"[a-z0-9._-]+", normalized):
        normalized = ""
    if not normalized or not rrtype:
        return {**base_result, "status": "resolver_error", "records": [], "validation_error": "invalid_dns_query"}
    try:
        import dns.resolver  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        return {**base_result, "status": "dependency_missing", "records": [], "validation_error": "dependency_missing"}

    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = max(1, min(int(timeout or 3), 5))
        resolver.timeout = max(1, min(int(timeout or 3), 5))
        answers = resolver.resolve(normalized, rrtype)
        records: list[str] = []
        for answer in answers:
            if rrtype == "MX":
                preference = str(getattr(answer, "preference", "")).strip()
                exchange = _normalize_hostname(str(getattr(answer, "exchange", answer)).rstrip("."))
                records.append(f"{preference} {exchange}".strip())
            elif rrtype == "TXT":
                strings = getattr(answer, "strings", None)
                if strings:
                    records.append("".join(part.decode("utf-8", errors="replace") for part in strings))
                else:
                    records.append(str(answer).strip('"'))
            else:
                records.append(str(answer).rstrip("."))
        return {**base_result, "status": "present" if records else "absent", "records": records, "validation_error": ""}
    except Exception as exc:
        exc_name = type(exc).__name__
        if exc_name == "NXDOMAIN":
            return {**base_result, "status": "absent", "records": [], "validation_error": "nxdomain"}
        if exc_name == "NoAnswer":
            return {**base_result, "status": "absent", "records": [], "validation_error": "no_answer"}
        if exc_name in {"Timeout", "LifetimeTimeout"}:
            return {**base_result, "status": "timeout", "records": [], "validation_error": "timeout"}
        return {**base_result, "status": "resolver_error", "records": [], "validation_error": f"resolver_error: {exc_name}: {exc}"}


def _resolve_dns_records(host: str, timeout: int) -> dict[str, Any]:
    normalized = _normalize_hostname(host)
    result = {
        "resolved_ips": [],
        "ipv6_addresses": [],
        "cname_chain": [],
        "dns_status": "no_records",
        "resolver_error": "",
    }
    if not normalized:
        result["dns_status"] = "error"
        result["resolver_error"] = "invalid_target_host"
        return result
    try:
        ip_obj = ipaddress.ip_address(normalized)
        if ip_obj.version == 4:
            result["resolved_ips"] = [str(ip_obj)]
        else:
            result["ipv6_addresses"] = [str(ip_obj)]
        result["dns_status"] = "resolved"
        return result
    except ValueError:
        pass

    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(max(1, min(int(timeout or 3), 5)))
    addresses_v4: set[str] = set()
    addresses_v6: set[str] = set()
    try:
        for family, _socktype, _proto, _canonname, sockaddr in socket.getaddrinfo(normalized, None, proto=socket.IPPROTO_TCP):
            address = str(sockaddr[0])
            if family == socket.AF_INET:
                addresses_v4.add(address)
            elif family == socket.AF_INET6:
                addresses_v6.add(address)
        result["resolved_ips"] = sorted(addresses_v4)
        result["ipv6_addresses"] = sorted(addresses_v6)
        result["cname_chain"] = _cname_chain(normalized, timeout)
        result["dns_status"] = "resolved" if addresses_v4 or addresses_v6 or result["cname_chain"] else "no_records"
    except socket.timeout as exc:
        result["dns_status"] = "timeout"
        result["resolver_error"] = str(exc) or "dns timeout"
    except socket.gaierror as exc:
        no_record_codes = {getattr(socket, "EAI_NONAME", None), getattr(socket, "EAI_NODATA", None)}
        if exc.errno in no_record_codes:
            result["dns_status"] = "no_records"
        else:
            result["dns_status"] = "error"
        result["resolver_error"] = str(exc)
    except OSError as exc:
        result["dns_status"] = "error"
        result["resolver_error"] = f"{type(exc).__name__}: {exc}"
    finally:
        socket.setdefaulttimeout(previous_timeout)
    return result


def _reverse_dns_lookup(ip: str, timeout: int) -> str:
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(max(1, min(int(timeout or 2), 3)))
    try:
        hostname, _aliases, _addresses = socket.gethostbyaddr(ip)
        return str(hostname or "").rstrip(".")
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(previous_timeout)


def _ip_version(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip).version)
    except ValueError:
        return 0


def _special_ip_context(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if parsed.is_private:
        return "private"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link_local"
    if parsed.is_reserved:
        return "reserved"
    if parsed.is_multicast:
        return "multicast"
    if not parsed.is_global:
        return "special_use"
    return ""


def _provider_guess_from_text(values: list[str]) -> str:
    text = " ".join(str(value or "") for value in values).lower()
    for token, provider in _CDN_PROVIDER_KEYWORDS:
        if token in text:
            return provider
    return ""


def _provider_guess_from_ip(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if parsed.version == 4:
        for network_text in _CLOUDFLARE_IPV4_RANGES:
            try:
                if parsed in ipaddress.ip_network(network_text):
                    return "Cloudflare"
            except ValueError:
                continue
    return ""


def _passive_infrastructure_lookup_links(ip: str, registered_domain: str | None) -> list[dict[str, Any]]:
    links = [
        ("Open Shodan host lookup", f"https://www.shodan.io/host/{ip}"),
        ("Open Censys host lookup", f"https://search.censys.io/hosts/{ip}"),
        ("Open urlscan IP search", f"https://urlscan.io/search/#{ip}"),
    ]
    if registered_domain:
        links.append(("Open SecurityTrails DNS lookup", f"https://securitytrails.com/domain/{registered_domain}/dns"))
    return [
        {
            "label": label,
            "url": url,
            "url_role": "passive_infrastructure_lookup",
            "url_status": "api_key_missing",
            "check_policy": "api_required",
            "validation_method": "api",
            "final_url": "",
            "content_type": "",
            "http_status": None,
            "validation_error": "",
            "browser_safe": True,
            "render_as_clickable": True,
            "status": "suggestion_only",
            "risk_score_impact": 0,
        }
        for label, url in links
    ]


def _build_infrastructure_intelligence(
    *,
    target_host: str,
    target_registered_domain: str | None,
    timeout: int,
) -> dict[str, Any]:
    dns = _resolve_dns_records(target_host, timeout)
    resolved_ips = [str(ip) for ip in dns.get("resolved_ips", []) if str(ip or "").strip()]
    ipv6_addresses = [str(ip) for ip in dns.get("ipv6_addresses", []) if str(ip or "").strip()]
    cname_chain = [str(item) for item in dns.get("cname_chain", []) if str(item or "").strip()]
    all_ips = resolved_ips + ipv6_addresses
    ownership: list[dict[str, Any]] = []
    passive_links: list[dict[str, Any]] = []
    provider_guesses: list[str] = []
    for ip in all_ips:
        reverse_dns = _reverse_dns_lookup(ip, timeout)
        special_context = _special_ip_context(ip)
        provider_guess = _provider_guess_from_text([reverse_dns] + cname_chain + [target_host, target_registered_domain or ""])
        provider_guess = provider_guess or _provider_guess_from_ip(ip)
        if provider_guess:
            provider_guesses.append(provider_guess)
        status = "lookup_suggested"
        confidence = "low"
        org = ""
        if special_context:
            status = "unavailable"
            confidence = "medium"
            org = f"special-use address: {special_context}"
        ownership.append(
            {
                "ip": ip,
                "ip_version": _ip_version(ip),
                "reverse_dns": reverse_dns,
                "asn": None,
                "as_name": None,
                "org": org,
                "country": None,
                "provider_guess": provider_guess,
                "enrichment_status": status,
                "confidence": confidence,
                "notes": (
                    "No local ASN database was available; passive lookup links were generated."
                    if status == "lookup_suggested"
                    else "ASN lookup skipped for non-global/special-use address."
                ),
            }
        )
        passive_links.extend(_passive_infrastructure_lookup_links(ip, target_registered_domain))

    overall_provider = _provider_guess_from_text(
        cname_chain
        + provider_guesses
        + [item.get("reverse_dns", "") for item in ownership]
        + [target_host, target_registered_domain or ""]
    )
    if not overall_provider:
        for ip in all_ips:
            overall_provider = _provider_guess_from_ip(ip)
            if overall_provider:
                break
    cdn_likely = bool(overall_provider)
    origin_confidence = "low" if cdn_likely else "medium" if all_ips else "unknown"
    return {
        "target_host": _normalize_hostname(target_host),
        "target_registered_domain": target_registered_domain,
        "resolved_ips": resolved_ips,
        "ipv6_addresses": ipv6_addresses,
        "cname_chain": cname_chain,
        "dns_status": str(dns.get("dns_status") or "error"),
        "resolver_error": str(dns.get("resolver_error") or ""),
        "ip_ownership": ownership,
        "cdn_or_proxy_likely": cdn_likely,
        "cdn_provider_guess": overall_provider,
        "origin_confidence": origin_confidence,
        "caveat": _INFRASTRUCTURE_CAVEAT if cdn_likely else "",
        "passive_lookup_links": passive_links,
        "notes": "Infrastructure enrichment is passive DNS/metadata context only; it is not exposure evidence.",
    }


def _extract_html_title(text: str) -> str:
    match = re.search(r"(?is)<title[^>]*>(.*?)</title>", str(text or ""))
    if not match:
        return ""
    return _strip_html(match.group(1)).strip()[:160]


def _body_text(value: str) -> str:
    return _strip_html(str(value or "")).strip()


def _contact_visible_text(value: str) -> str:
    text = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", str(value or ""))
    text = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", text)
    text = re.sub(r"(?is)<svg[^>]*>.*?</svg>", " ", text)
    return _strip_html(text).strip()


def _body_template_signature(value: str) -> str:
    visible = _body_text(value).lower()
    visible = re.sub(r"https?://\S+", " URL ", visible)
    visible = re.sub(r"\b\d+\b", " N ", visible)
    visible = re.sub(r"\s+", " ", visible).strip()
    if not visible:
        return ""
    digest = hashlib.sha1(visible[:5000].encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"{digest}:{len(visible)}"


def _has_soft_error_final_url(final_url: str) -> bool:
    parsed = urlsplit(str(final_url or ""))
    path = parsed.path.lower()
    query = parsed.query.lower()
    return any(marker in path for marker in _SOFT_ERROR_PATH_MARKERS) or any(
        marker in query for marker in _SOFT_ERROR_QUERY_MARKERS
    )


def _has_soft_error_text(value: str) -> bool:
    text = _body_text(value).lower()
    return bool(text and any(marker in text for marker in _SOFT_ERROR_TEXT_MARKERS))


def _soft_error_reasons(*, final_url: str, title: str, body: str) -> list[str]:
    reasons: list[str] = []
    if _has_soft_error_final_url(final_url):
        reasons.append("soft_error_final_url")
    if _has_soft_error_text(title):
        reasons.append("soft_error_title")
    if _has_soft_error_text(body):
        reasons.append("soft_error_body")
    return reasons


def _has_decisive_soft_error_evidence(reasons: list[str]) -> bool:
    return bool({"soft_error_final_url", "soft_error_title"} & set(reasons))


def _redirect_status_for_valid_page(original_url: str, final_url: str, target_registered_domain: str | None = None) -> str:
    original_host = _normalize_hostname(urlsplit(str(original_url or "")).hostname or "")
    final_host = _normalize_hostname(urlsplit(str(final_url or "")).hostname or "")
    original_registered = _registered_domain(original_host) or original_host
    final_registered = _registered_domain(final_host) or final_host
    target_registered = _normalize_hostname(target_registered_domain or "") or original_registered
    if final_host and original_host and final_host != original_host and final_registered != target_registered:
        return "checked_official_affiliate_redirect"
    return "checked_redirect_valid"


def _content_type_matches_page_type(content_type: str, page_type: str, body: str) -> bool:
    lower_type = str(content_type or "").lower()
    lower_body = str(body or "").lstrip().lower()
    if page_type == "security_txt":
        return "text/plain" in lower_type or "text/" in lower_type or bool(_parse_security_txt(body))
    if page_type == "robots":
        return "text/plain" in lower_type or "text/" in lower_type or _looks_like_robots_txt(body)
    if page_type == "sitemap":
        return (
            "xml" in lower_type
            or lower_body.startswith("<?xml")
            or "<urlset" in lower_body
            or "<sitemapindex" in lower_body
        )
    return "text/html" in lower_type


def _looks_like_robots_txt(body: str) -> bool:
    return bool(re.search(r"(?im)^\s*(user-agent|disallow|allow|sitemap)\s*:", str(body or "")))


def _looks_like_sitemap_xml(body: str) -> bool:
    lower = str(body or "").lstrip().lower()
    return bool(lower.startswith("<?xml") or "<urlset" in lower or "<sitemapindex" in lower)


def _apply_organization_page_validation(row: dict[str, Any], *, page_type: str, body: str) -> None:
    url_status = str(row.get("url_status") or "")
    http_status = int(row.get("http_status") or 0)
    final_url = str(row.get("final_url") or row.get("url") or "")
    title = str(row.get("title") or "")
    reasons = _soft_error_reasons(final_url=final_url, title=title, body=body)
    if 200 <= http_status < 400 and _has_decisive_soft_error_evidence(reasons):
        row["url_status"] = "checked_soft_error"
        row["status"] = "checked_soft_error"
        row["check_status"] = "checked"
        row["page_found"] = False
        row["render_as_clickable"] = False
        row["meaning"] = "soft error page, not a valid public page"
        row["rejection_reason"] = reasons
        row["risk_score_impact"] = 0
        return

    if url_status not in {"checked_ok", "checked_redirect"}:
        row["page_found"] = False
        row["status"] = url_status or str(row.get("check_status") or "error")
        if url_status in _NON_ACTIONABLE_URL_STATUSES:
            row["render_as_clickable"] = False
        row["meaning"] = "not evidence; validation context only"
        row["risk_score_impact"] = 0
        return

    if not _content_type_matches_page_type(str(row.get("content_type") or ""), page_type, body):
        row["url_status"] = "checked_unexpected_content"
        row["status"] = "checked_unexpected_content"
        row["page_found"] = False
        row["render_as_clickable"] = False
        row["meaning"] = "unexpected content type/body, not a valid public page"
        row["rejection_reason"] = ["unexpected_content_type"]
        row["risk_score_impact"] = 0
        return

    if page_type == "security_txt" and not _parse_security_txt(body):
        row["url_status"] = "checked_unexpected_content"
        row["status"] = "checked_unexpected_content"
        row["page_found"] = False
        row["render_as_clickable"] = False
        row["meaning"] = "security.txt-like fields not present"
        row["rejection_reason"] = ["security_txt_fields_missing"]
        row["risk_score_impact"] = 0
        return

    if page_type == "robots" and not _looks_like_robots_txt(body):
        row["url_status"] = "checked_unexpected_content"
        row["status"] = "checked_unexpected_content"
        row["page_found"] = False
        row["render_as_clickable"] = False
        row["meaning"] = "robots.txt directives not present"
        row["rejection_reason"] = ["robots_txt_directives_missing"]
        row["risk_score_impact"] = 0
        return

    if page_type == "sitemap" and not _looks_like_sitemap_xml(body):
        row["url_status"] = "checked_unexpected_content"
        row["status"] = "checked_unexpected_content"
        row["page_found"] = False
        row["render_as_clickable"] = False
        row["meaning"] = "sitemap XML markers not present"
        row["rejection_reason"] = ["sitemap_xml_markers_missing"]
        row["risk_score_impact"] = 0
        return

    if url_status == "checked_redirect":
        redirect_status = _redirect_status_for_valid_page(
            str(row.get("url") or ""),
            str(row.get("final_url") or row.get("url") or ""),
            str(row.get("target_registered_domain") or ""),
        )
        row["url_status"] = redirect_status
        url_status = redirect_status
    row["page_found"] = True
    row["render_as_clickable"] = True
    row["status"] = "checked_public_page" if url_status == "checked_ok" else url_status
    row["meaning"] = "official public page exists"
    row["risk_score_impact"] = 0


def _canonical_org_url_key(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return ""
    scheme = "https" if parsed.scheme.lower() in {"http", "https"} else parsed.scheme.lower()
    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        return ""
    port = parsed.port
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    path = parsed.path or "/"
    path = re.sub(r"/+", "/", path)
    if path != "/":
        path = path.rstrip("/")
    kept_query = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key.lower() not in _TRACKING_QUERY_PARAMS and not key.lower().startswith("utm_")
    ]
    query = urlencode(kept_query, doseq=True)
    return urlunsplit((scheme, netloc, path, query, ""))


def _org_page_dedupe_key(row: dict[str, Any]) -> str:
    final_url = str(row.get("final_url") or "").strip()
    original_url = str(row.get("url") or "").strip()
    return _canonical_org_url_key(final_url) or _canonical_org_url_key(original_url)


def _org_page_quality(row: dict[str, Any], body: str) -> tuple[int, int, int, int, int]:
    status = str(row.get("url_status") or "")
    checked_rank = 3 if row.get("page_found") else 0
    status_rank = {
        "checked_ok": 4,
        "checked_redirect": 3,
        "checked_redirect_valid": 3,
        "checked_official_affiliate_redirect": 3,
        "checked_forbidden": 2,
    }.get(status, 1 if status else 0)
    title_rank = 1 if str(row.get("title") or "").strip() else 0
    body_rank = min(len(_body_text(body)), 5000)
    original_rank = 1 if _canonical_org_url_key(str(row.get("url") or "")) == _org_page_dedupe_key(row) else 0
    return (checked_rank, status_rank, title_rank, body_rank, original_rank)


def _dedupe_organization_pages(official_pages: list[dict[str, Any]], row_bodies: dict[str, str]) -> None:
    best_by_key: dict[str, dict[str, Any]] = {}
    for row in official_pages:
        key = _org_page_dedupe_key(row)
        row["dedupe_key"] = key
        if not key:
            continue
        current = best_by_key.get(key)
        if current is None:
            best_by_key[key] = row
            continue
        current_body = row_bodies.get(str(current.get("url") or ""), "")
        row_body = row_bodies.get(str(row.get("url") or ""), "")
        if _org_page_quality(row, row_body) > _org_page_quality(current, current_body):
            best_by_key[key] = row
    for row in official_pages:
        key = str(row.get("dedupe_key") or "")
        if not key:
            continue
        winner = best_by_key.get(key)
        if winner is None or winner is row:
            continue
        row["duplicate_of"] = str(winner.get("final_url") or winner.get("url") or key)
        row["suppressed_reason"] = "duplicate_final_url"
        row["page_found"] = False
        row["render_as_clickable"] = False
        row["status"] = "checked_duplicate"
        row["url_status"] = "checked_duplicate"
        row["meaning"] = "duplicate canonical final URL; suppressed from main tables"
        row["risk_score_impact"] = 0


def _url_status_from_http(http_status: int, final_url: str = "", original_url: str = "") -> str:
    status = int(http_status or 0)
    redirected = bool(final_url and original_url and final_url.rstrip("/") != original_url.rstrip("/"))
    if status in {401, 407}:
        return "auth_required"
    if status == 403:
        return "checked_forbidden"
    if status in {404, 410}:
        return "checked_not_found"
    if 200 <= status < 400:
        return "checked_redirect" if redirected else "checked_ok"
    return "error"


def _http_error_response(exc: HTTPError, original_url: str) -> dict[str, Any]:
    content_type = str(getattr(exc, "headers", {}).get("Content-Type") or "")
    final_url = str(getattr(exc, "url", "") or original_url)
    return {
        "check_status": "checked",
        "url_status": _url_status_from_http(int(getattr(exc, "code", 0) or 0), final_url, original_url),
        "http_status": int(getattr(exc, "code", 0) or 0),
        "final_url": final_url,
        "content_type": content_type,
        "validation_error": "",
    }


def _validation_error_status(exc: BaseException) -> str:
    text = str(exc).lower()
    if isinstance(exc, TimeoutError) or "timed out" in text or "timeout" in text:
        return "timeout"
    if isinstance(exc, ssl.SSLError) or "ssl" in text or "certificate" in text or "tls" in text:
        return "tls_error"
    return "connection_error"


def _validate_osint_url(
    url: str,
    *,
    timeout: int,
    validation_method: str = "head_get",
    parse_title: bool = False,
    max_bytes: int = 262_144,
) -> dict[str, Any]:
    started_url = str(url or "").strip()
    result: dict[str, Any] = {
        "check_policy": "auto_check_allowed",
        "validation_method": validation_method,
        "check_status": "skipped",
        "url_status": "manual_only" if not started_url else "connection_error",
        "http_status": None,
        "final_url": "",
        "content_type": "",
        "title": "",
        "validation_error": "",
        "body": "",
    }
    if not started_url:
        result["validation_error"] = "empty URL"
        return result
    try:
        response: dict[str, Any]
        should_get = validation_method == "get_only"
        if validation_method == "head_get":
            try:
                head = _fetch_limited_response(started_url, timeout, method="HEAD", max_bytes=0)
                head_status = int(head.get("status") or 0)
                head_type = str(head.get("content_type") or "")
                should_get = parse_title and 200 <= head_status < 400 and (
                    not head_type or "html" in head_type.lower() or "text/" in head_type.lower()
                )
                if should_get:
                    response = _fetch_limited_response(started_url, timeout, method="GET", max_bytes=max_bytes)
                else:
                    response = head
            except HTTPError as exc:
                if int(getattr(exc, "code", 0) or 0) in {405, 501}:
                    response = _fetch_limited_response(started_url, timeout, method="GET", max_bytes=max_bytes)
                else:
                    _close_http_error(exc)
                    error_result = _http_error_response(exc, started_url)
                    result.update(error_result)
                    return result
        else:
            response = _fetch_limited_response(started_url, timeout, method="GET", max_bytes=max_bytes)
        http_status = int(response.get("status") or 0)
        final_url = str(response.get("final_url") or started_url)
        body = str(response.get("text") or "")
        result.update(
            {
                "check_status": "checked",
                "url_status": _url_status_from_http(http_status, final_url, started_url),
                "http_status": http_status,
                "final_url": final_url,
                "content_type": str(response.get("content_type") or ""),
                "title": _extract_html_title(body) if parse_title and body else "",
                "body": body,
            }
        )
    except HTTPError as exc:
        _close_http_error(exc)
        result.update(_http_error_response(exc, started_url))
    except (TimeoutError, URLError, OSError, ssl.SSLError) as exc:
        status = _validation_error_status(exc)
        result.update(
            {
                "check_status": "timeout" if status == "timeout" else "error",
                "url_status": status,
                "validation_error": _error_label(exc),
            }
        )
        _close_http_error(exc)
    return result


def _parse_security_txt(text: str) -> dict[str, list[str]]:
    parsed: dict[str, list[str]] = {}
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        field = _SECURITY_TXT_FIELDS.get(key.strip().lower())
        value = value.strip()
        if field and value:
            parsed.setdefault(field, [])
            if value not in parsed[field]:
                parsed[field].append(value)
    return parsed


def _contact_email_from_value(value: str) -> str:
    text = str(value or "").strip()
    if text.lower().startswith("mailto:"):
        text = text[7:]
    match = re.search(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", text)
    return match.group(0).lower() if match else ""


_CONTACT_URL_PATH_RE = re.compile(
    r"(?i)(?:^|[/_-])("
    r"contact|contact-us|support|help|abuse|security|disclosure|responsible-disclosure|"
    r"vulnerability-disclosure|bug[-_]?bounty|report[-_]?vulnerability|report[-_]?abuse|"
    r"security-report|customer-service|customer-support"
    r")(?:$|[/_.\-\s])"
)
_CONTACT_URL_HOST_RE = re.compile(r"(?i)\b(hackerone|bugcrowd|intigriti|yeswehack)\.")
_CONTACT_CONTEXT_RE = re.compile(r"(?i)\b(phone|tel|telephone|customer service|support|contact|abuse|legal|privacy|security|help)\b")
_CONTACT_FORM_ACCEPT_RE = re.compile(
    r"(?i)(?:^|/)"
    r"(?:contact(?:[-_/]?us)?|support/contact|help/contact|customer[-_/]support/contact|"
    r"customer[-_/]service/contact|contact[-_/]form|security[-_/]report|report[-_/]vulnerability|"
    r"vulnerability[-_/]disclosure|responsible[-_/]disclosure|report[-_/]abuse)"
    r"(?:$|[/?#._\-\s])"
)
_CONTACT_FORM_REJECT_RE = re.compile(
    r"(?i)(?:^|[/&?=_-])("
    r"login|log-in|signin|sign-in|signup|sign-up|register|newsletter|subscribe|store-locator|"
    r"storelocator|stores?|locations?|careers?|jobs?|cart|checkout|app|mobile-app|rewards?|"
    r"privacy|terms|cookie|share|sharer|intent|tweet|campaign|promo|coupon|deal|utm_[a-z]+"
    r")(?:$|[/&?=#._\-\s])"
)


def _is_contact_endpoint_url(value: str, *, contact_type: str = "", source: str = "") -> bool:
    url = str(value or "").strip()
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    if str(source or "").strip() == "security_txt":
        return True
    text = " ".join(
        part
        for part in (
            parsed.netloc,
            parsed.path,
            parsed.query,
            str(contact_type or ""),
        )
        if part
    )
    return bool(_CONTACT_URL_HOST_RE.search(parsed.netloc) or _CONTACT_URL_PATH_RE.search(text))


def _contact_rejection_reason(value: str, *, contact_type: str = "", source: str = "") -> str:
    url = str(value or "").strip()
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return "not_http_url"
    if str(source or "").strip() == "security_txt":
        return ""
    text = " ".join(part for part in (parsed.path, parsed.query, str(contact_type or "")) if part)
    if _CONTACT_FORM_REJECT_RE.search(text):
        return "non_contact_or_tracking_url"
    if contact_type == "contact_form" and not (_CONTACT_URL_HOST_RE.search(parsed.netloc) or _CONTACT_FORM_ACCEPT_RE.search(text)):
        return "not_a_real_contact_support_form"
    if not _is_contact_endpoint_url(value, contact_type=contact_type, source=source):
        return "not_contact_endpoint"
    return ""


def _is_contact_form_url(value: str, *, context: str = "", source: str = "") -> bool:
    reason = _contact_rejection_reason(value, contact_type="contact_form", source=source)
    if reason:
        return False
    parsed = urlsplit(str(value or "").strip())
    text = " ".join(part for part in (parsed.path, parsed.query, context) if part)
    return bool(_CONTACT_URL_HOST_RE.search(parsed.netloc) or _CONTACT_FORM_ACCEPT_RE.search(text))


def _contact_endpoint_from_value(value: str) -> tuple[str, str]:
    text = str(value or "").strip()
    if not text:
        return "", "unknown"
    email = _contact_email_from_value(text)
    if email:
        return email, "email"
    lower = text.lower()
    if lower.startswith(("http://", "https://")):
        parsed = urlsplit(text)
        path_text = " ".join(part for part in (parsed.path, parsed.query) if part)
        endpoint_type = "contact_form" if _CONTACT_FORM_ACCEPT_RE.search(path_text) else "url"
        return text, endpoint_type
    return text, "unknown"


def _official_page_url(host: str, path: str) -> str:
    clean_path = str(path or "/")
    if not clean_path.startswith("/"):
        clean_path = f"/{clean_path}"
    return f"https://{_normalize_hostname(host)}{clean_path}"


def _contact_endpoint_registered_domain(endpoint: str, contact_type: str) -> str:
    value = str(endpoint or "").strip()
    ctype = str(contact_type or "").strip().lower()
    host = ""
    if ctype == "email" and "@" in value:
        host = value.rsplit("@", 1)[-1]
    elif ctype in {"url", "form", "contact_form", "security_txt"}:
        host = urlsplit(value).hostname or ""
    return _registered_domain(host) or _normalize_hostname(host)


def _contact_domain_relationship(
    *,
    endpoint_registered_domain: str,
    target_registered_domain: str,
    observed: bool,
    source_url: str,
    contact_type: str,
) -> tuple[bool | None, str]:
    ctype = str(contact_type or "").strip().lower()
    if ctype == "phone":
        return None, "not_applicable"
    if not endpoint_registered_domain:
        return False, "unknown"
    same_registered = bool(target_registered_domain and endpoint_registered_domain == target_registered_domain)
    if same_registered:
        return True, "same_registered_domain"
    if observed and source_url:
        return False, "official_affiliate_domain"
    return False, "external_domain_unverified"


def _enrich_contact_domain_metadata(contact: dict[str, Any], target_registered_domain: str) -> dict[str, Any]:
    endpoint = str(contact.get("contact_endpoint") or "")
    ctype = str(contact.get("contact_type") or "").strip().lower() or "unknown"
    endpoint_registered = _contact_endpoint_registered_domain(endpoint, ctype)
    same_registered, relationship = _contact_domain_relationship(
        endpoint_registered_domain=endpoint_registered,
        target_registered_domain=target_registered_domain,
        observed=bool(contact.get("observed")),
        source_url=str(contact.get("source_url") or ""),
        contact_type=ctype,
    )
    contact["same_registered_domain"] = same_registered
    contact["endpoint_registered_domain"] = endpoint_registered
    contact["domain_relationship"] = relationship
    if "confidence" not in contact:
        if bool(contact.get("observed")) and relationship == "same_registered_domain":
            contact["confidence"] = "high"
        elif bool(contact.get("observed")) and relationship == "official_affiliate_domain":
            contact["confidence"] = "medium"
        elif ctype == "phone" and bool(contact.get("observed")):
            contact["confidence"] = "medium"
        else:
            contact["confidence"] = "low"
    contact["risk_score_impact"] = 0
    contact["account_validated"] = False
    return contact


def _contact_summary(
    *,
    observed_email_addresses: list[dict[str, Any]],
    observed_phone_numbers: list[dict[str, Any]],
    observed_contact_urls: list[dict[str, Any]],
    observed_contact_forms: list[dict[str, Any]],
    generated_role_email_guesses: list[dict[str, Any]],
    suppressed_contacts: list[dict[str, Any]],
) -> dict[str, int]:
    return {
        "observed_email_addresses_count": len(observed_email_addresses),
        "observed_phone_numbers_count": len(observed_phone_numbers),
        "observed_contact_urls_count": len(observed_contact_urls),
        "observed_contact_forms_count": len(observed_contact_forms),
        "generated_role_email_guesses_count": len(generated_role_email_guesses),
        "suppressed_contacts_count": len(suppressed_contacts),
        "observed_public_contacts_count": (
            len(observed_email_addresses)
            + len(observed_phone_numbers)
            + len(observed_contact_urls)
            + len(observed_contact_forms)
        ),
    }


def _role_contact_candidates(registered_domain: str | None) -> list[dict[str, Any]]:
    domain = _normalize_hostname(registered_domain or "")
    if not domain or _looks_like_ip(domain):
        return []
    return [
        {
            "contact_endpoint": f"{role}@{domain}",
            "contact_type": "email",
            "source": "generated_candidate",
            "source_url": "",
            "observed": False,
            "status": "generated_guess",
            "verification_level": "not_observed_not_verified",
            "account_validated": False,
            "same_registered_domain": True,
            "endpoint_registered_domain": domain,
            "domain_relationship": "same_registered_domain",
            "check_policy": "generated_candidate",
            "validation_method": "not_applicable",
            "url_status": "generated_candidate",
            "final_url": "",
            "content_type": "",
            "http_status": None,
            "validation_error": "",
            "personal_data": False,
            "confidence": "low",
            "confidence_reason": "Generated role-address guess; not observed on a public official page.",
            "display_value": f"{role}@{domain}",
            "source_page_type": "unknown",
            "source_title": "",
            "extraction_method": "regex",
            "is_generated_guess": True,
            "risk_score_impact": 0,
            "note": "Generated role email guess only; not observed or verified.",
        }
        for role in _ORG_ROLE_CONTACTS
    ]


def _security_txt_contact_rows(fields: dict[str, list[str]], source_url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in fields.get("Contact", []):
        contact, contact_type = _contact_endpoint_from_value(value)
        if not contact or contact.lower() in seen:
            continue
        seen.add(contact.lower())
        rows.append(
            {
                "contact_endpoint": contact,
                "contact_type": contact_type,
                "value": contact,
                "display_value": contact,
                "source": "security_txt",
                "source_url": source_url,
                "source_page_type": "security_txt",
                "source_title": "security.txt",
                "extraction_method": "security_txt",
                "observed": True,
                "status": "observed_public_contact",
                "verification_level": "observed_on_public_source",
                "account_validated": False,
                "check_policy": "auto_check_allowed",
                "validation_method": "get_only",
                "url_status": "checked_ok",
                "final_url": source_url,
                "content_type": "text/plain",
                "http_status": 200,
                "validation_error": "",
                "personal_data": False,
                "confidence": "high",
                "confidence_reason": "Observed in Contact field of validated security.txt.",
                "is_generated_guess": False,
                "risk_score_impact": 0,
                "validation": "not_verified_no_account_validation",
            }
        )
    return rows


def _official_page_is_safe_source(row: dict[str, Any], registered_domain: str | None) -> bool:
    if not isinstance(row, dict) or not row.get("page_found"):
        return False
    if str(row.get("url_status") or "") in _NON_ACTIONABLE_URL_STATUSES:
        return False
    content_type = str(row.get("content_type") or "").lower()
    if "text/html" not in content_type and "html" not in content_type:
        return False
    source_url = str(row.get("final_url") or row.get("url") or "")
    host = _normalize_hostname(urlsplit(source_url).hostname or "")
    source_registered = _registered_domain(host) or host
    target_registered = _normalize_hostname(registered_domain or "")
    return bool(source_url and (not target_registered or source_registered == target_registered or str(row.get("url_status") or "") == "checked_official_affiliate_redirect"))


def _valid_official_html_pages(
    official_pages: list[dict[str, Any]],
    row_bodies: dict[str, str],
    registered_domain: str | None,
) -> list[tuple[dict[str, Any], str]]:
    rows: list[tuple[dict[str, Any], str]] = []
    for row in official_pages:
        if not _official_page_is_safe_source(row, registered_domain):
            continue
        body = row_bodies.get(str(row.get("url") or ""), "")
        if body:
            rows.append((row, body))
    return rows


def _json_loads_loose(value: str) -> Any:
    try:
        return json.loads(unescape(str(value or "").strip()))
    except json.JSONDecodeError:
        cleaned = re.sub(r"(?is)^\s*<!--|-->\s*$", "", str(value or "").strip())
        try:
            return json.loads(unescape(cleaned))
        except Exception:
            return None


def _extract_json_ld_objects(body: str) -> list[Any]:
    objects: list[Any] = []
    for match in re.finditer(
        r"(?is)<script[^>]+type=[\"']application/ld\+json[\"'][^>]*>(.*?)</script>",
        str(body or ""),
    ):
        parsed = _json_loads_loose(match.group(1))
        if parsed is not None:
            objects.append(parsed)
    return objects


def _iter_jsonld_nodes(value: Any) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    if isinstance(value, dict):
        nodes.append(value)
        graph = value.get("@graph")
        if isinstance(graph, list):
            for item in graph:
                nodes.extend(_iter_jsonld_nodes(item))
        for key in ("address", "contactPoint", "sameAs"):
            nested = value.get(key)
            if isinstance(nested, (dict, list)):
                nodes.extend(_iter_jsonld_nodes(nested))
    elif isinstance(value, list):
        for item in value:
            nodes.extend(_iter_jsonld_nodes(item))
    return nodes


def _jsonld_type_set(node: dict[str, Any]) -> set[str]:
    raw = node.get("@type")
    values = raw if isinstance(raw, list) else [raw]
    return {str(item).strip().lower() for item in values if str(item or "").strip()}


def _address_text_from_dict(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    parts = [
        value.get("streetAddress"),
        value.get("addressLocality"),
        value.get("addressRegion"),
        value.get("postalCode"),
        value.get("addressCountry"),
    ]
    return ", ".join(str(part).strip() for part in parts if str(part or "").strip())


_LOCATION_ADDRESS_KEYWORD_RE = re.compile(
    r"(?i)\b("
    r"headquarters|hq|office|address|registered office|corporate office|"
    r"genel müdürlük|sirket merkezi|şirket merkezi|adres"
    r")\b"
)
_LOCATION_STREET_RE = re.compile(
    r"(?i)\b\d{1,6}\s+[A-Za-z0-9][A-Za-z0-9 .'-]{1,80}\s+"
    r"(?:street|st\.?|avenue|ave\.?|road|rd\.?|boulevard|blvd\.?|drive|dr\.?|lane|ln\.?|"
    r"way|plaza|square|parkway|pkwy\.?|court|ct\.?|circle|cir\.?|terrace|ter\.?)\b"
)
_LOCATION_POSTAL_RE = re.compile(r"(?i)(?:\b\d{5}(?:-\d{4})?\b|\b[A-Z]\d[A-Z][ -]?\d[A-Z]\d\b)")
_LOCATION_CITY_STATE_RE = re.compile(
    r"\b[A-Z][A-Za-z.'-]+(?:\s+[A-Z][A-Za-z.'-]+){0,3},\s*(?:[A-Z]{2}|[A-Z][A-Za-z.'-]{2,})\b"
)
_LOCATION_NOISE_RE = re.compile(
    r"(?i)\b("
    r"store locator|find a store|food,\s*drinks\s*&\s*fuel|store chain by newsweek|"
    r"trust is a major factor|franchise|discount|coupon|promo|promotion|deal|sale|course|training|"
    r"lesson|statistic|statistics|percent|shop now|limited time"
    r")\b"
)
_LOCATION_NAVIGATION_RE = re.compile(
    r"(?i)\b(store locator|find a store|menu|navigation|footer|privacy policy|terms of use|site map)\b"
)


def _clean_location_text(value: str) -> str:
    printable = "".join(ch if ch.isprintable() or ch in "\t\r\n" else " " for ch in unescape(str(value or "")))
    return re.sub(r"\s+", " ", printable).strip(" .,\t\r\n")


def _looks_like_binary_location_text(value: str) -> bool:
    text = str(value or "")
    if not text:
        return False
    checked = text[:4000]
    control_count = sum(1 for ch in checked if not ch.isprintable() and ch not in "\t\r\n")
    replacement_count = checked.count("\ufffd")
    return (control_count + replacement_count) >= 6 and ((control_count + replacement_count) / max(len(checked), 1)) > 0.03


def _location_evidence_flags(value: str, *, schema_postal_address: bool = False, contact_address_label: bool = False) -> set[str]:
    text = _clean_location_text(value)
    flags: set[str] = set()
    if _LOCATION_STREET_RE.search(text):
        flags.add("street_number_street_name")
    if _LOCATION_POSTAL_RE.search(text):
        flags.add("postal_code")
    if _LOCATION_CITY_STATE_RE.search(text):
        flags.add("city_state_country")
    if _LOCATION_ADDRESS_KEYWORD_RE.search(text):
        flags.add("address_keyword")
    if schema_postal_address:
        flags.add("schema_postal_address")
    if contact_address_label:
        flags.add("contact_page_address_label")
    return flags


def _location_rejection_reason(value: str, flags: set[str]) -> str:
    text = _clean_location_text(value)
    if _looks_like_binary_location_text(value):
        return "weak_address_evidence"
    if re.search(r"(?i)\b(store locator|find a store)\b", text) and "street_number_street_name" not in flags:
        return "store_locator_without_address"
    if _LOCATION_NAVIGATION_RE.search(text) and len(flags) < 2:
        return "not_address_navigation_text"
    if _LOCATION_NOISE_RE.search(text) and len(flags) < 2:
        return "not_address_marketing_text"
    return "weak_address_evidence"


def _strong_location_text(value: str, *, schema_postal_address: bool = False, contact_address_label: bool = False) -> bool:
    if _looks_like_binary_location_text(value):
        return False
    flags = _location_evidence_flags(
        value,
        schema_postal_address=schema_postal_address,
        contact_address_label=contact_address_label,
    )
    return len(flags) >= 2


def _location_type_from_text(value: str, source_page_type: str = "") -> str:
    text = f"{source_page_type} {value}".lower()
    if any(marker in text for marker in ("headquarters", " hq", "corporate office", "registered office", "genel müdürlük", "şirket merkezi", "sirket merkezi")):
        return "headquarters"
    if "support" in text or "customer service" in text or "help" in text:
        return "support"
    if "store" in text or "branch" in text:
        return "store"
    if "office" in text or "address" in text or "adres" in text:
        return "office"
    return "unknown"


def _location_candidate(
    *,
    label: str,
    address_text: str,
    source_url: str,
    source_type: str,
    source_page_type: str,
    source_title: str = "",
    confidence: str,
    confidence_reason: str = "",
    status: str = "official_observed_location",
) -> dict[str, Any]:
    cleaned = _clean_location_text(address_text)
    page_type = str(source_page_type or source_type or "unknown").strip() or "unknown"
    return {
        "label": label,
        "location_text": cleaned,
        "address_text": cleaned,
        "location_type": _location_type_from_text(cleaned, page_type),
        "source": source_type,
        "source_url": source_url,
        "source_type": source_type,
        "source_page_type": page_type,
        "source_title": source_title,
        "observed": True,
        "status": status,
        "verification_level": "observed_on_official_source",
        "confidence": confidence,
        "confidence_reason": confidence_reason
        or "Extracted from a validated official public page with sufficient address-like components.",
        "rejection_reason": [],
        "risk_score_impact": 0,
        "url_role": "official_page",
        "url_status": "checked_ok",
        "browser_safe": _is_browser_safe_osint_url(source_url),
        "render_as_clickable": _is_browser_safe_osint_url(source_url),
        "caveat": "Observed on a validated official source; verify relevance before using as authoritative location data.",
    }


def _location_candidate_from_hint(hint: dict[str, Any]) -> dict[str, Any]:
    return _location_candidate(
        label="Observed official location/address text",
        address_text=str(hint.get("location_hint") or ""),
        source_url=str(hint.get("source_url") or ""),
        source_type="official_page",
        source_page_type=str(hint.get("source_page_type") or "official_page"),
        source_title=str(hint.get("source_title") or ""),
        confidence=str(hint.get("confidence") or "medium"),
        confidence_reason="Extracted from visible official page text with address/location markers.",
    )


def _dedupe_location_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    sortable = sorted(
        (item for item in candidates if isinstance(item, dict)),
        key=lambda item: len(str(item.get("address_text") or "")),
    )
    for item in sortable:
        if not isinstance(item, dict):
            continue
        address = _clean_location_text(str(item.get("address_text") or ""))
        if not address or _looks_like_binary_location_text(address):
            continue
        key = re.sub(r"[^a-z0-9]+", " ", address.lower()).strip()
        if not key or key in seen or any((key in existing or existing in key) and min(len(key), len(existing)) > 20 for existing in seen):
            continue
        item["address_text"] = address
        seen.add(key)
        deduped.append(item)
    return deduped


def _extract_structured_location_candidates(
    body: str,
    source_url: str,
    *,
    source_page_type: str = "json_ld",
    source_title: str = "",
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for parsed in _extract_json_ld_objects(body):
        for node in _iter_jsonld_nodes(parsed):
            types = _jsonld_type_set(node)
            address_value = node.get("address")
            address_text = ""
            if isinstance(address_value, dict):
                address_text = _address_text_from_dict(address_value)
            elif "postaladdress" in types:
                address_text = _address_text_from_dict(node)
            if not address_text:
                continue
            if types and not (types & {"organization", "localbusiness", "postaladdress", "corporation", "governmentorganization"}):
                continue
            if not _strong_location_text(address_text, schema_postal_address=True):
                continue
            candidates.append(
                _location_candidate(
                    label=str(node.get("name") or "Structured official postal address"),
                    address_text=address_text,
                    source_url=source_url,
                    source_type="structured_data",
                    source_page_type="json_ld",
                    source_title=source_title,
                    confidence="high",
                    confidence_reason="Structured schema.org PostalAddress found on a validated official page.",
                )
            )
    return candidates


def _normalize_phone_candidate(value: str) -> str:
    text = unescape(str(value or "")).strip()
    if text.lower().startswith("tel:"):
        text = text[4:]
    text = re.sub(r"(?i)^(phone|tel|telephone)\s*[:\-]\s*", "", text).strip()
    return re.sub(r"\s+", " ", text)


def _valid_phone_candidate(value: str, *, context: str = "", tel_link: bool = False, structured_contact: bool = False) -> str:
    phone = _normalize_phone_candidate(value)
    if not phone:
        return ""
    decimal_groups = re.findall(r"\d+\.\d+", phone)
    if len(decimal_groups) > 1:
        return ""
    if any(len(group.split(".", 1)[1]) > 2 for group in decimal_groups):
        return ""
    number_groups = re.findall(r"\d+(?:\.\d+)?", phone)
    if len(number_groups) >= 4 and not re.search(r"[+()\-]", phone):
        short_groups = sum(1 for group in number_groups if len(re.sub(r"\D", "", group)) <= 2)
        if short_groups >= len(number_groups) - 1:
            return ""
    digits = re.sub(r"\D", "", phone)
    if len(digits) < 7 or len(digits) > 15:
        return ""
    if re.search(r"[A-Za-z]", phone):
        return ""
    compact_punctuation = re.sub(r"[\d\s]", "", phone)
    if compact_punctuation and not re.fullmatch(r"[+().\-]+", compact_punctuation):
        return ""
    has_phone_shape = bool(
        phone.startswith("+")
        or re.search(r"\(\s*\d{2,4}\s*\)", phone)
        or re.search(r"\d{2,4}[\s.-]\d{3,4}[\s.-]\d{3,4}", phone)
        or re.search(r"\d{3}[\s.-]\d{3}[\s.-]\d{4}", phone)
    )
    has_context = tel_link or structured_contact or bool(_CONTACT_CONTEXT_RE.search(context))
    if not has_phone_shape or not has_context:
        return ""
    return phone


def _contact_candidate_rejection(url: str, *, source_url: str, reason: str, source_page_type: str, source_title: str) -> dict[str, Any]:
    return {
        "candidate_type": "contact",
        "value": url,
        "contact_endpoint": url,
        "source_url": source_url,
        "source_page_type": source_page_type or "unknown",
        "source_title": source_title,
        "status": "rejected_contact_candidate",
        "rejection_reason": reason,
        "confidence": "low",
        "confidence_reason": "Rejected during strict official-page contact extraction.",
        "observed": False,
        "is_generated_guess": False,
        "risk_score_impact": 0,
    }


def _extract_official_contact_rows(
    body: str,
    source_url: str,
    *,
    source_page_type: str = "unknown",
    source_title: str = "",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(
        endpoint: str,
        contact_type: str,
        source: str = "official_page",
        *,
        context: str = "",
        tel_link: bool = False,
        structured_contact: bool = False,
        extraction_method: str = "visible_html",
    ) -> None:
        normalized = str(endpoint or "").strip()
        ctype = str(contact_type or "unknown").strip() or "unknown"
        if ctype == "form":
            ctype = "contact_form"
        if not normalized:
            return
        if ctype == "phone":
            normalized = _valid_phone_candidate(
                normalized,
                context=context,
                tel_link=tel_link,
                structured_contact=structured_contact,
            )
            if not normalized:
                return
        if ctype == "contact_form" and not _is_contact_form_url(normalized, context=context, source=source):
            rejected.append(
                _contact_candidate_rejection(
                    normalized,
                    source_url=source_url,
                    reason=_contact_rejection_reason(normalized, contact_type="contact_form", source=source) or "not_a_real_contact_support_form",
                    source_page_type=source_page_type,
                    source_title=source_title,
                )
            )
            return
        if ctype == "url" and not _is_contact_endpoint_url(normalized, contact_type=context or ctype, source=source):
            return
        key_endpoint = re.sub(r"\D", "", normalized) if ctype == "phone" else normalized.lower()
        key = (key_endpoint, ctype)
        if key in seen:
            return
        seen.add(key)
        confidence_reason = {
            "email": "Observed as a public mailto/email contact on a validated official page.",
            "phone": "Observed with phone/support/contact context on a validated official page.",
            "contact_form": "Observed as an official contact/support/help/security-report link on a validated official page.",
            "url": "Observed as an official public contact URL on a validated official page.",
            "security_txt": "Observed in validated security.txt.",
        }.get(ctype, "Observed on a validated official page.")
        rows.append(
            {
                "contact_endpoint": normalized,
                "contact_type": ctype,
                "value": normalized,
                "display_value": normalized,
                "source": source,
                "source_url": source_url,
                "source_page_type": source_page_type or "unknown",
                "source_title": source_title,
                "extraction_method": extraction_method,
                "observed": True,
                "status": "observed_public_contact",
                "verification_level": "observed_on_public_source",
                "account_validated": False,
                "check_policy": "auto_check_allowed",
                "validation_method": "get_only",
                "url_status": "checked_ok",
                "final_url": source_url,
                "content_type": "text/html",
                "http_status": 200,
                "validation_error": "",
                "personal_data": False,
                "confidence_reason": confidence_reason,
                "is_generated_guess": False,
                "risk_score_impact": 0,
                "validation": "not_verified_no_account_validation",
            }
        )

    for match in re.finditer(r"(?is)href=[\"']mailto:([^\"'#?]+)", str(body or "")):
        add(unescape(match.group(1)).strip(), "email", extraction_method="visible_html")
    for match in re.finditer(r"(?is)href=[\"']tel:([^\"'#?]+)", str(body or "")):
        add(unescape(match.group(1)).strip(), "phone", context="tel link", tel_link=True, extraction_method="visible_html")
    for match in re.finditer(r"(?is)href=[\"']([^\"']+)[\"']", str(body or "")):
        href = unescape(match.group(1)).strip()
        if not href or href.lower().startswith(("mailto:", "tel:", "#", "javascript:")):
            continue
        if _document_candidate_url(href, source_url):
            continue
        contact_url = urljoin(source_url, href)
        if _is_contact_form_url(contact_url, context="form", source="official_page"):
            add(contact_url, "contact_form", "official_page", context="form", extraction_method="link_relation")
        else:
            reason = _contact_rejection_reason(contact_url, contact_type="contact_form", source="official_page")
            if reason and len(rejected) < 50:
                rejected.append(
                    _contact_candidate_rejection(
                        contact_url,
                        source_url=source_url,
                        reason=reason,
                        source_page_type=source_page_type,
                        source_title=source_title,
                    )
                )
    for parsed in _extract_json_ld_objects(body):
        for node in _iter_jsonld_nodes(parsed):
            types = _jsonld_type_set(node)
            if "contactpoint" not in types and not any(key in node for key in ("email", "telephone", "url", "contactType")):
                continue
            contact_type = str(node.get("contactType") or "").strip().lower()
            structured_contact = "contactpoint" in types or bool(contact_type)
            if node.get("email"):
                email_value = str(node.get("email") or "").strip()
                if email_value.lower().startswith("mailto:"):
                    email_value = email_value[7:]
                add(email_value, "email", "structured_data", extraction_method="json_ld")
            if node.get("telephone"):
                add(
                    str(node.get("telephone") or "").strip(),
                    "phone",
                    "structured_data",
                    context=contact_type,
                    structured_contact=structured_contact,
                    extraction_method="json_ld",
                )
            if node.get("url"):
                url_value = str(node.get("url") or "").strip()
                if structured_contact or _is_contact_endpoint_url(url_value, contact_type=contact_type, source="structured_data"):
                    add(url_value, "contact_form" if "form" in contact_type or _is_contact_form_url(url_value, context=contact_type, source="structured_data") else "url", "structured_data", context=contact_type, extraction_method="json_ld")
    text = _contact_visible_text(body)
    phone_context_re = re.compile(r"(?i)\b(phone|tel|telephone|customer service|support|contact|abuse|legal|privacy|security|help)\b.{0,80}?(\+?\d[\d\s().-]{7,}\d)")
    for match in phone_context_re.finditer(text):
        add(match.group(2), "phone", context=match.group(0), extraction_method="regex")
        if len(rows) >= 20:
            break
    return rows, rejected


def _social_candidate_rejection(url: str, *, source_url: str, source: str, reason: str) -> dict[str, Any]:
    return {
        "candidate_type": "social_profile",
        "url": url,
        "profile_url": url,
        "source": source,
        "source_url": source_url,
        "status": "rejected_social_candidate",
        "rejection_reason": reason,
        "confidence": "low",
        "confidence_reason": "Rejected during strict official social profile extraction.",
        "observed": False,
        "risk_score_impact": 0,
    }


def _extract_social_profile_rows(body: str, source_url: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    urls: list[tuple[str, str]] = []
    for match in re.finditer(r"(?is)href=[\"']([^\"']+)[\"']", str(body or "")):
        href = unescape(match.group(1)).strip()
        if href:
            urls.append((urljoin(source_url, href), "official_page"))
    for parsed in _extract_json_ld_objects(body):
        for node in _iter_jsonld_nodes(parsed):
            same_as = node.get("sameAs")
            values = same_as if isinstance(same_as, list) else [same_as]
            for value in values:
                if str(value or "").strip():
                    urls.append((str(value).strip(), "structured_data"))
    rows: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for url, source in urls:
        parsed = urlsplit(url)
        host = _normalize_hostname(parsed.hostname or "")
        profile_type = _SOCIAL_PROFILE_HOSTS.get(host)
        if not profile_type or not parsed.scheme.startswith("http"):
            continue
        if not _is_official_social_profile_url(parsed, profile_type):
            if len(rejected) < 50:
                rejected.append(_social_candidate_rejection(url, source_url=source_url, source=source, reason="not_official_profile_or_share_intent"))
            continue
        normalized_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") or "/", parsed.query, ""))
        key = normalized_url.lower()
        if key in seen:
            rejected.append(_social_candidate_rejection(normalized_url, source_url=source_url, source=source, reason="duplicate_profile_url"))
            continue
        seen.add(key)
        rows.append(
            {
                "label": f"{profile_type} profile linked from official source",
                "url": normalized_url,
                "profile_url": normalized_url,
                "profile_type": profile_type,
                "provider": profile_type,
                "source": source,
                "source_url": source_url,
                "extraction_method": "json_ld" if source == "structured_data" else "link_relation",
                "observed": True,
                "status": "observed_official_social_profile",
                "verification_level": "linked_from_official_source",
                "confidence": "high",
                "confidence_reason": "Linked from validated official page or JSON-LD sameAs.",
                "risk_score_impact": 0,
                "url_role": "observed_official_social_profile",
                "url_status": "checked_ok",
                "browser_safe": True,
                "render_as_clickable": True,
            }
        )
    return rows, rejected


def _is_official_social_profile_url(parsed: Any, profile_type: str) -> bool:
    path = str(getattr(parsed, "path", "") or "/").strip() or "/"
    lower_path = path.lower()
    query = str(getattr(parsed, "query", "") or "").lower()
    blocked_markers = (
        "/share",
        "/sharer",
        "/intent",
        "/tweet",
        "/hashtag",
        "/search",
        "/plugins",
        "/dialog",
        "/sharearticle",
        "/embed",
        "/watch",
        "/status/",
        "/posts/",
        "/p/",
        "/reel/",
        "/explore",
        "/accounts/",
    )
    if any(marker in lower_path for marker in blocked_markers):
        return False
    if any(marker in query for marker in ("share", "intent", "url=", "text=", "utm_")):
        return False
    if profile_type == "linkedin":
        return lower_path.startswith(("/company/", "/school/", "/showcase/"))
    if profile_type == "youtube":
        return lower_path.startswith(("/channel/", "/c/", "/user/", "/@"))
    if profile_type == "tiktok":
        return lower_path.startswith("/@")
    if profile_type == "medium":
        return lower_path == "/" or lower_path.startswith("/@") or lower_path.count("/") == 1
    if profile_type in {"github", "instagram", "facebook", "x"}:
        return lower_path != "/"
    return False


def _is_public_metadata_json_path(path: str) -> bool:
    lower_path = str(path or "").lower()
    if not lower_path.endswith(".json"):
        return True
    return any(
        marker in lower_path
        for marker in (
            "policy",
            "privacy",
            "security",
            "metadata",
            "manifest",
            "assetlinks",
            "apple-app-site-association",
            "well-known",
        )
    )


def _document_candidate_url(value: str, base_url: str = "") -> str:
    url = urljoin(base_url, unescape(str(value or "").strip()))
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    path = parsed.path.lower()
    if not any(path.endswith(ext) for ext in _DOCUMENT_EXTENSIONS):
        return ""
    if path.endswith(".json") and not _is_public_metadata_json_path(path):
        return ""
    return url


def _extract_document_links_from_page(body: str, source_url: str) -> list[str]:
    urls: list[str] = []
    for match in re.finditer(r"(?is)href=[\"']([^\"']+)[\"']", str(body or "")):
        candidate = _document_candidate_url(match.group(1), source_url)
        if candidate:
            urls.append(candidate)
    return urls


def _extract_document_links_from_sitemap(body: str, source_url: str) -> list[str]:
    urls: list[str] = []
    for match in re.finditer(r"(?is)<loc>\s*([^<]+?)\s*</loc>", str(body or "")):
        candidate = _document_candidate_url(match.group(1), source_url)
        if candidate:
            urls.append(candidate)
    return urls


def _validate_public_document_candidate(url: str, *, source_url: str, source_type: str, timeout: int) -> dict[str, Any]:
    validation = _validate_osint_url(
        url,
        timeout=timeout,
        validation_method="head_get",
        parse_title=False,
        max_bytes=65_536,
    )
    body = str(validation.pop("body", "") or "")
    content_type = str(validation.get("content_type") or "").split(";", 1)[0].strip().lower()
    status = str(validation.get("url_status") or "")
    path = urlsplit(url).path.lower()
    valid_type = content_type in _DOCUMENT_CONTENT_TYPES or any(path.endswith(ext) for ext in _DOCUMENT_EXTENSIONS)
    document_type = _document_type_from_url(url)
    row: dict[str, Any] = {
        "label": url.rsplit("/", 1)[-1] or "public document",
        "url": url,
        "document_type": document_type,
        "source_url": source_url,
        "source_type": source_type,
        "validation_method": "head_get",
        "content_type": content_type,
        "observed": False,
        "status": "rejected_document_candidate",
        "verification_level": "not_validated",
        "confidence": "low",
        "confidence_reason": "Candidate document was not validated as a safe public metadata/policy document.",
        "rejection_reason": [],
        "risk_score_impact": 0,
        "url_role": "public_document_search",
        "browser_safe": _is_browser_safe_osint_url(url),
        "render_as_clickable": False,
    }
    row.update(validation)
    if status in {"checked_ok", "checked_redirect", "checked_redirect_valid", "checked_official_affiliate_redirect"} and valid_type:
        row.update(
            {
                "observed": True,
                "status": "validated_public_document",
                "verification_level": "validated_public_official_link",
                "confidence": "medium",
                "confidence_reason": "Validated public document URL linked from an official page or sitemap; content was not deeply parsed.",
                "url_role": "validated_public_document",
                "check_policy": str(row.get("check_policy") or "auto_check_allowed"),
                "validation_method": str(row.get("validation_method") or "head_get"),
                "url_status": status,
                "render_as_clickable": bool(row["browser_safe"]),
                "caveat": "Validated public document URL linked from an official source; file content was not deeply parsed.",
            }
        )
    else:
        reasons = []
        if status in _NON_ACTIONABLE_URL_STATUSES or status not in {"checked_ok", "checked_redirect", "checked_redirect_valid", "checked_official_affiliate_redirect"}:
            reasons.append(status or "not_checked")
        if not valid_type:
            reasons.append("unexpected_document_content_type")
        if body:
            reasons.append("body_ignored")
        row["rejection_reason"] = reasons
        row["render_as_clickable"] = False
    return row


def _document_type_from_url(url: str) -> str:
    path = urlsplit(str(url or "")).path.lower()
    if path.endswith("/.well-known/security.txt") or path.endswith("security.txt"):
        return "security_txt"
    if path.endswith("/robots.txt") or path.endswith("robots.txt"):
        return "robots_txt"
    if path.endswith("/sitemap.xml") or path.endswith("sitemap.xml"):
        return "sitemap_xml"
    if path.endswith(".pdf"):
        return "pdf"
    if path.endswith(".txt"):
        return "txt"
    if path.endswith(".xml"):
        return "xml"
    if path.endswith(".json"):
        return "json"
    return "public_document"


def _duplicate_document_candidate(url: str, *, source_url: str, source_type: str) -> dict[str, Any]:
    return {
        "label": url.rsplit("/", 1)[-1] or "public document",
        "url": url,
        "document_type": _document_type_from_url(url),
        "source_url": source_url,
        "source_type": source_type,
        "validation_method": "duplicate_suppression",
        "content_type": "",
        "http_status": None,
        "observed": False,
        "status": "rejected_document_candidate",
        "verification_level": "not_validated",
        "confidence": "low",
        "confidence_reason": "Duplicate final URL suppressed before validation table insertion.",
        "rejection_reason": ["duplicate_final_url"],
        "risk_score_impact": 0,
        "url_role": "public_document_search",
        "browser_safe": _is_browser_safe_osint_url(url),
        "render_as_clickable": False,
    }


def _public_document_record_from_official_page(row: dict[str, Any]) -> dict[str, Any]:
    url = str(row.get("final_url") or row.get("url") or "")
    page_type = str(row.get("page_type") or "")
    label = {
        "security_txt": "security.txt",
        "robots": "robots.txt",
        "sitemap": "sitemap.xml",
    }.get(page_type, url.rsplit("/", 1)[-1] or "public document")
    return {
        "label": label,
        "url": url,
        "document_type": _document_type_from_url(url),
        "source_url": url,
        "source_type": page_type or "official_page",
        "observed": True,
        "status": "validated_public_document",
        "verification_level": "validated_public_official_page",
        "confidence": "high",
        "confidence_reason": "Validated as an official metadata document page.",
        "content_type": str(row.get("content_type") or ""),
        "http_status": row.get("http_status"),
        "check_policy": str(row.get("check_policy") or "auto_check_allowed"),
        "validation_method": str(row.get("validation_method") or "get_only"),
        "url_status": str(row.get("url_status") or "checked_ok"),
        "final_url": url,
        "validation_error": str(row.get("validation_error") or ""),
        "rejection_reason": [],
        "risk_score_impact": 0,
        "url_role": "validated_public_document",
        "browser_safe": _is_browser_safe_osint_url(url),
        "render_as_clickable": _is_browser_safe_osint_url(url),
        "caveat": "Validated public metadata document discovered as an official organization page; content was not deeply parsed.",
    }


def _contact_dedupe_value(item: dict[str, Any]) -> str:
    ctype = str(item.get("contact_type") or "").strip().lower()
    value = str(item.get("value") or item.get("contact_endpoint") or "").strip()
    if ctype == "phone":
        return re.sub(r"\D", "", value)
    if ctype in {"contact_form", "form", "url", "security_txt"}:
        return _normalize_url_key(value) or value.lower()
    return value.lower()


def _duplicate_contact_candidate(item: dict[str, Any]) -> dict[str, Any]:
    row = dict(item)
    row["status"] = "suppressed_duplicate_contact"
    row["suppression_reason"] = "duplicate_observed_contact"
    row["observed"] = False
    row["confidence"] = "low"
    row["confidence_reason"] = "Duplicate observed contact suppressed from the main evidence table."
    row["risk_score_impact"] = 0
    return row


def _dedupe_observed_contacts_with_suppressed(contacts: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    deduped: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in contacts:
        if not isinstance(item, dict):
            continue
        if not item.get("observed"):
            deduped.append(item)
            continue
        ctype = str(item.get("contact_type") or "").strip().lower()
        if ctype == "form":
            item["contact_type"] = "contact_form"
            ctype = "contact_form"
        key = (_contact_dedupe_value(item), str(item.get("scope_origin") or ""), ctype)
        if key[0] and key in seen:
            suppressed.append(_duplicate_contact_candidate(item))
            continue
        seen.add(key)
        deduped.append(item)
    return deduped, suppressed


def _duplicate_social_candidate(item: dict[str, Any]) -> dict[str, Any]:
    row = dict(item)
    row["status"] = "suppressed_duplicate_social_profile"
    row["rejection_reason"] = "duplicate_social_profile"
    row["observed"] = False
    row["confidence"] = "low"
    row["confidence_reason"] = "Duplicate official social profile suppressed from the main evidence table."
    row["risk_score_impact"] = 0
    return row


def _dedupe_social_profiles_with_suppressed(profiles: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    deduped: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in profiles:
        if not isinstance(item, dict):
            continue
        provider = str(item.get("provider") or item.get("profile_type") or "").strip().lower()
        profile_url = str(item.get("profile_url") or item.get("url") or "").strip()
        normalized = _normalize_url_key(profile_url) or profile_url.lower()
        key = (provider, normalized, str(item.get("scope_origin") or ""))
        if normalized and key in seen:
            suppressed.append(_duplicate_social_candidate(item))
            continue
        seen.add(key)
        deduped.append(item)
    return deduped, suppressed


def _mail_infrastructure_intelligence(registered_domain: str | None, timeout: int) -> dict[str, Any]:
    domain = _normalize_hostname(registered_domain or "")
    result: dict[str, Any] = {
        "target_registered_domain": domain,
        "mx_status": "not_checked",
        "mx_records": [],
        "spf_status": "not_checked",
        "dmarc_status": "not_checked",
        "dkim_status": "not_checked",
        "spf_records": [],
        "dmarc_records": [],
        "resolver_method": "dnspython",
        "validation_error": "",
        "observed_public_contacts": [],
        "generated_role_contact_guesses": [],
        "suppressed_contacts": [],
        "email_summary": {
            "observed_public_contacts_count": 0,
            "generated_role_guesses_count": 0,
            "mx_records_count": 0,
            "suppressed_contacts_count": 0,
        },
        "policy": {
            "passive_dns_only": True,
            "no_smtp_connection": True,
            "no_mailbox_validation": True,
            "risk_score_impact": "none",
        },
        "note": "Mail infrastructure does not prove individual inbox existence.",
    }
    if not domain or _looks_like_ip(domain):
        return result

    mx = _query_dns_records(domain, "MX", timeout)
    txt = _query_dns_records(domain, "TXT", timeout)
    dmarc = _query_dns_records(f"_dmarc.{domain}", "TXT", timeout)
    txt_status = str(txt.get("status") or "resolver_error")
    dmarc_query_status = str(dmarc.get("status") or "resolver_error")
    spf_records = [record for record in txt.get("records", []) if str(record).strip().lower().startswith("v=spf1")]
    dmarc_records = [record for record in dmarc.get("records", []) if str(record).strip().lower().startswith("v=dmarc1")]
    spf_status = "present" if spf_records else txt_status if txt_status in {"timeout", "resolver_error", "dependency_missing"} else "absent"
    dmarc_status = "present" if dmarc_records else dmarc_query_status if dmarc_query_status in {"timeout", "resolver_error", "dependency_missing"} else "absent"
    validation_errors = [
        str(item.get("validation_error") or "")
        for item in (mx, txt, dmarc)
        if str(item.get("validation_error") or "").strip()
    ]
    resolver_methods = [
        str(item.get("resolver_method") or "")
        for item in (mx, txt, dmarc)
        if str(item.get("resolver_method") or "").strip()
    ]
    result.update(
        {
            "mx_status": str(mx.get("status") or "resolver_error"),
            "mx_records": list(mx.get("records") or []),
            "mx_validation_error": str(mx.get("validation_error") or mx.get("error") or ""),
            "spf_status": spf_status,
            "spf_records": spf_records,
            "spf_validation_error": str(txt.get("validation_error") or txt.get("error") or ""),
            "dmarc_status": dmarc_status,
            "dmarc_records": dmarc_records,
            "dmarc_validation_error": str(dmarc.get("validation_error") or dmarc.get("error") or ""),
            "resolver_method": ", ".join(sorted(set(resolver_methods))) or "dnspython",
            "validation_error": "; ".join(validation_errors),
        }
    )
    result["email_summary"]["mx_records_count"] = len(result["mx_records"])
    return result


def _organization_lookup_links(brand: str, registered_domain: str | None) -> list[dict[str, Any]]:
    domain = _normalize_hostname(registered_domain or "")
    company = str(brand or domain or "").strip()
    query_company = quote_plus(company or domain)
    query_domain = quote_plus(domain or company)
    items = [
        ("Open LinkedIn company search", f"https://www.linkedin.com/search/results/companies/?keywords={query_company}"),
        ("Open Crunchbase company search", f"https://www.crunchbase.com/search/organizations/field/organizations/name/{query_company}"),
        ("Open GitHub organization search", f"https://github.com/search?q={query_domain}&type=users"),
        ("Open Twitter/X search", f"https://x.com/search?q={query_company}&src=typed_query"),
        ("Open Facebook page search", f"https://www.facebook.com/search/pages/?q={query_company}"),
        ("Open YouTube search", f"https://www.youtube.com/results?search_query={query_company}"),
        ("Open Google official company profile search", f"https://www.google.com/search?q={quote_plus((company or domain) + ' official company profile')}"),
    ]
    return [
        {
            "label": label,
            "url": url,
            "url_role": "organization_lookup_shortcut",
            "url_status": "manual_only",
            "check_policy": "manual_only",
            "validation_method": "not_applicable",
            "final_url": "",
            "content_type": "",
            "http_status": None,
            "validation_error": "",
            "browser_safe": True,
            "render_as_clickable": True,
            "status": "suggestion_only",
            "risk_score_impact": 0,
        }
        for label, url in items
        if url
    ]


def _location_lookup_links(brand: str, registered_domain: str | None) -> list[dict[str, Any]]:
    domain = _normalize_hostname(registered_domain or "")
    company = str(brand or domain or "").strip()
    retail_caveat = bool(re.search(r"(?i)\b(7[- ]?eleven|retail|store|franchise)\b", company or domain))
    links = [
        (
            "Google Maps brand search — may return local stores or unrelated businesses.",
            f"https://www.google.com/maps/search/{quote_plus(company or domain)}",
            "manual location search shortcut, not verified office",
            "Retail/franchise map results may point to a local store, not corporate office or target infrastructure." if retail_caveat else "Maps search may return local results unrelated to headquarters or target infrastructure.",
        ),
        (
            f"Open location lookup: {company} offices" if company else "",
            f"https://www.google.com/search?q={quote_plus(f'{company} offices')}" if company else "",
            "manual location search shortcut, not verified office",
            "No verified official office/location was observed unless listed under official location hints.",
        ),
        (
            f"Open location lookup: {company} headquarters" if company else "",
            f"https://www.google.com/search?q={quote_plus(f'{company} headquarters')}" if company else "",
            "manual location search shortcut, not verified office",
            "No verified official office/location was observed unless listed under official location hints.",
        ),
        (
            f"Open location lookup: {domain} contact address" if domain else "",
            f"https://www.google.com/search?q={quote_plus(f'{domain} contact address')}" if domain else "",
            "manual location search shortcut, not verified office",
            "No verified official office/location was observed unless listed under official location hints.",
        ),
    ]
    return [
        {
            "label": label,
            "url": url,
            "url_role": "location_lookup_shortcut",
            "url_status": "manual_only",
            "check_policy": "manual_only",
            "validation_method": "not_applicable",
            "final_url": "",
            "content_type": "",
            "http_status": None,
            "validation_error": "",
            "browser_safe": True,
            "render_as_clickable": True,
            "status": "suggestion_only",
            "observed": False,
            "verification_level": "not_verified_manual_lookup",
            "source_type": "manual_shortcut",
            "confidence": "low",
            "risk_score_impact": 0,
            "meaning": meaning,
            "caveat": caveat,
        }
        for label, url, meaning, caveat in links
        if label and url
    ]


def _people_lookup_shortcuts(brand: str, registered_domain: str | None) -> list[dict[str, Any]]:
    domain = _normalize_hostname(registered_domain or "")
    company = str(brand or domain or "").strip()
    query_company = quote_plus(company or domain)
    query_domain = quote_plus(domain or company)
    brand_slug = re.sub(r"[^a-z0-9-]+", "-", (company or domain).lower()).strip("-")
    links = [
        ("LinkedIn company search", f"https://www.linkedin.com/search/results/companies/?keywords={query_company}"),
        ("Crunchbase company search", f"https://www.crunchbase.com/search/organizations/field/organizations/name/{query_company}"),
        ("GitHub organization search", f"https://github.com/search?q={query_domain}&type=users"),
        ("Google company leadership search", f"https://www.google.com/search?q={quote_plus((company or domain) + ' leadership team')}"),
    ]
    rows = [
        {
            "label": label,
            "url": url,
            "url_role": "people_lookup_shortcut",
            "url_status": "manual_only",
            "check_policy": "manual_only",
            "validation_method": "not_applicable",
            "browser_safe": True,
            "render_as_clickable": True,
            "status": "suggestion_only",
            "risk_score_impact": 0,
            "note": "manual lookup shortcut, not scraped result.",
        }
        for label, url in links
        if url
    ]
    if brand_slug:
        rows.append(
            {
                "label": "Open GitHub direct organization candidate",
                "url": f"https://github.com/{quote(brand_slug)}",
                "url_role": "people_lookup_shortcut",
                "url_status": "manual_only",
                "check_policy": "auto_check_allowed",
                "validation_method": "head_get",
                "browser_safe": True,
                "render_as_clickable": True,
                "status": "suggestion_only",
                "confidence": "low",
                "risk_score_impact": 0,
                "note": "Possible public organization profile candidate only; repositories and people are not scraped.",
                "profile_candidate_type": "github_org_landing",
            }
        )
    return rows


def _validate_github_org_shortcut(item: dict[str, Any], *, brand: str, timeout: int) -> None:
    if str(item.get("profile_candidate_type") or "") != "github_org_landing":
        return
    validation = _validate_osint_url(
        str(item.get("url") or ""),
        timeout=timeout,
        validation_method="head_get",
        parse_title=True,
        max_bytes=80_000,
    )
    body = str(validation.pop("body", "") or "")
    item.update(validation)
    status = str(item.get("url_status") or "")
    title = str(item.get("title") or "")
    text = f"{title} {_body_text(body)[:500]}".lower()
    brand_tokens = [token for token in re.split(r"[^a-z0-9]+", str(brand or "").lower()) if token]
    plausible = status in {"checked_ok", "checked_redirect"} and (
        "github" in text or any(token and token in text for token in brand_tokens)
    )
    if plausible:
        item["status"] = "possible_official_org_profile"
        item["confidence"] = "medium" if brand_tokens and any(token in text for token in brand_tokens) else "low"
        item["url_status"] = status
        item["meaning"] = "Possible public organization profile landing page; not a finding."
    else:
        item["status"] = "suggestion_only"
        item["confidence"] = "low"
        item["url_status"] = status if status else "manual_only"
        item["meaning"] = "Manual profile shortcut only; not validated as official."
    item["risk_score_impact"] = 0
    item["check_policy"] = "auto_check_allowed"
    item["validation_method"] = "head_get"


def _public_document_searches(registered_domain: str | None) -> list[dict[str, Any]]:
    domain = _normalize_hostname(registered_domain or "")
    if not domain:
        return []
    queries = [
        f"site:{domain} filetype:pdf",
        f"site:{domain} (filetype:doc OR filetype:docx)",
        f"site:{domain} (filetype:xls OR filetype:xlsx)",
        f"site:{domain} \"confidential\"",
        f"site:{domain} \"internal use only\"",
    ]
    return [
        {
            "label": f"Open public document search: {query}",
            "query": query,
            "url": f"https://www.google.com/search?q={quote_plus(query)}",
            "url_role": "public_document_search",
            "url_status": "manual_only",
            "check_policy": "manual_only",
            "validation_method": "not_applicable",
            "final_url": "",
            "content_type": "",
            "http_status": None,
            "validation_error": "",
            "browser_safe": True,
            "render_as_clickable": True,
            "status": "suggestion_only",
            "risk_score_impact": 0,
        }
        for query in queries
    ]


def _rejected_location_candidate(*, text: str, source_url: str, source_type: str, rejection_reason: str) -> dict[str, Any]:
    return {
        "text": _clean_location_text(text)[:240],
        "source_url": source_url,
        "source_type": source_type,
        "rejection_reason": rejection_reason,
        "status": "rejected_location_candidate",
        "observed": False,
        "verification_level": "not_verified_rejected",
        "risk_score_impact": 0,
    }


def _dedupe_rejected_location_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in candidates:
        if not isinstance(item, dict):
            continue
        text = _clean_location_text(str(item.get("text") or ""))
        if not text or _looks_like_binary_location_text(text):
            continue
        key = (re.sub(r"[^a-z0-9]+", " ", text.lower()).strip(), str(item.get("source_url") or ""))
        if not key[0] or key in seen:
            continue
        seen.add(key)
        item["text"] = text
        deduped.append(item)
        if len(deduped) >= 25:
            break
    return deduped


def _extract_location_hints_with_rejections(text: str, source_url: str, *, page_type: str = "") -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if _looks_like_binary_location_text(text):
        return [], []
    clean = _clean_location_text(_strip_html(str(text or "")))
    if not clean:
        return [], []
    hints: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen: set[str] = set()
    noisy_phrase_re = re.compile(
        r"(?i)\b(?:store locator|find a store|food,\s*drinks\s*&\s*fuel|store chain by newsweek|trust is a major factor|menu|footer|franchise)\b"
    )
    patterns = (
        r"(?i)\b(?:headquarters|hq|corporate office|registered office|office|address|located at|genel müdürlük|şirket merkezi|sirket merkezi|adres)\b.{0,180}",
        r"(?i)\b\d{1,6}\s+[A-Z][A-Za-z0-9 .,\-']{10,160}\b(?:\s+\d{5}(?:-\d{4})?)?",
        r"(?i)\b(?:store locator|find a store|food,\s*drinks\s*&\s*fuel|store chain by newsweek|trust is a major factor|menu|footer|franchise).{0,80}",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, clean):
            value = _clean_location_text(match.group(0))[:220]
            if not value:
                continue
            canonical = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
            if not canonical or canonical in seen:
                continue
            seen.add(canonical)
            contact_address_label = page_type == "contact" and bool(_LOCATION_ADDRESS_KEYWORD_RE.search(value))
            flags = _location_evidence_flags(value, contact_address_label=contact_address_label)
            if len(flags) < 2:
                rejected.append(
                    _rejected_location_candidate(
                        text=value,
                        source_url=source_url,
                        source_type="official_page",
                        rejection_reason=_location_rejection_reason(value, flags),
                    )
                )
                continue
            hints.append(
                {
                    "location_hint": value,
                    "dedupe_key": canonical,
                    "source_url": source_url,
                    "confidence": "high" if {"street_number_street_name", "postal_code"} <= flags else "medium",
                    "status": "observed_public_location_hint",
                    "caveat": "Public page/location hint only; manually validate.",
                    "evidence_flags": sorted(flags),
                    "risk_score_impact": 0,
                }
            )
            if len(hints) >= 5:
                break
    for match in noisy_phrase_re.finditer(clean):
        value = _clean_location_text(match.group(0))
        canonical = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
        if value and canonical and canonical not in seen:
            seen.add(canonical)
            rejected.append(
                _rejected_location_candidate(
                    text=value,
                    source_url=source_url,
                    source_type="official_page",
                    rejection_reason=_location_rejection_reason(value, set()),
                )
            )
    return hints, _dedupe_rejected_location_candidates(rejected)


def _extract_location_hints(text: str, source_url: str) -> list[dict[str, Any]]:
    hints, _rejected = _extract_location_hints_with_rejections(text, source_url)
    return hints


def _dedupe_location_hints(hints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    sortable = sorted(
        (hint for hint in hints if isinstance(hint, dict)),
        key=lambda hint: len(str(hint.get("location_hint") or "")),
    )
    for hint in sortable:
        key = str(hint.get("dedupe_key") or re.sub(r"[^a-z0-9]+", " ", str(hint.get("location_hint") or "").lower()).strip())
        if not key or key in seen:
            continue
        if any((key in existing or existing in key) and min(len(key), len(existing)) > 20 for existing in seen):
            continue
        seen.add(key)
        deduped.append(hint)
    return deduped


def _build_organization_intelligence(
    *,
    target_host: str,
    target_registered_domain: str | None,
    organization_aliases: list[str],
    timeout: int,
    check_pages: bool = False,
    events: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    host = _normalize_hostname(target_host)
    registered = _normalize_hostname(target_registered_domain or "") or host
    brand = next((alias for alias in organization_aliases if alias and "." not in alias), "") or registered
    hosts: list[str] = []
    for candidate in (registered, host):
        normalized = _normalize_hostname(candidate)
        if normalized and normalized not in hosts and not _looks_like_ip(normalized):
            hosts.append(normalized)

    official_pages: list[dict[str, Any]] = []
    security_txt: dict[str, Any] = {
        "status": "not_checked",
        "found": False,
        "found_url": "",
        "fields": {},
        "contacts": [],
        "checked_urls": [],
        "caveat": "Public security contact metadata only; ReconBot does not validate inboxes or submit reports.",
    }
    role_contacts = _role_contact_candidates(registered)
    email_intelligence = _mail_infrastructure_intelligence(registered, min(timeout, 5))
    location_hints: list[dict[str, Any]] = []
    observed_locations: list[dict[str, Any]] = []
    rejected_location_candidates: list[dict[str, Any]] = []
    observed_page_contacts: list[dict[str, Any]] = []
    rejected_contact_candidates: list[dict[str, Any]] = []
    observed_social_profiles: list[dict[str, Any]] = []
    rejected_social_candidates: list[dict[str, Any]] = []
    security_attempts = 0
    security_statuses: list[str] = []
    found_security_fields: dict[str, list[str]] = {}
    found_security_url = ""
    row_bodies: dict[str, str] = {}

    for current_host in hosts:
        for path, page_type in _ORG_OFFICIAL_PATHS:
            url = _official_page_url(current_host, path)
            row: dict[str, Any] = {
                "url": url,
                "page_type": page_type,
                "target_registered_domain": registered,
                "check_policy": "auto_check_allowed",
                "validation_method": "get_only" if path in _ORG_SPECIAL_CHECK_PATHS else "head_get",
                "check_status": "skipped",
                "http_status": None,
                "title": "",
                "url_role": "security_txt" if page_type == "security_txt" else "official_page",
                "url_status": "manual_only",
                "final_url": "",
                "content_type": "",
                "validation_error": "",
                "page_found": False,
                "browser_safe": True,
                "render_as_clickable": False,
                "status": "manual_only" if not check_pages and path not in _ORG_SPECIAL_CHECK_PATHS else "suggestion_only",
                "risk_score_impact": 0,
            }
            if check_pages or path in _ORG_SPECIAL_CHECK_PATHS:
                validation = _validate_osint_url(
                    url,
                    timeout=timeout,
                    validation_method=str(row["validation_method"]),
                    parse_title=page_type not in {"security_txt", "sitemap", "robots"},
                    max_bytes=262_144,
                )
                body = str(validation.pop("body", "") or "")
                row.update(validation)
                if page_type not in {"security_txt", "sitemap", "robots"} and body and not row.get("title"):
                    row["title"] = _extract_html_title(body)
                _apply_organization_page_validation(row, page_type=page_type, body=body)
                row_bodies[url] = body
                if row["page_found"] and page_type in {"homepage", "about", "contact"}:
                    hints, rejected_locations = _extract_location_hints_with_rejections(body, url, page_type=page_type)
                    for hint in hints:
                        hint["source_page_type"] = page_type
                        hint["source_title"] = str(row.get("title") or "")
                    location_hints.extend(hints)
                    rejected_location_candidates.extend(rejected_locations)
                if page_type == "security_txt":
                    security_attempts += 1
                    security_txt["checked_urls"].append(url)
                    security_statuses.append(str(row.get("url_status") or ""))
                    fields = _parse_security_txt(body) if row["page_found"] else {}
                    if fields and not found_security_fields:
                        found_security_fields = fields
                        found_security_url = str(row.get("final_url") or url)
            official_pages.append(row)

    signature_groups: dict[str, list[dict[str, Any]]] = {}
    for row in official_pages:
        if not isinstance(row, dict) or not row.get("page_found"):
            continue
        body = row_bodies.get(str(row.get("url") or ""), "")
        signature = _body_template_signature(body)
        if signature:
            signature_groups.setdefault(signature, []).append(row)
    for rows in signature_groups.values():
        page_types = {str(row.get("page_type") or "") for row in rows}
        if len(rows) < 3 or len(page_types) < 2:
            continue
        error_like = any(
            _has_soft_error_text(str(row.get("title") or "")) or _has_soft_error_final_url(str(row.get("final_url") or ""))
            for row in rows
        )
        if not error_like:
            continue
        for row in rows:
            row["page_found"] = False
            row["status"] = "checked_soft_error"
            row["url_status"] = "checked_soft_error"
            row["check_status"] = "checked"
            row["render_as_clickable"] = False
            row["meaning"] = "soft error page, not a valid public page"
            reasons = list(row.get("rejection_reason") or [])
            if "repeated_error_template" not in reasons:
                reasons.append("repeated_error_template")
            row["rejection_reason"] = reasons
            row["risk_score_impact"] = 0

    _dedupe_organization_pages(official_pages, row_bodies)

    for row, body in _valid_official_html_pages(official_pages, row_bodies, registered):
        source_url = str(row.get("final_url") or row.get("url") or "")
        page_type = str(row.get("page_type") or "")
        if page_type in {"homepage", "about", "contact", "support", "security", "legal", "privacy", "press", "careers"}:
            observed_locations.extend(
                _extract_structured_location_candidates(
                    body,
                    source_url,
                    source_page_type=page_type,
                    source_title=str(row.get("title") or ""),
                )
            )
            extracted_contacts, rejected_contacts = _extract_official_contact_rows(
                body,
                source_url,
                source_page_type=page_type,
                source_title=str(row.get("title") or ""),
            )
            observed_page_contacts.extend(extracted_contacts)
            rejected_contact_candidates.extend(rejected_contacts)
        extracted_profiles, rejected_profiles = _extract_social_profile_rows(body, source_url)
        observed_social_profiles.extend(extracted_profiles)
        rejected_social_candidates.extend(rejected_profiles)

    if found_security_fields:
        observed_contacts = _security_txt_contact_rows(found_security_fields, found_security_url)
        security_txt.update(
            {
                "status": "found",
                "found": True,
                "found_url": found_security_url,
                "fields": found_security_fields,
                "contacts": observed_contacts,
                "check_policy": "auto_check_allowed",
                "validation_method": "get_only",
                "url_status": "checked_ok",
                "final_url": found_security_url,
                "content_type": "text/plain",
                "http_status": 200,
                "validation_error": "",
            }
        )
        role_contacts.extend(observed_contacts)
    elif security_attempts:
        fallback_status = "checked_not_found"
        for candidate_status in security_statuses:
            if candidate_status in {"checked_soft_error", "checked_unexpected_content", "timeout", "connection_error", "tls_error"}:
                fallback_status = candidate_status
                break
        security_txt.update(
            {
                "status": fallback_status,
                "check_policy": "auto_check_allowed",
                "validation_method": "get_only",
                "url_status": fallback_status,
                "validation_error": "",
            }
        )

    for item in observed_page_contacts:
        endpoint = str(item.get("contact_endpoint") or "").lower()
        contact_type = str(item.get("contact_type") or "")
        if endpoint:
            role_contacts = [
                existing
                for existing in role_contacts
                if not (
                    isinstance(existing, dict)
                    and str(existing.get("source") or "") == "generated_candidate"
                    and endpoint == str(existing.get("contact_endpoint") or "").lower()
                    and contact_type == str(existing.get("contact_type") or "")
                )
            ]
        if endpoint and not any(
            endpoint == str(existing.get("contact_endpoint") or "").lower()
            and contact_type == str(existing.get("contact_type") or "")
            for existing in role_contacts
            if isinstance(existing, dict)
        ):
            role_contacts.append(item)

    organization_lookup_links = _organization_lookup_links(brand, registered)
    location_lookup_links = _location_lookup_links(brand, registered)
    public_document_searches = _public_document_searches(registered)
    company_profile_lookup_shortcuts = _people_lookup_shortcuts(brand, registered)
    for item in company_profile_lookup_shortcuts:
        if isinstance(item, dict):
            _validate_github_org_shortcut(item, brand=brand, timeout=min(timeout, 5))
    location_hints = _dedupe_location_hints(location_hints)
    rejected_location_candidates = _dedupe_rejected_location_candidates(rejected_location_candidates)
    observed_locations.extend(_location_candidate_from_hint(hint) for hint in location_hints)
    observed_locations = _dedupe_location_candidates(observed_locations)
    official_location_pages = [
        page
        for page in official_pages
        if isinstance(page, dict)
        and page.get("page_found")
        and str(page.get("page_type") or "") in {"homepage", "about", "contact", "support", "legal", "privacy", "press", "careers"}
        and any(str(location.get("source_url") or "") == str(page.get("final_url") or page.get("url") or "") for location in observed_locations)
    ]
    location_intelligence = {
        "target_registered_domain": registered,
        "observed_locations": observed_locations,
        "official_location_pages": official_location_pages,
        "external_location_candidates": [],
        "rejected_location_candidates": rejected_location_candidates,
        "location_lookup_shortcuts": location_lookup_links,
        "location_summary": {
            "observed_locations_count": len(observed_locations),
            "official_location_pages_count": len(official_location_pages),
            "external_candidates_count": 0,
            "rejected_candidates_count": len(rejected_location_candidates),
            "fallback_shortcuts_count": len(location_lookup_links),
        },
        "policy": {
            "official_sources_only_without_api_keys": True,
            "external_directory_results_require_manual_verification": True,
            "risk_score_impact": "none",
        },
    }

    document_candidates: list[dict[str, Any]] = []
    seen_document_urls: set[str] = set()
    for row in official_pages:
        if (
            isinstance(row, dict)
            and row.get("page_found")
            and str(row.get("page_type") or "") in {"security_txt", "robots", "sitemap"}
            and str(row.get("url_status") or "") in {"checked_ok", "checked_redirect", "checked_redirect_valid", "checked_official_affiliate_redirect"}
        ):
            document_url = str(row.get("final_url") or row.get("url") or "")
            key = _normalize_url_key(document_url)
            if key and key not in seen_document_urls:
                seen_document_urls.add(key)
                document_candidates.append(_public_document_record_from_official_page(row))
            elif key:
                document_candidates.append(_duplicate_document_candidate(document_url, source_url=document_url, source_type=str(row.get("page_type") or "official_page")))
    for row, body in _valid_official_html_pages(official_pages, row_bodies, registered):
        source_url = str(row.get("final_url") or row.get("url") or "")
        for document_url in _extract_document_links_from_page(body, source_url):
            key = _normalize_url_key(document_url)
            if key and key not in seen_document_urls:
                seen_document_urls.add(key)
                document_candidates.append(
                    _validate_public_document_candidate(
                        document_url,
                        source_url=source_url,
                        source_type="official_page_link",
                        timeout=min(timeout, 5),
                    )
                )
            elif key:
                document_candidates.append(_duplicate_document_candidate(document_url, source_url=source_url, source_type="official_page_link"))
    for row in official_pages:
        if not isinstance(row, dict) or not row.get("page_found") or str(row.get("page_type") or "") != "sitemap":
            continue
        source_url = str(row.get("final_url") or row.get("url") or "")
        body = row_bodies.get(str(row.get("url") or ""), "")
        for document_url in _extract_document_links_from_sitemap(body, source_url):
            key = _normalize_url_key(document_url)
            if key and key not in seen_document_urls:
                seen_document_urls.add(key)
                document_candidates.append(
                    _validate_public_document_candidate(
                        document_url,
                        source_url=source_url,
                        source_type="sitemap",
                        timeout=min(timeout, 5),
                    )
                )
            elif key:
                document_candidates.append(_duplicate_document_candidate(document_url, source_url=source_url, source_type="sitemap"))
    validated_public_documents = [item for item in document_candidates if item.get("status") == "validated_public_document"]
    rejected_document_candidates = [item for item in document_candidates if item.get("status") != "validated_public_document"]
    public_document_intelligence = {
        "validated_public_documents": validated_public_documents,
        "document_candidates": document_candidates,
        "rejected_document_candidates": rejected_document_candidates,
        "manual_document_search_shortcuts": public_document_searches,
        "document_summary": {
            "validated_public_documents_count": len(validated_public_documents),
            "document_candidates_count": len(document_candidates),
            "rejected_document_candidates_count": len(rejected_document_candidates),
            "duplicate_suppressed_candidates_count": sum(
                1
                for item in rejected_document_candidates
                if isinstance(item, dict) and "duplicate_final_url" in (item.get("rejection_reason") or [])
            ),
            "fallback_shortcuts_count": len(public_document_searches),
        },
        "policy": {
            "safe_head_get_validation_only": True,
            "large_file_download_performed": False,
            "deep_personal_data_parsing_performed": False,
            "risk_score_impact": "none",
        },
    }

    for item in role_contacts:
        if isinstance(item, dict):
            _enrich_contact_domain_metadata(item, registered)
            _apply_scope_provenance(
                item,
                requested_target_host=host,
                requested_registered_domain=registered,
                observed=bool(item.get("observed")),
            )
    observed_public_contacts = [item for item in role_contacts if item.get("observed")]
    generated_role_guesses = [item for item in role_contacts if item.get("source") == "generated_candidate"]
    for item in generated_role_guesses:
        if isinstance(item, dict):
            item["mx_domain_status"] = str(email_intelligence.get("mx_status") or "not_checked")
    suppressed_contacts: list[dict[str, Any]] = []
    if email_intelligence.get("mx_status") == "absent":
        for item in generated_role_guesses:
            suppressed = dict(item)
            suppressed["status"] = "suppressed_no_mx"
            suppressed["suppression_reason"] = "domain_has_no_mx"
            suppressed["confidence"] = "very_low"
            suppressed_contacts.append(suppressed)
        role_contacts = [item for item in role_contacts if item.get("source") != "generated_candidate"]
        generated_role_guesses = []
    observed_email_addresses = [item for item in observed_public_contacts if str(item.get("contact_type") or "") == "email"]
    observed_phone_numbers = [item for item in observed_public_contacts if str(item.get("contact_type") or "") == "phone"]
    observed_contact_forms = [item for item in observed_public_contacts if str(item.get("contact_type") or "") in {"form", "contact_form"}]
    observed_contact_urls = [item for item in observed_public_contacts if str(item.get("contact_type") or "") == "url"]
    for collection in (
        official_pages,
        organization_lookup_links,
        location_lookup_links,
        public_document_searches,
        company_profile_lookup_shortcuts,
        location_hints,
        rejected_location_candidates,
        observed_locations,
        official_location_pages,
        document_candidates,
        validated_public_documents,
        rejected_document_candidates,
        observed_social_profiles,
        rejected_contact_candidates,
        rejected_social_candidates,
    ):
        for item in collection:
            if not isinstance(item, dict):
                continue
            if item in (document_candidates + validated_public_documents + rejected_document_candidates):
                url_keys = ("url", "source_url", "final_url")
            elif item in observed_social_profiles:
                url_keys = ("source_url", "url")
            else:
                url_keys = ("source_url", "final_url", "url", "link")
            _apply_scope_provenance(
                item,
                requested_target_host=host,
                requested_registered_domain=registered,
                url_keys=url_keys,
                observed=bool(item.get("observed") or item.get("page_found")),
            )
    if security_txt.get("found"):
        _apply_scope_provenance(
            security_txt,
            requested_target_host=host,
            requested_registered_domain=registered,
            url_keys=("found_url", "final_url", "url"),
            observed=True,
        )
    role_contacts, duplicate_contacts = _dedupe_observed_contacts_with_suppressed(role_contacts)
    if duplicate_contacts:
        suppressed_contacts.extend(duplicate_contacts)
        rejected_contact_candidates.extend(duplicate_contacts)
    observed_social_profiles, duplicate_profiles = _dedupe_social_profiles_with_suppressed(observed_social_profiles)
    if duplicate_profiles:
        rejected_social_candidates.extend(duplicate_profiles)
    observed_public_contacts = [item for item in role_contacts if isinstance(item, dict) and item.get("observed")]
    generated_role_guesses = [item for item in role_contacts if isinstance(item, dict) and item.get("source") == "generated_candidate"]
    observed_email_addresses = [item for item in observed_public_contacts if str(item.get("contact_type") or "") == "email"]
    observed_phone_numbers = [item for item in observed_public_contacts if str(item.get("contact_type") or "") == "phone"]
    observed_contact_forms = [item for item in observed_public_contacts if str(item.get("contact_type") or "") in {"form", "contact_form"}]
    observed_contact_urls = [item for item in observed_public_contacts if str(item.get("contact_type") or "") == "url"]
    all_observed_contacts = [item for item in role_contacts if isinstance(item, dict) and item.get("observed")]
    target_observed_public_contacts = _target_scope_count(all_observed_contacts)
    parent_org_observed_public_contacts = _scope_count(all_observed_contacts, "parent_organization")
    affiliate_observed_public_contacts = _scope_count(all_observed_contacts, "official_affiliate_domain")
    target_observed_phone_numbers = _target_scope_count(all_observed_contacts, contact_type="phone")
    parent_org_observed_phone_numbers = _scope_count(all_observed_contacts, "parent_organization", contact_type="phone")
    target_observed_locations = _target_scope_count(observed_locations)
    parent_org_observed_locations = _scope_count(observed_locations, "parent_organization")
    affiliate_observed_locations = _scope_count(observed_locations, "official_affiliate_domain") + _scope_count(observed_locations, "external_verified_source")
    target_validated_public_documents = _target_scope_count(validated_public_documents)
    parent_org_validated_public_documents = _scope_count(validated_public_documents, "parent_organization")
    affiliate_validated_public_documents = _scope_count(validated_public_documents, "official_affiliate_domain")
    target_observed_social_profiles = _target_scope_count(observed_social_profiles)
    parent_org_observed_social_profiles = _scope_count(observed_social_profiles, "parent_organization")
    affiliate_observed_social_profiles = _scope_count(observed_social_profiles, "official_affiliate_domain")
    contact_intelligence = {
        "observed_email_addresses": observed_email_addresses,
        "observed_phone_numbers": observed_phone_numbers,
        "observed_contact_urls": observed_contact_urls,
        "observed_contact_forms": observed_contact_forms,
        "generated_role_email_guesses": generated_role_guesses,
        "suppressed_contacts": suppressed_contacts,
        "rejected_contact_candidates": rejected_contact_candidates,
        "contact_summary": _contact_summary(
            observed_email_addresses=observed_email_addresses,
            observed_phone_numbers=observed_phone_numbers,
            observed_contact_urls=observed_contact_urls,
            observed_contact_forms=observed_contact_forms,
            generated_role_email_guesses=generated_role_guesses,
            suppressed_contacts=suppressed_contacts,
        ),
        "policy": {
            "passive_only": True,
            "no_account_validation": True,
            "no_smtp_verification": True,
            "risk_score_impact": "none",
        },
    }
    contact_intelligence["contact_summary"].update(
        {
            "target_observed_public_contacts": target_observed_public_contacts,
            "parent_org_observed_public_contacts": parent_org_observed_public_contacts,
            "affiliate_observed_public_contacts": affiliate_observed_public_contacts,
            "target_observed_phone_numbers": target_observed_phone_numbers,
            "parent_org_observed_phone_numbers": parent_org_observed_phone_numbers,
            "rejected_contact_candidates_count": len(rejected_contact_candidates),
        }
    )
    location_intelligence["location_summary"].update(
        {
            "target_observed_locations": target_observed_locations,
            "parent_org_observed_locations": parent_org_observed_locations,
            "affiliate_observed_locations": affiliate_observed_locations,
        }
    )
    public_document_intelligence["document_summary"].update(
        {
            "target_validated_public_documents": target_validated_public_documents,
            "parent_org_validated_public_documents": parent_org_validated_public_documents,
            "affiliate_validated_public_documents": affiliate_validated_public_documents,
        }
    )
    email_intelligence["observed_public_contacts"] = observed_email_addresses
    email_intelligence["generated_role_contact_guesses"] = generated_role_guesses
    email_intelligence["suppressed_contacts"] = suppressed_contacts
    email_intelligence["email_summary"] = {
        "observed_public_contacts_count": len(observed_email_addresses),
        "observed_email_addresses_count": len(observed_email_addresses),
        "generated_role_guesses_count": len(generated_role_guesses),
        "mx_records_count": len(email_intelligence.get("mx_records") if isinstance(email_intelligence.get("mx_records"), list) else []),
        "suppressed_contacts_count": len(suppressed_contacts),
    }
    people_pages = [
        page
        for page in official_pages
        if isinstance(page, dict)
        and page.get("page_found")
        and str(page.get("page_type") or "") in {"about", "people", "press"}
    ]
    people_organization_presence = {
        "official_people_pages": people_pages,
        "observed_official_social_profiles": observed_social_profiles,
        "rejected_social_candidates": rejected_social_candidates,
        "leadership_page_candidates": [
            page for page in official_pages if isinstance(page, dict) and str(page.get("page_type") or "") == "people"
        ],
        "company_profile_lookup_shortcuts": company_profile_lookup_shortcuts,
        "people_lookup_summary": {
            "official_people_pages_count": len(people_pages),
            "observed_official_social_profiles_count": len(observed_social_profiles),
            "target_observed_social_profiles": target_observed_social_profiles,
            "parent_org_observed_social_profiles": parent_org_observed_social_profiles,
            "affiliate_observed_social_profiles": affiliate_observed_social_profiles,
            "rejected_social_candidates_count": len(rejected_social_candidates),
            "manual_lookup_shortcuts_count": len(company_profile_lookup_shortcuts),
            "employee_scraping_performed": False,
            "personal_email_generation_performed": False,
        },
        "status": "observed_public_page" if people_pages or observed_social_profiles else "suggestion_only",
        "risk_score_impact": 0,
        "policy": {
            "no_linkedin_employee_scraping": True,
            "no_employee_list_harvesting": True,
            "no_personal_email_generation": True,
        },
    }
    checked_pages = [page for page in official_pages if page.get("check_status") == "checked"]
    found_pages = [page for page in official_pages if page.get("page_found")]
    manual_only_urls = sum(1 for item in organization_lookup_links + location_lookup_links + public_document_searches if item.get("check_policy") == "manual_only")
    generated_candidate_urls = sum(1 for item in role_contacts if item.get("check_policy") == "generated_candidate")
    summary = {
        "official_pages_checked": len(checked_pages),
        "official_pages_found": len(found_pages),
        "official_pages_not_found": sum(1 for page in official_pages if page.get("url_status") == "checked_not_found"),
        "official_pages_soft_error": sum(1 for page in official_pages if page.get("url_status") == "checked_soft_error"),
        "official_pages_unexpected_content": sum(1 for page in official_pages if page.get("url_status") == "checked_unexpected_content"),
        "official_pages_duplicates": sum(1 for page in official_pages if page.get("url_status") == "checked_duplicate"),
        "official_pages_forbidden": sum(1 for page in official_pages if page.get("url_status") == "checked_forbidden"),
        "security_txt_checked": security_attempts,
        "security_txt_found": 1 if security_txt.get("found") else 0,
        "robots_found": sum(1 for page in official_pages if page.get("page_type") == "robots" and page.get("page_found")),
        "sitemap_found": sum(1 for page in official_pages if page.get("page_type") == "sitemap" and page.get("page_found")),
        "auto_checked_urls": sum(1 for page in official_pages if page.get("check_policy") == "auto_check_allowed" and page.get("check_status") in {"checked", "timeout", "error"}),
        "manual_only_urls": manual_only_urls,
        "api_required_urls": 0,
        "generated_candidate_urls": generated_candidate_urls,
        "role_contact_candidates": sum(1 for item in role_contacts if item.get("source") == "generated_candidate"),
        "generated_contact_guesses": len(generated_role_guesses),
        "observed_public_contacts": sum(1 for item in role_contacts if item.get("observed")),
        "observed_email_addresses": len(observed_email_addresses),
        "observed_phone_numbers": len(observed_phone_numbers),
        "observed_contact_urls": len(observed_contact_urls),
        "observed_contact_forms": len(observed_contact_forms),
        "suppressed_contacts_count": len(suppressed_contacts),
        "rejected_contact_candidates": len(rejected_contact_candidates),
        "mx_records_count": len(email_intelligence.get("mx_records") if isinstance(email_intelligence.get("mx_records"), list) else []),
        "organization_lookup_tasks": len(organization_lookup_links) + len(location_lookup_links),
        "public_document_search_tasks": len(public_document_searches),
        "validated_public_documents": len(validated_public_documents),
        "document_candidates": len(document_candidates),
        "location_hints": len(location_hints),
        "observed_locations": len(observed_locations),
        "official_location_pages": len(official_location_pages),
        "observed_official_social_profiles": len(observed_social_profiles),
        "rejected_social_candidates": len(rejected_social_candidates),
        "target_observed_public_contacts": target_observed_public_contacts,
        "parent_org_observed_public_contacts": parent_org_observed_public_contacts,
        "affiliate_observed_public_contacts": affiliate_observed_public_contacts,
        "target_observed_phone_numbers": target_observed_phone_numbers,
        "parent_org_observed_phone_numbers": parent_org_observed_phone_numbers,
        "target_observed_locations": target_observed_locations,
        "parent_org_observed_locations": parent_org_observed_locations,
        "affiliate_observed_locations": affiliate_observed_locations,
        "target_validated_public_documents": target_validated_public_documents,
        "parent_org_validated_public_documents": parent_org_validated_public_documents,
        "affiliate_validated_public_documents": affiliate_validated_public_documents,
        "target_observed_social_profiles": target_observed_social_profiles,
        "parent_org_observed_social_profiles": parent_org_observed_social_profiles,
        "affiliate_observed_social_profiles": affiliate_observed_social_profiles,
    }
    _record_osint_event(
        events,
        "info",
        "organization_intelligence",
        (
            f"official_pages_checked={summary['official_pages_checked']} "
            f"security_txt_found={summary['security_txt_found']} "
            f"role_contacts={summary['role_contact_candidates']} "
            f"lookup_tasks={summary['organization_lookup_tasks']}"
        ),
    )
    return {
        "target_host": host,
        "target_registered_domain": registered,
        "brand_aliases": organization_aliases,
        "official_pages": official_pages,
        "security_txt": security_txt,
        "role_contacts": role_contacts,
        "email_intelligence": email_intelligence,
        "contact_intelligence": contact_intelligence,
        "location_intelligence": location_intelligence,
        "public_document_intelligence": public_document_intelligence,
        "people_organization_presence": people_organization_presence,
        "suppressed_contacts": suppressed_contacts,
        "organization_lookup_links": organization_lookup_links,
        "location_lookup_links": location_lookup_links,
        "location_hints": location_hints,
        "public_document_searches": public_document_searches,
        "summary": summary,
        "policy": {
            "passive_only": True,
            "no_account_validation": True,
            "no_smtp_verification": True,
            "no_social_scraping": True,
            "no_document_download": True,
            "risk_score_impact": "none",
        },
    }


def _normalize_url_key(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    scheme = parsed.scheme.lower() or "http"
    netloc = parsed.netloc.lower()
    if not netloc and parsed.path:
        reparsed = urlsplit(f"//{parsed.path}")
        netloc = reparsed.netloc.lower()
        path = reparsed.path or "/"
    else:
        path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def _extract_ct_subdomains(records: Any, domain: str) -> list[str]:
    names: set[str] = set()
    if not isinstance(records, list):
        return []
    for item in records:
        if not isinstance(item, dict):
            continue
        for field in ("name_value", "common_name", "dns_names"):
            raw = item.get(field)
            if not raw:
                continue
            values = raw if isinstance(raw, list) else str(raw).splitlines()
            for line in values:
                candidate = _normalize_hostname(line)
                if _in_domain(candidate, domain):
                    names.add(candidate)
    return sorted(names, key=lambda value: (value.count("."), value))


def _ct_query_urls(domain: str, include_subdomains: bool) -> list[tuple[str, str, str]]:
    queries = [("crtsh", "exact query", f"https://crt.sh/?q={quote(domain)}&output=json")]
    if include_subdomains:
        queries.append(("crtsh", "wildcard query", f"https://crt.sh/?q=%25.{quote(domain)}&output=json"))
    certspotter_url = (
        "https://api.certspotter.com/v1/issuances"
        f"?domain={quote(domain)}&include_subdomains={'true' if include_subdomains else 'false'}&expand=dns_names"
    )
    queries.append(("certspotter", "issuances query", certspotter_url))
    return queries


def _ct_name_classification(name: str, domain: str, registered_domain: str | None = None) -> dict[str, Any]:
    normalized = _normalize_hostname(name)
    target = _normalize_hostname(domain)
    registered = _normalize_hostname(registered_domain or "")
    if not normalized or not target:
        return {
            "tier": "out_of_scope",
            "title": "Certificate Transparency observation",
            "confidence": "low",
            "confidence_score": 0,
            "exposure_priority": "info",
            "reason": "out_of_scope",
        }
    if normalized in {target, f"www.{target}"} or (registered and normalized in {registered, f"www.{registered}"}):
        return {
            "tier": "asset_identity",
            "title": "Certificate Transparency asset identity observation",
            "confidence": "low",
            "confidence_score": 25,
            "exposure_priority": "info",
            "reason": "asset_identity_only",
        }

    prefix = normalized[: -len(target)].rstrip(".") if normalized.endswith(target) else normalized
    labels = [label for label in prefix.split(".") if label]
    label_tokens = set(labels)
    for label in labels:
        label_tokens.update(token for token in re.split(r"[-_]", label) if token)
    interesting = bool(label_tokens & _CT_INTERESTING_LABELS)
    if interesting:
        return {
            "tier": "interesting_subdomain_candidate",
            "title": "Certificate Transparency subdomain candidate",
            "confidence": "medium",
            "confidence_score": 50,
            "exposure_priority": "watch",
            "reason": "interesting_subdomain_keyword",
        }
    return {
        "tier": "subdomain_candidate",
        "title": "Certificate Transparency subdomain candidate",
        "confidence": "medium",
        "confidence_score": 45,
        "exposure_priority": "info",
        "reason": "non_trivial_subdomain",
    }


def _base_ct_observation(
    *,
    domain: str,
    subdomain: str,
    classification: dict[str, Any],
    source_url: str,
    source_provider: str,
) -> dict[str, Any]:
    title = str(classification.get("title") or "Certificate Transparency observation")
    category = "certificate_transparency" if classification.get("tier") == "asset_identity" else "asset_discovery_candidate"
    signal = _base_signal(
        category=category,
        title=title,
        status="asset_discovery_candidate" if classification.get("tier") != "asset_identity" else "asset_identity",
        confidence=str(classification.get("confidence") or "low"),
        confidence_score=int(classification.get("confidence_score") or 0),
        source_name="certificate_transparency",
        source_url=source_url,
        source_provider=source_provider,
        provider_reference=source_url,
        matched_entities={"domains": [domain], "subdomains": [subdomain], "emails": [], "urls": [], "keywords": [], "file_names": []},
        snippet=f"{subdomain} observed in CT data via {source_provider}",
        validation_notes=[
            "Passive CT observation only; not proof the host is currently live.",
            "Manual validation required before treating as in-scope asset.",
        ],
        recommended_action=(
            "Treat as normal certificate/public asset identity context; no action unless scope requires asset inventory review."
            if classification.get("tier") == "asset_identity"
            else "Review whether this subdomain is in scope before active testing."
        ),
        exposure_priority=str(classification.get("exposure_priority") or "info"),
        false_positive_notes=[
            "Certificate records may be stale, duplicated, wildcard-generated, or unrelated to current exposure.",
        ],
    )
    signal["ct_classification"] = classification.get("tier")
    return signal


def _run_certificate_transparency(
    *,
    domain: str,
    registered_domain: str | None,
    timeout: int,
    retry_count: int,
    deadline: float,
    max_signals: int,
    include_subdomains: bool,
    include_asset_identity_as_signal: bool,
    signals: list[dict[str, Any]],
    suppressed: list[dict[str, Any]],
    asset_identity_observations: list[dict[str, Any]],
    asset_discovery_candidates: list[dict[str, Any]],
    output_dir: Path | str | None,
    events: list[dict[str, str]] | None,
) -> dict[str, Any]:
    started = time.monotonic()
    query_urls = _ct_query_urls(domain, include_subdomains)
    source_url = query_urls[0][2] if query_urls else ""
    if not domain or _looks_like_ip(domain):
        return _source_record("certificate_transparency", "skipped", 0, "CT lookup skipped because target is not a domain.", source_url, raw_count=0)

    records_by_name: dict[str, dict[str, str]] = {}
    errors: list[str] = []
    no_record_notes: list[str] = []
    provider_results: dict[str, dict[str, Any]] = {}
    provider_terminal_failures: set[str] = set()

    for provider, label, query_url in query_urls:
        result = provider_results.setdefault(
            provider,
            {
                "provider": provider,
                "status": "error",
                "raw_count": 0,
                "signal_count": 0,
                "asset_identity_count": 0,
                "errors": [],
                "notes": "",
                "duration_ms": 0,
                "queries_attempted": 0,
                "successful_queries": 0,
                "failed_queries": 0,
                "error_class": "",
                "user_message": "",
            },
        )
        if provider in provider_terminal_failures:
            result["notes"] = f"{result.get('notes') or ''} provider unavailable; skipped remaining query.".strip()
            continue
        result["queries_attempted"] += 1
        query_started = time.monotonic()
        _emit_osint_event(events, output_dir, "info", "certificate_transparency", f"{provider} starting {label}")
        try:
            fetched = _fetch_json_with_retries(
                query_url,
                timeout=timeout,
                deadline=deadline,
                output_dir=output_dir,
                log_prefix="certificate transparency",
                events=events,
                event_source="certificate_transparency",
                retries=retry_count,
            )
            if isinstance(fetched, list):
                result["raw_count"] += len(fetched)
                for name in _extract_ct_subdomains(fetched, domain):
                    records_by_name.setdefault(name, {"provider": provider, "source_url": query_url})
            result["successful_queries"] += 1
        except HTTPError as exc:
            if exc.code == 404:
                result["successful_queries"] += 1
                note = f"{label} returned HTTP 404; classified as no records."
                no_record_notes.append(note)
                result["notes"] = f"{result.get('notes') or ''} {note}".strip()
                _emit_osint_event(events, output_dir, "warn", "certificate_transparency", f"{provider} {note}")
                _close_http_error(exc)
                continue
            result["failed_queries"] += 1
            error = _error_note(f"{label} failed", exc)
            errors.append(error)
            result["errors"].append(error)
            result["error_class"] = _error_class(exc)
            if exc.code in {502, 503, 504}:
                provider_terminal_failures.add(provider)
                result["user_message"] = "crt.sh unavailable during this run; CT coverage is partial." if provider == "crtsh" else f"{provider} unavailable during this run."
                _emit_osint_event(events, output_dir, "warn", "certificate_transparency", f"{provider} unavailable: HTTP {exc.code} after retries")
            else:
                _emit_osint_event(events, output_dir, "error", "certificate_transparency", f"{provider} error {_error_label(exc)}")
            _close_http_error(exc)
        except (URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            result["failed_queries"] += 1
            error = _error_note(f"{label} failed", exc)
            errors.append(error)
            result["errors"].append(error)
            result["error_class"] = _error_class(exc)
            if isinstance(exc, TimeoutError):
                provider_terminal_failures.add(provider)
                result["user_message"] = "crt.sh unavailable during this run; CT coverage is partial." if provider == "crtsh" else f"{provider} timed out during this run."
                _emit_osint_event(events, output_dir, "warn", "certificate_transparency", f"{provider} timed out after retries")
            else:
                _emit_osint_event(events, output_dir, "error", "certificate_transparency", f"{provider} error {_error_label(exc)}")
        finally:
            result["duration_ms"] += int((time.monotonic() - query_started) * 1000)

    for result in provider_results.values():
        successful = int(result.get("successful_queries") or 0)
        failed = int(result.get("failed_queries") or 0)
        if successful and failed:
            result["status"] = "partial"
        elif successful:
            result["status"] = "completed"
        elif failed:
            error_class = str(result.get("error_class") or "")
            if error_class == "timeout":
                result["status"] = "timeout"
            elif error_class in {"http_502", "http_503", "http_504", "url_error"}:
                result["status"] = "unavailable"
            else:
                result["status"] = "error"

    completed_providers = [
        item for item in provider_results.values() if str(item.get("status")) in {"completed", "partial"}
    ]
    if not completed_providers:
        notes = "Passive CT provider queries failed completely."
        if errors:
            notes = f"{notes} Errors: {'; '.join(errors)}"
        provider_statuses = {str(item.get("status") or "") for item in provider_results.values()}
        source_status = "timeout" if provider_statuses == {"timeout"} else "unavailable" if provider_statuses <= {"unavailable", "timeout"} else "error"
        _emit_osint_event(events, output_dir, "error", "certificate_transparency", f"0 observed signals, status={source_status}")
        return _source_record(
            "certificate_transparency",
            source_status,
            0,
            notes,
            source_url,
            raw_count=0,
            suppressed_count=0,
            errors=errors,
            duration_ms=int((time.monotonic() - started) * 1000),
            provider_results=list(provider_results.values()),
        )

    subdomains = sorted(records_by_name, key=lambda value: (value.count("."), value))
    before_signals = len(signals)
    before_suppressed = len(suppressed)
    before_asset_identity = len(asset_identity_observations)
    before_asset_discovery = len(asset_discovery_candidates)
    provider_signal_counts: dict[str, int] = {}
    provider_asset_counts: dict[str, int] = {}
    provider_discovery_counts: dict[str, int] = {}
    for subdomain in subdomains:
        provider_context = records_by_name.get(subdomain, {})
        source_provider = provider_context.get("provider", "unknown")
        signal_source_url = provider_context.get("source_url") or source_url
        classification = _ct_name_classification(subdomain, domain, registered_domain)
        observation = _base_ct_observation(
            domain=domain,
            subdomain=subdomain,
            classification=classification,
            source_url=signal_source_url,
            source_provider=source_provider,
        )
        if classification.get("tier") == "asset_identity" and not include_asset_identity_as_signal:
            observation["asset_identity_reason"] = classification.get("reason", "asset_identity_only")
            asset_identity_observations.append(observation)
            provider_asset_counts[source_provider] = provider_asset_counts.get(source_provider, 0) + 1
            continue
        observation["asset_discovery_reason"] = classification.get("reason", "subdomain_candidate")
        asset_discovery_candidates.append(observation)
        provider_discovery_counts[source_provider] = provider_discovery_counts.get(source_provider, 0) + 1

    status = "partial" if any(str(item.get("status")) != "completed" for item in provider_results.values()) else "completed"
    raw_count = sum(int(item.get("raw_count") or 0) for item in provider_results.values())
    if not raw_count:
        notes = "No CT records returned."
    elif not subdomains:
        notes = "CT records returned, but no in-scope hostnames were parsed."
    else:
        notes = "Passive CT query completed; candidates were not probed."
    if no_record_notes:
        notes = f"{notes} {' '.join(no_record_notes)}"
    if errors:
        notes = f"{notes} Some CT provider queries failed."
    if any(str(item.get("user_message") or "") for item in provider_results.values()):
        notes = f"{notes} " + " ".join(str(item.get("user_message") or "") for item in provider_results.values() if str(item.get("user_message") or "").strip())
    observed_delta = len(signals) - before_signals
    asset_delta = len(asset_identity_observations) - before_asset_identity
    discovery_delta = len(asset_discovery_candidates) - before_asset_discovery
    _emit_osint_event(
        events,
        output_dir,
        "info",
        "certificate_transparency",
        f"{observed_delta} observed signals, {asset_delta} asset identity observations, {discovery_delta} asset discovery candidates, status={status}",
    )
    for provider_result in provider_results.values():
        provider_name = str(provider_result.get("provider") or "")
        provider_result["signal_count"] = provider_signal_counts.get(provider_name, 0)
        provider_result["asset_identity_count"] = provider_asset_counts.get(provider_name, 0)
        provider_result["asset_discovery_count"] = provider_discovery_counts.get(provider_name, 0)
    source = _source_record(
        "certificate_transparency",
        status,
        observed_delta,
        notes,
        source_url,
        raw_count=raw_count,
        suppressed_count=len(suppressed) - before_suppressed,
        errors=errors,
        duration_ms=int((time.monotonic() - started) * 1000),
        provider_results=list(provider_results.values()),
        asset_identity_count=asset_delta,
    )
    source["asset_discovery_count"] = discovery_delta
    return source


def _extract_wayback_urls(records: Any) -> list[dict[str, str]]:
    if not isinstance(records, list):
        return []
    rows = records
    headers: list[str] = []
    if rows and isinstance(rows[0], list) and all(isinstance(item, str) for item in rows[0]):
        headers = [str(item) for item in rows[0]]
        rows = rows[1:]
    if not headers:
        headers = ["original", "timestamp", "statuscode", "mimetype"]

    extracted: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        entry: dict[str, str] = {}
        if isinstance(row, list):
            for index, header in enumerate(headers):
                entry[header] = str(row[index]) if index < len(row) else ""
        elif isinstance(row, dict):
            entry = {str(key): str(value) for key, value in row.items()}
        url = str(entry.get("original") or entry.get("url") or "").strip()
        key = _normalize_url_key(url)
        if not url or key in seen:
            continue
        seen.add(key)
        extracted.append(entry)
    return extracted


def _wayback_limit_for_profile(scan_profile: str) -> int:
    normalized = str(scan_profile or "balanced").strip().lower()
    if normalized == "slow":
        return 500
    if normalized == "balanced":
        return 200
    return 50


def _ct_wayback_timeout_for_profile(scan_profile: str, configured_timeout: int) -> int:
    normalized = str(scan_profile or "balanced").strip().lower()
    if normalized in {"slow", "deep"}:
        cap = 30
    elif normalized == "fast":
        cap = 5
    else:
        cap = 12
    configured = int(configured_timeout or cap)
    return max(1, min(configured, cap))


def _classify_wayback_url(url: str) -> dict[str, Any]:
    low = str(url or "").lower()
    path = urlsplit(str(url or "")).path.lower()
    static_asset = bool(re.search(r"\.(?:css|js|png|jpe?g|gif|svg|woff2?|ttf|ico|map)(?:$|\?)", path))
    checks = [
        ("admin", ("admin", "dashboard", "manage", "wp-admin", "phpmyadmin"), "review", "medium"),
        ("login", ("login", "signin", "sign-in", "oauth", "sso"), "watch", "medium"),
        ("auth", ("auth", "reset", "logout", "register"), "watch", "medium"),
        ("api", ("/api", "graphql", "rest/", "openapi", "swagger"), "watch", "medium"),
        ("backup", ("backup", ".bak", ".old", ".zip", ".tar", ".gz", ".sql", "archive", "dump"), "review", "medium"),
        ("config", ("config", ".env", "settings", "secret", "token"), "review", "medium"),
        ("debug", ("debug", "trace", "phpinfo", "server-status", "stacktrace"), "review", "medium"),
        ("staging/dev/test", ("staging", "dev", "test", "uat", "qa", "internal", "old"), "watch", "low"),
        ("docs/swagger", ("docs", "documentation", "swagger", "redoc", "openapi"), "watch", "low"),
        ("upload", ("upload", "uploads", "file", "multipart"), "review", "medium"),
    ]
    keywords: list[str] = []
    priority = "info"
    confidence = "low"
    for label, tokens, token_priority, token_confidence in checks:
        matched = [token for token in tokens if token in low]
        if matched:
            keywords.append(label)
            priority = token_priority
            if _CONFIDENCE_RANK[token_confidence] > _CONFIDENCE_RANK[confidence]:
                confidence = token_confidence
    return {
        "interesting": bool(keywords) and not (static_asset and not {"backup", "config", "debug"} & set(keywords)),
        "keywords": keywords,
        "priority": priority,
        "confidence": confidence,
        "confidence_score": 50 if confidence == "medium" else 30,
        "static_asset": static_asset,
    }


def _run_wayback(
    *,
    domain: str,
    timeout: int,
    retry_count: int,
    deadline: float,
    max_signals: int,
    scan_profile: str,
    signals: list[dict[str, Any]],
    suppressed: list[dict[str, Any]],
    historical_url_context: list[dict[str, Any]],
    output_dir: Path | str | None,
    events: list[dict[str, str]] | None,
) -> dict[str, Any]:
    started = time.monotonic()
    limit = _wayback_limit_for_profile(scan_profile)
    wildcard_url = (
        "https://web.archive.org/cdx"
        f"?url=*.{quote(domain)}/*&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit={limit}"
    )
    exact_url = (
        "https://web.archive.org/cdx"
        f"?url={quote(domain)}/*&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit={limit}"
    )
    https_url = (
        "https://web.archive.org/cdx"
        f"?url={quote(f'https://{domain}/*', safe='')}&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit={limit}"
    )
    http_url = (
        "https://web.archive.org/cdx"
        f"?url={quote(f'http://{domain}/*', safe='')}&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit={limit}"
    )
    source_url = exact_url
    if not domain or _looks_like_ip(domain):
        return _source_record("historical_urls", "skipped", 0, "Wayback lookup skipped because target is not a domain.", source_url, raw_count=0)

    entries: list[dict[str, str]] = []
    errors: list[str] = []
    error_classes: list[str] = []
    completed_queries = 0
    queries = [
        ("exact-host query", exact_url),
        ("wildcard CDX query", wildcard_url),
        ("https scheme query", https_url),
        ("http scheme query", http_url),
    ]
    if str(scan_profile or "").strip().lower() == "fast":
        queries = queries[:2]
    wayback_retries = max(0, retry_count)
    for index, (label, query_url) in enumerate(queries):
        if label == "exact-host query":
            _emit_osint_event(events, output_dir, "info", "historical_urls", f"starting exact-host CDX query limit={limit}")
        elif label == "wildcard CDX query":
            _emit_osint_event(events, output_dir, "info", "historical_urls", "fallback wildcard CDX query")
        else:
            _emit_osint_event(events, output_dir, "info", "historical_urls", f"fallback {label}")
        try:
            records = _fetch_json_with_retries(
                query_url,
                timeout=timeout,
                deadline=deadline,
                output_dir=output_dir,
                log_prefix="wayback",
                events=events,
                event_source="historical_urls",
                retries=wayback_retries,
            )
            entries.extend(_extract_wayback_urls(records))
            completed_queries += 1
            if entries:
                break
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            errors.append(_error_note(f"{label} failed", exc))
            error_classes.append(_error_class(exc))
            if isinstance(exc, TimeoutError):
                _emit_osint_event(events, output_dir, "warn", "historical_urls", "Wayback CDX timed out; absence of historical URLs is not conclusive.")
                break
            _emit_osint_event(events, output_dir, "error", "historical_urls", f"error {_error_label(exc)}")

    if completed_queries == 0:
        _emit_osint_event(events, output_dir, "error", "historical_urls", "0 interesting historical URL candidates")
        notes = "Passive Wayback query failed completely."
        status = "timeout" if "timeout" in error_classes else "error"
        user_message = ""
        if "timeout" in error_classes:
            user_message = "Wayback CDX timed out; absence of historical URLs is not conclusive."
            notes = f"{notes} {user_message}"
        elif any(error_class in {"url_error", "http_502", "http_503", "http_504"} for error_class in error_classes):
            user_message = "Wayback CDX source unavailable/slow from this environment. This does not prove absence of historical URLs."
            notes = f"{notes} {user_message}"
        if errors:
            notes = f"{notes} Errors: {'; '.join(errors)}"
        source = _source_record(
            "historical_urls",
            status,
            0,
            notes,
            source_url,
            raw_count=0,
            suppressed_count=0,
            errors=errors,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        source["error_class"] = "timeout" if "timeout" in error_classes else (error_classes[0] if error_classes else "")
        source["user_message"] = user_message
        return source

    unique_entries = _extract_wayback_urls([entry for entry in entries])
    before_suppressed = len(suppressed)
    interesting_count = 0
    boring_count = 0
    for entry in unique_entries:
        original = str(entry.get("original") or "")
        classification = _classify_wayback_url(original)
        if not classification.get("interesting"):
            boring_count += 1
            continue
        interesting_count += 1
        historical_url_context.append(
            {
                "category": "historical_url",
                "url": original,
                "status": "historical_context",
                "url_status": "archived_not_live_checked",
                "observed_signal": False,
                "risk_score_impact": 0,
                "verdict_contribution": "historical_context_only",
                "source_name": "historical_urls",
                "source_url": source_url,
                "keywords": list(classification["keywords"]),
                "confidence": str(classification["confidence"]),
                "confidence_score": int(classification["confidence_score"]),
                "priority": str(classification["priority"]),
                "note": "Archived URL candidate, not current exposure.",
                "validation_method": "not_fetched_live",
                "check_policy": "archive_metadata_only",
            }
        )
    _emit_osint_event(events, output_dir, "info", "historical_urls", f"{interesting_count} interesting historical URL candidates")
    if not unique_entries:
        notes = "No records returned."
    elif not interesting_count:
        notes = f"Observed {len(unique_entries)} historical URL metadata rows; no review paths classified."
    else:
        notes = f"Observed {len(unique_entries)} historical URL metadata rows; {interesting_count} review candidates classified."
    status = "partial" if errors else "completed"
    source = _source_record(
        "historical_urls",
        status,
        0,
        notes,
        source_url,
        raw_count=len(unique_entries),
        suppressed_count=(len(suppressed) - before_suppressed) + boring_count,
        errors=errors,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    source["historical_url_candidates"] = interesting_count
    source["live_validated_historical_urls"] = 0
    return source


def _search_dork_queries(domain: str, email_domain: str | None = None) -> list[tuple[str, str, str, str, str]]:
    email_scope = _normalize_hostname(email_domain or "") or domain
    return [
        (f"site:{domain} inurl:swagger", "high_signal", "api_docs", "Find target-scoped Swagger paths.", "exact_host"),
        (f"site:{domain} inurl:api-docs", "high_signal", "api_docs", "Find target-scoped API documentation paths.", "exact_host"),
        (f"site:{domain} intitle:\"Swagger UI\"", "high_signal", "api_docs", "Find target-scoped Swagger UI pages.", "exact_host"),
        (f"site:{domain} filetype:json openapi", "high_signal", "api_docs", "Find target-scoped OpenAPI JSON documents.", "exact_host"),
        (f"site:{domain} filetype:yaml openapi", "high_signal", "api_docs", "Find target-scoped OpenAPI YAML documents.", "exact_host"),
        (f"site:{domain} filetype:yml openapi", "high_signal", "api_docs", "Find target-scoped OpenAPI YML documents.", "exact_host"),
        (f"site:{domain} inurl:backup", "high_signal", "config_terms", "Find target-scoped backup path references.", "exact_host"),
        (f"site:{domain} inurl:config", "high_signal", "config_terms", "Find target-scoped config path references.", "exact_host"),
        (f"site:{domain} inurl:.env", "high_signal", "config_terms", "Find target-scoped .env path references.", "exact_host"),
        (f"site:{domain} inurl:admin", "high_signal", "general", "Find target-scoped admin path references.", "exact_host"),
        (f"site:{domain} inurl:login", "high_signal", "general", "Find target-scoped login path references.", "exact_host"),
        (f"site:{domain} filetype:pdf", "medium_signal", "documents", "Find target-scoped public PDF documents.", "exact_host"),
        (f"site:{domain} (filetype:doc OR filetype:docx)", "medium_signal", "documents", "Find target-scoped public Word documents.", "exact_host"),
        (f"site:{domain} (filetype:xls OR filetype:xlsx)", "medium_signal", "documents", "Find target-scoped public spreadsheet documents.", "exact_host"),
        (f"site:{domain} \"internal\"", "medium_signal", "general", "Find target-scoped internal wording.", "exact_host"),
        (f"site:{domain} \"confidential\"", "medium_signal", "general", "Find target-scoped confidential wording.", "exact_host"),
        (f"site:{domain} \"staging\"", "medium_signal", "general", "Find target-scoped staging references.", "exact_host"),
        (f"site:{domain} \"dev\"", "medium_signal", "general", "Find target-scoped development references.", "exact_host"),
        (f"\"@{email_scope}\"", "noisy", "emails", "Find public email-format references.", "registered_domain" if email_scope != domain else "exact_host"),
    ]


def _downgrade_generic_task_quality(quality: str, generic_or_reserved_domain: bool) -> str:
    if not generic_or_reserved_domain:
        return quality
    if quality == "high_signal":
        return "medium_signal"
    if quality == "medium_signal":
        return "noisy"
    return quality


def _add_dork_suggestions(
    *,
    domain: str,
    email_domain: str | None = None,
    generic_or_reserved_domain: bool,
    operator_search_tasks: list[dict[str, Any]],
    output_dir: Path | str | None,
    events: list[dict[str, str]] | None,
) -> dict[str, Any]:
    queries = _search_dork_queries(domain, email_domain=email_domain)
    generic_note = (
        " Generic/example domains commonly produce documentation noise."
        if generic_or_reserved_domain
        else ""
    )
    for query, quality, category, purpose, query_scope in queries:
        operator_search_tasks.append(
            _base_operator_search_task(
                source_name="safe_search_dorks",
                query=query,
                link=f"https://www.google.com/search?q={quote_plus(query)}",
                purpose=purpose,
                safety_note=f"Suggestion only. ReconBot does not scrape Google results; do not collect credentials or validate secrets.{generic_note}",
                quality=_downgrade_generic_task_quality(quality, generic_or_reserved_domain),
                category=category,
                query_scope=query_scope,
            )
        )
    _emit_osint_event(events, output_dir, "info", "safe_search_dorks", f"generated {len(queries)}")
    notes = "Generated safe operator-run search suggestions only."
    if generic_or_reserved_domain:
        notes = f"{notes} Generic/example domains commonly produce documentation noise."
    return _source_record("safe_search_dorks", "suggestions_generated", 0, notes)


def _add_public_code_reference_suggestions(
    *,
    domain: str,
    generic_or_reserved_domain: bool = False,
    operator_search_tasks: list[dict[str, Any]],
    output_dir: Path | str | None,
    events: list[dict[str, str]] | None,
) -> dict[str, Any]:
    _emit_osint_event(events, output_dir, "info", "public_code_search", "live search skipped, generated manual search tasks")
    tasks = [
        (f'"{domain}" path:.env', f"https://github.com/search?q=%22{quote_plus(domain)}%22+path%3A.env&type=code", "high_signal", "code_search"),
        (f'"{domain}" filename:.env', f"https://github.com/search?q=%22{quote_plus(domain)}%22+filename%3A.env&type=code", "high_signal", "code_search"),
        (f'"{domain}" filename:config', f"https://github.com/search?q=%22{quote_plus(domain)}%22+filename%3Aconfig&type=code", "medium_signal", "code_search"),
        (f'"{domain}" "api_key"', f"https://github.com/search?q=%22{quote_plus(domain)}%22+%22api_key%22&type=code", "noisy", "code_search"),
        (f'"{domain}" "password"', f"https://github.com/search?q=%22{quote_plus(domain)}%22+%22password%22&type=code", "noisy", "code_search"),
    ]
    generic_note = (
        " Generic/example domains commonly produce documentation noise."
        if generic_or_reserved_domain
        else ""
    )
    for query, url, quality, category in tasks:
        task = _base_operator_search_task(
            source_name="public_code_search",
            query=query,
            link=url,
            purpose="Manual search task for public code references.",
            safety_note=f"Suggestion only. Live GitHub code search was not executed; do not download or validate secret-looking material.{generic_note}",
            quality=_downgrade_generic_task_quality(quality, generic_or_reserved_domain),
            category=category,
            query_scope="exact_host",
        )
        task["check_policy"] = "manual_only"
        task["url_status"] = "auth_required" if not os.environ.get("GITHUB_TOKEN") else "manual_only"
        operator_search_tasks.append(task)
    return _source_record("public_code_search", "suggestions_generated", 0, "Live GitHub code search was not executed; manual search URLs generated.")


def _github_max_results(scan_profile: str) -> int:
    normalized = str(scan_profile or "balanced").strip().lower()
    if normalized == "slow":
        return 20
    if normalized == "balanced":
        return 10
    return 5


def _github_signal_priority(path: str) -> tuple[str, str, int]:
    low = str(path or "").lower()
    strong = (
        ".env",
        "secrets",
        "credentials",
        "kubeconfig",
        "tfvars",
        "application.yml",
        "application.properties",
        "values.yaml",
    )
    medium = (
        "config",
        "settings",
        "docker-compose",
        "terraform",
        "helm",
        "nginx",
        "apache",
        "swagger",
        "openapi",
    )
    if any(token in low for token in strong):
        return "review", "medium", 50
    if any(token in low for token in medium):
        return "watch", "low", 30
    return "watch", "low", 25


def _run_github_code_search(
    *,
    domain: str,
    timeout: int,
    api_key_env: str,
    deadline: float,
    max_signals: int,
    scan_profile: str,
    generic_or_reserved_domain: bool,
    signals: list[dict[str, Any]],
    suppressed: list[dict[str, Any]],
    operator_search_tasks: list[dict[str, Any]],
    output_dir: Path | str | None,
    events: list[dict[str, str]] | None,
) -> dict[str, Any]:
    started = time.monotonic()
    max_results = _github_max_results(scan_profile)
    if not domain or _looks_like_ip(domain):
        return _source_record("public_code_search", "skipped", 0, "GitHub search skipped because target is not a domain.", raw_count=0)
    configured_env = str(api_key_env or "GITHUB_TOKEN").strip() or "GITHUB_TOKEN"
    token_configured = bool(os.environ.get(configured_env))
    if not token_configured:
        _emit_osint_event(events, output_dir, "warn", "public_code_search", f"API auth_required; {configured_env} not configured; generated manual search tasks")
        _add_public_code_reference_suggestions(
            domain=domain,
            generic_or_reserved_domain=generic_or_reserved_domain,
            operator_search_tasks=operator_search_tasks,
            output_dir=output_dir,
            events=events,
        )
        source = _source_record(
            "public_code_search",
            "auth_required_fallback",
            0,
            "GitHub live code search requires authentication; manual search suggestions generated.",
            "https://api.github.com/search/code",
            raw_count=0,
            suppressed_count=0,
            errors=[f"GitHub API auth_required: missing {configured_env}"],
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        source["error_class"] = "auth_required"
        source["user_message"] = "GitHub live code search requires authentication; manual search suggestions generated."
        source["requires_api_key"] = True
        source["api_key_env"] = configured_env
        source["api_key_configured"] = False
        return source
    queries = [f'"{domain}"', f'"{domain}" config', f'"{domain}" api']
    per_query = max(1, max_results // len(queries))
    all_items: list[dict[str, Any]] = []
    errors: list[str] = []
    completed_queries = 0
    for query in queries:
        url = f"https://api.github.com/search/code?q={quote_plus(query)}&per_page={per_query}"
        _emit_osint_event(events, output_dir, "info", "public_code_search", f"API query started: {query}")
        try:
            payload = _fetch_json_with_retries(
                url,
                timeout=timeout,
                deadline=deadline,
                output_dir=output_dir,
                log_prefix="github",
                events=events,
                event_source="public_code_search",
                retries=1,
                api_key_env=configured_env,
            )
            completed_queries += 1
            if isinstance(payload, dict):
                items = payload.get("items")
                if isinstance(items, list):
                    all_items.extend(item for item in items if isinstance(item, dict))
        except HTTPError as exc:
            if exc.code == 401:
                error = "GitHub API auth_required: HTTPError 401"
                errors.append(error)
                _emit_osint_event(events, output_dir, "warn", "public_code_search", "API auth_required; generated manual search tasks")
                _close_http_error(exc)
                _add_public_code_reference_suggestions(
                    domain=domain,
                    generic_or_reserved_domain=generic_or_reserved_domain,
                    operator_search_tasks=operator_search_tasks,
                    output_dir=output_dir,
                    events=events,
                )
                source = _source_record(
                    "public_code_search",
                    "auth_required_fallback",
                    0,
                    "GitHub live code search requires authentication; manual search suggestions generated.",
                    "https://api.github.com/search/code",
                    raw_count=0,
                    suppressed_count=0,
                    errors=errors,
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
                source["error_class"] = "auth_required"
                source["user_message"] = "GitHub live code search requires authentication; manual search suggestions generated."
                source["requires_api_key"] = True
                source["api_key_env"] = configured_env
                source["api_key_configured"] = token_configured
                return source
            if exc.code == 403:
                error = "GitHub API rate_limited: HTTPError 403"
                errors.append(error)
                _emit_osint_event(events, output_dir, "warn", "public_code_search", "API rate_limited; generated manual search tasks")
                _close_http_error(exc)
                _add_public_code_reference_suggestions(
                    domain=domain,
                    generic_or_reserved_domain=generic_or_reserved_domain,
                    operator_search_tasks=operator_search_tasks,
                    output_dir=output_dir,
                    events=events,
                )
                source = _source_record(
                    "public_code_search",
                    "rate_limited_fallback",
                    0,
                    "GitHub live code search was rate-limited; manual search tasks generated.",
                    "https://api.github.com/search/code",
                    raw_count=0,
                    suppressed_count=0,
                    errors=errors,
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
                source["error_class"] = "rate_limited"
                source["user_message"] = "GitHub live code search was rate-limited; manual search tasks generated."
                source["requires_api_key"] = True
                source["api_key_env"] = configured_env
                source["api_key_configured"] = token_configured
                return source
            error = _error_note("GitHub API query failed", exc)
            errors.append(error)
            _emit_osint_event(events, output_dir, "error", "public_code_search", f"API error {_error_label(exc)}")
            _close_http_error(exc)
        except (URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            error = _error_note("GitHub API query failed", exc)
            errors.append(error)
            _emit_osint_event(events, output_dir, "error", "public_code_search", f"API error {_error_label(exc)}")

    seen: set[str] = set()
    unique_items: list[dict[str, Any]] = []
    for item in all_items:
        html_url = str(item.get("html_url") or "")
        path = str(item.get("path") or "")
        repo = item.get("repository") if isinstance(item.get("repository"), dict) else {}
        key = html_url or f"{repo.get('full_name')}:{path}"
        if not key or key in seen:
            continue
        seen.add(key)
        unique_items.append(item)
        if len(unique_items) >= max_results:
            break

    before_signals = len(signals)
    before_suppressed = len(suppressed)
    for item in unique_items:
        path = str(item.get("path") or "")
        repo = item.get("repository") if isinstance(item.get("repository"), dict) else {}
        repo_name = str(repo.get("full_name") or "")
        repo_url = str(repo.get("html_url") or repo.get("url") or "")
        html_url = str(item.get("html_url") or "")
        priority, confidence, confidence_score = _github_signal_priority(path)
        _append_signal(
            signals,
            suppressed,
            _base_signal(
                category="public_code_reference",
                title="Public code reference observed",
                status="needs_manual_review",
                confidence=confidence,
                confidence_score=confidence_score,
                source_name="public_code_search",
                source_url=html_url or "https://api.github.com/search/code",
                matched_entities={
                    "domains": [domain],
                    "subdomains": [],
                    "emails": [],
                    "urls": [html_url] if html_url else [],
                    "keywords": [token for token in ("config", "api", "openapi", "swagger", ".env") if token in path.lower()],
                    "file_names": [path] if path else [],
                },
                snippet=f"Metadata-only GitHub result: repo={repo_name}; path={path}; repository_url={repo_url}; score={item.get('score', '')}",
                validation_notes=[
                    "Metadata-only public code reference; file contents were not downloaded.",
                    "Manual validation required before treating this as exposure.",
                ],
                recommended_action="Review the public code reference metadata and scope before any follow-up.",
                exposure_priority=priority,
                false_positive_notes=[
                    "Search API metadata may be stale, mirrored, unrelated, or outside authorized scope.",
                ],
            ),
            max_signals,
        )

    if completed_queries == 0:
        fallback = _add_public_code_reference_suggestions(
            domain=domain,
            generic_or_reserved_domain=generic_or_reserved_domain,
            operator_search_tasks=operator_search_tasks,
            output_dir=output_dir,
            events=events,
        )
        notes = "Live GitHub code search failed; manual search URLs generated."
        if errors:
            notes = f"{notes} Errors: {'; '.join(errors)}"
        source = _source_record(
            "public_code_search",
            "error",
            0,
            notes,
            "https://api.github.com/search/code",
            raw_count=0,
            suppressed_count=0,
            errors=errors,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        source["requires_api_key"] = True
        source["api_key_env"] = configured_env
        source["api_key_configured"] = token_configured
        return source

    status = "partial" if errors else "completed"
    notes = "No exact public code results found." if not unique_items else "Metadata-only public code references observed; file contents were not downloaded."
    if errors:
        notes = f"{notes} Some GitHub API queries failed; manual search fallback may be useful."
    _emit_osint_event(events, output_dir, "info", "public_code_search", f"{len(unique_items)} metadata results, status={status}")
    source = _source_record(
        "public_code_search",
        status,
        len(signals) - before_signals,
        notes,
        "https://api.github.com/search/code",
        raw_count=len(unique_items),
        suppressed_count=len(suppressed) - before_suppressed,
        errors=errors,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    source["requires_api_key"] = True
    source["api_key_env"] = configured_env
    source["api_key_configured"] = token_configured
    return source


def _strip_html(value: str) -> str:
    text = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", str(value or ""))
    text = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _normalize_alias_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _brand_tokens(value: str) -> list[str]:
    text = re.sub(r"(?i)\b(data\s+breach|breach)\b", " ", str(value or ""))
    return [token for token in re.split(r"[^a-z0-9]+", text.lower()) if token]


def _brand_text_variants(value: str) -> set[str]:
    tokens = _brand_tokens(value)
    variants = {"".join(tokens)} if tokens else set()
    raw = _normalize_alias_text(value)
    if raw:
        variants.add(raw)
    return {variant for variant in variants if variant}


def _hibp_slug_candidates(aliases: list[str]) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(alias: str, slug: str) -> None:
        cleaned_slug = re.sub(r"[^A-Za-z0-9 -]", "", str(slug or "")).strip()
        if not cleaned_slug:
            return
        key = cleaned_slug.lower()
        if key in seen:
            return
        seen.add(key)
        candidates.append((alias, cleaned_slug))

    ordered_aliases = [
        alias for _, alias in sorted(enumerate(aliases), key=lambda item: ("." in str(item[1] or ""), item[0]))
    ]
    for alias in ordered_aliases:
        text = str(alias or "").strip()
        if not text:
            continue
        if "." in text:
            label = text.split(".", 1)[0]
            if label == "www":
                parts = text.split(".")
                label = parts[1] if len(parts) > 1 else ""
            label_tokens = [token for token in re.split(r"[-_]+", label) if token]
            if label_tokens:
                add(alias, "-".join(_display_token(token) for token in label_tokens))
            continue
        add(alias, text)
        if " " in text:
            add(alias, text.replace(" ", ""))
            add(alias, text.replace(" ", "-"))

    return candidates[:8]


def _hibp_match_decision(
    alias: str,
    breach_name: str,
    breach_domain: str,
    target_domain: str,
    *,
    target_registered_domain: str | None = None,
    parent_domain_expansion: bool = False,
) -> dict[str, Any]:
    alias_text = str(alias or "").strip()
    alias_domain = _normalize_hostname(alias_text) if "." in alias_text else ""
    domain_norm = _normalize_hostname(breach_domain)
    target_host = _normalize_hostname(target_domain)
    target_registered = _normalize_hostname(target_registered_domain or "") or _registered_domain(target_host) or ""
    debug = {
        "breach_name": str(breach_name or ""),
        "breach_domain": domain_norm,
        "candidate_alias": alias_text,
        "match_type": "",
        "accepted": False,
        "reject_reason": "",
    }

    if alias_domain:
        if not domain_norm:
            debug["reject_reason"] = "missing_breach_domain"
            return debug
        exact_domains = {value for value in (target_registered, target_host) if value}
        if domain_norm in exact_domains:
            debug.update({"match_type": "exact_domain", "accepted": True})
            return debug
        if parent_domain_expansion and target_host and target_host.endswith(f".{domain_norm}"):
            debug.update({"match_type": "exact_domain", "accepted": True})
            return debug
        debug["match_type"] = "exact_domain"
        debug["reject_reason"] = "domain_mismatch"
        return debug

    alias_variants = _brand_text_variants(alias_text)
    breach_variants = _brand_text_variants(breach_name)
    if alias_variants and breach_variants and alias_variants & breach_variants:
        debug.update({"match_type": "brand_alias", "accepted": True})
        return debug
    if alias_variants and breach_variants and set(_brand_tokens(alias_text)) == set(_brand_tokens(breach_name)):
        debug.update({"match_type": "fuzzy_brand_alias", "accepted": True})
        return debug
    debug["match_type"] = "brand_alias"
    debug["reject_reason"] = "brand_alias_mismatch"
    return debug


def _hibp_match_type(
    alias: str,
    breach_name: str,
    breach_domain: str,
    target_domain: str,
    *,
    target_registered_domain: str | None = None,
    parent_domain_expansion: bool = False,
) -> str | None:
    decision = _hibp_match_decision(
        alias,
        breach_name,
        breach_domain,
        target_domain,
        target_registered_domain=target_registered_domain,
        parent_domain_expansion=parent_domain_expansion,
    )
    return str(decision.get("match_type") or "") if decision.get("accepted") else None


def _hibp_confidence(
    alias: str,
    breach_name: str,
    breach_domain: str,
    target_domain: str,
    *,
    target_registered_domain: str | None = None,
    parent_domain_expansion: bool = False,
) -> tuple[str, int, str]:
    match_type = _hibp_match_type(
        alias,
        breach_name,
        breach_domain,
        target_domain,
        target_registered_domain=target_registered_domain,
        parent_domain_expansion=parent_domain_expansion,
    )
    if match_type == "brand_alias":
        return "high", 75, "Breach catalog name matches a generated organization alias."
    if match_type == "exact_domain":
        return "high", 70, "Breach catalog domain exactly matches the target domain context."
    if match_type == "fuzzy_brand_alias":
        return "medium", 55, "Breach catalog name matches generated brand alias tokens; manual review required."
    return "medium", 55, "Breach catalog reference matched a generated organization/domain alias."


_HIBP_GENERIC_DATA_CLASS_TERMS = {
    "recommended actions",
    "sponsored",
    "use a password manager",
    "services",
    "information",
    "connect with us",
    "subscribe",
    "privacy",
    "terms",
}


def _hibp_alias_matches(
    alias: str,
    breach_name: str,
    breach_domain: str,
    target_domain: str,
    *,
    target_registered_domain: str | None = None,
    parent_domain_expansion: bool = False,
) -> bool:
    return (
        _hibp_match_type(
            alias,
            breach_name,
            breach_domain,
            target_domain,
            target_registered_domain=target_registered_domain,
            parent_domain_expansion=parent_domain_expansion,
        )
        is not None
    )


def _hibp_alias_sort_key(alias: str) -> tuple[int, int, str]:
    text = str(alias or "")
    is_domain = 1 if "." in text else 0
    return (is_domain, len(text), text.lower())


def _hibp_clean_data_classes(values: Any) -> list[str]:
    cleaned: list[str] = []
    if not isinstance(values, list):
        return cleaned
    for value in values:
        text = re.sub(r"\s+", " ", str(value or "")).strip(" .;:-")
        if not text:
            continue
        lower = text.lower()
        if lower in _HIBP_GENERIC_DATA_CLASS_TERMS:
            continue
        if any(term in lower for term in _HIBP_GENERIC_DATA_CLASS_TERMS):
            continue
        cleaned.append(text)
    return cleaned[:20]


def _hibp_record_has_metadata(record: dict[str, Any]) -> bool:
    if str(record.get("breach_date") or "").strip():
        return True
    if str(record.get("added_date") or "").strip():
        return True
    if str(record.get("affected_accounts") or "").strip():
        return True
    return bool(_hibp_clean_data_classes(record.get("compromised_data_classes")))


def _hibp_content_is_not_found(html: str, *, final_url: str = "", status: int = 0) -> bool:
    if status in {404, 410}:
        return True
    final_path = urlsplit(str(final_url or "")).path.lower()
    if final_path.endswith("/404") or final_path == "/404":
        return True
    text = _strip_html(html).lower()
    title_match = re.search(r"(?is)<title[^>]*>(.*?)</title>", html or "")
    title = _strip_html(title_match.group(1)).lower() if title_match else ""
    has_breach_metadata = bool(re.search(r"(?i)\b(Breach date|Added date|Pwned accounts|Affected accounts|Compromised data)\b", html or ""))
    not_found_markers = (
        "404",
        "page not found",
        "not found",
        "outback",
        "gone walkabout",
        "couldn't find",
        "could not find",
    )
    return not has_breach_metadata and any(marker in title or marker in text for marker in not_found_markers)


def _breach_record_from_hibp_api(
    payload: Any,
    *,
    matched_alias: str,
    source_url: str,
    target_domain: str,
    target_registered_domain: str | None = None,
    parent_domain_expansion: bool = False,
) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    name = str(payload.get("Title") or payload.get("Name") or "").strip()
    if not name:
        return None
    domain = str(payload.get("Domain") or "").strip()
    if not _hibp_alias_matches(
        matched_alias,
        name,
        domain,
        target_domain,
        target_registered_domain=target_registered_domain,
        parent_domain_expansion=parent_domain_expansion,
    ):
        return None
    confidence, confidence_score, confidence_reason = _hibp_confidence(
        matched_alias,
        name,
        domain,
        target_domain,
        target_registered_domain=target_registered_domain,
        parent_domain_expansion=parent_domain_expansion,
    )
    match_type = _hibp_match_type(
        matched_alias,
        name,
        domain,
        target_domain,
        target_registered_domain=target_registered_domain,
        parent_domain_expansion=parent_domain_expansion,
    ) or "brand_alias"
    data_classes = _hibp_clean_data_classes(payload.get("DataClasses"))
    record = {
        "breach_name": name,
        "breach_date": str(payload.get("BreachDate") or ""),
        "added_date": str(payload.get("AddedDate") or ""),
        "affected_accounts": int(payload.get("PwnCount") or 0) if str(payload.get("PwnCount") or "").isdigit() else payload.get("PwnCount"),
        "compromised_data_classes": data_classes,
        "source_url": source_url,
        "matched_alias": matched_alias,
        "match_type": match_type,
        "confidence": confidence,
        "confidence_score": confidence_score,
        "confidence_reason": confidence_reason,
    }
    return record if _hibp_record_has_metadata(record) else None


def _regex_after_label(text: str, label: str) -> str:
    next_labels = "Breach date|Added date|Pwned accounts|Affected accounts|Compromised data"
    match = re.search(
        rf"(?i)\b{re.escape(label)}\s*:?\s*(.+?)(?=\s+(?:{next_labels})\b|[.;|]|$)",
        text,
    )
    return match.group(1).strip() if match else ""


def _breach_record_from_hibp_html(
    html: str,
    *,
    matched_alias: str,
    source_url: str,
    target_domain: str,
    target_registered_domain: str | None = None,
    parent_domain_expansion: bool = False,
    final_url: str = "",
    http_status: int = 200,
) -> dict[str, Any] | None:
    if _hibp_content_is_not_found(html, final_url=final_url or source_url, status=http_status):
        return None
    text = _strip_html(html)
    if not text:
        return None
    heading_match = re.search(r"(?is)<h1[^>]*>(.*?)</h1>", html) or re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
    heading = _strip_html(heading_match.group(1)) if heading_match else ""
    breach_name = heading
    data_breach_match = re.search(r"(?i)([A-Z0-9][A-Za-z0-9 '&.-]{1,80}? Data Breach)", text)
    if data_breach_match:
        breach_name = data_breach_match.group(1).strip()
    if not breach_name or not _hibp_alias_matches(
        matched_alias,
        breach_name,
        "",
        target_domain,
        target_registered_domain=target_registered_domain,
        parent_domain_expansion=parent_domain_expansion,
    ):
        return None

    data_classes_text = _regex_after_label(text, "Compromised data")
    data_classes: list[str] = []
    if data_classes_text:
        data_classes = _hibp_clean_data_classes([item.strip() for item in re.split(r",| and ", data_classes_text) if item.strip()])
    affected = _regex_after_label(text, "Pwned accounts") or _regex_after_label(text, "Affected accounts")
    affected_accounts = int(affected.replace(",", "")) if affected.replace(",", "").isdigit() else affected
    confidence, confidence_score, confidence_reason = _hibp_confidence(
        matched_alias,
        breach_name,
        "",
        target_domain,
        target_registered_domain=target_registered_domain,
        parent_domain_expansion=parent_domain_expansion,
    )
    match_type = _hibp_match_type(
        matched_alias,
        breach_name,
        "",
        target_domain,
        target_registered_domain=target_registered_domain,
        parent_domain_expansion=parent_domain_expansion,
    ) or "brand_alias"
    record = {
        "breach_name": breach_name,
        "breach_date": _regex_after_label(text, "Breach date"),
        "added_date": _regex_after_label(text, "Added date"),
        "affected_accounts": affected_accounts,
        "compromised_data_classes": data_classes,
        "source_url": source_url,
        "matched_alias": matched_alias,
        "match_type": match_type,
        "confidence": confidence,
        "confidence_score": confidence_score,
        "confidence_reason": confidence_reason,
    }
    return record if _hibp_record_has_metadata(record) else None


def _breach_record_from_hibp_catalog(
    payload: Any,
    *,
    organization_aliases: list[str],
    target_domain: str,
    target_registered_domain: str | None = None,
    parent_domain_expansion: bool = False,
    candidate_match_debug: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    if not isinstance(payload, list):
        return None
    for alias in sorted(organization_aliases, key=_hibp_alias_sort_key):
        for item in payload:
            if not isinstance(item, dict):
                continue
            name_for_url = str(item.get("Name") or item.get("Title") or "").strip()
            domain = str(item.get("Domain") or "").strip()
            decision = _hibp_match_decision(
                str(alias),
                name_for_url,
                domain,
                target_domain,
                target_registered_domain=target_registered_domain,
                parent_domain_expansion=parent_domain_expansion,
            )
            if candidate_match_debug is not None and len(candidate_match_debug) < 200:
                candidate_match_debug.append(decision)
            if not decision.get("accepted"):
                continue
            source_url = f"https://haveibeenpwned.com/Breach/{quote(name_for_url, safe='')}" if name_for_url else ""
            record = _breach_record_from_hibp_api(
                item,
                matched_alias=str(alias),
                source_url=source_url,
                target_domain=target_domain,
                target_registered_domain=target_registered_domain,
                parent_domain_expansion=parent_domain_expansion,
            )
            if record:
                return record
    return None


def _known_breach_signal(domain: str, record: dict[str, Any]) -> dict[str, Any]:
    breach_name = str(record.get("breach_name") or "Public breach catalog reference")
    data_classes = [str(item) for item in record.get("compromised_data_classes", []) if str(item or "").strip()]
    signal = _base_signal(
        category="known_breach_reference",
        title="Public breach catalog reference",
        status="needs_manual_review",
        confidence=str(record.get("confidence") or "medium"),
        confidence_score=int(record.get("confidence_score") or 55),
        source_name="known_breach_catalog",
        source_url=str(record.get("source_url") or ""),
        source_provider="haveibeenpwned",
        provider_reference=str(record.get("source_url") or ""),
        matched_entities={
            "domains": [domain] if domain else [],
            "subdomains": [],
            "emails": [],
            "urls": [str(record.get("source_url") or "")] if record.get("source_url") else [],
            "keywords": [str(record.get("matched_alias") or "")] if record.get("matched_alias") else [],
            "file_names": [],
        },
        snippet=(
            f"Public breach catalog reference found: {breach_name}; "
            f"breach_date={record.get('breach_date') or 'unknown'}; "
            f"affected_accounts={record.get('affected_accounts') or 'unknown'}; "
            f"data_classes={', '.join(data_classes[:8]) if data_classes else 'not listed'}"
        ),
        validation_notes=[
            "Public breach catalog reference only.",
            "Does not prove this scanned host is vulnerable.",
            "No credential material was collected.",
            "Manual validation required.",
        ],
        recommended_action="Review the public breach catalog page and validate organization relevance manually; do not collect credentials.",
        exposure_priority="review",
        false_positive_notes=[
            "Third-party breach catalog references may describe a parent brand, historical incident, subsidiary, or unrelated organization with a similar name.",
        ],
    )
    signal["breach_name"] = breach_name
    signal["breach_date"] = record.get("breach_date") or ""
    signal["added_date"] = record.get("added_date") or ""
    signal["affected_accounts"] = record.get("affected_accounts") or ""
    signal["compromised_data_classes"] = data_classes
    signal["matched_alias"] = record.get("matched_alias") or ""
    signal["match_type"] = record.get("match_type") or ""
    signal["confidence_reason"] = record.get("confidence_reason") or ""
    return signal


def _run_known_breach_catalog(
    *,
    domain: str,
    target_registered_domain: str | None,
    parent_domain_expansion: bool,
    organization_aliases: list[str],
    generic_or_reserved_domain: bool,
    timeout: int,
    deadline: float,
    max_signals: int,
    signals: list[dict[str, Any]],
    suppressed: list[dict[str, Any]],
    operator_search_tasks: list[dict[str, Any]],
    output_dir: Path | str | None,
    events: list[dict[str, str]] | None,
) -> dict[str, Any]:
    started = time.monotonic()
    endpoint_url = "https://haveibeenpwned.com/api/v3/breaches"
    if not domain or _looks_like_ip(domain):
        source = _source_record("known_breach_catalog", "skipped", 0, "Known breach lookup skipped because target is not a domain.", "", raw_count=0)
        source.update({"endpoint_url": endpoint_url, "endpoint_url_status": "not_checked", "report_url": "", "report_url_status": "unavailable"})
        return source
    if generic_or_reserved_domain:
        source = _source_record("known_breach_catalog", "skipped", 0, "Known breach lookup skipped for generic/reserved/example domain.", "", raw_count=0)
        source.update({"endpoint_url": endpoint_url, "endpoint_url_status": "not_checked", "report_url": "", "report_url_status": "unavailable"})
        return source

    records: list[dict[str, Any]] = []
    errors: list[str] = []
    not_found = 0
    catalog_checked = False
    alias_attempts: list[dict[str, str]] = []
    candidate_match_debug: list[dict[str, Any]] = []
    catalog_url = endpoint_url
    _emit_osint_event(events, output_dir, "info", "known_breach_catalog", "HIBP public all-breaches catalog lookup")
    try:
        catalog_payload = _fetch_json_with_retries(
            catalog_url,
            timeout=timeout,
            deadline=deadline,
            output_dir=output_dir,
            log_prefix="known breach catalog",
            events=events,
            event_source="known_breach_catalog",
            retries=1,
        )
        catalog_checked = True
        record = _breach_record_from_hibp_catalog(
            catalog_payload,
            organization_aliases=organization_aliases,
            target_domain=domain,
            target_registered_domain=target_registered_domain,
            parent_domain_expansion=parent_domain_expansion,
            candidate_match_debug=candidate_match_debug,
        )
        if record:
            records.append(record)
    except HTTPError as exc:
        errors.append(_error_note("HIBP all-breaches catalog lookup failed", exc))
        _emit_osint_event(events, output_dir, "error", "known_breach_catalog", f"HIBP catalog error {_error_label(exc)}")
        _close_http_error(exc)
    except (URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        errors.append(_error_note("HIBP all-breaches catalog lookup failed", exc))
        _emit_osint_event(events, output_dir, "error", "known_breach_catalog", f"HIBP catalog error {_error_label(exc)}")

    candidates = _hibp_slug_candidates(organization_aliases)
    for matched_alias, slug in ([] if records else candidates):
        attempt = {"alias": matched_alias, "slug": slug, "page_status": "not_attempted", "api_status": "not_attempted", "outcome": "no_match"}
        alias_attempts.append(attempt)
        page_url = f"https://haveibeenpwned.com/Breach/{quote(slug, safe='')}"
        _emit_osint_event(events, output_dir, "info", "known_breach_catalog", f"HIBP public page lookup: {slug}")
        try:
            page = _fetch_text_response_with_retries(
                page_url,
                timeout=timeout,
                deadline=deadline,
                output_dir=output_dir,
                log_prefix="known breach catalog",
                events=events,
                event_source="known_breach_catalog",
                retries=1,
            )
            http_status = int(page.get("status") or 0)
            final_url = str(page.get("final_url") or page_url)
            if http_status in {404, 410} or _hibp_content_is_not_found(str(page.get("text") or ""), final_url=final_url, status=http_status):
                not_found += 1
                attempt["page_status"] = "not_found"
            else:
                record = _breach_record_from_hibp_html(
                    str(page.get("text") or ""),
                    matched_alias=matched_alias,
                    source_url=final_url or page_url,
                    target_domain=domain,
                    target_registered_domain=target_registered_domain,
                    parent_domain_expansion=parent_domain_expansion,
                    final_url=final_url,
                    http_status=http_status,
                )
                if record:
                    attempt["page_status"] = "matched"
                    attempt["outcome"] = "matched"
                    records.append(record)
                    break
                attempt["page_status"] = "parse_failed"
        except HTTPError as exc:
            if exc.code in {404, 410}:
                not_found += 1
                attempt["page_status"] = "not_found"
                _close_http_error(exc)
            else:
                attempt["page_status"] = "error"
                attempt["outcome"] = "source_error"
                errors.append(_error_note(f"HIBP page lookup failed for {slug}", exc))
                _emit_osint_event(events, output_dir, "error", "known_breach_catalog", f"HIBP page error {_error_label(exc)}")
                _close_http_error(exc)
        except (URLError, TimeoutError, OSError) as exc:
            attempt["page_status"] = "error"
            attempt["outcome"] = "source_error"
            errors.append(_error_note(f"HIBP page lookup failed for {slug}", exc))
            _emit_osint_event(events, output_dir, "error", "known_breach_catalog", f"HIBP page error {_error_label(exc)}")

        api_url = f"https://haveibeenpwned.com/api/v3/breach/{quote(slug, safe='')}"
        try:
            payload = _fetch_json_with_retries(
                api_url,
                timeout=timeout,
                deadline=deadline,
                output_dir=output_dir,
                log_prefix="known breach catalog",
                events=events,
                event_source="known_breach_catalog",
                retries=1,
            )
            if isinstance(payload, dict):
                decision = _hibp_match_decision(
                    matched_alias,
                    str(payload.get("Title") or payload.get("Name") or ""),
                    str(payload.get("Domain") or ""),
                    domain,
                    target_registered_domain=target_registered_domain,
                    parent_domain_expansion=parent_domain_expansion,
                )
                if len(candidate_match_debug) < 200:
                    candidate_match_debug.append(decision)
            record = _breach_record_from_hibp_api(
                payload,
                matched_alias=matched_alias,
                source_url=page_url,
                target_domain=domain,
                target_registered_domain=target_registered_domain,
                parent_domain_expansion=parent_domain_expansion,
            )
            if record:
                attempt["api_status"] = "matched"
                attempt["outcome"] = "matched"
                records.append(record)
                break
            attempt["api_status"] = "completed_zero"
        except HTTPError as exc:
            if exc.code == 404:
                not_found += 1
                attempt["api_status"] = "alias_not_found"
                _close_http_error(exc)
            else:
                attempt["api_status"] = "error"
                attempt["outcome"] = "source_error"
                errors.append(_error_note(f"HIBP API lookup failed for {slug}", exc))
                _emit_osint_event(events, output_dir, "error", "known_breach_catalog", f"HIBP API error {_error_label(exc)}")
                _close_http_error(exc)
        except (URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            attempt["api_status"] = "error"
            attempt["outcome"] = "source_error"
            errors.append(_error_note(f"HIBP API lookup failed for {slug}", exc))
            _emit_osint_event(events, output_dir, "error", "known_breach_catalog", f"HIBP API error {_error_label(exc)}")

    seen: set[str] = set()
    before_signals = len(signals)
    before_suppressed = len(suppressed)
    for record in records:
        key = f"{record.get('breach_name')}:{record.get('source_url')}"
        if key in seen:
            continue
        seen.add(key)
        _append_signal(signals, suppressed, _known_breach_signal(domain, record), max_signals)

    signal_delta = len(signals) - before_signals
    if signal_delta:
        status = "partial" if errors else "completed_matched"
        notes = "Public third-party breach catalog reference observed; metadata only, no credential material collected."
    elif errors:
        status = "error"
        notes = "Known breach catalog lookup had a real source error; no breach reference was created from successful alias checks."
    else:
        status = "completed_no_match"
        notes = "No reliable public breach catalog reference matched generated aliases."
        if organization_aliases and not any(task.get("source_name") == "known_breach_catalog" for task in operator_search_tasks):
            operator_search_tasks.append(
                _base_operator_search_task(
                    source_name="known_breach_catalog",
                    query=f"HIBP manual breach catalog review for {organization_aliases[0]}",
                    link="",
                    purpose="Suggestion only: manually review the public HIBP breach catalog for generated aliases if needed.",
                    safety_note="Manual catalog review only. Do not search accounts, collect credentials, download dumps, or validate secrets.",
                    quality="medium_signal",
                    category="breach_catalog",
                )
            )
    if errors:
        notes = f"{notes} Errors: {'; '.join(errors)}"
    report_url = ""
    report_url_status = "unavailable"
    endpoint_url_status = "validated" if catalog_checked else "not_checked"
    if signal_delta:
        report_url = str(next((record.get("source_url") for record in records if str(record.get("source_url") or "").startswith("https://haveibeenpwned.com/Breach/")), "") or "")
        report_url_status = "validated" if report_url else "unavailable"
    _emit_osint_event(events, output_dir, "info", "known_breach_catalog", f"{signal_delta} known breach references, status={status}")
    source = _source_record(
        "known_breach_catalog",
        status,
        signal_delta,
        notes,
        report_url,
        raw_count=len(records),
        suppressed_count=len(suppressed) - before_suppressed,
        errors=errors,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    source["outcome"] = "matched" if signal_delta else "source_error" if errors else "alias_not_found"
    source["match_status"] = "matched" if signal_delta else "source_error" if errors else "no_match"
    source["endpoint_url"] = endpoint_url
    source["endpoint_url_status"] = endpoint_url_status
    source["report_url"] = report_url
    source["report_url_status"] = report_url_status
    source["alias_attempts"] = alias_attempts
    source["candidate_match_debug"] = candidate_match_debug
    source["diagnostics"] = {
        "aliases_tried": [alias for alias, _slug in candidates],
        "slugs_tried": [slug for _alias, slug in candidates],
        "no_match_reason": "" if signal_delta else "Generated aliases/slugs did not match a public HIBP breach page or API record.",
        "not_found_responses": not_found,
        "candidate_match_debug": candidate_match_debug,
    }
    return source


def _summary(
    signals: list[dict[str, Any]],
    suppressed: list[dict[str, Any]],
    operator_search_tasks: list[dict[str, Any]],
    asset_identity_observations: list[dict[str, Any]],
    asset_discovery_candidates: list[dict[str, Any]],
    historical_url_context: list[dict[str, Any]],
    infrastructure: dict[str, Any] | None = None,
    organization_intelligence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    counts = {"confirmed": 0, "unconfirmed": 0, "needs_manual_review": 0}
    highest = "none"
    for signal in signals:
        status = str(signal.get("status") or "")
        if status in counts:
            counts[status] += 1
        confidence = str(signal.get("confidence") or "none")
        if _CONFIDENCE_RANK.get(confidence, 0) > _CONFIDENCE_RANK.get(highest, 0):
            highest = confidence
    observed_count = len(signals)
    infra = infrastructure if isinstance(infrastructure, dict) else {}
    infrastructure_ips = len(infra.get("resolved_ips", []) if isinstance(infra.get("resolved_ips"), list) else [])
    infrastructure_ipv6 = len(infra.get("ipv6_addresses", []) if isinstance(infra.get("ipv6_addresses"), list) else [])
    infrastructure_lookup_tasks = len(infra.get("passive_lookup_links", []) if isinstance(infra.get("passive_lookup_links"), list) else [])
    cdn_or_proxy_likely_count = 1 if infra.get("cdn_or_proxy_likely") else 0
    org = organization_intelligence if isinstance(organization_intelligence, dict) else {}
    org_summary = org.get("summary") if isinstance(org.get("summary"), dict) else {}
    return {
        "observed_signals": observed_count,
        "asset_identity_observations": len(asset_identity_observations),
        "asset_discovery_candidates": len(asset_discovery_candidates),
        "infrastructure_ips": infrastructure_ips,
        "infrastructure_ipv6": infrastructure_ipv6,
        "infrastructure_lookup_tasks": infrastructure_lookup_tasks,
        "cdn_or_proxy_likely_count": cdn_or_proxy_likely_count,
        "official_pages_checked": int(org_summary.get("official_pages_checked") or 0),
        "official_pages_found": int(org_summary.get("official_pages_found") or 0),
        "official_pages_not_found": int(org_summary.get("official_pages_not_found") or 0),
        "official_pages_soft_error": int(org_summary.get("official_pages_soft_error") or 0),
        "official_pages_unexpected_content": int(org_summary.get("official_pages_unexpected_content") or 0),
        "official_pages_duplicates": int(org_summary.get("official_pages_duplicates") or 0),
        "official_pages_forbidden": int(org_summary.get("official_pages_forbidden") or 0),
        "security_txt_checked": int(org_summary.get("security_txt_checked") or 0),
        "security_txt_found": int(org_summary.get("security_txt_found") or 0),
        "robots_found": int(org_summary.get("robots_found") or 0),
        "sitemap_found": int(org_summary.get("sitemap_found") or 0),
        "auto_checked_urls": int(org_summary.get("auto_checked_urls") or 0),
        "manual_only_urls": int(org_summary.get("manual_only_urls") or 0),
        "api_required_urls": int(org_summary.get("api_required_urls") or 0) + infrastructure_lookup_tasks,
        "generated_candidate_urls": int(org_summary.get("generated_candidate_urls") or 0),
        "role_contact_candidates": int(org_summary.get("role_contact_candidates") or 0),
        "generated_contact_guesses": int(org_summary.get("generated_contact_guesses") or 0),
        "observed_public_contacts": int(org_summary.get("observed_public_contacts") or 0),
        "observed_email_addresses": int(org_summary.get("observed_email_addresses") or 0),
        "observed_phone_numbers": int(org_summary.get("observed_phone_numbers") or 0),
        "observed_contact_urls": int(org_summary.get("observed_contact_urls") or 0),
        "observed_contact_forms": int(org_summary.get("observed_contact_forms") or 0),
        "target_observed_public_contacts": int(org_summary.get("target_observed_public_contacts") or 0),
        "parent_org_observed_public_contacts": int(org_summary.get("parent_org_observed_public_contacts") or 0),
        "affiliate_observed_public_contacts": int(org_summary.get("affiliate_observed_public_contacts") or 0),
        "target_observed_phone_numbers": int(org_summary.get("target_observed_phone_numbers") or 0),
        "parent_org_observed_phone_numbers": int(org_summary.get("parent_org_observed_phone_numbers") or 0),
        "historical_url_candidates": len(historical_url_context),
        "live_validated_historical_urls": 0,
        "mx_records_count": int(org_summary.get("mx_records_count") or 0),
        "suppressed_contacts_count": int(org_summary.get("suppressed_contacts_count") or 0),
        "organization_lookup_tasks": int(org_summary.get("organization_lookup_tasks") or 0),
        "public_document_search_tasks": int(org_summary.get("public_document_search_tasks") or 0),
        "location_hints": int(org_summary.get("location_hints") or 0),
        "observed_locations": int(org_summary.get("observed_locations") or 0),
        "official_location_pages": int(org_summary.get("official_location_pages") or 0),
        "validated_public_documents": int(org_summary.get("validated_public_documents") or 0),
        "document_candidates": int(org_summary.get("document_candidates") or 0),
        "observed_official_social_profiles": int(org_summary.get("observed_official_social_profiles") or 0),
        "target_observed_locations": int(org_summary.get("target_observed_locations") or 0),
        "parent_org_observed_locations": int(org_summary.get("parent_org_observed_locations") or 0),
        "affiliate_observed_locations": int(org_summary.get("affiliate_observed_locations") or 0),
        "target_validated_public_documents": int(org_summary.get("target_validated_public_documents") or 0),
        "parent_org_validated_public_documents": int(org_summary.get("parent_org_validated_public_documents") or 0),
        "affiliate_validated_public_documents": int(org_summary.get("affiliate_validated_public_documents") or 0),
        "target_observed_social_profiles": int(org_summary.get("target_observed_social_profiles") or 0),
        "parent_org_observed_social_profiles": int(org_summary.get("parent_org_observed_social_profiles") or 0),
        "affiliate_observed_social_profiles": int(org_summary.get("affiliate_observed_social_profiles") or 0),
        "generated_search_tasks": len(operator_search_tasks),
        "manual_search_tasks": len(operator_search_tasks),
        "total_signals": observed_count,
        "confirmed": counts["confirmed"],
        "unconfirmed": counts["unconfirmed"],
        "needs_manual_review": counts["needs_manual_review"],
        "suppressed": len(suppressed),
        "suppressed_noise": len(suppressed),
        "highest_confidence": highest,
        "risk_score_impact": "none",
    }


def _source_health_summary(sources: list[dict[str, Any]]) -> dict[str, int]:
    live_names = {"certificate_transparency", "historical_urls", "public_code_search", "known_breach_catalog"}
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
    for source in sources:
        name = str(source.get("name") or "")
        status = str(source.get("status") or "")
        row_status = _source_health_status(source)
        if status == "suggestions_generated":
            health["suggestions_only"] += 1
            health["suggestions_generated_count"] += 1
            continue
        if status == "skipped":
            health["skipped"] += 1
            continue
        if name in live_names:
            health["attempted_live_sources"] += 1
        if status == "partial":
            health["partial"] += 1
        if row_status in {"ok", "slow"}:
            health["completed"] += 1
        elif row_status == "no_match":
            health["no_match"] += 1
            health["no_match_count"] += 1
        elif row_status == "timeout":
            health["timeout"] += 1
            health["timeout_count"] += 1
        elif row_status == "provider_unavailable":
            health["unavailable"] += 1
            health["provider_unavailable"] += 1
            health["provider_unavailable_count"] += 1
        elif row_status == "auth_required":
            health["auth_required_fallback"] += 1
            health["auth_required_fallback_count"] += 1
            health["suggestions_only"] += 1
        elif row_status == "rate_limited":
            health["rate_limited_fallback"] += 1
            health["rate_limited_fallback_count"] += 1
            health["suggestions_only"] += 1
        elif row_status == "error":
            health["error"] += 1
        elif row_status == "suggestions_generated":
            health["suggestions_only"] += 1
            health["suggestions_generated_count"] += 1
        elif status == "unavailable":
            health["unavailable"] += 1
        elif status in {"error", "timeout", "no_match"}:
            health[status] += 1
            if status == "timeout":
                health["timeout_count"] += 1
            if status == "no_match":
                health["no_match_count"] += 1
    return health


def _osint_coverage_issue_phrases(sources: list[dict[str, Any]]) -> list[str]:
    phrases: list[str] = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        name = str(source.get("name") or "")
        status = str(source.get("status") or "")
        if name == "certificate_transparency":
            provider_issue = _provider_issue_details(source)
            provider_status = str(provider_issue.get("status") or "")
            if provider_status == "provider_unavailable" or status == "unavailable":
                phrase = "crt.sh unavailable"
            elif provider_status == "timeout" or status == "timeout":
                phrase = "crt.sh timed out"
            elif provider_status == "error" or status == "error":
                phrase = "crt.sh errored"
            else:
                phrase = ""
            if phrase and phrase not in phrases:
                phrases.append(phrase)
        elif name == "historical_urls":
            phrase = "Wayback timed out" if status == "timeout" else "Wayback unavailable" if status == "unavailable" else "Wayback errored" if status == "error" else ""
            if phrase and phrase not in phrases:
                phrases.append(phrase)
        elif name == "public_code_search":
            phrase = (
                "GitHub code search requires authentication"
                if status == "auth_required_fallback"
                else "GitHub code search is rate limited"
                if status == "rate_limited_fallback"
                else "GitHub code search errored"
                if status == "error"
                else ""
            )
            if phrase and phrase not in phrases:
                phrases.append(phrase)
    return phrases


def _effective_status(status: str, sources: list[dict[str, Any]]) -> str:
    health = _source_health_summary(sources)
    attempted = health["attempted_live_sources"]
    if attempted == 0 and health["suggestions_only"] > 0:
        return "suggestions_only"
    failure_count = health["error"] + health["timeout"] + health["unavailable"]
    if attempted and failure_count == attempted and health["suggestions_only"] > 0:
        return "live_sources_failed_suggestions_only"
    if attempted and (health.get("auth_required_fallback", 0) or health.get("rate_limited_fallback", 0)) and health["completed"] == 0 and health["partial"] == 0:
        return "live_sources_auth_or_rate_fallback"
    if attempted and health["completed"] == 0 and health["partial"] == 0 and failure_count == attempted:
        return "live_sources_failed"
    if attempted and health["completed"] == 0 and health["partial"] == 0 and health["error"] == 0 and health.get("no_match", 0):
        return "live_sources_completed_zero"
    if status == "completed" and health["completed"] and health["error"] == 0 and health["partial"] == 0:
        return "live_sources_completed"
    if status == "partial":
        return "live_sources_partial"
    return status or "unknown"


def _provider_issue_details(source: dict[str, Any]) -> dict[str, str]:
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


def _source_health_status(source: dict[str, Any]) -> str:
    status = str(source.get("status") or "")
    errors = " ".join(str(item) for item in source.get("errors", []) if str(item or "").strip()).lower()
    if status == "completed":
        duration = int(source.get("duration_ms") or 0)
        return "slow" if duration > 5000 else "ok"
    if status == "completed_matched":
        duration = int(source.get("duration_ms") or 0)
        return "slow" if duration > 5000 else "ok"
    if status in {"no_match", "completed_no_match"}:
        return "no_match"
    if status == "timeout":
        return "timeout"
    if status == "unavailable":
        return "provider_unavailable"
    if status == "partial":
        provider_status = _provider_issue_details(source).get("status")
        if provider_status:
            return str(provider_status)
        return "slow" if "timeout" in errors else "unknown"
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


def _diagnostics_from_sources(sources: list[dict[str, Any]]) -> dict[str, Any]:
    endpoint_map = {
        "certificate_transparency": "https://crt.sh/",
        "historical_urls": "https://web.archive.org/cdx",
        "public_code_search": "https://api.github.com/search/code",
        "known_breach_catalog": "https://haveibeenpwned.com/api/v3/breaches",
        "safe_search_dorks": "manual",
    }
    checked_hosts: list[str] = []
    dns_errors: list[str] = []
    checked_endpoints: list[str] = []
    http_errors: list[str] = []
    source_health: list[dict[str, Any]] = []
    live_records = 0
    live_ok = 0
    live_error = 0
    live_fallback = 0
    for source in sources:
        name = str(source.get("name") or "")
        endpoint = str(source.get("endpoint_url") or endpoint_map.get(name, ""))
        if endpoint and endpoint != "manual":
            checked_endpoints.append(endpoint)
            parsed = urlsplit(endpoint)
            if parsed.hostname:
                checked_hosts.append(parsed.hostname)
        status = str(source.get("status") or "")
        errors = [str(item) for item in source.get("errors", []) if str(item or "").strip()]
        if name in {"certificate_transparency", "historical_urls", "public_code_search", "known_breach_catalog"} and status != "suggestions_generated":
            live_records += 1
            if status in {"completed", "completed_matched", "partial", "no_match", "completed_no_match"}:
                live_ok += 1
            if status in {"error", "timeout", "unavailable"}:
                live_error += 1
                http_errors.extend(errors)
            if status in {"auth_required_fallback", "rate_limited_fallback"}:
                live_fallback += 1
        provider_issue = _provider_issue_details(source)
        endpoint_status = str(source.get("endpoint_url_status") or "not_checked")
        source_health.append(
            {
                "source": name,
                "endpoint": endpoint,
                "url_role": "diagnostic_endpoint" if endpoint and endpoint != "manual" else "",
                "url_status": endpoint_status,
                "browser_safe": False,
                "render_as_clickable": False,
                "status": _source_health_status(source),
                "latency_ms": int(source.get("duration_ms") or 0) or None,
                "http_status": None,
                "error": "; ".join(errors),
                "error_class": str(source.get("error_class") or provider_issue.get("error_class") or ""),
                "user_message": str(source.get("user_message") or provider_issue.get("user_message") or ""),
            }
        )
    if live_records == 0:
        network_available: bool | str = "unknown"
        http_status = "partial" if checked_endpoints else "error"
    else:
        network_available = live_ok > 0
        http_status = "ok" if live_ok == live_records else "partial" if live_ok or live_fallback else "error"
    return {
        "network_available": network_available,
        "dns_resolution": {
            "status": "ok" if checked_hosts else "skipped",
            "checked_hosts": sorted(set(checked_hosts)),
            "errors": dns_errors,
        },
        "http_connectivity": {
            "status": http_status,
            "checked_endpoints": checked_endpoints,
            "errors": http_errors,
        },
        "source_health": source_health,
    }


def _osint_verdict(
    *,
    enabled: bool,
    summary: dict[str, Any],
    source_health: dict[str, int],
    infrastructure: dict[str, Any] | None = None,
    organization_intelligence: dict[str, Any] | None = None,
    sources: list[dict[str, Any]] | None = None,
) -> tuple[str, str]:
    observed = int(summary.get("observed_signals") or 0)
    manual_tasks = int(summary.get("generated_search_tasks") or 0)
    asset_discovery = int(summary.get("asset_discovery_candidates") or 0)
    asset_identity = int(summary.get("asset_identity_observations") or 0)
    infrastructure_ips = int(summary.get("infrastructure_ips") or 0) + int(summary.get("infrastructure_ipv6") or 0)
    organization_context = sum(
        int(summary.get(key) or 0)
        for key in (
            "official_pages_checked",
            "official_pages_found",
            "official_pages_soft_error",
            "security_txt_found",
            "generated_contact_guesses",
            "observed_public_contacts",
            "organization_lookup_tasks",
            "public_document_search_tasks",
            "location_hints",
            "observed_locations",
            "validated_public_documents",
            "observed_official_social_profiles",
        )
    )
    infra = infrastructure if isinstance(infrastructure, dict) else {}
    dns_status = str(infra.get("dns_status") or "")
    attempted = int(source_health.get("attempted_live_sources") or 0)
    failures = int(source_health.get("error") or 0)
    failures += int(source_health.get("timeout") or 0)
    failures += int(source_health.get("unavailable") or 0)
    coverage_issues = _osint_coverage_issue_phrases(sources or [])
    if not enabled:
        return "disabled", "OSINT enrichment was disabled for this run."
    if observed > 0:
        return (
            "observed_evidence",
            f"Passive public sources produced {observed} observed evidence item(s). Manual search tasks are suggestions only and do not affect risk score.",
        )
    if failures > 0 or (coverage_issues and int(source_health.get("auth_required_fallback_count") or source_health.get("auth_required_fallback") or 0)):
        if coverage_issues:
            issue_text = ", ".join(coverage_issues[:-1])
            if len(coverage_issues) > 1:
                issue_text = f"{issue_text}, and {coverage_issues[-1]}" if issue_text else coverage_issues[-1]
            else:
                issue_text = coverage_issues[0]
            return (
                "source_failures",
                f"OSINT coverage is partial: {issue_text}. Absence of evidence is not conclusive. Manual search tasks are not findings.",
            )
        return (
            "source_failures",
            f"{failures} live passive source(s) failed or were unavailable, so absence of evidence is not conclusive. Manual search tasks are not findings.",
        )
    if dns_status in {"error", "timeout"}:
        return (
            "source_failures",
            "DNS infrastructure resolution failed or timed out, so absence of infrastructure evidence is not conclusive. Manual lookup links are not findings.",
        )
    if int(summary.get("historical_url_candidates") or 0) > 0:
        return (
            "historical_context_only",
            "Wayback/CDX produced archived URL candidates, but they were not fetched live and are not observed current exposure evidence.",
        )
    if asset_discovery > 0 or asset_identity > 0 or infrastructure_ips > 0:
        return (
            "asset_discovery_only",
            f"Passive sources produced {asset_discovery} CT asset discovery candidate(s), {asset_identity} asset identity observation(s), and {infrastructure_ips} resolved infrastructure address(es), but no observed exposure evidence. Infrastructure records are not proof hosts are vulnerable or origin servers.",
        )
    if organization_context > 0:
        return (
            "organization_context_only",
            "Passive organization intelligence produced public context, contact candidates, or manual lookup shortcuts, but no observed exposure evidence. Organization context does not affect risk score.",
        )
    if attempted == 0 and manual_tasks > 0:
        return (
            "suggestions_only",
            "No live passive source produced observed evidence; only manual search tasks were generated. Manual search tasks are not findings.",
        )
    return (
        "no_observed_evidence",
        "Live passive sources completed or returned no matching public records; no observed evidence was created. Manual search tasks, if any, are suggestions only.",
    )


def build_osint_enrichment(
    *,
    target: str,
    enabled: bool,
    mode: str = "safe_mvp",
    scan_profile: str = "balanced",
    tool_settings: dict[str, Any] | None = None,
    output_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Run bounded passive OSINT MVP adapters and return the OSINT contract.

    The adapters query only public passive metadata sources and never probe the target,
    validate secrets, access credential dumps, or create vulnerability findings.
    """
    settings = _osint_settings(tool_settings)
    target_context = _target_context(target)
    domain = str(target_context.get("target_domain") or "")
    generic_or_reserved_domain = bool(target_context.get("generic_or_reserved_domain"))
    max_signals = _setting_int(settings, "max_signals", "maxSignals", 50)
    timeout = _setting_int(settings, "timeout", "timeout", 30) or 30
    ct_wayback_timeout = _ct_wayback_timeout_for_profile(scan_profile, timeout)
    include_ct = _setting_bool(settings, "include_certificate_transparency", "includeCertificateTransparency", True)
    include_wayback = _setting_bool(settings, "include_historical_urls", "includeHistoricalUrls", True)
    include_code = _setting_bool(settings, "include_public_code_references", "includePublicCodeReferences", True)
    include_known_breach = _setting_bool(
        settings,
        "include_known_breach_catalog",
        "includeKnownBreachCatalog",
        bool(not settings or settings.get("enabled")),
    )
    include_dorks = _setting_bool(settings, "include_search_dork_suggestions", "includeSearchDorkSuggestions", True)
    include_infrastructure = _setting_bool(settings, "include_infrastructure_intelligence", "includeInfrastructureIntelligence", True)
    include_organization = _setting_bool(settings, "include_organization_intelligence", "includeOrganizationIntelligence", True)
    github_source_settings = _source_setting(settings, "githubCodeSearch", "github_code_search")
    wayback_source_settings = _source_setting(settings, "wayback", "wayback")
    crt_source_settings = _source_setting(settings, "crtsh", "crtsh")
    known_breach_source_settings = _source_setting(settings, "knownBreachCatalog", "known_breach_catalog")
    github_api_key_env = str(github_source_settings.get("apiKeyEnv") or github_source_settings.get("api_key_env") or "GITHUB_TOKEN").strip() or "GITHUB_TOKEN"
    if "enabled" in github_source_settings:
        include_code = bool(github_source_settings.get("enabled"))
    if "enabled" in wayback_source_settings:
        include_wayback = bool(wayback_source_settings.get("enabled"))
    if "enabled" in crt_source_settings:
        include_ct = bool(crt_source_settings.get("enabled"))
    if "enabled" in known_breach_source_settings:
        include_known_breach = bool(known_breach_source_settings.get("enabled"))
    github_timeout = _setting_int(github_source_settings, "timeout", "timeout", timeout) if "timeout" in github_source_settings else timeout
    wayback_retry_count = _setting_int(wayback_source_settings, "retry_count", "retryCount", 0 if str(scan_profile or "").strip().lower() == "fast" else 1)
    crt_retry_count = _setting_int(crt_source_settings, "retry_count", "retryCount", 0 if str(scan_profile or "").strip().lower() == "fast" else 1)
    if "timeout" in wayback_source_settings or "timeout" in crt_source_settings:
        wayback_timeout = _setting_int(wayback_source_settings, "timeout", "timeout", ct_wayback_timeout)
        crt_timeout = _setting_int(crt_source_settings, "timeout", "timeout", ct_wayback_timeout)
    else:
        wayback_timeout = ct_wayback_timeout
        crt_timeout = ct_wayback_timeout
    check_organization_pages = _setting_bool(settings, "check_organization_pages", "checkOrganizationPages", True)
    include_subdomains = _setting_bool(settings, "include_subdomains", "includeSubdomains", True)
    include_asset_identity_as_signal = _setting_bool(
        settings,
        "include_asset_identity_as_signal",
        "includeAssetIdentityAsSignal",
        False,
    )
    passive_only = _setting_bool(settings, "passive_only", "passiveOnly", True)
    metadata_feed_config = _metadata_feed_settings(settings)
    darkweb_config = _darkweb_settings(settings)
    metadata_feed_runtime_config = dict(metadata_feed_config)
    darkweb_runtime_config = dict(darkweb_config)
    if not bool(enabled and mode == "safe_mvp" and passive_only):
        metadata_feed_runtime_config["enabled"] = False
        darkweb_runtime_config["enabled"] = False
    organization_aliases = [
        str(alias)
        for alias in target_context.get("organization_aliases", [])
        if str(alias or "").strip()
    ]

    signals: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    asset_identity_observations: list[dict[str, Any]] = []
    asset_discovery_candidates: list[dict[str, Any]] = []
    historical_url_context: list[dict[str, Any]] = []
    operator_search_tasks: list[dict[str, Any]] = []
    infrastructure: dict[str, Any] = {}
    organization_intelligence: dict[str, Any] = {}
    sources: list[dict[str, Any]] = []
    events: list[dict[str, str]] = []
    deadline = time.monotonic() + max(1, timeout)
    if enabled:
        _emit_osint_event(events, output_dir, "info", "osint", f"target normalized: {domain}")

    if not enabled:
        status = "disabled"
    elif mode != "safe_mvp" or not passive_only:
        status = "error"
        sources.append(_source_record("policy", "error", 0, "OSINT MVP requires mode=safe_mvp and passive_only=true."))
    else:
        if include_infrastructure:
            _emit_osint_event(events, output_dir, "info", "infrastructure_intelligence", f"passive DNS resolution started for {domain}")
            infrastructure = _build_infrastructure_intelligence(
                target_host=domain,
                target_registered_domain=str(target_context.get("target_registered_domain") or "") or None,
                timeout=min(timeout, 5),
            )
            _emit_osint_event(
                events,
                output_dir,
                "info",
                "infrastructure_intelligence",
                (
                    f"dns_status={infrastructure.get('dns_status')} "
                    f"ipv4={len(infrastructure.get('resolved_ips', []))} "
                    f"ipv6={len(infrastructure.get('ipv6_addresses', []))} "
                    f"lookup_links={len(infrastructure.get('passive_lookup_links', []))}"
                ),
            )
        if include_organization:
            organization_intelligence = _build_organization_intelligence(
                target_host=domain,
                target_registered_domain=str(target_context.get("target_registered_domain") or "") or None,
                organization_aliases=organization_aliases,
                timeout=min(timeout, 3 if scan_profile == "fast" else 10 if scan_profile in {"slow", "deep"} else 6),
                check_pages=check_organization_pages,
                events=events,
            )
        if include_ct:
            sources.append(
                _run_certificate_transparency(
                    domain=domain,
                    registered_domain=str(target_context.get("target_registered_domain") or ""),
                    timeout=crt_timeout,
                    retry_count=crt_retry_count,
                    deadline=deadline,
                    max_signals=max_signals,
                    include_subdomains=include_subdomains,
                    include_asset_identity_as_signal=include_asset_identity_as_signal,
                    signals=signals,
                    suppressed=suppressed,
                    asset_identity_observations=asset_identity_observations,
                    asset_discovery_candidates=asset_discovery_candidates,
                    output_dir=output_dir,
                    events=events,
                )
            )
        if include_wayback:
            sources.append(
                _run_wayback(
                    domain=domain,
                    timeout=wayback_timeout,
                    retry_count=wayback_retry_count,
                    deadline=deadline,
                    max_signals=max_signals,
                    scan_profile=scan_profile,
                    signals=signals,
                    suppressed=suppressed,
                    historical_url_context=historical_url_context,
                    output_dir=output_dir,
                    events=events,
                )
            )
        if include_code:
            sources.append(
                _run_github_code_search(
                    domain=domain,
                    timeout=github_timeout,
                    api_key_env=github_api_key_env,
                    deadline=deadline,
                    max_signals=max_signals,
                    scan_profile=scan_profile,
                    generic_or_reserved_domain=generic_or_reserved_domain,
                    signals=signals,
                    suppressed=suppressed,
                    operator_search_tasks=operator_search_tasks,
                    output_dir=output_dir,
                    events=events,
                )
            )
        if include_known_breach:
            sources.append(
                _run_known_breach_catalog(
                    domain=domain,
                    target_registered_domain=str(target_context.get("target_registered_domain") or ""),
                    parent_domain_expansion=bool(target_context.get("parent_domain_expansion")),
                    organization_aliases=organization_aliases,
                    generic_or_reserved_domain=generic_or_reserved_domain,
                    timeout=timeout,
                    deadline=deadline,
                    max_signals=max_signals,
                    signals=signals,
                    suppressed=suppressed,
                    operator_search_tasks=operator_search_tasks,
                    output_dir=output_dir,
                    events=events,
                )
            )
        if include_dorks:
            sources.append(
                _add_dork_suggestions(
                    domain=domain,
                    email_domain=str(target_context.get("target_registered_domain") or ""),
                    generic_or_reserved_domain=generic_or_reserved_domain,
                    operator_search_tasks=operator_search_tasks,
                    output_dir=output_dir,
                    events=events,
                )
            )
        if operator_search_tasks:
            _emit_osint_event(events, output_dir, "info", "osint", f"manual search tasks: generated {len(operator_search_tasks)}")
        health = _source_health_summary(sources)
        attempted = health["attempted_live_sources"]
        failure_count = health["error"] + health["timeout"] + health["unavailable"]
        if attempted == 0:
            status = "suggestions_only" if health["suggestions_only"] else "completed"
        elif (health["completed"] >= 1 or health["no_match"] >= 1) and failure_count == 0 and health["partial"] == 0:
            status = "completed"
        elif health["completed"] >= 1 or health["partial"] >= 1 or health["no_match"] >= 1:
            status = "partial"
        else:
            status = "partial" if health["suggestions_only"] else "error"

    summary = _summary(
        signals,
        suppressed,
        operator_search_tasks,
        asset_identity_observations,
        asset_discovery_candidates,
        historical_url_context,
        infrastructure,
        organization_intelligence,
    )
    source_health = _source_health_summary(sources)
    diagnostics = _diagnostics_from_sources(sources)
    effective_status = _effective_status(status, sources)
    verdict, verdict_reason = _osint_verdict(
        enabled=enabled,
        summary=summary,
        source_health=source_health,
        infrastructure=infrastructure,
        organization_intelligence=organization_intelligence,
        sources=sources,
    )
    summary["source_health"] = source_health
    summary["effective_status"] = effective_status
    summary["verdict"] = verdict
    summary["verdict_reason"] = verdict_reason
    leak_intelligence = build_leak_intelligence(
        enabled=bool(enabled and (include_known_breach or metadata_feed_runtime_config.get("enabled"))),
        known_breach_enabled=bool(enabled and include_known_breach),
        signals=signals,
        sources=sources,
        requested_target_host=str(target_context.get("target_host") or domain or ""),
        requested_registered_domain=str(target_context.get("target_registered_domain") or ""),
        organization_aliases=organization_aliases,
        metadata_feed_config=metadata_feed_runtime_config,
    )
    darkweb_intelligence = build_darkweb_intelligence(
        enabled=bool(enabled and (include_known_breach or metadata_feed_runtime_config.get("enabled") or darkweb_runtime_config.get("enabled", True))),
        target_context=target_context,
        leak_intelligence=leak_intelligence,
        settings=darkweb_runtime_config,
    )
    _emit_osint_event(
        events,
        output_dir,
        "info",
        "osint",
        f"completed: observed_signals={summary['observed_signals']} manual_tasks={summary['generated_search_tasks']} status={status}",
    )

    payload = {
        "enabled": bool(enabled),
        "status": status,
        "verdict": verdict,
        "verdict_reason": verdict_reason,
        "mode": mode or "safe_mvp",
        "summary": summary,
        "effective_status": effective_status,
        "source_health": source_health,
        "osint_source_health_summary": diagnostics.get("osint_source_health_summary", {}),
        "diagnostics": diagnostics,
        "normalization": {
            "input": str(target or ""),
            "target_host": target_context.get("target_host"),
            "target_domain": domain,
            "target_registered_domain": target_context.get("target_registered_domain"),
            "scope_mode": target_context.get("scope_mode"),
            "parent_domain_expansion": target_context.get("parent_domain_expansion"),
            "generic_or_reserved_domain": generic_or_reserved_domain,
            "organization_aliases": organization_aliases,
        },
        "signals": signals,
        "leak_intelligence": leak_intelligence,
        "darkweb_intelligence": darkweb_intelligence,
        "infrastructure": infrastructure,
        "organization_intelligence": organization_intelligence,
        "historical_url_context": historical_url_context,
        "asset_identity_observations": asset_identity_observations,
        "asset_discovery_candidates": asset_discovery_candidates,
        "operator_search_tasks": operator_search_tasks,
        "suppressed_signals": suppressed,
        "sources": sources,
        "events": events,
        "policy": {
            "passive_only": True,
            "no_credential_download": True,
            "no_marketplace_scraping": True,
            "no_login_required_sources": True,
            "no_active_exploit": True,
            "risk_score_impact": "none",
        },
        "settings": {
            "target_domain": domain,
            "target_host": target_context.get("target_host"),
            "target_registered_domain": target_context.get("target_registered_domain"),
            "scope_mode": target_context.get("scope_mode"),
            "parent_domain_expansion": target_context.get("parent_domain_expansion"),
            "include_certificate_transparency": include_ct,
            "include_historical_urls": include_wayback,
            "include_public_code_references": include_code,
            "include_known_breach_catalog": include_known_breach,
            "include_search_dork_suggestions": include_dorks,
            "include_infrastructure_intelligence": include_infrastructure,
            "include_organization_intelligence": include_organization,
            "check_organization_pages": check_organization_pages,
            "include_subdomains": include_subdomains,
            "include_asset_identity_as_signal": include_asset_identity_as_signal,
            "leak_sources": {
                "metadata_feed": _sanitized_metadata_feed_settings(metadata_feed_config),
            },
            "darkweb": _sanitized_darkweb_settings(darkweb_config),
            "max_signals": max_signals,
            "timeout": timeout,
            "ct_wayback_timeout": ct_wayback_timeout,
            "osint_sources": {
                "github_code_search": {
                    "enabled": include_code,
                    "api_key_env": github_api_key_env,
                    "api_key_configured": bool(os.environ.get(github_api_key_env)),
                },
                "wayback": {
                    "enabled": include_wayback,
                    "timeout": wayback_timeout,
                    "retry_count": wayback_retry_count,
                },
                "crtsh": {
                    "enabled": include_ct,
                    "timeout": crt_timeout,
                    "retry_count": crt_retry_count,
                },
                "known_breach_catalog": {"enabled": include_known_breach},
            },
            "passive_only": True,
            "scan_profile": scan_profile,
            "generic_or_reserved_domain": generic_or_reserved_domain,
        },
    }
    return _decorate_osint_url_audit(payload)


def build_osint_placeholder(
    *,
    enabled: bool,
    mode: str = "safe_mvp",
    tool_settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Backward-compatible wrapper for callers that still request placeholder data."""
    return build_osint_enrichment(
        target="",
        enabled=enabled,
        mode=mode,
        tool_settings=tool_settings,
    )


# Compatibility wrappers for the public facade. Keep these names patchable via
# `reconbot.orchestration.osint.*` while the implementation lives in focused
# osint_core modules.
def _query_dns_records(name: str, record_type: str, timeout: int) -> dict[str, Any]:
    return _mail_dns_core.query_dns_records(name, record_type, timeout)


def _mail_infrastructure_intelligence(registered_domain: str | None, timeout: int) -> dict[str, Any]:
    return _mail_dns_core.mail_infrastructure_intelligence(
        registered_domain,
        timeout,
        query_func=_query_dns_records,
        now_func=_now_iso,
    )


def _provider_issue_details(source: dict[str, Any]) -> dict[str, str]:
    return _source_health_core.provider_issue_details(source)


def _source_health_status(source: dict[str, Any]) -> str:
    return _source_health_core.source_health_status(source)


def _source_health_summary(sources: list[dict[str, Any]]) -> dict[str, int]:
    return _source_health_core.source_health_summary(sources)


def _diagnostics_from_sources(sources: list[dict[str, Any]]) -> dict[str, Any]:
    diagnostics = _source_health_core.diagnostics_from_sources(sources)
    diagnostics["dns_runtime"] = _mail_dns_core.dns_runtime_diagnostic()
    return diagnostics
