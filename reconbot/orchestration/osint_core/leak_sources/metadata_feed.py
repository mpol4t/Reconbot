"""Generic metadata-only leak feed collector.

This adapter intentionally consumes only normalized breach/leak metadata from a
configured local JSON file or HTTPS JSON endpoint. It never fetches raw dumps,
credentials, paste bodies, onion sites, or darkweb forums.
"""

from __future__ import annotations

from reconbot.orchestration.osint_core.domains import registered_domain

import json
import os
import re
import socket
import time
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

from .models import LeakSourceReference, LeakSourceResult, SuppressedSensitiveItem
from .policy import is_browser_safe_manual_url, safety_note_for_category, sanitize_reference_payload
from .provider_registry import (
    ProviderValidation,
    validate_metadata_feed_provider,
)
from .redaction import detect_sensitive_categories, marker_for_category


DEFAULT_SOURCE_NAME = "leak_metadata_feed"
SOURCE_TYPE = "leak_metadata_api"
RECOMMENDED_ACTION = "Manually validate organization relevance; do not collect credentials."
GENERIC_ALIAS_WORDS = {
    "www",
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "io",
    "co",
    "inc",
    "llc",
    "ltd",
    "corp",
    "company",
    "group",
    "the",
    "and",
    "for",
    "app",
    "api",
    "online",
    "digital",
    "security",
    "service",
    "services",
}
KNOWN_MULTI_LABEL_SUFFIXES = {
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


def _now_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


def _as_int(value: Any, default: int, *, minimum: int = 0, maximum: int | None = None) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = default
    parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_host(value: Any) -> str:
    raw = _clean_text(value).lower()
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw.split("/", 1)[0].split(":", 1)[0]
    host = host.replace("*.", "").strip(".").lower()
    if not host or "/" in host or "@" in host:
        return ""
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        return ""
    return host


def _registered_domain(host: Any) -> str:
    return registered_domain(str(host or ""))


def _safe_endpoint(value: str) -> str:
    parsed = urlsplit(_clean_text(value))
    if parsed.scheme == "https" and parsed.netloc:
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    if parsed.scheme:
        return f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else parsed.scheme
    return "local_json_feed" if value else ""


def _feed_source_type(*, feed_path: str = "", feed_url: str = "") -> str:
    if feed_path:
        return "local_file"
    if feed_url:
        return "https_json" if urlsplit(feed_url).scheme == "https" else "unsupported_url"
    return ""


def _provider_diagnostics(validation: ProviderValidation, *, api_key_env: str = "") -> dict[str, Any]:
    profile = validation.profile
    return {
        "provider_id": validation.provider_id,
        "provider_display_name": profile.display_name if profile else "",
        "provider_status": profile.status if profile else "unknown",
        "source_mode": validation.source_mode,
        "schema_adapter": profile.schema_adapter if profile else "",
        "metadata_only": True if profile is None else bool(profile.metadata_only),
        "forbids_credentials": True if profile is None else bool(profile.forbids_credentials),
        "forbids_dumps": True if profile is None else bool(profile.forbids_dumps),
        "forbids_raw_content": True if profile is None else bool(profile.forbids_raw_content),
        "provider_validation_status": validation.status,
        "provider_validation_message": validation.message,
        "api_key_env_configured": bool(_clean_text(api_key_env)),
        "api_key_value_serialized": False,
    }


def _feed_path_basename(path: str) -> str:
    return Path(path).expanduser().name if _clean_text(path) else ""


def _safe_error_message(exc: Exception, *, feed_path: str = "") -> str:
    if feed_path:
        return f"{exc.__class__.__name__}: {_feed_path_basename(feed_path)}"
    return str(exc)


def _safe_diagnostics(diagnostics: Mapping[str, Any] | None) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in dict(diagnostics or {}).items():
        if key in {"api_key", "apiKey", "apiKeyEnv", "api_key_env", "authorization"}:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            safe[str(key)] = value
    return safe


def _source_health(
    *,
    source_name: str,
    status: str,
    started: float,
    endpoint: str = "",
    user_message: str = "",
    error: str = "",
    error_class: str = "",
    diagnostics: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    row = {
        "source": source_name,
        "collector_name": DEFAULT_SOURCE_NAME,
        "collector": DEFAULT_SOURCE_NAME,
        "endpoint": _safe_endpoint(endpoint),
        "status": status,
        "source_status": status,
        "latency_ms": _now_ms(started),
        "error": error[:200],
        "error_class": error_class[:100],
        "user_message": user_message[:300],
        "browser_safe": False,
        "render_as_clickable": False,
        "risk_score_impact": 0,
    }
    row.update(_safe_diagnostics(diagnostics))
    return row


def _result(
    *,
    source_name: str,
    status: str,
    started: float,
    endpoint: str = "",
    observed_references: list[LeakSourceReference] | None = None,
    suppressed_sensitive_items: list[SuppressedSensitiveItem] | None = None,
    operator_notes: list[str] | None = None,
    user_message: str = "",
    error: str = "",
    error_class: str = "",
    diagnostics: Mapping[str, Any] | None = None,
) -> LeakSourceResult:
    return LeakSourceResult(
        source_name=source_name,
        source_type=SOURCE_TYPE,
        status=status,  # type: ignore[arg-type]
        observed_references=observed_references or [],
        suppressed_sensitive_items=suppressed_sensitive_items or [],
        source_health_row=_source_health(
            source_name=source_name,
            status=status,
            started=started,
            endpoint=endpoint,
            user_message=user_message,
            error=error,
            error_class=error_class,
            diagnostics=diagnostics,
        ),
        operator_notes=operator_notes or [],
        risk_score_impact=0,
    )


def _list_values(value: Any) -> list[str]:
    if isinstance(value, list):
        return [_clean_text(item) for item in value if _clean_text(item)]
    if isinstance(value, tuple):
        return [_clean_text(item) for item in value if _clean_text(item)]
    text = _clean_text(value)
    return [text] if text else []


def _first(item: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in item and item.get(key) not in (None, ""):
            return item.get(key)
    return ""


def _strong_alias(alias: str) -> str:
    value = re.sub(r"\s+", " ", _clean_text(alias).lower())
    if not value or value in GENERIC_ALIAS_WORDS:
        return ""
    if value.count(".") == 0 and len(value) < 4:
        return ""
    if re.fullmatch(r"[a-z]{2,3}", value) and value in GENERIC_ALIAS_WORDS:
        return ""
    return value


def _alias_candidates(aliases: Iterable[str], target_host: str, registered_domain: str) -> list[str]:
    candidates: list[str] = []
    for alias in [target_host, registered_domain, *aliases]:
        value = _strong_alias(alias)
        if value and value not in candidates:
            candidates.append(value)
        host = _normalize_host(value)
        if host:
            label = host.split(".", 1)[0]
            label = _strong_alias(label)
            if label and label not in candidates:
                candidates.append(label)
    return candidates


def _item_domains(item: Mapping[str, Any]) -> list[str]:
    domains = _list_values(_first(item, "matched_domains", "domains"))
    normalized: list[str] = []
    for domain in domains:
        host = _normalize_host(domain)
        if host and host not in normalized:
            normalized.append(host)
    return normalized


def _item_brands(item: Mapping[str, Any]) -> list[str]:
    brands = _list_values(_first(item, "matched_brands", "brands"))
    return [brand for brand in (_strong_alias(item) for item in brands) if brand]


def _match_item(
    item: Mapping[str, Any],
    *,
    target_host: str,
    registered_domain: str,
    aliases: list[str],
) -> tuple[str, str, str, list[str], str]:
    item_domains = _item_domains(item)
    for domain in item_domains:
        if target_host and domain == target_host:
            return (
                "exact_domain",
                "high",
                "Feed metadata explicitly matched the requested target host.",
                [domain],
                domain,
            )
    for domain in item_domains:
        if registered_domain and (domain == registered_domain or _registered_domain(domain) == registered_domain):
            return (
                "registered_domain",
                "high",
                "Feed metadata explicitly matched the requested registered domain.",
                [domain],
                domain,
            )

    alias_candidates = _alias_candidates(aliases, target_host, registered_domain)
    item_brands = _item_brands(item)
    for alias in alias_candidates:
        if "." in alias:
            continue
        if alias in item_brands:
            confidence = "high" if len(alias) >= 8 else "medium"
            return (
                "brand_alias",
                confidence,
                "Feed metadata matched a normalized brand alias; manual relevance review required.",
                [alias],
                "",
            )

    searchable_text = " ".join(
        [
            _clean_text(_first(item, "title")),
            _clean_text(_first(item, "snippet")),
        ]
    )
    searchable_text = searchable_text.lower()
    for alias in alias_candidates:
        if "." in alias or len(alias) < 6:
            continue
        if re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", searchable_text):
            return (
                "keyword_alias",
                "low",
                "Feed text mentioned a strong alias; manual relevance review required.",
                [alias],
                "",
            )
    return "", "", "", [], ""


def _browser_safe_reference_url(url: str) -> bool:
    parsed = urlsplit(_clean_text(url))
    host = (parsed.hostname or "").lower()
    return (
        is_browser_safe_manual_url(url)
        and parsed.scheme == "https"
        and not host.endswith(".onion")
        and host != "onion"
    )


def _suppressed_from_value(value: Any, *, source_provider: str) -> list[SuppressedSensitiveItem]:
    suppressed: list[SuppressedSensitiveItem] = []
    if isinstance(value, Mapping):
        for nested in value.values():
            suppressed.extend(_suppressed_from_value(nested, source_provider=source_provider))
    elif isinstance(value, list):
        for nested in value:
            suppressed.extend(_suppressed_from_value(nested, source_provider=source_provider))
    elif isinstance(value, tuple):
        for nested in value:
            suppressed.extend(_suppressed_from_value(nested, source_provider=source_provider))
    elif isinstance(value, str):
        for category in sorted(detect_sensitive_categories(value)):
            suppressed.append(
                SuppressedSensitiveItem(
                    category=category,
                    redaction_marker=marker_for_category(category),
                    safety_note=safety_note_for_category(category),
                    source_provider=source_provider,
                )
            )
    return suppressed


def _reference_from_item(
    item: Mapping[str, Any],
    *,
    feed_source_name: str,
    provider_id: str,
    provider_display_name: str,
    target_host: str,
    registered_domain: str,
    aliases: list[str],
) -> tuple[LeakSourceReference | None, list[SuppressedSensitiveItem]]:
    source_provider = _clean_text(_first(item, "source_provider")) or feed_source_name or DEFAULT_SOURCE_NAME
    match_type, confidence, confidence_reason, matched_entities, observed_domain = _match_item(
        item,
        target_host=target_host,
        registered_domain=registered_domain,
        aliases=aliases,
    )
    suppressed = _suppressed_from_value(item, source_provider=source_provider)
    if not match_type:
        return None, suppressed

    title = _clean_text(_first(item, "title")) or "External leak metadata reference"
    reference_url = _clean_text(_first(item, "reference_url", "url"))
    parsed_reference = urlsplit(reference_url)
    reference_host = (parsed_reference.hostname or "").lower()
    observed_on_host = _normalize_host(reference_host)
    observed_on_registered_domain = _registered_domain(observed_on_host)
    data_classes = _list_values(_first(item, "compromised_data_classes", "data_classes"))
    published_at = _clean_text(_first(item, "published_at", "added_date"))
    payload, redaction_suppressed = sanitize_reference_payload(
        {
            "title": title,
            "reference_url": reference_url,
            "browser_safe": _browser_safe_reference_url(reference_url),
            "render_as_clickable": _browser_safe_reference_url(reference_url),
            "source_provider": source_provider,
            "provider_id": provider_id,
            "provider_display_name": provider_display_name,
            "matched_entities": {
                "domains": _item_domains(item),
                "brands": _item_brands(item),
                "matched": matched_entities,
            },
            "match_type": match_type,
            "confidence": confidence,
            "confidence_reason": confidence_reason,
            "scope_origin": "external_verified_source",
            "requested_target_host": target_host,
            "requested_registered_domain": registered_domain,
            "observed_on_host": observed_on_host,
            "observed_on_registered_domain": observed_on_registered_domain,
            "applies_to_target": True if match_type == "exact_domain" else "unknown",
            "applies_to_parent_org": False,
            "scope_caveat": "Metadata-only external reference; relevance to the exact target must be reviewed manually.",
            "evidence_type": "public_leak_metadata",
            "breach_date": _clean_text(_first(item, "breach_date")),
            "added_date": published_at,
            "published_at": published_at,
            "affected_accounts": _first(item, "affected_accounts"),
            "compromised_data_classes": data_classes,
            "redacted_snippet": _clean_text(_first(item, "snippet")),
            "recommended_action": RECOMMENDED_ACTION,
        },
        source_provider=source_provider,
    )
    return LeakSourceReference(**payload), suppressed + redaction_suppressed


def _load_local_feed(path: str) -> Mapping[str, Any]:
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, Mapping):
        raise ValueError("metadata feed root must be a JSON object")
    return loaded


def _load_https_feed(url: str, *, api_key_env: str, timeout: int) -> Mapping[str, Any]:
    parsed = urlsplit(_clean_text(url))
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("metadata feed URL must use https://")
    headers = {"Accept": "application/json", "User-Agent": "ReconBot-metadata-feed/1.0"}
    env_name = _clean_text(api_key_env)
    if env_name:
        api_key = os.environ.get(env_name, "")
        if not api_key:
            raise PermissionError("metadata feed API key environment variable is not set")
        headers["Authorization"] = f"Bearer {api_key}"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=max(1, timeout)) as response:
        data = response.read(2_000_000)
    loaded = json.loads(data.decode("utf-8"))
    if not isinstance(loaded, Mapping):
        raise ValueError("metadata feed root must be a JSON object")
    return loaded


def _items_from_feed(feed: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    items = feed.get("items")
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, Mapping)]


def result_from_metadata_feed(
    *,
    config: Mapping[str, Any] | None,
    requested_target_host: str,
    requested_registered_domain: str,
    organization_aliases: list[str] | None = None,
) -> LeakSourceResult:
    started = time.monotonic()
    cfg = config if isinstance(config, Mapping) else {}
    source_name = _clean_text(cfg.get("sourceName") or cfg.get("source_name")) or DEFAULT_SOURCE_NAME
    validation = validate_metadata_feed_provider(cfg)
    provider_diagnostics = _provider_diagnostics(
        validation,
        api_key_env=_clean_text(cfg.get("apiKeyEnv") or cfg.get("api_key_env")),
    )
    base_diagnostics = {
        **provider_diagnostics,
        "feed_source_type": validation.source_mode,
        "feed_path_basename": _feed_path_basename(_clean_text(cfg.get("feedPath") or cfg.get("feed_path"))),
        "items_loaded_count": 0,
        "items_matched_count": 0,
        "items_suppressed_count": 0,
    }
    if validation.status in {"invalid_config", "not_implemented"}:
        endpoint = _clean_text(cfg.get("feedPath") or cfg.get("feed_path")) or _clean_text(cfg.get("feedUrl") or cfg.get("feed_url"))
        return _result(
            source_name=source_name,
            status=validation.status,  # type: ignore[arg-type]
            started=started,
            endpoint=endpoint,
            user_message=validation.message,
            error=validation.status,
            error_class="ProviderValidationError",
            diagnostics=base_diagnostics,
        )
    if not _as_bool(cfg.get("enabled"), default=False):
        return _result(
            source_name=source_name,
            status="disabled",
            started=started,
            user_message="Metadata feed collector disabled because metadataFeed.enabled=false.",
            diagnostics={
                **base_diagnostics,
                "disabled_reason": "metadataFeed.enabled=false",
            },
        )

    feed_path = _clean_text(cfg.get("feedPath") or cfg.get("feed_path"))
    feed_url = _clean_text(cfg.get("feedUrl") or cfg.get("feed_url"))
    api_key_env = _clean_text(cfg.get("apiKeyEnv") or cfg.get("api_key_env"))
    timeout = _as_int(cfg.get("timeout"), 10, minimum=1, maximum=60)
    max_results = _as_int(cfg.get("maxResults") or cfg.get("max_results"), 25, minimum=1, maximum=100)
    endpoint = feed_path or feed_url

    if not feed_path and not feed_url:
        return _result(
            source_name=source_name,
            status="not_configured",
            started=started,
            user_message="Metadata feed collector enabled=true but no feedPath/feedUrl was configured.",
            diagnostics={
                **base_diagnostics,
                "not_configured_reason": "enabled=true but no feedPath/feedUrl",
            },
        )
    feed_diagnostics = {
        **provider_diagnostics,
        "feed_source_type": _feed_source_type(feed_path=feed_path, feed_url=feed_url),
        "source_mode": validation.source_mode or _feed_source_type(feed_path=feed_path, feed_url=feed_url),
        "feed_path_basename": _feed_path_basename(feed_path),
        "items_loaded_count": 0,
        "items_matched_count": 0,
        "items_suppressed_count": 0,
    }
    parsed_feed_url = urlsplit(feed_url) if feed_url else None
    if parsed_feed_url and (parsed_feed_url.scheme != "https" or not parsed_feed_url.netloc):
        return _result(
            source_name=source_name,
            status="error",
            started=started,
            endpoint=feed_url,
            user_message="Metadata feed URL must be a complete https:// URL.",
            error="unsupported_metadata_feed_url_scheme",
            error_class="ValueError",
            diagnostics=feed_diagnostics,
        )

    try:
        feed = _load_local_feed(feed_path) if feed_path else _load_https_feed(feed_url, api_key_env=api_key_env, timeout=timeout)
    except PermissionError as exc:
        return _result(
            source_name=source_name,
            status="auth_required",
            started=started,
            endpoint=endpoint,
            user_message="Metadata feed API key environment variable is missing.",
            error=str(exc),
            error_class=exc.__class__.__name__,
            diagnostics=feed_diagnostics,
        )
    except TimeoutError as exc:
        return _result(
            source_name=source_name,
            status="timeout",
            started=started,
            endpoint=endpoint,
            user_message="Metadata feed request timed out.",
            error=str(exc),
            error_class=exc.__class__.__name__,
            diagnostics=feed_diagnostics,
        )
    except HTTPError as exc:
        status = "auth_required" if exc.code in {401, 403} else "provider_unavailable" if exc.code in {429, 500, 502, 503, 504} else "error"
        return _result(
            source_name=source_name,
            status=status,
            started=started,
            endpoint=endpoint,
            user_message=f"Metadata feed returned HTTP {exc.code}.",
            error=f"HTTP {exc.code}",
            error_class=exc.__class__.__name__,
            diagnostics=feed_diagnostics,
        )
    except (URLError, socket.timeout) as exc:
        reason = getattr(exc, "reason", exc)
        status = "timeout" if isinstance(reason, TimeoutError) or "timed out" in str(reason).lower() else "provider_unavailable"
        return _result(
            source_name=source_name,
            status=status,
            started=started,
            endpoint=endpoint,
            user_message="Metadata feed endpoint was unavailable.",
            error=str(reason),
            error_class=exc.__class__.__name__,
            diagnostics=feed_diagnostics,
        )
    except Exception as exc:
        return _result(
            source_name=source_name,
            status="error",
            started=started,
            endpoint=endpoint,
            user_message="Metadata feed could not be parsed as safe JSON metadata.",
            error=_safe_error_message(exc, feed_path=feed_path),
            error_class=exc.__class__.__name__,
            diagnostics=feed_diagnostics,
        )

    feed_source_name = _clean_text(feed.get("source_name")) or source_name
    references: list[LeakSourceReference] = []
    suppressed: list[SuppressedSensitiveItem] = []
    items = _items_from_feed(feed)
    for item in items:
        reference, item_suppressed = _reference_from_item(
            item,
            feed_source_name=feed_source_name,
            provider_id=validation.provider_id,
            provider_display_name=validation.profile.display_name if validation.profile else "",
            target_host=_normalize_host(requested_target_host),
            registered_domain=_normalize_host(requested_registered_domain),
            aliases=organization_aliases or [],
        )
        suppressed.extend(item_suppressed)
        if reference is not None:
            references.append(reference)
        if len(references) >= max_results:
            break

    status = "completed" if references else "no_match"
    feed_diagnostics.update(
        {
            "items_loaded_count": len(items),
            "items_matched_count": len(references),
            "items_suppressed_count": len(suppressed),
        }
    )
    return _result(
        source_name=source_name,
        status=status,
        started=started,
        endpoint=endpoint,
        observed_references=references,
        suppressed_sensitive_items=suppressed,
        operator_notes=[
            "Metadata feed collector consumed only normalized metadata; no raw leak material was requested or stored."
        ],
        user_message=(
            f"Metadata feed {feed_diagnostics['feed_source_type']} loaded {len(items)} item(s); "
            f"matched {len(references)}; suppressed {len(suppressed)}."
            if references
            else (
                f"Metadata feed {feed_diagnostics['feed_source_type']} loaded {len(items)} item(s); "
                f"matched 0; suppressed {len(suppressed)}. No matching public leak metadata reference was observed in the configured feed."
            )
        ),
        diagnostics=feed_diagnostics,
    )
