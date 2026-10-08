"""Manual metadata-only darkweb reference import."""

from __future__ import annotations

from reconbot.orchestration.osint_core.domains import registered_domain

import json
import re
from pathlib import Path
from typing import Any, Mapping

from .models import observed_reference, source_record, suppressed_item
from .provider_registry import MANUAL_DARKWEB_METADATA_IMPORT
from .safety import is_safe_metadata_item, safe_reference_url


GENERIC_WORDS = {"www", "com", "net", "org", "corp", "company", "group", "the", "and"}


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _as_int(value: Any, default: int, *, minimum: int = 1, maximum: int = 100) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = default
    return max(minimum, min(maximum, parsed))


def _normalize_host(value: Any) -> str:
    raw = _clean(value).lower().replace("*.", "").strip(".")
    if not raw:
        return ""
    if "://" in raw:
        from urllib.parse import urlsplit

        raw = urlsplit(raw).hostname or ""
    raw = raw.split("/", 1)[0].split(":", 1)[0]
    return raw if re.fullmatch(r"[a-z0-9.-]+", raw) else ""


def _registered_domain(host: str) -> str:
    return registered_domain(str(host or ""))


def _list_values(value: Any) -> list[str]:
    if isinstance(value, list):
        return [_clean(item) for item in value if _clean(item)]
    text = _clean(value)
    return [text] if text else []


def _strong_alias(value: str) -> str:
    alias = re.sub(r"\s+", " ", _clean(value).lower())
    if not alias or alias in GENERIC_WORDS:
        return ""
    if "." not in alias and len(alias) < 4:
        return ""
    return alias


def _match_item(
    item: Mapping[str, Any],
    *,
    target_host: str,
    registered_domain: str,
    aliases: list[str],
) -> tuple[str, str, str, list[str], bool | str]:
    item_domains = [_normalize_host(domain) for domain in _list_values(item.get("matched_domains") or item.get("domains"))]
    item_domains = [domain for domain in item_domains if domain]
    for domain in item_domains:
        if target_host and domain == target_host:
            return "exact_domain", "high", "Metadata import hedef host ile açık eşleşti.", [domain], True
    for domain in item_domains:
        if registered_domain and (domain == registered_domain or _registered_domain(domain) == registered_domain):
            return "registered_domain", "high", "Metadata import registered domain ile açık eşleşti.", [domain], "unknown"
    item_brands = [_strong_alias(brand) for brand in _list_values(item.get("matched_brands") or item.get("brands"))]
    item_brands = [brand for brand in item_brands if brand]
    alias_candidates = [_strong_alias(alias) for alias in [target_host, registered_domain, *aliases]]
    alias_candidates = [alias for alias in alias_candidates if alias and "." not in alias]
    for alias in alias_candidates:
        if alias in item_brands:
            return "brand_alias", "medium", "Metadata import marka alias'ı ile eşleşti; manuel doğrulama gerekir.", [alias], "unknown"
    return "", "", "", [], "unknown"


def _load_json(path: str) -> Mapping[str, Any]:
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, Mapping):
        raise ValueError("manual darkweb metadata root must be a JSON object")
    return loaded


def collect_manual_metadata_import(
    *,
    config: Mapping[str, Any] | None,
    requested_target_host: str,
    requested_registered_domain: str,
    organization_aliases: list[str],
) -> dict[str, Any]:
    cfg = config if isinstance(config, Mapping) else {}
    source_name = _clean(cfg.get("sourceName") or cfg.get("source_name")) or "manual_darkweb_metadata_import"
    if not _as_bool(cfg.get("enabled")):
        source = source_record(
            source_id=MANUAL_DARKWEB_METADATA_IMPORT,
            display_name_tr="Manuel darkweb metadata import",
            source_type="manual_metadata_import",
            status="disabled",
            coverage_impact="low",
            user_message_tr="Kaynak kurulu ama kapalı.",
            operator_action_tr="Güvenilir metadata-only JSON dosyası varsa manuel import'u etkinleştir.",
        )
        return {"source": source, "observed_references": [], "suppressed_sensitive_items": []}

    file_path = _clean(cfg.get("filePath") or cfg.get("file_path"))
    max_results = _as_int(cfg.get("maxResults") or cfg.get("max_results"), 25)
    if not file_path:
        source = source_record(
            source_id=MANUAL_DARKWEB_METADATA_IMPORT,
            display_name_tr="Manuel darkweb metadata import",
            source_type="manual_metadata_import",
            status="not_configured",
            coverage_impact="low",
            finding_impact="manual_review_needed",
            user_message_tr="Kaynak açık ama yapılandırılmamış.",
            operator_action_tr="Metadata-only JSON dosya yolunu yapılandır.",
        )
        return {"source": source, "observed_references": [], "suppressed_sensitive_items": []}

    try:
        loaded = _load_json(file_path)
    except Exception as exc:
        source = source_record(
            source_id=MANUAL_DARKWEB_METADATA_IMPORT,
            display_name_tr="Manuel darkweb metadata import",
            source_type="manual_metadata_import",
            status="invalid_config",
            coverage_impact="low",
            finding_impact="manual_review_needed",
            user_message_tr="Manuel metadata import güvenli JSON metadata olarak okunamadı.",
            operator_action_tr="Dosyanın metadata-only JSON formatında olduğunu doğrula.",
            items_loaded_count=0,
        )
        source["error_class"] = exc.__class__.__name__
        source["error"] = Path(file_path).name
        return {"source": source, "observed_references": [], "suppressed_sensitive_items": []}

    source_name = _clean(loaded.get("source_name")) or source_name
    items = loaded.get("items") if isinstance(loaded.get("items"), list) else []
    references: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    target_host = _normalize_host(requested_target_host)
    registered_domain = _normalize_host(requested_registered_domain)
    for item in items:
        if not isinstance(item, Mapping):
            continue
        safe, categories = is_safe_metadata_item(item)
        if not safe:
            for category in sorted(categories):
                suppressed.append(suppressed_item(category=category, source_provider=_clean(item.get("source_provider")) or source_name))
            continue
        match_type, confidence, confidence_reason, matched, applies_to_target = _match_item(
            item,
            target_host=target_host,
            registered_domain=registered_domain,
            aliases=organization_aliases,
        )
        if not match_type:
            continue
        reference_url = _clean(item.get("reference_url") or item.get("url"))
        browser_safe, clickable, observed_host, observed_registered = safe_reference_url(reference_url)
        references.append(
            observed_reference(
                title=_clean(item.get("title")) or "Darkweb metadata reference",
                source_provider=_clean(item.get("source_provider")) or source_name,
                source_name=source_name,
                source_channel=_clean(item.get("source_channel")) or "manual_import",
                reference_url=reference_url,
                browser_safe=browser_safe,
                render_as_clickable=clickable,
                published_at=_clean(item.get("published_at") or item.get("added_date")),
                breach_date=_clean(item.get("breach_date")),
                affected_accounts=item.get("affected_accounts") if item.get("affected_accounts") not in ("", None) else None,
                data_classes=_list_values(item.get("data_classes") or item.get("compromised_data_classes")),
                matched_entities={"matched": matched, "domains": _list_values(item.get("matched_domains")), "brands": _list_values(item.get("matched_brands"))},
                match_type=match_type,
                confidence=confidence,
                confidence_reason_tr=confidence_reason,
                scope_origin="manual_metadata_import",
                applies_to_target=applies_to_target,
                requested_target_host=target_host,
                requested_registered_domain=registered_domain,
                observed_on_host=observed_host,
                observed_on_registered_domain=observed_registered,
            )
        )
        if len(references) >= max_results:
            break

    status = "completed" if references else "no_match"
    source = source_record(
        source_id=MANUAL_DARKWEB_METADATA_IMPORT,
        display_name_tr="Manuel darkweb metadata import",
        source_type="manual_metadata_import",
        status=status,
        coverage_impact="none",
        user_message_tr=(
            "Manuel metadata import tamamlandı; eşleşen metadata referansı görüldü."
            if references
            else "Manuel metadata import tamamlandı; eşleşen metadata referansı görülmedi."
        ),
        operator_action_tr="Kurumla ilişkisini manuel doğrula; kimlik bilgisi toplama." if references else "Aksiyon yok.",
        items_loaded_count=len(items),
        items_matched_count=len(references),
        items_suppressed_count=len(suppressed),
    )
    return {"source": source, "observed_references": references, "suppressed_sensitive_items": suppressed}
