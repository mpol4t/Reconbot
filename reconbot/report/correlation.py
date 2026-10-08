from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, replace
from typing import Any
from urllib.parse import urlparse

from reconbot.core.models import nuclei_to_findings


SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}

AUTH_SURFACE_MARKERS = (
    "login",
    "signin",
    "sign-in",
    "admin",
    "dashboard",
    "wp-login",
    "wp-admin",
    "phpmyadmin",
    "cpanel",
    "manager",
)


PUBLIC_CONTENT_PATH_MARKERS = (
    "/blog/",
    "/blog/category/",
    "/blog/tags/",
    "/docs/",
    "/help/",
    "/resources/",
    "/resource/",
    "/category/",
    "/tags/",
    "/tag/",
    "/services/",
    "/products/",
    "/news/",
    "/events/",
    "/company/",
    "/careers/",
    "/legal/",
)


@dataclass(frozen=True)
class CorrelationInsight:
    id: str
    title: str
    affected_asset: str
    finding_type: str
    severity: str
    confidence: int
    evidence_sources: list[str] = field(default_factory=list)
    evidence_summary: str = ""
    why_it_matters: str = ""
    exploitability_assessment: str = ""
    manual_validation_steps: list[str] = field(default_factory=list)
    false_positive_notes: str = ""
    recommended_first_action: str = ""
    related_tools: list[str] = field(default_factory=list)
    related_findings: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_correlation_insights(
    *,
    target: str = "",
    nmap_output: str = "",
    gobuster_results: dict[str, Any] | None = None,
    katana_urls: list[str] | None = None,
    checks_results: dict[str, Any] | None = None,
    nuclei_entries: list[dict[str, Any]] | None = None,
    nuclei_results: dict[str, Any] | None = None,
    run_context: dict[str, Any] | None = None,
) -> list[CorrelationInsight]:
    """Build report-level correlations from already collected Reconbot evidence.

    This layer intentionally does not run scanners or read extra artifacts. It
    only interprets the normalized structures already available to the report.
    """

    checks_results = checks_results if isinstance(checks_results, dict) else {}
    gobuster_results = gobuster_results if isinstance(gobuster_results, dict) else {}
    katana_urls = katana_urls if isinstance(katana_urls, list) else []
    run_context = run_context if isinstance(run_context, dict) else {}
    nuclei_items = _normalize_nuclei_entries(nuclei_entries, nuclei_results)
    screenshots_by_asset = _collect_screenshot_signals(checks_results, run_context)

    insights: list[CorrelationInsight] = []
    insights.extend(
        _correlate_technology_with_nuclei(
            checks_results=checks_results,
            run_context=run_context,
            nuclei_entries=nuclei_items,
            screenshots_by_asset=screenshots_by_asset,
        )
    )
    insights.extend(
        _correlate_high_severity_nuclei_validation(
            checks_results=checks_results,
            run_context=run_context,
            nuclei_entries=nuclei_items,
            screenshots_by_asset=screenshots_by_asset,
        )
    )
    insights.extend(
        _correlate_waf_with_nuclei(
            checks_results=checks_results,
            run_context=run_context,
            nuclei_entries=nuclei_items,
            screenshots_by_asset=screenshots_by_asset,
        )
    )
    insights.extend(
        _correlate_auth_surfaces(
            target=target,
            gobuster_results=gobuster_results,
            katana_urls=katana_urls,
            checks_results=checks_results,
            run_context=run_context,
            screenshots_by_asset=screenshots_by_asset,
        )
    )
    insights.extend(
        _correlate_services_with_http_surface(
            target=target,
            nmap_output=nmap_output,
            checks_results=checks_results,
            run_context=run_context,
        )
    )
    insights.extend(
        _correlate_historical_urls(
            checks_results=checks_results,
            nuclei_entries=nuclei_items,
            screenshots_by_asset=screenshots_by_asset,
        )
    )

    return _dedupe_and_rank(insights)


def _normalize_nuclei_entries(
    nuclei_entries: list[dict[str, Any]] | None,
    nuclei_results: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if isinstance(nuclei_entries, list):
        return [dict(item) for item in nuclei_entries if isinstance(item, dict)]

    if not isinstance(nuclei_results, dict):
        return []

    entries: list[dict[str, Any]] = []
    events: list[Any] = []
    for key in ("findings", "Findings", "results", "Results", "data", "Data"):
        value = nuclei_results.get(key)
        if isinstance(value, list):
            events = value
            break

    for event in events:
        if not isinstance(event, dict):
            continue
        info = event.get("info") if isinstance(event.get("info"), dict) else {}
        entries.append(
            {
                "endpoint": str(
                    event.get("matched-at")
                    or event.get("matchedAt")
                    or event.get("host")
                    or event.get("url")
                    or "unknown"
                ),
                "name": str(info.get("name") or event.get("name") or event.get("template-id") or "Unknown"),
                "severity": _normalize_severity(info.get("severity") or event.get("severity")),
                "template_id": str(event.get("template-id") or event.get("templateID") or event.get("id") or "Unknown"),
                "description": str(info.get("description") or event.get("description") or info.get("impact") or ""),
                "evidence": "",
            }
        )

    if entries:
        return entries

    try:
        for finding in nuclei_to_findings(nuclei_results):
            entries.append(
                {
                    "endpoint": str(getattr(finding, "matched_at", "unknown")),
                    "name": str(getattr(finding, "name", "Unknown")),
                    "severity": _normalize_severity(getattr(finding, "severity", "unknown")),
                    "template_id": str(getattr(finding, "template_id", "Unknown") or "Unknown"),
                    "description": "",
                    "evidence": str(getattr(finding, "evidence", "") or ""),
                }
            )
    except Exception:
        return []
    return entries


def _correlate_technology_with_nuclei(
    *,
    checks_results: dict[str, Any],
    run_context: dict[str, Any],
    nuclei_entries: list[dict[str, Any]],
    screenshots_by_asset: dict[str, list[dict[str, Any]]],
) -> list[CorrelationInsight]:
    if not nuclei_entries:
        return []

    technology_by_asset = _collect_technology_signals(checks_results)
    if not technology_by_asset:
        return []

    insights: list[CorrelationInsight] = []
    for finding in nuclei_entries:
        endpoint = str(finding.get("endpoint") or "").strip()
        asset_key = _asset_key(endpoint)
        if not asset_key or asset_key not in technology_by_asset:
            continue

        tech = technology_by_asset[asset_key]
        labels = sorted(tech.get("labels", set()))
        if not labels:
            continue

        template_text = " ".join(
            str(finding.get(key) or "")
            for key in ("template_id", "name", "description", "evidence")
        ).lower()
        matched_labels = [
            label for label in labels
            if _technology_token_matches(label, template_text)
        ]
        source_names = sorted(set(tech.get("sources", set())) | {"nuclei"})
        live_sources = _live_sources_for_asset(asset_key, run_context, checks_results)
        source_names = sorted(set(source_names) | set(live_sources))
        has_live_evidence = bool(live_sources)
        independent_sources = len(set(source_names))
        has_context_match = bool(matched_labels)
        confidence = _confidence_score(
            base=48 if has_context_match else 42,
            independent_sources=independent_sources,
            has_live_evidence=has_live_evidence,
            has_context_match=has_context_match,
            severity=_normalize_severity(finding.get("severity")),
            cap=92 if has_context_match else 72,
        )
        severity = _normalize_severity(finding.get("severity"))
        asset = _display_asset(endpoint) or _display_asset(tech.get("asset")) or asset_key
        template_id = str(finding.get("template_id") or "Unknown")
        title = (
            "Tespit edilen teknolojiyle eşleşen zafiyet sinyali var"
            if has_context_match
            else "Zafiyet doğrulaması için teknoloji bağlamı mevcut"
        )
        confidence_reason = _confidence_reason(
            confidence,
            [
                f"{independent_sources} bağımsız kanıt kaynağı: {', '.join(source_names)}",
                "canlı endpoint kanıtı mevcut" if has_live_evidence else "ayrı httpx canlı-endpoint kanıtı bulunamadı",
                "teknoloji terimleri Nuclei template/advisory ile uyumlu" if matched_labels else "aynı asset eşleşmesi var, ancak template metninde güçlü teknoloji terimi eşleşmesi yok",
            ],
        )

        insight = CorrelationInsight(
                id=_make_id("technology-nuclei", asset_key, template_id),
                title=title,
                affected_asset=asset,
                finding_type="technology_nuclei_correlation" if has_context_match else "technology_context_nuclei_correlation",
                severity=severity,
                confidence=confidence,
                evidence_sources=source_names,
                evidence_summary=(
                    f"Teknoloji kanıtı ({', '.join(labels[:8])}) ve Nuclei bulgusu "
                    f"{template_id} aynı scheme/host/port üzerinde görüldü. {confidence_reason}"
                ),
                why_it_matters=(
                    "Bir zafiyet sinyali, aynı erişilebilir asset üzerinde gözlenen server, framework "
                    "veya uygulama teknolojisiyle hizalandığında daha anlamlıdır."
                ),
                exploitability_assessment=(
                    "Bu yalnızca gözlenen ürün/version ve template önkoşulları bu endpoint için birlikte "
                    "geçerliyse aksiyona dönüştürülebilir doğrulama kanıtıdır. Confirmed exploitable impact "
                    "olarak ele almadan önce önkoşullar teyit edilmelidir."
                ),
                manual_validation_steps=[
                    "Tespit edilen teknoloji ve version değerini header, sayfa içeriği veya authenticated inventory kaynağından doğrula.",
                    f"{template_id} için Nuclei template/advisory içeriğini incele ve önkoşulların geçerli olup olmadığını kontrol et.",
                    "Kontrolü güvenli, salt-okunur bir doğrulama isteğiyle tekrarla ve beklenen patched davranışla karşılaştır.",
                ],
                false_positive_notes=(
                    "Teknoloji fingerprint ve template eşleşmeleri eski, jenerik veya proxy üzerinden eşleşmiş olabilir. "
                    "Version ve configuration manuel olarak doğrulanmalıdır."
                ),
                recommended_first_action="Etkilenen teknoloji/version değerini doğrula ve Nuclei sinyalini güvenli manuel kontrolle teyit et.",
                related_tools=source_names,
                related_findings=[template_id],
                tags=["technology", "nuclei", severity],
            )
        insights.append(_with_visual_context(insight, screenshots_by_asset.get(asset_key), context="nuclei"))
    return insights


def _correlate_high_severity_nuclei_validation(
    *,
    checks_results: dict[str, Any],
    run_context: dict[str, Any],
    nuclei_entries: list[dict[str, Any]],
    screenshots_by_asset: dict[str, list[dict[str, Any]]],
) -> list[CorrelationInsight]:
    technology_by_asset = _collect_technology_signals(checks_results)
    waf_by_asset = _collect_waf_signals(checks_results)
    insights: list[CorrelationInsight] = []

    for finding in nuclei_entries:
        severity = _normalize_severity(finding.get("severity"))
        if severity not in {"critical", "high"}:
            continue
        endpoint = str(finding.get("endpoint") or "").strip()
        asset_key = _asset_key(endpoint)
        if not asset_key or asset_key in technology_by_asset or asset_key in waf_by_asset:
            continue

        live_sources = _live_sources_for_asset(asset_key, run_context, checks_results)
        source_names = sorted(set(["nuclei"]) | set(live_sources))
        confidence = _confidence_score(
            base=42,
            independent_sources=len(source_names),
            has_live_evidence=bool(live_sources),
            has_context_match=False,
            severity=severity,
            cap=68,
        )
        template_id = str(finding.get("template_id") or "Unknown")
        confidence_reason = _confidence_reason(
            confidence,
            [
                f"{len(source_names)} kanıt kaynağı: {', '.join(source_names)}",
                "canlı endpoint kanıtı mevcut" if live_sources else "bu asset için tek güçlü sinyal Nuclei",
                "bu asset için WhatWeb/web-check teknoloji kanıtı yok",
            ],
        )

        insight = CorrelationInsight(
                id=_make_id("nuclei-validation", asset_key, template_id),
                title="High severity scanner bulgusu doğrulama kuyruğunda",
                affected_asset=_display_asset(endpoint) or asset_key,
                finding_type="nuclei_validation",
                severity=severity,
                confidence=confidence,
                evidence_sources=source_names,
                evidence_summary=f"Nuclei {severity} bulgusu raporladı: {template_id}. {confidence_reason}",
                why_it_matters=(
                    "Destekleyici teknoloji kanıtı eksik olsa bile high-severity scanner sonucu doğrulama "
                    "kuyruğuna girmelidir; gerçek ve erişilebilir bir durumu işaret ediyor olabilir."
                ),
                exploitability_assessment=(
                    "Eşleşen teknoloji/version veya WAF bağlamı olmadan bu sinyal, "
                    "confirmed exploitability yerine doğrulanmamış scanner sinyali olarak ele alınmalıdır."
                ),
                manual_validation_steps=[
                    "Eşleşen endpoint’i aç ve beklenen ortamda scope içinde, erişilebilir olduğunu doğrula.",
                    f"{template_id} için Nuclei template/advisory içeriğini oku ve gerekli vulnerable önkoşulları listele.",
                    "Remediation önceliklendirmesi öncesinde bu önkoşulların varlığını güvenli salt-okunur kontrolle doğrula.",
                ],
                false_positive_notes=(
                    "Tek başına Nuclei eşleşmeleri jenerik response pattern, redirect, cache’lenmiş sayfa veya shared infrastructure kaynaklı olabilir."
                ),
                recommended_first_action="Escalation öncesinde Nuclei sinyalini manuel doğrula ve eksik teknoloji/version kanıtını topla.",
                related_tools=source_names,
                related_findings=[template_id],
                tags=["nuclei", "manual-validation", severity],
            )
        insights.append(_with_visual_context(insight, screenshots_by_asset.get(asset_key), context="nuclei"))
    return insights


def _correlate_waf_with_nuclei(
    *,
    checks_results: dict[str, Any],
    run_context: dict[str, Any],
    nuclei_entries: list[dict[str, Any]],
    screenshots_by_asset: dict[str, list[dict[str, Any]]],
) -> list[CorrelationInsight]:
    waf_by_asset = _collect_waf_signals(checks_results)
    if not waf_by_asset or not nuclei_entries:
        return []

    insights: list[CorrelationInsight] = []
    for finding in nuclei_entries:
        severity = _normalize_severity(finding.get("severity"))
        if severity not in {"critical", "high"}:
            continue
        endpoint = str(finding.get("endpoint") or "").strip()
        asset_key = _asset_key(endpoint)
        waf = waf_by_asset.get(asset_key)
        if not waf or waf.get("detected") is True:
            continue

        explicit_absence = waf.get("detected") is False
        live_sources = _live_sources_for_asset(asset_key, run_context, checks_results)
        source_names = sorted(set(["wafw00f", "nuclei"]) | set(live_sources))
        confidence = _confidence_score(
            base=58 if explicit_absence else 50,
            independent_sources=len(source_names),
            has_live_evidence=bool(live_sources),
            has_context_match=explicit_absence,
            severity=severity,
            cap=88,
        )
        asset = _display_asset(endpoint) or _display_asset(waf.get("asset")) or asset_key
        template_id = str(finding.get("template_id") or "Unknown")
        confidence_reason = _confidence_reason(
            confidence,
            [
                f"{len(source_names)} bağımsız kanıt kaynağı: {', '.join(source_names)}",
                "WAFW00F açıkça WAF yok raporladı" if explicit_absence else "WAF koruması confirmed absent değil, belirsiz görünüyor",
                f"Nuclei severity: {severity}",
            ],
        )

        insight = CorrelationInsight(
                id=_make_id("waf-nuclei", asset_key, template_id),
                title="High severity bulgu net WAF koruması olmadan erişilebilir görünüyor",
                affected_asset=asset,
                finding_type="waf_nuclei_correlation",
                severity=severity,
                confidence=confidence,
                evidence_sources=source_names,
                evidence_summary=(
                    f"WAFW00F bu asset için net WAF raporlamadı; aynı sırada Nuclei "
                    f"{severity} bulgusu raporladı: {template_id}. {confidence_reason}"
                ),
                why_it_matters=(
                    "Doğrudan erişilebilir web yüzeyindeki high severity sinyal, WAF/CDN katmanı tespit edilmediğinde "
                    "daha az görünür compensating control ile değerlendirilir."
                ),
                exploitability_assessment=(
                    "Birleşik sinyal doğrulama önceliğini artırır, ancak WAF yokluğu "
                    "exploitability kanıtı değildir ve Nuclei koşulu güvenli biçimde yeniden üretilmelidir."
                ),
                manual_validation_steps=[
                    "Nuclei bulgusunu ve etkilenen endpoint davranışını scope içinde teyit et.",
                    "WAFW00F görünürlüğü dışında upstream CDN, reverse proxy, IP allowlist veya application-layer control olup olmadığını kontrol et.",
                    "Geçici exposure kontrolleri uygulamadan önce log ve sahipliği incele.",
                ],
                false_positive_notes=(
                    "WAFW00F özel korumaları veya upstream kontrolleri kaçırabilir; Nuclei severity template’e bağlı olabilir."
                ),
                recommended_first_action=(
                    "Bulguyu manuel doğrula; remediation planlanırken geçici erişim kısıtı veya compensating control değerlendir."
                ),
                related_tools=source_names,
                related_findings=[template_id],
                tags=["waf", "nuclei", "exposure", severity],
            )
        insights.append(_with_visual_context(insight, screenshots_by_asset.get(asset_key), context="nuclei"))
    return insights


def _correlate_auth_surfaces(
    *,
    target: str,
    gobuster_results: dict[str, Any],
    katana_urls: list[str],
    checks_results: dict[str, Any],
    run_context: dict[str, Any],
    screenshots_by_asset: dict[str, list[dict[str, Any]]],
) -> list[CorrelationInsight]:
    surface_by_asset: dict[str, dict[str, Any]] = {}

    def add(url: Any, source: str) -> None:
        text = str(url or "").strip()
        if not text or not _is_auth_surface(text):
            return
        key = _asset_key(text) or _asset_key(target) or "unknown"
        bucket = surface_by_asset.setdefault(
            key,
            {"asset": _display_asset(text) or _display_asset(target) or key, "urls": set(), "sources": set()},
        )
        bucket["urls"].add(_display_url(text, target))
        bucket["sources"].add(source)

    classified = checks_results.get("classified_endpoints") if isinstance(checks_results.get("classified_endpoints"), dict) else {}
    for bucket_name in ("admin_like", "auth_like"):
        for value in classified.get(bucket_name, []) if isinstance(classified.get(bucket_name), list) else []:
            add(value, "checks")

    for value in checks_results.get("login_pages", []) if isinstance(checks_results.get("login_pages"), list) else []:
        add(value.get("url") if isinstance(value, dict) else value, "checks")

    for base_url, results in gobuster_results.items():
        if not isinstance(results, list):
            continue
        for item in results:
            if not isinstance(item, dict):
                continue
            add(item.get("url") or _join_url(str(base_url), item.get("path")), "gobuster")

    for url in katana_urls:
        add(url, "katana")

    data = run_context.get("data") if isinstance(run_context.get("data"), dict) else {}
    for url in _extract_http_live_urls(data):
        add(url, "httpx")

    insights: list[CorrelationInsight] = []
    for asset_key, bucket in surface_by_asset.items():
        urls = sorted(bucket.get("urls", set()))
        if not urls:
            continue
        sources = sorted(bucket.get("sources", set()))
        confidence = _confidence_score(
            base=28,
            independent_sources=len(sources),
            has_live_evidence=bool({"httpx", "checks"} & set(sources)),
            has_context_match=any(_is_admin_marker(url) for url in urls),
            severity="low",
            cap=66,
        )
        severity = "medium" if any(_is_admin_marker(url) for url in urls) and len(sources) >= 2 else "low"
        confidence_reason = _confidence_reason(
            confidence,
            [
                f"{len(sources)} discovery kaynağı: {', '.join(sources)}",
                f"URL normalizasyonundan sonra {len(urls)} auth/admin benzeri path",
                "yalnızca yüzey keyword sinyali; bu endpoint ile eşleşen zafiyet template’i yok",
            ],
        )
        preview = ", ".join(urls[:5])
        if len(urls) > 5:
            preview += f" (+{len(urls) - 5} ek)"

        insight = CorrelationInsight(
                id=_make_id("auth-surface", asset_key, str(len(urls))),
                title="Olası authentication yüzeyi keşfedildi",
                affected_asset=str(bucket.get("asset") or asset_key),
                finding_type="login_admin_surface",
                severity=severity,
                confidence=confidence,
                evidence_sources=sources,
                evidence_summary=f"Authentication veya administration benzeri path’ler keşfedildi: {preview}. {confidence_reason}",
                why_it_matters=(
                    "Login ve admin yüzeyleri normal uygulama özellikleridir; ancak access control, session handling, "
                    "default exposure ve rate limiting incelemesinin nerede yapılacağını gösterir."
                ),
                exploitability_assessment=(
                    "Bu tek başına zafiyet değil, yüzey göstergesidir. Yalnızca endpoint amaçlanmamışsa, yanlış ortamda "
                    "exposed ise, beklenen access control eksikse veya uygun hardening kontrolleri yoksa güvenlik açısından önem kazanır."
                ),
                manual_validation_steps=[
                    "Endpoint’in bu ortam için public olmasının amaçlanıp amaçlanmadığını doğrula.",
                    "Access control gereksinimlerini ve default exposure varsayımlarını uygulama sahibiyle incele.",
                    "Rate limiting, lockout davranışı, CSRF koruması ve güvenli hata yönetimi gibi görünür hardening kontrollerini kontrol et.",
                ],
                false_positive_notes=(
                    "Path keyword’leri normal kullanıcı login sayfalarını, redirect’leri veya decoy route’ları yakalayabilir. "
                    "Bunu tek başına security finding olarak ele alma."
                ),
                recommended_first_action="Keşfedilen auth/admin yüzeyleri için access control incelemesi ve default exposure kontrolü yap.",
                related_tools=sources,
                related_findings=urls[:10],
                tags=["auth-surface", "access-control", severity],
            )
        insights.append(_with_visual_context(insight, screenshots_by_asset.get(asset_key), context="auth"))
    return insights


def _correlate_services_with_http_surface(
    *,
    target: str,
    nmap_output: str,
    checks_results: dict[str, Any],
    run_context: dict[str, Any],
) -> list[CorrelationInsight]:
    open_services = _parse_nmap_open_services(nmap_output)
    if not open_services:
        return []

    data = run_context.get("data") if isinstance(run_context.get("data"), dict) else {}
    http_surfaces = _extract_http_live_urls(data)
    http_surfaces.extend(_extract_web_surface_urls(checks_results))
    if target:
        http_surfaces.append(target)
    http_surfaces = sorted({url for url in http_surfaces if _asset_key(url)})
    if not http_surfaces:
        return []

    services_by_asset: dict[str, list[dict[str, str]]] = {}
    fallback_key = _asset_key(target)
    for service in open_services:
        key = _asset_key(service.get("host")) or fallback_key or "unknown"
        services_by_asset.setdefault(key, []).append(service)

    http_keys = {_host_key(url) for url in http_surfaces if _host_key(url)}
    insights: list[CorrelationInsight] = []
    for asset_key, services in services_by_asset.items():
        if _host_key(asset_key) not in http_keys:
            continue
        non_http = [
            service for service in services
            if str(service.get("service") or "").lower() not in {"http", "https", "ssl/http", "http-proxy"}
        ]
        http_services = [
            service for service in services
            if str(service.get("service") or "").lower() in {"http", "https", "ssl/http", "http-proxy"}
        ]
        if not non_http or not (http_services or http_keys):
            continue

        service_labels = [
            f"{svc.get('port')}/{svc.get('proto')} {svc.get('service')}".strip()
            for svc in services
        ]
        severity = "medium" if len(services) >= 3 or _has_sensitive_service(non_http) else "low"
        confidence = _confidence_score(
            base=42,
            independent_sources=2,
            has_live_evidence=True,
            has_context_match=bool(http_services),
            severity=severity,
            cap=78,
        )
        display_asset = _display_asset(next(iter(http_surfaces), "")) or asset_key
        confidence_reason = _confidence_reason(
            confidence,
            [
                "2 kanıt kaynağı türü: nmap service inventory ve erişilebilir HTTP yüzeyi",
                f"aynı host üzerinde {len(services)} açık service",
                "HTTP yanında non-HTTP service mevcut" if non_http else "yalnızca HTTP service kanıtı",
            ],
        )

        insights.append(
            CorrelationInsight(
                id=_make_id("service-http", asset_key, str(len(services))),
                title="Host birden fazla erişilebilir service sunuyor",
                affected_asset=display_asset,
                finding_type="service_http_surface",
                severity=severity,
                confidence=confidence,
                evidence_sources=["nmap", "httpx" if _extract_http_live_urls(data) else "web_checks"],
                evidence_summary=(
                    f"Nmap açık service’ler buldu ({', '.join(service_labels[:8])}) ve aynı host üzerinde erişilebilir HTTP yüzeyi var. "
                    f"{confidence_reason}"
                ),
                why_it_matters=(
                    "Birden fazla erişilebilir service, dışarıdan incelenebilir attack surface miktarını artırır ve gereksiz "
                    "veya yanlış yapılandırılmış service varsa cross-service exposure path oluşturabilir."
                ),
                exploitability_assessment=(
                    "Bu otomatik zafiyet değil, attack-surface genişlemesidir. Service beklenmiyorsa, policy’ye aykırı biçimde "
                    "externally exposed ise, administrative ise veya unsupported software çalıştırıyorsa önceliği artar."
                ),
                manual_validation_steps=[
                    "Asset rolü için hangi açık service’lerin gerekli olduğunu doğrula.",
                    "Network exposure durumunu hedef ortam ve firewall policy ile karşılaştırarak doğrula.",
                    "Remediation planlamadan önce non-HTTP service’lerde version ve sahipliği kontrol et.",
                ],
                false_positive_notes=(
                    "Nmap service adları jenerik veya banner kaynaklı olabilir; service sahipleri ve güncel inventory ile doğrula."
                ),
                recommended_first_action="Gereksiz service’leri doğrula ve gerekli olmayan noktalarda exposure azalt.",
                related_tools=["nmap", "httpx" if _extract_http_live_urls(data) else "web_checks"],
                related_findings=service_labels,
                tags=["attack-surface", "nmap", "http-surface", severity],
            )
        )
    return insights


def _correlate_historical_urls(
    *,
    checks_results: dict[str, Any],
    nuclei_entries: list[dict[str, Any]],
    screenshots_by_asset: dict[str, list[dict[str, Any]]],
) -> list[CorrelationInsight]:
    historical = checks_results.get("historical_urls") if isinstance(checks_results.get("historical_urls"), dict) else {}
    if not historical:
        return []

    live_records = [
        item for item in historical.get("records", [])
        if isinstance(item, dict) and item.get("live") and _asset_key(item.get("url"))
    ]
    if not live_records:
        return []

    insights: list[CorrelationInsight] = []
    records_by_asset: dict[str, list[dict[str, Any]]] = {}
    for item in live_records:
        records_by_asset.setdefault(_asset_key(item.get("url")), []).append(item)

    for asset_key, records in sorted(records_by_asset.items()):
        source_names = _historical_sources(records, include=("httpx",))
        confidence = _confidence_score(
            base=32,
            independent_sources=len(source_names),
            has_live_evidence=True,
            has_context_match=len(source_names) >= 3,
            severity="low",
            cap=76,
        )
        sample_urls = _historical_sample_urls(records)
        source_summary = f"{len(source_names)} kanıt kaynağı: {', '.join(source_names)}"
        insight = CorrelationInsight(
                id=_make_id("historical-live", asset_key, str(len(records))),
                title="Historical endpoint hâlâ erişilebilir",
                affected_asset=_display_asset(sample_urls[0]) or asset_key,
                finding_type="historical_url_live",
                severity="low",
                confidence=confidence,
                evidence_sources=source_names,
                evidence_summary=(
                    f"Aynı scheme/host/port için {len(records)} normalize historical URL canlı probing sırasında yanıt verdi. "
                    f"{_confidence_reason(confidence, [source_summary, 'httpx canlı kanıtı erişilebilirliği doğruladı', 'archive varlığı tek başına zafiyet kanıtı sayılmaz'])}"
                ),
                why_it_matters=(
                    "Archived URL’ler hâlâ dışarıdan erişilebilir eski route’ları gösterebilir. Değeri inventory ve exposure review içindir; "
                    "otomatik zafiyet kanıtı değildir."
                ),
                exploitability_assessment=(
                    "Reachability yalnızca endpoint’in şu anda yanıt verdiği anlamına gelir. Etki; route’un amaçlanıp amaçlanmadığına, "
                    "mevcut uygulamaya ait olup olmadığına ve manuel inceleme sonrası sensitive behavior veya data sunup sunmadığına bağlıdır."
                ),
                manual_validation_steps=[
                    "Canlı historical URL’i aç ve mevcut in-scope uygulamaya ait olduğunu doğrula.",
                    "Route’un dokümante edilmiş, kasıtlı exposed ve normal access-control beklentileri kapsamında olup olmadığını kontrol et.",
                    "Aktif içeriği placeholder veya CDN davranışından ayırmak için redirect ve response status değerlerini incele.",
                ],
                false_positive_notes=(
                    "Archive araçları eski, üçüncü taraf veya redirected URL döndürebilir. Canlı response hâlâ jenerik redirect, static placeholder veya CDN edge response olabilir."
                ),
                recommended_first_action="Erişilebilir historical route’lar için amaçlanan exposure ve sahipliği doğrula.",
                related_tools=source_names,
                related_findings=sample_urls[:5],
                tags=["historical-url", "live", "exposure-review"],
            )
        insights.append(_with_visual_context(insight, screenshots_by_asset.get(asset_key), context="historical"))

    category_titles = {
        "auth_surface": "Historical authentication yüzeyi hâlâ erişilebilir",
        "api_surface": "Historical API endpoint hâlâ erişilebilir",
        "file_exposure_candidate": "Sensitive görünümlü historical dosya path’i hâlâ erişilebilir",
        "legacy_or_hidden_path": "Historical legacy veya gizli görünümlü path hâlâ erişilebilir",
        "parameterized_endpoint": "Historical parametreli endpoint hâlâ erişilebilir",
        "upload_surface": "Historical upload yüzeyi hâlâ erişilebilir",
    }
    category_severity = {
        "auth_surface": "low",
        "api_surface": "medium",
        "file_exposure_candidate": "medium",
        "legacy_or_hidden_path": "medium",
        "parameterized_endpoint": "low",
        "upload_surface": "medium",
    }
    category_action = {
        "auth_surface": "Canlı route için access control beklentilerini, default exposure ve rate-limit kapsamını incele.",
        "api_surface": "API sahipliğini, authentication gereksinimlerini ve endpoint’in hâlâ public olmasının amaçlanıp amaçlanmadığını doğrula.",
        "file_exposure_candidate": "Response’un gerçek backup/configuration içeriği açığa çıkarıp çıkarmadığını güvenli biçimde doğrula; ardından amaçlanmamış dosyaları kaldır veya kısıtla.",
        "legacy_or_hidden_path": "Route’un güncel, sahipli ve kasıtlı exposed olup olmadığını doğrula; eski path’leri emekliye ayır veya kısıtla.",
        "parameterized_endpoint": "Daha derin manuel doğrulamaya eklemeden önce parameter handling ve sahipliği incele.",
        "upload_surface": "Upload/import kısıtlarını, authentication durumunu ve kabul edilen dosya işleme davranışını güvenli non-destructive kontrollerle doğrula.",
    }

    category_records: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in live_records:
        categories = item.get("categories") if isinstance(item.get("categories"), list) else []
        for category in categories:
            category = str(category or "").strip()
            if category in category_titles:
                category_records.setdefault((_asset_key(item.get("url")), category), []).append(item)

    for (asset_key, category), records in sorted(category_records.items()):
        source_names = _historical_sources(records, include=("httpx",))
        sample_urls = _historical_sample_urls(records)
        severity = category_severity.get(category, "low")
        if category == "file_exposure_candidate" and any(
            marker in url.lower()
            for url in sample_urls
            for marker in (".env", ".sql", ".bak", "backup", "dump")
        ):
            severity = "high"
        confidence = _confidence_score(
            base=38,
            independent_sources=len(source_names),
            has_live_evidence=True,
            has_context_match=len(records) > 1 or len(source_names) >= 3,
            severity=severity,
            cap=82,
        )
        source_summary = f"{len(source_names)} kanıt kaynağı: {', '.join(source_names)}"
        insight = CorrelationInsight(
                id=_make_id("historical-category", asset_key, category),
                title=category_titles[category],
                affected_asset=_display_asset(sample_urls[0]) or asset_key,
                finding_type=f"historical_{category}",
                severity=severity,
                confidence=confidence,
                evidence_sources=source_names,
                evidence_summary=(
                    f"Aynı scheme/host/port üzerinde {len(records)} canlı historical URL {category} classifier ile eşleşti. "
                    f"{_confidence_reason(confidence, [source_summary, 'httpx canlı kanıtı erişilebilirliği doğruladı', 'sınıflandırma keyword tabanlıdır; operatör teyidi gerekir'])}"
                ),
                why_it_matters=(
                    "Geçmişte keşfedilmiş ve hâlâ yanıt veren route incelenmelidir; eski veya gizli path’ler normal inventory, monitoring "
                    "ve access-control kontrollerinin dışında kalabilir."
                ),
                exploitability_assessment=(
                    "Bu confirmed exploitability değil, önceliklendirme sinyalidir. Endpoint yalnızca manuel inceleme unintended exposure, "
                    "sensitive content, zayıf access control veya unsafe behavior doğrularsa güvenlik konusuna dönüşür."
                ),
                manual_validation_steps=[
                    "URL’i normal browser veya güvenli salt-okunur HTTP client ile iste ve status, redirect ve content type değerlerini kaydet.",
                    "Route sahibini ve path’in mevcut ortamda erişilebilir olmasının beklenip beklenmediğini doğrula.",
                    "Sensitive görünümlü dosyalar veya legacy path’ler için bulk data indirmeden veya state değiştirmeden içeriği doğrula.",
                ],
                false_positive_notes=(
                    "Keyword sınıflandırması benign path, redirect, marketing sayfası veya placeholder ile eşleşebilir. Archive kaynağı ve canlı response birlikte kontrol edilmelidir."
                ),
                recommended_first_action=category_action[category],
                related_tools=source_names,
                related_findings=sample_urls[:5],
                tags=["historical-url", category, severity],
            )
        insights.append(_with_visual_context(insight, screenshots_by_asset.get(asset_key), context="historical"))

    high_nuclei_by_asset: dict[str, list[dict[str, Any]]] = {}
    for finding in nuclei_entries:
        severity = _normalize_severity(finding.get("severity"))
        if severity not in {"critical", "high"}:
            continue
        asset_key = _asset_key(finding.get("endpoint"))
        if asset_key:
            high_nuclei_by_asset.setdefault(asset_key, []).append(finding)

    for asset_key, records in sorted(records_by_asset.items()):
        nuclei_for_asset = high_nuclei_by_asset.get(asset_key) or []
        if not nuclei_for_asset:
            continue
        source_names = _historical_sources(records, include=("httpx", "nuclei"))
        top_severity = max(
            (_normalize_severity(item.get("severity")) for item in nuclei_for_asset),
            key=lambda value: SEVERITY_ORDER.get(value, 0),
            default="high",
        )
        confidence = _confidence_score(
            base=44,
            independent_sources=len(source_names),
            has_live_evidence=True,
            has_context_match=True,
            severity=top_severity,
            cap=84,
        )
        sample_urls = _historical_sample_urls(records)
        template_ids = [str(item.get("template_id") or item.get("name") or "Unknown") for item in nuclei_for_asset]
        source_summary = f"{len(source_names)} kanıt kaynağı: {', '.join(source_names)}"
        insight = CorrelationInsight(
                id=_make_id("historical-nuclei", asset_key, ",".join(template_ids[:3])),
                title="Historical exposure ve high severity bulgu aynı asset üzerinde",
                affected_asset=_display_asset(sample_urls[0]) or asset_key,
                finding_type="historical_url_nuclei_correlation",
                severity=top_severity,
                confidence=confidence,
                evidence_sources=source_names,
                evidence_summary=(
                    f"Aynı scheme/host/port üzerinde {len(records)} canlı historical URL ve high-priority Nuclei sinyali var: {', '.join(template_ids[:5])}. "
                    f"{_confidence_reason(confidence, [source_summary, 'historical URL canlılığı ve Nuclei kanıtı aynı base asset üzerinde', 'path seviyesinde kanıt olmadan nedensellik varsayılmaz'])}"
                ),
                why_it_matters=(
                    "Bu, exposure genişliği ile aynı asset üzerindeki ayrı zafiyet sinyalini birleştirir; asset’i daha güçlü manuel inceleme adayı yapar."
                ),
                exploitability_assessment=(
                    "Historical endpoint ve Nuclei bulgusu aynı asset üzerindeki ilgisiz path’ler olabilir; archive URL’in zafiyete neden olduğunu veya zafiyeti kanıtladığını varsayma."
                ),
                manual_validation_steps=[
                    "Nuclei bulgusunun endpoint’ini, template önkoşullarını ve eşleşen koşulun yeniden üretilebilir olup olmadığını doğrula.",
                    "Aynı asset üzerindeki canlı historical URL’leri amaçlanan sahiplik ve access-control kapsamı açısından incele.",
                    "İki bulguyu yalnızca path seviyesinde davranış veya shared component kanıtı ilişkiyi destekliyorsa bağla.",
                ],
                false_positive_notes=(
                    "Aynı-asset korelasyonu ilgisiz path’leri fazla önceliklendirebilir. Manuel kanıt route veya component’leri bağlayana kadar triyaj bağlamı olarak ele al."
                ),
                recommended_first_action="High-severity Nuclei sinyalini manuel doğrula; ardından exposure reduction için aynı asset üzerindeki canlı historical route’ları incele.",
                related_tools=source_names,
                related_findings=[*template_ids[:5], *sample_urls[:3]],
                tags=["historical-url", "nuclei", top_severity],
            )
        insights.append(_with_visual_context(insight, screenshots_by_asset.get(asset_key), context="nuclei"))

    return insights


def _historical_sources(records: list[dict[str, Any]], *, include: tuple[str, ...] = ()) -> list[str]:
    sources: set[str] = set(include)
    for item in records:
        values = item.get("sources") if isinstance(item.get("sources"), list) else []
        for value in values:
            text = str(value or "").strip()
            if text:
                sources.add(text)
    return sorted(sources)


def _historical_sample_urls(records: list[dict[str, Any]]) -> list[str]:
    urls: list[str] = []
    for item in records:
        url = str(item.get("url") or "").strip()
        if url and url not in urls:
            urls.append(url)
    return urls or ["-"]


def _collect_technology_signals(checks_results: dict[str, Any]) -> dict[str, dict[str, Any]]:
    by_asset: dict[str, dict[str, Any]] = {}

    def add(asset: Any, labels: list[str], source: str) -> None:
        key = _asset_key(asset)
        if not key:
            return
        bucket = by_asset.setdefault(key, {"asset": _display_asset(asset) or key, "labels": set(), "sources": set()})
        for label in labels:
            text = str(label or "").strip()
            if text:
                bucket["labels"].add(text)
        if source:
            bucket["sources"].add(source)

    for item in checks_results.get("technology_fingerprint", []) if isinstance(checks_results.get("technology_fingerprint"), list) else []:
        if not isinstance(item, dict):
            continue
        labels: list[str] = []
        labels.extend(str(x) for x in (item.get("technologies") or []) if str(x or "").strip())
        if item.get("server"):
            labels.append(str(item.get("server")))
        if item.get("x_powered_by"):
            labels.append(str(item.get("x_powered_by")))
        source = str(item.get("source_type") or "web_checks")
        add(item.get("site"), labels, source)

    whatweb = checks_results.get("whatweb_signals") if isinstance(checks_results.get("whatweb_signals"), dict) else {}
    for base_url, item in whatweb.items():
        if not isinstance(item, dict):
            continue
        labels = [str(x) for x in (item.get("plugin_names") or []) if str(x or "").strip()]
        for entry in item.get("entries", []) if isinstance(item.get("entries"), list) else []:
            if not isinstance(entry, dict):
                continue
            for plugin in entry.get("plugins", []) if isinstance(entry.get("plugins"), list) else []:
                if not isinstance(plugin, dict):
                    continue
                name = str(plugin.get("name") or "").strip()
                version = str(plugin.get("version") or "").strip()
                string = str(plugin.get("string") or "").strip()
                if name and version:
                    labels.append(f"{name} {version}")
                elif name:
                    labels.append(name)
                if string:
                    labels.append(string)
        add(item.get("target") or base_url, labels, "whatweb")

    return by_asset


def _collect_waf_signals(checks_results: dict[str, Any]) -> dict[str, dict[str, Any]]:
    by_asset: dict[str, dict[str, Any]] = {}
    waf_signals = checks_results.get("waf_signals") if isinstance(checks_results.get("waf_signals"), dict) else {}
    for base_url, item in waf_signals.items():
        if not isinstance(item, dict):
            continue
        key = _asset_key(item.get("target") or base_url)
        if not key:
            continue
        detected = item.get("detected")
        raw = str(item.get("raw_output") or "").lower()
        if detected is None and "no waf detected" in raw:
            detected = False
        by_asset[key] = {
            "asset": _display_asset(item.get("target") or base_url) or key,
            "detected": detected,
            "vendor": item.get("vendor"),
        }
    return by_asset


def _collect_screenshot_signals(
    checks_results: dict[str, Any],
    run_context: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    screenshots = checks_results.get("screenshots") if isinstance(checks_results.get("screenshots"), dict) else {}
    if not screenshots:
        data = run_context.get("data") if isinstance(run_context.get("data"), dict) else {}
        screenshots = data.get("screenshots") if isinstance(data.get("screenshots"), dict) else {}
    entries = screenshots.get("entries") if isinstance(screenshots.get("entries"), list) else []

    by_asset: dict[str, list[dict[str, Any]]] = {}
    for item in entries:
        if not isinstance(item, dict):
            continue
        screenshot_path = str(item.get("screenshot_path") or "").strip()
        if not screenshot_path:
            continue
        url = str(item.get("url") or "").strip()
        key = _asset_key(url)
        if not key:
            continue
        by_asset.setdefault(key, []).append(item)
    return by_asset


def _with_visual_context(
    insight: CorrelationInsight,
    screenshots: list[dict[str, Any]] | None,
    *,
    context: str,
) -> CorrelationInsight:
    if not screenshots:
        return insight

    refs = [
        str(item.get("screenshot_path") or item.get("url") or "").strip()
        for item in screenshots[:3]
        if isinstance(item, dict) and str(item.get("screenshot_path") or item.get("url") or "").strip()
    ]
    if not refs:
        return insight

    source_set = sorted(set([*insight.evidence_sources, "screenshot/gowitness"]))
    related = list(insight.related_findings)
    for ref in refs:
        if ref not in related:
            related.append(ref)

    if context == "auth":
        summary_tail = " Exposed sayfanın incelenmesi için gowitness görsel kanıtı mevcut."
        action = "Görsel screenshot’ı destekleyici bağlam olarak kullanarak amaçlanan exposure, access control ve rate limiting durumunu incele."
        confidence = min(90, int(insight.confidence or 0) + 4)
        tags = sorted(set([*insight.tags, "visual-evidence"]))
    elif context == "historical":
        summary_tail = " Manuel triyajı hızlandırmak için gowitness screenshot mevcut."
        action = insight.recommended_first_action
        confidence = min(90, int(insight.confidence or 0) + 3)
        tags = sorted(set([*insight.tags, "visual-evidence"]))
    else:
        summary_tail = " Aynı asset üzerinde manuel doğrulama için görsel bağlam mevcut; severity değişmedi."
        action = insight.recommended_first_action
        confidence = int(insight.confidence or 0)
        tags = sorted(set([*insight.tags, "visual-evidence"]))

    return replace(
        insight,
        confidence=confidence,
        evidence_sources=source_set,
        evidence_summary=f"{insight.evidence_summary}{summary_tail}",
        recommended_first_action=action,
        related_findings=related[:12],
        tags=tags,
    )


def _extract_http_live_urls(data: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for key in ("httpx_results", "httpx", "httpx_output"):
        value = data.get(key)
        if isinstance(value, dict):
            for list_key in ("live_urls", "urls", "results"):
                values = value.get(list_key)
                if isinstance(values, list):
                    urls.extend(str(x) for x in values if str(x or "").strip())
        elif isinstance(value, list):
            urls.extend(str(x) for x in value if str(x or "").strip())
    return urls


def _extract_web_surface_urls(checks_results: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for item in checks_results.get("technology_fingerprint", []) if isinstance(checks_results.get("technology_fingerprint"), list) else []:
        if isinstance(item, dict) and item.get("site"):
            urls.append(str(item.get("site")))
    for source_key in ("whatweb_signals", "waf_signals"):
        source = checks_results.get(source_key) if isinstance(checks_results.get(source_key), dict) else {}
        for base_url, item in source.items():
            if isinstance(item, dict):
                urls.append(str(item.get("target") or base_url))
            else:
                urls.append(str(base_url))
    return urls


def _live_sources_for_asset(
    asset_key: str,
    run_context: dict[str, Any],
    checks_results: dict[str, Any],
) -> list[str]:
    sources: set[str] = set()
    data = run_context.get("data") if isinstance(run_context.get("data"), dict) else {}

    for url in _extract_http_live_urls(data):
        if _asset_key(url) == asset_key:
            sources.add("httpx")

    for url in _extract_web_surface_urls(checks_results):
        if _asset_key(url) == asset_key:
            sources.add("web_checks")

    return sorted(sources)


def _confidence_score(
    *,
    base: int,
    independent_sources: int,
    has_live_evidence: bool,
    has_context_match: bool,
    severity: str,
    cap: int,
) -> int:
    score = int(base)
    score += max(0, min(4, independent_sources)) * 8
    if has_live_evidence:
        score += 8
    if has_context_match:
        score += 10
    if _normalize_severity(severity) in {"critical", "high"} and independent_sources >= 2:
        score += 4
    return max(15, min(int(cap), score))


def _confidence_reason(confidence: int, factors: list[str]) -> str:
    if confidence >= 75:
        band = "high"
    elif confidence >= 50:
        band = "medium"
    else:
        band = "low"
    clean_factors = [str(factor or "").strip() for factor in factors if str(factor or "").strip()]
    return f"Confidence {band} ({confidence}/100); neden: " + "; ".join(clean_factors[:4]) + "."


def _parse_nmap_open_services(nmap_output: str) -> list[dict[str, str]]:
    services: list[dict[str, str]] = []
    current_host = ""
    for raw_line in str(nmap_output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        host_match = re.match(r"Nmap scan report for\s+(.+)$", line, flags=re.I)
        if host_match:
            current_host = host_match.group(1).strip()
            paren_match = re.search(r"\(([^)]+)\)", current_host)
            if paren_match:
                current_host = current_host[: paren_match.start()].strip() or paren_match.group(1).strip()
            continue
        service_match = re.match(r"^(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line, flags=re.I)
        if not service_match:
            continue
        services.append(
            {
                "host": current_host,
                "port": service_match.group(1),
                "proto": service_match.group(2).lower(),
                "service": service_match.group(3).lower(),
                "version": (service_match.group(4) or "").strip(),
            }
        )
    return services


def _dedupe_and_rank(insights: list[CorrelationInsight]) -> list[CorrelationInsight]:
    deduped: dict[str, CorrelationInsight] = {}
    for insight in insights:
        if insight.id not in deduped:
            deduped[insight.id] = insight
    return sorted(
        deduped.values(),
        key=lambda item: (
            SEVERITY_ORDER.get(_normalize_severity(item.severity), 0),
            int(item.confidence or 0),
            item.title.lower(),
        ),
        reverse=True,
    )


def _asset_key(value: Any) -> str:
    text = str(value or "").strip()
    if not text or text.lower() == "unknown":
        return ""
    if "://" not in text and "/" not in text and not text.startswith("["):
        return text.lower().strip("[]")
    parsed = urlparse(text if "://" in text else f"http://{text.lstrip('/')}")
    host = (parsed.hostname or parsed.netloc or "").lower().strip("[]")
    if not host:
        return ""
    scheme = (parsed.scheme or "").lower()
    if scheme in {"http", "https"}:
        port = parsed.port or (443 if scheme == "https" else 80)
        return f"{scheme}://{host}:{port}"
    if parsed.port:
        return f"{host}:{parsed.port}"
    return host


def _host_key(value: Any) -> str:
    key = _asset_key(value)
    if "://" in key:
        parsed = urlparse(key)
        return (parsed.hostname or "").lower().strip("[]")
    if key.startswith("[") and "]" in key:
        return key.strip("[]")
    if key.count(":") == 1:
        host, maybe_port = key.rsplit(":", 1)
        if maybe_port.isdigit():
            return host
    return key


def _display_asset(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else f"http://{text.lstrip('/')}")
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return text


def _display_url(value: str, target: str = "") -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        return text
    if text.startswith("/") and target:
        return _join_url(_display_asset(target), text)
    return text


def _join_url(base_url: str, path: Any) -> str:
    base = str(base_url or "").rstrip("/")
    suffix = str(path or "").strip()
    if not suffix:
        return base
    if suffix.startswith(("http://", "https://")):
        return suffix
    return f"{base}/{suffix.lstrip('/')}" if base else suffix


def _normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in SEVERITY_ORDER else "unknown"


def _make_id(prefix: str, *parts: str) -> str:
    raw = "-".join([prefix, *[str(part or "") for part in parts]])
    slug = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
    return slug[:120] or prefix


def _technology_token_matches(label: str, text: str) -> bool:
    normalized = re.sub(r"[^a-z0-9.+-]+", " ", str(label or "").lower()).strip()
    if not normalized or not text:
        return False
    tokens = [token for token in normalized.split() if len(token) >= 3]
    aliases = {
        "apache": ("apache", "httpd"),
        "php": ("php",),
        "nginx": ("nginx",),
        "wordpress": ("wordpress", "wp-"),
        "drupal": ("drupal",),
        "joomla": ("joomla",),
    }
    for token in tokens:
        for alias in aliases.get(token, (token,)):
            if alias in text:
                return True
    return False


def _is_public_content_context_url(value: str) -> bool:
    low = str(value or "").lower()
    path = urlparse(low).path or low
    if any(marker in path for marker in PUBLIC_CONTENT_PATH_MARKERS):
        return True
    if path.endswith(".html") and not any(
        marker in path
        for marker in (
            "/admin",
            "/administrator",
            "/manage",
            "/management",
            "/console",
            "/cpanel",
            "/control-panel",
            "/login",
            "/signin",
            "/auth",
        )
    ):
        slug = path.rsplit("/", 1)[-1]
        return bool("-" in slug or "_" in slug)
    return False


def _dashboard_has_admin_context(value: str) -> bool:
    low = str(value or "").lower()
    parsed = urlparse(low)
    path = parsed.path or low
    query = parsed.query or ""
    strong_markers = (
        "/admin",
        "/administrator",
        "/manage",
        "/management",
        "/console",
        "/cpanel",
        "/control-panel",
        "/wp-admin",
        "/phpmyadmin",
        "phpmyadmin",
        "pma",
        "backend",
        "restricted",
        "unauthorized",
        "forbidden",
        "noindex",
    )
    dashboard_admin_paths = (
        "/dashboard/login",
        "/dashboard/admin",
        "/dashboard/users",
        "/dashboard/settings",
        "/dashboard/roles",
        "/dashboard/export",
    )
    auth_context = ("/login", "/signin", "/auth", "login=", "redirect_to=", "reauth=")
    return (
        any(marker in low for marker in strong_markers)
        or any(marker in path for marker in dashboard_admin_paths)
        or any(marker in low or marker in query for marker in auth_context)
    )


def _is_auth_surface(value: str) -> bool:
    low = str(value or "").lower()
    if _is_public_content_context_url(low):
        return False
    return any(marker in low for marker in AUTH_SURFACE_MARKERS)


def _is_admin_marker(value: str) -> bool:
    low = str(value or "").lower()
    if _is_public_content_context_url(low):
        return False
    if "dashboard" in low and not _dashboard_has_admin_context(low):
        return False
    return any(marker in low for marker in ("admin", "dashboard", "wp-admin", "phpmyadmin", "cpanel", "manager"))


def _has_sensitive_service(services: list[dict[str, str]]) -> bool:
    sensitive = {"ssh", "ftp", "telnet", "rdp", "smb", "microsoft-ds", "mysql", "postgresql", "redis", "mongodb"}
    return any(str(service.get("service") or "").lower() in sensitive for service in services)
