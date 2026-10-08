from __future__ import annotations

from html import escape
from typing import Any


def _html_escape(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


DISPLAY_STATUS_LABELS: dict[str, str] = {
    "completed": "Tamamlandı",
    "completed_matched": "Tamamlandı - eşleşme var",
    "completed_no_match": "Eşleşme yok",
    "completed_zero": "Tamamlandı - kayıt yok",
    "checked_successfully": "Başarıyla kontrol edildi",
    "ok": "Başarılı",
    "slow": "Yavaş",
    "no_match": "Eşleşme yok",
    "alias_not_found": "Eşleşme yok",
    "disabled": "Kapalı",
    "installed_but_disabled": "Kurulu ama kapalı",
    "not_configured": "Açık ama yapılandırılmamış",
    "invalid_config": "Geçersiz ayar",
    "partial": "Kısmi",
    "timeout": "Zaman aşımı",
    "auth_required": "Kimlik doğrulama gerekli",
    "auth_required_fallback": "Kimlik doğrulama gerekli; manuel öneriler üretildi",
    "rate_limited": "Oran limiti",
    "rate_limited_fallback": "Oran limiti; manuel öneriler üretildi",
    "provider_unavailable": "Sağlayıcıya erişilemedi",
    "unavailable": "Kaynağa erişilemedi",
    "suggestions_generated": "Manuel öneriler üretildi",
    "suggestion_only": "Sadece manuel öneri",
    "fallback_only": "Sadece manuel öneri",
    "manual_only": "Sadece manuel işlem",
    "not_implemented": "Henüz uygulanmadı",
    "not_supported": "Desteklenmiyor",
    "skipped": "Atlandı",
    "source_failures": "Kaynak hataları var",
    "observed_evidence": "Gözlemlenmiş kanıt var",
    "no_observed_evidence": "Gözlemlenmiş aktif kanıt yok",
    "not_checked": "Kontrol edilmedi",
    "error": "Kaynak hatası",
    "valid": "Geçerli",
    "unknown": "Bilinmiyor",
    "checked_ok": "Başarıyla kontrol edildi",
    "checked_redirect": "Yönlendirildi",
    "checked_redirect_valid": "Geçerli yönlendirme",
    "checked_official_affiliate_redirect": "Geçerli affiliate yönlendirme",
    "checked_not_found": "Bulunamadı",
    "checked_soft_error": "Soft-error sayfası reddedildi",
    "checked_unexpected_content": "Beklenmeyen içerik",
    "checked_duplicate": "Tekrarlı canonical URL",
    "checked_forbidden": "Erişim yasak",
    "tls_error": "TLS hatası",
    "connection_error": "Bağlantı hatası",
    "api_key_missing": "API key gerekli",
    "generated_candidate": "Üretilmiş aday",
    "archived_not_live_checked": "Arşivlenmiş; canlı kontrol edilmedi",
    "present": "Mevcut",
    "absent": "Yok",
    "resolver_error": "Resolver hatası",
    "dependency_missing": "Bağımlılık eksik",
}


SOURCE_DISPLAY: dict[str, dict[str, str]] = {
    "certificate_transparency": {
        "title": "crt.sh sertifika şeffaflığı kaynağı",
        "meaning": "Herkese açık sertifika kayıtlarından hedefe ait isimler için pasif metadata kontrolü.",
    },
    "historical_urls": {
        "title": "Wayback geçmiş URL kaynağı",
        "meaning": "Wayback CDX üzerinden geçmiş URL metadata kontrolü; canlı URL doğrulaması değildir.",
    },
    "public_code_search": {
        "title": "GitHub public code search",
        "meaning": "GitHub public code search metadata kontrolü; repo klonlama, dosya indirme veya secret doğrulama yapılmaz.",
    },
    "known_breach_catalog": {
        "title": "Herkese açık ihlal kataloğu",
        "meaning": "HIBP-style herkese açık ihlal kataloğu metadata kontrolü; kimlik bilgisi veya dump toplanmaz.",
    },
    "leak_metadata_feed": {
        "title": "Metadata-only sızıntı feed'i",
        "meaning": "Sağlayıcı registry ile sınırlandırılmış güvenilir metadata feed'i; ham sızıntı kaydı toplanmaz.",
    },
    "safe_search_dorks": {
        "title": "Manuel arama önerileri",
        "meaning": "Operatörün manuel bakacağı arama linkleri; doğrulanmış kanıt veya bulgu değildir.",
    },
}

CATEGORY_LABELS: dict[str, str] = {
    "ct": "CT",
    "archive": "Arşiv",
    "code_search": "Kod arama",
    "breach_metadata": "İhlal metadata",
    "manual_suggestions": "Manuel öneriler",
    "entity_intelligence": "Organizasyon",
    "infrastructure": "Altyapı",
}

COVERAGE_IMPACT_LABELS: dict[str, str] = {
    "none": "Yok",
    "low": "Düşük",
    "medium": "Orta",
    "high": "Yüksek",
}


RECOMMENDED_ACTION_LABELS: dict[str, str] = {
    "Manually validate organization relevance; do not collect credentials.": "Kurumla gerçekten ilişkili olup olmadığını manuel doğrula; kimlik bilgisi toplama.",
    "Review the public breach catalog page and validate organization relevance manually; do not collect credentials.": "Herkese açık ihlal kataloğu sayfasını incele ve kurumla ilişkisini manuel doğrula; kimlik bilgisi toplama.",
    "manual relevance review": "Kurumla gerçekten ilişkili olup olmadığını manuel doğrula; kimlik bilgisi toplama.",
    "No action required.": "Ek aksiyon gerekmiyor.",
    "Configure provider settings.": "Sağlayıcı ayarlarını yapılandır.",
}


DATA_CLASS_LABELS: dict[str, str] = {
    "Dates of birth": "Doğum tarihleri",
    "Email addresses": "E-posta adresleri",
    "Names": "İsimler",
    "Phone numbers": "Telefon numaraları",
    "Physical addresses": "Fiziksel adresler",
    "Passwords": "Parolalar",
    "Usernames": "Kullanıcı adları",
    "IP addresses": "IP adresleri",
    "Geographic locations": "Coğrafi konumlar",
    "Job titles": "İş unvanları",
    "Social media profiles": "Sosyal medya profilleri",
}


DISPLAY_TEXT_LABELS: dict[str, str] = {
    "Breach catalog name matches a generated organization alias.": "İhlal kataloğundaki ad, ReconBot'un ürettiği kurum alias'ı ile eşleşiyor.",
    "Breach catalog name closely matches generated organization alias.": "İhlal kataloğundaki ad, ReconBot'un ürettiği kurum alias'ı ile yakın eşleşiyor.",
    "Public third-party breach metadata may describe a parent brand, historical incident, subsidiary, or unrelated organization with a similar name.": "Üçüncü taraf herkese açık ihlal metadata'sı üst marka, tarihsel olay, iştirak veya benzer adlı alakasız bir kurumu anlatıyor olabilir.",
    "Public third-party breach metadata requires manual relevance validation.": "Üçüncü taraf herkese açık ihlal metadata'sı için kurum ilişkisi manuel doğrulanmalıdır.",
    "Metadata-only external reference; relevance to the exact target must be reviewed manually.": "Sadece-metadata dış referans; tam hedefle ilişkisi manuel incelenmelidir.",
    "ReconBot did not collect credentials, passwords, hashes, tokens, private keys, session cookies, raw dumps, or raw leaked records. Leak-source results are metadata-only and require manual relevance validation.": "ReconBot kimlik bilgisi, parola, hash, token, private key, session cookie, raw dump veya ham sızıntı kaydı toplamadı. Sızıntı kaynaklarından gelen sonuçlar sadece metadata'dır ve kurumla ilişkisi manuel doğrulanmalıdır.",
    "ReconBot did not collect credentials, passwords, hashes, tokens, private keys, session cookies, raw dumps, or raw leaked records.": "ReconBot kimlik bilgisi, parola, hash, token, private key, session cookie, raw dump veya ham sızıntı kaydı toplamadı.",
    "custom_https_metadata_feed accepts only complete https:// feedUrl values.": "custom_https_metadata_feed yalnızca tam https:// feedUrl değerlerini kabul eder.",
    "Provider profile is a placeholder; no live provider integration is implemented.": "Sağlayıcı profili placeholder durumunda; canlı sağlayıcı entegrasyonu uygulanmadı.",
    "Feed metadata explicitly matched the requested registered domain.": "Metadata feed'i istenen registered domain ile açıkça eşleşti.",
    "Feed metadata explicitly matched the requested target host.": "Metadata feed'i istenen target host ile açıkça eşleşti.",
    "OSINT coverage is partial: crt.sh unavailable, Wayback timed out, and GitHub code search requires authentication. Absence of evidence is not conclusive.": "OSINT kapsamı kısmi: crt.sh erişilemedi, Wayback zaman aşımına uğradı ve GitHub code search kimlik doğrulama gerektiriyor. Kanıt yokluğu kesin sonuç değildir.",
    "Leak-source results are metadata-only and require manual relevance validation.": "Sızıntı kaynaklarından gelen sonuçlar sadece metadata'dır ve kurumla ilişkisi manuel doğrulanmalıdır.",
    "Generated safe operator-run search suggestions only.": "Yalnızca operatörün manuel çalıştıracağı güvenli arama önerileri üretildi.",
    "Passive public sources produced 1 observed evidence item(s). Manual search tasks are suggestions only and do not affect risk score.": "Pasif public kaynaklarda 1 gözlemlenmiş kanıt bulundu. Manuel arama görevleri sadece öneridir ve risk skorunu etkilemez.",
    "Manual search tasks are suggestions only and do not affect risk score.": "Manuel arama görevleri sadece öneridir ve risk skorunu etkilemez.",
    "No local ASN database was available; passive lookup links were generated.": "Yerel ASN veritabanı bulunamadı; pasif lookup linkleri üretildi.",
    "This IP may represent CDN/proxy/edge infrastructure and may not be the target origin.": "Bu IP CDN/proxy/edge altyapısına ait olabilir; hedefin gerçek origin sunucusu olmayabilir.",
    "Infrastructure enrichment is passive DNS/metadata context only; it is not exposure evidence.": "Altyapı zenginleştirmesi yalnızca pasif DNS/metadata bağlamıdır; maruziyet kanıtı değildir.",
    "Wayback CDX timed out; absence of historical URLs is not conclusive.": "Wayback CDX zaman aşımına uğradı; geçmiş URL bulunmaması kesin olarak yok anlamına gelmez.",
    "GitHub live code search requires authentication; manual search suggestions generated.": "GitHub canlı kod araması kimlik doğrulama gerektiriyor; bu yüzden manuel arama önerileri üretildi.",
    "crt.sh unavailable during this run; CT coverage is partial.": "Bu çalıştırmada crt.sh erişilemedi; Certificate Transparency kapsamı kısmi kaldı.",
    "GitHub live code search requires authentication or was not authorized; manual search tasks generated.": "GitHub canlı kod araması kimlik doğrulama gerektiriyor veya yetkilendirilmedi. Bu yüzden manuel arama önerileri üretildi.",
    "Wayback CDX source unavailable/slow from this environment. This does not prove absence of historical URLs.": "Wayback CDX bu ortamda erişilemedi veya yavaş kaldı. Bu, geçmiş URL olmadığı anlamına gelmez.",
    "No public breach/leak metadata reference was observed from the known breach catalog.": "Herkese açık ihlal kataloğunda eşleşen sızıntı/ihlal metadata referansı görülmedi.",
    "Metadata-only public breach catalog adapter.": "Metadata-only herkese açık ihlal kataloğu adaptörü.",
    "No credential material, raw dumps, or leaked records were collected.": "Kimlik bilgisi, raw dump veya ham sızıntı kaydı toplanmadı.",
    "not evidence; validation context only": "kanıt değil; yalnızca doğrulama bağlamı",
    "manual location search shortcut, not verified office": "Manuel konum arama kısayolu; doğrulanmış ofis değil.",
    "Maps search may return local results unrelated to headquarters or target infrastructure.": "Maps araması genel merkez veya hedef altyapıyla ilgisiz yerel sonuçlar döndürebilir.",
    "No verified official office/location was observed unless listed under official location hints.": "Resmî konum ipuçları altında listelenmedikçe doğrulanmış resmî ofis/konum gözlemlenmedi.",
    "Manuel pasif arama kısayolu; bulgu değil. API key gerekli veya manuel pasif arama; API kanıtı toplanmadı.": "Manuel pasif arama kısayolu; bulgu değildir. API key gerekli veya manuel pasif arama; API kanıtı toplanmadı.",
}


MANUAL_LOOKUP_LABELS: dict[str, str] = {
    "Open Shodan host lookup": "Shodan host aramasını aç",
    "Open Censys host lookup": "Censys host aramasını aç",
    "Open urlscan IP search": "urlscan IP aramasını aç",
    "Open SecurityTrails DNS lookup": "SecurityTrails DNS aramasını aç",
    "Manual fallback": "Manuel öneri",
    "Open Crunchbase company search": "Crunchbase şirket aramasını aç",
    "Open GitHub organization search": "GitHub organizasyon aramasını aç",
    "Open Twitter/X search": "Twitter/X aramasını aç",
    "Open Facebook page search": "Facebook sayfa aramasını aç",
    "Open YouTube search": "YouTube aramasını aç",
    "Open Google official company profile search": "Google resmî şirket profili aramasını aç",
    "Crunchbase company search": "Crunchbase şirket aramasını aç",
    "GitHub organization search": "GitHub organizasyon aramasını aç",
    "Twitter/X search": "Twitter/X aramasını aç",
    "Facebook page search": "Facebook sayfa aramasını aç",
    "YouTube search": "YouTube aramasını aç",
    "Google official company profile search": "Google resmî şirket profili aramasını aç",
    "Google company leadership search": "Google şirket liderliği aramasını aç",
    "Open GitHub direct organization candidate": "GitHub doğrudan organizasyon adayını aç",
    "Open LinkedIn company search": "LinkedIn şirket aramasını aç",
    "Open Google Maps search": "Google Maps aramasını aç",
    "Open crt.sh browser search": "crt.sh tarayıcı aramasını aç",
    "Open Wayback browser search": "Wayback tarayıcı aramasını aç",
    "Open GitHub .env search": "GitHub .env aramasını aç",
    "Open GitHub config search": "GitHub config aramasını aç",
    "Open Google Swagger search": "Google Swagger aramasını aç",
    "Open Google API docs search": "Google API docs aramasını aç",
    "Google config search": "Google config aramasını aç",
    "Google document search": "Google doküman aramasını aç",
    "Google search": "Google aramasını aç",
    "Open Google PDF search": "Google PDF aramasını aç",
    "Open Google email-pattern search": "Google e-posta pattern aramasını aç",
    "Open evidence report": "Kanıt raporunu aç",
    "View details": "Detayları gör",
    "Open passive lookup": "Pasif lookup aramasını aç",
    "Open public document search": "Herkese açık doküman aramasını aç",
    "Open profile": "Profili aç",
}


RUNTIME_MESSAGE_LABELS: dict[str, str] = {
    "Metadata feed collector disabled because metadataFeed.enabled=false.": "Metadata feed sağlayıcısı metadataFeed.enabled=false olduğu için kapalı.",
    "Metadata feed collector enabled=true but no feedPath/feedUrl was configured.": "Metadata feed açık ama feedPath/feedUrl yapılandırılmamış.",
    "Metadata feed URL must be a complete https:// URL.": "Metadata feed URL'i eksiksiz bir https:// URL olmalıdır.",
    "Metadata feed API key environment variable is missing.": "Metadata feed API key ortam değişkeni eksik.",
    "Metadata feed request timed out.": "Metadata feed isteği zaman aşımına uğradı.",
    "Metadata feed endpoint was unavailable.": "Metadata feed endpoint'ine erişilemedi.",
    "Metadata feed could not be parsed as safe JSON metadata.": "Metadata feed güvenli JSON metadata olarak okunamadı.",
    "Provider registry validation passed.": "Sağlayıcı registry doğrulaması başarılı.",
    "Provider profile is valid; metadataFeed.enabled=false.": "Sağlayıcı profili geçerli; metadataFeed.enabled=false.",
    "Provider profile is a placeholder; no live provider integration is implemented.": "Sağlayıcı profili placeholder; canlı entegrasyon henüz uygulanmadı.",
    "No public breach/leak metadata reference was observed from the known breach catalog.": "Herkese açık ihlal kataloğunda eşleşen sızıntı/ihlal metadata referansı görülmedi.",
    "Metadata-only public breach catalog adapter.": "Metadata-only herkese açık ihlal kataloğu adaptörü.",
    "No credential material, raw dumps, or leaked records were collected.": "Kimlik bilgisi, raw dump veya ham sızıntı kaydı toplanmadı.",
}


def _display_status_label(status: Any) -> str:
    status_text = str(status or "").strip()
    return DISPLAY_STATUS_LABELS.get(status_text, status_text or DISPLAY_STATUS_LABELS["unknown"])


def _coverage_impact_label(value: Any) -> str:
    impact = str(value or "").strip()
    return COVERAGE_IMPACT_LABELS.get(impact, impact or "-")


def _display_recommended_action(action: Any) -> str:
    action_text = str(action or "").strip()
    return RECOMMENDED_ACTION_LABELS.get(action_text, action_text)


def _display_text(text: Any) -> str:
    value = str(text or "").strip()
    if not value:
        return ""
    if value in DISPLAY_TEXT_LABELS:
        return DISPLAY_TEXT_LABELS[value]
    translated = value
    for source, target in DISPLAY_TEXT_LABELS.items():
        translated = translated.replace(source, target)
    return translated


def _display_data_class(value: Any) -> str:
    text = str(value or "").strip()
    return DATA_CLASS_LABELS.get(text, text)


def _display_data_classes(values: Any) -> str:
    if isinstance(values, str):
        parts = [part.strip() for part in values.split(",") if part.strip()]
    else:
        parts = [str(value).strip() for value in _as_list(values) if str(value or "").strip()]
    return ", ".join(_display_data_class(part) for part in parts)


def _display_manual_lookup_label(label: Any, *, url_role: Any = "", url: Any = "") -> str:
    text = str(label or "").strip()
    if text in MANUAL_LOOKUP_LABELS:
        return MANUAL_LOOKUP_LABELS[text]
    if text.startswith("Open location lookup:"):
        return text.replace("Open location lookup:", "Konum aramasını aç:", 1)
    if text.startswith("Open public document search:"):
        return text.replace("Open public document search:", "Herkese açık doküman aramasını aç:", 1)
    url_role_text = str(url_role or "").strip()
    url_text = str(url or "").lower()
    if "shodan.io" in url_text:
        return "Shodan host aramasını aç"
    if "censys.io" in url_text:
        return "Censys host aramasını aç"
    if "urlscan.io" in url_text:
        return "urlscan IP aramasını aç"
    if "securitytrails.com" in url_text:
        return "SecurityTrails DNS aramasını aç"
    if "linkedin.com" in url_text:
        return "LinkedIn şirket aramasını aç"
    if "google.com/maps" in url_text or "maps.google." in url_text:
        return "Google Maps aramasını aç"
    if url_role_text in {"passive_infrastructure_lookup", "organization_lookup_shortcut", "manual_search_suggestion"} and text.startswith("Open "):
        return text.replace("Open ", "").replace(" lookup", " aramasını aç")
    return text or "Linki aç"


def _display_breach_reference_sentence(item: dict[str, Any]) -> str:
    breach_name = str(item.get("breach_name") or item.get("title") or item.get("name") or "Bilinmeyen ihlal").strip()
    breach_date = str(item.get("breach_date") or item.get("published_at") or item.get("added_date") or "-").strip()
    affected = str(item.get("affected_accounts") or "-").strip()
    data_classes = _display_data_classes(item.get("compromised_data_classes") or item.get("data_classes"))
    return (
        f"Herkese açık ihlal kataloğunda {breach_name} için metadata referansı görüldü. "
        f"İhlal tarihi: {breach_date}. Etkilenen hesap: {affected}. "
        f"Veri sınıfları: {data_classes or '-'}."
    )


def _display_reference_snippet(reference: dict[str, Any]) -> str:
    snippet = str(reference.get("redacted_snippet") or _as_dict(reference.get("evidence")).get("snippet") or "").strip()
    if snippet.startswith("Public breach catalog reference found:"):
        return _display_breach_reference_sentence(reference)
    return _display_text(snippet)


def _display_runtime_message(message: Any) -> str:
    text = str(message or "").strip()
    if not text:
        return ""
    if text in DISPLAY_TEXT_LABELS:
        return DISPLAY_TEXT_LABELS[text]
    if text in RUNTIME_MESSAGE_LABELS:
        return RUNTIME_MESSAGE_LABELS[text]
    if text.startswith("Metadata feed ") and " loaded " in text and "matched" in text:
        return text.replace("Metadata feed", "Metadata feed").replace("loaded", "yüklendi:").replace("matched", "eşleşen").replace("suppressed", "bastırılan")
    if text.startswith("Metadata feed returned HTTP "):
        return text.replace("Metadata feed returned", "Metadata feed HTTP yanıtı")
    if text.startswith("Unknown metadata feed providerId:"):
        return "Bilinmeyen metadata feed providerId değeri. Ağ veya dosya erişimi yapılmadı."
    if text.startswith("Unsafe provider profile rejected:"):
        return "Güvensiz provider profili reddedildi. Ağ veya dosya erişimi yapılmadı."
    if "does not support source mode" in text:
        return "Provider seçilen kaynak modunu desteklemiyor. Ağ veya dosya erişimi yapılmadı."
    if "accepts only" in text or "requires feed" in text:
        return "Provider ayarı geçersiz. Ağ veya dosya erişimi yapılmadı."
    return _display_text(text)


def _display_bool(value: Any) -> str:
    if value is None:
        return "-"
    return "Evet" if bool(value) else "Hayır"


def _is_browser_safe_osint_url(url: str) -> bool:
    from urllib.parse import urlsplit

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


_NON_ACTIONABLE_URL_STATUSES = {
    "checked_not_found",
    "checked_soft_error",
    "checked_unexpected_content",
    "checked_duplicate",
    "timeout",
    "connection_error",
    "tls_error",
}


def _render_clickable(item: dict[str, Any], url: str, *, role: str, status: str = "not_checked") -> bool:
    if "render_as_clickable" in item:
        return bool(item.get("render_as_clickable"))
    if not _is_browser_safe_osint_url(url):
        return False
    if str(status or "") in _NON_ACTIONABLE_URL_STATUSES:
        return False
    if role in {"observed_evidence_link", "source_report_link"}:
        return status == "validated"
    return role in {
        "manual_search_suggestion",
        "passive_infrastructure_lookup",
        "passive_lookup_shortcut",
        "official_page",
        "security_txt",
        "validated_public_document",
        "observed_official_social_profile",
        "official_observed_location",
        "organization_lookup_shortcut",
        "public_document_search",
        "location_lookup_shortcut",
        "people_lookup_shortcut",
    }


def _source_detail_id(source_name: str) -> str:
    mapping = {
        "certificate_transparency": "osint-source-certificate-transparency",
        "historical_urls": "osint-source-historical-urls",
        "public_code_search": "osint-source-public-code-search",
        "known_breach_catalog": "osint-source-known-breach-catalog",
        "safe_search_dorks": "osint-source-safe-search-dorks",
    }
    normalized = str(source_name or "").strip()
    return mapping.get(normalized, "osint-source-unknown")


def _signal_entities(signal: dict[str, Any]) -> str:
    entities = _as_dict(signal.get("matched_entities"))
    parts: list[str] = []
    for key in ("subdomains", "urls", "keywords", "file_names", "domains"):
        values = [str(item) for item in _as_list(entities.get(key)) if str(item or "").strip()]
        if values:
            parts.append(f"{key}: {', '.join(values[:3])}")
    return " | ".join(parts)


def _snippet(signal: dict[str, Any]) -> str:
    evidence = _as_dict(signal.get("evidence"))
    return str(evidence.get("snippet") or "")


def _status_tone(status: str, *, source_name: str = "", notes: str = "", errors: list[Any] | None = None) -> str:
    status = str(status or "")
    error_text = " ".join(str(error) for error in (errors or []) if str(error or "").strip()).lower()
    notes_text = str(notes or "").lower()
    if status in {"completed", "completed_matched"}:
        return "ok"
    if status in {"no_match", "completed_no_match", "completed_zero", "alias_not_found"}:
        return "muted"
    if status in {"partial", "auth_required_fallback", "rate_limited_fallback", "timeout", "unavailable"}:
        return "warn"
    if status in {"invalid_config", "not_implemented"}:
        return "bad"
    if status == "error":
        if source_name == "historical_urls" and (
            "timeout" in error_text
            or "timeout" in notes_text
            or "unavailable/slow" in notes_text
            or "urlerror" in error_text
        ):
            return "warn"
        return "bad"
    return "muted"


def _status_label(status: Any, *, source_name: str = "", notes: str = "", errors: list[Any] | None = None) -> str:
    status_text = str(status or "")
    error_text = " ".join(str(error) for error in (errors or []) if str(error or "").strip()).lower()
    notes_text = str(notes or "").lower()
    if status_text == "completed":
        return _display_status_label("completed")
    if status_text == "completed_matched":
        return _display_status_label("completed_matched")
    if status_text in {"no_match", "completed_no_match", "completed_zero", "alias_not_found"}:
        return _display_status_label("no_match")
    if status_text == "auth_required_fallback":
        return _display_status_label("auth_required_fallback")
    if status_text == "rate_limited_fallback":
        return _display_status_label("rate_limited_fallback")
    if status_text == "partial":
        return _display_status_label("partial")
    if status_text == "timeout":
        return _display_status_label("timeout")
    if status_text == "unavailable":
        return _display_status_label("unavailable")
    if status_text == "error" and source_name == "historical_urls" and (
        "timeout" in error_text
        or "timeout" in notes_text
        or "unavailable/slow" in notes_text
        or "urlerror" in error_text
    ):
        return "Kaynak bu ortamdan yavaş veya erişilemez"
    if status_text == "error" and ("timeout" in error_text or "timeout" in notes_text):
        return "Hata / zaman aşımı"
    return _display_status_label(status_text)


def _plain_status_label(status: Any) -> str:
    mapping = {
        "completed": "Başarıyla kontrol edildi",
        "completed_matched": "Eşleşen public metadata bulundu",
        "completed_no_match": "Eşleşme yok",
        "no_match": "Eşleşme yok",
        "completed_zero": "Tamamlandı; kayıt yok",
        "alias_not_found": "Eşleşme yok",
        "disabled": "Kapalı",
        "not_configured": "Açık ama yapılandırılmamış",
        "auth_required_fallback": "Canlı API kimlik doğrulama gerektiriyor; manuel öneriler üretildi",
        "rate_limited_fallback": "Canlı API rate-limit aldı; manuel öneriler üretildi",
        "suggestions_generated": "Manuel öneriler üretildi",
        "suggestion_only": "Sadece manuel öneri",
        "manual_only": "Sadece manuel işlem; doğrulanmış kanıt değil",
        "checked_duplicate": "Tekrarlı/canonical URL bastırıldı",
        "checked_soft_error": "Soft-error sayfası reddedildi",
        "checked_not_found": "Kontrol edildi; sayfa bulunamadı",
        "checked_unexpected_content": "Kontrol edildi; beklenen public sayfa içeriği yok",
        "timeout": "Zaman aşımı",
        "unavailable": "Kaynağa erişilemedi",
        "provider_unavailable": "Sağlayıcıya erişilemedi",
        "invalid_config": "Geçersiz ayar",
        "not_implemented": "Henüz uygulanmadı",
        "partial": "Kısmi",
        "error": "Kaynak hatası",
        "skipped": "Atlandı",
    }
    return mapping.get(str(status or ""), _display_status_label(status))


def _finding_status(count: int, *, checked: bool = True, partial: bool = False, disabled: bool = False, fallback_only: bool = False) -> str:
    if disabled:
        return _display_status_label("disabled")
    if fallback_only:
        return _display_status_label("fallback_only")
    if partial:
        return _display_status_label("partial")
    if count > 0:
        return "Bulundu"
    return "Bulunmadı" if checked else _display_status_label("not_checked")


def _provider_display_name(provider: Any) -> str:
    provider_name = str(provider or "").strip()
    if provider_name == "crtsh":
        return "crt.sh"
    return provider_name or "unknown"


def _provider_details(item: dict[str, Any]) -> str:
    providers = _as_list(item.get("provider_results"))
    details: list[str] = []
    for provider in providers:
        if not isinstance(provider, dict):
            continue
        errors = provider.get("errors") if isinstance(provider.get("errors"), list) else []
        error_text = "; ".join(str(error) for error in errors if str(error or "").strip())
        details.append(
            " ".join(
                part
                for part in (
                    f"{_provider_display_name(provider.get('provider'))}:",
                    f"status={_status_label(provider.get('status'), errors=errors, notes=str(provider.get('notes') or ''))}",
                    f"raw={provider.get('raw_count', 0)}",
                    f"signals={provider.get('signal_count', 0)}",
                    f"asset_identity={provider.get('asset_identity_count', 0)}",
                    f"asset_discovery={provider.get('asset_discovery_count', 0)}" if provider.get("asset_discovery_count") is not None else "",
                    f"errors={_display_runtime_message(error_text)}" if error_text else "",
                )
                if str(part or "").strip()
            )
        )
    return " | ".join(details)


def _ct_provider_health_html(sources: list[Any]) -> str:
    source = next(
        (
            item
            for item in sources
            if isinstance(item, dict) and str(item.get("name") or "") == "certificate_transparency"
        ),
        None,
    )
    if not isinstance(source, dict):
        return ""
    providers = [item for item in _as_list(source.get("provider_results")) if isinstance(item, dict)]
    if not providers:
        return ""
    rows: list[str] = []
    for provider in providers:
        errors = provider.get("errors") if isinstance(provider.get("errors"), list) else []
        error_text = "; ".join(str(error) for error in errors if str(error or "").strip())
        notes = str(provider.get("notes") or "")
        status_label = _status_label(provider.get("status"), errors=errors, notes=notes)
        status_tone = _status_tone(str(provider.get("status") or ""), errors=errors, notes=notes)
        detail_parts = [
            f"sorgu {provider.get('successful_queries', 0)}/{provider.get('queries_attempted', 0)}",
            f"raw {provider.get('raw_count', 0)}",
            f"signals {provider.get('signal_count', 0)}",
            f"asset identity {provider.get('asset_identity_count', 0)}",
            f"asset discovery {provider.get('asset_discovery_count', 0)}",
        ]
        if notes:
            detail_parts.append(_display_runtime_message(notes))
        if error_text:
            detail_parts.append(f"Kaynak hatası: {_display_runtime_message(error_text)}")
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(_provider_display_name(provider.get('provider')))}</code></td>"
            f'<td><span class="pill {status_tone}">{_html_escape(status_label)}</span></td>'
            f"<td>{_html_escape(' | '.join(detail_parts))}</td>"
            f"<td>{_html_escape(provider.get('duration_ms', 0))}</td>"
            "</tr>"
        )
    overall_label = _status_label(source.get("status"), source_name="certificate_transparency", notes=str(source.get("notes") or ""), errors=source.get("errors") if isinstance(source.get("errors"), list) else [])
    return f"""
      <h3>Certificate Transparency Sağlayıcı Sağlığı</h3>
      <p class="operator-view-note"><strong>Genel CT durumu:</strong> {_html_escape(overall_label)}. Sağlayıcı satırları crt.sh ve Cert Spotter davranışını ayrı gösterir.</p>
      <table>
        <tr><th>Sağlayıcı</th><th>Durum</th><th>Sağlayıcı detayı</th><th>Süre ms</th></tr>
        {''.join(rows)}
      </table>
    """


def _source_action_html(item: dict[str, Any], operator_search_tasks: list[Any]) -> str:
    source_name = str(item.get("name") or "")
    detail_id = str(item.get("detail_id") or _source_detail_id(source_name))
    actions: list[str] = []
    evidence_url = _source_observed_evidence_url(item)
    if evidence_url:
        actions.append(
            f'<a href="{_html_escape(evidence_url)}" target="_blank" rel="noopener noreferrer" data-browser-safe="true">Kanıt raporunu aç</a>'
        )
    actions.append(f'<a href="#{_html_escape(detail_id)}">Sağlayıcı teşhislerini görüntüle</a>')
    if _source_has_manual_fallback(item, operator_search_tasks):
        actions.append('<a href="#osint-manual-search-suggestions">Manuel önerileri görüntüle</a>')
    return "<br>".join(actions)


def _source_observed_evidence_url(item: dict[str, Any]) -> str:
    report_url = str(item.get("report_url") or "").strip()
    if not report_url or str(item.get("report_url_status") or "") != "validated":
        return ""
    role = str(item.get("url_role") or "source_report_link")
    browser_safe = bool(item.get("browser_safe")) or role in {"observed_evidence_link", "source_report_link"}
    renderable = bool(item.get("render_as_clickable")) or _render_clickable(item, report_url, role=role, status="validated")
    if browser_safe and renderable and _is_browser_safe_osint_url(report_url):
        return report_url
    return ""


def _source_has_manual_fallback(item: dict[str, Any], operator_search_tasks: list[Any]) -> bool:
    source_name = str(item.get("name") or "")
    if source_name == "safe_search_dorks":
        return True
    if any(isinstance(task, dict) and str(task.get("source_name") or "") == source_name for task in operator_search_tasks):
        return True
    return str(item.get("status") or "") in {"auth_required_fallback", "rate_limited_fallback", "suggestions_generated"}


def _source_action_audit_label(item: dict[str, Any], operator_search_tasks: list[Any]) -> str:
    if _source_observed_evidence_url(item):
        return "Kanıt raporu + teşhis"
    if _source_has_manual_fallback(item, operator_search_tasks):
        return "Manuel öneriler + teşhis"
    endpoint = str(item.get("endpoint_url") or item.get("source_url") or "")
    if endpoint and not bool(item.get("render_as_clickable")):
        return "Makine endpoint'i düz metin + teşhis"
    return "Teşhis"


def _source_action_audit_html(sources: list[Any], operator_search_tasks: list[Any]) -> str:
    rows: list[str] = []
    for item in sources:
        if not isinstance(item, dict):
            continue
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(item.get('name') or 'unknown')}</code></td>"
            f"<td>{_html_escape(_source_action_audit_label(item, operator_search_tasks))}</td>"
            f"<td>{_html_escape('yes' if _source_observed_evidence_url(item) else 'no')}</td>"
            f"<td>{_html_escape('yes' if _source_has_manual_fallback(item, operator_search_tasks) else 'no')}</td>"
            "</tr>"
        )
    return f"""
      <details class="show-more">
        <summary>Rapor aksiyon denetimi ({_html_escape(len(rows))} kaynak)</summary>
        <p class="operator-view-note">Kanıt linkleri, iç teşhisler, manuel öneriler ve makine endpoint'leri kaynak satırlarına basılmadan önce ayrılır.</p>
        <table>
          <tr><th>Kaynak</th><th>Gösterilen aksiyon politikası</th><th>Gözlemlenmiş kanıt URL'i</th><th>Manuel öneri</th></tr>
          {''.join(rows) or '<tr><td colspan="4">Denetlenecek OSINT kaynak satırı yok.</td></tr>'}
        </table>
      </details>
    """


def _source_rows(sources: list[Any], operator_search_tasks: list[Any]) -> str:
    rows: list[str] = []
    for item in sources:
        if not isinstance(item, dict):
            continue
        source_name = str(item.get("name") or "")
        source_label = f"<code>{_html_escape(item.get('name'))}</code>"
        status = str(item.get("status") or "")
        errors = item.get("errors") if isinstance(item.get("errors"), list) else []
        error_text = "; ".join(str(error) for error in errors if str(error or "").strip())
        details = _display_runtime_message(item.get("notes") or "")
        if error_text and "Kaynak hatası:" not in details:
            translated_error = _display_runtime_message(error_text)
            details = f"{details} Kaynak hatası: {translated_error}" if details else f"Kaynak hatası: {translated_error}"
        provider_text = _provider_details(item)
        if provider_text:
            details = f"{details} Sağlayıcılar: {provider_text}" if details else f"Sağlayıcılar: {provider_text}"
        if source_name == "known_breach_catalog":
            validated_report_url = (
                str(item.get("report_url") or "").strip()
                if str(item.get("report_url_status") or "") == "validated"
                else ""
            )
            if validated_report_url:
                evidence_note = "doğrulanmış herkese açık ihlal raporu mevcut"
                details = f"{details} {evidence_note}" if details else evidence_note
            else:
                browser_note = "katalog içeride kontrol edildi; browser-safe katalog URL'i gösterilmedi"
                details = f"{details} {browser_note}" if details else browser_note
            attempts = [
                attempt
                for attempt in _as_list(item.get("alias_attempts"))
                if isinstance(attempt, dict)
            ]
            if attempts:
                preview = "; ".join(
                    f"{attempt.get('alias')} -> {attempt.get('slug')} ({attempt.get('outcome')}, page {attempt.get('page_status')}, api {attempt.get('api_status')})"
                    for attempt in attempts[:6]
                )
                suffix = f"; {len(attempts) - 6} ek deneme" if len(attempts) > 6 else ""
                details = f"{details} Alias denemeleri: {preview}{suffix}" if details else f"Alias denemeleri: {preview}{suffix}"
        rows.append(
            "<tr>"
            f"<td>{source_label}</td>"
            f'<td><span class="pill {_status_tone(status, source_name=str(item.get("name") or ""), notes=details, errors=errors)}">{_html_escape(_status_label(status, source_name=str(item.get("name") or ""), notes=details, errors=errors))}</span><br><span class="muted">{_html_escape(status or "unknown")}</span></td>'
            f"<td>{_html_escape(item.get('signal_count', 0))}</td>"
            f"<td>{_html_escape(item.get('asset_identity_count', 0))}</td>"
            f"<td>{_html_escape(item.get('raw_count', 0))}</td>"
            f"<td>{_html_escape(item.get('suppressed_count', 0))}</td>"
            f"<td>{_html_escape(item.get('duration_ms', 0))}</td>"
            f"<td>{_html_escape(details)}</td>"
            f"<td>{_source_action_html(item, operator_search_tasks)}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="9">Çalıştırılmış OSINT kaynağı yok.</td></tr>'


def _signal_rows(signals: list[Any]) -> str:
    rows: list[str] = []
    for item in signals:
        if not isinstance(item, dict):
            continue
        source_url = str(item.get("source_url") or "").strip()
        source_name = _html_escape(item.get("source_name"))
        if source_url and _render_clickable(item, source_url, role="observed_evidence_link", status=str(item.get("url_status") or "not_checked")):
            source_name = f'<a href="{_html_escape(source_url)}" target="_blank" rel="noopener noreferrer" data-browser-safe="true">{source_name}</a>'
        evidence = _snippet(item) or _signal_entities(item)
        rows.append(
            "<tr>"
            f"<td>{_html_escape(item.get('exposure_priority'))}</td>"
            f"<td><code>{_html_escape(item.get('category'))}</code></td>"
            f"<td><strong>{_html_escape(item.get('title'))}</strong><br><span class=\"muted\">{_html_escape(_signal_entities(item))}</span></td>"
            f"<td>{source_name}</td>"
            f"<td>{_html_escape(item.get('confidence'))} ({_html_escape(item.get('confidence_score', 0))})</td>"
            f"<td>{_html_escape(evidence)}</td>"
            f"<td>{_html_escape(_display_recommended_action(item.get('recommended_action')))}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="7">Gözlemlenmiş pasif kaynak kanıtı toplanmadı.</td></tr>'


def _non_breach_signals(signals: list[Any]) -> list[Any]:
    return [
        item
        for item in signals
        if not (isinstance(item, dict) and str(item.get("category") or "") == "known_breach_reference")
    ]


def _known_breach_signals(signals: list[Any]) -> list[Any]:
    return [
        item
        for item in signals
        if isinstance(item, dict) and str(item.get("category") or "") == "known_breach_reference"
    ]


def _asset_identity_rows(observations: list[Any]) -> str:
    rows: list[str] = []
    for item in observations:
        if not isinstance(item, dict):
            continue
        entities = _as_dict(item.get("matched_entities"))
        subdomains = [str(value) for value in _as_list(entities.get("subdomains")) if str(value or "").strip()]
        source_url = str(item.get("source_url") or "").strip()
        provider = str(item.get("source_provider") or item.get("source_name") or "")
        if source_url and _render_clickable(item, source_url, role=str(item.get("url_role") or "source_report_link"), status=str(item.get("url_status") or "not_checked")):
            provider = f'<a href="{_html_escape(source_url)}" target="_blank" rel="noopener noreferrer" data-browser-safe="true">{_html_escape(provider)}</a>'
        else:
            provider = _html_escape(provider)
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(subdomains[0] if subdomains else '')}</code></td>"
            f"<td>{provider}</td>"
            f"<td>{_html_escape(_snippet(item) or _signal_entities(item))}</td>"
            f"<td>{_html_escape(item.get('asset_identity_reason', 'asset_identity_only'))}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="4">Asset identity gözlemi toplanmadı.</td></tr>'


def _ct_asset_row(item: dict[str, Any], *, row_type: str) -> str:
    entities = _as_dict(item.get("matched_entities"))
    subdomains = [str(value) for value in _as_list(entities.get("subdomains")) if str(value or "").strip()]
    provider = str(item.get("source_provider") or item.get("source_name") or "")
    source_url = str(item.get("source_url") or "").strip()
    endpoint = f"<code>{_html_escape(source_url)}</code>" if source_url else "-"
    return (
        "<tr>"
        f"<td>{_html_escape(row_type)}</td>"
        f"<td><code>{_html_escape(subdomains[0] if subdomains else '')}</code></td>"
        f"<td>{_html_escape(provider)}</td>"
        f"<td>{endpoint}<br><span class=\"muted\">API kaynağı; browser kanıt linki değil</span></td>"
        f"<td>{_html_escape(item.get('ct_classification') or item.get('asset_identity_reason') or item.get('asset_discovery_reason') or '')}</td>"
        f"<td>{_html_escape(_snippet(item) or _signal_entities(item))}</td>"
        "</tr>"
    )


def _ct_asset_discovery_html(sources: list[Any], observations: list[Any], candidates: list[Any]) -> str:
    ct_observations = [
        item
        for item in observations
        if isinstance(item, dict) and str(item.get("source_name") or "") == "certificate_transparency"
    ]
    ct_candidates = [
        item
        for item in candidates
        if isinstance(item, dict) and str(item.get("source_name") or "") == "certificate_transparency"
    ]
    source = next(
        (
            item
            for item in sources
            if isinstance(item, dict) and str(item.get("name") or "") == "certificate_transparency"
        ),
        None,
    )
    provider_note = _provider_details(source) if isinstance(source, dict) else ""
    rows = "".join(_ct_asset_row(item, row_type="exact host / asset identity") for item in ct_observations)
    rows += "".join(_ct_asset_row(item, row_type="subdomain adayı") for item in ct_candidates)
    if not rows:
        rows = '<tr><td colspan="6">Certificate Transparency varlık keşfi kaydı toplanmadı.</td></tr>'
    return f"""
      <h3 id="osint-certificate-transparency">Certificate Transparency Varlık Keşfi</h3>
      <p class="operator-view-note"><strong>Sadece pasif CT.</strong> Bu kayıtlar varlık envanteri bağlamıdır; gözlemlenmiş maruziyet kanıtı değildir ve host'un canlı veya zafiyetli olduğunu kanıtlamaz. Makine/API endpoint'leri browser kanıt linki olarak gösterilmez.</p>
      {('<p class="operator-view-note"><strong>Kaynak sağlığı:</strong> ' + _html_escape(provider_note) + '</p>') if provider_note else ''}
      <table>
        <tr><th>Tip</th><th>Varlık</th><th>Sağlayıcı</th><th>Kaynak referansı</th><th>Sınıflandırma</th><th>Kanıt</th></tr>
        {rows}
      </table>
    """


def _source_lookup_link_rows(links: list[Any]) -> str:
    rows: list[str] = []
    for link in links:
        if not isinstance(link, dict):
            continue
        url = str(link.get("url") or "").strip()
        label = _display_manual_lookup_label(link.get("label") or "Browser lookup aramasını aç", url_role=link.get("url_role") or "passive_lookup_shortcut", url=url)
        if url and _render_clickable(link, url, role=str(link.get("url_role") or "passive_lookup_shortcut"), status=str(link.get("url_status") or "not_checked")):
            link_html = f'<a href="{_html_escape(url)}" target="_blank" rel="noopener noreferrer" data-browser-safe="true">{_html_escape(label)}</a>'
        elif url:
            link_html = f"<code>{_html_escape(url)}</code>"
        else:
            link_html = "-"
        rows.append(
            "<tr>"
            f"<td>{link_html}</td>"
            f"<td><code>{_html_escape(link.get('url_role') or 'passive_lookup_shortcut')}</code></td>"
            f"<td>{_html_escape(_display_status_label(link.get('url_status') or 'not_checked'))}<br><span class=\"muted\"><code>{_html_escape(link.get('url_status') or 'not_checked')}</code></span></td>"
            f"<td>{_html_escape(_display_status_label(link.get('status') or 'suggestion_only'))}<br><span class=\"muted\"><code>{_html_escape(link.get('status') or 'suggestion_only')}</code></span></td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="4">Browser-safe kaynak arama kısayolu üretilmedi.</td></tr>'


def _known_breach_detail_note(source: dict[str, Any]) -> str:
    if str(source.get("name") or "") != "known_breach_catalog":
        return ""
    report_url = _source_observed_evidence_url(source)
    if str(source.get("match_status") or "") == "matched" and str(source.get("report_url_status") or "") == "validated" and report_url:
        return f"""
        <div class="operator-view-note">
          <strong>Doğrulanmış herkese açık ihlal raporu</strong><br>
          <a href="{_html_escape(report_url)}" target="_blank" rel="noopener noreferrer" data-browser-safe="true">{_html_escape(report_url)}</a><br>
          Üçüncü taraf herkese açık ihlal kataloğu referansı; aktif zafiyet kanıtı değildir.
        </div>
        """
    if str(source.get("match_status") or "") in {"no_match", ""} or str(source.get("status") or "") in {"completed_no_match", "no_match"}:
        return '<p class="operator-view-note">Katalog kontrol edildi; üretilen alias değerleriyle güvenilir herkese açık ihlal kataloğu referansı eşleşmedi.</p>'
    return ""


def _source_detail_block(source: dict[str, Any], operator_search_tasks: list[Any]) -> str:
    source_name = str(source.get("name") or "")
    detail_id = str(source.get("detail_id") or _source_detail_id(source_name))
    endpoint_url = str(source.get("endpoint_url") or source.get("source_url") or "")
    if source_name == "known_breach_catalog":
        endpoint_url = str(source.get("endpoint_url") or "https://haveibeenpwned.com/api/v3/breaches")
    endpoint_note = "Makine/API endpoint veya teşhis referansı; browser kanıt linki değildir."
    if source_name == "safe_search_dorks":
        endpoint_url = "manual"
        endpoint_note = "Manuel kaynak; tıklanabilir API endpoint'i yok."
    source_tasks = [task for task in operator_search_tasks if isinstance(task, dict) and str(task.get("source_name") or "") == source_name]
    task_note = ""
    if source_name == "public_code_search" and source_tasks:
        task_note = f'<p class="operator-view-note"><a href="#osint-manual-search-suggestions">GitHub manuel arama önerilerini görüntüle</a>. GitHub API endpoint sadece teşhis metni olarak kalır.</p>'
    elif source_name == "safe_search_dorks" and source_tasks:
        task_note = f'<p class="operator-view-note"><a href="#osint-manual-search-suggestions">Manuel arama önerilerini görüntüle</a>. Üretilen dork değerleri suggestion_only kapsamındadır ve bulgu değildir.</p>'
    elif source_name == "known_breach_catalog" and str(source.get("status") or "") in {"completed_no_match", "no_match"}:
        task_note = '<p class="operator-view-note">Katalog kontrol edildi; üretilen alias değerleriyle güvenilir herkese açık ihlal kataloğu referansı eşleşmedi. HIBP API endpointleri tıklanabilir rapor linki değildir.</p>'
    return f"""
      <div class="osint-source-detail" id="{_html_escape(detail_id)}">
        <h4>{_html_escape(source_name or 'unknown source')} detayları</h4>
        <p class="operator-view-note">
          Durum: <code>{_html_escape(source.get('status') or 'unknown')}</code> |
          Endpoint: <code>{_html_escape(endpoint_url or '-')}</code><br>
          {endpoint_note}
        </p>
        {_known_breach_detail_note(source)}
        {task_note}
        <table>
          <tr><th>Browser-safe arama kısayolu</th><th>URL rolü</th><th>URL durumu</th><th>Durum</th></tr>
          {_source_lookup_link_rows(_as_list(source.get('browser_lookup_links')))}
        </table>
      </div>
    """


def _source_details_html(sources: list[Any], operator_search_tasks: list[Any]) -> str:
    blocks = [
        _source_detail_block(source, operator_search_tasks)
        for source in sources
        if isinstance(source, dict)
    ]
    return f"""
      <h3>Sağlayıcı Detayları</h3>
      {''.join(blocks) or '<p class="operator-view-note">Sağlayıcı detay bloğu üretilmedi.</p>'}
    """


def _infrastructure_ownership_rows(rows: list[Any]) -> str:
    html_rows: list[str] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        asn_parts = [
            str(item.get("asn") or "").strip(),
            str(item.get("as_name") or item.get("org") or "").strip(),
            str(item.get("country") or "").strip(),
        ]
        asn_text = " / ".join(part for part in asn_parts if part) or "-"
        html_rows.append(
            "<tr>"
            f"<td><code>{_html_escape(item.get('ip'))}</code><br><span class=\"muted\">IPv{_html_escape(item.get('ip_version') or '')}</span></td>"
            f"<td>{_html_escape(item.get('reverse_dns') or '-')}</td>"
            f"<td>{_html_escape(asn_text)}</td>"
            f"<td>{_html_escape(item.get('provider_guess') or '-')}</td>"
            f'<td><span class="pill muted">{_html_escape(_display_status_label(item.get("enrichment_status") or "unavailable"))}</span><br><span class="muted">Güven: {_html_escape(item.get("confidence") or "low")}</span></td>'
            "</tr>"
        )
    return "".join(html_rows) or '<tr><td colspan="5">IP sahiplik satırı bulunamadı.</td></tr>'


def _infrastructure_lookup_rows(links: list[Any]) -> str:
    rows: list[str] = []
    for item in links:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        label = _display_manual_lookup_label(item.get("label") or "Open passive lookup", url_role=item.get("url_role") or "passive_infrastructure_lookup", url=url)
        if url and _render_clickable(item, url, role="passive_infrastructure_lookup", status=str(item.get("url_status") or "not_checked")):
            link_html = f'<a href="{_html_escape(url)}" target="_blank" rel="noopener noreferrer" data-browser-safe="true">{_html_escape(label)}</a>'
        elif url:
            link_html = f"<code>{_html_escape(url)}</code>"
        else:
            link_html = "-"
        rows.append(
            "<tr>"
            f"<td>{link_html}<br><span class=\"muted\">Manuel pasif arama kısayolu; bulgu değildir.</span></td>"
            f"<td><code>{_html_escape(item.get('url_role') or 'passive_infrastructure_lookup')}</code></td>"
            f"<td>{_html_escape(_display_status_label(item.get('url_status') or 'not_checked'))}<br><span class=\"muted\"><code>{_html_escape(item.get('url_status') or 'not_checked')}</code></span></td>"
            f"<td>{_html_escape(_display_status_label(item.get('status') or 'suggestion_only'))}<br><span class=\"muted\"><code>{_html_escape(item.get('status') or 'suggestion_only')}</code></span></td>"
            f"<td>{_html_escape(item.get('risk_score_impact', 0))}</td>"
            "</tr>"
        )
    return "".join(rows) or "<tr><td colspan=\"5\">Pasif altyapı arama kısayolu üretilmedi.</td></tr>"


def _infrastructure_html(infrastructure: dict[str, Any]) -> str:
    if not infrastructure:
        return """
      <h3 id="osint-source-infrastructure">Altyapı Bağlamı</h3>
      <p class="operator-view-note">Bu OSINT payload'u için altyapı istihbaratı toplanmadı.</p>
        """
    resolved_ips = _as_list(infrastructure.get("resolved_ips"))
    ipv6_addresses = _as_list(infrastructure.get("ipv6_addresses"))
    cname_chain = _as_list(infrastructure.get("cname_chain"))
    dns_status = str(infrastructure.get("dns_status") or "unknown")
    resolver_error = str(infrastructure.get("resolver_error") or "")
    cdn_likely = bool(infrastructure.get("cdn_or_proxy_likely"))
    caveat_html = ""
    if cdn_likely:
        caveat_html = """
      <div class="operator-view-note warning">
        <strong>Muhtemel CDN/proxy edge. Origin sunucu olduğu varsayılmamalıdır.</strong>
      </div>
        """
    failure_note = ""
    if dns_status in {"error", "timeout"}:
        failure_note = '<p class="operator-view-note"><strong>DNS çözümleme başarısız veya erişilemez.</strong> Bu temiz hedef veya public altyapı yokluğu anlamına gelmez.</p>'
    return f"""
      <h3 id="osint-source-infrastructure">Altyapı Bağlamı</h3>
      <p class="operator-view-note"><strong>Sadece pasif altyapı bağlamı.</strong> DNS kayıtları ve sahiplik ipuçları maruziyet bulgusu değildir ve risk skorunu etkilemez.</p>
      {failure_note}
      <h4>DNS Çözümleme Özeti</h4>
      <table>
        <tr><th>Hedef host</th><td><code>{_html_escape(infrastructure.get('target_host'))}</code></td></tr>
        <tr><th>Registered domain</th><td><code>{_html_escape(infrastructure.get('target_registered_domain') or '-')}</code></td></tr>
        <tr><th>A records</th><td>{_html_escape(', '.join(str(item) for item in resolved_ips) or '-')}</td></tr>
        <tr><th>AAAA records</th><td>{_html_escape(', '.join(str(item) for item in ipv6_addresses) or '-')}</td></tr>
        <tr><th>CNAME chain</th><td>{_html_escape(' -> '.join(str(item) for item in cname_chain) or '-')}</td></tr>
        <tr><th>DNS durumu</th><td><span class="pill muted">{_html_escape(_display_status_label(dns_status))}</span>{('<br><span class="muted">' + _html_escape(resolver_error) + '</span>') if resolver_error else ''}</td></tr>
      </table>
      <h4>Altyapı Sahiplik Bağlamı</h4>
      <table>
        <tr><th>IP</th><th>Reverse DNS</th><th>ASN / organizasyon</th><th>Sağlayıcı tahmini</th><th>Enrichment durumu</th></tr>
        {_infrastructure_ownership_rows(_as_list(infrastructure.get('ip_ownership')))}
      </table>
      <h4>CDN / Proxy Uyarısı</h4>
      <p class="operator-view-note">
        CDN/proxy olasılığı: {_html_escape('evet' if cdn_likely else 'hayır')} |
        Sağlayıcı tahmini: {_html_escape(infrastructure.get('cdn_provider_guess') or '-')} |
        Origin güveni: {_html_escape(infrastructure.get('origin_confidence') or 'bilinmiyor')}.
        {_html_escape(_display_text(infrastructure.get('caveat') or ''))}
      </p>
      {caveat_html}
      <p class="operator-view-note">Pasif altyapı API aramaları yapılandırıldı mı: {_html_escape('hayır' if _as_list(infrastructure.get('passive_lookup_links')) else 'n/a')}. API yapılandırılmadığında kısayollar yalnızca <a href="#osint-manual-search-suggestions">Manuel / API-gerekli öneriler</a> altında listelenir.</p>
    """


def _org_link_html(item: dict[str, Any], *, label_key: str = "label", fallback_label: str = "Open link") -> str:
    url = str(item.get("url") or item.get("source_url") or "").strip()
    label = _display_manual_lookup_label(item.get(label_key) or url or fallback_label, url_role=item.get("url_role") or "organization_lookup_shortcut", url=url)
    role = str(item.get("url_role") or "organization_lookup_shortcut")
    status = str(item.get("url_status") or "not_checked")
    if url and _render_clickable(item, url, role=role, status=status):
        return f'<a href="{_html_escape(url)}" target="_blank" rel="noopener noreferrer" data-browser-safe="true">{_html_escape(label)}</a>'
    if url:
        return f"<code>{_html_escape(url)}</code>"
    return "-"


def _url_status_label(status: Any) -> str:
    mapping = {
        "checked_ok": "Başarıyla kontrol edildi",
        "checked_redirect": "Yönlendirildi",
        "checked_redirect_valid": "Geçerli yönlendirme",
        "checked_official_affiliate_redirect": "Geçerli affiliate yönlendirme",
        "checked_not_found": "Bulunamadı",
        "checked_soft_error": "Soft-error sayfası reddedildi",
        "checked_unexpected_content": "Beklenmeyen içerik",
        "checked_duplicate": "Tekrarlı canonical URL",
        "checked_forbidden": "Erişim yasak",
        "timeout": "Zaman aşımı",
        "tls_error": "TLS hatası",
        "connection_error": "Bağlantı hatası",
        "auth_required": "Kimlik doğrulama gerekli",
        "api_key_missing": "API key gerekli",
        "manual_only": "Sadece manuel işlem",
        "generated_candidate": "Üretilmiş aday",
        "archived_not_live_checked": "Arşivlenmiş; canlı kontrol edilmedi",
        "present": "Mevcut",
        "absent": "Yok",
        "resolver_error": "Resolver hatası",
        "dependency_missing": "Bağımlılık eksik",
        "not_checked": "Kontrol edilmedi",
        "error": "Hata",
    }
    return mapping.get(str(status or ""), _display_status_label(status))


def _organization_official_page_rows(pages: list[Any]) -> str:
    rows: list[str] = []
    for item in pages:
        if not isinstance(item, dict):
            continue
        meaning = str(item.get("meaning") or ("resmî herkese açık sayfa var" if item.get("page_found") else "kanıt değil; yalnızca doğrulama bağlamı"))
        rows.append(
            "<tr>"
            f"<td>{_html_escape(item.get('page_type') or 'unknown')}</td>"
            f"<td>{_org_link_html(item, label_key='url')}</td>"
            f"<td><span class=\"pill muted\">{_html_escape(_url_status_label(item.get('url_status')))}</span><br><span class=\"muted\">check: {_html_escape(item.get('check_status') or 'skipped')}</span></td>"
            f"<td>{_html_escape(item.get('http_status') or '-')}</td>"
            f"<td>{_html_escape(item.get('final_url') or '-')}</td>"
            f"<td>{_html_escape(item.get('title') or '-')}</td>"
            f"<td>{_html_escape(_display_text(meaning))}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="7">Kontrol edilmiş resmî sayfa satırı yok.</td></tr>'


def _filtered_page_rows(pages: list[Any]) -> str:
    rows: list[str] = []
    for item in pages:
        if not isinstance(item, dict):
            continue
        reasons = item.get("rejection_reason") if isinstance(item.get("rejection_reason"), list) else []
        reason_parts = [str(reason) for reason in reasons if str(reason or "").strip()]
        if item.get("suppressed_reason"):
            reason_parts.append(str(item.get("suppressed_reason")))
        if item.get("duplicate_of"):
            reason_parts.append(f"duplicate_of={item.get('duplicate_of')}")
        reason_text = ", ".join(reason_parts) or str(item.get("validation_error") or "-")
        status = str(item.get("url_status") or item.get("check_status") or "unknown")
        rows.append(
            "<tr>"
            f"<td>{_html_escape(item.get('page_type') or 'unknown')}</td>"
            f"<td><code>{_html_escape(item.get('url') or '-')}</code></td>"
            f"<td><span class=\"pill muted\">{_html_escape(_url_status_label(status))}</span></td>"
            f"<td>{_html_escape(item.get('http_status') or '-')}</td>"
            f"<td><code>{_html_escape(item.get('final_url') or '-')}</code></td>"
            f"<td>{_html_escape(reason_text)}</td>"
            f"<td>{_html_escape(_display_text(item.get('meaning') or ('Soft-error sayfası reddedildi.' if status == 'checked_soft_error' else 'Sadece filtrelenmiş teşhis.')))}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="7">Filtrelenmiş/reddedilmiş path satırı yok.</td></tr>'


def _security_txt_html(security_txt: dict[str, Any]) -> str:
    fields = security_txt.get("fields") if isinstance(security_txt.get("fields"), dict) else {}
    field_rows: list[str] = []
    for key in ("Contact", "Policy", "Hiring", "Acknowledgments", "Preferred-Languages", "Expires", "Canonical"):
        values = [str(item) for item in _as_list(fields.get(key)) if str(item or "").strip()]
        if values:
            field_rows.append(f"<tr><th>{_html_escape(key)}</th><td>{_html_escape('; '.join(values))}</td></tr>")
    contacts = [item for item in _as_list(security_txt.get("contacts")) if isinstance(item, dict)]
    contact_rows = "".join(
        "<tr>"
        f"<td>{_html_escape(item.get('contact_endpoint') or item.get('email') or '-')}</td>"
        f"<td>{_html_escape(item.get('contact_type') or ('email' if item.get('email') else 'unknown'))}</td>"
        f"<td>{_html_escape(item.get('source') or 'security_txt')}</td>"
        f"<td>{_html_escape(item.get('status') or 'observed_public_contact')}</td>"
        f"<td>{_html_escape(item.get('validation') or 'not_verified_no_account_validation')}</td>"
        "</tr>"
        for item in contacts
    )
    found_url_html = ""
    if security_txt.get("found_url"):
        found_url_item = {
            "url": security_txt.get("found_url"),
            "url_role": security_txt.get("url_role") or "security_txt",
            "url_status": security_txt.get("url_status") or "found",
            "browser_safe": security_txt.get("browser_safe", True),
            "render_as_clickable": security_txt.get("render_as_clickable", True),
        }
        found_url_html = f"<br>Bulunan URL: {_org_link_html(found_url_item, label_key='url', fallback_label='security.txt aç')}"
    return f"""
      <h4>Security.txt</h4>
      <p class="operator-view-note">
        Durum: <strong>{_html_escape(_url_status_label(security_txt.get('url_status') or security_txt.get('status')))}</strong>{found_url_html}<br>
        Contact alanları yalnızca herkese açık security contact endpoint'leridir. ReconBot inbox doğrulamaz, rapor göndermez veya hesap doğrulamaz.
      </p>
      <table>
        {''.join(field_rows) or '<tr><td colspan="2">security.txt alanı parse edilmedi.</td></tr>'}
      </table>
      <table>
        <tr><th>Herkese açık iletişim endpoint'i</th><th>Tip</th><th>Kaynak</th><th>Durum</th><th>Doğrulama</th></tr>
        {contact_rows or '<tr><td colspan="5">Gözlemlenmiş security.txt contact satırı yok.</td></tr>'}
      </table>
    """


def _role_contact_rows(contacts: list[Any], *, observed: bool) -> str:
    rows: list[str] = []
    for item in contacts:
        if not isinstance(item, dict) or bool(item.get("observed")) is not observed:
            continue
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(item.get('contact_endpoint') or item.get('email') or '-')}</code></td>"
            f"<td>{_html_escape(item.get('contact_type') or ('email' if item.get('email') else 'unknown'))}</td>"
            f"<td>{_html_escape(item.get('source') or ('official public source' if observed else 'generated standard role'))}</td>"
            f"<td>{_html_escape(item.get('status') or '-')}</td>"
            f"<td>{_html_escape(item.get('verification_level') or ('observed_on_public_source' if observed else 'not_observed_not_verified'))}</td>"
            f"<td>{_html_escape(str(bool(item.get('account_validated'))).lower())}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="6">Bu kategoride contact yok.</td></tr>'


def _contact_rows(contacts: list[Any], *, empty: str) -> str:
    rows: list[str] = []
    for item in contacts:
        if not isinstance(item, dict):
            continue
        scope = str(item.get("scope_origin") or "-")
        applies = item.get("applies_to_target")
        applies_text = str(applies).lower() if isinstance(applies, bool) else str(applies or "-")
        value = str(item.get("display_value") or item.get("value") or item.get("contact_endpoint") or "-")
        if value.startswith(("http://", "https://")):
            value_html = _org_link_html(
                {
                    "url": value,
                    "label": value,
                    "url_role": "official_contact",
                    "url_status": "checked_ok",
                    "browser_safe": bool(item.get("browser_safe", True)),
                    "render_as_clickable": bool(item.get("render_as_clickable", True)),
                },
                label_key="label",
            )
        else:
            value_html = f"<code>{_html_escape(value)}</code>"
        note_parts = [
            str(item.get("confidence_reason") or "").strip(),
            str(item.get("scope_caveat") or "").strip(),
            "account_validated=false",
        ]
        note = "; ".join(part for part in note_parts if part)
        rows.append(
            "<tr>"
            f"<td>{_html_escape(item.get('contact_type') or '-')}</td>"
            f"<td>{value_html}</td>"
            f"<td>{_org_link_html({'url': item.get('source_url'), 'label': item.get('source_title') or item.get('source_url'), 'url_role': 'official_page', 'url_status': 'checked_ok', 'browser_safe': True, 'render_as_clickable': True}, label_key='label')}</td>"
            f"<td>{_html_escape(item.get('extraction_method') or item.get('source') or '-')}</td>"
            f"<td>{_html_escape(item.get('confidence') or 'low')}<br><span class=\"muted\">{_html_escape(item.get('verification_level') or item.get('confidence_reason') or '-')}</span></td>"
            f"<td>{_html_escape(scope)}</td>"
            f"<td>{_html_escape(applies_text)}</td>"
            f"<td>{_html_escape(note or '-')}</td>"
            "</tr>"
        )
    return "".join(rows) or f'<tr><td colspan="8">{_html_escape(empty)}</td></tr>'


def _scope_origin(item: dict[str, Any]) -> str:
    return str(item.get("scope_origin") or "")


def _target_scope_items(items: list[Any]) -> list[dict[str, Any]]:
    return [
        item
        for item in items
        if isinstance(item, dict)
        and (
            (
                item.get("applies_to_target") is True
                and _scope_origin(item) in {"exact_target_host", "registered_domain"}
            )
            or not _scope_origin(item)
        )
    ]


def _scope_items(items: list[Any], *origins: str) -> list[dict[str, Any]]:
    allowed = set(origins)
    return [item for item in items if isinstance(item, dict) and _scope_origin(item) in allowed]


def _generated_contact_rows(contacts: list[Any], *, mx_status: str) -> str:
    rows: list[str] = []
    for item in contacts:
        if not isinstance(item, dict):
            continue
        value = item.get("display_value") or item.get("contact_endpoint") or item.get("email") or "-"
        note = item.get("confidence_reason") or item.get("note") or f"mx_domain_status={mx_status or 'not_checked'}"
        rows.append(
            "<tr>"
            f"<td>{_html_escape(item.get('contact_type') or 'email')}</td>"
            f"<td><code>{_html_escape(value)}</code></td>"
            f"<td>{_html_escape(item.get('source_url') or '-')}</td>"
            f"<td>{_html_escape(item.get('extraction_method') or 'regex')}</td>"
            f"<td>{_html_escape(item.get('confidence') or 'low')}<br><span class=\"muted\">{_html_escape(item.get('verification_level') or item.get('confidence_reason') or '-')}</span></td>"
            f"<td>{_html_escape(item.get('scope_origin') or '-')}</td>"
            f"<td>false</td>"
            f"<td>{_html_escape(note)}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="8">Üretilmiş role-based e-posta tahmini gösterilmedi.</td></tr>'


def _suppressed_contact_rows(contacts: list[Any]) -> str:
    rows: list[str] = []
    for item in contacts:
        if not isinstance(item, dict):
            continue
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(item.get('contact_endpoint') or item.get('email') or '-')}</code></td>"
            f"<td>{_html_escape(item.get('status') or 'suppressed')}</td>"
            f"<td>{_html_escape(item.get('suppression_reason') or item.get('note') or '-')}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="3">Bastırılan contact yok.</td></tr>'


def _rejected_candidate_rows(candidates: list[Any], *, value_key: str = "value", empty: str) -> str:
    rows: list[str] = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        reason = item.get("rejection_reason")
        if isinstance(reason, list):
            reason_text = ", ".join(str(part) for part in reason)
        else:
            reason_text = str(reason or item.get("suppression_reason") or "-")
        value = item.get(value_key) or item.get("contact_endpoint") or item.get("profile_url") or item.get("url") or "-"
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(value)}</code></td>"
            f"<td>{_html_escape(item.get('status') or 'rejected')}</td>"
            f"<td>{_html_escape(item.get('source_url') or '-')}</td>"
            f"<td>{_html_escape(reason_text)}</td>"
            "</tr>"
        )
    return "".join(rows) or f'<tr><td colspan="4">{_html_escape(empty)}</td></tr>'


def _mail_infrastructure_html(email_intel: dict[str, Any]) -> str:
    if not email_intel:
        return "<h4>Mail Altyapı Özeti</h4><p class=\"operator-view-note\">Mail altyapısı kontrol edilmedi.</p>"
    dependency_text = "Kontrol edilmedi - DNS resolver bağımlılığı yok."
    no_record_text = "Kayıt gözlemlenmedi"
    dependency_missing = any(str(email_intel.get(key) or "") == "dependency_missing" for key in ("mx_status", "spf_status", "dmarc_status"))
    mx_records = ", ".join(str(item) for item in _as_list(email_intel.get("mx_records"))) or (
        dependency_text if email_intel.get("mx_status") == "dependency_missing" else no_record_text if email_intel.get("mx_status") == "absent" else "-"
    )
    spf_records = "; ".join(str(item) for item in _as_list(email_intel.get("spf_records"))) or (
        dependency_text if email_intel.get("spf_status") == "dependency_missing" else no_record_text if email_intel.get("spf_status") == "absent" else "-"
    )
    dmarc_records = "; ".join(str(item) for item in _as_list(email_intel.get("dmarc_records"))) or (
        dependency_text if email_intel.get("dmarc_status") == "dependency_missing" else no_record_text if email_intel.get("dmarc_status") == "absent" else "-"
    )
    dns_detail_rows = []
    for label, key in (("MX", "mx_validation_error"), ("SPF", "spf_validation_error"), ("DMARC", "dmarc_validation_error")):
        detail = str(email_intel.get(key) or "").strip()
        if detail:
            dns_detail_rows.append(f"{label}: {detail}")
    dependency_note = ""
    if dependency_missing:
        dependency_note = f'<p class="operator-view-note warning">{_html_escape(dependency_text)} dnspython kur veya DNS resolver desteğini yapılandır.</p>'
    details_html = ""
    if dns_detail_rows:
        details_html = f"<br><span class=\"muted\">{_html_escape('; '.join(dns_detail_rows))}</span>"
    def status_label(value: Any) -> str:
        return dependency_text if str(value or "") == "dependency_missing" else _url_status_label(value or "not_checked")
    validation_error = str(email_intel.get("validation_error") or "").strip()
    return f"""
      <h4>Mail Altyapı Özeti</h4>
      <p class="operator-view-note"><strong>Mail altyapısı tekil inbox varlığını kanıtlamaz.</strong> ReconBot yalnızca pasif domain-seviyesi DNS kontrolleri yapar ve alıcı doğrulamaz.</p>
      {dependency_note}
      <table>
        <tr><th>Registered domain</th><td><code>{_html_escape(email_intel.get('target_registered_domain') or '-')}</code></td></tr>
        <tr><th>Resolver yöntemi</th><td>{_html_escape(email_intel.get('resolver_method') or 'dnspython')}</td></tr>
        <tr><th>MX status</th><td>{_html_escape(status_label(email_intel.get('mx_status') or 'not_checked'))}</td></tr>
        <tr><th>MX records</th><td>{_html_escape(mx_records)}</td></tr>
        <tr><th>SPF status</th><td>{_html_escape(status_label(email_intel.get('spf_status') or 'not_checked'))}</td></tr>
        <tr><th>SPF records</th><td>{_html_escape(spf_records)}</td></tr>
        <tr><th>DMARC status</th><td>{_html_escape(status_label(email_intel.get('dmarc_status') or 'not_checked'))}</td></tr>
        <tr><th>DMARC records</th><td>{_html_escape(dmarc_records)}</td></tr>
        <tr><th>DKIM status</th><td>{_html_escape(_url_status_label(email_intel.get('dkim_status') or 'not_checked'))}{details_html}</td></tr>
        {f'<tr><th>Doğrulama hatası</th><td>{_html_escape(validation_error)}</td></tr>' if validation_error else ''}
      </table>
    """


def _org_shortcut_rows(items: list[Any], *, empty: str) -> str:
    rows: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        details = []
        for key in ("confidence", "meaning", "caveat", "note"):
            value = str(item.get(key) or "").strip()
            if value:
                details.append(f"{key}: {_display_text(value)}")
        link_html = _org_link_html(item)
        if details:
            link_html = f"{link_html}<br><span class=\"muted\">{_html_escape('; '.join(details))}</span>"
        rows.append(
            "<tr>"
            f"<td>{link_html}</td>"
            f"<td><code>{_html_escape(item.get('url_role') or '-')}</code></td>"
            f"<td>{_html_escape(_url_status_label(item.get('url_status') or 'manual_only'))}</td>"
        f"<td>{_html_escape(_plain_status_label(item.get('status') or 'suggestion_only'))}</td>"
            f"<td>{_html_escape(item.get('risk_score_impact', 0))}</td>"
            "</tr>"
        )
    return "".join(rows) or f'<tr><td colspan="5">{_html_escape(empty)}</td></tr>'


def _location_hint_rows(hints: list[Any]) -> str:
    rows: list[str] = []
    for item in hints:
        if not isinstance(item, dict):
            continue
        source_item = {
            "url": item.get("source_url"),
            "url_role": "official_page",
            "url_status": "checked",
            "browser_safe": True,
            "render_as_clickable": True,
        }
        rows.append(
            "<tr>"
            f"<td>{_html_escape(item.get('location_hint') or '-')}</td>"
            f"<td>{_org_link_html(source_item, label_key='url')}</td>"
            f"<td>{_html_escape(item.get('confidence') or 'low')}</td>"
            f"<td>{_html_escape(item.get('status') or 'observed_public_location_hint')}</td>"
            f"<td>{_html_escape(item.get('caveat') or 'Herkese açık sayfa/konum ipucu; manuel doğrula.')}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="5">Doğrulanmış resmî ofis/konum gözlemlenmedi. Maps araması manueldir ve yerel/franchise sonuç döndürebilir.</td></tr>'


def _location_rows(locations: list[Any]) -> str:
    rows: list[str] = []
    for item in locations:
        if not isinstance(item, dict):
            continue
        source_item = {
            "url": item.get("source_url"),
            "url_role": "official_page",
            "url_status": "checked_ok",
            "browser_safe": True,
            "render_as_clickable": True,
        }
        caveat = str(item.get("caveat") or "")
        scope_caveat = str(item.get("scope_caveat") or "")
        if scope_caveat and scope_caveat not in caveat:
            caveat = f"{caveat} {scope_caveat}".strip()
        caveat_html = f'<br><span class="muted">{_html_escape(caveat)}</span>' if caveat else ""
        applies = item.get("applies_to_target")
        applies_text = str(applies).lower() if isinstance(applies, bool) else str(applies or "-")
        rows.append(
            "<tr>"
            f"<td>{_html_escape(item.get('label') or 'Observed location')}</td>"
            f"<td>{_html_escape(item.get('address_text') or '-')}</td>"
            f"<td>{_html_escape(item.get('source_type') or item.get('source') or '-')}</td>"
            f"<td>{_org_link_html(source_item, label_key='url')}</td>"
            f"<td>{_html_escape(str(bool(item.get('observed'))).lower())}</td>"
            f"<td>{_html_escape(item.get('verification_level') or '-')}</td>"
            f"<td>{_html_escape(item.get('confidence') or 'low')}{caveat_html}</td>"
            f"<td>{_html_escape(item.get('scope_origin') or '-')}</td>"
            f"<td>{_html_escape(applies_text)}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="9">Doğrulanmış resmî sayfalardan doğrulanmış adres/konum çıkarılamadı.</td></tr>'


def _location_rejected_rows(candidates: list[Any]) -> str:
    rows: list[str] = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        source_item = {
            "url": item.get("source_url"),
            "url_role": "official_page",
            "url_status": "checked_ok",
            "browser_safe": True,
            "render_as_clickable": True,
        }
        reason = str(item.get("rejection_reason") or "missing_address_fields")
        reason = {
            "weak_address_evidence": "missing_address_fields",
            "store_locator_without_address": "store_locator_noise",
            "not_address_navigation_text": "missing_address_fields",
            "not_address_marketing_text": "missing_address_fields",
        }.get(reason, reason)
        rows.append(
            "<tr>"
            f"<td>{_html_escape(item.get('text') or '-')}</td>"
            f"<td>{_org_link_html(source_item, label_key='url')}</td>"
            f"<td>{_html_escape(reason)}</td>"
            f"<td>{_html_escape(item.get('source_type') or '-')}</td>"
            f"<td>{_html_escape(item.get('risk_score_impact', 0))}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="5">Reddedilmiş konum adayı yok.</td></tr>'


def _location_shortcut_rows(shortcuts: list[Any]) -> str:
    rows: list[str] = []
    for item in shortcuts:
        if not isinstance(item, dict):
            continue
        rows.append(
            "<tr>"
            f"<td>{_org_link_html(item, label_key='label', fallback_label='Manuel konum aramasını aç')}</td>"
            f"<td>{_html_escape(item.get('meaning') or 'Sadece manuel konum arama önerisi.')}</td>"
            f"<td>{_html_escape(item.get('caveat') or 'Bu linkler doğrulanmış kanıt değildir. Yerel mağaza veya alakasız işletme döndürebilir.')}</td>"
            f"<td>{_html_escape(_plain_status_label(item.get('url_status') or item.get('status') or 'manual_only'))}</td>"
            f"<td>{_html_escape(item.get('risk_score_impact', 0))}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="5">Manuel konum arama önerisi üretilmedi.</td></tr>'


def _location_summary_card(
    summary: dict[str, Any],
    *,
    shortcut_count: int,
    rejected_count: int,
    external_count: int,
    observed_count: int,
    exact_count: int,
    parent_count: int,
    affiliate_count: int,
) -> str:
    observed = _safe_int(summary.get("observed_locations_count"), observed_count)
    external = _safe_int(summary.get("external_candidates_count"), external_count)
    fallback = _safe_int(summary.get("fallback_shortcuts_count"), shortcut_count)
    rejected = _safe_int(summary.get("rejected_candidates_count"), rejected_count)
    return f"""
      <h4>Konum İstihbaratı Özeti</h4>
      <div class="kpi-grid overview-core-grid">
        <div class="kpi"><div class="label">Tam hedef konumları</div><div class="value">{_html_escape(exact_count)}</div><div class="note">İstenen host üzerinde doğrulanmış adres/konum.</div></div>
        <div class="kpi"><div class="label">Üst kurum konumları</div><div class="value">{_html_escape(parent_count)}</div><div class="note">Bağlamdır; tam hedefe doğrudan ait varsayılmamalıdır.</div></div>
        <div class="kpi"><div class="label">Bağlı/harici resmî kaynak konumları</div><div class="value">{_html_escape(affiliate_count + external)}</div><div class="note">Resmî bağlı/harici bağlam; tam hedef kanıtı değildir.</div></div>
        <div class="kpi"><div class="label">Manuel öneri konum aramaları</div><div class="value">{_html_escape(fallback)}</div><div class="note">Doğrulanmış kanıt değildir. Risk etkisi 0.</div></div>
        <div class="kpi"><div class="label">Reddedilen/noisy konum adayları</div><div class="value">{_html_escape(rejected)}</div><div class="note">Soft-error, tekrar, eksik adres alanı veya store-locator noise.</div></div>
        <div class="kpi"><div class="label">Toplam gözlemlenen resmî konum</div><div class="value">{_html_escape(observed)}</div><div class="note">Tüm kapsamlar birlikte.</div></div>
      </div>
    """


def _location_intelligence_html(organization: dict[str, Any]) -> str:
    location_intel = _as_dict(organization.get("location_intelligence"))
    locations = _as_list(location_intel.get("observed_locations"))
    external_candidates = _as_list(location_intel.get("external_location_candidates"))
    rejected_candidates = _as_list(location_intel.get("rejected_location_candidates"))
    shortcuts = _as_list(location_intel.get("location_lookup_shortcuts")) or _as_list(organization.get("location_lookup_links"))
    summary = _as_dict(location_intel.get("location_summary"))
    target_locations = _target_scope_items(locations)
    parent_locations = _scope_items(locations, "parent_organization")
    affiliate_locations = _scope_items(locations, "official_affiliate_domain", "external_verified_source")
    external_rows = _location_rows(external_candidates) if external_candidates else '<tr><td colspan="9">Harici konum API adayı toplanmadı. API destekli kaynaklar yapılandırılmadıkça kapalı kalır.</td></tr>'
    empty_note = ""
    if not locations:
        empty_note = '<p class="operator-view-note warning">Tam hedef üzerinde doğrulanmış adres/konum çıkarılamadı.</p><p class="operator-view-note">Manuel öneri konum aramaları aşağıdadır.</p>'
    elif not target_locations:
        empty_note = '<p class="operator-view-note warning">Tam hedef üzerinde doğrulanmış adres/konum çıkarılamadı.</p>'
    fallback_notice = ""
    if shortcuts:
        fallback_notice = '<p class="operator-view-note"><strong>Manuel Maps/search kısayolları aşağıda sadece manuel öneri olarak listelenir.</strong> Bu linkler doğrulanmış kanıt değildir. Yerel mağaza veya alakasız işletme döndürebilir.</p>'
    why_box = ""
    if not target_locations:
        soft_errors = _safe_int(_as_dict(organization.get("summary")).get("official_pages_soft_error"))
        why_box = f"""
      <div class="operator-view-note warning">
        <strong>Neden konum bulunamadı?</strong><br>
        Tam hedef üzerinde doğrulanmış adres/konum çıkarılamadı. ReconBot yalnızca doğrulanmış resmî kaynaklarda görülen adresleri kanıt sayar.
        Google Maps veya arama linkleri kanıt değildir, sadece manuel kontrol önerisidir. Store locator sayfaları doğrulanmış kanıt sayılmaz.
        Bazı siteler taranan host üzerinde kurumsal adres yayımlamaz. Kaynak kapsamı zaman aşımı nedeniyle kısmi kalabilir.
        {_html_escape('Bazı sayfalar soft-error/noise olarak reddedildi.' if soft_errors else '')}
      </div>
        """
    return f"""
      <h3 id="osint-location-intelligence">Konum İstihbaratı</h3>
      <p class="operator-view-note"><strong>ReconBot yalnızca doğrulanmış resmî kaynaklarda görülen adresleri kanıt sayar.</strong> Google Maps veya arama linkleri kanıt değildir, sadece manuel kontrol önerisidir.</p>
      {_location_summary_card(summary, shortcut_count=len(shortcuts), rejected_count=len(rejected_candidates), external_count=len(external_candidates), observed_count=len(locations), exact_count=len(target_locations), parent_count=len(parent_locations), affiliate_count=len(affiliate_locations))}
      {fallback_notice}
      {empty_note}
      {why_box}
      <h4>Tam hedef konumları</h4>
      <p class="operator-view-note">İstenen tam hedef host üzerinde doğrudan gözlemlenen konumlar. {('Tam hedef üzerinde doğrulanmış adres/konum çıkarılamadı.' if not target_locations else '')}</p>
      <table>
        <tr><th>Etiket</th><th>Adres metni</th><th>Kaynak tipi</th><th>Kaynak URL</th><th>Gözlemlendi</th><th>Doğrulama seviyesi</th><th>Güven</th><th>Kapsam kaynağı</th><th>Target'a uygulanır mı?</th></tr>
        {_location_rows(target_locations)}
      </table>
      <h4>Üst kurum konumları</h4>
      <p class="operator-view-note">Üst kurum bağlamında konum bulundu; tam hedefe doğrudan ait olduğu varsayılmamalıdır.</p>
      <table>
        <tr><th>Etiket</th><th>Adres metni</th><th>Kaynak tipi</th><th>Kaynak URL</th><th>Gözlemlendi</th><th>Doğrulama seviyesi</th><th>Güven</th><th>Kapsam kaynağı</th><th>Target'a uygulanır mı?</th></tr>
        {_location_rows(parent_locations)}
      </table>
      <h4>Bağlı/harici resmî kaynak konumları</h4>
      <p class="operator-view-note">Resmî bağlı domain, güvenilir resmî redirect veya yapılandırılmış harici metadata kaynaklarından gelen konumlar. Kapsam ve not alanları tam hedefe uygulanıp uygulanmadığını belirler.</p>
      <table>
        <tr><th>Etiket</th><th>Adres metni</th><th>Kaynak tipi</th><th>Kaynak URL</th><th>Gözlemlendi</th><th>Doğrulama seviyesi</th><th>Güven</th><th>Kapsam kaynağı</th><th>Target'a uygulanır mı?</th></tr>
        {_location_rows(affiliate_locations)}
      </table>
      <h4>Harici Konum Adayları</h4>
      <table>
        <tr><th>Etiket</th><th>Adres metni</th><th>Kaynak tipi</th><th>Kaynak URL</th><th>Gözlemlendi</th><th>Doğrulama seviyesi</th><th>Güven</th><th>Kapsam kaynağı</th><th>Target'a uygulanır mı?</th></tr>
        {external_rows}
      </table>
      <h4>Manuel fallback konum aramaları</h4>
      <p class="operator-view-note">Bu linkler doğrulanmış kanıt değildir. Yerel mağaza veya alakasız işletme döndürebilir. Risk etkisi 0.</p>
      <table>
        <tr><th>Arama</th><th>Anlamı</th><th>Uyarı</th><th>Durum</th><th>Risk etkisi</th></tr>
        {_location_shortcut_rows(shortcuts)}
      </table>
      <details class="show-more">
        <summary>Reddedilen Konum Adayları ({_html_escape(len(rejected_candidates))})</summary>
        <p class="operator-view-note">Reddedilen snippet'ler sadece teşhistir ve gözlemlenen resmî konum olarak gösterilmez.</p>
        <table>
          <tr><th>Metin</th><th>Kaynak URL</th><th>Red nedeni</th><th>Kaynak tipi</th><th>Risk etkisi</th></tr>
          {_location_rejected_rows(rejected_candidates)}
        </table>
      </details>
    """


def _public_document_rows(documents: list[Any]) -> str:
    rows: list[str] = []
    for item in documents:
        if not isinstance(item, dict):
            continue
        http_detail = " / ".join(
            part
            for part in (
                str(item.get("content_type") or "").strip(),
                str(item.get("http_status") or "").strip(),
            )
            if part
        ) or "-"
        applies = item.get("applies_to_target")
        applies_text = str(applies).lower() if isinstance(applies, bool) else str(applies or "-")
        rows.append(
            "<tr>"
            f"<td>{_html_escape(item.get('document_type') or item.get('source_type') or '-')}</td>"
            f"<td>{_org_link_html(item, label_key='label', fallback_label='Open public document')}</td>"
            f"<td>{_org_link_html({'url': item.get('source_url'), 'label': item.get('source_url'), 'url_role': 'official_page', 'url_status': 'checked_ok', 'browser_safe': True, 'render_as_clickable': True}, label_key='label')}</td>"
            f"<td>{_html_escape(item.get('validation_method') or item.get('source_type') or '-')}</td>"
            f"<td>{_html_escape(http_detail)}</td>"
            f"<td>{_html_escape(item.get('confidence') or 'low')}</td>"
            f"<td>{_html_escape(item.get('scope_origin') or '-')}</td>"
            f"<td>{_html_escape(applies_text)}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="8">Doğrulanmış resmî kaynaklarda doğrulanmış herkese açık doküman bulunmadı.</td></tr>'


def _rejected_document_rows(documents: list[Any]) -> str:
    rows: list[str] = []
    for item in documents:
        if not isinstance(item, dict):
            continue
        reasons = item.get("rejection_reason") if isinstance(item.get("rejection_reason"), list) else []
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(item.get('url') or '-')}</code></td>"
            f"<td>{_html_escape(item.get('source_type') or '-')}</td>"
            f"<td>{_html_escape(_url_status_label(item.get('url_status') or 'not_checked'))}</td>"
            f"<td>{_html_escape(item.get('http_status') or '-')}</td>"
            f"<td>{_html_escape(', '.join(str(reason) for reason in reasons) or '-')}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="5">Reddedilmiş herkese açık doküman adayı yok.</td></tr>'


def _public_document_intelligence_html(organization: dict[str, Any]) -> str:
    document_intel = _as_dict(organization.get("public_document_intelligence"))
    documents = _as_list(document_intel.get("validated_public_documents"))
    rejected = _as_list(document_intel.get("rejected_document_candidates"))
    shortcuts = _as_list(document_intel.get("manual_document_search_shortcuts")) or _as_list(organization.get("public_document_searches"))
    target_count, parent_count, affiliate_count, manual_count = _document_scope_counts(organization)
    target_documents = _target_scope_items(documents)
    parent_documents = _scope_items(documents, "parent_organization")
    affiliate_documents = _scope_items(documents, "official_affiliate_domain", "external_verified_source")
    empty_note = ""
    if not documents:
        empty_note = '<p class="operator-view-note warning">Herkese açık dokümanlar için doğrulanmış kaynaklarda gözlemlenmiş konum/iletişim/doküman bulunmadı. Manuel doküman dork önerileri yalnızca manuel öneri teşhisidir.</p>'
    return f"""
      <h3 id="osint-public-document-intelligence">Herkese Açık Dokümanlar</h3>
      <p class="operator-view-note"><strong>Güvenli herkese açık doküman keşfi önce resmî linkleri ve sitemap referanslarını kontrol eder.</strong> ReconBot URL status/content type değerlerini sınırlı isteklerle doğrular; personal data derin parse etmez ve varsayılan olarak büyük dosya indirmez.</p>
      <div class="kpi-grid overview-core-grid">
        <div class="kpi"><div class="label">Tam hedef herkese açık dokümanları</div><div class="value">{_html_escape(target_count)}</div><div class="note">İstenen target host veya tam hedef kapsamında doğrulandı.</div></div>
        <div class="kpi"><div class="label">Üst kurum herkese açık dokümanları</div><div class="value">{_html_escape(parent_count)}</div><div class="note">Üst kurum bağlamı; tam hedef kanıtı değildir.</div></div>
        <div class="kpi"><div class="label">Bağlı/harici resmî herkese açık dokümanlar</div><div class="value">{_html_escape(affiliate_count)}</div><div class="note">Resmî bağlı veya harici doğrulanmış kaynak bağlamı; tam hedef kanıtı değildir.</div></div>
        <div class="kpi"><div class="label">Manuel doküman arama kısayolları</div><div class="value">{_html_escape(manual_count)}</div><div class="note">Sadece doküman dork/kısayol; doğrulanmış doküman değildir.</div></div>
      </div>
      {empty_note}
      <h4>Tam hedef herkese açık dokümanları</h4>
      <table>
        <tr><th>Doküman tipi</th><th>URL</th><th>Kaynak</th><th>Doğrulama</th><th>Content-Type / HTTP</th><th>Güven</th><th>Kapsam</th><th>Target'a uygulanır mı?</th></tr>
        {_public_document_rows(target_documents)}
      </table>
      <h4>Üst kurum herkese açık dokümanları</h4>
      <p class="operator-view-note">Üst kurum bağlamında bulundu; tam hedefe doğrudan ait olduğu varsayılmamalıdır.</p>
      <table>
        <tr><th>Doküman tipi</th><th>URL</th><th>Kaynak</th><th>Doğrulama</th><th>Content-Type / HTTP</th><th>Güven</th><th>Kapsam</th><th>Target'a uygulanır mı?</th></tr>
        {_public_document_rows(parent_documents)}
      </table>
      <h4>Bağlı/harici resmî herkese açık dokümanlar</h4>
      <p class="operator-view-note">Bağlı/harici resmî kaynak bağlamıdır; tam hedef kanıtı değildir.</p>
      <table>
        <tr><th>Doküman tipi</th><th>URL</th><th>Kaynak</th><th>Doğrulama</th><th>Content-Type / HTTP</th><th>Güven</th><th>Kapsam</th><th>Target'a uygulanır mı?</th></tr>
        {_public_document_rows(affiliate_documents)}
      </table>
      <details class="show-more">
        <summary>Reddedilen doküman adayları ({_html_escape(len(rejected))})</summary>
        <table>
          <tr><th>URL</th><th>Kaynak tipi</th><th>Durum</th><th>HTTP</th><th>Neden</th></tr>
          {_rejected_document_rows(rejected)}
        </table>
      </details>
      <p class="operator-view-note">Manuel doküman kısayolu sayısı: {_html_escape(len(shortcuts))}. Manuel herkese açık doküman dork'ları <a href="#osint-manual-search-suggestions">Manuel öneri / API-gerekli öneriler</a> altında kapanır ve doğrulanmış bulgu değildir.</p>
    """


def _social_profile_rows(profiles: list[Any]) -> str:
    rows: list[str] = []
    for item in profiles:
        if not isinstance(item, dict):
            continue
        applies = item.get("applies_to_target")
        applies_text = str(applies).lower() if isinstance(applies, bool) else str(applies or "-")
        rows.append(
            "<tr>"
            f"<td>{_html_escape(item.get('provider') or item.get('profile_type') or '-')}</td>"
            f"<td>{_org_link_html({'url': item.get('profile_url') or item.get('url'), 'label': item.get('profile_url') or item.get('url'), 'url_role': 'observed_official_social_profile', 'url_status': 'checked_ok', 'browser_safe': True, 'render_as_clickable': True}, label_key='label', fallback_label='Open profile')}</td>"
            f"<td>{_org_link_html({'url': item.get('source_url'), 'label': item.get('source_url'), 'url_role': 'official_page', 'url_status': 'checked_ok', 'browser_safe': True, 'render_as_clickable': True}, label_key='label')}</td>"
            f"<td>{_html_escape(item.get('extraction_method') or item.get('source') or '-')}</td>"
            f"<td>{_html_escape(item.get('confidence') or 'low')}<br><span class=\"muted\">{_html_escape(item.get('verification_level') or item.get('confidence_reason') or '-')}</span></td>"
            f"<td>{_html_escape(item.get('scope_origin') or '-')}</td>"
            f"<td>{_html_escape(applies_text)}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="7">Doğrulanmış resmî kaynaklarda resmî sosyal/company profil linki gözlemlenmedi.</td></tr>'


def _people_presence_html(presence: dict[str, Any]) -> str:
    shortcuts = _as_list(presence.get("company_profile_lookup_shortcuts"))
    official_pages = _as_list(presence.get("official_people_pages"))
    social_profiles = _as_list(presence.get("observed_official_social_profiles"))
    page_rows = _organization_official_page_rows(official_pages)
    shortcut_rows = _org_shortcut_rows(shortcuts, empty="People/company lookup shortcut üretilmedi.")
    return f"""
      <h3 id="osint-people-organization-presence">Resmî Sosyal Profiller</h3>
      <p class="operator-view-note"><strong>Sadece güvenli organizasyon görünürlüğü.</strong> Manuel arama kısayolları scrape edilmiş sonuç değildir. Resmî sosyal/company profilleri yalnızca doğrulanmış resmî sayfadan veya structured data üzerinden linklenmişse gösterilir. ReconBot LinkedIn çalışan listesi scrape etmez, çalışan adı toplamaz, kişisel çalışan e-postası toplamaz veya kişisel email pattern üretmez. Eski raporlardaki Herkese Açık Dokümanlar ve Sosyal Profiller kapsamının sosyal profil bölümü burada ayrı gösterilir.</p>
      <p class="operator-view-note warning">Share/intent linkleri ve rastgele kullanıcı profilleri resmî sosyal profil sayılmaz.</p>
      <h4>Gözlemlenen Resmî Sosyal Profiller</h4>
      <table>
        <tr><th>Platform</th><th>Profil</th><th>Kaynak sayfa</th><th>Nasıl çıkarıldı?</th><th>Güven</th><th>Kapsam</th><th>Target'a uygulanır mı?</th></tr>
        {_social_profile_rows(social_profiles)}
      </table>
      <h4>Resmî People / Organization Sayfaları</h4>
      <table>
        <tr><th>Sayfa tipi</th><th>URL</th><th>Durum</th><th>HTTP</th><th>Final URL</th><th>Başlık</th><th>Anlamı</th></tr>
        {page_rows}
      </table>
      <p class="operator-view-note">Manuel company profile kısayolu sayısı: {_html_escape(len(shortcuts))}. Manuel LinkedIn/Crunchbase/search kısayolları <a href="#osint-manual-search-suggestions">Manuel öneri / API-gerekli öneriler</a> altında kapalıdır.</p>
    """


def _email_intelligence_html(organization: dict[str, Any]) -> str:
    email_intel = _as_dict(organization.get("email_intelligence"))
    contact_intel = _as_dict(organization.get("contact_intelligence"))
    contacts = _as_list(organization.get("role_contacts"))
    email_summary = _as_dict(email_intel.get("email_summary"))
    if not contact_intel:
        observed_contacts = [item for item in contacts if isinstance(item, dict) and item.get("observed")]
        contact_intel = {
            "observed_email_addresses": [item for item in observed_contacts if str(item.get("contact_type") or "") == "email"],
            "observed_phone_numbers": [item for item in observed_contacts if str(item.get("contact_type") or "") == "phone"],
            "observed_contact_urls": [item for item in observed_contacts if str(item.get("contact_type") or "") == "url"],
            "observed_contact_forms": [item for item in observed_contacts if str(item.get("contact_type") or "") in {"form", "contact_form"}],
            "generated_role_email_guesses": _as_list(email_intel.get("generated_role_contact_guesses")),
            "suppressed_contacts": _as_list(organization.get("suppressed_contacts")) + _as_list(email_intel.get("suppressed_contacts")),
        }
    observed_emails = _as_list(contact_intel.get("observed_email_addresses"))
    observed_phones = _as_list(contact_intel.get("observed_phone_numbers"))
    observed_urls = _as_list(contact_intel.get("observed_contact_urls"))
    observed_forms = _as_list(contact_intel.get("observed_contact_forms"))
    generated_contacts = _as_list(contact_intel.get("generated_role_email_guesses")) or _as_list(email_intel.get("generated_role_contact_guesses"))
    suppressed_contacts = _as_list(contact_intel.get("suppressed_contacts"))
    generated_count = _safe_int(email_summary.get("generated_role_guesses_count"), len(generated_contacts))
    observed_contacts = observed_emails + observed_phones + observed_urls + observed_forms
    target_contacts = _target_scope_items(observed_contacts)
    parent_contacts = _scope_items(observed_contacts, "parent_organization")
    affiliate_contacts = _scope_items(observed_contacts, "official_affiliate_domain")
    external_contacts = _scope_items(observed_contacts, "external_verified_source")
    no_target_contact_note = ""
    if not target_contacts:
        no_target_contact_note = "<p class=\"operator-view-note warning\">Tam hedef host üzerinde herkese açık iletişim endpoint'i gözlemlenmedi.</p>"
    contact_header = "<tr><th>Tür</th><th>Değer / Link</th><th>Kaynak sayfa</th><th>Nasıl çıkarıldı?</th><th>Güven</th><th>Kapsam</th><th>Target'a uygulanır mı?</th><th>Not</th></tr>"
    return f"""
      <h3 id="osint-email-intelligence">Herkese Açık İletişim Bilgileri</h3>
      <p class="operator-view-note"><strong>Herkese açık iletişim bilgileri yalnızca pasif organizasyon bağlamıdır.</strong> Gözlemlenen contact'lar doğrulanmış resmî herkese açık kaynaklardan gelir. Üretilen role e-posta tahminleri gözlemlenmiş sinyal, geçerli inbox, risk veya manuel inceleme kanıtı değildir.</p>
      <h4>Tam hedef iletişim bilgileri</h4>
      <p class="operator-view-note">Tam hedef contact kanıtı istenen target host üzerinde gözlemlenir. account_validated=false çünkü ReconBot inbox doğrulamaz.</p>
      {no_target_contact_note}
      <table>
        {contact_header}
        {_contact_rows(target_contacts, empty="Tam hedef host üzerinde herkese açık iletişim endpoint'i gözlemlenmedi.")}
      </table>
      <h4>Üst kurum iletişim bilgileri</h4>
      <p class="operator-view-note">Registered/üst kurum domain üzerinde gözlemlendi; tam hedef host üzerinde olduğu varsayılmamalıdır.</p>
      <table>
        {contact_header}
        {_contact_rows(parent_contacts, empty="Üst kurum iletişim endpoint'i gözlemlenmedi.")}
      </table>
      <h4>Bağlı/harici resmî iletişim bilgileri</h4>
      <table>
        {contact_header}
        {_contact_rows(affiliate_contacts + external_contacts, empty='Resmî affiliate veya harici doğrulanmış contact endpoint gözlemlenmedi.')}
      </table>
      {_mail_infrastructure_html(email_intel)}
      <div class="operator-view-note warning">
        <strong>Üretilen role e-posta tahmini: {_html_escape(generated_count)} adet - gözlemlenmiş veya doğrulanmış değildir.</strong><br>
        Bunlar doğrulanmış inbox değildir. Üretilen role e-posta tahminleri geçerli inbox değildir. Bunlar gözlemlenmiş public contact değildir; sadece manuel deneme/tahmin listesidir.
      </div>
      <details class="show-more">
        <summary>Üretilen role e-posta tahminlerini göster / Üretilmiş rol tahminleri ({_html_escape(generated_count)})</summary>
        <table>
          {contact_header}
          {_generated_contact_rows(generated_contacts, mx_status=str(email_intel.get('mx_status') or 'not_checked'))}
        </table>
      </details>
      <h4>Bastırılan Contact'lar</h4>
      <table>
        <tr><th>İletişim endpoint'i</th><th>Durum</th><th>Bastırma nedeni</th></tr>
        {_suppressed_contact_rows(suppressed_contacts)}
      </table>
    """


def _organization_manual_lookup_html(organization: dict[str, Any], operator_search_tasks: list[Any], *, generic_or_reserved_domain: bool) -> str:
    manual_shortcuts = (
        _as_list(organization.get("organization_lookup_links"))
        + _as_list(organization.get("location_lookup_links"))
        + _as_list(organization.get("public_document_searches"))
    )
    return f"""
      <h3 id="osint-manual-search-suggestions">Manuel / API Gerektiren Arama Kısayolları</h3>
      <p class="operator-view-note"><strong>Manuel/API-gerekli arama kısayolları bulgu değildir.</strong> ReconBot Google, LinkedIn, Crunchbase, sosyal site, Maps veya herkese açık doküman sonuç sayfalarını scrape etmez. Üretilen her görev suggestion_only olarak etiketlenir.{_html_escape(' Generic/example domainler çoğunlukla dokümantasyon gürültüsü üretebilir.' if generic_or_reserved_domain else '')}</p>
      <details class="show-more">
        <summary>Organizasyon / API-gerekli kısayollar ({_html_escape(len(manual_shortcuts))})</summary>
        <table>
          <tr><th>Kısayol</th><th>URL rolü</th><th>URL durumu</th><th>Durum</th><th>Risk etkisi</th></tr>
          {_org_shortcut_rows(manual_shortcuts, empty='Manuel/API-gerekli arama kısayolu üretilmedi.')}
        </table>
      </details>
      <details class="show-more">
        <summary>Üretilen manuel arama önerileri ({_html_escape(len(operator_search_tasks))})</summary>
        {_operator_tasks_html(operator_search_tasks)}
      </details>
    """


def _filtered_rejected_paths_html(organization: dict[str, Any]) -> str:
    pages = _as_list(organization.get("official_pages"))
    filtered_pages = [
        page
        for page in pages
        if isinstance(page, dict)
        and str(page.get("url_status") or page.get("check_status") or "")
        in {
            "checked_not_found",
            "checked_soft_error",
            "checked_unexpected_content",
            "checked_duplicate",
            "timeout",
            "connection_error",
            "tls_error",
            "resolver_error",
            "error",
        }
    ]
    contact_intel = _as_dict(organization.get("contact_intelligence"))
    people = _as_dict(organization.get("people_organization_presence"))
    docs = _as_dict(organization.get("public_document_intelligence"))
    suppressed_contacts = _as_list(organization.get("suppressed_contacts")) + _as_list(_as_dict(organization.get("email_intelligence")).get("suppressed_contacts"))
    rejected_contacts = _as_list(contact_intel.get("rejected_contact_candidates"))
    rejected_social = _as_list(people.get("rejected_social_candidates"))
    rejected_documents = _as_list(docs.get("rejected_document_candidates"))
    return f"""
      <h3 id="osint-filtered-rejected-paths">Filtrelenen / Reddedilen / Tekrarlı Path'ler</h3>
      <details class="show-more">
        <summary>Reddedilen / Bastırılan Adaylar ({_html_escape(len(rejected_contacts) + len(rejected_social) + len(rejected_documents) + len(suppressed_contacts))})</summary>
        <p class="operator-view-note">Bu satırlar ana kanıt tablolarına alınmayan adaylardır. Duplicate, share/intent, login/signup/newsletter/store-locator/app/rewards/privacy/tracking veya doğrulanmamış doküman adayları bulgu değildir.</p>
        <h4>Reddedilen contact adayları</h4>
        <table>
          <tr><th>Aday</th><th>Durum</th><th>Kaynak</th><th>Neden</th></tr>
          {_rejected_candidate_rows(rejected_contacts, value_key='value', empty='Reddedilen contact adayı yok.')}
        </table>
        <h4>Reddedilen sosyal adayları</h4>
        <table>
          <tr><th>Aday</th><th>Durum</th><th>Kaynak</th><th>Neden</th></tr>
          {_rejected_candidate_rows(rejected_social, value_key='profile_url', empty='Reddedilen sosyal aday yok.')}
        </table>
        <h4>Reddedilen doküman adayları</h4>
        <table>
          <tr><th>Aday</th><th>Durum</th><th>Kaynak</th><th>Neden</th></tr>
          {_rejected_candidate_rows(rejected_documents, value_key='url', empty='Reddedilen doküman adayı yok.')}
        </table>
        <h4>Duplicate / bastırılmış contact adayları</h4>
        <table>
          <tr><th>Aday</th><th>Durum</th><th>Kaynak</th><th>Neden</th></tr>
          {_rejected_candidate_rows(suppressed_contacts, value_key='contact_endpoint', empty='Duplicate veya bastırılmış contact adayı yok.')}
        </table>
      </details>
      <details class="show-more" open>
        <summary>Filtrelenen organizasyon path'leri için teşhis ({_html_escape(len(filtered_pages))})</summary>
        <p class="operator-view-note">404, soft-error, unexpected-content, timeout/error ve duplicate satırları yalnızca teşhistir. Ana tablolarda aksiyon alınacak sayfa linki olarak gösterilmez.</p>
        <table>
          <tr><th>Sayfa tipi</th><th>İstenen URL</th><th>Durum</th><th>HTTP</th><th>Final URL</th><th>Red nedeni</th><th>Anlamı</th></tr>
          {_filtered_page_rows(filtered_pages)}
        </table>
        <h4>Bastırılan Contact'lar</h4>
        <table>
          <tr><th>İletişim endpoint'i</th><th>Durum</th><th>Bastırma nedeni</th></tr>
          {_suppressed_contact_rows(suppressed_contacts)}
        </table>
      </details>
    """


def _historical_url_context_html(rows: list[Any]) -> str:
    html_rows: list[str] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        html_rows.append(
            "<tr>"
            f"<td><code>{_html_escape(item.get('url') or '-')}</code><br><span class=\"muted\">Arşiv URL adayı; mevcut maruziyet değildir.</span></td>"
            f"<td>{_html_escape(item.get('status') or 'historical_context')}</td>"
            f"<td>{_html_escape(_url_status_label(item.get('url_status') or 'archived_not_live_checked'))}</td>"
            f"<td>{_html_escape(str(bool(item.get('observed_signal'))).lower())}</td>"
            f"<td>{_html_escape(item.get('verdict_contribution') or 'historical_context_only')}</td>"
            "</tr>"
        )
    return f"""
      <span id="osint-historical-url-context"></span>
      <h3>Geçmiş URL Bağlamı</h3>
      <p class="operator-view-note"><strong>Arşiv URL adayı; mevcut maruziyet değildir.</strong> Bu Wayback/CDX URL'leri canlı fetch edilip doğrulanmadı, bu yüzden gözlemlenen OSINT kanıtı değildir.</p>
      <table>
        <tr><th>Arşiv URL adayı</th><th>Durum</th><th>URL durumu</th><th>Gözlemlenmiş sinyal</th><th>Verdict katkısı</th></tr>
        {''.join(html_rows) or '<tr><td colspan="5">Geçmiş URL adayı yok.</td></tr>'}
      </table>
    """


def _organization_intelligence_html(organization: dict[str, Any]) -> str:
    if not organization:
        return """
      <h3 id="osint-organization-intelligence">Organizasyon İstihbaratı</h3>
      <p class="operator-view-note">Bu OSINT payload'u için organizasyon istihbaratı üretilmedi.</p>
        """
    org_summary = _as_dict(organization.get("summary"))
    security_txt = _as_dict(organization.get("security_txt"))
    email_intel = _as_dict(organization.get("email_intelligence"))
    email_summary = _as_dict(email_intel.get("email_summary"))
    mx_summary_value = (
        "Kontrol edilmedi"
        if str(email_intel.get("mx_status") or "") == "dependency_missing"
        else str(org_summary.get("mx_records_count", email_summary.get("mx_records_count", 0)))
    )
    pages = _as_list(organization.get("official_pages"))
    normal_pages = [
        page
        for page in pages
        if isinstance(page, dict)
        and page.get("page_found")
        and str(page.get("url_status") or "") not in {"checked_soft_error", "checked_unexpected_content"}
        and str(page.get("page_type") or "") not in {"security_txt", "robots", "sitemap"}
    ]
    special_pages = [
        page
        for page in pages
        if isinstance(page, dict)
        and page.get("page_found")
        and str(page.get("page_type") or "") in {"security_txt", "robots", "sitemap"}
    ]
    return f"""
      <h3 id="osint-organization-intelligence">Organizasyon İstihbaratı</h3>
      <p class="operator-view-note"><strong>Sadece pasif organizasyon bağlamı.</strong> Organizasyon sayfaları, contact'lar, gözlemlenen sosyal/profil linkleri, konumlar ve herkese açık dokümanlar zafiyet kanıtı değildir ve risk skorunu etkilemez. Manuel/API-gerekli kısayollar yalnızca manuel öneri teşhisi olarak gösterilir.</p>
      <p class="operator-view-note">
        ReconBot {_html_escape(org_summary.get('official_pages_checked', 0))} resmî URL kontrol etti.
        {_html_escape(org_summary.get('official_pages_found', 0))} sayfa bulundu.
        {_html_escape(org_summary.get('official_pages_soft_error', 0))} soft-error sayfası reddedildi.
        {_html_escape(org_summary.get('official_pages_not_found', 0))} sayfa bulunamadı.
        security.txt {_html_escape('bulundu' if org_summary.get('security_txt_found') else 'bulunamadı')}.
        Tam hedef herkese açık iletişim bilgisi: {_html_escape(org_summary.get('target_observed_public_contacts', org_summary.get('observed_public_contacts', 0)))}.
        Üst kurum herkese açık iletişim bilgisi: {_html_escape(org_summary.get('parent_org_observed_public_contacts', 0))}.
        Üretilen contact guess: {_html_escape(org_summary.get('generated_contact_guesses', email_summary.get('generated_role_guesses_count', 0)))}.
        Geçmiş URL adayları varsa ayrı gösterilir.
        Manuel/API-gerekli kısayollar yalnızca manuel öneri teşhisidir.
      </p>
      <h4>Organizasyon Bağlam Özeti</h4>
      <table>
        <tr><th>Hedef host</th><td><code>{_html_escape(organization.get('target_host') or '-')}</code></td></tr>
        <tr><th>Registered domain</th><td><code>{_html_escape(organization.get('target_registered_domain') or '-')}</code></td></tr>
        <tr><th>Üretilen brand alias'ları</th><td>{_html_escape(', '.join(str(item) for item in _as_list(organization.get('brand_aliases'))) or '-')}</td></tr>
        <tr><th>Kontrol edilen/bulunan resmî sayfalar</th><td>{_html_escape(org_summary.get('official_pages_checked', 0))} / {_html_escape(org_summary.get('official_pages_found', 0))}</td></tr>
        <tr><th>Soft-error / bulunamadı / unexpected / duplicate resmî sayfalar</th><td>{_html_escape(org_summary.get('official_pages_soft_error', 0))} / {_html_escape(org_summary.get('official_pages_not_found', 0))} / {_html_escape(org_summary.get('official_pages_unexpected_content', 0))} / {_html_escape(org_summary.get('official_pages_duplicates', 0))}</td></tr>
        <tr><th>Forbidden resmî sayfalar</th><td>{_html_escape(org_summary.get('official_pages_forbidden', 0))}</td></tr>
        <tr><th>security.txt kontrolü</th><td>{_html_escape(org_summary.get('security_txt_checked', 0))}</td></tr>
        <tr><th>security.txt bulundu</th><td>{_html_escape('evet' if org_summary.get('security_txt_found') else 'hayır')}</td></tr>
        <tr><th>robots/sitemap bulundu</th><td>{_html_escape(org_summary.get('robots_found', 0))} / {_html_escape(org_summary.get('sitemap_found', 0))}</td></tr>
        <tr><th>Auto/manual/API/generated URL sayıları</th><td>{_html_escape(org_summary.get('auto_checked_urls', 0))} / {_html_escape(org_summary.get('manual_only_urls', 0))} / {_html_escape(org_summary.get('api_required_urls', 0))} / {_html_escape(org_summary.get('generated_candidate_urls', 0))}</td></tr>
        <tr><th>Üretilen role contact guess</th><td>{_html_escape(org_summary.get('generated_contact_guesses', email_summary.get('generated_role_guesses_count', 0)))}</td></tr>
        <tr><th>Gözlemlenen herkese açık iletişim bilgisi (legacy toplam)</th><td>{_html_escape(org_summary.get('observed_public_contacts', 0))}</td></tr>
        <tr><th>Tam hedef / üst kurum / bağlı-harici resmî iletişim bilgisi</th><td>{_html_escape(org_summary.get('target_observed_public_contacts', 0))} / {_html_escape(org_summary.get('parent_org_observed_public_contacts', 0))} / {_html_escape(org_summary.get('affiliate_observed_public_contacts', 0))}</td></tr>
        <tr><th>Target / parent telefon numarası</th><td>{_html_escape(org_summary.get('target_observed_phone_numbers', 0))} / {_html_escape(org_summary.get('parent_org_observed_phone_numbers', 0))}</td></tr>
        <tr><th>MX record / bastırılan contact</th><td>{_html_escape(mx_summary_value)} / {_html_escape(org_summary.get('suppressed_contacts_count', email_summary.get('suppressed_contacts_count', 0)))}</td></tr>
        <tr><th>Lookup görevleri</th><td>{_html_escape(org_summary.get('organization_lookup_tasks', 0))}</td></tr>
        <tr><th>Herkese açık doküman arama görevleri</th><td>{_html_escape(org_summary.get('public_document_search_tasks', 0))}</td></tr>
        <tr><th>Konum ipuçları</th><td>{_html_escape(org_summary.get('location_hints', 0))}</td></tr>
        <tr><th>Gözlemlenen konumlar (legacy toplam)</th><td>{_html_escape(org_summary.get('observed_locations', 0))}</td></tr>
        <tr><th>Target / parent konumları</th><td>{_html_escape(org_summary.get('target_observed_locations', 0))} / {_html_escape(org_summary.get('parent_org_observed_locations', 0))}</td></tr>
        <tr><th>Doğrulanmış herkese açık dokümanlar (legacy toplam)</th><td>{_html_escape(org_summary.get('validated_public_documents', 0))}</td></tr>
        <tr><th>Tam hedef / üst kurum / bağlı-harici resmî herkese açık dokümanlar</th><td>{_html_escape(org_summary.get('target_validated_public_documents', 0))} / {_html_escape(org_summary.get('parent_org_validated_public_documents', 0))} / {_html_escape(org_summary.get('affiliate_validated_public_documents', 0))}</td></tr>
        <tr><th>Gözlemlenen resmî sosyal profil (legacy toplam)</th><td>{_html_escape(org_summary.get('observed_official_social_profiles', 0))}</td></tr>
        <tr><th>Target / parent / affiliate sosyal profil</th><td>{_html_escape(org_summary.get('target_observed_social_profiles', 0))} / {_html_escape(org_summary.get('parent_org_observed_social_profiles', 0))} / {_html_escape(org_summary.get('affiliate_observed_social_profiles', 0))}</td></tr>
      </table>
      <h4>Geçerli Kontrol Edilmiş Sayfalar</h4>
      <table>
        <tr><th>Sayfa tipi</th><th>URL</th><th>Durum</th><th>HTTP</th><th>Final URL</th><th>Başlık</th><th>Anlamı</th></tr>
        {_organization_official_page_rows(normal_pages)}
      </table>
      <h4>Security.txt / Robots / Sitemap</h4>
      <table>
        <tr><th>Sayfa tipi</th><th>URL</th><th>Durum</th><th>HTTP</th><th>Final URL</th><th>Başlık</th><th>Anlamı</th></tr>
        {_organization_official_page_rows(special_pages)}
      </table>
      {_security_txt_html(security_txt)}
    """


def _known_breach_rows(signals: list[Any]) -> str:
    rows: list[str] = []
    for item in signals:
        if not isinstance(item, dict) or str(item.get("category") or "") != "known_breach_reference":
            continue
        source_url = str(item.get("source_url") or "").strip()
        source_html = _html_escape(item.get("source_provider") or item.get("source_name") or "")
        if source_url and _render_clickable(item, source_url, role="observed_evidence_link", status=str(item.get("url_status") or "not_checked")):
            source_html = f'<a href="{_html_escape(source_url)}" target="_blank" rel="noopener noreferrer" data-browser-safe="true">{source_html}</a>'
        data_classes = _display_data_classes(item.get("compromised_data_classes"))
        rows.append(
            "<tr>"
            f"<td><strong>{_html_escape(_display_breach_reference_sentence(item))}</strong><br><span class=\"muted\">Eşleşen alias: {_html_escape(item.get('matched_alias'))}</span></td>"
            f"<td>{source_html}</td>"
            f"<td>{_html_escape(item.get('confidence'))}<br><span class=\"muted\">{_html_escape(_display_text(item.get('confidence_reason')))}</span></td>"
            f"<td>{_html_escape(item.get('breach_date') or '-')}</td>"
            f"<td>{_html_escape(item.get('added_date') or '-')}</td>"
            f"<td>{_html_escape(item.get('affected_accounts') or '-')}</td>"
            f"<td>{_html_escape(data_classes or '-')}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="7">Üretilen alias değerleriyle güvenilir herkese açık ihlal kataloğu referansı eşleşmedi.</td></tr>'


def _leak_reference_rows(results: list[Any]) -> str:
    rows: list[str] = []
    grouped: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for result in results:
        if not isinstance(result, dict):
            continue
        for reference in _as_list(result.get("observed_references")):
            if not isinstance(reference, dict):
                continue
            source_label = str(reference.get("source_provider") or result.get("source_name") or "unknown_source")
            grouped.setdefault(source_label, []).append((result, reference))
    for source_label in sorted(grouped):
        rows.append(
            f'<tr><td colspan="10"><strong>{_html_escape(source_label)}</strong><br><span class="muted">Sadece-metadata dış referanslar kaynak sağlayıcısına/kaynak adına göre gruplanır. Bu aktif bir zafiyet bulgusu değildir.</span></td></tr>'
        )
        for result, reference in grouped[source_label]:
            reference_url = str(reference.get("reference_url") or "").strip()
            title = str(reference.get("title") or "Herkese açık ihlal metadata referansı")
            result_note = ""
            if str(result.get("source_type") or "") == "leak_metadata_api":
                result_note = '<br><span class="muted">Metadata feed sonucu. Bu aktif bir zafiyet bulgusu değildir.</span>'
            url_html = "-"
            if reference_url and bool(reference.get("browser_safe")) and bool(reference.get("render_as_clickable")):
                url_html = f'<a href="{_html_escape(reference_url)}" target="_blank" rel="noopener noreferrer" data-browser-safe="true">{_html_escape(reference_url)}</a>'
            elif reference_url:
                url_html = f"<code>{_html_escape(reference_url)}</code>"
            matched = _as_dict(reference.get("matched_entities"))
            matched_alias = str(matched.get("matched_alias") or "").strip()
            if not matched_alias:
                domains = [str(item) for item in _as_list(matched.get("domains")) if str(item or "").strip()]
                keywords = [str(item) for item in _as_list(matched.get("keywords")) if str(item or "").strip()]
                brands = [str(item) for item in _as_list(matched.get("brands")) if str(item or "").strip()]
                matched_values = [str(item) for item in _as_list(matched.get("matched")) if str(item or "").strip()]
                matched_alias = next(iter(matched_values + domains + brands + keywords), "")
            data_classes = _display_data_classes(reference.get("compromised_data_classes"))
            source_text = str(reference.get("source_provider") or result.get("source_name") or "")
            source_name = str(result.get("source_name") or "")
            if source_name and source_name != source_text:
                source_text = f"{source_text} / {source_name}" if source_text else source_name
            provider_id = str(reference.get("provider_id") or _as_dict(result.get("source_health_row")).get("provider_id") or "")
            provider_display = str(reference.get("provider_display_name") or _as_dict(result.get("source_health_row")).get("provider_display_name") or "")
            provider_detail = ""
            if provider_id or provider_display:
                provider_detail = (
                    f"<br><span class=\"muted\">Sağlayıcı: {_html_escape(provider_display or '-')} "
                    f"(<code>{_html_escape(provider_id or '-')}</code>)</span>"
                )
            rows.append(
                "<tr>"
                f"<td><strong>{_html_escape(title)}</strong><br><span class=\"muted\">{_html_escape(_display_reference_snippet(reference))}</span>{result_note}</td>"
                f"<td>{_html_escape(source_text)}{provider_detail}</td>"
                f"<td>{url_html}</td>"
                f"<td>{_html_escape(reference.get('confidence') or '-')}<br><span class=\"muted\">{_html_escape(_display_text(reference.get('confidence_reason')))}</span></td>"
                f"<td>{_html_escape(reference.get('match_type') or '-')}<br><span class=\"muted\">Eşleşen: {_html_escape(matched_alias or '-')}</span></td>"
                f"<td>{_html_escape(reference.get('affected_accounts') or '-')}</td>"
                f"<td>{_html_escape(reference.get('breach_date') or reference.get('published_at') or reference.get('added_date') or '-')}</td>"
                f"<td>{_html_escape(data_classes or '-')}</td>"
                f"<td>{_html_escape(_display_text(reference.get('scope_caveat')))}<br><span class=\"muted\">Kapsam: {_html_escape(reference.get('scope_origin') or '-')} | target ile ilişki: {_html_escape(reference.get('applies_to_target') or 'unknown')}</span></td>"
                f"<td>{_html_escape(_display_recommended_action(reference.get('recommended_action')))}</td>"
                "</tr>"
            )
    return "".join(rows) or '<tr><td colspan="10">Açık kaynaklardan herkese açık ihlal/sızıntı metadata referansı gözlemlenmedi.<br>Bu, sızıntı olmadığı anlamına kesin olarak gelmez.</td></tr>'


def _leak_source_health_rows(rows_data: list[Any]) -> str:
    rows: list[str] = []
    for row in rows_data:
        if not isinstance(row, dict):
            continue
        status = str(row.get("source_status") or row.get("status") or "")
        source = str(row.get("source") or "")
        collector_name = str(row.get("collector_name") or row.get("collector") or "")
        provider_display = str(row.get("provider_display_name") or "")
        provider_id = str(row.get("provider_id") or "")
        source_mode = str(row.get("source_mode") or row.get("feed_source_type") or "")
        source_html = f"<code>{_html_escape(source)}</code>"
        if collector_name and collector_name != source:
            source_html += f'<br><span class="muted">collector: <code>{_html_escape(collector_name)}</code></span>'
        validation_status = str(row.get("provider_validation_status") or "-")
        security_contract = "Metadata-only; kimlik bilgisi, dump ve ham içerik yasak."
        records = (
            f"Yüklenen: {row.get('items_loaded_count', 0)} | "
            f"Eşleşen: {row.get('items_matched_count', 0)} | "
            f"Bastırılan: {row.get('items_suppressed_count', 0)}"
        )
        rows.append(
            "<tr>"
            f"<td>{_html_escape(provider_display or '-')}</td>"
            f"<td><code>{_html_escape(provider_id or '-')}</code></td>"
            f"<td>{source_html}</td>"
            f"<td><code>{_html_escape(source_mode or '-')}</code></td>"
            f"<td><span class=\"pill {_html_escape(_status_tone(str(row.get('status') or ''), source_name=source))}\">{_html_escape(_plain_status_label(status))}</span><br><span class=\"muted\"><code>{_html_escape(status or '-')}</code></span></td>"
            f"<td>{_html_escape(security_contract)}<br><span class=\"muted\">Doğrulama: {_html_escape(_display_status_label(validation_status))}. {_html_escape(_display_runtime_message(row.get('provider_validation_message')))}</span></td>"
            f"<td>{_html_escape(records)}</td>"
            f"<td>{_html_escape(_display_runtime_message(row.get('user_message') or row.get('error') or ''))}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="8">Sızıntı kaynağı collector sağlık satırı üretilmedi.</td></tr>'


def _leak_result_status(results: list[Any], source_name: str) -> str:
    for result in results:
        if isinstance(result, dict) and str(result.get("source_name") or "") == source_name:
            return str(result.get("status") or "")
    if source_name == "leak_metadata_feed":
        for result in results:
            if isinstance(result, dict) and str(result.get("source_type") or "") == "leak_metadata_api":
                return str(result.get("status") or "")
    return "not_configured" if source_name == "leak_metadata_feed" else "not_checked"


def _leak_health_message(health_rows: list[Any], source_name: str) -> str:
    for row in health_rows:
        if isinstance(row, dict) and str(row.get("source") or "") == source_name:
            return str(row.get("user_message") or row.get("error") or "")
    if source_name == "leak_metadata_feed":
        for row in health_rows:
            if isinstance(row, dict) and str(row.get("source") or "") != "known_breach_catalog":
                return str(row.get("user_message") or row.get("error") or "")
    return ""


def _metadata_feed_status_message(status: str, fallback_message: str = "") -> str:
    normalized = str(status or "").strip()
    if normalized == "completed":
        return "Metadata feed bu çalıştırmada açık ve başarıyla kontrol edildi."
    if normalized == "disabled":
        return "Metadata feed sağlayıcısı kurulu ama kapalı."
    if normalized == "not_configured":
        return "Metadata feed açık ama feedPath/feedUrl yapılandırılmamış."
    if normalized == "no_match":
        return "Metadata feed bu çalıştırmada açık ve başarıyla kontrol edildi; eşleşen metadata referansı görülmedi."
    if normalized == "invalid_config":
        return "Provider ayarı geçersiz. Ağ veya dosya erişimi yapılmadı."
    if normalized == "not_implemented":
        return "Seçilen metadata feed provider profili henüz uygulanmadı. Ağ veya dosya erişimi yapılmadı."
    if normalized == "auth_required":
        return _display_runtime_message(fallback_message) or "Metadata feed kimlik doğrulama gerektiriyor."
    if normalized == "timeout":
        return _display_runtime_message(fallback_message) or "Metadata feed zaman aşımına uğradı."
    if normalized == "provider_unavailable":
        return _display_runtime_message(fallback_message) or "Metadata feed sağlayıcısına erişilemedi."
    if normalized == "partial":
        return _display_runtime_message(fallback_message) or "Metadata feed kısmi sonuç üretti."
    if normalized == "error":
        return _display_runtime_message(fallback_message) or "Metadata feed kontrolünde hata oluştu."
    return _display_runtime_message(fallback_message) or "Yalnızca güvenilir metadata-only feed için osint.leakSources.metadataFeed yapılandır."


def _darkweb_reference_rows(references: list[Any]) -> str:
    rows: list[str] = []
    for reference in references:
        if not isinstance(reference, dict):
            continue
        reference_url = str(reference.get("reference_url") or "").strip()
        if reference_url and bool(reference.get("browser_safe")) and bool(reference.get("render_as_clickable")):
            url_html = f'<a href="{_html_escape(reference_url)}" target="_blank" rel="noopener noreferrer" data-browser-safe="true">{_html_escape(reference_url)}</a>'
        elif reference_url:
            url_html = f"<code>{_html_escape(reference_url)}</code><br><span class=\"muted\">clickable değil</span>"
        else:
            url_html = "-"
        data_classes = _display_data_classes(reference.get("data_classes"))
        matched = _as_dict(reference.get("matched_entities"))
        matched_values = [str(item) for item in _as_list(matched.get("matched")) if str(item or "").strip()]
        domains = [str(item) for item in _as_list(matched.get("domains")) if str(item or "").strip()]
        brands = [str(item) for item in _as_list(matched.get("brands")) if str(item or "").strip()]
        matched_text = ", ".join(matched_values + domains + brands) or "-"
        source_name = str(reference.get("source_name") or "")
        provider = str(reference.get("source_provider") or "")
        provider_text = provider if not source_name or source_name == provider else f"{provider} / {source_name}"
        affected = reference.get("affected_accounts")
        affected_note = f" | etkilenen hesap: {affected}" if affected not in ("", None) else ""
        scope = f"{reference.get('scope_origin') or '-'} | target: {reference.get('applies_to_target', 'unknown')}{affected_note}"
        reference_note = "Bu aktif bir zafiyet bulgusu değildir."
        if str(reference.get("source_channel") or "") in {"darkweb_metadata_index", "manual_import", "trusted_metadata_provider"}:
            reference_note = "Metadata feed sonucu. Bu aktif bir zafiyet bulgusu değildir."
        elif str(reference.get("source_channel") or "") == "public_breach_catalog":
            reference_note = "Metadata-only public breach catalog adapter. Bu aktif bir zafiyet bulgusu değildir."
        rows.append(
            "<tr>"
            f"<td><strong>{_html_escape(reference.get('title') or 'Darkweb metadata referansı')}</strong><br><span class=\"muted\">{_html_escape(reference_note)}</span></td>"
            f"<td>{_html_escape(provider_text or '-')}<br><span class=\"muted\">{_html_escape(reference.get('source_channel') or '-')}</span></td>"
            f"<td>{url_html}</td>"
            f"<td>{_html_escape(reference.get('confidence') or '-')}<br><span class=\"muted\">{_html_escape(reference.get('confidence_reason_tr') or '')}</span></td>"
            f"<td>{_html_escape(reference.get('match_type') or '-')}<br><span class=\"muted\">Eşleşen: {_html_escape(matched_text)}</span></td>"
            f"<td>{_html_escape(scope)}</td>"
            f"<td>{_html_escape(reference.get('breach_date') or reference.get('published_at') or '-')}</td>"
            f"<td>{_html_escape(data_classes or '-')}</td>"
            f"<td>{_html_escape(reference.get('scope_caveat_tr') or 'Bu metadata referansı hedef sistemde aktif zafiyet olduğu anlamına gelmez.')}<br><span class=\"muted\">{_html_escape(reference.get('recommended_action_tr') or '')}</span></td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="9">Metadata-only darkweb/sızıntı referansı görülmedi. Bu sonuç, kaynak kapsamı kısmi ise kesin temiz anlamına gelmez.</td></tr>'


def _darkweb_source_rows(sources: list[Any]) -> str:
    rows: list[str] = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        status = str(source.get("status") or "")
        metadata_only = "Evet" if bool(source.get("metadata_only")) else "Hayır"
        records = (
            f"Yüklenen: {source.get('items_loaded_count', 0)} | "
            f"Eşleşen: {source.get('items_matched_count', 0)} | "
            f"Bastırılan: {source.get('items_suppressed_count', 0)}"
        )
        source_detail = f"{_html_escape(source.get('display_name_tr') or source.get('source_id') or '-')}"
        source_detail += f"<br><span class=\"muted\"><code>{_html_escape(source.get('source_id') or '-')}</code></span>"
        collector_name = str(source.get("collector_name") or "")
        if collector_name:
            source_detail += f"<br><span class=\"muted\">collector: <code>{_html_escape(collector_name)}</code></span>"
        runtime_source_name = str(source.get("runtime_source_name") or "")
        if runtime_source_name and runtime_source_name != str(source.get("source_id") or ""):
            source_detail += f"<br><span class=\"muted\">source: <code>{_html_escape(runtime_source_name)}</code></span>"
        provider_message = _display_text(source.get("provider_validation_message"))
        meaning = str(source.get("user_message_tr") or "-")
        if provider_message:
            meaning = f"{meaning} {provider_message}"
        rows.append(
            "<tr>"
            f"<td>{source_detail}</td>"
            f"<td>{_html_escape(source.get('source_type') or '-')}</td>"
            f"<td><span class=\"pill {_html_escape(_status_tone(status, source_name=str(source.get('source_id') or '')))}\">{_html_escape(_plain_status_label(status))}</span><br><span class=\"muted\"><code>{_html_escape(status or '-')}</code></span></td>"
            f"<td>{metadata_only}</td>"
            f"<td>{_html_escape(_coverage_impact_label(source.get('coverage_impact')))}</td>"
            f"<td>{_html_escape(meaning)}</td>"
            f"<td>{_html_escape(source.get('operator_action_tr') or '-')}</td>"
            f"<td>{_html_escape(records)}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="8">Darkweb metadata source satırı üretilmedi.</td></tr>'


def _darkweb_intelligence_html(darkweb: dict[str, Any]) -> str:
    summary = _as_dict(darkweb.get("summary"))
    sources = _as_list(darkweb.get("sources"))
    references = _as_list(darkweb.get("observed_references"))
    tor = _as_dict(darkweb.get("tor_onion_crawling"))
    observed = _safe_int(summary.get("observed_references"))
    suppressed = _safe_int(summary.get("suppressed_sensitive_items"))
    no_match_note = ""
    if observed == 0:
        no_match_note = '<p class="operator-view-note warning">Metadata-only darkweb/sızıntı referansı görülmedi. Bu, sızıntı olmadığı anlamına kesin olarak gelmez. Bu sonuç, kaynak kapsamı kısmi ise kesin temiz anlamına gelmez. Bu aktif bir zafiyet bulgusu değildir.</p>'
    return f"""
      <h3 id="osint-leak-breach-intelligence">Darkweb / Sızıntı / İhlal İstihbaratı</h3>
      <p class="operator-view-note"><strong>Sadece metadata. Tor/onion taraması yok. Kimlik bilgisi veya dump toplanmadı.</strong><br>Bu bölüm darkweb/leak/breach tarafında yalnızca metadata-only kaynakları gösterir. ReconBot Tor/onion crawling yapmaz, credential/dump/raw leak toplamaz ve credential doğrulaması yapmaz.</p>
      <div class="kpi-grid overview-core-grid">
        <div class="kpi"><div class="label">Metadata-only kaynaklar</div><div class="value">{_html_escape(summary.get('metadata_sources_checked', 0))}</div><div class="note">Kontrol edilen güvenli metadata kaynağı.</div></div>
        <div class="kpi"><div class="label">Gözlemlenen referans</div><div class="value">{_html_escape(observed)}</div><div class="note">Metadata referansı; aktif zafiyet değildir.</div></div>
        <div class="kpi"><div class="label">Tor/onion crawling</div><div class="value">{_html_escape(_plain_status_label(tor.get('status') or 'not_supported'))}</div><div class="note">Tor/onion crawling yapılmadı.</div></div>
        <div class="kpi"><div class="label">Toplanan kimlik bilgisi</div><div class="value">Yok</div><div class="note">Kimlik bilgisi veya dump toplanmadı.</div></div>
        <div class="kpi"><div class="label">Toplanan dump</div><div class="value">Yok</div><div class="note">Raw dump saklanmadı.</div></div>
        <div class="kpi"><div class="label">Toplanan ham sızıntı kaydı</div><div class="value">Yok</div><div class="note">Ham kayıt toplanmadı veya saklanmadı.</div></div>
        <div class="kpi"><div class="label">Credential doğrulama</div><div class="value">Yok</div><div class="note">Credential doğrulaması yapılmadı.</div></div>
        <div class="kpi"><div class="label">Bastırılan hassas içerik</div><div class="value">{_html_escape(suppressed)}</div><div class="note">Sadece kategori marker'ı saklanır.</div></div>
        <div class="kpi"><div class="label">Risk skoru etkisi</div><div class="value">Yok</div><div class="note">Metadata-only referanslar risk skorunu artırmaz.</div></div>
      </div>
      {no_match_note}
      <p class="operator-view-note"><strong>Tor/onion crawling yapılmadı:</strong> {_html_escape(tor.get('user_message_tr') or 'Tor/onion crawling desteklenmiyor ve bu çalıştırmada yapılmadı.')}</p>
      <p class="operator-view-note"><strong>Güvenlik sınırı:</strong> {_html_escape(darkweb.get('safety_boundary_tr') or '')}</p>
      <h4>Kaynak kapsamı</h4>
      <table>
        <tr><th>Kaynak</th><th>Tür</th><th>Durum</th><th>Metadata-only</th><th>Kapsam etkisi</th><th>Ne anlama geliyor?</th><th>Operatör aksiyonu</th><th>Kayıtlar</th></tr>
        {_darkweb_source_rows(sources)}
      </table>
      <h4>Gözlemlenen dış referanslar</h4>
      <table>
        <tr><th>Başlık</th><th>Kaynak / Sağlayıcı</th><th>Referans</th><th>Güven</th><th>Eşleşme tipi</th><th>Kapsam</th><th>İhlal / yayın tarihi</th><th>Veri sınıfları</th><th>Not / Aksiyon</th></tr>
        {_darkweb_reference_rows(references)}
      </table>
    """


def _leak_intelligence_html(leak_intelligence: dict[str, Any], darkweb_intelligence: dict[str, Any] | None = None) -> str:
    if darkweb_intelligence:
        return _darkweb_intelligence_html(darkweb_intelligence)
    if not leak_intelligence:
        leak_intelligence = {
            "enabled": False,
            "status": "disabled",
            "live_collection_performed": False,
            "summary": {},
            "results": [],
            "source_health": [],
        }
    summary = _as_dict(leak_intelligence.get("summary"))
    results = _as_list(leak_intelligence.get("results"))
    health_rows = _as_list(leak_intelligence.get("source_health"))
    suppressed_count = _safe_int(summary.get("suppressed_sensitive_items"))
    observed_references = _safe_int(summary.get("observed_references"))
    enabled_collectors_count = _safe_int(leak_intelligence.get("enabled_collectors_count"))
    known_status = _leak_result_status(results, "known_breach_catalog")
    metadata_status = _leak_result_status(results, "leak_metadata_feed")
    metadata_message = _metadata_feed_status_message(metadata_status, _leak_health_message(health_rows, "leak_metadata_feed"))
    no_match_note = ""
    if observed_references == 0:
        no_match_note = '<p class="operator-view-note warning">Açık kaynaklardan herkese açık ihlal/sızıntı metadata referansı gözlemlenmedi. Bu, sızıntı olmadığı anlamına kesin olarak gelmez.</p>'
    safety_boundary = str(
        leak_intelligence.get("safety_boundary")
        or "ReconBot kimlik bilgisi, parola, hash, token, private key, session cookie, raw dump veya ham sızıntı kaydı toplamadı. Sızıntı kaynaklarından gelen sonuçlar sadece metadata'dır ve kurumla ilişkisi manuel doğrulanmalıdır."
    )
    return f"""
      <h3 id="osint-leak-breach-intelligence">Darkweb / Sızıntı / İhlal İstihbaratı</h3>
      <p class="operator-view-note"><strong>Sadece metadata. Tor/onion taraması yok. Kimlik bilgisi veya dump toplanmadı.</strong><br>Sadece metadata. Tor/onion taraması yok. Kimlik bilgisi, dump veya ham sızıntı kaydı toplanmaz. Bu bölüm aktif zafiyet kanıtı olarak yorumlanmamalıdır.</p>
      <div class="kpi-grid overview-core-grid">
        <div class="kpi">
          <div class="label">Herkese açık ihlal kataloğu</div>
          <div class="value">{_html_escape(_plain_status_label(known_status or 'not_checked'))}</div>
          <div class="note">Herkese açık katalog metadata kontrolü; kimlik bilgisi veya dump toplanmaz.</div>
        </div>
        <div class="kpi">
          <div class="label">Metadata feed sağlayıcısı</div>
          <div class="value">{_html_escape(_plain_status_label(metadata_status))}</div>
          <div class="note">{_html_escape(metadata_message or 'Yalnızca güvenilir metadata-only feed yapılandırılmalıdır.')}</div>
        </div>
        <div class="kpi">
          <div class="label">Tor/onion taraması</div>
          <div class="value">Yok</div>
          <div class="note">Tor/onion taraması yok. Darkweb index collector yapılandırılmadı.</div>
        </div>
        <div class="kpi">
          <div class="label">Toplanan kimlik bilgisi</div>
          <div class="value">Yok</div>
          <div class="note">Parola, hash, token, API key, private key, session cookie veya hesap kaydı toplanmadı.</div>
        </div>
        <div class="kpi">
          <div class="label">Toplanan dump</div>
          <div class="value">Yok</div>
          <div class="note">Dump, paste raw content veya ham sızıntı kaydı toplanmadı.</div>
        </div>
        <div class="kpi">
          <div class="label">Kimlik bilgisi doğrulama</div>
          <div class="value">Yok</div>
          <div class="note">Sızmış kimlik bilgisi test edilmez veya doğrulanmaz.</div>
        </div>
        <div class="kpi">
          <div class="label">Gözlemlenen referans</div>
          <div class="value">{_html_escape(observed_references)}</div>
          <div class="note">Metadata referansı; aktif zafiyet bulgusu değildir.</div>
        </div>
        <div class="kpi">
          <div class="label">Bastırılan hassas içerik</div>
          <div class="value">{_html_escape(suppressed_count)}</div>
          <div class="note">Sadece kategori marker'ı olarak tutulur.</div>
        </div>
        <div class="kpi">
          <div class="label">Risk skoru etkisi</div>
          <div class="value">Yok</div>
          <div class="note">Bu aktif bir zafiyet bulgusu değildir ve risk skorunu artırmaz.</div>
        </div>
        <div class="kpi">
          <div class="label">Açık collector sayısı</div>
          <div class="value">{_html_escape(enabled_collectors_count)}</div>
          <div class="note">Kapalı/yapılandırılmamış collector'lar bulgu değil, kaynak kapsamıdır.</div>
        </div>
      </div>
      {no_match_note}
      <h4>Gözlemlenen dış referanslar</h4>
      <table>
        <tr><th>Başlık</th><th>Kaynak / provider</th><th>Referans URL</th><th>Güven</th><th>Eşleşen varlık</th><th>Etkilenen hesap</th><th>İhlal / yayın tarihi</th><th>Veri sınıfları</th><th>Kapsam notu</th><th>Önerilen aksiyon</th></tr>
        {_leak_reference_rows(results)}
      </table>
      <h4>Sağlayıcı registry ve kaynak kapsamı</h4>
      <table>
        <tr><th>Sağlayıcı</th><th>Provider ID</th><th>Kaynak</th><th>Kaynak modu</th><th>Durum</th><th>Güvenlik sözleşmesi</th><th>Kayıtlar</th><th>Kullanıcı mesajı</th></tr>
        {_leak_source_health_rows(health_rows)}
      </table>
      <p class="operator-view-note"><strong>Güvenlik sınırı:</strong> {_html_escape(_display_runtime_message(safety_boundary))}</p>
      <p class="operator-view-note"><strong>Operatör notu:</strong> Metadata referansı görülürse kurumla gerçekten ilişkili olup olmadığını manuel doğrula; kimlik bilgisi toplama.</p>
    """


def _task_rows(tasks: list[Any]) -> str:
    rows: list[str] = []
    for item in tasks:
        if not isinstance(item, dict):
            continue
        link = str(item.get("link") or "").strip()
        link_html = "-"
        if link and _render_clickable(item, link, role="manual_search_suggestion", status=str(item.get("url_status") or "not_checked")):
            label = str(item.get("link_label") or "").strip() or _manual_task_link_label(item)
            label = _display_manual_lookup_label(label, url_role=item.get("url_role") or "manual_search_suggestion", url=link)
            link_html = (
                f'<a href="{_html_escape(link)}" target="_blank" rel="noopener noreferrer" data-browser-safe="true">{_html_escape(label)}</a>'
                '<br><span class="muted">manuel arama önerisi; doğrulanmış bulgu değil</span>'
            )
        elif link:
            link_html = f"<code>{_html_escape(link)}</code><br><span class=\"muted\">kanıt linki olarak gösterilmedi</span>"
        rows.append(
            "<tr>"
            f"<td>{_html_escape(item.get('source_name'))}</td>"
            f'<td><span class="pill muted">{_html_escape(_plain_status_label(item.get("status") or "suggestion_only"))}</span></td>'
            f'<td><span class="pill muted">{_html_escape(item.get("quality", "medium_signal"))}</span></td>'
            f"<td>{_html_escape(item.get('category', 'general'))}<br><span class=\"muted\">scope: {_html_escape(item.get('query_scope') or 'exact_host')}</span></td>"
            f"<td><code>{_html_escape(item.get('query'))}</code></td>"
            f"<td>{link_html}</td>"
            f"<td>{_html_escape(_display_text(item.get('purpose')))}</td>"
            f"<td>{_html_escape(_display_text(item.get('safety_note')))}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="8">Manuel arama önerisi üretilmedi.</td></tr>'


def _manual_task_link_label(item: dict[str, Any]) -> str:
    source = str(item.get("source_name") or "").strip().lower()
    category = str(item.get("category") or "").strip().lower()
    query = str(item.get("query") or "").strip().lower()
    if source == "public_code_search":
        if ".env" in query:
            return "GitHub .env aramasını aç"
        if "filename:config" in query or "config" in query:
            return "GitHub config aramasını aç"
        return "GitHub code search aç"
    if source == "safe_search_dorks":
        if category == "api_docs":
            return "Google Swagger aramasını aç" if "swagger" in query else "Google API docs aramasını aç"
        if category == "config_terms":
            return "Google config aramasını aç"
        if category == "documents":
            return "Google PDF aramasını aç" if "filetype:pdf" in query else "Google doküman aramasını aç"
        if category == "emails":
            return "Google email-pattern aramasını aç"
        return "Google aramasını aç"
    if source == "known_breach_catalog":
        return "Manuel ihlal kataloğu incelemesini aç"
    return "Manuel arama önerisini aç"


def _task_sort_key(item: Any) -> tuple[int, str, str, str]:
    if not isinstance(item, dict):
        return (99, "", "", "")
    quality = str(item.get("quality") or "").strip().lower()
    category = str(item.get("category") or "").strip().lower()
    query = str(item.get("query") or "")
    source_name = str(item.get("source_name") or "")
    config_code_categories = {"config_terms", "code_search", "config", "code"}
    api_doc_categories = {"api_docs", "api", "docs"}
    if quality == "high_signal" and category in config_code_categories:
        bucket = 0
    elif quality == "high_signal" and category in api_doc_categories:
        bucket = 1
    elif quality == "high_signal":
        bucket = 2
    elif quality == "medium_signal":
        bucket = 3
    elif quality == "noisy":
        bucket = 4
    else:
        bucket = 5
    return (bucket, source_name, category, query)


def _operator_tasks_html(tasks: list[Any]) -> str:
    sorted_tasks = sorted([item for item in tasks if isinstance(item, dict)], key=_task_sort_key)
    if not sorted_tasks:
        return """
      <table>
        <tr><th>Kaynak</th><th>Durum</th><th>Kalite</th><th>Kategori</th><th>Sorgu</th><th>Link</th><th>Amaç</th><th>Güvenlik notu</th></tr>
        <tr><td colspan="8">Manuel arama önerisi üretilmedi.</td></tr>
      </table>
        """
    preview = sorted_tasks[:8]
    rest = sorted_tasks[8:]
    preview_table = f"""
      <table>
        <tr><th>Kaynak</th><th>Durum</th><th>Kalite</th><th>Kategori</th><th>Sorgu</th><th>Link</th><th>Amaç</th><th>Güvenlik notu</th></tr>
        {_task_rows(preview)}
      </table>
    """
    if not rest:
        return preview_table
    return f"""
      {preview_table}
      <details class="show-more">
        <summary>Tüm üretilen görevleri göster ({len(rest)} ek)</summary>
        <table>
          <tr><th>Kaynak</th><th>Durum</th><th>Kalite</th><th>Kategori</th><th>Sorgu</th><th>Link</th><th>Amaç</th><th>Güvenlik notu</th></tr>
          {_task_rows(rest)}
        </table>
      </details>
    """


def _source_status_summary(sources: list[Any]) -> str:
    counts = {
        "completed": 0,
        "completed_matched": 0,
        "partial": 0,
        "error": 0,
        "timeout": 0,
        "unavailable": 0,
        "auth_required_fallback": 0,
        "rate_limited_fallback": 0,
        "suggestions_generated": 0,
        "no_match": 0,
        "completed_no_match": 0,
        "not_executed": 0,
        "skipped": 0,
    }
    for item in sources:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "")
        if status in counts:
            counts[status] += 1
    return (
        f"tamamlandı {counts['completed']} | eşleşti {counts['completed_matched']} | öneri {counts['suggestions_generated']} | "
        f"eşleşme yok {counts['no_match'] + counts['completed_no_match']} | "
        f"auth_required_fallback {counts['auth_required_fallback']} | rate_limited_fallback {counts['rate_limited_fallback']} | "
        f"çalıştırılmadı {counts['not_executed']} | kısmi {counts['partial']} | zaman aşımı {counts['timeout']} | erişilemedi {counts['unavailable']} | hata {counts['error']} | atlandı {counts['skipped']}"
    )


def _source_health_summary_html(sources: list[Any], observed_count: int, manual_count: int) -> str:
    available = 0
    provider_unavailable_count = 0
    timeout_count = 0
    auth_required_fallback_count = 0
    no_match_count = 0
    suggestions_generated_count = 0
    detail_notes: list[str] = []
    provider_rows: list[str] = []
    for item in sources:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "")
        source_name = str(item.get("name") or "")
        if status in {"completed", "completed_matched", "completed_no_match", "no_match"}:
            available += 1
        if status == "auth_required_fallback":
            auth_required_fallback_count += 1
        if status == "suggestions_generated":
            suggestions_generated_count += 1
        if status in {"completed_no_match", "no_match"}:
            no_match_count += 1
        if source_name == "certificate_transparency":
            provider_label = "crt.sh"
            provider_status = status
            provider_http = ""
            for provider in _as_list(item.get("provider_results")):
                if not isinstance(provider, dict):
                    continue
                message = _display_runtime_message(provider.get("user_message") or "")
                if message and message not in detail_notes:
                    detail_notes.append(message)
                provider_name = str(provider.get("provider") or "").strip()
                current_provider_status = str(provider.get("status") or "").strip()
                http_status = str(provider.get("http_status") or "").strip()
                if provider_name == "crt.sh" or not provider_label:
                    provider_label = provider_name or "crt.sh"
                    provider_status = current_provider_status or provider_status
                    provider_http = http_status
                if provider_name and current_provider_status in {"unavailable", "timeout", "error"}:
                    note = f"{provider_name}: {_display_status_label(current_provider_status)}{(' / HTTP ' + http_status) if http_status else ''} / CT kapsamı kısmi."
                    if note not in detail_notes:
                        detail_notes.append(note)
            if provider_status in {"unavailable", "error"}:
                provider_unavailable_count += 1
            if provider_status == "timeout":
                timeout_count += 1
            provider_rows.append(
                "<tr>"
                f"<td><code>crt.sh</code></td>"
                f"<td>{_html_escape(_display_status_label(provider_status or status or 'unknown'))}{_html_escape((' / HTTP ' + provider_http) if provider_http else '')}<br><span class=\"muted\"><code>{_html_escape(provider_status or status or 'unknown')}</code></span></td>"
                "<td>CT kapsamı kısmi</td>"
                "</tr>"
            )
        if source_name == "historical_urls":
            if status == "timeout":
                timeout_count += 1
            note = "Wayback CDX zaman aşımına uğradı; geçmiş URL kapsamı kısmi." if status == "timeout" else ""
            if note and note not in detail_notes:
                detail_notes.append(note)
            provider_rows.append(
                "<tr>"
                "<td><code>Wayback CDX</code></td>"
                f"<td>{_html_escape(_display_status_label(status or 'unknown'))}<br><span class=\"muted\"><code>{_html_escape(status or 'unknown')}</code></span></td>"
                "<td>geçmiş URL kapsamı kısmi</td>"
                "</tr>"
            )
        if source_name == "public_code_search":
            note = "GitHub code search kimlik doğrulama gerektiriyor; manuel öneri üretildi." if status == "auth_required_fallback" else ""
            if note and note not in detail_notes:
                detail_notes.append(note)
            provider_rows.append(
                "<tr>"
                "<td><code>GitHub code search</code></td>"
                f"<td>{_html_escape('Kimlik doğrulama gerekli; manuel öneri üretildi' if status == 'auth_required_fallback' else _display_status_label(status or 'unknown'))}<br><span class=\"muted\"><code>{_html_escape(status or 'unknown')}</code></span></td>"
                "<td>fallback gerektiğinde public code search kapsamı kısmi</td>"
                "</tr>"
            )
        if source_name == "known_breach_catalog":
            note = "HIBP kataloğu kontrol edildi; üretilen alias değerleriyle güvenilir herkese açık ihlal kataloğu referansı eşleşmedi."
            if status in {"completed_no_match", "no_match"} and note not in detail_notes:
                detail_notes.append(note)
            provider_rows.append(
                "<tr>"
                "<td><code>HIBP</code></td>"
                f"<td>{_html_escape(_display_status_label('no_match' if status in {'completed_no_match', 'no_match'} else status or 'unknown'))}<br><span class=\"muted\"><code>{_html_escape('no_match' if status in {'completed_no_match', 'no_match'} else status or 'unknown')}</code></span></td>"
                "<td>sadece herkese açık ihlal kataloğu metadata</td>"
                "</tr>"
            )
        if source_name == "safe_search_dorks":
            provider_rows.append(
                "<tr>"
                "<td><code>safe_search_dorks</code></td>"
                f"<td>{_html_escape(_display_status_label(status or 'unknown'))}<br><span class=\"muted\"><code>{_html_escape(status or 'unknown')}</code></span></td>"
                "<td>Yalnızca operatörün manuel çalıştıracağı güvenli arama önerileri üretildi.</td>"
                "</tr>"
            )
    partial_note = ""
    issue_bits = []
    if provider_unavailable_count:
        issue_bits.append("crt.sh erişilemedi")
    if timeout_count:
        issue_bits.append("Wayback zaman aşımına uğradı")
    if auth_required_fallback_count:
        issue_bits.append("GitHub code search kimlik doğrulama gerektiriyor")
    if issue_bits:
        issue_text = ", ".join(issue_bits[:-1])
        issue_text = f"{issue_text} ve {issue_bits[-1]}" if issue_text else issue_bits[0]
        partial_note = f'<p class="operator-view-note warning">OSINT kapsamı kısmi: {_html_escape(issue_text)}. Kanıt yokluğu kesin sonuç değildir.</p>'
    detail_html = (
        '<p class="operator-view-note">' + _html_escape(" ".join(detail_notes)) + "</p>"
        if detail_notes
        else ""
    )
    return f"""
      <h3 id="osint-source-health-details">Gelişmiş Kaynak Kapsamı Detayları</h3>
      <div class="kpi-grid overview-core-grid">
        <div class="kpi"><div class="label">Kullanılabilir kaynak</div><div class="value">{_html_escape(available)}</div><div class="note">Tamamlanan veya tamamlandı/eşleşme yok dönen kaynaklar.</div></div>
        <div class="kpi"><div class="label">Erişilemeyen sağlayıcı</div><div class="value">{_html_escape(provider_unavailable_count)}</div><div class="note">Sağlayıcı erişilemedi, örn. crt.sh HTTP 502.</div></div>
        <div class="kpi"><div class="label">Zaman aşımı</div><div class="value">{_html_escape(timeout_count)}</div><div class="note">Zaman aşımına uğrayan pasif kaynaklar.</div></div>
        <div class="kpi"><div class="label">Kimlik doğrulama gereken kaynak</div><div class="value">{_html_escape(auth_required_fallback_count)}</div><div class="note">GitHub API auth eksik veya yetkisiz; manuel öneri gerekli.</div></div>
        <div class="kpi"><div class="label">Eşleşme yok</div><div class="value">{_html_escape(no_match_count)}</div><div class="note">Güvenilir eşleşme döndürmeyen tamamlanmış kaynaklar.</div></div>
        <div class="kpi"><div class="label">Üretilen manuel öneri</div><div class="value">{_html_escape(suggestions_generated_count)}</div><div class="note">Sadece öneri üreten kaynak çıktısı.</div></div>
        <div class="kpi"><div class="label">Manuel öneriler</div><div class="value">{_html_escape(manual_count)}</div><div class="note">Manuel arama önerisi; doğrulanmış bulgu değil.</div></div>
        <div class="kpi"><div class="label">Gözlemlenmiş aktif OSINT kanıtı</div><div class="value">{_html_escape(observed_count)}</div><div class="note">Yalnızca doğrulanmış pasif kaynak kanıtı; metadata-only sızıntı/ihlal referansları hariçtir.</div></div>
      </div>
      {partial_note}
      <table>
        <tr><th>Kaynak</th><th>Durum</th><th>Kapsam anlamı</th></tr>
        {''.join(provider_rows) or '<tr><td colspan="3">Kaynak sağlık satırı üretilmedi.</td></tr>'}
      </table>
      {detail_html}
    """


def _diagnostics_html(diagnostics: dict[str, Any]) -> str:
    if not diagnostics:
        return '<p class="operator-view-note">OSINT teşhisi kaydedilmedi.</p>'
    dns = _as_dict(diagnostics.get("dns_resolution"))
    http = _as_dict(diagnostics.get("http_connectivity"))
    runtime_dns = _as_dict(diagnostics.get("dns_runtime"))
    runtime_dns_html = ""
    if runtime_dns and not bool(runtime_dns.get("dns_resolver_import_ok")):
        sys_path_excerpt = runtime_dns.get("sys_path_excerpt")
        if isinstance(sys_path_excerpt, list):
            sys_path_text = " | ".join(str(item) for item in sys_path_excerpt)
        else:
            sys_path_text = str(sys_path_excerpt or "")
        runtime_dns_html = f"""
      <h3>DNS Runtime Self-Check</h3>
      <p class="operator-view-note warning">Bu scan için kullanılan Python runtime içinde DNS resolver bağımlılığı yok.</p>
      <table>
        <tr><th>python_executable</th><td><code>{_html_escape(runtime_dns.get('python_executable') or '-')}</code></td></tr>
        <tr><th>python_version</th><td>{_html_escape(runtime_dns.get('python_version') or '-')}</td></tr>
        <tr><th>dns_resolver_import_ok</th><td>{_html_escape(runtime_dns.get('dns_resolver_import_ok'))}</td></tr>
        <tr><th>dns_resolver_import_error</th><td>{_html_escape(runtime_dns.get('dns_resolver_import_error') or '-')}</td></tr>
        <tr><th>sys.path excerpt</th><td><code>{_html_escape(sys_path_text or '-')}</code></td></tr>
      </table>
        """
    rows: list[str] = []
    for item in _as_list(diagnostics.get("source_health")):
        if not isinstance(item, dict):
            continue
        error_detail = _html_escape(_display_runtime_message(item.get("error")))
        if item.get("error_class"):
            error_detail += f'<br><span class="muted">{_html_escape(item.get("error_class"))}</span>'
        if item.get("user_message"):
            error_detail += f"<br>{_html_escape(_display_runtime_message(item.get('user_message')))}"
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(item.get('source'))}</code></td>"
            f"<td>{_html_escape(item.get('endpoint'))}</td>"
            f"<td>{_html_escape(item.get('status'))}</td>"
            f"<td>{_html_escape(item.get('latency_ms'))}</td>"
            f"<td>{_html_escape(item.get('http_status'))}</td>"
            f"<td>{error_detail}</td>"
            "</tr>"
        )
    return f"""
      <p class="operator-view-note">
        Ağ: {_html_escape(diagnostics.get('network_available'))} |
        DNS: {_html_escape(dns.get('status'))} |
        HTTP: {_html_escape(http.get('status'))}
      </p>
      <table>
        <tr><th>Kaynak</th><th>Endpoint</th><th>Sağlık</th><th>Latency ms</th><th>HTTP</th><th>Hata</th></tr>
        {''.join(rows) or '<tr><td colspan="6">Kaynak sağlık girdisi yok.</td></tr>'}
      </table>
      {runtime_dns_html}
    """


def _report_link_label(url: str) -> str:
    from urllib.parse import urlsplit

    parsed = urlsplit(str(url or ""))
    host = parsed.hostname or ""
    path = parsed.path.rstrip("/") or ""
    if host == "haveibeenpwned.com" and path.startswith("/Breach/"):
        return f"HIBP {path}"
    return host + path if host else (url or "Open evidence report")


def _evidence_report_links(signals: list[Any], sources: list[Any]) -> list[tuple[str, str]]:
    links: list[tuple[str, str]] = []
    seen: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            continue
        url = _source_observed_evidence_url(source)
        if url and url not in seen:
            seen.add(url)
            links.append((_report_link_label(url), url))
    for signal in signals:
        if not isinstance(signal, dict):
            continue
        url = str(signal.get("source_url") or "").strip()
        if not url or url in seen:
            continue
        if _render_clickable(signal, url, role=str(signal.get("url_role") or "observed_evidence_link"), status=str(signal.get("url_status") or "not_checked")):
            seen.add(url)
            links.append((_report_link_label(url), url))
    return links


def _count_observed_contacts(organization: dict[str, Any], key: str) -> int:
    contact_intel = _as_dict(organization.get("contact_intelligence"))
    return len([item for item in _as_list(contact_intel.get(key)) if isinstance(item, dict)])


def _manual_fallback_shortcut_count(osint: dict[str, Any]) -> int:
    urls: set[str] = set()
    linkless = 0

    def add_items(items: list[Any], *, link_key: str = "url") -> None:
        nonlocal linkless
        for item in items:
            if not isinstance(item, dict):
                continue
            url = str(item.get(link_key) or item.get("link") or "").strip()
            status = str(item.get("status") or "")
            role = str(item.get("url_role") or "")
            check_policy = str(item.get("check_policy") or "")
            if status != "suggestion_only" and check_policy not in {"manual_only", "api_required"}:
                continue
            if role in {"observed_evidence_link", "source_report_link", "official_page", "security_txt"}:
                continue
            if url:
                urls.add(url)
            else:
                linkless += 1

    organization = _as_dict(osint.get("organization_intelligence"))
    infrastructure = _as_dict(osint.get("infrastructure"))
    location_intel = _as_dict(organization.get("location_intelligence"))
    public_docs = _as_dict(organization.get("public_document_intelligence"))
    people = _as_dict(organization.get("people_organization_presence"))
    add_items(_as_list(osint.get("operator_search_tasks")), link_key="link")
    add_items(_as_list(infrastructure.get("passive_lookup_links")))
    add_items(_as_list(organization.get("organization_lookup_links")))
    add_items(_as_list(organization.get("location_lookup_links")))
    add_items(_as_list(organization.get("public_document_searches")))
    add_items(_as_list(location_intel.get("location_lookup_shortcuts")))
    add_items(_as_list(public_docs.get("manual_document_search_shortcuts")))
    add_items(_as_list(people.get("company_profile_lookup_shortcuts")))
    for source in _as_list(osint.get("sources")):
        if isinstance(source, dict):
            add_items(_as_list(source.get("browser_lookup_links")))
    return len(urls) + linkless


def _osint_findings_summary_html(
    *,
    osint: dict[str, Any],
    signals: list[Any],
    sources: list[Any],
    organization: dict[str, Any],
    infrastructure: dict[str, Any],
    failed_live_sources: int,
    failure_breakdown_parts: list[str],
) -> str:
    evidence_links = _evidence_report_links(signals, sources)
    breach_count = len(
        [
            item
            for item in signals
            if isinstance(item, dict) and str(item.get("category") or "") == "known_breach_reference"
        ]
    )
    org_summary = _as_dict(organization.get("summary"))
    observed_emails = _count_observed_contacts(organization, "observed_email_addresses")
    observed_phones = _count_observed_contacts(organization, "observed_phone_numbers")
    observed_urls = _count_observed_contacts(organization, "observed_contact_urls") + _count_observed_contacts(organization, "observed_contact_forms")
    target_contacts = _safe_int(org_summary.get("target_observed_public_contacts"), observed_emails + observed_phones + observed_urls)
    parent_contacts = _safe_int(org_summary.get("parent_org_observed_public_contacts"), 0)
    affiliate_contacts = _safe_int(org_summary.get("affiliate_observed_public_contacts"), 0)
    target_phones = _safe_int(org_summary.get("target_observed_phone_numbers"), observed_phones)
    parent_phones = _safe_int(org_summary.get("parent_org_observed_phone_numbers"), 0)
    location_intel = _as_dict(organization.get("location_intelligence"))
    public_docs = _as_dict(organization.get("public_document_intelligence"))
    people = _as_dict(organization.get("people_organization_presence"))
    observed_locations = _safe_int(org_summary.get("target_observed_locations"), len(_target_scope_items(_as_list(location_intel.get("observed_locations")))))
    parent_locations = _safe_int(org_summary.get("parent_org_observed_locations"), 0)
    validated_docs = _safe_int(org_summary.get("target_validated_public_documents"), len(_target_scope_items(_as_list(public_docs.get("validated_public_documents")))))
    parent_docs = _safe_int(org_summary.get("parent_org_validated_public_documents"), 0)
    affiliate_docs = _safe_int(org_summary.get("affiliate_validated_public_documents"), 0)
    observed_profiles = _safe_int(org_summary.get("target_observed_social_profiles"), len(_target_scope_items(_as_list(people.get("observed_official_social_profiles")))))
    parent_profiles = _safe_int(org_summary.get("parent_org_observed_social_profiles"), 0)
    affiliate_profiles = _safe_int(org_summary.get("affiliate_observed_social_profiles"), 0)
    infra_items = len(_as_list(infrastructure.get("resolved_ips"))) + len(_as_list(infrastructure.get("ipv6_addresses")))
    if infrastructure.get("cdn_or_proxy_likely"):
        infra_note = f"{infra_items} resolved IP(s); CDN/proxy context present"
    elif infra_items:
        infra_note = f"{infra_items} resolved IP(s)"
    else:
        infra_note = str(infrastructure.get("dns_status") or "not collected")
    fallback_count = _manual_fallback_shortcut_count(osint)
    evidence_link_html = "".join(
        f'<br><a href="{_html_escape(url)}" target="_blank" rel="noopener noreferrer" data-browser-safe="true">Kanıt raporunu aç: {_html_escape(label)}</a>'
        for label, url in evidence_links[:5]
    )
    failures = ", ".join(failure_breakdown_parts)
    return f"""
      <div class="operator-view-note">
        <strong>OSINT Bulgu Özeti</strong><br>
        Gözlemlenmiş kanıt raporu: {_html_escape(len(evidence_links))}; gözlemlenmiş ihlal kataloğu referansı: {_html_escape(breach_count)}.{evidence_link_html}<br>
        Tam hedef herkese açık iletişim bilgisi: toplam {_html_escape(target_contacts)}, telefon {_html_escape(target_phones)}. Üst kurum iletişim bilgisi: toplam {_html_escape(parent_contacts)}, telefon {_html_escape(parent_phones)}. Bağlı/harici resmî kaynak iletişim bilgisi: {_html_escape(affiliate_contacts)}.<br>
        Tam hedef resmî konum: {_html_escape(observed_locations)}. Üst kurum konumu: {_html_escape(parent_locations)}. Tam hedef herkese açık doküman: {_html_escape(validated_docs)}; üst kurum dokümanı: {_html_escape(parent_docs)}; bağlı/harici resmî kaynak dokümanı: {_html_escape(affiliate_docs)}. Tam hedef sosyal/profil linki: {_html_escape(observed_profiles)}; üst kurum sosyal/profil linki: {_html_escape(parent_profiles)}; bağlı/harici resmî kaynak sosyal/profil linki: {_html_escape(affiliate_profiles)}.<br>
        Altyapı bağlamı: {_html_escape(infra_note)}.<br>
        Kaynak hataları / kısmi kapsam: {_html_escape(failed_live_sources)} ({_html_escape(failures)}).
      </div>
      <p class="operator-view-note">Kullanılabilir manuel/API-gerekli arama kısayolu: {_html_escape(fallback_count)}. Bunlar bulgu değildir.</p>
    """


def _board_action_link(url: str, label: str, item: dict[str, Any], *, role: str, status: str) -> str:
    if url and _render_clickable(item, url, role=role, status=status):
        return f'<a href="{_html_escape(url)}" target="_blank" rel="noopener noreferrer" data-browser-safe="true">{_html_escape(label)}</a>'
    return "Doğrudan kanıt aksiyonu yok"


def _internal_board_link(anchor: str, label: str) -> str:
    return f'<a href="#{_html_escape(anchor)}">{_html_escape(label)}</a>'


def _intel_board_card(
    *,
    title: str,
    count: int,
    strongest: str,
    action_html: str,
    confidence: str,
    caveat: str,
    why: str,
    next_step: str,
    extra_html: str = "",
) -> str:
    extra = f"\n        {extra_html}" if extra_html else ""
    return f"""
      <div class="kpi osint-intel-card">
        <div class="label">{_html_escape(title)}</div>
        <div class="value">{_html_escape(count)}</div>
        <div class="note"><strong>En güçlü kanıt:</strong> {_html_escape(strongest or 'Gözlemlenmedi')}</div>
        <div class="note"><strong>Aksiyon:</strong> {action_html}</div>
        <div class="note"><strong>Güven:</strong> {_html_escape(confidence or 'none')}</div>
        <div class="note"><strong>Uyarı:</strong> {_html_escape(caveat)}</div>
        {extra}
        <div class="note"><strong>Neden önemli?</strong> {_html_escape(why)}</div>
        <div class="note"><strong>Operatör sonraki adımı:</strong> {_html_escape(next_step)}</div>
      </div>
    """


def _known_breach_board_card(signals: list[Any], sources: list[Any]) -> str:
    breaches = [
        item
        for item in signals
        if isinstance(item, dict) and str(item.get("category") or "") == "known_breach_reference"
    ]
    source = next(
        (item for item in sources if isinstance(item, dict) and str(item.get("name") or "") == "known_breach_catalog"),
        {},
    )
    breach = breaches[0] if breaches else {}
    report_url = _source_observed_evidence_url(source) if isinstance(source, dict) else ""
    if not report_url and breach:
        candidate = str(breach.get("source_url") or "").strip()
        if candidate and _render_clickable(breach, candidate, role="observed_evidence_link", status=str(breach.get("url_status") or "not_checked")):
            report_url = candidate
    snippet = str(_as_dict(breach.get("evidence")).get("snippet") or "").strip()
    breach_name = str(breach.get("breach_name") or breach.get("title") or breach.get("name") or "").strip()
    if (
        (not breach_name or breach_name.lower() in {"public breach catalog reference", "public breach reference"})
        and "Public breach catalog reference found:" in snippet
    ):
        breach_name = snippet.split("Public breach catalog reference found:", 1)[1].strip()
    data_classes = _display_data_classes(breach.get("compromised_data_classes"))
    strongest = ""
    if breach:
        strongest = (
            f"{breach_name or 'Herkese açık ihlal referansı'}; "
            f"Eşleşen alias: {breach.get('matched_alias') or '-'}; "
            f"Eşleşme tipi: {breach.get('match_type') or '-'}; "
            f"Etkilenen hesap: {breach.get('affected_accounts') or '-'}; "
            f"Veri sınıfları: {data_classes or '-'}; "
            f"İhlal tarihi: {breach.get('breach_date') or '-'}"
        )
    action = _board_action_link(
        report_url,
        "İhlal raporunu aç",
        {"render_as_clickable": bool(report_url), "browser_safe": True},
        role="source_report_link",
        status="validated",
    ) if report_url else _internal_board_link("osint-known-breach-catalog", "İhlal bölümünü incele")
    return _intel_board_card(
        title="İhlal / sızıntı referansları",
        count=len(breaches),
        strongest=strongest,
        action_html=action,
        confidence=str(breach.get("confidence") or ("high" if report_url else "none")),
        caveat="Üçüncü taraf herkese açık ihlal referansı; mevcut zafiyet kanıtı değildir.",
        extra_html=f'<div class="note"><strong>İhlal adı:</strong> {_html_escape(breach_name)}</div>' if breach_name else "",
        why="Herkese açık ihlal kataloğu referansları hesap maruziyeti incelemesi ve iletişim planlaması için bağlam sağlayabilir.",
        next_step="Raporu aç, organizasyon eşleşmesini manuel doğrula ve takip gerekip gerekmediğine karar ver.",
    )


def _observed_contacts(organization: dict[str, Any]) -> list[dict[str, Any]]:
    contact_intel = _as_dict(organization.get("contact_intelligence"))
    contacts: list[dict[str, Any]] = []
    for key in ("observed_email_addresses", "observed_phone_numbers", "observed_contact_urls", "observed_contact_forms"):
        for item in _as_list(contact_intel.get(key)):
            if isinstance(item, dict):
                contacts.append(item)
    if contacts:
        return contacts
    return [
        item
        for item in _as_list(organization.get("role_contacts"))
        if isinstance(item, dict) and bool(item.get("observed")) and str(item.get("status") or "") == "observed_public_contact"
    ]


def _contacts_board_card(organization: dict[str, Any]) -> str:
    all_contacts = _observed_contacts(organization)
    contacts = _target_scope_items(all_contacts)
    parent_contacts = _scope_items(all_contacts, "parent_organization")
    affiliate_contacts = _scope_items(all_contacts, "official_affiliate_domain")
    strongest = contacts[0] if contacts else {}
    endpoint = str(strongest.get("contact_endpoint") or strongest.get("email") or strongest.get("phone") or strongest.get("url") or "")
    relationship = str(strongest.get("domain_relationship") or ("same_registered_domain" if strongest.get("same_registered_domain") else "-"))
    source_url = str(strongest.get("source_url") or strongest.get("final_url") or "")
    source_item = {"url": source_url, "url_role": "official_page", "url_status": "checked_ok", "browser_safe": True, "render_as_clickable": True}
    endpoints = [
        str(item.get("contact_endpoint") or item.get("email") or item.get("phone") or item.get("url") or "").strip()
        for item in contacts
        if isinstance(item, dict)
    ]
    endpoint_summary = ", ".join(item for item in endpoints if item) or "Gözlemlenmedi"
    return _intel_board_card(
        title="Herkese açık iletişim bilgileri",
        count=len(contacts),
        strongest=(
            f"{endpoint or 'Gözlemlenmedi'}; tip: {strongest.get('contact_type') or '-'}; "
            f"kaynak: {strongest.get('source') or '-'}; ilişki: {relationship}; account_validated=false"
        ),
        action_html=_board_action_link(source_url, "Kaynak sayfayı aç", source_item, role="official_page", status="checked_ok") if source_url else _internal_board_link("osint-email-intelligence", "Herkese açık iletişim bilgilerini incele"),
        confidence=str(strongest.get("confidence") or ("medium" if contacts else "none")),
        caveat=(
            "Yalnızca herkese açık iletişim endpoint'i; account_validated=false ve inbox/form gönderimi denenmedi. "
            f"Üst kurum bağlamı: {len(parent_contacts)}; bağlı/harici resmî kaynak bağlamı: {len(affiliate_contacts)}."
        ),
        extra_html=f'<div class="note"><strong>Gözlemlenen contact:</strong> {_html_escape(endpoint_summary)}</div>' if contacts else "",
        why="Gözlemlenen herkese açık iletişim bilgileri inbox geçerliliği tahmin etmeden resmî iletişim yollarını gösterir.",
        next_step="Yalnızca onaylı iletişim iş akışını kullan; ReconBot üzerinden inbox doğrulama veya form gönderimi yapma.",
    )


def _validated_documents(organization: dict[str, Any]) -> list[dict[str, Any]]:
    docs = _as_dict(organization.get("public_document_intelligence"))
    return [item for item in _as_list(docs.get("validated_public_documents")) if isinstance(item, dict)]


def _document_scope_counts(organization: dict[str, Any]) -> tuple[int, int, int, int]:
    org_summary = _as_dict(organization.get("summary"))
    public_docs = _as_dict(organization.get("public_document_intelligence"))
    all_documents = _validated_documents(organization)
    shortcuts = _as_list(public_docs.get("manual_document_search_shortcuts")) or _as_list(organization.get("public_document_searches"))
    target_count = _safe_int(org_summary.get("target_validated_public_documents"), len(_target_scope_items(all_documents)))
    parent_count = _safe_int(org_summary.get("parent_org_validated_public_documents"), len(_scope_items(all_documents, "parent_organization")))
    affiliate_count = _safe_int(
        org_summary.get("affiliate_validated_public_documents"),
        len(_scope_items(all_documents, "official_affiliate_domain", "external_verified_source")),
    )
    manual_count = _safe_int(org_summary.get("public_document_search_tasks"), len(shortcuts))
    return target_count, parent_count, affiliate_count, manual_count


def _documents_board_card(organization: dict[str, Any]) -> str:
    all_documents = _validated_documents(organization)
    documents = _target_scope_items(all_documents)
    parent_documents = _scope_items(all_documents, "parent_organization")
    affiliate_documents = _scope_items(all_documents, "official_affiliate_domain", "external_verified_source")
    visible_documents = documents or parent_documents or affiliate_documents
    doc = visible_documents[0] if visible_documents else {}
    url = str(doc.get("url") or "")
    return _intel_board_card(
        title="Herkese açık dokümanlar",
        count=len(documents) + len(parent_documents) + len(affiliate_documents),
        strongest=(
            f"{doc.get('label') or url or 'Gözlemlenmedi'}; kaynak sayfa: {doc.get('source_url') or '-'}; "
            f"content type: {doc.get('content_type') or '-'}; HTTP: {doc.get('http_status') or '-'}"
        ),
        action_html=_board_action_link(url, "Herkese açık dokümanı aç", doc, role=str(doc.get("url_role") or "validated_public_document"), status=str(doc.get("url_status") or "checked_ok")) if url else _internal_board_link("osint-public-document-intelligence", "Herkese açık dokümanları incele"),
        confidence=str(doc.get("confidence") or ("medium" if visible_documents else "none")),
        caveat=f"Resmî kaynaktan linklenen herkese açık doküman; içerik derin parse edilmedi. Tam hedef: {len(documents)}; üst kurum bağlamı: {len(parent_documents)}; bağlı/harici resmî kaynak bağlamı: {len(affiliate_documents)}.",
        why="Doğrulanmış herkese açık dokümanlar dork önerilerini bulgu saymadan faydalı public bağlam sağlayabilir.",
        next_step="Yalnızca doğrulanmış herkese açık dokümanları aç ve ilgisini manuel incele.",
    )


def _valid_official_pages(organization: dict[str, Any]) -> list[dict[str, Any]]:
    valid_statuses = {"checked_ok", "checked_redirect_valid", "checked_official_affiliate_redirect", "checked_redirect"}
    return [
        page
        for page in _as_list(organization.get("official_pages"))
        if isinstance(page, dict)
        and page.get("page_found")
        and str(page.get("url_status") or "") in valid_statuses
        and str(page.get("page_type") or "") not in {"robots", "sitemap"}
    ]


def _observed_profiles(organization: dict[str, Any]) -> list[dict[str, Any]]:
    people = _as_dict(organization.get("people_organization_presence"))
    return [
        item
        for item in _as_list(people.get("observed_official_social_profiles"))
        if isinstance(item, dict) and str(item.get("status") or "") == "observed_official_social_profile"
    ]


def _profiles_board_card(organization: dict[str, Any]) -> str:
    all_profiles = _observed_profiles(organization)
    target_profiles = _target_scope_items(all_profiles)
    affiliate_profiles = _scope_items(all_profiles, "official_affiliate_domain", "external_verified_source")
    profiles = target_profiles or affiliate_profiles
    parent_profiles = _scope_items(all_profiles, "parent_organization")
    pages = _valid_official_pages(organization)
    selected = profiles[0] if profiles else (pages[0] if pages else {})
    url = str(selected.get("url") or selected.get("final_url") or "")
    role = str(selected.get("url_role") or ("official_page" if selected in pages else "observed_official_social_profile"))
    status = str(selected.get("url_status") or "checked_ok")
    profile_links = ", ".join(
        str(item.get("url") or "").strip()
        for item in profiles
        if str(item.get("url") or "").strip()
    )
    return _intel_board_card(
        title="Resmî sayfalar ve profiller",
        count=len(target_profiles) + len(affiliate_profiles) + len(pages),
        strongest=(
            f"{selected.get('label') or selected.get('page_type') or url or 'Gözlemlenmedi'}; "
            f"kaynak: {selected.get('source') or selected.get('source_url') or '-'}; "
            f"doğrulama: {selected.get('verification_level') or selected.get('meaning') or '-'}"
        ),
        action_html=_board_action_link(url, "Resmî sayfa/profili aç", selected, role=role, status=status) if url else _internal_board_link("osint-people-organization-presence", "Organizasyon/profil bağlamını incele"),
        confidence=str(selected.get("confidence") or ("high" if selected else "none")),
        caveat=f"Yalnızca kontrol edilmiş geçerli resmî sayfalar ve resmî kaynaklardan linklenen profiller öne çıkarılır. Resmî affiliate profil bağlamı: {len(affiliate_profiles)}; parent organization profil bağlamı: {len(parent_profiles)}.",
        extra_html=f'<div class="note"><strong>Gözlemlenen resmî profil linkleri:</strong> {_html_escape(profile_links)}</div>' if profile_links else "",
        why="Resmî sayfa ve profil linkleri güvenilir organizasyon bağlamını kurmaya yardım eder.",
        next_step="Bu linkleri manuel bağlam incelemesi için başlangıç noktası olarak kullan; doğrulanmamış sosyal arama shortcut'larını yok say.",
    )


def _observed_locations(organization: dict[str, Any]) -> list[dict[str, Any]]:
    location = _as_dict(organization.get("location_intelligence"))
    return [
        item
        for item in _as_list(location.get("observed_locations"))
        if isinstance(item, dict) and str(item.get("status") or "") == "official_observed_location"
    ]


def _location_board_card(organization: dict[str, Any]) -> str:
    all_locations = _observed_locations(organization)
    locations = _target_scope_items(all_locations)
    parent_locations = _scope_items(all_locations, "parent_organization")
    pages = _valid_official_pages(organization)
    selected = locations[0] if locations else {}
    source_url = str(selected.get("source_url") or "")
    source_item = {"url": source_url, "url_role": "official_page", "url_status": "checked_ok", "browser_safe": True, "render_as_clickable": True}
    return _intel_board_card(
        title="Konum / organizasyon bağlamı",
        count=len(locations) + len(pages),
        strongest=(
            f"{selected.get('label') or 'Resmî konum gözlemlenmedi'}; "
            f"adres: {selected.get('address_text') or '-'}; organizasyon sayfaları: {len(pages)}"
        ),
        action_html=_board_action_link(source_url, "Konum kaynağını aç", source_item, role="official_page", status="checked_ok") if source_url else _internal_board_link("osint-organization-intelligence", "Organizasyon bağlamını incele"),
        confidence=str(selected.get("confidence") or ("medium" if pages else "none")),
        caveat=f"Yalnızca resmî organizasyon bağlamı; Maps/search kısayolları manuel öneridir, gözlemlenen konum değildir. Üst kurum konum bağlamı: {len(parent_locations)}.",
        why="Organizasyon ve konum bağlamı doğrulanmış public bilgiyi arama sonucu gürültüsünden ayırmaya yardım eder.",
        next_step="Önce resmî sayfaları kullan; konumları operasyonel kullanmadan önce manuel doğrula.",
    )


def _infrastructure_board_card(infrastructure: dict[str, Any]) -> str:
    resolved_ips = [str(item) for item in _as_list(infrastructure.get("resolved_ips")) if str(item or "").strip()]
    ipv6 = [str(item) for item in _as_list(infrastructure.get("ipv6_addresses")) if str(item or "").strip()]
    ownership = [item for item in _as_list(infrastructure.get("ip_ownership")) if isinstance(item, dict)]
    provider = str(infrastructure.get("cdn_provider_guess") or (ownership[0].get("provider_guess") if ownership else "") or "-")
    api_missing = any(str(item.get("url_status") or "") == "api_key_missing" for item in _as_list(infrastructure.get("passive_lookup_links")) if isinstance(item, dict))
    return _intel_board_card(
        title="Altyapı bağlamı",
        count=len(resolved_ips) + len(ipv6),
        strongest=(
            f"IP'ler: {', '.join((resolved_ips + ipv6)[:3]) or '-'}; "
            f"CDN/proxy olası: {bool(infrastructure.get('cdn_or_proxy_likely'))}; provider tahmini: {provider}"
        ),
        action_html=_internal_board_link("osint-source-infrastructure", "Altyapı bağlamını incele"),
        confidence=str(infrastructure.get("origin_confidence") or ("low" if resolved_ips or ipv6 else "none")),
        caveat=("API yapılandırılmamış; pasif arama kısayolları yalnızca manuel öneridir. " if api_missing else "") + _display_text(infrastructure.get("caveat") or "DNS bağlamı origin kanıtı değildir."),
        why="Pasif DNS ve sahiplik ipuçları bağlam sağlar ancak zafiyet kanıtı olarak ele alınmamalıdır.",
        next_step="Doğrulanmış bir kaynak origin sahipliğini kanıtlamadıkça CDN/proxy IP'lerini edge bağlamı say.",
    )


def _coverage_gap_parts(sources: list[Any]) -> list[str]:
    parts: list[str] = []
    for item in sources:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        status = str(item.get("status") or "")
        if name == "certificate_transparency":
            for provider in _as_list(item.get("provider_results")):
                if isinstance(provider, dict):
                    provider_status = str(provider.get("status") or "")
                    if provider_status in {"unavailable", "timeout", "error"}:
                        parts.append(f"{_provider_display_name(provider.get('provider'))}: {_display_status_label(provider_status)}")
        elif status in {"partial", "unavailable", "timeout", "auth_required_fallback", "rate_limited_fallback", "error", "suggestions_generated"}:
            parts.append(f"{name}: {_display_status_label(status)}")
    return parts


def _coverage_board_card(sources: list[Any]) -> str:
    gaps = _coverage_gap_parts(sources)
    available = len([item for item in sources if isinstance(item, dict) and str(item.get("status") or "") in {"completed", "completed_matched", "completed_no_match", "no_match"}])
    return _intel_board_card(
        title="Kaynak kapsamı eksikleri",
        count=len(gaps),
        strongest=", ".join(gaps[:3]) or f"{available} kaynak kullanılabilir",
        action_html=_internal_board_link("osint-source-health", "Kaynak kapsamını incele"),
        confidence="diagnostic",
        caveat="Kaynaklar kısmi, erişilemez, zaman aşımında veya auth-required ise kanıt yokluğu kesin sonuç değildir.",
        why="Kapsam eksikleri ReconBot'un hangi kaynakları güvenilir biçimde gözlemleyemediğini açıklar.",
        next_step="Sessiz OSINT sonucunu temiz kabul etmeden önce erişilemeyen/auth-required kaynakları incele.",
    )


def _summary_card(*, title: str, status: str, count: int | str, meaning: str, next_action: str) -> str:
    return f"""
      <div class="kpi osint-intel-card">
        <div class="label">{_html_escape(title)}</div>
        <div class="value" style="font-size:22px; line-height:1.15;">{_html_escape(status)}</div>
        <div class="note"><strong>Sayı:</strong> {_html_escape(count)}</div>
        <div class="note">{_html_escape(meaning)}</div>
        <div class="note"><strong>Sonraki adım:</strong> {_html_escape(next_action)}</div>
      </div>
    """


def _turkish_operator_brief_html(
    *,
    osint: dict[str, Any],
    sources: list[Any],
    organization: dict[str, Any],
    infrastructure: dict[str, Any],
) -> str:
    summary = _as_dict(osint.get("summary"))
    leak = _as_dict(osint.get("leak_intelligence"))
    leak_summary = _as_dict(leak.get("summary"))
    active_observed = _safe_int(summary.get("observed_signals", summary.get("total_signals", 0)))
    leak_refs = _safe_int(leak_summary.get("observed_references"))
    manual_count = _manual_fallback_shortcut_count(osint)
    coverage_gaps = _coverage_gap_parts(sources)
    org_summary = _as_dict(organization.get("summary"))
    exact_locations = _safe_int(org_summary.get("target_observed_locations"), 0)
    parent_locations = _safe_int(org_summary.get("parent_org_observed_locations"), 0)
    target_contacts = _safe_int(org_summary.get("target_observed_public_contacts"), 0)
    parent_contacts = _safe_int(org_summary.get("parent_org_observed_public_contacts"), 0)
    affiliate_contacts = _safe_int(org_summary.get("affiliate_observed_public_contacts"), 0)
    social_profiles = _safe_int(org_summary.get("observed_official_social_profiles"), 0)
    public_docs = _safe_int(org_summary.get("validated_public_documents"), 0)
    infra_count = len(_as_list(infrastructure.get("resolved_ips"))) + len(_as_list(infrastructure.get("ipv6_addresses")))
    found_text = (
        f"Aktif OSINT maruziyet kanıtı bulundu: {active_observed}."
        if active_observed
        else "Aktif OSINT maruziyet kanıtı bulunmadı."
    )
    if leak_refs:
        found_text += f" Ancak {leak_refs} adet sadece-metadata sızıntı/ihlal referansı görüldü. Bu aktif bir zafiyet bulgusu değildir ve risk skorunu artırmaz."
    org_bits: list[str] = []
    if target_contacts:
        org_bits.append(f"Tam hedefte {target_contacts} resmî contact/form linki görüldü.")
    if parent_contacts:
        org_bits.append(f"Üst kurum bağlamında {parent_contacts} iletişim kaydı görüldü; tam hedef kanıtı değildir.")
    if affiliate_contacts:
        org_bits.append(f"Bağlı/harici resmî kaynakta {affiliate_contacts} iletişim kaydı görüldü; tam hedef kanıtı değildir.")
    if social_profiles:
        org_bits.append(f"{social_profiles} resmî sosyal profil linki doğrulandı.")
    if public_docs:
        org_bits.append(f"{public_docs} herkese açık doküman doğrulandı.")
    if not exact_locations:
        org_bits.append("Doğrulanmış fiziksel adres/konum bulunmadı.")
    else:
        org_bits.append(f"Tam hedefte {exact_locations} doğrulanmış konum görüldü.")
    if org_bits:
        found_text += " " + " ".join(org_bits)
    not_found_bits = [
        "Kimlik bilgisi veya dump toplanmadı.",
        "Kimlik bilgisi doğrulama yapılmadı.",
        "Ham sızıntı kaydı veya personal record toplanmadı.",
    ]
    if not exact_locations:
        not_found_bits.append("Tam hedef üzerinde doğrulanmış adres/konum çıkarılamadı.")
    partial_text = (
        "Kısmi kalan kaynaklar: " + ", ".join(coverage_gaps[:6]) + ". Bulunmaması kesin olarak yok anlamına gelmez."
        if coverage_gaps
        else "Kısmi kalan kritik kaynak görünmüyor; yine de kapalı/yapılandırılmamış kaynakları kontrol et."
    )
    manual_text = (
        f"{manual_count} manuel öneri linki üretildi. Manuel arama görevleri sadece öneridir ve risk skorunu etkilemez. Google dork, GitHub manuel önerisi, Shodan/Censys/urlscan/Maps linkleri kanıt değildir ve risk skoruna etki etmez."
    )
    next_step = (
        "Kurumla gerçekten ilişkili olup olmadığını manuel doğrula; kimlik bilgisi toplama."
        if leak_refs
        else "Kaynak kapsamını gözden geçir; gerekirse kapalı veya yapılandırılmamış kaynakları güvenli biçimde yapılandır."
    )
    if parent_locations:
        next_step += " Üst kurum konumu tam hedefe doğrudan ait varsayılmamalıdır."
    plain_parts = []
    if active_observed == 0:
        plain_parts.append("Bu çalıştırmada aktif ve doğrulanmış OSINT maruziyet kanıtı bulunmadı. Bazı kaynaklar zaman aşımı veya kimlik doğrulama nedeniyle kısmi kaldığı için bu sonuç 'kesin temiz' anlamına gelmez.")
    if leak_refs:
        plain_parts.append("Bu raporda bir sızıntı/ihlal metadata referansı görüldü. Bu, hedef sistemde aktif zafiyet olduğu anlamına gelmez; yalnızca herkese açık bir kaynakta kurumla ilişkili olabilecek bir kayıt bulunduğunu gösterir.")
    if manual_count:
        plain_parts.append("Manuel öneri linkleri bulgu değildir. Operatörün daha sonra kontrollü incelemesi için üretilmiştir.")
    plain_summary = " ".join(plain_parts)
    return f"""
      <h3 id="osint-operator-brief">Bu Rapor Kısaca Ne Diyor?</h3>
      {('<p class="operator-view-note"><strong>Operatör için kısa yorum:</strong> ' + _html_escape(plain_summary) + '</p>') if plain_summary else ''}
      <div class="kpi-grid overview-core-grid">
        {_summary_card(title="Ne kontrol edildi?", status="Kontrol özeti", count=len(sources), meaning="Pasif herkese açık OSINT kaynakları, herkese açık ihlal kataloğu, metadata feed durumu, konum/iletişim/altyapı bağlamı ve manuel öneriler kontrol edildi.", next_action="Ham JSON yerine önce kaynak kapsamı ve bu özet bloklarını oku.")}
        {_summary_card(title="Ne bulundu?", status=("Gözlemlenmiş kanıt var" if active_observed else "Gözlemlenmiş aktif kanıt yok"), count=f"aktif {active_observed}; metadata {leak_refs}; altyapı {infra_count}", meaning=found_text, next_action=next_step)}
        {_summary_card(title="Ne bulunmadı?", status="Güvenlik sınırı korundu", count=f"tam hedef konum {exact_locations}", meaning=" ".join(not_found_bits), next_action="Eksik görünen alanları manuel ve onaylı kaynaklardan doğrula.")}
        {_summary_card(title="Hangi kaynaklar kısmi kaldı?", status=("Kısmi" if coverage_gaps else "Tamamlandı"), count=len(coverage_gaps), meaning=partial_text, next_action="Zaman aşımı, auth required veya provider unavailable durumlarını ayrı ayrı incele.")}
        {_summary_card(title="Hangi şeyler sadece manuel öneri?", status="Sadece manuel öneri", count=manual_count, meaning=manual_text, next_action="Bu linkleri bulgu gibi raporlama; operatör kontrol listesi olarak kullan.")}
        {_summary_card(title="Operatör şimdi ne yapmalı?", status="Manuel doğrulama", count="1", meaning=next_step, next_action="Kimlik bilgisi, dump, secret veya ham sızıntı kaydı toplama.")}
      </div>
    """


def _source_by_name(sources: list[Any], name: str) -> dict[str, Any]:
    return next((item for item in sources if isinstance(item, dict) and str(item.get("name") or "") == name), {})


def _leak_source_status_from_payload(leak_intelligence: dict[str, Any], source_name: str) -> str:
    return _leak_result_status(_as_list(leak_intelligence.get("results")), source_name)


def _osint_executive_summary_html(
    *,
    osint: dict[str, Any],
    signals: list[Any],
    sources: list[Any],
    organization: dict[str, Any],
    infrastructure: dict[str, Any],
) -> str:
    org_summary = _as_dict(organization.get("summary"))
    leak = _as_dict(osint.get("leak_intelligence"))
    leak_summary = _as_dict(leak.get("summary"))
    location_intel = _as_dict(organization.get("location_intelligence"))
    people = _as_dict(organization.get("people_organization_presence"))
    email = _as_dict(organization.get("email_intelligence"))
    exact_locations = _safe_int(org_summary.get("target_observed_locations"), len(_target_scope_items(_as_list(location_intel.get("observed_locations")))))
    parent_locations = _safe_int(org_summary.get("parent_org_observed_locations"), 0)
    affiliate_locations = len(_scope_items(_as_list(location_intel.get("observed_locations")), "official_affiliate_domain", "external_verified_source"))
    location_shortcuts = len(_as_list(location_intel.get("location_lookup_shortcuts")) or _as_list(organization.get("location_lookup_links")))
    rejected_locations = len(_as_list(location_intel.get("rejected_location_candidates")))
    leak_refs = _safe_int(leak_summary.get("observed_references"))
    if not leak and leak_refs == 0:
        leak_refs = len([item for item in signals if isinstance(item, dict) and item.get("category") == "known_breach_reference"])
    metadata_status = _leak_source_status_from_payload(leak, "leak_metadata_feed") or "disabled"
    metadata_meaning = _metadata_feed_status_message(metadata_status)
    known_status = _leak_source_status_from_payload(leak, "known_breach_catalog") or str(_source_by_name(sources, "known_breach_catalog").get("status") or "not_checked")
    summary_payload = _as_dict(osint.get("summary"))
    active_observed = _safe_int(summary_payload.get("observed_signals", summary_payload.get("total_signals", len(signals))))
    contact_count = _safe_int(org_summary.get("target_observed_public_contacts"), _count_observed_contacts(organization, "observed_email_addresses") + _count_observed_contacts(organization, "observed_phone_numbers"))
    mx_status = str(email.get("mx_status") or "not_checked")
    spf_status = str(email.get("spf_status") or "not_checked")
    dmarc_status = str(email.get("dmarc_status") or "not_checked")
    official_pages_found = _safe_int(org_summary.get("official_pages_found"))
    target_docs, parent_docs, affiliate_docs, manual_doc_shortcuts = _document_scope_counts(organization)
    profile_count = _safe_int(
        org_summary.get(
            "target_observed_social_profiles",
            org_summary.get(
                "observed_official_social_profiles",
                len(_target_scope_items(_as_list(people.get("observed_official_social_profiles")))),
            ),
        )
    )
    infra_count = len(_as_list(infrastructure.get("resolved_ips"))) + len(_as_list(infrastructure.get("ipv6_addresses")))
    coverage_gaps = _coverage_gap_parts(sources)
    soft_errors = _safe_int(org_summary.get("official_pages_soft_error"), _as_dict(osint.get("summary")).get("official_pages_soft_error"))
    if exact_locations:
        location_meaning = "Tam hedef üzerinde doğrulanmış adres/konum çıkarıldı."
    elif parent_locations:
        location_meaning = "Üst kurum bağlamında konum bulundu; tam hedef konumu doğrulanmadı."
    elif soft_errors:
        location_meaning = "Doğrulanmış konum çıkarılamadı. Bazı sayfalar soft-error/noise olarak reddedildi."
    elif location_shortcuts:
        location_meaning = "Doğrulanmış resmî konum çıkarılamadı. Manuel konum aramaları var ama kanıt değildir."
    else:
        location_meaning = "Tam hedef üzerinde doğrulanmış adres/konum çıkarılamadı."
    if target_docs:
        document_status = _finding_status(target_docs)
        document_meaning = "Tam hedef herkese açık dokümanları bulundu."
    elif parent_docs:
        document_status = _finding_status(parent_docs)
        document_meaning = "Üst kurum herkese açık dokümanları bulundu; tam hedef kanıtı değildir."
    elif affiliate_docs:
        document_status = _finding_status(affiliate_docs)
        document_meaning = "Bağlı/harici resmî kaynak herkese açık dokümanı bulundu; tam hedef kanıtı değildir."
    else:
        document_status = _finding_status(0, fallback_only=manual_doc_shortcuts > 0)
        document_meaning = "Doğrulanmış herkese açık doküman bulunmadı; doküman dork'ları sadece manuel öneridir."
    if leak_refs and active_observed == 0:
        leak_meaning = (
            f"Aktif OSINT maruziyet kanıtı bulunmadı. Ancak {leak_refs} adet sadece-metadata sızıntı/ihlal "
            "referansı görüldü. Bu aktif bir zafiyet bulgusu değildir ve risk skorunu artırmaz."
        )
        leak_next_action = "Kurumla gerçekten ilişkili olup olmadığını manuel doğrula; kimlik bilgisi toplama."
    elif leak_refs:
        leak_meaning = "Herkese açık ihlal/sızıntı metadata referansı görüldü. Bu referanslar aktif OSINT maruziyet kanıtından ayrıdır ve risk skorunu artırmaz."
        leak_next_action = "Kurum ilişkisini manuel doğrula; kimlik bilgisi toplama."
    else:
        leak_meaning = "Açık kaynaklardan herkese açık ihlal/sızıntı metadata referansı gözlemlenmedi."
        leak_next_action = "Kanıt yokluğunu kesin sonuç saymadan önce kaynak kapsamını incele."
    return f"""
      <h3 id="osint-intelligence-board">ReconBot Ne Öğrendi?</h3>
      <p class="operator-view-note"><strong>Türkçe operatör özeti.</strong> Bu kartlar kanıtı, bağlamı, kapalı kaynakları ve sadece manuel önerileri ayırır. Ham internal status değerleri gelişmiş teşhislerde korunur.</p>
      <div class="kpi-grid overview-core-grid">
        {_summary_card(title="Herkese açık ihlal/sızıntı referansları", status=_finding_status(leak_refs), count=leak_refs, meaning=leak_meaning, next_action=leak_next_action)}
        {_summary_card(title="Darkweb / sızıntı metadata kaynakları", status=(_display_status_label("partial") if known_status in {"timeout", "error", "provider_unavailable"} else _finding_status(leak_refs, disabled=(metadata_status == "disabled" and known_status in {"not_checked", "disabled"}))), count=f"katalog: {_plain_status_label(known_status)}; metadata feed: {_plain_status_label(metadata_status)}", meaning=f"Herkese açık ihlal metadata açık olduğunda kontrol edilir. Tor/onion taraması yok. {metadata_meaning}", next_action="Yalnızca güvenilir metadata-only feed için osint.leakSources.metadataFeed yapılandır.")}
        {_summary_card(title="Herkese açık iletişim bilgileri", status=_finding_status(contact_count), count=contact_count, meaning=("Hedefte doğrulanmış herkese açık iletişim endpoint'i gözlemlendi." if contact_count else "Tam hedef üzerinde herkese açık iletişim endpoint'i gözlemlenmedi."), next_action="Yalnızca onaylı iletişim akışını kullan; inbox doğrulama veya form gönderimi yapma.")}
        {_summary_card(title="Mail güvenlik kayıtları", status=_finding_status(1 if mx_status == "present" or spf_status == "present" or dmarc_status == "present" else 0, checked=mx_status != "not_checked"), count=f"MX {_display_status_label(mx_status)}, SPF {_display_status_label(spf_status)}, DMARC {_display_status_label(dmarc_status)}", meaning="Passive DNS kayıtları registered domain için kontrol edildiğinde görünür. Bu kayıtlar inbox varlığını kanıtlamaz.", next_action="SPF/DMARC yoksa veya zayıfsa manuel incele.")}
        {_summary_card(title="Resmî sayfalar", status=_finding_status(official_pages_found), count=official_pages_found, meaning=("Doğrulanmış resmî sayfalar bulundu." if official_pages_found else "Kontrol edilen path'lerde doğrulanmış resmî sayfa bulunmadı."), next_action="Önce doğrulanmış sayfaları kullan; reddedilen sayfaları yalnızca teşhis olarak incele.")}
        {_summary_card(title="Konumlar", status=_finding_status(exact_locations, fallback_only=(exact_locations == 0 and parent_locations == 0 and location_shortcuts > 0)), count=f"tam hedef {exact_locations}; üst kurum {parent_locations}; bağlı/harici {affiliate_locations}; manuel öneri {location_shortcuts}; reddedilen {rejected_locations}", meaning=location_meaning, next_action="Maps/search kısayollarını sadece manuel öneri say; resmî kaynak adreslerini manuel doğrula.")}
        {_summary_card(title="Herkese açık dokümanlar", status=document_status, count=f"tam hedef {target_docs}; üst kurum {parent_docs}; bağlı/harici {affiliate_docs}; manuel öneri {manual_doc_shortcuts}", meaning=document_meaning, next_action="Yalnızca doğrulanmış doküman linklerini aç; arama dork'larını manuel öneri say.")}
        {_summary_card(title="Sosyal profiller", status=_finding_status(profile_count), count=profile_count, meaning=("Doğrulanmış kaynaklarda resmî sosyal/profil linki gözlemlendi." if profile_count else "Tam hedef resmî sosyal/profil linki gözlemlenmedi."), next_action="Doğrulanmamış sosyal arama shortcut'larını manuel doğrulanana kadar dikkate alma.")}
        {_summary_card(title="Altyapı bağlamı", status=_finding_status(infra_count, checked=bool(infrastructure)), count=infra_count, meaning=("Passive DNS/IP bağlamı toplandı." if infra_count else "Passive altyapı IP bağlamı toplanmadı veya kayıt yok."), next_action="CDN/proxy IP'lerini origin kanıtı sayma.")}
        {_summary_card(title="Kaynak kapsamı / kısmi sonuçlar", status=(_display_status_label("partial") if coverage_gaps else "Tamamlandı"), count=len(coverage_gaps), meaning=("Bazı OSINT kaynakları hata verdi veya zaman aşımına uğradı. Kanıt yokluğu kesin sonuç değildir." if coverage_gaps else "Yapılandırılmış pasif kaynaklar tamamlandı veya güvenilir eşleşme döndürmedi."), next_action="Sessiz raporu temiz saymadan önce kapalı/auth-required/zaman aşımı kaynaklarını incele.")}
      </div>
    """


def _evidence_context_fallback_legend_html() -> str:
    return """
      <h3 id="osint-evidence-context-fallback">Kanıt / Bağlam / Manuel Öneri Ayrımı</h3>
      <div class="kpi-grid overview-core-grid">
        <div class="kpi"><div class="label">Kanıt</div><div class="value">Gözlemlendi</div><div class="note">Doğrulanmış herkese açık kaynakta gözlemlenen ve linki kontrol edilebilir veri.</div></div>
        <div class="kpi"><div class="label">Bağlam</div><div class="value">Kapsam</div><div class="note">Üst kurum, bağlı/harici resmî kaynak, altyapı veya kaynak kapsamı bilgisi. Tek başına bulgu değildir.</div></div>
        <div class="kpi"><div class="label">Manuel Öneri</div><div class="value">Manuel</div><div class="note">Google dork, Shodan/Censys/urlscan/Maps arama linki gibi operatörün manuel bakacağı öneriler. Risk skoruna etki etmez.</div></div>
        <div class="kpi"><div class="label">Kapalı / Yapılandırılmamış</div><div class="value">Kapalı</div><div class="note">Modül var ama bu çalıştırmada açık değil veya gerekli ayar girilmemiş.</div></div>
      </div>
    """


def _source_result_text(source_id: str, status: str, metadata_meaning: str = "") -> str:
    if source_id == "certificate_transparency" and status == "timeout":
        return "crt.sh bu çalıştırmada zaman aşımına uğradı; Certificate Transparency kapsamı kısmi kaldı."
    if source_id == "certificate_transparency" and status in {"provider_unavailable", "unavailable", "partial", "error"}:
        return "crt.sh bu çalıştırmada erişilemedi; CT sertifika kapsamı kısmi kaldı."
    if source_id == "historical_urls" and status == "timeout":
        return "Wayback CDX zaman aşımına uğradı. Geçmiş URL bulunmaması kesin olarak 'yok' anlamına gelmez."
    if source_id == "public_code_search" and status in {"auth_required_fallback", "auth_required"}:
        return "GitHub canlı kod araması kimlik doğrulama gerektiriyor. Bu yüzden sadece manuel arama önerileri üretildi."
    if source_id == "leak_metadata_feed":
        return metadata_meaning
    if status in {"completed_no_match", "no_match", "completed_zero", "alias_not_found"}:
        return "Kaynak kontrol edildi; güvenilir eşleşme bulunmadı. Bu, ilgili verinin kesin olarak olmadığı anlamına gelmez."
    if status in {"completed", "completed_matched"}:
        return "Kaynak başarıyla kontrol edildi."
    if status == "disabled":
        return "Kaynak kurulu ama bu çalıştırmada kapalı."
    if status == "not_configured":
        return "Kaynak açık ama gerekli ayar girilmemiş."
    if status == "invalid_config":
        return "Provider ayarı geçersiz. Ağ veya dosya erişimi yapılmadı."
    if status == "timeout":
        return "Kaynak zaman aşımına uğradı. Kanıt yokluğu kesin sonuç değildir."
    if status in {"provider_unavailable", "unavailable", "error", "partial"}:
        return "Kaynak kısmi veya erişilemez durumda. Sonuç eksik olabilir."
    if status in {"suggestions_generated", "suggestion_only", "manual_only"}:
        return "Sadece manuel öneriler üretildi; otomatik kanıt toplanmadı."
    return "Kaynak durumu gelişmiş teşhislerde raw status olarak korunur."


def _source_action_text(source_id: str, status: str) -> str:
    if source_id == "leak_metadata_feed" and status == "disabled":
        return "Gerek yoksa kapalı bırak. Kullanacaksan güvenilir metadata-only provider ayarlarını yapılandır."
    if source_id == "leak_metadata_feed" and status == "not_configured":
        return "feedPath/feedUrl ve provider ayarlarını yapılandır."
    if source_id == "leak_metadata_feed" and status == "invalid_config":
        return "Provider ayarını düzelt; http/file/raw içerikli feed kullanma."
    if source_id == "public_code_search" and status in {"auth_required_fallback", "auth_required"}:
        return "GitHub token ekle; üretilen manuel önerileri bulgu sayma ve secret/token doğrulama yapma."
    if source_id == "certificate_transparency" and status in {"timeout", "provider_unavailable", "unavailable", "partial", "error"}:
        return "Daha sonra tekrar dene veya OSINT timeout/retry ayarını artır."
    if source_id == "historical_urls" and status == "timeout":
        return "Wayback kaynağını daha sonra veya daha yüksek timeout ile tekrar dene; sessiz sonucu temiz kabul etme."
    if status in {"completed_no_match", "no_match", "completed_zero", "alias_not_found"}:
        return "Eşleşme yok sonucunu kaynak kapsamı notuyla birlikte yorumla."
    if status in {"completed", "completed_matched"}:
        return "Varsa kanıt linkini aç ve kurum ilişkisini manuel doğrula."
    if status in {"suggestions_generated", "suggestion_only", "manual_only"}:
        return "Bu satırı bulgu değil manuel kontrol listesi olarak kullan."
    if status in {"timeout", "provider_unavailable", "unavailable", "partial", "error"}:
        return "Kaynak hatasını gider veya kapsam notu olarak rapora dahil et."
    return "Gelişmiş teşhisleri incele."


def _coverage_row(source_id: str, status: str, result: str = "") -> str:
    source_info = SOURCE_DISPLAY.get(source_id, {"title": source_id or "Bilinmeyen kaynak", "meaning": "Kaynak kapsamı bilgisi."})
    return (
        "<tr>"
        f"<td><strong>{_html_escape(source_info['title'])}</strong><br><code>{_html_escape(source_id)}</code></td>"
        f"<td><span class=\"pill {_html_escape(_status_tone(status))}\">{_html_escape(_plain_status_label(status))}</span><br><span class=\"muted\"><code>{_html_escape(status or '-')}</code></span></td>"
        f"<td>{_html_escape(source_info['meaning'])}</td>"
        f"<td>{_html_escape(result or _source_result_text(source_id, status))}</td>"
        f"<td>{_html_escape(_source_action_text(source_id, status))}</td>"
        "</tr>"
    )


def _status_for_health_table(status: str) -> str:
    aliases = {
        "auth_required_fallback": "auth_required",
        "rate_limited_fallback": "partial",
        "suggestions_generated": "suggestions_only",
        "no_match": "completed_no_match",
        "unavailable": "provider_unavailable",
    }
    return aliases.get(str(status or ""), str(status or "not_checked"))


def _coverage_impact_for_row(source_id: str, status: str) -> str:
    status = _status_for_health_table(status)
    if status in {"completed", "completed_no_match"}:
        return "none"
    if source_id == "public_code_search" and status == "auth_required":
        return "high"
    if source_id in {"certificate_transparency", "historical_urls", "known_breach_catalog"} and status in {"partial", "timeout", "provider_unavailable", "error"}:
        return "medium"
    if source_id in {"safe_search_dorks", "leak_metadata_feed"} and status in {"disabled", "skipped", "suggestions_only"}:
        return "low"
    return "medium" if status in {"partial", "timeout", "provider_unavailable", "auth_required", "error"} else "low"


def _fallback_health_row(source_id: str, status: str, metadata_meaning: str = "") -> dict[str, Any]:
    normalized_status = _status_for_health_table(status)
    source_info = SOURCE_DISPLAY.get(source_id, {"title": source_id or "Bilinmeyen kaynak", "meaning": ""})
    category = {
        "certificate_transparency": "ct",
        "historical_urls": "archive",
        "public_code_search": "code_search",
        "known_breach_catalog": "breach_metadata",
        "leak_metadata_feed": "breach_metadata",
        "safe_search_dorks": "manual_suggestions",
    }.get(source_id, "manual_suggestions")
    return {
        "source": source_id,
        "display_name": source_info.get("title") or source_id,
        "category": category,
        "status": normalized_status,
        "coverage_impact": _coverage_impact_for_row(source_id, normalized_status),
        "user_message_tr": metadata_meaning or _source_result_text(source_id, normalized_status),
        "operator_action_tr": _source_action_text(source_id, normalized_status),
        "latency_ms": 0,
        "http_status": 0,
        "error_class": "",
        "error": "",
    }


def _normalized_source_health_rows(osint: dict[str, Any], sources: list[Any], leak_intelligence: dict[str, Any]) -> list[dict[str, Any]]:
    diagnostics = _as_dict(osint.get("diagnostics"))
    raw_rows = [item for item in _as_list(diagnostics.get("source_health")) if isinstance(item, dict)]
    rows_by_source: dict[str, dict[str, Any]] = {str(row.get("source") or ""): dict(row) for row in raw_rows}
    source_status = {str(item.get("name") or ""): str(item.get("status") or "not_checked") for item in sources if isinstance(item, dict)}
    leak_results = _as_list(leak_intelligence.get("results"))
    metadata_status = _leak_result_status(leak_results, "leak_metadata_feed") or "disabled"
    metadata_meaning = _metadata_feed_status_message(metadata_status)
    ordered = [
        ("certificate_transparency", source_status.get("certificate_transparency", "not_checked"), ""),
        ("historical_urls", source_status.get("historical_urls", "not_checked"), ""),
        ("public_code_search", source_status.get("public_code_search", "not_checked"), ""),
        ("known_breach_catalog", source_status.get("known_breach_catalog", _leak_result_status(leak_results, "known_breach_catalog") or "not_checked"), ""),
        ("leak_metadata_feed", metadata_status, metadata_meaning),
        ("safe_search_dorks", source_status.get("safe_search_dorks", "not_checked"), ""),
    ]
    normalized: list[dict[str, Any]] = []
    for source_id, status, result in ordered:
        row = rows_by_source.get(source_id) or _fallback_health_row(source_id, status, result)
        row["status"] = _status_for_health_table(str(row.get("status") or status))
        row.setdefault("coverage_impact", _coverage_impact_for_row(source_id, str(row.get("status") or status)))
        if not row.get("user_message_tr"):
            row["user_message_tr"] = result or _source_result_text(source_id, str(row.get("status") or status))
        if not row.get("operator_action_tr"):
            row["operator_action_tr"] = _source_action_text(source_id, str(row.get("status") or status))
        normalized.append(row)
    return normalized


def _source_health_error_text(row: dict[str, Any]) -> str:
    parts: list[str] = []
    http_status = _safe_int(row.get("http_status"))
    if http_status:
        parts.append(f"HTTP {http_status}")
    if row.get("error_class"):
        parts.append(str(row.get("error_class")))
    if row.get("error"):
        parts.append(_display_runtime_message(row.get("error")))
    if not parts and str(row.get("status") or "") in {"timeout", "provider_unavailable", "auth_required", "error", "partial"}:
        parts.append(_plain_status_label(row.get("status")))
    latency = _safe_int(row.get("latency_ms"))
    latency_text = f"{latency} ms" if latency else "-"
    detail = " / ".join(part for part in parts if part)
    return f"{latency_text}{(' / ' + detail) if detail else ''}"


def _source_coverage_overview_html(osint: dict[str, Any], sources: list[Any], leak_intelligence: dict[str, Any]) -> str:
    rows = []
    for row in _normalized_source_health_rows(osint, sources, leak_intelligence):
        source_id = str(row.get("source") or "")
        status = str(row.get("status") or "not_checked")
        rows.append(
            "<tr>"
            f"<td><strong>{_html_escape(row.get('display_name') or SOURCE_DISPLAY.get(source_id, {}).get('title') or source_id)}</strong><br><code>{_html_escape(source_id)}</code></td>"
            f"<td>{_html_escape(CATEGORY_LABELS.get(str(row.get('category') or ''), str(row.get('category') or '-')))}</td>"
            f"<td><span class=\"pill {_html_escape(_status_tone(status))}\">{_html_escape(_plain_status_label(status))}</span><br><span class=\"muted\"><code>{_html_escape(status)}</code></span></td>"
            f"<td>{_html_escape(COVERAGE_IMPACT_LABELS.get(str(row.get('coverage_impact') or ''), str(row.get('coverage_impact') or '-')))}</td>"
            f"<td>{_html_escape(row.get('user_message_tr') or _source_result_text(source_id, status))}</td>"
            f"<td>{_html_escape(row.get('operator_action_tr') or _source_action_text(source_id, status))}</td>"
            f"<td>{_html_escape(_source_health_error_text(row))}</td>"
            "</tr>"
        )
    summary = _as_dict(osint.get("osint_source_health_summary")) or _as_dict(_as_dict(osint.get("diagnostics")).get("osint_source_health_summary"))
    confidence_note = ""
    if summary:
        confidence_note = (
            f"<p class=\"operator-view-note\"><strong>Kapsam güveni:</strong> "
            f"{_html_escape(summary.get('coverage_confidence') or 'unknown')} - "
            f"{_html_escape(summary.get('coverage_note') or '')}</p>"
        )
    return f"""
      <h3 id="osint-source-health">Kaynak Kapsamı - Kaynak Sağlığı ve Kapsam</h3>
      <p class="operator-view-note"><strong>Kısmi kaynak kapsamı ReconBot'un her pasif kaynağı tam kontrol edemediği anlamına gelir.</strong> Kanıt yokluğu kesin sonuç değildir.</p>
      {confidence_note}
      <table>
        <tr><th>Kaynak</th><th>Kategori</th><th>Durum</th><th>Kapsam etkisi</th><th>Ne anlama geliyor?</th><th>Operatör aksiyonu</th><th>Süre / Hata</th></tr>
        {''.join(rows)}
      </table>
    """


def _osint_intelligence_board_html(osint: dict[str, Any], signals: list[Any], sources: list[Any], organization: dict[str, Any], infrastructure: dict[str, Any]) -> str:
    return _osint_executive_summary_html(
        osint=osint,
        signals=signals,
        sources=sources,
        organization=organization,
        infrastructure=infrastructure,
    )


def _fallback_item_link_html(item: dict[str, Any]) -> str:
    url = str(item.get("url") or item.get("link") or "").strip()
    label = _display_manual_lookup_label(
        item.get("label") or item.get("link_label") or item.get("query") or url or "Manuel öneri linkini aç",
        url_role=item.get("url_role") or "manual_search_suggestion",
        url=url,
    )
    role = str(item.get("url_role") or "manual_search_suggestion")
    status = str(item.get("url_status") or item.get("status") or "manual_only")
    if url and _render_clickable(item, url, role=role, status=status):
        return f'<a href="{_html_escape(url)}" target="_blank" rel="noopener noreferrer" data-browser-safe="true">{_html_escape(label)}</a>'
    if url:
        return f"<code>{_html_escape(url)}</code>"
    return "-"


def _collect_fallback_shortcuts(
    *,
    organization: dict[str, Any],
    infrastructure: dict[str, Any],
    sources: list[Any],
    operator_search_tasks: list[Any],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def add(item: dict[str, Any], *, source: str, purpose: str, why: str) -> None:
        rows.append({"item": item, "source": source, "purpose": purpose, "why": why})

    for task in operator_search_tasks:
        if isinstance(task, dict):
            add(task, source=str(task.get("source_name") or "manual_search"), purpose=str(task.get("purpose") or task.get("category") or "Manuel arama önerisi"), why="Üretilen suggestion_only görev; dış arama toplanmadı veya doğrulanmadı.")
    for item in _as_list(infrastructure.get("passive_lookup_links")):
        if isinstance(item, dict):
            add(item, source="infrastructure", purpose=str(item.get("label") or "Pasif altyapı araması"), why="Manuel pasif arama kısayolu; bulgu değil. API key gerekli veya manuel pasif arama; API kanıtı toplanmadı.")
    location = _as_dict(organization.get("location_intelligence"))
    public_docs = _as_dict(organization.get("public_document_intelligence"))
    people = _as_dict(organization.get("people_organization_presence"))
    for item in _as_list(organization.get("organization_lookup_links")):
        if isinstance(item, dict):
            add(item, source="organization", purpose=str(item.get("label") or "Organizasyon araması"), why="Manuel/API-gerekli arama kısayolu; gözlemlenmiş bulgu değil.")
    for item in _as_list(organization.get("location_lookup_links")) + _as_list(location.get("location_lookup_shortcuts")):
        if isinstance(item, dict):
            add(item, source="location", purpose=str(item.get("label") or "Konum araması"), why="Yalnızca Maps/search kısayolu; ReconBot bu konumu doğrulamadı.")
    for item in _as_list(organization.get("public_document_searches")) + _as_list(public_docs.get("manual_document_search_shortcuts")):
        if isinstance(item, dict):
            add(item, source="public_documents", purpose=str(item.get("label") or "Herkese açık doküman araması"), why="Manuel doküman dork; doğrulanmış herkese açık doküman değil.")
    for item in _as_list(people.get("company_profile_lookup_shortcuts")):
        if isinstance(item, dict):
            add(item, source="profiles", purpose=str(item.get("label") or "Company profile lookup"), why="Manuel profil araması; resmî kaynaktan linklenmiş değil.")
    for source in sources:
        if not isinstance(source, dict):
            continue
        for item in _as_list(source.get("browser_lookup_links")):
            if isinstance(item, dict):
                add(item, source=str(source.get("name") or "source_lookup"), purpose=str(item.get("label") or "Kaynak browser araması"), why="Browser-safe arama kısayolu; toplanmış kanıt değil.")
    return rows


def _fallback_shortcuts_rows(rows: list[dict[str, Any]]) -> str:
    html_rows: list[str] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        item = _as_dict(row.get("item"))
        link = str(item.get("url") or item.get("link") or "")
        key = (str(row.get("source") or ""), link or str(row.get("purpose") or ""))
        if key in seen:
            continue
        seen.add(key)
        html_rows.append(
            "<tr>"
            f"<td>{_html_escape(row.get('source') or '-')}</td>"
            f"<td>{_html_escape(_display_manual_lookup_label(row.get('purpose') or '-', url_role=item.get('url_role') or 'manual_search_suggestion', url=link))}</td>"
            f"<td>{_html_escape(_display_text(row.get('why') or '-'))}</td>"
            f"<td>{_fallback_item_link_html(item)}</td>"
            f"<td>{_html_escape(item.get('risk_score_impact', 0))}</td>"
            "</tr>"
        )
    return "".join(html_rows) or '<tr><td colspan="5">Manuel/API-gerekli arama kısayolu üretilmedi.</td></tr>'


def _fallback_manual_shortcuts_html(
    *,
    organization: dict[str, Any],
    infrastructure: dict[str, Any],
    sources: list[Any],
    operator_search_tasks: list[Any],
    generic_or_reserved_domain: bool,
) -> str:
    rows = _collect_fallback_shortcuts(
        organization=organization,
        infrastructure=infrastructure,
        sources=sources,
        operator_search_tasks=operator_search_tasks,
    )
    return f"""
      <h3 id="osint-manual-search-suggestions">Manuel / API Gerektiren Arama Kısayolları</h3>
      <details class="show-more">
        <summary>Manuel / API-gerekli arama kısayolları ({_html_escape(len(rows))})</summary>
        <p class="operator-view-note"><strong>Bunlar bulgu değildir.</strong> Manuel aramalar, API-key-required lookup'lar, source browser kısayolları ve üretilen öneriler yalnızca manuel öneri teşhisi olarak kalır; manuel arama önerisi doğrulanmış bulgu değildir. Risk etkisi her zaman 0'dır.{_html_escape(' Generic/example domainler çoğunlukla dokümantasyon gürültüsü üretebilir.' if generic_or_reserved_domain else '')}</p>
        <table>
          <tr><th>Kaynak</th><th>Amaç</th><th>Neden manuel?</th><th>Link</th><th>Risk etkisi</th></tr>
          {_fallback_shortcuts_rows(rows)}
        </table>
      </details>
    """


def render_osint_section(context: dict[str, Any]) -> str:
    osint = context.get("osint") if isinstance(context.get("osint"), dict) else {}
    if not osint or osint.get("enabled") is not True:
        return ""

    summary = osint.get("summary") if isinstance(osint.get("summary"), dict) else {}
    sources = osint.get("sources") if isinstance(osint.get("sources"), list) else []
    signals = osint.get("signals") if isinstance(osint.get("signals"), list) else []
    asset_identity_observations = osint.get("asset_identity_observations") if isinstance(osint.get("asset_identity_observations"), list) else []
    asset_discovery_candidates = osint.get("asset_discovery_candidates") if isinstance(osint.get("asset_discovery_candidates"), list) else []
    infrastructure = osint.get("infrastructure") if isinstance(osint.get("infrastructure"), dict) else {}
    organization_intelligence = osint.get("organization_intelligence") if isinstance(osint.get("organization_intelligence"), dict) else {}
    historical_url_context = _as_list(osint.get("historical_url_context"))
    operator_search_tasks = osint.get("operator_search_tasks") if isinstance(osint.get("operator_search_tasks"), list) else []
    suppressed_signals = osint.get("suppressed_signals") if isinstance(osint.get("suppressed_signals"), list) else []
    policy = osint.get("policy") if isinstance(osint.get("policy"), dict) else {}
    diagnostics = osint.get("diagnostics") if isinstance(osint.get("diagnostics"), dict) else {}
    normalization = osint.get("normalization") if isinstance(osint.get("normalization"), dict) else {}
    leak_intelligence = osint.get("leak_intelligence") if isinstance(osint.get("leak_intelligence"), dict) else {}
    darkweb_intelligence = osint.get("darkweb_intelligence") if isinstance(osint.get("darkweb_intelligence"), dict) else {}
    leak_summary = _as_dict(leak_intelligence.get("summary"))
    source_health = osint.get("source_health") if isinstance(osint.get("source_health"), dict) else _as_dict(summary.get("source_health"))
    observed_signals = summary.get("observed_signals", summary.get("total_signals", len(signals)))
    asset_identity_count = summary.get("asset_identity_observations", len(asset_identity_observations))
    asset_discovery_count = summary.get("asset_discovery_candidates", len(asset_discovery_candidates))
    infrastructure_ips = summary.get("infrastructure_ips", len(_as_list(infrastructure.get("resolved_ips"))))
    infrastructure_ipv6 = summary.get("infrastructure_ipv6", len(_as_list(infrastructure.get("ipv6_addresses"))))
    infrastructure_lookup_tasks = summary.get("infrastructure_lookup_tasks", len(_as_list(infrastructure.get("passive_lookup_links"))))
    cdn_or_proxy_likely_count = summary.get("cdn_or_proxy_likely_count", 1 if infrastructure.get("cdn_or_proxy_likely") else 0)
    org_lookup_tasks = summary.get("organization_lookup_tasks", _as_dict(organization_intelligence.get("summary")).get("organization_lookup_tasks", 0))
    org_contacts = summary.get("role_contact_candidates", _as_dict(organization_intelligence.get("summary")).get("role_contact_candidates", 0))
    org_observed_contacts = summary.get("observed_public_contacts", _as_dict(organization_intelligence.get("summary")).get("observed_public_contacts", 0))
    public_document_search_tasks = summary.get("public_document_search_tasks", _as_dict(organization_intelligence.get("summary")).get("public_document_search_tasks", 0))
    generated_search_tasks = summary.get("generated_search_tasks", len(operator_search_tasks))
    metadata_only_leak_references = _safe_int(_as_dict(darkweb_intelligence.get("summary")).get("observed_references", leak_summary.get("observed_references")))
    generic_or_reserved_domain = bool(normalization.get("generic_or_reserved_domain"))
    observed_signal_count = _safe_int(observed_signals)
    failed_live_sources = (
        _safe_int(source_health.get("error"))
        + _safe_int(source_health.get("timeout"))
        + _safe_int(source_health.get("unavailable"))
        + _safe_int(source_health.get("auth_required_fallback"))
        + _safe_int(source_health.get("rate_limited_fallback"))
    )
    failure_breakdown_parts = [
        f"error {_safe_int(source_health.get('error'))}",
        f"timeout {_safe_int(source_health.get('timeout'))}",
        f"unavailable {_safe_int(source_health.get('unavailable'))}",
        f"auth_required {_safe_int(source_health.get('auth_required_fallback'))}",
        f"rate_limited {_safe_int(source_health.get('rate_limited_fallback'))}",
    ]
    source_failure_notes: list[str] = []
    for item in sources:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        status = str(item.get("status") or "")
        if name == "certificate_transparency":
            for provider in _as_list(item.get("provider_results")):
                if not isinstance(provider, dict):
                    continue
                provider_status = str(provider.get("status") or "")
                if provider_status in {"unavailable", "timeout", "error"}:
                    provider_name = str(provider.get("provider") or "provider")
                    http_status = str(provider.get("http_status") or "").strip()
                    source_failure_notes.append(f"{provider_name}: {provider_status}{(' HTTP ' + http_status) if http_status else ''}")
        elif name == "historical_urls" and status == "timeout":
            source_failure_notes.append("Wayback: timeout")
        elif name == "public_code_search" and status == "auth_required_fallback":
            source_failure_notes.append("GitHub: auth_required_fallback")
    verdict = str(osint.get("verdict") or summary.get("verdict") or osint.get("effective_status") or osint.get("status") or "unknown")
    verdict_reason = str(osint.get("verdict_reason") or summary.get("verdict_reason") or "")
    live_source_statuses = [
        str(item.get("status") or "")
        for item in sources
        if isinstance(item, dict)
        and (
            str(item.get("name") or "") in {"certificate_transparency", "historical_urls"}
            or (str(item.get("name") or "") == "public_code_search" and str(item.get("status") or "") != "suggestions_generated")
            or str(item.get("name") or "") == "known_breach_catalog"
        )
    ]
    live_failures = bool(live_source_statuses) and all(
        status
        in {
            "error",
            "timeout",
            "unavailable",
            "auth_required_fallback",
            "rate_limited_fallback",
            "skipped",
            "suggestions_generated",
        }
        for status in live_source_statuses
    )
    github_auth_missing = any(
        isinstance(item, dict)
        and str(item.get("name") or "") == "public_code_search"
        and str(item.get("status") or "") == "auth_required_fallback"
        for item in sources
    )
    partial_coverage = failed_live_sources > 0 or bool(_coverage_gap_parts(sources))
    top_sentence = ""
    if observed_signal_count > 0:
        top_sentence = f"Pasif OSINT {_html_escape(observed_signals)} gözlemlenmiş sinyal topladı. Bunlar zafiyet değildir ve manuel doğrulama gerektirir."
    elif metadata_only_leak_references > 0:
        top_sentence = (
            f"Aktif OSINT maruziyet kanıtı bulunmadı. Ancak {metadata_only_leak_references} adet sadece-metadata "
            "sızıntı/ihlal referansı görüldü. "
            "Bu aktif bir zafiyet bulgusu değildir ve risk skorunu artırmaz. Kurum ilişkisi manuel doğrulanmalıdır."
        )
    elif live_failures:
        top_sentence = "Gözlemlenmiş OSINT kanıtı toplanmadı; canlı pasif kaynaklar başarısız oldu veya kullanılabilir kayıt döndürmedi. Manuel arama önerileri ayrı listelenir."
    elif partial_coverage:
        top_sentence = "Doğrulanmış bulgu görülmedi; ancak kaynak kapsamı kısmi kaldı."
    else:
        top_sentence = "Canlı pasif kaynaklar tamamlandı ancak gözlemlenmiş kanıt döndürmedi."
    if partial_coverage:
        if observed_signal_count == 0 and "Doğrulanmış bulgu görülmedi; ancak kaynak kapsamı kısmi kaldı." not in top_sentence:
            top_sentence = "Doğrulanmış bulgu görülmedi; ancak kaynak kapsamı kısmi kaldı. " + top_sentence
        top_sentence = "Bu rapor bazı OSINT kaynakları eksik kaldığı için kesin temiz sonucu değildir. " + top_sentence
    if github_auth_missing:
        top_sentence += " GitHub token olmadığı için canlı public code search yapılmadı; sadece manuel arama linkleri üretildi."
    verdict_note = top_sentence if partial_coverage or github_auth_missing else (_display_text(verdict_reason) if verdict_reason else top_sentence)

    policy_items = [
        ("Sadece pasif", policy.get("passive_only")),
        ("Credential dump yok", policy.get("no_credential_download")),
        ("Marketplace scraping yok", policy.get("no_marketplace_scraping")),
        ("Login gerektiren ihlal veritabanı yok", policy.get("no_login_required_sources")),
        ("Secret doğrulama yok", True),
        ("Exploit aktivitesi yok", policy.get("no_active_exploit")),
        ("Risk skoru etkisi", policy.get("risk_score_impact")),
    ]
    policy_html = "".join(
        f"<li><strong>{_html_escape(label)}:</strong> {_html_escape(value)}</li>"
        for label, value in policy_items
    )
    suppressed_html = ""
    if suppressed_signals:
        suppressed_html = f"""
      <table>
        <tr><th>Öncelik</th><th>Kategori</th><th>Sinyal</th><th>Kaynak</th><th>Güven</th><th>Kanıt / snippet</th><th>Önerilen aksiyon</th></tr>
        {_signal_rows(suppressed_signals)}
      </table>
      """

    return f"""
    <div class="section compact report-depth-body-all" data-depth-body="summary balanced deep" id="osint-enrichment">
      <h2>OSINT Yönetici Özeti</h2>
      {_turkish_operator_brief_html(osint=osint, sources=sources, organization=organization_intelligence, infrastructure=infrastructure)}
      <details class="show-more report-evidence-disclosure report-depth-evidence-detail"{' open' if getattr(context.get('report_depth_config'), 'name', 'balanced') == 'deep' else ''}>
      <summary>OSINT kaynakları, kanıtlar ve manuel inceleme ayrıntıları</summary>
      {_osint_intelligence_board_html(osint, signals, sources, organization_intelligence, infrastructure)}
      {_evidence_context_fallback_legend_html()}
      {_source_coverage_overview_html(osint, sources, leak_intelligence)}
      {_leak_intelligence_html(leak_intelligence, darkweb_intelligence)}
      <h3 id="osint-overview">OSINT Genel Bakış</h3>
      {_osint_findings_summary_html(
          osint=osint,
          signals=signals,
          sources=sources,
          organization=organization_intelligence,
          infrastructure=infrastructure,
          failed_live_sources=failed_live_sources,
          failure_breakdown_parts=failure_breakdown_parts,
      )}
      <div class="kpi-grid overview-core-grid">
        <div class="kpi">
          <div class="label">OSINT sonucu</div>
          <div class="value" style="font-size:20px; line-height:1.2;">{_html_escape(verdict)}</div>
          <div class="note">{_html_escape(verdict_note)}</div>
          <div class="note">Aktif maruziyet kanıtı: {_html_escape(observed_signals)} | Sadece-metadata sızıntı/ihlal referansı: {_html_escape(metadata_only_leak_references)}</div>
        </div>
        <div class="kpi">
          <div class="label">Gözlemlenmiş aktif OSINT kanıtı</div>
          <div class="value">{_html_escape(observed_signals)}</div>
          <div class="note">Metadata-only sızıntı/ihlal referansları ve manuel fallback görevleri hariçtir.</div>
        </div>
        <div class="kpi">
          <div class="label">Sadece-metadata sızıntı/ihlal referansı</div>
          <div class="value">{_html_escape(metadata_only_leak_references)}</div>
          <div class="note">Aktif zafiyet bulgusu değildir; risk skoru etkisi yoktur.</div>
        </div>
        <div class="kpi">
          <div class="label">Manuel arama önerileri</div>
          <div class="value">{_html_escape(generated_search_tasks)}</div>
          <div class="note">suggestion_only; bulgu değildir.</div>
        </div>
        <div class="kpi">
          <div class="label">Kaynak kapsamı sorunları</div>
          <div class="value">{_html_escape(failed_live_sources)}</div>
          <div class="note">{_html_escape('; '.join(source_failure_notes) or 'Hatalar kaynak teşhisidir; target yokluğu anlamına gelmez.')}</div>
          <div class="note">{_html_escape(' | '.join(failure_breakdown_parts))}</div>
        </div>
      </div>
      <p class="operator-view-note"><strong>Manuel arama önerileri bulgu değildir.</strong> Üretilen arama linkleri suggestion_only kontrol listesi öğeleridir; gözlemlenen kanıt, güven, manuel-inceleme sayısı veya risk skorunu artırmaz.</p>
      <p class="operator-view-note">
        OSINT sinyalleri doğrulanmış zafiyet değildir. Yalnızca pasif, public ve legal kaynaklara izin verilir; ReconBot credential dump toplamaz,
        marketplace scrape etmez, login gerektiren ihlal veritabanlarına erişmez, secret doğrulamaz veya exploit aktivitesi yapmaz.
      </p>
      {('<p class="operator-view-note"><strong>Generic/reserved domain notu:</strong> Bu generic/reserved/example domain; public arama sonuçları çoğunlukla dokümantasyon gürültüsü olabilir.</p>' if generic_or_reserved_domain else '')}
      {('<p class="operator-view-note"><strong>Aktif OSINT maruziyet kanıtı bulunmadı.</strong> Ancak ' + _html_escape(metadata_only_leak_references) + ' adet sadece-metadata sızıntı/ihlal referansı görüldü. Bu aktif bir zafiyet bulgusu değildir ve risk skorunu artırmaz. Kuruma gerçekten ait olup olmadığı manuel olarak doğrulanmalıdır.</p>' if observed_signal_count == 0 and metadata_only_leak_references > 0 else ('<p class="operator-view-note"><strong>Gözlemlenmiş OSINT kanıtı toplanmadı.</strong> Canlı pasif kaynaklar başarısız oldu veya kayıt döndürmedi. Manuel arama önerileri ayrı listelenir.</p>' if observed_signal_count == 0 and live_failures else ('<p class="operator-view-note"><strong>Bu çalıştırmada aktif OSINT maruziyet kanıtı bulunmadı.</strong> Manuel arama önerileri ve metadata-only referanslar ayrı bağlamdır, aktif bulgu değildir.</p>' if observed_signal_count == 0 else '')))}
      <div class="kpi-grid overview-core-grid">
        <div class="kpi">
          <div class="label">Durum</div>
          <div class="value">{_html_escape(_display_status_label(osint.get("status")))}</div>
          <div class="note">Effective: {_html_escape(osint.get("effective_status", summary.get("effective_status", "")))} | Mode: {_html_escape(osint.get("mode"))}</div>
        </div>
        <div class="kpi">
          <div class="label">Gözlemlenen sinyaller</div>
          <div class="value">{_html_escape(observed_signals)}</div>
          <div class="note">Doğrulanmış: {_html_escape(summary.get("confirmed", 0))} | Doğrulanmamış: {_html_escape(summary.get("unconfirmed", 0))}</div>
        </div>
        <div class="kpi">
          <div class="label">Asset identity gözlemleri</div>
          <div class="value">{_html_escape(asset_identity_count)}</div>
          <div class="note">Root/www CT kayıtları; maruziyet bulgusu değil.</div>
        </div>
        <div class="kpi">
          <div class="label">Asset discovery adayları</div>
          <div class="value">{_html_escape(asset_discovery_count)}</div>
          <div class="note">Pasif CT adayları; gözlemlenmiş kanıt değil.</div>
        </div>
        <div class="kpi">
          <div class="label">Altyapı IP'leri</div>
          <div class="value">{_html_escape(infrastructure_ips)}</div>
          <div class="note">A record'ları; gözlemlenmiş maruziyet değil.</div>
        </div>
        <div class="kpi">
          <div class="label">Altyapı IPv6</div>
          <div class="value">{_html_escape(infrastructure_ipv6)}</div>
          <div class="note">AAAA record'ları; gözlemlenmiş maruziyet değil.</div>
        </div>
        <div class="kpi">
          <div class="label">Altyapı lookup görevleri</div>
          <div class="value">{_html_escape(infrastructure_lookup_tasks)}</div>
          <div class="note">Pasif kısayol linkleri; bulgu değil.</div>
        </div>
        <div class="kpi">
          <div class="label">CDN/proxy olası</div>
          <div class="value">{_html_escape(cdn_or_proxy_likely_count)}</div>
          <div class="note">CDN IP'leri origin kanıtı değildir.</div>
        </div>
        <div class="kpi">
          <div class="label">Organizasyon lookup görevleri</div>
          <div class="value">{_html_escape(org_lookup_tasks)}</div>
          <div class="note">Manuel company/profile/location kısayolları; bulgu değil.</div>
        </div>
        <div class="kpi">
          <div class="label">Role contact adayları</div>
          <div class="value">{_html_escape(org_contacts)}</div>
          <div class="note">Üretilen role contact'lar; doğrulanmış değil.</div>
        </div>
        <div class="kpi">
          <div class="label">Gözlemlenen herkese açık iletişim bilgileri</div>
          <div class="value">{_html_escape(org_observed_contacts)}</div>
          <div class="note">Yalnızca resmî herkese açık iletişim endpoint'leri.</div>
        </div>
        <div class="kpi">
          <div class="label">Doküman arama görevleri</div>
          <div class="value">{_html_escape(public_document_search_tasks)}</div>
          <div class="note">Manuel arama önerileri; dokümanlar indirilmez.</div>
        </div>
        <div class="kpi">
          <div class="label">Manuel arama önerileri</div>
          <div class="value">{_html_escape(generated_search_tasks)}</div>
          <div class="note">Sadece öneri; bulgu değil.</div>
        </div>
        <div class="kpi">
          <div class="label">Canlı kaynak sağlığı</div>
          <div class="value" style="font-size:14px; line-height:1.3;">{_html_escape(_source_status_summary(sources))}</div>
          <div class="note">Suggestion-only kaynaklar ayrı sayılır.</div>
        </div>
        <div class="kpi">
          <div class="label">En yüksek güven</div>
          <div class="value">{_html_escape(summary.get("highest_confidence", "none"))}</div>
          <div class="note">Üretilen görevler güven değerini etkilemez.</div>
        </div>
        <div class="kpi">
          <div class="label">Risk skoru etkisi</div>
          <div class="value">{_html_escape(summary.get("risk_score_impact", "none"))}</div>
          <div class="note">Yalnızca external exposure intelligence bağlamı.</div>
        </div>
      </div>
      <details class="show-more">
        <summary>Gelişmiş kaynak kapsamı tablosu</summary>
        {_source_health_summary_html(sources, observed_signal_count, _safe_int(generated_search_tasks))}
      <h3 id="osint-source-coverage">Detaylı Kaynak Kapsamı</h3>
      {_source_action_audit_html(sources, operator_search_tasks)}
      <table>
        <tr><th>Kaynak</th><th>Durum</th><th>Sinyal</th><th>Asset identity</th><th>Raw</th><th>Bastırılan</th><th>Süre ms</th><th>Notlar / hatalar</th><th>Aksiyonlar</th></tr>
        {_source_rows(sources, operator_search_tasks)}
      </table>
      {_source_details_html(sources, operator_search_tasks)}
      </details>
      <span id="osint-diagnostics"></span>
      <details class="show-more">
        <summary>Gelişmiş teşhisler</summary>
        <h3>Teşhisler</h3>
        {_diagnostics_html(diagnostics)}
      </details>
      <span id="osint-observed-signals"></span>
      <h3>Gözlemlenen OSINT Kanıtları</h3>
      <p class="operator-view-note">Gözlemlenen sinyaller yalnızca pasif kaynak kanıt satırlarıdır. Herkese açık ihlal kataloğu metadata'sı öncelikle Darkweb / Sızıntı / İhlal İstihbaratı bölümünde gösterilir ve duplicate bulgu görünümü oluşmaması için bu ana sinyal tablosundan hariç tutulur. Üretilen arama görevleri ve asset identity kayıtları bu tabloya dahil edilmez.</p>
      <table>
        <tr><th>Öncelik</th><th>Kategori</th><th>Sinyal</th><th>Kaynak</th><th>Güven</th><th>Kanıt / snippet</th><th>Önerilen aksiyon</th></tr>
        {_signal_rows(_non_breach_signals(signals))}
      </table>
      <span id="osint-known-breach-catalog"></span>
      <h3>Gelişmiş / Eski Uyumluluk Teşhisleri</h3>
      <p class="operator-view-note"><strong>Sadece compatibility görünümü.</strong> Herkese açık ihlal kataloğu metadata'sı zaten Darkweb / Sızıntı / İhlal İstihbaratı bölümünde gösterilir. Bu legacy satırlar eski known_breach_reference sinyal formatını bekleyen rapor okuyucuları için kalır; aktif zafiyet bulgusu değildir.</p>
      <details class="show-more">
        <summary>Known breach metadata legacy satırları ({_html_escape(len(_known_breach_signals(signals)))})</summary>
        <p class="operator-view-note"><strong>Bunlar üçüncü taraf herkese açık ihlal referanslarıdır; aktif scan bulgusu değildir.</strong> ReconBot sızıntıyı doğrulamaz, kimlik bilgisi toplamaz, dump indirmez veya secret doğrulamaz.</p>
        <table>
          <tr><th>Referans</th><th>Kaynak</th><th>Güven</th><th>İhlal tarihi</th><th>Eklenme tarihi</th><th>Etkilenen hesap</th><th>Etkilenen veri sınıfları</th></tr>
          {_known_breach_rows(_known_breach_signals(signals))}
        </table>
      </details>
      {_ct_provider_health_html(sources)}
      {_ct_asset_discovery_html(sources, asset_identity_observations, asset_discovery_candidates)}
      <h3 id="osint-asset-identity-observations">Asset Identity Gözlemleri</h3>
      <p class="operator-view-note">Bunlar normal sertifika/public asset identity kayıtlarıdır ve maruziyet bulgusu değildir.</p>
      <table>
        <tr><th>Varlık</th><th>Sağlayıcı</th><th>Kanıt</th><th>Neden</th></tr>
        {_asset_identity_rows(asset_identity_observations)}
      </table>
      {_email_intelligence_html(organization_intelligence)}
      {_location_intelligence_html(organization_intelligence)}
      {_public_document_intelligence_html(organization_intelligence)}
      {_people_presence_html(_as_dict(organization_intelligence.get("people_organization_presence")))}
      {_infrastructure_html(infrastructure)}
      {_organization_intelligence_html(organization_intelligence)}
      {_historical_url_context_html(historical_url_context)}
      {_fallback_manual_shortcuts_html(
          organization=organization_intelligence,
          infrastructure=infrastructure,
          sources=sources,
          operator_search_tasks=operator_search_tasks,
          generic_or_reserved_domain=generic_or_reserved_domain,
      )}
      <h3 id="osint-suppressed-noisy-items">Bastırılan / Gürültülü Öğeler</h3>
      {suppressed_html or '<p class="operator-view-note">Bastırılan/gürültülü OSINT kanıt öğesi yok.</p>'}
      {_filtered_rejected_paths_html(organization_intelligence)}
      <h3 id="osint-safety-boundary">Güvenlik Sınırı</h3>
      <ul class="operator-view-note">{policy_html}</ul>
      </details>
    </div>
    """
