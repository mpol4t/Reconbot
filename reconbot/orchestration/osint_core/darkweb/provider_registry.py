"""Provider profiles for safe metadata-only darkweb intelligence."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class DarkwebProviderProfile:
    provider_id: str
    display_name_tr: str
    enabled_by_default: bool
    source_modes: tuple[str, ...] = field(default_factory=tuple)
    allowed_url_patterns: tuple[str, ...] = field(default_factory=tuple)
    auth_mode: str = "none"
    metadata_only: bool = True
    forbids_credentials: bool = True
    forbids_dumps: bool = True
    forbids_raw_records: bool = True
    risk_score_impact: int = 0
    warning_tr: str = ""
    status: str = "active"


MANUAL_DARKWEB_METADATA_IMPORT = "manual_darkweb_metadata_import"
CUSTOM_HTTPS_DARKWEB_METADATA_PROVIDER = "custom_https_darkweb_metadata_provider"
TOR_ONION_CRAWL_UNSUPPORTED = "tor_onion_crawl_unsupported"


PROFILES: dict[str, DarkwebProviderProfile] = {
    MANUAL_DARKWEB_METADATA_IMPORT: DarkwebProviderProfile(
        provider_id=MANUAL_DARKWEB_METADATA_IMPORT,
        display_name_tr="Manuel darkweb metadata import",
        enabled_by_default=False,
        source_modes=("local_metadata_json",),
        metadata_only=True,
        forbids_credentials=True,
        forbids_dumps=True,
        forbids_raw_records=True,
        risk_score_impact=0,
    ),
    CUSTOM_HTTPS_DARKWEB_METADATA_PROVIDER: DarkwebProviderProfile(
        provider_id=CUSTOM_HTTPS_DARKWEB_METADATA_PROVIDER,
        display_name_tr="Custom HTTPS darkweb metadata sağlayıcısı",
        enabled_by_default=False,
        source_modes=("https_json",),
        allowed_url_patterns=("https://",),
        auth_mode="optional_bearer_env",
        metadata_only=True,
        forbids_credentials=True,
        forbids_dumps=True,
        forbids_raw_records=True,
        risk_score_impact=0,
        warning_tr="Yalnızca güvenilir metadata-only sağlayıcılar kullanılmalıdır.",
        status="placeholder",
    ),
    TOR_ONION_CRAWL_UNSUPPORTED: DarkwebProviderProfile(
        provider_id=TOR_ONION_CRAWL_UNSUPPORTED,
        display_name_tr="Tor/onion crawling",
        enabled_by_default=False,
        source_modes=(),
        metadata_only=False,
        forbids_credentials=True,
        forbids_dumps=True,
        forbids_raw_records=True,
        risk_score_impact=0,
        warning_tr="ReconBot safe mode Tor/onion crawling yapmaz.",
        status="not_supported",
    ),
}


def provider_profiles() -> dict[str, DarkwebProviderProfile]:
    return dict(PROFILES)


def validate_custom_https_provider(config: dict[str, Any] | None) -> tuple[str, str]:
    cfg = config if isinstance(config, dict) else {}
    if not bool(cfg.get("enabled", False)):
        return "disabled", "Custom HTTPS darkweb metadata sağlayıcısı kapalı."
    url = str(cfg.get("providerUrl") or cfg.get("provider_url") or cfg.get("feedUrl") or "").strip()
    if not url:
        return "not_configured", "Kaynak açık ama yapılandırılmamış."
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not parsed.netloc or host.endswith(".onion"):
        return "invalid_config", "Custom HTTPS darkweb metadata sağlayıcısı yalnızca https:// URL kabul eder; onion/http/file desteklenmez."
    return "not_supported", "HTTPS provider profili geçerli; canlı provider entegrasyonu bu sürümde uygulanmadı."
