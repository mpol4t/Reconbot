"""Safe provider registry for metadata-only leak/breach intelligence feeds."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Mapping
from urllib.parse import urlsplit


ProviderValidationStatus = Literal["valid", "invalid_config", "not_implemented"]


@dataclass(frozen=True)
class ProviderProfile:
    provider_id: str
    display_name: str
    description: str
    source_type: str
    enabled_by_default: bool
    allowed_source_modes: tuple[str, ...] = field(default_factory=tuple)
    allowed_url_patterns: tuple[str, ...] = field(default_factory=tuple)
    auth_mode: str = "none"
    api_key_env_required: bool = False
    schema_adapter: str = "generic_metadata_feed_v1"
    max_results_default: int = 25
    timeout_default: int = 10
    rate_limit_hint: str = ""
    metadata_only: bool = True
    forbids_raw_content: bool = True
    forbids_credentials: bool = True
    forbids_dumps: bool = True
    risk_score_impact: int = 0
    safety_notes: tuple[str, ...] = field(default_factory=tuple)
    operator_warning: str = ""
    status: str = "active"


@dataclass(frozen=True)
class ProviderValidation:
    status: ProviderValidationStatus
    message: str
    provider_id: str
    source_mode: str
    profile: ProviderProfile | None = None
    explicit_provider_id: bool = False


LOCAL_DEMO_FEED = "local_demo_feed"
CUSTOM_HTTPS_METADATA_FEED = "custom_https_metadata_feed"
FUTURE_TRUSTED_PROVIDER_PROFILE = "future_trusted_provider_profile"


PROVIDER_REGISTRY: dict[str, ProviderProfile] = {
    LOCAL_DEMO_FEED: ProviderProfile(
        provider_id=LOCAL_DEMO_FEED,
        display_name="Local demo metadata feed",
        description="Local JSON fixture for deterministic metadata-feed testing.",
        source_type="leak_metadata_api",
        enabled_by_default=False,
        allowed_source_modes=("local_file",),
        allowed_url_patterns=(),
        auth_mode="none",
        api_key_env_required=False,
        schema_adapter="generic_metadata_feed_v1",
        max_results_default=25,
        timeout_default=10,
        rate_limit_hint="Local file read only.",
        metadata_only=True,
        forbids_raw_content=True,
        forbids_credentials=True,
        forbids_dumps=True,
        risk_score_impact=0,
        safety_notes=(
            "Local fixture only.",
            "Metadata references do not affect risk score.",
        ),
        operator_warning="Demo fixture for local testing only. Do not treat as a production intelligence provider.",
    ),
    CUSTOM_HTTPS_METADATA_FEED: ProviderProfile(
        provider_id=CUSTOM_HTTPS_METADATA_FEED,
        display_name="Custom HTTPS metadata feed",
        description="Operator-configured trusted HTTPS JSON metadata feed.",
        source_type="leak_metadata_api",
        enabled_by_default=False,
        allowed_source_modes=("https_json",),
        allowed_url_patterns=("https://",),
        auth_mode="optional_bearer_env",
        api_key_env_required=False,
        schema_adapter="generic_metadata_feed_v1",
        max_results_default=25,
        timeout_default=10,
        rate_limit_hint="Respect the configured provider's documented rate limits.",
        metadata_only=True,
        forbids_raw_content=True,
        forbids_credentials=True,
        forbids_dumps=True,
        risk_score_impact=0,
        safety_notes=(
            "Only https:// endpoints are accepted.",
            "Use trusted metadata-only providers only.",
        ),
        operator_warning=(
            "Only use trusted metadata-only feeds. Do not configure feeds containing credentials, "
            "dumps, raw paste content, or personal records."
        ),
    ),
    FUTURE_TRUSTED_PROVIDER_PROFILE: ProviderProfile(
        provider_id=FUTURE_TRUSTED_PROVIDER_PROFILE,
        display_name="Future trusted provider profile",
        description="Reserved provider profile placeholder. No live integration exists.",
        source_type="leak_metadata_api",
        enabled_by_default=False,
        allowed_source_modes=(),
        allowed_url_patterns=(),
        auth_mode="none",
        api_key_env_required=False,
        schema_adapter="generic_metadata_feed_v1",
        max_results_default=25,
        timeout_default=10,
        rate_limit_hint="Not implemented.",
        metadata_only=True,
        forbids_raw_content=True,
        forbids_credentials=True,
        forbids_dumps=True,
        risk_score_impact=0,
        safety_notes=("Placeholder only. No runtime access is implemented.",),
        operator_warning="Placeholder only. No live provider integration is implemented.",
        status="placeholder",
    ),
}


def get_provider_profile(provider_id: str) -> ProviderProfile | None:
    return PROVIDER_REGISTRY.get(str(provider_id or "").strip())


def provider_profiles() -> dict[str, ProviderProfile]:
    return dict(PROVIDER_REGISTRY)


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _provider_id_from_config(config: Mapping[str, Any]) -> tuple[str, bool]:
    configured = _clean(config.get("providerId") or config.get("provider_id"))
    if configured:
        return configured, True
    feed_path = _clean(config.get("feedPath") or config.get("feed_path"))
    feed_url = _clean(config.get("feedUrl") or config.get("feed_url"))
    if feed_path and not feed_url:
        return LOCAL_DEMO_FEED, False
    if feed_url:
        return CUSTOM_HTTPS_METADATA_FEED, False
    return CUSTOM_HTTPS_METADATA_FEED, False


def source_mode_from_config(config: Mapping[str, Any]) -> str:
    raw_mode = _clean(
        config.get("sourceType")
        or config.get("source_type")
        or config.get("sourceMode")
        or config.get("source_mode")
        or config.get("feedSourceType")
        or config.get("feed_source_type")
    )
    normalized_mode = {
        "local_json": "local_file",
        "local": "local_file",
        "file": "local_file",
        "https": "https_json",
    }.get(raw_mode, raw_mode)
    if normalized_mode:
        return normalized_mode
    if _clean(config.get("feedPath") or config.get("feed_path")):
        return "local_file"
    if _clean(config.get("feedUrl") or config.get("feed_url")):
        return "https_json"
    return ""


def infer_provider_id(config: Mapping[str, Any] | None) -> str:
    provider_id, _explicit = _provider_id_from_config(config if isinstance(config, Mapping) else {})
    return provider_id


def _profile_safety_violation(profile: ProviderProfile) -> str:
    if not profile.metadata_only:
        return "provider profile is not metadata-only"
    if not profile.forbids_raw_content:
        return "provider profile does not forbid raw content"
    if not profile.forbids_credentials:
        return "provider profile does not forbid credentials"
    if not profile.forbids_dumps:
        return "provider profile does not forbid dumps"
    if profile.risk_score_impact > 0:
        return "provider profile risk_score_impact must be 0"
    return ""


def validate_metadata_feed_provider(config: Mapping[str, Any] | None) -> ProviderValidation:
    cfg = config if isinstance(config, Mapping) else {}
    provider_id, explicit_provider = _provider_id_from_config(cfg)
    source_mode = source_mode_from_config(cfg)
    profile = get_provider_profile(provider_id)
    if profile is None:
        return ProviderValidation(
            status="invalid_config",
            message=f"Unknown metadata feed providerId: {provider_id or 'missing'}.",
            provider_id=provider_id,
            source_mode=source_mode,
            profile=None,
            explicit_provider_id=explicit_provider,
        )

    safety_violation = _profile_safety_violation(profile)
    if safety_violation:
        return ProviderValidation(
            status="invalid_config",
            message=f"Unsafe provider profile rejected: {safety_violation}.",
            provider_id=provider_id,
            source_mode=source_mode,
            profile=profile,
            explicit_provider_id=explicit_provider,
        )

    if profile.status == "placeholder":
        return ProviderValidation(
            status="not_implemented",
            message="Provider profile is a placeholder; no live provider integration is implemented.",
            provider_id=provider_id,
            source_mode=source_mode,
            profile=profile,
            explicit_provider_id=explicit_provider,
        )

    enabled = bool(cfg.get("enabled", False))
    feed_path = _clean(cfg.get("feedPath") or cfg.get("feed_path"))
    feed_url = _clean(cfg.get("feedUrl") or cfg.get("feed_url"))
    if not enabled:
        return ProviderValidation(
            status="valid",
            message="Provider profile is valid; metadataFeed.enabled=false.",
            provider_id=provider_id,
            source_mode=source_mode,
            profile=profile,
            explicit_provider_id=explicit_provider,
        )

    if source_mode and source_mode not in profile.allowed_source_modes:
        return ProviderValidation(
            status="invalid_config",
            message=f"Provider {provider_id} does not support source mode {source_mode}.",
            provider_id=provider_id,
            source_mode=source_mode,
            profile=profile,
            explicit_provider_id=explicit_provider,
        )

    if provider_id == LOCAL_DEMO_FEED:
        if feed_url:
            return ProviderValidation(
                status="invalid_config",
                message="local_demo_feed accepts only local_file mode with feedPath; feedUrl is not supported.",
                provider_id=provider_id,
                source_mode=source_mode or "local_file",
                profile=profile,
                explicit_provider_id=explicit_provider,
            )
        if not feed_path and explicit_provider:
            return ProviderValidation(
                status="invalid_config",
                message="local_demo_feed requires feedPath when explicitly enabled.",
                provider_id=provider_id,
                source_mode=source_mode or "local_file",
                profile=profile,
                explicit_provider_id=explicit_provider,
            )

    if provider_id == CUSTOM_HTTPS_METADATA_FEED:
        if feed_path:
            return ProviderValidation(
                status="invalid_config",
                message="custom_https_metadata_feed accepts only https_json mode with feedUrl; feedPath is not supported.",
                provider_id=provider_id,
                source_mode=source_mode or "https_json",
                profile=profile,
                explicit_provider_id=explicit_provider,
            )
        if not feed_url and explicit_provider:
            return ProviderValidation(
                status="invalid_config",
                message="custom_https_metadata_feed requires feedUrl when explicitly enabled.",
                provider_id=provider_id,
                source_mode=source_mode or "https_json",
                profile=profile,
                explicit_provider_id=explicit_provider,
            )
        if feed_url:
            parsed = urlsplit(feed_url)
            if parsed.scheme != "https" or not parsed.netloc:
                return ProviderValidation(
                    status="invalid_config",
                    message="custom_https_metadata_feed accepts only complete https:// feedUrl values.",
                    provider_id=provider_id,
                    source_mode=source_mode or "https_json",
                    profile=profile,
                    explicit_provider_id=explicit_provider,
                )

    return ProviderValidation(
        status="valid",
        message="Provider registry validation passed.",
        provider_id=provider_id,
        source_mode=source_mode,
        profile=profile,
        explicit_provider_id=explicit_provider,
    )
