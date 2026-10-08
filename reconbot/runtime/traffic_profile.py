from __future__ import annotations

from copy import deepcopy
from typing import Any


TRAFFIC_PROFILE_DEFAULTS: dict[str, dict[str, Any]] = {
    "safe": {
        "risk_level": "low",
        "katana": {
            "concurrency": 1,
            "parallelism": 1,
            "rate_limit": 1,
            "delay_sec": 1,
        },
        "web_checks": {
            "requests_per_second": 1,
            "delay_ms": 750,
        },
        "nuclei": {
            "rate_limit": 1,
        },
        "nmap": {
            "timing": "T2",
        },
        "gobuster": {
            "threads": 5,
        },
        "ffuf": {
            "threads": 5,
            "rate": 10,
        },
        "httpx": {
            "rate_limit": 10,
        },
        "dnsx": {
            "rate_limit": 10,
        },
        "subfinder": {
            "rate_limit": 5,
        },
        "historical_urls": {
            "max_domains": 25,
            "max_urls": 100,
            "live_check_limit": 25,
        },
        "screenshots": {
            "limit": 10,
        },
    },
    "balanced": {
        "risk_level": "medium",
        "katana": {
            "concurrency": 2,
            "parallelism": 2,
            "rate_limit": 2,
            "delay_sec": 1,
        },
        "web_checks": {
            "requests_per_second": 2,
            "delay_ms": 350,
        },
        "nuclei": {
            "rate_limit": 3,
        },
        "nmap": {
            "timing": "T3",
        },
        "gobuster": {
            "threads": 20,
        },
        "ffuf": {
            "threads": 20,
            "rate": 50,
        },
        "httpx": {
            "rate_limit": 50,
        },
        "dnsx": {
            "rate_limit": 50,
        },
        "subfinder": {
            "rate_limit": 20,
        },
        "historical_urls": {
            "max_domains": 50,
            "max_urls": 300,
            "live_check_limit": 80,
        },
        "screenshots": {
            "limit": 20,
        },
    },
    "fast": {
        "risk_level": "high",
        "katana": {
            "concurrency": 5,
            "parallelism": 4,
            "rate_limit": 6,
            "delay_sec": 0,
        },
        "web_checks": {
            "requests_per_second": 6,
            "delay_ms": 0,
        },
        "nuclei": {
            "rate_limit": 8,
        },
        "nmap": {
            "timing": "T4",
        },
        "gobuster": {
            "threads": 50,
        },
        "ffuf": {
            "threads": 50,
            "rate": 150,
        },
        "httpx": {
            "rate_limit": 150,
        },
        "dnsx": {
            "rate_limit": 150,
        },
        "subfinder": {
            "rate_limit": 50,
        },
        "historical_urls": {
            "max_domains": 25,
            "max_urls": 150,
            "live_check_limit": 40,
        },
        "screenshots": {
            "limit": 10,
        },
    },
    "privacy": {
        "risk_level": "low",
        "katana": {
            "concurrency": 1,
            "parallelism": 1,
            "rate_limit": 1,
            "delay_sec": 1,
        },
        "web_checks": {
            "requests_per_second": 1,
            "delay_ms": 750,
        },
        "nuclei": {
            "rate_limit": 1,
        },
        "nmap": {
            "timing": "T2",
        },
        "gobuster": {
            "threads": 5,
        },
        "ffuf": {
            "threads": 5,
            "rate": 10,
        },
        "httpx": {
            "rate_limit": 10,
        },
        "dnsx": {
            "rate_limit": 10,
        },
        "subfinder": {
            "rate_limit": 5,
        },
        "historical_urls": {
            "max_domains": 10,
            "max_urls": 100,
            "live_check_limit": 10,
        },
        "screenshots": {
            "limit": 5,
        },
    },
    "slow": {
        "risk_level": "low",
        "katana": {
            "concurrency": 1,
            "parallelism": 1,
            "rate_limit": 1,
            "delay_sec": 1,
        },
        "web_checks": {
            "requests_per_second": 1,
            "delay_ms": 750,
        },
        "nuclei": {
            "rate_limit": 1,
        },
        "nmap": {
            "timing": "T2",
        },
        "gobuster": {
            "threads": 5,
        },
        "ffuf": {
            "threads": 5,
            "rate": 10,
        },
        "httpx": {
            "rate_limit": 10,
        },
        "dnsx": {
            "rate_limit": 10,
        },
        "subfinder": {
            "rate_limit": 5,
        },
        "historical_urls": {
            "max_domains": 10,
            "max_urls": 100,
            "live_check_limit": 10,
        },
        "screenshots": {
            "limit": 5,
        },
    },
}


def _merge_non_none(base: dict[str, Any], overrides: dict[str, Any]) -> None:
    for key, value in (overrides or {}).items():
        if value is None:
            continue
        if isinstance(value, dict):
            current = base.get(key)
            if not isinstance(current, dict):
                current = {}
                base[key] = current
            _merge_non_none(current, value)
            continue
        base[key] = value


def _normalize_nmap_timing(value: Any, *, fallback: str = "T3") -> str:
    raw = str(value or "").strip().upper()
    if raw.startswith("-T"):
        raw = raw[2:]
    elif raw.startswith("T"):
        raw = raw[1:]

    if raw.isdigit():
        timing_int = int(raw)
        if 0 <= timing_int <= 4:
            return f"T{timing_int}"
        if timing_int >= 5:
            return "T4"

    fb = str(fallback or "").strip().upper()
    if fb.startswith("-T"):
        fb = fb[2:]
    elif fb.startswith("T"):
        fb = fb[1:]
    if fb.isdigit():
        fb_int = int(fb)
        if 0 <= fb_int <= 4:
            return f"T{fb_int}"
    return "T3"


def _coerce_int(value: Any, fallback: int, *, min_value: int | None = None) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = int(fallback)
    if min_value is not None and parsed < min_value:
        parsed = min_value
    return parsed


def resolve_traffic_profile(
    profile_name: str,
    explicit_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve profile defaults and apply non-None explicit overrides.

    Explicit overrides should be passed as a nested dict keyed by tool name:
    {
        "nmap": {"timing": "T3"},
        "gobuster": {"threads": 30},
    }
    """
    profile = (profile_name or "balanced").strip().lower() or "balanced"
    if profile not in TRAFFIC_PROFILE_DEFAULTS:
        profile = "balanced"

    resolved = deepcopy(TRAFFIC_PROFILE_DEFAULTS[profile])
    _merge_non_none(resolved, explicit_overrides or {})

    nmap = resolved.setdefault("nmap", {})
    nmap["timing"] = _normalize_nmap_timing(
        nmap.get("timing"),
        fallback=str((TRAFFIC_PROFILE_DEFAULTS[profile].get("nmap") or {}).get("timing", "T3")),
    )

    gobuster = resolved.setdefault("gobuster", {})
    gobuster["threads"] = _coerce_int(
        gobuster.get("threads"),
        int((TRAFFIC_PROFILE_DEFAULTS[profile].get("gobuster") or {}).get("threads", 20)),
        min_value=1,
    )

    ffuf = resolved.setdefault("ffuf", {})
    ffuf["threads"] = _coerce_int(
        ffuf.get("threads"),
        int((TRAFFIC_PROFILE_DEFAULTS[profile].get("ffuf") or {}).get("threads", 20)),
        min_value=1,
    )
    ffuf["rate"] = _coerce_int(
        ffuf.get("rate"),
        int((TRAFFIC_PROFILE_DEFAULTS[profile].get("ffuf") or {}).get("rate", 50)),
    )

    subfinder = resolved.setdefault("subfinder", {})
    subfinder["rate_limit"] = _coerce_int(
        subfinder.get("rate_limit"),
        int((TRAFFIC_PROFILE_DEFAULTS[profile].get("subfinder") or {}).get("rate_limit", 20)),
    )

    dnsx = resolved.setdefault("dnsx", {})
    dnsx["rate_limit"] = _coerce_int(
        dnsx.get("rate_limit"),
        int((TRAFFIC_PROFILE_DEFAULTS[profile].get("dnsx") or {}).get("rate_limit", 50)),
    )

    httpx = resolved.setdefault("httpx", {})
    httpx["rate_limit"] = _coerce_int(
        httpx.get("rate_limit"),
        int((TRAFFIC_PROFILE_DEFAULTS[profile].get("httpx") or {}).get("rate_limit", 50)),
    )

    historical_urls = resolved.setdefault("historical_urls", {})
    historical_urls["max_domains"] = _coerce_int(
        historical_urls.get("max_domains"),
        int((TRAFFIC_PROFILE_DEFAULTS[profile].get("historical_urls") or {}).get("max_domains", 50)),
        min_value=0,
    )
    historical_urls["max_urls"] = _coerce_int(
        historical_urls.get("max_urls"),
        int((TRAFFIC_PROFILE_DEFAULTS[profile].get("historical_urls") or {}).get("max_urls", 300)),
        min_value=0,
    )
    historical_urls["live_check_limit"] = _coerce_int(
        historical_urls.get("live_check_limit"),
        int((TRAFFIC_PROFILE_DEFAULTS[profile].get("historical_urls") or {}).get("live_check_limit", 80)),
        min_value=0,
    )

    screenshots = resolved.setdefault("screenshots", {})
    screenshots["limit"] = _coerce_int(
        screenshots.get("limit"),
        int((TRAFFIC_PROFILE_DEFAULTS[profile].get("screenshots") or {}).get("limit", 20)),
        min_value=0,
    )

    nuclei = resolved.setdefault("nuclei", {})
    nuclei["rate_limit"] = _coerce_int(
        nuclei.get("rate_limit"),
        int((TRAFFIC_PROFILE_DEFAULTS[profile].get("nuclei") or {}).get("rate_limit", 3)),
    )

    return resolved
