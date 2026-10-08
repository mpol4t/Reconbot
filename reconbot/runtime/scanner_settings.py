"""Map UI scanner settings to validated runtime fields; CLI values take precedence."""
from __future__ import annotations

TOOL_FIELDS = {
    "katana": {"maxDepth": "katana_depth", "timeout": "katana_timeout_sec", "rateLimit": "katana_rate_limit", "maxUrls": "katana_max_urls"},
    "gobuster": {"threads": "gobuster_threads", "timeout": "gobuster_timeout"},
    "ffuf": {"rateLimit": "ffuf_rate", "timeout": "ffuf_timeout"},
    "checks": {"timeout": "checks_timeout_sec", "maxBodySize": "checks_max_body_bytes", "followRedirects": "checks_follow_redirects"},
    "screenshots": {"maxScreenshots": "screenshots_limit", "timeout": "screenshots_timeout"},
    "nuclei": {"severityFilter": "nuclei_severity", "rateLimit": "nuclei_rate_limit", "timeout": "nuclei_timeout_sec", "maxTemplates": "nuclei_pool_limit"},
    "ipNmap": {"topPorts": "nmap_top_ports", "timeout": "nmap_timeout_sec"},
}
INTEGER_LIMITS = {
    "katana_depth": (1, 100), "katana_timeout_sec": (1, 3600), "katana_rate_limit": (0, 10000), "katana_max_urls": (0, 100000),
    "nmap_top_ports": (1, 65535), "nmap_timeout_sec": (1, 86400), "nuclei_timeout_sec": (1, 3600),
    "nuclei_pool_limit": (0, 100000), "nuclei_rate_limit": (1, 10000), "gobuster_threads": (1, 1000),
    "gobuster_timeout": (1, 3600), "ffuf_rate": (0, 10000), "ffuf_timeout": (1, 3600),
    "checks_timeout_sec": (1, 3600), "screenshots_limit": (0, 10000), "screenshots_timeout": (1, 86400),
    "checks_max_body_bytes": (1, 16777216),
}
SCANNER_FIELDS = {
    name: f"{name}_enabled" for name in (
        "nmap", "subfinder", "dnsx", "httpx", "katana", "gobuster", "ffuf",
        "historical_urls", "wafw00f", "whatweb", "checks", "nuclei",
    )
}
SCANNER_FIELDS["screenshots"] = "screenshots_enable"


def enabled_scanners(config, target_mode):
    if config.run_mode == "osint_only":
        return []
    return [name for name, field in SCANNER_FIELDS.items()
            if getattr(config, field) and not (target_mode != "domain" and name in {"subfinder", "dnsx", "httpx"})]


def flatten_scanner_settings(config):
    flat = dict(config)
    tools = flat.get("tool_settings") or {}
    if not isinstance(tools, dict):
        raise ValueError("tool_settings bir nesne olmalı.")
    for tool, fields in TOOL_FIELDS.items():
        values = tools.get(tool, {})
        if not isinstance(values, dict):
            raise ValueError(f"tool_settings.{tool} bir nesne olmalı.")
        for source, destination in fields.items():
            if source in values:
                flat.setdefault(destination, values[source])
    return flat


def validate_scanner_settings(config):
    for field in ("checks_follow_redirects", "katana_js_crawl", "katana_auto_js_crawl"):
        if type(getattr(config, field, False)) is not bool:
            raise ValueError(f"{field}: true/false gerekli.")
    for field, (low, high) in INTEGER_LIMITS.items():
        value = getattr(config, field, None)
        if value is None:
            continue
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"{field}: {low}–{high} aralığında tam sayı gerekli (alınan: {value!r}).")
    for name, value in vars(config).items():
        if name.endswith(("_enabled", "_enable")) and type(value) is not bool:
            raise ValueError(f"{name}: true/false gerekli.")
    severity = getattr(config, "nuclei_severity", None)
    if severity and (not isinstance(severity, str) or any(v.strip() not in {"info", "low", "medium", "high", "critical", "unknown"} for v in severity.split(","))):
        raise ValueError("nuclei_severity geçerli önem seviyeleri içermeli.")
