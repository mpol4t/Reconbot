# reconbot/core/engine.py


from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timezone
import subprocess
import ipaddress
import socket
import json
import time
import hashlib
import uuid
from urllib.parse import urlsplit, urlunsplit, urlencode
from typing import Any, Iterator
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen
from urllib.error import URLError, HTTPError
import os
import re

from reconbot.core.nmap_scan import run_nmap, parse_nmap_xml
from reconbot.runtime.scanner_settings import validate_scanner_settings, enabled_scanners
from reconbot.runtime.run_lifecycle import atomic_json, result_coverage_status
from reconbot.runtime.scanner_result import ScannerItems, scanner_metadata, aggregate_scanner_status
from reconbot.runtime.tool_metadata import runtime_metadata
from reconbot.core.gobuster_scan import run_gobuster
def _run_gobuster_compat(
    base_url: str,
    wordlist: str,
    *,
    threads: int,
    timeout: int,
    allowed_status: list[int] | None,
) -> list[dict]:
    """Run gobuster with a compatible signature.

    We previously passed `timeout_sec=...` from the engine, but the gobuster wrapper may
    expose `timeout=...` instead (or vice-versa). This helper tries both.
    """
    try:
        return run_gobuster(
            base_url,
            wordlist,
            threads=threads,
            timeout=timeout,
            allowed_status=allowed_status,
        )
    except TypeError:
        # Fallback for older wrapper versions that used `timeout_sec`
        return run_gobuster(
            base_url,
            wordlist,
            threads=threads,
            timeout_sec=timeout,
            allowed_status=allowed_status,
        )
from reconbot.core.nuclei_scan import start_nuclei
from reconbot.core.dnsx_scan import run_dnsx
from reconbot.core.httpx_scan import run_httpx
from reconbot.core.subfinder_scan import run_subfinder
from reconbot.core.katana import run_katana
from reconbot.core.ffuf_scan import run_ffuf
from reconbot.core.web_checks import run_web_checks
from reconbot.core.wafw00f_scan import run_wafw00f
from reconbot.core.whatweb_scan import run_whatweb
from reconbot.core.screenshots import capture_screenshots
from reconbot.core.endpoint_analysis import analyze_endpoints, summary_to_dict
from reconbot.core.auth_profiler import build_auth_profile
from reconbot.core.historical_urls import (
    collect_historical_urls,
    mark_live_historical_urls,
    normalize_historical_url,
    select_historical_domains,
)
from reconbot.runtime.traffic_profile import (
    resolve_traffic_profile as resolve_runtime_traffic_profile,
)


# --- Target mode helpers (domain / ip / url) ---

# --- Endpoint classification (sensitive endpoint detection) ---


_ENDPOINT_PATTERNS = {
    "admin_like": (
        "admin",
        "dashboard",
        "panel",
        "manage",
        "wp-admin",
        "phpmyadmin",
        "pma",
        "console",
        "backend",
    ),
    "auth_like": (
        "login",
        "signin",
        "sign-in",
        "auth",
        "oauth",
        "sso",
        "register",
        "signup",
        "sign-up",
        "logout",
        "forgot",
        "lostpassword",
        "reset",
        "recover",
        "xmlrpc",
    ),
    "api_like": (
        "api",
        "graphql",
        "swagger",
        "openapi",
        "actuator",
        "rest",
        "soap",
        "wsdl",
        "webservices",
        "xmlrpc",
    ),
    "upload_like": (
        "upload",
        "file",
        "import",
        "attachment",
        "multipart",
    ),
    "debug_like": (
        "debug",
        "internal",
        "test",
        "dev",
        "phpinfo",
        "server-status",
        "frame",
        "diagnostic",
        "trace",
        "errors",
    ),
    "docs_like": (
        "docs",
        "documentation",
        "redoc",
        "swagger-ui",
        "help",
        "install",
        "readme",
        "manual",
        "tutorial",
        "usage",
        "instructions",
        "vulnerabilities",
    ),
    "source_control_like": (
        ".git",
        "/.git/",
    ),
}


_LOW_VALUE_ENDPOINT_EXTENSIONS = (
    ".js",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
)

_LOW_VALUE_ENDPOINT_PATH_HINTS = (
    "/wp-includes/js/",
    "/wp-includes/css/",
    "/wp-content/themes/",
    "/wp-content/plugins/",
    "/wp-content/uploads/",
)


def _has_high_value_surface_markers(u: str) -> bool:
    """Return True when URL contains high-value page/query markers.

    This protects query-driven labs/CMS routes like:
    - index.php?page=upload-file.php
    - wp-login.php?action=lostpassword
    - documentation/vulnerabilities.php
    """
    low = (u or "").lower().strip()
    if not low:
        return False

    markers = (
        "admin",
        "dashboard",
        "panel",
        "manage",
        "phpmyadmin",
        "wp-admin",
        "login",
        "signin",
        "auth",
        "oauth",
        "sso",
        "register",
        "signup",
        "lostpassword",
        "reset",
        "recover",
        "xmlrpc",
        "swagger",
        "openapi",
        "graphql",
        "api",
        "rest",
        "soap",
        "wsdl",
        "webservices",
        "documentation",
        "docs",
        "redoc",
        "vulnerabilities",
        "install",
        "readme",
        "help",
        "debug",
        "test",
        "dev",
        "phpinfo",
        "server-status",
        ".git",
        "/.git/",
        "upload",
        "import",
        "file",
        "page=",
        "action=",
    )
    return any(marker in low for marker in markers)


def _looks_like_static_or_resource_url(u: str) -> bool:
    """Return True for URLs that are assets/resources, not meaningful attack surfaces."""
    low = (u or "").lower().strip()
    if not low:
        return True
    if _has_high_value_surface_markers(low):
        return False

    if any(hint in low for hint in _LOW_VALUE_ENDPOINT_PATH_HINTS):
        parsed_hint = urlsplit(low)
        path_hint = parsed_hint.path or ""
        if not _has_high_value_surface_markers(low):
            return True
        if path_hint.endswith(_LOW_VALUE_ENDPOINT_EXTENSIONS):
            return True

    parsed = urlsplit(low)
    path = parsed.path or ""
    query = parsed.query or ""

    if path.endswith(_LOW_VALUE_ENDPOINT_EXTENSIONS) and not _has_high_value_surface_markers(low):
        return True

    if "ver=" in query and (
        "/wp-includes/" in path or "/wp-content/" in path
    ) and not _has_high_value_surface_markers(low):
        return True

    return False


def _normalize_surface_url(u: str, *, keep_auth_query: bool = False) -> str:
    """Normalize URLs for endpoint classification.

    Default behavior:
    - drop query/fragment for stable dedup
    - keep only scheme/netloc/path

    Important exception:
    - if the URL is routed through a generic entrypoint like `/index.php`
      and the query string carries high-value surface markers (admin/debug/docs/api/upload/auth),
      preserve that query so we do not destroy meaningful classifications.
    - auth-aware mode still preserves auth workflow query params.
    """
    raw = (u or "").strip()
    if not raw:
        return ""

    parts = urlsplit(raw)
    if not parts.scheme or not parts.netloc:
        return raw

    path = parts.path or "/"
    query = ""

    low_path = path.lower()
    low_query = (parts.query or "").lower()

    auth_query_markers = (
        "action=lostpassword",
        "action=login",
        "action=register",
        "redirect_to=",
        "reauth=",
        "reset",
        "forgot",
        "recover",
        "lostpassword",
        "register",
        "signup",
    )

    high_value_query_markers = (
        "admin",
        "dashboard",
        "panel",
        "manage",
        "phpmyadmin",
        "wp-admin",
        "login",
        "auth",
        "oauth",
        "sso",
        "register",
        "signup",
        "swagger",
        "openapi",
        "graphql",
        "api",
        "rest",
        "soap",
        "wsdl",
        "webservices",
        "documentation",
        "docs",
        "redoc",
        "help",
        "install",
        "readme",
        "debug",
        "test",
        "dev",
        "phpinfo",
        "server-status",
        "upload",
        "import",
        "file",
        "page=",
        "action=",
    )

    router_like_paths = (
        "/index.php",
        "/index",
        "/",
        "",
    )

    preserve_query = False

    if keep_auth_query and low_query and any(marker in low_query for marker in auth_query_markers):
        preserve_query = True

    if not preserve_query and low_query:
        if low_path in router_like_paths or low_path.endswith("/index.php"):
            if any(marker in low_query for marker in high_value_query_markers):
                preserve_query = True

    if preserve_query:
        query = parts.query or ""

    return urlunsplit((parts.scheme, parts.netloc, path, query, ""))


def _is_meaningful_upload_surface(u: str) -> bool:
    """Conservative upload-surface detection to reduce false positives."""
    low = (u or "").lower()
    path = urlsplit(low).path or low

    strong_upload_markers = (
        "upload",
        "async-upload.php",
        "media-new.php",
        "file-upload",
        "upload-file",
        "multipart",
        "import",
        "attachment",
        "addmedia",
    )

    if any(marker in low for marker in strong_upload_markers):
        return True

    return False


_PUBLIC_CONTENT_PATH_MARKERS = (
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


def _url_path_segments(u: str) -> list[str]:
    path = urlsplit((u or "").lower()).path or (u or "").lower()
    return [segment for segment in path.strip("/").split("/") if segment]


def _is_public_content_context_url(u: str) -> bool:
    low = (u or "").lower()
    path = urlsplit(low).path or low
    if any(marker in path for marker in _PUBLIC_CONTENT_PATH_MARKERS):
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


def _has_strong_debug_surface_evidence(u: str) -> bool:
    low = (u or "").lower()
    path = urlsplit(low).path or low
    segments = set(_url_path_segments(low))

    if segments & {
        "__debug",
        "test",
        "dev",
        "staging",
        "console",
        "trace",
        "actuator",
        "diagnostic",
        "profiler",
        "logs",
        "log",
        "errors",
        "error-log",
        "config",
        "env",
        "internal",
    }:
        return True

    strong_tokens = (
        "/debug/console",
        "/__debug",
        "/test/",
        "/dev/",
        "/staging/",
        "/console/",
        "/trace/",
        "/actuator/",
        "/diagnostic/",
        "/profiler/",
        "/config/env",
        "/.env",
        "wp-config",
        "app-config",
        "config.php",
        "config.json",
        "config.yml",
        "config.yaml",
        "phpinfo.php",
        "server-status",
        "stacktrace",
        "verbose-error",
        "debug=true",
        "test-harness",
        "internal-route",
        "error.log",
        "access.log",
        "/.git/",
        ".git/config",
        ".git/head",
        ".git/index",
        ".git/logs",
    )
    if any(token in low for token in strong_tokens):
        return True

    return path.endswith(("/phpinfo", "/server-status"))


def _dashboard_has_admin_context(u: str) -> bool:
    low = (u or "").lower()
    parsed = urlsplit(low)
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
    auth_context = (
        "/login",
        "/signin",
        "/auth",
        "login=",
        "redirect_to=",
        "reauth=",
    )
    return (
        any(marker in low for marker in strong_markers)
        or any(marker in path for marker in dashboard_admin_paths)
        or any(marker in low or marker in query for marker in auth_context)
    )


def _is_meaningful_admin_surface(u: str) -> bool:
    """Admin surface should be a real page/panel, not a loader/resource."""
    low = (u or "").lower()
    path = urlsplit(low).path or low

    if _looks_like_static_or_resource_url(low):
        return False

    if "dashboard" in low and not _dashboard_has_admin_context(low):
        return False
    if _is_public_content_context_url(low) and not _dashboard_has_admin_context(low):
        return False

    admin_markers = (
        "/admin",
        "/panel",
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
    )
    if any(marker in low for marker in admin_markers):
        return True
    return "dashboard" in low and _dashboard_has_admin_context(low)


def _is_meaningful_auth_surface(u: str) -> bool:
    """Auth surface should be a real login/auth endpoint, not asset noise.

    Important: auth workflow URLs with useful query params should survive,
    e.g. lostpassword / redirect_to / reauth flows.
    """
    raw = (u or "").strip()
    low = raw.lower()
    parsed = urlsplit(low)
    path = parsed.path or low
    query = parsed.query or ""

    if _is_public_content_context_url(low):
        return False

    if _looks_like_static_or_resource_url(low):
        # Allow real auth workflow URLs even if they contain query params,
        # but never allow obvious static assets/resources.
        if path.endswith(_LOW_VALUE_ENDPOINT_EXTENSIONS):
            return False
        if any(hint in path for hint in _LOW_VALUE_ENDPOINT_PATH_HINTS):
            return False

    auth_markers = (
        "login",
        "signin",
        "sign-in",
        "auth",
        "oauth",
        "sso",
        "lostpassword",
        "wp-login.php",
        "xmlrpc.php",
        "xmlrpc",
        "reset",
        "forgot",
        "recover",
        "register",
        "signup",
        "sign-up",
        "logout",
    )

    auth_query_markers = (
        "action=lostpassword",
        "action=login",
        "action=register",
        "redirect_to=",
        "reauth=",
        "reset",
        "forgot",
        "recover",
        "lostpassword",
        "register",
        "signup",
    )

    return any(marker in path for marker in auth_markers) or any(
        marker in query for marker in auth_query_markers
    )


def _is_meaningful_api_surface(u: str) -> bool:
    low = (u or "").lower()
    path = urlsplit(low).path or low
    if _looks_like_static_or_resource_url(low):
        return False
    return any(marker in low for marker in ("/api", "graphql", "swagger", "openapi", "actuator", "/rest", "soap", "wsdl", "webservices", "xmlrpc"))


def _is_meaningful_docs_surface(u: str) -> bool:
    low = (u or "").lower()
    path = urlsplit(low).path or low
    if _looks_like_static_or_resource_url(low):
        return False
    return any(marker in low for marker in ("docs", "documentation", "redoc", "swagger-ui", "help", "install", "readme", "manual", "tutorial", "usage", "instructions", "vulnerabilities"))


def _is_meaningful_debug_surface(u: str) -> bool:
    low = (u or "").lower()
    if _looks_like_static_or_resource_url(low):
        return False
    if _is_meaningful_source_control_surface(low):
        return False
    if _is_public_content_context_url(low) and not _has_strong_debug_surface_evidence(low):
        return False
    return _has_strong_debug_surface_evidence(low)


def _is_meaningful_source_control_surface(u: str) -> bool:
    low = (u or "").lower()
    path = urlsplit(low).path or low
    return path == "/.git" or path.startswith("/.git/") or "/.git/" in path


def _is_strong_backup_exposure_url(u: str) -> bool:
    low = (u or "").lower()
    path = urlsplit(low).path or low
    if path.rstrip("/") in {"/backup", "/backups"}:
        return False
    return any(
        token in low
        for token in (
            "db-dump",
            "database-dump",
            "dump.sql",
            ".sql",
            ".bak",
            ".backup",
            "app-config.bak",
            "wp-config",
            "config.php",
            "config.json",
            "config.yml",
            "config.yaml",
        )
    )


def _structural_exposure_groups(classified_endpoints: dict[str, list[str]] | None) -> dict[str, list[str]]:
    classified_endpoints = classified_endpoints or {}
    urls: list[str] = []
    for bucket_urls in classified_endpoints.values():
        if isinstance(bucket_urls, list):
            urls.extend(str(url or "") for url in bucket_urls if str(url or "").strip())

    groups: dict[str, list[str]] = {
        "config": [],
        "backup": [],
        "logs": [],
        "debug_console": [],
        "runtime": [],
        "internal_api": [],
        "admin_export": [],
        "source_control": [],
    }
    for url in sorted(set(urls)):
        low = url.lower()
        path = urlsplit(low).path or low
        if _is_public_content_context_url(low) and not _has_strong_debug_surface_evidence(low):
            continue
        if _is_meaningful_source_control_surface(low):
            groups["source_control"].append(url)
        if any(token in low for token in ("/config/env", ".env", "wp-config", "app-config", "config.php", "config.json", "config.yml", "config.yaml")):
            groups["config"].append(url)
        if _is_strong_backup_exposure_url(url):
            groups["backup"].append(url)
        if any(token in low for token in ("error.log", "error-log", "php-errors", "access.log", "/logs", "/log/", "verbose-error")):
            groups["logs"].append(url)
        if any(token in low for token in ("/debug/console", "/__debug", "/trace", "/diagnostic", "/profiler", "stacktrace", "verbose-error", "debug=true", "internal-route")):
            groups["debug_console"].append(url)
        if any(token in low for token in ("phpinfo", "server-status", "/actuator/env", "/actuator/heapdump", "/actuator/configprops")):
            groups["runtime"].append(url)
        if ("/internal" in path and any(token in low for token in ("/api", "users", "status", "debug", "build", "version"))) or any(token in low for token in ("/api/internal", "/internal/users", "/internal/status")):
            groups["internal_api"].append(url)
        if "admin" in low and any(token in low for token in ("export", "reports", "download", "csv", "dump")):
            groups["admin_export"].append(url)

    return {key: sorted(set(values)) for key, values in groups.items() if values}


def _has_upload_execution_evidence(upload_like: list[str], tech_signals: set[str]) -> bool:
    for url in upload_like or []:
        low = str(url or "").lower()
        path = urlsplit(low).path or low
        if path.endswith((".php", ".phtml", ".phar", ".asp", ".aspx", ".jsp", ".cgi", ".pl", ".sh")):
            return True
        if any(token in low for token in ("webshell", "shell.php", "execute", "handler", "parser", "deserial", "unrestricted-upload")):
            return True
    return False


def _is_strong_api_or_docs_signal(api_like: list[str], docs_like: list[str], tech_signals: set[str]) -> bool:
    combined = " ".join((api_like or []) + (docs_like or [])).lower()
    strong_tokens = (
        "swagger",
        "openapi",
        "redoc",
        "graphql",
        "/api/internal",
        "/internal/api",
        "debug",
        "config",
        "secret",
        "token",
        "private",
        "credential",
        "bypass",
        "admin",
    )
    return "openapi" in tech_signals or "graphql" in tech_signals or any(token in combined for token in strong_tokens)


def _ordinary_public_docs_only(api_like: list[str], docs_like: list[str], tech_signals: set[str]) -> bool:
    return bool(docs_like) and not api_like and not _is_strong_api_or_docs_signal(api_like, docs_like, tech_signals)


def _classify_endpoints(urls: list[str]) -> dict[str, list[str]]:
    """Classify URLs into sensitive endpoint categories.

    Conservative mode:
    - drop asset/resource URLs
    - normalize query-heavy URLs
    - require stronger signals for upload/admin/auth/api/docs/debug classes
    """
    result: dict[str, list[str]] = {k: [] for k in _ENDPOINT_PATTERNS}

    for u in urls or []:
        auth_normalized = _normalize_surface_url(u, keep_auth_query=True)
        normalized = _normalize_surface_url(u)
        candidate = auth_normalized or normalized
        if not candidate:
            continue

        low = candidate.lower()

        is_auth_candidate = _is_meaningful_auth_surface(candidate)
        if _looks_like_static_or_resource_url(low) and not is_auth_candidate:
            continue

        if _is_meaningful_admin_surface(candidate):
            result["admin_like"].append(candidate)

        if _is_meaningful_auth_surface(candidate):
            result["auth_like"].append(auth_normalized)

        if _is_meaningful_api_surface(candidate):
            result["api_like"].append(candidate)

        if _is_meaningful_upload_surface(candidate):
            result["upload_like"].append(candidate)

        if _is_meaningful_debug_surface(candidate):
            result["debug_like"].append(candidate)

        if _is_meaningful_docs_surface(candidate):
            result["docs_like"].append(candidate)

        if _is_meaningful_source_control_surface(candidate):
            result["source_control_like"].append(candidate)

    for k, v in result.items():
        result[k] = sorted(set(v))

    return result


_FORBIDDEN_ONLY_STRUCTURAL_STATUSES = {401, 403}


def _endpoint_status_code(item: dict[str, Any]) -> int | None:
    """Extract a scanner status code without assuming a single tool schema."""
    for key in ("status", "status_code", "code"):
        raw = item.get(key)
        if raw is None:
            continue
        try:
            return int(raw)
        except (TypeError, ValueError):
            continue
    return None


def _status_identity(url: str) -> tuple[str, str]:
    parsed = urlsplit(str(url or "").strip().lower())
    path = parsed.path or "/"
    return (parsed.netloc, path.rstrip("/") or "/")


def _is_forbidden_only_structural_surface(url: str) -> bool:
    low = str(url or "").lower()
    path = urlsplit(low).path or low
    if _is_public_content_context_url(low) and not _has_strong_debug_surface_evidence(low):
        return False
    if _is_meaningful_source_control_surface(low):
        return True
    structural_markers = (
        "phpinfo",
        "server-status",
        "/debug",
        "/test",
        "/dev",
        "/staging",
        "/console",
        "/trace",
        "/actuator",
        "/env",
        "/config",
        "config.",
        ".env",
        "/backup",
        "db-dump",
        "dump.sql",
        ".sql",
        ".bak",
        ".backup",
        "/logs",
        "/log/",
        "error.log",
        "access.log",
    )
    return any(marker in low or marker in path for marker in structural_markers)


def _classify_endpoints_with_status(
    urls: list[str],
    *,
    readable_urls: list[str] | None = None,
    forbidden_urls: list[str] | None = None,
) -> tuple[dict[str, list[str]], list[str]]:
    """Classify endpoints while downgrading forbidden-only structural probes.

    A 403/401 on paths such as /server-status or /.git is still useful
    enumeration evidence, but it should not be persisted as a readable structural
    exposure unless a matching 2xx URL was also observed.
    """
    classified = _classify_endpoints(urls)
    readable_keys = {_status_identity(url) for url in readable_urls or [] if str(url or "").strip()}
    forbidden_keys = {_status_identity(url) for url in forbidden_urls or [] if str(url or "").strip()}
    structural_like = [
        url
        for url in readable_urls or []
        if _is_strong_backup_exposure_url(url)
    ]
    if structural_like:
        classified["structural_like"] = sorted(
            set((classified.get("structural_like") or []) + structural_like)
        )
    if not forbidden_keys:
        return classified, []

    blocked: list[str] = []
    for bucket in ("debug_like", "source_control_like"):
        kept: list[str] = []
        for url in classified.get(bucket, []) or []:
            key = _status_identity(url)
            if (
                key in forbidden_keys
                and key not in readable_keys
                and _is_forbidden_only_structural_surface(url)
            ):
                blocked.append(url)
                continue
            kept.append(url)
        classified[bucket] = kept

    return classified, sorted(set(blocked))


def _collect_scanner_urls_by_status(
    gobuster_results: dict[str, list[dict[str, Any]]] | None,
    ffuf_results: dict[str, list[dict[str, Any]]] | None,
) -> tuple[list[str], list[str]]:
    readable_urls: list[str] = []
    forbidden_urls: list[str] = []
    for result_map in (gobuster_results or {}, ffuf_results or {}):
        if not isinstance(result_map, dict):
            continue
        for results in result_map.values():
            if not isinstance(results, list):
                continue
            for item in results:
                if not isinstance(item, dict):
                    continue
                url = str(item.get("url") or "").strip()
                if not url:
                    continue
                status_code = _endpoint_status_code(item)
                if status_code is None:
                    continue
                if 200 <= status_code < 300:
                    readable_urls.append(url)
                elif status_code in _FORBIDDEN_ONLY_STRUCTURAL_STATUSES:
                    forbidden_urls.append(url)
    return sorted(set(readable_urls)), sorted(set(forbidden_urls))


_SOFT_ERROR_STATUS_CODES = {200, 301, 302, 303, 307, 308, 400, 401, 403, 404}
_SOFT_ERROR_CLUSTER_MIN = 20
_SOFT_ERROR_LENGTH_TOLERANCE = 32
_SOFT_ERROR_WORD_TOLERANCE = 2
_SOFT_ERROR_LINE_TOLERANCE = 1
_SOFT_ERROR_BODY_READ_LIMIT = 65536
_JSON_SAFE_TEXT_LIMIT = 2048

_GENERIC_ERROR_MARKERS = (
    "/error/400",
    "/error/404",
    "/errors/400",
    "/errors/404",
    "aspxerrorpath",
    "server error",
    "file not found",
    "not found",
    "bad request",
    "page not found",
    "the resource cannot be found",
)

_BODY_EVIDENCE_MARKERS = (
    "password",
    "username",
    "csrf",
    "token",
    "swagger",
    "openapi",
    "graphql",
    "directory listing",
    "index of /",
    "<form",
    "type=\"password\"",
    "name=\"password\"",
    "[core]",
    "[remote",
    "ref: refs/heads/",
)

_AUTH_BODY_MARKERS = (
    "type=\"password\"",
    "name=\"password\"",
    "login",
    "sign in",
    "signin",
    "forgot password",
    "account",
    "csrf",
    "__requestverificationtoken",
    "<form",
    "form action",
)

_ADMIN_BODY_MARKERS = (
    "admin",
    "administrator",
    "dashboard",
    "control panel",
    "management",
    "login",
    "restricted",
)

_API_BODY_MARKERS = (
    "openapi",
    "swagger",
    "graphql",
    "\"error\"",
    "\"message\"",
    "\"status\"",
    "api",
)


def _word_count(text: str) -> int:
    return len(re.findall(r"\S+", text or ""))


def _line_count(text: str) -> int:
    if not text:
        return 0
    return len((text or "").splitlines()) or 1


def _extract_html_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:160]


def _normalized_body_hash(body: bytes) -> str:
    if not body:
        return ""
    try:
        text = body.decode("utf-8", errors="ignore")
    except Exception:
        text = ""
    if text:
        normalized = re.sub(r"\s+", " ", text).strip().lower()
        normalized = re.sub(r"[0-9a-f]{8,}", "<hex>", normalized)
        normalized = re.sub(r"\d{4,}", "<num>", normalized)
        data = normalized.encode("utf-8", errors="ignore")
    else:
        data = body
    return hashlib.sha256(data[:_SOFT_ERROR_BODY_READ_LIMIT]).hexdigest()[:16]


def _bytes_json_metadata(value: bytes) -> dict[str, Any]:
    data = bytes(value or b"")
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    replacement_count = text.count("\ufffd")
    printable_count = sum(1 for char in text if char.isprintable() or char.isspace())
    looks_text = bool(text) and printable_count >= max(1, int(len(text) * 0.85)) and replacement_count <= max(2, len(text) // 20)
    metadata: dict[str, Any] = {
        "bytes_length": len(data),
        "sha256": hashlib.sha256(data).hexdigest() if data else "",
    }
    if looks_text:
        metadata["text_snippet"] = text[:_JSON_SAFE_TEXT_LIMIT]
        if len(text) > _JSON_SAFE_TEXT_LIMIT:
            metadata["truncated"] = True
    return metadata


def _json_safe_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return _bytes_json_metadata(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return [_json_safe_value(item) for item in value]
    if isinstance(value, set):
        return [_json_safe_value(item) for item in sorted(value, key=lambda item: str(item))]
    if isinstance(value, list):
        return [_json_safe_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe_value(item) for key, item in value.items()}
    return value


def _public_probe_record(probe: dict[str, Any], *, include_body_snippet: bool = False) -> dict[str, Any]:
    public = {
        str(key): value
        for key, value in (probe or {}).items()
        if not str(key).startswith("_")
    }
    if include_body_snippet and probe.get("_body_preview"):
        public["body_snippet"] = str(probe.get("_body_preview") or "")[:_JSON_SAFE_TEXT_LIMIT]
    return _json_safe_value(public)


def _error_route_markers(*values: object) -> list[str]:
    haystack = " ".join(str(value or "") for value in values).lower()
    markers = [marker for marker in _GENERIC_ERROR_MARKERS if marker in haystack]
    return sorted(set(markers))


def _response_probe_record(
    *,
    url: str,
    status_code: int,
    final_url: str,
    body: bytes,
    redirect_location: str = "",
    content_type: str = "",
    redirect_chain: list[str] | None = None,
) -> dict[str, Any]:
    try:
        text = body.decode("utf-8", errors="ignore")
    except Exception:
        text = ""
    return {
        "url": url,
        "status_code": int(status_code or 0),
        "final_url": final_url or url,
        "redirect_location": redirect_location,
        "content_type": content_type,
        "content_length": len(body or b""),
        "words": _word_count(text),
        "lines": _line_count(text),
        "title": _extract_html_title(text),
        "body_hash": _normalized_body_hash(body or b""),
        "redirect_chain": list(redirect_chain or []),
        "error_markers": _error_route_markers(url, final_url, redirect_location, text[:4096]),
        "_body_preview": text[:8192],
        "_body_bytes_prefix": bytes(body[:8] if body else b""),
    }


def _probe_soft_error_response(
    url: str,
    *,
    timeout: int = 8,
    follow_redirects: bool = True,
    redirect_limit: int = 4,
) -> dict[str, Any]:
    """Best-effort response fingerprint used only for evidence gating."""
    target_url = str(url or "").strip()
    if not target_url:
        return {}

    req = Request(
        target_url,
        headers={
            "User-Agent": "reconbot-soft-error-probe/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        method="GET",
    )
    redirect_chain: list[str] = []

    class _ControlledRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
            if not follow_redirects:
                return None
            if len(redirect_chain) >= max(0, int(redirect_limit)):
                return None
            redirect_chain.append(str(newurl or ""))
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    try:
        if follow_redirects:
            opener = build_opener(_ControlledRedirect)
            resp_ctx = opener.open(req, timeout=max(1, int(timeout)))
        else:
            opener = build_opener(_ControlledRedirect)
            resp_ctx = opener.open(req, timeout=max(1, int(timeout)))
        with resp_ctx as resp:
            body = resp.read(_SOFT_ERROR_BODY_READ_LIMIT) or b""
            try:
                final_url = str(resp.geturl() or target_url)
            except Exception:
                final_url = str(getattr(resp, "url", "") or target_url)
            return _response_probe_record(
                url=target_url,
                status_code=int(getattr(resp, "status", 0) or 0),
                final_url=final_url,
                body=body,
                redirect_location=str(resp.headers.get("Location", "") if getattr(resp, "headers", None) else ""),
                content_type=str(resp.headers.get("Content-Type", "") if getattr(resp, "headers", None) else ""),
                redirect_chain=redirect_chain,
            )
    except HTTPError as exc:
        try:
            body = exc.read(_SOFT_ERROR_BODY_READ_LIMIT) or b""
        except Exception:
            body = b""
        return _response_probe_record(
            url=target_url,
            status_code=int(getattr(exc, "code", 0) or 0),
            final_url=str(getattr(exc, "url", "") or target_url),
            body=body,
            redirect_location=str(exc.headers.get("Location", "") if getattr(exc, "headers", None) else ""),
            content_type=str(exc.headers.get("Content-Type", "") if getattr(exc, "headers", None) else ""),
            redirect_chain=redirect_chain,
        )
    except Exception as exc:
        return {"url": target_url, "error": str(exc)}


def _build_soft_error_baseline(base_url: str, *, timeout: int = 8) -> dict[str, Any]:
    base = str(base_url or "").strip()
    if not base:
        return {}
    samples: list[dict[str, Any]] = []
    token = uuid.uuid4().hex[:12]
    probe_paths = (
        f"/reconbot-nonexistent-{token}",
        f"/this-path-should-not-exist-{token}",
    )
    for path in probe_paths:
        probe_url = urlunsplit((
            urlsplit(base).scheme or "http",
            urlsplit(base).netloc,
            path,
            "",
            "",
        ))
        initial = _probe_soft_error_response(probe_url, timeout=timeout, follow_redirects=False)
        final = _probe_soft_error_response(probe_url, timeout=timeout, follow_redirects=True)
        if initial and int(initial.get("status_code") or 0) > 0:
            sample = dict(initial)
            sample["initial"] = _public_probe_record(initial)
            sample["final"] = _public_probe_record(final) if final else {}
            if final and final.get("final_url"):
                sample["final_url"] = final.get("final_url")
            sample["error_markers"] = sorted(
                set((initial.get("error_markers") or []) + (final.get("error_markers") or []))
            )
            samples.append(sample)
    if not samples:
        return {}

    def _mode(values: list[Any]) -> Any:
        counts: dict[Any, int] = {}
        for value in values:
            counts[value] = counts.get(value, 0) + 1
        return max(counts.items(), key=lambda item: item[1])[0] if counts else None

    status_code = _mode([sample.get("status_code") for sample in samples if sample.get("status_code")])
    lengths = sorted(int(sample.get("content_length") or 0) for sample in samples)
    words = sorted(int(sample.get("words") or 0) for sample in samples)
    lines = sorted(int(sample.get("lines") or 0) for sample in samples)
    return {
        "base_url": base,
        "status_code": int(status_code or 0),
        "final_url": str(_mode([sample.get("final_url") for sample in samples if sample.get("final_url")]) or ""),
        "content_length": lengths[len(lengths) // 2] if lengths else 0,
        "words": words[len(words) // 2] if words else 0,
        "lines": lines[len(lines) // 2] if lines else 0,
        "title": str(_mode([sample.get("title") for sample in samples if sample.get("title")]) or ""),
        "body_hash": str(_mode([sample.get("body_hash") for sample in samples if sample.get("body_hash")]) or ""),
        "error_markers": sorted({marker for sample in samples for marker in (sample.get("error_markers") or [])}),
        "samples": [
            _public_probe_record(sample)
            for sample in samples
        ],
    }


def _hit_content_length(hit: dict[str, Any]) -> int | None:
    for key in ("content_length", "length", "size"):
        raw = hit.get(key)
        if raw is None:
            continue
        try:
            return int(raw)
        except Exception:
            continue
    return None


def _hit_shape(hit: dict[str, Any]) -> tuple[int, int | None, int | None, int | None]:
    return (
        int(_endpoint_status_code(hit) or 0),
        _hit_content_length(hit),
        int(hit.get("words")) if hit.get("words") is not None else None,
        int(hit.get("lines")) if hit.get("lines") is not None else None,
    )


def _shape_matches_baseline(hit: dict[str, Any], baseline: dict[str, Any]) -> bool:
    if not baseline:
        return False
    if not any(
        baseline.get(key)
        for key in ("status_code", "content_length", "words", "lines", "body_hash", "final_url")
    ):
        return False
    status, length, words, lines = _hit_shape(hit)
    if status and baseline.get("status_code") and status != int(baseline.get("status_code") or 0):
        return False
    matched_shape_field = False
    base_length = int(baseline.get("content_length") or 0)
    if length is not None and base_length:
        matched_shape_field = True
        if abs(int(length) - base_length) > _SOFT_ERROR_LENGTH_TOLERANCE:
            return False
    base_words = int(baseline.get("words") or 0)
    if words is not None and base_words:
        matched_shape_field = True
        if abs(int(words) - base_words) > _SOFT_ERROR_WORD_TOLERANCE:
            return False
    base_lines = int(baseline.get("lines") or 0)
    if lines is not None and base_lines:
        matched_shape_field = True
        if abs(int(lines) - base_lines) > _SOFT_ERROR_LINE_TOLERANCE:
            return False
    return matched_shape_field


def _generic_error_redirect(hit: dict[str, Any], baseline: dict[str, Any] | None = None) -> bool:
    url = str(hit.get("url") or "")
    location = str(hit.get("redirect_location") or hit.get("location") or hit.get("final_url") or "")
    baseline_final = str((baseline or {}).get("final_url") or "")
    if int(_endpoint_status_code(hit) or 0) not in {301, 302, 303, 307, 308}:
        return False
    if _error_route_markers(url, location):
        return True
    if location and baseline_final:
        try:
            loc_path = (urlsplit(location).path or location).lower()
            base_path = (urlsplit(baseline_final).path or baseline_final).lower()
        except Exception:
            loc_path = location.lower()
            base_path = baseline_final.lower()
        return bool(loc_path and base_path and loc_path.rstrip("/") == base_path.rstrip("/"))
    return False


def _high_risk_keyword_url(url: str) -> bool:
    low = str(url or "").lower()
    return any(
        token in low
        for token in (
            "/.git",
            ".env",
            "config",
            "backup",
            "dump",
            ".sql",
            ".bak",
            "admin",
            "login",
            "auth",
            "swagger",
            "openapi",
            "phpinfo",
            "server-status",
        )
    )


def _has_git_body_evidence(url: str, probe: dict[str, Any]) -> bool:
    low = str(url or "").lower()
    body = str(probe.get("_body_preview") or "").lower()
    prefix = probe.get("_body_bytes_prefix") or b""
    if low.endswith("/.git/head") or low.endswith("/.git/head/"):
        return "ref: refs/heads/" in body
    if low.endswith("/.git/config") or low.endswith("/.git/config/"):
        return "[core]" in body or "[remote" in body
    if low.endswith("/.git/index") or low.endswith("/.git/index/"):
        return bool(prefix == b"DIRC" or "dirc" in body[:16] or "refs/heads/" in body)
    return "[core]" in body or "[remote" in body or "ref: refs/heads/" in body or prefix == b"DIRC"


def _has_meaningful_body_evidence(probe: dict[str, Any]) -> bool:
    body = str(probe.get("_body_preview") or "").lower()
    title = str(probe.get("title") or "").lower()
    if probe.get("error_markers"):
        return False
    return any(marker in body or marker in title for marker in _BODY_EVIDENCE_MARKERS)


def _soft_error_shape_clusters(results: list[dict[str, Any]]) -> set[tuple[int, int | None, int | None, int | None]]:
    counts: dict[tuple[int, int | None, int | None, int | None], list[str]] = {}
    for hit in results:
        if not isinstance(hit, dict):
            continue
        shape = _hit_shape(hit)
        status = shape[0]
        if status not in _SOFT_ERROR_STATUS_CODES:
            continue
        counts.setdefault(shape, []).append(str(hit.get("url") or ""))

    noisy_shapes: set[tuple[int, int | None, int | None, int | None]] = set()
    for shape, urls in counts.items():
        if len(urls) < _SOFT_ERROR_CLUSTER_MIN:
            continue
        first_segments = {
            (urlsplit(url).path or "/").strip("/").split("/", 1)[0].lower()
            for url in urls
            if str(url or "").strip()
        }
        first_segments.discard("")
        if len(first_segments) >= 5 or len(urls) >= 50:
            noisy_shapes.add(shape)
    return noisy_shapes


def _filter_soft_error_discovery(
    *,
    web_urls: list[str],
    gobuster_results: dict[str, list[dict[str, Any]]],
    ffuf_results: dict[str, list[dict[str, Any]]],
    timeout: int,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Suppress generic redirect/error discovery before downstream scoring."""
    metadata: dict[str, Any] = {
        "baselines": {},
        "suppressed": [],
        "suppressed_count": 0,
        "suppressed_by_reason": {},
        "validated_evidence": [],
    }

    candidate_bases = sorted(
        set(str(base or "").strip() for base in list(gobuster_results.keys()) + list(ffuf_results.keys()) if str(base or "").strip())
    )
    if not candidate_bases:
        return gobuster_results, ffuf_results, metadata

    baselines: dict[str, dict[str, Any]] = {}
    for base in candidate_bases:
        hits = list(gobuster_results.get(base) or []) + list(ffuf_results.get(base) or [])
        if not hits:
            continue
        has_shape_signal = any(_hit_content_length(hit) is not None for hit in hits if isinstance(hit, dict))
        has_redirect_or_sensitive = any(
            isinstance(hit, dict)
            and (
                int(_endpoint_status_code(hit) or 0) in {301, 302, 303, 307, 308}
                or _high_risk_keyword_url(str(hit.get("url") or ""))
            )
            for hit in hits
        )
        if not (has_shape_signal or has_redirect_or_sensitive):
            continue
        baseline = _build_soft_error_baseline(base, timeout=timeout)
        if baseline:
            baselines[base] = baseline
    metadata["baselines"] = baselines

    def _bump(reason: str) -> None:
        by_reason = metadata["suppressed_by_reason"]
        by_reason[reason] = int(by_reason.get(reason, 0) or 0) + 1

    def _record_suppressed(base: str, source: str, hit: dict[str, Any], reason: str) -> None:
        metadata["suppressed"].append(
            {
                "base_url": base,
                "source": source,
                "url": str(hit.get("url") or ""),
                "status": int(_endpoint_status_code(hit) or 0),
                "content_length": _hit_content_length(hit),
                "words": hit.get("words"),
                "lines": hit.get("lines"),
                "reason": reason,
            }
        )
        metadata["suppressed_count"] = int(metadata.get("suppressed_count", 0) or 0) + 1
        _bump(reason)

    probe_cache: dict[str, dict[str, Any]] = {}

    def _candidate_probe(url: str) -> dict[str, Any]:
        if url not in probe_cache:
            probe_cache[url] = _probe_soft_error_response(url, timeout=timeout, follow_redirects=True)
        return probe_cache[url]

    def _filter_map(source: str, result_map: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
        filtered_map: dict[str, list[dict[str, Any]]] = {}
        for base, hits in (result_map or {}).items():
            if not isinstance(hits, list):
                continue
            baseline = baselines.get(base, {})
            noisy_shapes = _soft_error_shape_clusters([hit for hit in hits if isinstance(hit, dict)])
            kept: list[dict[str, Any]] = []
            for hit in hits:
                if not isinstance(hit, dict):
                    continue
                url = str(hit.get("url") or "").strip()
                if not url:
                    continue
                reason = ""
                if baseline and _generic_error_redirect(hit, baseline):
                    reason = "generic_error_redirect"
                elif baseline and _shape_matches_baseline(hit, baseline):
                    reason = "baseline_shape_match"
                elif _hit_shape(hit) in noisy_shapes:
                    reason = "shared_soft_error_cluster"

                if not reason and _is_meaningful_source_control_surface(url):
                    probe = _candidate_probe(url)
                    if _has_git_body_evidence(url, probe):
                        enriched = dict(hit)
                        enriched["evidence_status"] = "confirmed_body"
                        enriched["evidence_markers"] = ["git_body"]
                        enriched["final_url"] = probe.get("final_url", "")
                        enriched["title"] = probe.get("title", "")
                        enriched["body_hash"] = probe.get("body_hash", "")
                        metadata["validated_evidence"].append(
                            {
                                "url": url,
                                "source": source,
                                "evidence": "git_body",
                                "body_hash": probe.get("body_hash", ""),
                            }
                        )
                        kept.append(enriched)
                        continue
                    reason = "unconfirmed_source_control"

                if not reason and _high_risk_keyword_url(url) and int(_endpoint_status_code(hit) or 0) in {301, 302, 303, 307, 308}:
                    probe = _candidate_probe(url)
                    final_url = str(probe.get("final_url") or "")
                    if _error_route_markers(final_url, probe.get("title"), probe.get("_body_preview")):
                        reason = "generic_error_redirect"

                if reason:
                    _record_suppressed(base, source, hit, reason)
                    continue

                if _high_risk_keyword_url(url) and int(_endpoint_status_code(hit) or 0) == 200 and source == "ffuf":
                    probe = _candidate_probe(url)
                    if _has_meaningful_body_evidence(probe):
                        enriched = dict(hit)
                        enriched["evidence_status"] = "confirmed_body"
                        enriched["final_url"] = probe.get("final_url", "")
                        enriched["title"] = probe.get("title", "")
                        enriched["body_hash"] = probe.get("body_hash", "")
                        kept.append(enriched)
                        continue
                kept.append(hit)
            if kept:
                filtered_map[base] = kept
        return filtered_map

    return (
        _json_safe_value(_filter_map("gobuster", gobuster_results)),
        _json_safe_value(_filter_map("ffuf", ffuf_results)),
        _json_safe_value(metadata),
    )


def _origin_url(value: str) -> str:
    try:
        parts = urlsplit(str(value or "").strip())
    except Exception:
        return ""
    if not parts.scheme or not parts.netloc:
        return ""
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), "", "", ""))


def _probe_to_shape_hit(probe: dict[str, Any]) -> dict[str, Any]:
    return {
        "url": probe.get("url") or "",
        "status": probe.get("status_code"),
        "content_length": probe.get("content_length"),
        "words": probe.get("words"),
        "lines": probe.get("lines"),
    }


def _probe_is_baseline_or_error(probe: dict[str, Any], baseline: dict[str, Any] | None) -> tuple[bool, str]:
    if not isinstance(probe, dict) or int(probe.get("status_code") or 0) <= 0:
        return True, "unconfirmed"

    final_url = str(probe.get("final_url") or "")
    title = str(probe.get("title") or "")
    body = str(probe.get("_body_preview") or "")
    chain = " ".join(str(item or "") for item in (probe.get("redirect_chain") or []))
    if _error_route_markers(final_url, title, body[:4096], chain):
        return True, "suppressed_generic_redirect"

    status = int(probe.get("status_code") or 0)
    if status in {400, 404, 410} and (_error_route_markers(title, body[:4096]) or (baseline and _shape_matches_baseline(_probe_to_shape_hit(probe), baseline))):
        return True, "suppressed_soft_error"

    if baseline and _shape_matches_baseline(_probe_to_shape_hit(probe), baseline):
        return True, "suppressed_baseline_match"

    return False, ""


def _body_contains_any(probe: dict[str, Any], markers: tuple[str, ...]) -> bool:
    haystack = " ".join(
        [
            str(probe.get("title") or ""),
            str(probe.get("_body_preview") or ""),
            str(probe.get("content_type") or ""),
        ]
    ).lower()
    return any(marker in haystack for marker in markers)


def _json_body_parses(probe: dict[str, Any]) -> bool:
    body = str(probe.get("_body_preview") or "").strip()
    if not body:
        return False
    try:
        json.loads(body)
        return True
    except Exception:
        return False


def _is_well_known_url(url: str) -> bool:
    path = (urlsplit(str(url or "").lower()).path or "").lower()
    return path.startswith("/.well-known/")


def _candidate_categories(url: str) -> list[str]:
    categories: list[str] = []
    low = str(url or "").lower()
    if _is_meaningful_source_control_surface(low):
        categories.append("source_control")
    if _is_well_known_url(low):
        categories.append("well_known")
    if _is_meaningful_auth_surface(low):
        categories.append("auth")
    if _is_meaningful_admin_surface(low):
        categories.append("admin")
    if _is_meaningful_api_surface(low):
        categories.append("api")
    if _is_meaningful_upload_surface(low):
        categories.append("upload")
    if _is_meaningful_debug_surface(low):
        categories.append("debug")
    if _is_meaningful_docs_surface(low):
        categories.append("docs")
    return categories


def _category_confirmed(url: str, probe: dict[str, Any], categories: list[str]) -> tuple[bool, list[str]]:
    status = int(probe.get("status_code") or 0)
    content_type = str(probe.get("content_type") or "").lower()
    body = str(probe.get("_body_preview") or "")
    body_nonempty = bool(body.strip())
    reasons: list[str] = []

    if "source_control" in categories:
        if _has_git_body_evidence(url, probe):
            reasons.append("source_control_body")
            return True, reasons
        return False, reasons

    if "well_known" in categories:
        if status == 200 and body_nonempty and any(token in content_type for token in ("json", "text", "application/pkcs7-mime", "application/octet-stream")):
            reasons.append("well_known_expected_body")
            return True, reasons
        return False, reasons

    if "api" in categories:
        if "json" in content_type or _json_body_parses(probe):
            reasons.append("api_json")
            return True, reasons
        if status in {401, 403} and (_body_contains_any(probe, _API_BODY_MARKERS) or "json" in content_type):
            reasons.append("api_auth_response")
            return True, reasons
        if status in {200, 400, 422} and _body_contains_any(probe, _API_BODY_MARKERS):
            reasons.append("api_specific_body")
            return True, reasons
        return False, reasons

    if "auth" in categories:
        if status in {200, 401, 403}:
            reasons.append("auth_meaningful_status")
            return True, reasons
        if _body_contains_any(probe, _AUTH_BODY_MARKERS):
            reasons.append("auth_body_marker")
            return True, reasons
        return False, reasons

    if "admin" in categories:
        if status in {200, 401, 403}:
            reasons.append("admin_meaningful_status")
            return True, reasons
        if _body_contains_any(probe, _ADMIN_BODY_MARKERS):
            reasons.append("admin_body_marker")
            return True, reasons
        return False, reasons

    if "debug" in categories or "upload" in categories or "docs" in categories:
        if status in {200, 401, 403} and (_has_meaningful_body_evidence(probe) or status in {401, 403}):
            reasons.append("meaningful_status_or_body")
            return True, reasons

    return False, reasons


def _validation_shape_key(record: dict[str, Any]) -> tuple[int, int, int, int, str]:
    probe = record.get("validation") if isinstance(record.get("validation"), dict) else {}
    return (
        int(probe.get("status_code") or 0),
        int(probe.get("content_length") or 0),
        int(probe.get("words") or 0),
        int(probe.get("lines") or 0),
        str(probe.get("title") or "").strip().lower()[:80],
    )


def _active_validate_endpoint_candidates(
    *,
    candidate_records: list[dict[str, str]],
    base_urls: list[str],
    existing_baselines: dict[str, Any] | None,
    timeout: int,
) -> dict[str, Any]:
    """Actively validate discovered endpoint candidates before classification/scoring."""
    base_origin_set = {_origin_url(url) for url in base_urls or [] if _origin_url(url)}
    baselines: dict[str, Any] = dict(existing_baselines or {})
    validation_records: list[dict[str, Any]] = []
    by_url: dict[str, dict[str, Any]] = {}

    def _baseline_for(url: str) -> dict[str, Any]:
        origin = _origin_url(url)
        if not origin:
            return {}
        if origin not in baselines:
            baselines[origin] = _build_soft_error_baseline(origin, timeout=timeout)
        return baselines.get(origin, {}) if isinstance(baselines.get(origin), dict) else {}

    deduped_candidates: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    for item in candidate_records or []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        origin = _origin_url(url)
        if origin and url.rstrip("/") == origin.rstrip("/"):
            continue
        deduped_candidates.append(dict(item))

    for item in deduped_candidates:
        url = str(item.get("url") or "").strip()
        categories = _candidate_categories(url)
        if not categories:
            continue
        baseline = _baseline_for(url)
        probe = _probe_soft_error_response(url, timeout=timeout, follow_redirects=True, redirect_limit=4)
        is_error, error_status = _probe_is_baseline_or_error(probe, baseline)
        confirmed = False
        reasons: list[str] = []
        classification_status = error_status
        if not is_error:
            confirmed, reasons = _category_confirmed(url, probe, categories)
            classification_status = "confirmed" if confirmed else "suppressed_keyword_only"

        record: dict[str, Any] = {
            "url": url,
            "source": str(item.get("source") or ""),
            "detail": str(item.get("detail") or ""),
            "categories": categories,
            "classification_status": classification_status,
            "confirmation_reasons": reasons,
            "validation": _public_probe_record(probe),
        }
        validation_records.append(record)
        by_url[url] = record

    shape_map: dict[tuple[int, int, int, int, str], list[dict[str, Any]]] = {}
    for record in validation_records:
        if str(record.get("classification_status")) == "confirmed":
            continue
        key = _validation_shape_key(record)
        if key[0] in _SOFT_ERROR_STATUS_CODES:
            shape_map.setdefault(key, []).append(record)

    for records in shape_map.values():
        if len(records) < _SOFT_ERROR_CLUSTER_MIN:
            continue
        first_segments = {
            (urlsplit(str(record.get("url") or "")).path or "/").strip("/").split("/", 1)[0].lower()
            for record in records
        }
        first_segments.discard("")
        if len(first_segments) < 5 and len(records) < 50:
            continue
        for record in records:
            if str(record.get("classification_status")) != "confirmed":
                record["classification_status"] = "suppressed_soft_error"

    confirmed_urls = sorted(
        {
            str(record.get("url") or "")
            for record in validation_records
            if str(record.get("classification_status") or "") == "confirmed"
        }
    )
    suppressed_records = [
        record
        for record in validation_records
        if str(record.get("classification_status") or "") != "confirmed"
    ]
    by_status: dict[str, int] = {}
    for record in validation_records:
        status = str(record.get("classification_status") or "unconfirmed")
        by_status[status] = by_status.get(status, 0) + 1

    return _json_safe_value({
        "baselines": baselines,
        "records": validation_records,
        "by_url": by_url,
        "confirmed_urls": confirmed_urls,
        "suppressed": suppressed_records,
        "suppressed_count": len(suppressed_records),
        "by_status": by_status,
        "base_urls_preserved": sorted(base_origin_set),
    })


def _validated_url_allowed(url: object, validation: dict[str, Any]) -> bool:
    text = str(url or "").strip()
    if not text:
        return False
    by_url = validation.get("by_url") if isinstance(validation.get("by_url"), dict) else {}
    record = by_url.get(text)
    if not isinstance(record, dict):
        return True
    return str(record.get("classification_status") or "") == "confirmed"


def _extract_tech_context(technology_fingerprint: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Extract deduplicated technology labels, WAF labels, and normalized signals.

    Centralises the tech-extraction logic that was previously duplicated across
    _build_attack_chains, _build_attack_graph, and _build_exploit_suggestions.
    """
    technology_fingerprint = technology_fingerprint or []
    tech_labels: list[str] = []
    waf_labels: list[str] = []
    for item in technology_fingerprint:
        if not isinstance(item, dict):
            continue
        for tech in item.get("technologies", []) or []:
            tech_text = str(tech or "").strip()
            if tech_text and tech_text not in tech_labels:
                tech_labels.append(tech_text)
        for waf in item.get("waf_signals", []) or []:
            waf_text = str(waf or "").strip()
            if waf_text and waf_text not in waf_labels:
                waf_labels.append(waf_text)
    return {
        "tech_labels": tech_labels,
        "lower_techs": {t.lower() for t in tech_labels},
        "tech_signals": set(
            _normalize_technology_signals(technology_fingerprint).get("normalized", [])
        ),
        "waf_labels": waf_labels,
    }


def _build_attack_chains(
    classified_endpoints: dict[str, list[str]] | None,
    technology_fingerprint: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Infer likely attack chains from endpoint classes + tech fingerprint.

    This is an inference layer for JSON/report consumers. It should stay in the
    engine, not in CLI rendering.
    """
    classified_endpoints = classified_endpoints or {}

    admin_like = classified_endpoints.get("admin_like", []) or []
    auth_like = classified_endpoints.get("auth_like", []) or []
    api_like = classified_endpoints.get("api_like", []) or []
    upload_like = classified_endpoints.get("upload_like", []) or []
    debug_like = classified_endpoints.get("debug_like", []) or []
    docs_like = classified_endpoints.get("docs_like", []) or []

    ctx = _extract_tech_context(technology_fingerprint)
    tech_labels: list[str] = ctx["tech_labels"]
    waf_labels: list[str] = ctx["waf_labels"]
    lower_techs: set[str] = ctx["lower_techs"]
    tech_signals: set[str] = ctx["tech_signals"]
    chains: list[dict[str, Any]] = []
    seen_chain_names: set[str] = set()
    structural_groups = _structural_exposure_groups(classified_endpoints)
    upload_execution_evidence = _has_upload_execution_evidence(upload_like, tech_signals)

    def _add_chain(name: str, confidence: int, signals: list[str], why: str, next_tests: list[str]) -> None:
        norm = name.strip().lower()
        if norm in seen_chain_names:
            return
        seen_chain_names.add(norm)
        chains.append(
            {
                "name": name,
                "confidence": max(0, min(100, int(confidence))),
                "signals": signals,
                "why": why,
                "next_tests": next_tests,
            }
        )

    # Upload/listing exposure. RCE language is only used when execution evidence exists.
    if upload_like:
        confidence = 42 + min(18, len(upload_like) * 2)
        signals = [f"upload endpoints={len(upload_like)}"]
        next_tests = [
            "public upload/listing exposure review",
            "manual validation for upload abuse",
            "check executable handling",
            "path traversal via upload/download handling",
        ]
        if upload_execution_evidence:
            confidence += 24
            signals.append("upload execution evidence")
            next_tests.extend(["dangerous extension exposure review", "uploaded executable accessibility check"])
        if upload_execution_evidence and "php" in tech_signals:
            confidence += 18
            signals.append("php stack")
            next_tests.extend([".php payload upload", ".htaccess abuse", "polyglot file"])
        if upload_execution_evidence and "apache" in tech_signals:
            confidence += 8
            signals.append("apache stack")
        if admin_like:
            confidence += 8
            signals.append(f"admin panels={len(admin_like)}")
        if debug_like:
            confidence += 6
            signals.append(f"debug/test endpoints={len(debug_like)}")
        _add_chain(
            "Upload → Manual Validation" if not upload_execution_evidence else "Upload → RCE Validation Candidate",
            confidence,
            signals,
            (
                "Upload yüzeyi public upload/listing exposure sinyali üretiyor; RCE doğrulanmış değildir ve executable handling manuel doğrulanmalıdır."
                if not upload_execution_evidence
                else "Upload yüzeyi dangerous extension/execution sinyaliyle birleştiği için RCE validation candidate olarak ele alınmalı; execution doğrulanmış değildir ve manuel doğrulama gerekir."
            ),
            sorted(set(next_tests)),
        )

    # Auth -> admin abuse chain
    if auth_like and admin_like:
        confidence = 54 + min(18, len(auth_like) * 3) + min(18, len(admin_like) * 3)
        signals = [f"auth endpoints={len(auth_like)}", f"admin panels={len(admin_like)}"]
        if waf_labels:
            confidence += 4
            signals.append("waf/cdn present")
        _add_chain(
            "Auth → Admin Abuse",
            confidence,
            signals,
            "Auth akışı ile admin yüzeyinin birlikte görünmesi access control, workflow ve forced browsing riskini artırır.",
            [
                "default credentials",
                "forced browsing",
                "role/access control testing",
                "password reset / session workflow analysis",
            ],
        )

    # Docs/API -> public documentation review unless stronger API/schema evidence exists.
    if docs_like or api_like:
        ordinary_docs_only = _ordinary_public_docs_only(api_like, docs_like, tech_signals)
        confidence = (
            34 + min(8, len(docs_like))
            if ordinary_docs_only
            else 46 + min(10, len(docs_like)) + min(22, len(api_like) * 2)
        )
        signals = []
        if docs_like:
            signals.append(f"documentation pages={len(docs_like)}")
        if api_like:
            signals.append(f"api endpoints={len(api_like)}")
        if "graphql" in tech_signals:
            confidence += 10
            signals.append("graphql tech fingerprint")
        if "openapi" in tech_signals:
            confidence += 10
            signals.append("swagger/redoc fingerprint")
        _add_chain(
            "Public documentation surface → manual review" if ordinary_docs_only else "Docs/API → Enumeration & Exposure",
            confidence,
            signals,
            (
                "Public docs/help/resource yüzeyi normal SaaS içerik olabilir; doğrudan zafiyet değildir ve yalnızca manuel içerik incelemesi gerektirir."
                if ordinary_docs_only
                else "Dokümantasyon ve API yüzeyi birlikte olduğunda schema discovery, endpoint harvesting ve object-level auth testleri değerli hale gelir."
            ),
            [
                "public documentation review",
                "manual review for internal API routes",
                "manual review for secrets/config/debug terms",
            ],
        )

    structural_chain_specs = (
        ("source_control", "Source Control Exposure → Code/Secret Leakage → Manual Validation", 92, "Repository metadata exposure signal detected; code/secret leakage requires manual validation."),
        ("config", "Config Mirror → Secret/Config Exposure", 88, "Secret/config exposure pattern detected; manual validation required."),
        ("backup", "Backup Area → Sensitive Data Exposure", 86, "Backup/dump naming exposure signal detected; manual validation required."),
        ("logs", "Logs Exposure → Internal Info Disclosure", 84, "Public log/error exposure signal detected; manual validation required."),
        ("debug_console", "Debug Console → Internal Routes/Config Exposure", 87, "Debug console/exposure signal detected; manual validation required."),
        ("runtime", "Runtime Disclosure → Manual Validation", 82, "Runtime/phpinfo/server-status exposure signal detected; manual validation required."),
        ("internal_api", "Internal API → Data Exposure Review", 85, "Internal API/status/users exposure signal detected; manual validation required."),
        ("admin_export", "Admin Export → Data Exposure Review", 84, "Admin export/download surface signal detected; manual validation required."),
    )
    for group_key, name, base_confidence, why in structural_chain_specs:
        urls = structural_groups.get(group_key, [])
        if not urls:
            continue
        _add_chain(
            name,
            min(94, base_confidence + min(8, len(urls) * 2)),
            [f"{group_key} endpoints={len(urls)}", "structural exposure signal", "no exploit confirmed"],
            why,
            [
                "manual validation required",
                "confirm response body and auth requirements",
                "classify demo/fake markers before impact claims",
            ],
        )

    # Debug -> secret/config leak chain
    if debug_like:
        confidence = 58 + min(24, len(debug_like) * 4)
        signals = [f"debug/test endpoints={len(debug_like)}"]
        if any(t in tech_signals for t in ["django", "laravel", "aspnet"]):
            confidence += 8
            signals.append("framework with debug/config sensitivity")
        _add_chain(
            "Debug/Test → Config Leak",
            confidence,
            signals,
            "Debug ve test yüzeyi çoğu zaman config leak, verbose error, internal feature veya env exposure riski taşır.",
            [
                "env/config leak review",
                "verbose error triggering",
                "hidden parameters",
                "test harness / internal route abuse",
            ],
        )

    chains = sorted(chains, key=lambda c: (int(c.get("confidence", 0)), len(c.get("signals", []))), reverse=True)
    return chains


# Inserted new function: _build_attack_graph
def _build_attack_graph(
    classified_endpoints: dict[str, list[str]] | None,
    technology_fingerprint: list[dict[str, Any]] | None,
    attack_chains: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Build a lightweight attack graph from discovered surface + tech hints."""
    classified_endpoints = classified_endpoints or {}
    attack_chains = attack_chains or []

    admin_like = classified_endpoints.get("admin_like", []) or []
    auth_like = classified_endpoints.get("auth_like", []) or []
    api_like = classified_endpoints.get("api_like", []) or []
    upload_like = classified_endpoints.get("upload_like", []) or []
    debug_like = classified_endpoints.get("debug_like", []) or []
    docs_like = classified_endpoints.get("docs_like", []) or []

    ctx = _extract_tech_context(technology_fingerprint)
    tech_labels: list[str] = ctx["tech_labels"]
    lower_techs: set[str] = ctx["lower_techs"]
    tech_signals: set[str] = ctx["tech_signals"]
    structural_groups = _structural_exposure_groups(classified_endpoints)
    upload_execution_evidence = _has_upload_execution_evidence(upload_like, tech_signals)

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    paths: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str]] = set()
    seen_paths: set[str] = set()

    def _add_node(node_id: str, label: str, node_type: str, count: int = 0, details: list[str] | None = None) -> None:
        if any(str(n.get("id") or "") == node_id for n in nodes):
            return
        nodes.append(
            {
                "id": node_id,
                "label": label,
                "type": node_type,
                "count": int(count or 0),
                "details": details or [],
            }
        )

    def _add_edge(src: str, dst: str, reason: str, confidence: int) -> None:
        key = (src, dst)
        if key in seen_edges:
            return
        seen_edges.add(key)
        edges.append(
            {
                "from": src,
                "to": dst,
                "reason": reason,
                "confidence": max(0, min(100, int(confidence))),
            }
        )

    def _add_path(name: str, confidence: int, sequence: list[str], why: str) -> None:
        norm = name.strip().lower()
        if norm in seen_paths:
            return
        seen_paths.add(norm)
        paths.append(
            {
                "name": name,
                "confidence": max(0, min(100, int(confidence))),
                "sequence": sequence,
                "why": why,
            }
        )

    if auth_like:
        _add_node("auth", "Authentication Surface", "surface", len(auth_like), auth_like[:5])
    if admin_like:
        _add_node("admin", "Admin Surface", "surface", len(admin_like), admin_like[:5])
    if upload_like:
        _add_node("upload", "Upload Surface", "surface", len(upload_like), upload_like[:5])
    if debug_like:
        _add_node("debug", "Debug/Test Surface", "surface", len(debug_like), debug_like[:5])
    if api_like:
        _add_node("api", "API Surface", "surface", len(api_like), api_like[:5])
    if docs_like:
        _add_node("docs", "Docs/Dev Surface", "surface", len(docs_like), docs_like[:5])
    if structural_groups.get("config"):
        _add_node("config_mirror", "Config Mirror", "surface", len(structural_groups["config"]), structural_groups["config"][:5])
    if structural_groups.get("backup"):
        _add_node("backup_area", "Backup Area", "surface", len(structural_groups["backup"]), structural_groups["backup"][:5])
    if structural_groups.get("logs"):
        _add_node("logs_exposure", "Logs Exposure", "surface", len(structural_groups["logs"]), structural_groups["logs"][:5])
    if structural_groups.get("debug_console"):
        _add_node("debug_console", "Debug Console", "surface", len(structural_groups["debug_console"]), structural_groups["debug_console"][:5])
    if structural_groups.get("runtime"):
        _add_node("runtime_disclosure", "Runtime Disclosure", "surface", len(structural_groups["runtime"]), structural_groups["runtime"][:5])
    if structural_groups.get("internal_api"):
        _add_node("internal_api", "Internal API Surface", "surface", len(structural_groups["internal_api"]), structural_groups["internal_api"][:5])
    if structural_groups.get("admin_export"):
        _add_node("admin_export", "Admin Export Surface", "surface", len(structural_groups["admin_export"]), structural_groups["admin_export"][:5])
    if structural_groups.get("source_control"):
        _add_node("source_control", "Source Control Exposure", "surface", len(structural_groups["source_control"]), structural_groups["source_control"][:5])

    if tech_labels:
        _add_node("tech", "Technology Stack", "technology", len(tech_labels), tech_labels)
    if "php" in tech_signals or "apache" in tech_signals:
        _add_node(
            "legacy_web_stack",
            "PHP/Apache Stack",
            "technology",
            2,
            [t for t in ["php", "apache"] if t in tech_signals],
        )
    if "graphql" in tech_signals:
        _add_node("graphql", "GraphQL Signal", "technology", 1, ["GraphQL"])
    if "openapi" in tech_signals:
        _add_node("openapi", "OpenAPI / Swagger Signal", "technology", 1, ["OpenAPI", "Swagger", "Redoc"])
    if "phpmyadmin" in tech_signals:
        _add_node("phpmyadmin", "phpMyAdmin Signal", "technology", 1, ["phpMyAdmin"])

    if upload_like:
        upload_outcome_label = "RCE Validation Candidate" if upload_execution_evidence else "Public Upload/Listing Exposure"
        upload_outcome_details = (
            ["dangerous extension", "manual validation required", "execution not confirmed"]
            if upload_execution_evidence
            else ["public upload/listing exposure", "manual validation", "check executable handling"]
        )
        upload_outcome_id = "rce" if upload_execution_evidence else "upload_exposure"
        _add_node(upload_outcome_id, upload_outcome_label, "outcome", 1, upload_outcome_details)
    if admin_like and auth_like:
        _add_node("admin_abuse", "Admin Abuse", "outcome", 1, ["auth bypass", "role abuse", "forced browsing"])
    if docs_like or api_like:
        _add_node("enumeration", "Enumeration / Exposure", "outcome", 1, ["endpoint harvesting", "schema discovery", "data exposure"])
    if debug_like:
        _add_node("config_leak", "Config Leak", "outcome", 1, ["env leak", "verbose errors", "internal route abuse"])
    if structural_groups.get("config"):
        _add_node("secret_config_exposure", "Secret/Config Exposure", "outcome", 1, ["manual validation required", "not confirmed vulnerability"])
    if structural_groups.get("backup"):
        _add_node("sensitive_data_exposure", "Sensitive Data Exposure", "outcome", 1, ["manual validation required", "backup/dump preview"])
    if structural_groups.get("logs"):
        _add_node("internal_info_disclosure", "Internal Info Disclosure", "outcome", 1, ["manual validation required", "verbose logs"])
    if structural_groups.get("internal_api"):
        _add_node("internal_api_data_review", "Internal API Data Exposure Review", "outcome", 1, ["manual validation required", "users/status/build/version preview"])
    if structural_groups.get("source_control"):
        _add_node("code_secret_leakage", "Code/Secret Leakage Review", "outcome", 1, ["repository metadata exposure", "check remotes/config/history", "manual validation required"])

    if upload_like:
        _add_edge(
            "upload",
            "rce" if upload_execution_evidence else "upload_exposure",
            (
                "Upload yüzeyi execution sinyaliyle birleştiği için RCE validation candidate kabul edilir; execution doğrulanmış değildir ve executable handling manuel doğrulanmalı."
                if upload_execution_evidence
                else "Upload/listing yüzeyi public exposure sinyali; RCE doğrulanmış değildir, executable handling manuel doğrulanmalı."
            ),
            78 if upload_execution_evidence else 54,
        )
    if upload_execution_evidence and upload_like and ("php" in tech_signals or "apache" in tech_signals):
        _add_edge("legacy_web_stack", "rce", "PHP/Apache stack upload abuse adaylığını yükseltebilir; direct execution kanıtı değildir.", 90)
    if auth_like and admin_like:
        _add_edge("auth", "admin", "Auth akışı admin yüzeyi ile birlikte access control testlerini değerli kılar.", 72)
        _add_edge("admin", "admin_abuse", "Admin yüzeyi forced browsing / role bypass için kritik.", 80)
    if docs_like:
        _add_edge("docs", "enumeration", "Dokümantasyon endpoint harvesting ve gizli surface keşfi sağlar.", 68)
    if api_like:
        _add_edge("api", "enumeration", "API yüzeyi object-level auth ve data exposure incelemesi gerektirir.", 74)
    if "graphql" in tech_signals:
        _add_edge("graphql", "enumeration", "GraphQL schema discovery ve excessive data exposure için güçlü sinyal.", 82)
    if "openapi" in tech_signals:
        _add_edge("openapi", "enumeration", "Swagger/OpenAPI/Redoc sinyali endpoint harvesting ve auth review için güçlü sinyal.", 84)
    if "phpmyadmin" in tech_signals and admin_like:
        _add_edge("phpmyadmin", "admin_abuse", "phpMyAdmin gibi admin veri yüzeyleri default creds / exposure testleri için değerlidir.", 86)
    if debug_like:
        _add_edge("debug", "config_leak", "Debug/test yüzeyi config/env leak ihtimalini artırır.", 75)
    if structural_groups.get("config"):
        _add_edge("config_mirror", "secret_config_exposure", "Secret/config exposure pattern detected; manual validation required.", 92)
    if structural_groups.get("backup"):
        _add_edge("backup_area", "sensitive_data_exposure", "Backup/dump exposure signal detected; manual validation required.", 90)
    if structural_groups.get("logs"):
        _add_edge("logs_exposure", "internal_info_disclosure", "Public logs/error exposure signal detected; manual validation required.", 88)
    if structural_groups.get("debug_console"):
        _add_edge("debug_console", "config_leak", "Debug console exposure signal detected; manual validation required.", 89)
    if structural_groups.get("runtime"):
        _add_edge("runtime_disclosure", "config_leak", "Runtime disclosure signal detected; manual validation required.", 84)
    if structural_groups.get("internal_api"):
        _add_edge("internal_api", "internal_api_data_review", "Internal users/status/build/version API signal detected; manual validation required.", 89)
    if structural_groups.get("admin_export"):
        _add_edge("admin_export", "sensitive_data_exposure", "Admin export/download signal detected; manual validation required.", 88)
    if structural_groups.get("source_control"):
        _add_edge("source_control", "code_secret_leakage", "Repository metadata exposure detected; confirm public .git access and leaked remotes/config/history.", 94)

    if upload_execution_evidence and upload_like and ("php" in tech_signals or "apache" in tech_signals):
        _add_path(
            "Upload → RCE Validation Candidate",
            92,
            ["Upload Surface", "PHP/Apache Stack", "RCE Validation Candidate"],
            "Upload endpointleri ve PHP/Apache stack birlikte olduğunda executable handling doğrulaması öncelikli hale gelir; execution confirmed değildir ve manual validation required.",
        )
    elif upload_execution_evidence and upload_like:
        _add_path(
            "Upload → RCE Validation Candidate",
            76,
            ["Upload Surface", "RCE Validation Candidate"],
            "Upload yüzeyi dangerous extension/execution sinyaliyle birleştiği için manuel validation gerektirir; execution confirmed değildir.",
        )
    elif upload_like:
        _add_path(
            "Upload → Manual Validation",
            53,
            ["Upload Surface", "Public Upload/Listing Exposure"],
            "Upload/listing yüzeyi RCE kanıtı değildir; executable handling ve abuse koşulları manuel doğrulanmalıdır.",
        )

    if auth_like and admin_like:
        _add_path(
            "Auth → Admin Abuse",
            74,
            ["Authentication Surface", "Admin Surface", "Admin Abuse"],
            "Auth ve admin yüzeyinin birlikte görünmesi access control / session / forced browsing testlerini öne çıkarır.",
        )

    if structural_groups.get("source_control"):
        _add_path(
            "Source Control Exposure → Code/Secret Leakage → Manual Validation",
            94,
            ["Source Control Exposure", "Code/Secret Leakage", "Manual Validation"],
            "Public .git metadata exposure source, remote/config/history leakage riski taşır; impact manual validation ile doğrulanmalıdır.",
        )

    if docs_like and api_like:
        _add_path(
            "Docs → API → Enumeration",
            70 if _is_strong_api_or_docs_signal(api_like, docs_like, tech_signals) else 62,
            ["Docs/Dev Surface", "API Surface", "Enumeration / Exposure"],
            "Docs ve API yüzeyi birlikte olduğunda schema discovery değeri olabilir; exposure claim için iç API/config/secret kanıtı manuel doğrulanmalıdır.",
        )
    elif docs_like or api_like:
        ordinary_docs_only = _ordinary_public_docs_only(api_like, docs_like, tech_signals)
        _add_path(
            "Public documentation surface → manual review" if ordinary_docs_only else "Docs/API → Enumeration",
            38 if ordinary_docs_only else 58,
            ["Docs/Dev Surface" if docs_like else "API Surface", "Manual Review" if ordinary_docs_only else "Enumeration / Exposure"],
            (
                "Public docs/help/resource yüzeyi normal içerik olabilir; no direct Nuclei evidence, manual validation required."
                if ordinary_docs_only
                else "API/docs yüzeyi keşif için adaydır; exposure claim için ek kanıt gerekir."
            ),
        )

    if debug_like:
        _add_path(
            "Debug/Test → Config Leak",
            75,
            ["Debug/Test Surface", "Config Leak"],
            "Debug/test yüzeyi env/config leak ve verbose error tetikleme denemeleri için doğal başlangıçtır.",
        )

    structural_path_specs = (
        ("config", "Config Mirror → Secret/Config Exposure", 90, ["Config Mirror", "Secret/Config Exposure"], "Secret/config exposure pattern detected; manual validation required; not confirmed vulnerability."),
        ("backup", "Backup Area → Sensitive Data Exposure", 88, ["Backup Area", "Sensitive Data Exposure"], "Backup/dump exposure signal detected; manual validation required; not confirmed vulnerability."),
        ("logs", "Logs Exposure → Internal Info Disclosure", 86, ["Logs Exposure", "Internal Info Disclosure"], "Public log/error exposure signal detected; manual validation required; not confirmed vulnerability."),
        ("debug_console", "Debug Console → Internal Routes/Config Exposure", 87, ["Debug Console", "Config Leak"], "Debug console exposure signal detected; manual validation required; not confirmed vulnerability."),
        ("runtime", "Runtime Disclosure → Manual Validation", 82, ["Runtime Disclosure", "Config Leak"], "Runtime/phpinfo/server-status disclosure signal detected; manual validation required; not confirmed vulnerability."),
        ("internal_api", "Internal API → Users Preview/Data Exposure", 87, ["Internal API Surface", "Internal API Data Exposure Review"], "Internal users/status/build/version API signal detected; manual validation required; not confirmed vulnerability."),
        ("admin_export", "Admin Export → Data Exposure Review", 85, ["Admin Export Surface", "Sensitive Data Exposure"], "Admin export/download surface signal detected; manual validation required; not confirmed vulnerability."),
    )
    for group_key, name, confidence, sequence, why in structural_path_specs:
        if structural_groups.get(group_key):
            _add_path(name, confidence, sequence, why)

    chain_names = [str(c.get("name") or "") for c in attack_chains if isinstance(c, dict)]

    return {
        "nodes": nodes,
        "edges": edges,
        "paths": sorted(paths, key=lambda p: int(p.get("confidence", 0)), reverse=True),
        "chain_names": chain_names,
    }


def _normalize_technology_signals(technology_fingerprint: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Normalize noisy WhatWeb / fingerprint technologies into high-value tech tags.

    Goal:
    - keep stack / panel / API technologies that affect attack decisions
    - drop generic noise like cookies, script, ip, uncommonheaders
    """
    technology_fingerprint = technology_fingerprint or []

    raw_labels: list[str] = []
    for item in technology_fingerprint:
        if not isinstance(item, dict):
            continue
        for tech in item.get("technologies", []) or []:
            tech_text = str(tech or "").strip()
            if tech_text:
                raw_labels.append(tech_text)

    noise_markers = {
        "ip",
        "cookies",
        "cookie",
        "script",
        "jquery",
        "uncommonheaders",
        "x-powered-by",
        "poweredby",
        "xss-protection",
        "httpserver",
        "httpserverheader",
        "httpproxy",
        "html5",
        "title",
        "metagenerator",
        "allow",
        "country",
    }

    normalized_map: list[tuple[str, str]] = [
        ("apache httpd", "apache"),
        ("apache", "apache"),
        ("php", "php"),
        ("nginx", "nginx"),
        ("wordpress", "wordpress"),
        ("drupal", "drupal"),
        ("joomla", "joomla"),
        ("laravel", "laravel"),
        ("django", "django"),
        ("flask", "flask"),
        ("asp.net", "aspnet"),
        ("aspnet", "aspnet"),
        ("tomcat", "tomcat"),
        ("jenkins", "jenkins"),
        ("phpmyadmin", "phpmyadmin"),
        ("graphql", "graphql"),
        ("swagger", "openapi"),
        ("openapi", "openapi"),
        ("redoc", "openapi"),
    ]

    normalized: list[str] = []
    noise: list[str] = []

    for raw in raw_labels:
        low = raw.lower().strip()
        if not low:
            continue

        if low in noise_markers:
            if raw not in noise:
                noise.append(raw)
            continue

        matched = None
        for marker, target in normalized_map:
            if marker in low:
                matched = target
                break

        if matched:
            if matched not in normalized:
                normalized.append(matched)
        else:
            if raw not in noise:
                noise.append(raw)

    return {
        "normalized": normalized,
        "noise": noise,
        "raw": raw_labels,
    }

# Helper function: _extract_cve_queries
def _extract_cve_queries(technology_fingerprint: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    """Build conservative version-aware CVE keyword queries from tech evidence."""
    technology_fingerprint = technology_fingerprint or []
    queries: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add_query(product: str, version: str, evidence: str) -> None:
        product = (product or "").strip()
        version = (version or "").strip()
        if not product or not version:
            return
        key = (product.lower(), version.lower())
        if key in seen:
            return
        seen.add(key)
        queries.append(
            {
                "product": product,
                "version": version,
                "keyword": f"{product} {version}",
                "evidence": evidence,
            }
        )

    for item in technology_fingerprint:
        if not isinstance(item, dict):
            continue

        server_header = str(item.get("server") or "")
        powered_by = str(item.get("x_powered_by") or "")

        m_apache = re.search(r"apache/?([0-9]+(?:\.[0-9]+){1,3})", server_header, flags=re.I)
        if m_apache:
            _add_query("Apache HTTP Server", m_apache.group(1), f"server={server_header}")

        m_nginx = re.search(r"nginx/?([0-9]+(?:\.[0-9]+){1,3})", server_header, flags=re.I)
        if m_nginx:
            _add_query("Nginx", m_nginx.group(1), f"server={server_header}")

        m_php = re.search(r"php/?([0-9]+(?:\.[0-9]+){1,3})", powered_by, flags=re.I)
        if m_php:
            _add_query("PHP", m_php.group(1), f"x-powered-by={powered_by}")

        m_asp = re.search(r"asp\.net/?([0-9]+(?:\.[0-9]+){1,3})", powered_by, flags=re.I)
        if m_asp:
            _add_query("ASP.NET", m_asp.group(1), f"x-powered-by={powered_by}")

    return queries


# Helper function: _fetch_nvd_keyword_cves
def _fetch_nvd_keyword_cves(keyword: str, max_results: int = 5, timeout_sec: int = 8) -> list[dict[str, Any]]:
    """Query NVD CVE API using keyword search (best-effort).

    This is intentionally lightweight and failure-tolerant. If the API
    request fails, an empty list is returned.
    """

    if not keyword:
        return []

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    })

    url = f"{base_url}?{params}"

    try:
        req = Request(url, headers={"User-Agent": "Reconbot-CVE-Enrichment"})
        with urlopen(req, timeout=timeout_sec) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")

        data = json.loads(raw)
        vulns = data.get("vulnerabilities", [])

        results: list[dict[str, Any]] = []

        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id")

            descriptions = cve.get("descriptions", []) or []
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            results.append(
                {
                    "cve_id": cve_id,
                    "description": desc[:400],
                }
            )

        return results

    except (URLError, HTTPError, TimeoutError, json.JSONDecodeError):
        return []


# Inserted helper function for CVE relevance scoring

def _score_cve_relevance(
    cve_item: dict[str, Any],
    classified_endpoints: dict[str, list[str]] | None,
    technology_fingerprint: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Best-effort CVE relevance scoring using discovered attack surface."""
    classified_endpoints = classified_endpoints or {}
    technology_fingerprint = technology_fingerprint or []

    desc = str(cve_item.get("description") or "").lower()
    score = 0
    reasons: list[str] = []

    admin_like = classified_endpoints.get("admin_like", []) or []
    auth_like = classified_endpoints.get("auth_like", []) or []
    api_like = classified_endpoints.get("api_like", []) or []
    upload_like = classified_endpoints.get("upload_like", []) or []
    debug_like = classified_endpoints.get("debug_like", []) or []
    docs_like = classified_endpoints.get("docs_like", []) or []

    tech_labels: list[str] = []
    for item in technology_fingerprint:
        if not isinstance(item, dict):
            continue
        for tech in item.get("technologies", []) or []:
            tech_text = str(tech or "").strip().lower()
            if tech_text and tech_text not in tech_labels:
                tech_labels.append(tech_text)

    def _matches_any(text: str, keywords: list[str]) -> bool:
        return any(k in text for k in keywords)

    query_product = str(cve_item.get("query_product") or "").strip().lower()

    def _product_aligned(product: str, text: str) -> bool:
        if not product:
            return True
        product = product.lower()
        if product == "php":
            product_markers = (
                "php before",
                "php through",
                "php versions",
                "php version",
                "php 5",
                "php 7",
                "php 8",
                "php-cgi",
                "php-fpm",
                "php interpreter",
                "the php",
                " in php ",
            )
            mismatched_products = (
                "dell kace",
                "kace systems management",
                "wordpress",
                "drupal",
                "joomla",
            )
            return any(marker in text for marker in product_markers) and not any(
                marker in text for marker in mismatched_products
            )
        if product == "apache http server":
            return any(marker in text for marker in ("apache http server", "apache httpd", "apache 2."))
        if product == "nginx":
            return "nginx" in text
        if product == "asp.net":
            return "asp.net" in text or "asp net" in text
        tokens = [token for token in re.split(r"[^a-z0-9]+", product) if len(token) > 2]
        return bool(tokens) and all(token in text for token in tokens)

    if upload_like and _matches_any(desc, [
        "upload", "file upload", "multipart", "path traversal", "directory traversal",
        "inclusion", "remote code execution", "code execution", "arbitrary file", "webshell",
        "parser",
    ]):
        score += 30
        reasons.append("aligns with upload surface")

    if (auth_like or admin_like) and _matches_any(desc, [
        "authentication", "authorization", "access control", "privilege escalation",
        "session", "login", "bypass", "admin",
    ]):
        score += 24
        reasons.append("aligns with auth/admin surface")

    if api_like and _matches_any(desc, [
        "api", "graphql", "swagger", "endpoint", "exposure", "information disclosure",
        "data exposure",
    ]):
        score += 18
        reasons.append("aligns with API surface")

    if docs_like and _matches_any(desc, [
        "documentation", "swagger", "redoc", "information disclosure", "exposure",
    ]):
        score += 12
        reasons.append("aligns with docs/dev surface")

    if debug_like and _matches_any(desc, [
        "debug", "verbose", "information disclosure", "configuration", "config", "environment",
        "stack trace", "error message",
    ]):
        score += 20
        reasons.append("aligns with debug/test surface")

    if "php" in tech_labels and _matches_any(desc, ["php"]):
        score += 10
        reasons.append("matches PHP stack")

    if "apache httpd" in tech_labels and _matches_any(desc, ["apache", "http server", "httpd"]):
        score += 10
        reasons.append("matches Apache stack")

    if "nginx" in tech_labels and "nginx" in desc:
        score += 10
        reasons.append("matches Nginx stack")

    product_aligned = _product_aligned(query_product, f" {desc} ")
    if query_product and not product_aligned:
        score = min(score, 24)
        reasons.append("product/vendor mismatch; manual review only")

    return {
        **cve_item,
        "relevance_score": max(0, min(100, score)),
        "relevance_reasons": reasons,
    }


# New helper: _build_exploit_suggestions
def _resolve_nuclei_template_families(families: list[str] | None) -> dict[str, Any]:
    """Resolve high-level nuclei families into practical tags/groups.

    This is intentionally heuristic. It does not enumerate exact template files;
    it provides operator-friendly tags/families that can later be used by CLI/GUI.
    """
    families = families or []

    family_to_tags: dict[str, list[str]] = {
        "file-upload": ["file-upload", "upload", "rce", "lfi"],
        "rce": ["rce", "command-injection", "code-execution"],
        "lfi": ["lfi", "path-traversal", "file-read"],
        "misconfiguration": ["misconfig", "exposure", "config"],
        "default-login": ["default-login", "login", "auth"],
        "auth-bypass": ["auth-bypass", "auth", "bypass"],
        "exposures": ["exposure", "disclosure", "debug", "config"],
        "api": ["api", "graphql", "swagger", "openapi"],
        "config": ["config", "exposure", "debug"],
        "workflows": ["workflow", "auth", "rce", "misconfig"],
    }

    resolved: list[dict[str, Any]] = []
    all_tags: list[str] = []
    seen_tags: set[str] = set()

    for family in families:
        fam = str(family or "").strip().lower()
        if not fam:
            continue
        tags = family_to_tags.get(fam, [fam])
        resolved.append({
            "family": fam,
            "tags": tags,
        })
        for tag in tags:
            if tag not in seen_tags:
                seen_tags.add(tag)
                all_tags.append(tag)

    suggested_cli = ""
    if all_tags:
        suggested_cli = f"nuclei -tags {','.join(all_tags)} -rl 2 -c 2"

    return {
        "families": resolved,
        "all_tags": all_tags,
        "suggested_cli": suggested_cli,
    }

def _build_node_relationships(
    classified_endpoints: dict[str, list[str]] | None,
    attack_graph: dict[str, Any] | None,
    exploit_suggestions: list[dict[str, Any]] | None,
    technology_fingerprint: list[dict[str, Any]] | None,
    cve_enrichment: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build GUI-ready node click relationships.

    This is backend data only. GUI can later use it for node-click side panels.
    """
    classified_endpoints = classified_endpoints or {}
    attack_graph = attack_graph or {}
    exploit_suggestions = exploit_suggestions or []
    cve_enrichment = cve_enrichment or {}
    technology_fingerprint = technology_fingerprint or []

    graph_nodes = attack_graph.get("nodes", []) if isinstance(attack_graph, dict) else []
    cve_matches = cve_enrichment.get("matches", []) if isinstance(cve_enrichment, dict) else []
    tech_signals = set(_normalize_technology_signals(technology_fingerprint).get("normalized", []))

    relation_map: dict[str, dict[str, Any]] = {}

    for node in graph_nodes:
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("id") or "").strip()
        node_label = str(node.get("label") or "").strip()
        if not node_id:
            continue

        low_label = node_label.lower()
        node_details = node.get("details", []) if isinstance(node, dict) else []
        related_suggestions: list[dict[str, Any]] = []
        related_cves: list[dict[str, Any]] = []
        related_nuclei_tags: list[str] = []
        related_endpoints: list[str] = []
        related_technologies: list[str] = []

        if "upload" in low_label:
            related_endpoints = [
                ep for ep in classified_endpoints.get("upload_like", [])[:10]
                if _is_meaningful_upload_surface(ep)
            ]
            related_technologies = [t for t in ["php", "apache"] if t in tech_signals]
        elif "auth" in low_label:
            related_endpoints = [
                ep for ep in classified_endpoints.get("auth_like", [])[:10]
                if _is_meaningful_auth_surface(ep)
            ]
            related_technologies = [t for t in ["wordpress", "phpmyadmin"] if t in tech_signals]
        elif "admin" in low_label:
            related_endpoints = [
                ep for ep in classified_endpoints.get("admin_like", [])[:10]
                if _is_meaningful_admin_surface(ep)
            ]
            related_technologies = [t for t in ["phpmyadmin", "wordpress", "php", "apache"] if t in tech_signals]
        elif "api" in low_label:
            related_endpoints = [
                ep for ep in classified_endpoints.get("api_like", [])[:10]
                if _is_meaningful_api_surface(ep)
            ]
            related_technologies = [t for t in ["graphql", "openapi"] if t in tech_signals]
        elif "docs" in low_label:
            related_endpoints = [
                ep for ep in classified_endpoints.get("docs_like", [])[:10]
                if _is_meaningful_docs_surface(ep)
            ]
            related_technologies = [t for t in ["openapi", "graphql"] if t in tech_signals]
        elif "debug" in low_label:
            related_endpoints = [
                ep for ep in classified_endpoints.get("debug_like", [])[:10]
                if _is_meaningful_debug_surface(ep)
            ]
            related_technologies = [t for t in ["django", "laravel", "aspnet", "php"] if t in tech_signals]
        elif "source control" in low_label or "code/secret" in low_label:
            related_endpoints = [
                ep for ep in classified_endpoints.get("source_control_like", [])[:10]
                if _is_meaningful_source_control_surface(ep)
            ]
            related_technologies = [t for t in ["php", "apache"] if t in tech_signals]
        elif "php/apache" in low_label or "stack" in low_label:
            related_endpoints = []
            related_technologies = [t for t in ["php", "apache"] if t in tech_signals]
        elif "graphql" in low_label:
            related_endpoints = []
            related_technologies = [t for t in ["graphql"] if t in tech_signals]
        elif "openapi" in low_label or "swagger" in low_label:
            related_endpoints = []
            related_technologies = [t for t in ["openapi"] if t in tech_signals]
        elif "phpmyadmin" in low_label:
            related_endpoints = []
            related_technologies = [t for t in ["phpmyadmin", "php", "apache"] if t in tech_signals]

        for suggestion in exploit_suggestions:
            if not isinstance(suggestion, dict):
                continue
            surface = str(suggestion.get("surface") or "").lower()
            title = str(suggestion.get("title") or "")
            include = False

            if "upload" in low_label and "upload" in surface:
                include = True
            elif "auth" in low_label and "auth" in surface:
                include = True
            elif "admin" in low_label and ("auth/admin" in surface or "auth" in surface):
                include = True
            elif "api" in low_label and "api/docs" in surface:
                include = True
            elif "docs" in low_label and "api/docs" in surface:
                include = True
            elif "debug" in low_label and "debug" in surface:
                include = True
            elif ("source control" in low_label or "code/secret" in low_label) and "source control" in surface:
                include = True
            elif "attack chains" in surface and ("rce" in low_label or "abuse" in low_label or "enumeration" in low_label or "leak" in low_label):
                include = True
            elif "php/apache" in low_label and "upload exploitation" in title.lower():
                include = True

            if include:
                related_suggestions.append(
                    {
                        "title": suggestion.get("title", "-"),
                        "priority": int(suggestion.get("priority", 0) or 0),
                        "surface": suggestion.get("surface", "-"),
                    }
                )
                resolved = suggestion.get("resolved_nuclei", {}) if isinstance(suggestion, dict) else {}
                for tag in (resolved.get("all_tags", []) or []):
                    tag_text = str(tag or "").strip()
                    if tag_text and tag_text not in related_nuclei_tags:
                        related_nuclei_tags.append(tag_text)

        for match_group in cve_matches[:10]:
            if not isinstance(match_group, dict):
                continue
            product = str(match_group.get("product") or "")
            version = str(match_group.get("version") or "")
            for cve in (match_group.get("cves", []) or [])[:5]:
                if not isinstance(cve, dict):
                    continue
                reasons = [str(r or "").lower() for r in (cve.get("relevance_reasons", []) or [])]
                include = False
                if "upload" in low_label and any("upload surface" in r for r in reasons):
                    include = True
                elif ("auth" in low_label or "admin" in low_label) and any("auth/admin surface" in r for r in reasons):
                    include = True
                elif "api" in low_label and any("api surface" in r for r in reasons):
                    include = True
                elif "docs" in low_label and any("docs/dev surface" in r for r in reasons):
                    include = True
                elif "debug" in low_label and any("debug/test surface" in r for r in reasons):
                    include = True
                elif "php" in low_label and any("php stack" in r for r in reasons):
                    include = True
                elif "apache" in low_label and any("apache stack" in r for r in reasons):
                    include = True

                if include:
                    related_cves.append(
                        {
                            "cve_id": cve.get("cve_id", "-"),
                            "relevance_score": int(cve.get("relevance_score", 0) or 0),
                            "product": product,
                            "version": version,
                        }
                    )

        related_suggestions = sorted(related_suggestions, key=lambda x: int(x.get("priority", 0)), reverse=True)
        related_cves = sorted(related_cves, key=lambda x: int(x.get("relevance_score", 0)), reverse=True)

        cleaned_related_endpoints: list[str] = []
        for ep in related_endpoints:
            if not ep:
                continue
            if "login" in low_label or "auth" in low_label:
                normalized_ep = _normalize_surface_url(ep, keep_auth_query=True)
            else:
                normalized_ep = _normalize_surface_url(ep)
            if normalized_ep:
                cleaned_related_endpoints.append(normalized_ep)

        related_endpoints = sorted(set(cleaned_related_endpoints))

        relation_map[node_id] = {
            "node_id": node_id,
            "node_label": node_label,
            "related_suggestions": related_suggestions[:6],
            "related_cves": related_cves[:8],
            "related_nuclei_tags": related_nuclei_tags[:20],
            "related_endpoints": related_endpoints,
            "related_technologies": related_technologies,
        }

    return relation_map

def _build_exploit_suggestions(
    classified_endpoints: dict[str, list[str]] | None,
    technology_fingerprint: list[dict[str, Any]] | None,
    attack_chains: list[dict[str, Any]] | None,
    attack_graph: dict[str, Any] | None,
    cve_enrichment: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Build operator-facing exploit suggestions from surface + tech + CVE hints.

    These are NOT exploit confirmations. They are prioritized manual test ideas.
    """
    classified_endpoints = classified_endpoints or {}
    attack_chains = attack_chains or []
    attack_graph = attack_graph or {}
    cve_enrichment = cve_enrichment or {}

    admin_like = classified_endpoints.get("admin_like", []) or []
    auth_like = classified_endpoints.get("auth_like", []) or []
    api_like = classified_endpoints.get("api_like", []) or []
    upload_like = classified_endpoints.get("upload_like", []) or []
    debug_like = classified_endpoints.get("debug_like", []) or []
    docs_like = classified_endpoints.get("docs_like", []) or []

    ctx = _extract_tech_context(technology_fingerprint)
    tech_labels: list[str] = [t.lower() for t in ctx["tech_labels"]]
    tech_signals: set[str] = ctx["tech_signals"]
    upload_execution_evidence = _has_upload_execution_evidence(upload_like, tech_signals)
    structural_groups = _structural_exposure_groups(classified_endpoints)

    cve_hits = cve_enrichment.get("matches", []) if isinstance(cve_enrichment, dict) else []
    top_cves: list[str] = []
    for match_group in cve_hits[:5]:
        for cve in (match_group.get("cves", []) or [])[:2]:
            cve_id = str(cve.get("cve_id") or "").strip()
            if cve_id and cve_id not in top_cves:
                top_cves.append(cve_id)

    suggestions: list[dict[str, Any]] = []
    seen_suggestions: set[str] = set()

    def _add_suggestion(
        title: str,
        priority: int,
        surface: str,
        why: str,
        tests: list[str],
        evidence: list[str],
        nuclei_families: list[str] | None = None,
        *,
        contributing_signals: list[str] | None = None,
        matched_endpoints: list[str] | None = None,
        matched_technologies: list[str] | None = None,
        matched_cves: list[str] | None = None,
    ) -> None:
        dedup_key = f"{surface.strip().lower()}::{title.strip().lower()}"
        if dedup_key in seen_suggestions:
            return
        seen_suggestions.add(dedup_key)
        suggestions.append(
            {
                "title": title,
                "priority": max(0, min(100, int(priority))),
                "surface": surface,
                "why": why,
                "tests": tests,
                "evidence": evidence,
                "nuclei_template_families": nuclei_families or [],
                "resolved_nuclei": _resolve_nuclei_template_families(nuclei_families or []),
                "contributing_signals": contributing_signals or [],
                "matched_endpoints": matched_endpoints or [],
                "matched_technologies": matched_technologies or [],
                "matched_cves": matched_cves or [],
            }
        )

    if upload_like:
        tests = [
            "public upload/listing exposure review",
            "manual validation for upload abuse",
            "check executable handling",
            "path traversal via upload/download handling",
        ]
        evidence = [f"upload endpoints={len(upload_like)}"]
        signals = [f"upload_endpoints={len(upload_like)} → base 62"]
        matched_tech: list[str] = []
        priority = 62
        if upload_execution_evidence:
            priority += 20
            evidence.append("dangerous/executable upload signal")
            signals.append("upload_execution_evidence → +20")
            tests.extend(["dangerous extension exposure review", "uploaded executable accessibility check"])
        if upload_execution_evidence and "php" in tech_signals:
            priority += 8
            tests.extend([".php payload upload", ".phtml/.phar variant denemeleri"])
            evidence.append("php stack")
            signals.append("php_stack → +8")
            matched_tech.append("php")
        if upload_execution_evidence and "apache" in tech_signals:
            priority += 5
            tests.append(".htaccess abuse / handler confusion")
            evidence.append("apache stack")
            signals.append("apache_stack → +5")
            matched_tech.append("apache")
        if top_cves:
            evidence.append(f"cve hints={', '.join(top_cves[:3])}")
            signals.append(f"cve_hints={len(top_cves[:3])}")
        signals.append(f"total → {min(100, priority)}")
        why_parts = [f"{len(upload_like)} upload endpoint bulundu"]
        if upload_execution_evidence and "php" in tech_signals:
            why_parts.append("PHP stack tespit edildi")
        if upload_execution_evidence and "apache" in tech_signals:
            why_parts.append("Apache stack tespit edildi")
        if top_cves:
            why_parts.append(f"ilgili CVE ipuçları görüldü ({', '.join(top_cves[:2])})")
        why_text = ", ".join(why_parts) + ". RCE doğrulanmış değildir; public upload/listing exposure ve executable handling manuel doğrulanmalıdır."
        _add_suggestion(
            "Upload Validation Suggestions" if not upload_execution_evidence else "Upload Execution Validation Suggestions",
            priority,
            "Upload",
            why_text,
            sorted(set(tests)),
            evidence,
            nuclei_families=[
                "file-upload",
                "lfi",
                "misconfiguration",
            ],
            contributing_signals=signals,
            matched_endpoints=upload_like[:10],
            matched_technologies=matched_tech,
            matched_cves=top_cves[:3],
        )

    if auth_like or admin_like:
        tests = [
            "default credential checks",
            "forced browsing",
            "session fixation / session reuse",
            "role / access control matrix testing",
            "password reset workflow analysis",
        ]
        evidence = []
        signals = ["base → 68"]
        matched_tech: list[str] = []
        priority = 68
        if auth_like:
            evidence.append(f"auth endpoints={len(auth_like)}")
            priority += 6
            signals.append(f"auth_endpoints={len(auth_like)} → +6")
        if admin_like:
            evidence.append(f"admin panels={len(admin_like)}")
            priority += 8
            signals.append(f"admin_panels={len(admin_like)} → +8")
        if "phpmyadmin" in tech_signals:
            evidence.append("phpmyadmin signal")
            priority += 10
            signals.append("phpmyadmin → +10")
            matched_tech.append("phpmyadmin")
            tests.extend([
                "phpMyAdmin exposure review",
                "phpMyAdmin default credential checks",
            ])
        if "wordpress" in tech_signals:
            evidence.append("wordpress signal")
            priority += 8
            signals.append("wordpress → +8")
            matched_tech.append("wordpress")
            tests.extend([
                "wp-login / xmlrpc review",
                "WordPress plugin/theme enumeration",
            ])
        if top_cves:
            evidence.append(f"cve hints={', '.join(top_cves[:2])}")
            signals.append(f"cve_hints={len(top_cves[:2])}")
        signals.append(f"total → {min(100, priority)}")
        why_parts = []
        if auth_like:
            why_parts.append(f"{len(auth_like)} auth endpoint bulundu")
        if admin_like:
            why_parts.append(f"{len(admin_like)} admin panel bulundu")
        if "phpmyadmin" in tech_signals:
            why_parts.append("phpMyAdmin sinyali tespit edildi")
        if "wordpress" in tech_signals:
            why_parts.append("WordPress sinyali tespit edildi")
        if top_cves:
            why_parts.append(f"ilgili CVE ipuçları görüldü ({', '.join(top_cves[:2])})")
        why_text = ", ".join(why_parts) + ". Bu yüzden access control, default credential ve workflow/bypass testleri öne çıktı."
        _add_suggestion(
            "Auth / Admin Abuse Suggestions",
            priority,
            "Auth/Admin",
            why_text,
            tests,
            evidence,
            nuclei_families=[
                "default-login",
                "auth-bypass",
                "misconfiguration",
            ],
            contributing_signals=signals,
            matched_endpoints=(auth_like[:5] + admin_like[:5]),
            matched_technologies=matched_tech,
            matched_cves=top_cves[:3],
        )

    if docs_like or api_like:
        ordinary_docs_only = _ordinary_public_docs_only(api_like, docs_like, tech_signals)
        tests = [
            "public documentation review",
            "manual review for internal API routes",
            "manual review for secrets/config/debug terms",
        ]
        evidence = []
        signals = ["base → 38" if ordinary_docs_only else "base → 56"]
        matched_tech: list[str] = []
        priority = 38 if ordinary_docs_only else 56
        if api_like:
            evidence.append(f"api endpoints={len(api_like)}")
            priority += 10
            signals.append(f"api_endpoints={len(api_like)} → +10")
            tests.extend(["object-level authorization checks", "excessive data exposure review"])
        if docs_like:
            evidence.append(f"docs pages={len(docs_like)}")
            docs_delta = 2 if ordinary_docs_only else 6
            priority += docs_delta
            signals.append(f"docs_pages={len(docs_like)} → +{docs_delta}")
        if "openapi" in tech_signals:
            tests.append("openapi / swagger schema review")
            evidence.append("openapi/swagger signal")
            priority += 10
            signals.append("openapi → +10")
            matched_tech.append("openapi")
        if "graphql" in tech_signals:
            matched_tech.append("graphql")
        signals.append(f"total → {min(100, priority)}")
        why_parts = []
        if api_like:
            why_parts.append(f"{len(api_like)} API endpoint bulundu")
        if docs_like:
            why_parts.append(f"{len(docs_like)} docs/dev sayfası bulundu")
        if "graphql" in tech_signals:
            why_parts.append("GraphQL sinyali tespit edildi")
        if "openapi" in tech_signals:
            why_parts.append("OpenAPI / Swagger sinyali tespit edildi")
        why_text = (
            ", ".join(why_parts) + ". Public docs/help/resource yüzeyi normal SaaS içeriği olabilir; direct exposure claim yerine manuel inceleme gerekir."
            if ordinary_docs_only
            else ", ".join(why_parts) + ". Bu yüzden endpoint harvesting, exposure sinyali ve authorization testleri manuel doğrulama için öne çıktı."
        )
        _add_suggestion(
            "Public Documentation Manual Review" if ordinary_docs_only else "API / Docs Enumeration Suggestions",
            priority,
            "API/Docs",
            why_text,
            sorted(set(tests)),
            evidence,
            nuclei_families=[
                "exposures",
                "misconfiguration",
                "api",
            ],
            contributing_signals=signals,
            matched_endpoints=(api_like[:5] + docs_like[:5]),
            matched_technologies=matched_tech,
            matched_cves=top_cves[:2],
        )

    structural_suggestion_specs = (
        ("source_control", "Source Control Exposure Manual Validation", 94, "Source Control", "Repository metadata exposure signal detected; confirm leaked remotes/config/history and block public .git access."),
        ("config", "Config Exposure Manual Validation", 90, "Config/Env", "Secret/config exposure pattern detected; manual validation required."),
        ("backup", "Backup/Dump Exposure Manual Validation", 88, "Backup", "Backup/dump exposure signal detected; manual validation required."),
        ("logs", "Logs Exposure Manual Validation", 86, "Logs", "Public logs/error exposure signal detected; manual validation required."),
        ("debug_console", "Debug Console Manual Validation", 87, "Debug/Test", "Debug console exposure signal detected; manual validation required."),
        ("runtime", "Runtime Disclosure Manual Validation", 82, "Runtime", "Runtime/phpinfo/server-status disclosure signal detected; manual validation required."),
        ("internal_api", "Internal API Manual Validation", 87, "Internal API", "Internal users/status/build/version API signal detected; manual validation required."),
        ("admin_export", "Admin Export Manual Validation", 85, "Admin Export", "Admin export/download surface signal detected; manual validation required."),
    )
    for group_key, title, priority, surface, why_text in structural_suggestion_specs:
        urls = structural_groups.get(group_key, [])
        if not urls:
            continue
        _add_suggestion(
            title,
            priority,
            surface,
            why_text + " Not a confirmed vulnerability.",
            [
                "manual validation required",
                "confirm response body and authentication requirements",
                "preserve demo/fake markers in impact wording",
            ],
            [f"{group_key} endpoints={len(urls)}", "structural exposure signal", "no direct Nuclei evidence"],
            nuclei_families=["exposures", "config", "misconfiguration"],
            contributing_signals=[f"{group_key}_endpoints={len(urls)}", f"fixed → {priority}"],
            matched_endpoints=urls[:10],
            matched_technologies=[],
            matched_cves=[],
        )

    if debug_like:
        tests = [
            "verbose error triggering",
            "env/config disclosure review",
            "hidden parameters and debug flags",
            "internal/test route abuse",
        ]
        evidence = [f"debug/test endpoints={len(debug_like)}"]
        signals = [f"debug_endpoints={len(debug_like)} → base 74"]
        matched_tech: list[str] = []
        priority = 74
        debug_frameworks = [t for t in ["django", "laravel", "aspnet"] if t in tech_signals]
        if debug_frameworks:
            evidence.append("framework with debug sensitivity")
            priority += 6
            signals.append(f"debug_framework ({', '.join(debug_frameworks)}) → +6")
            matched_tech.extend(debug_frameworks)
        signals.append(f"total → {min(100, priority)}")
        why_parts = [f"{len(debug_like)} debug/test endpoint bulundu"]
        if debug_frameworks:
            why_parts.append("debug duyarlılığı yüksek framework sinyali görüldü")
        why_text = ", ".join(why_parts) + ". Bu yüzden config/env disclosure ve verbose error tetikleme testleri öne çıktı."
        _add_suggestion(
            "Debug / Config Leak Suggestions",
            priority,
            "Debug/Test",
            why_text,
            tests,
            evidence,
            nuclei_families=[
                "exposures",
                "config",
                "misconfiguration",
            ],
            contributing_signals=signals,
            matched_endpoints=debug_like[:10],
            matched_technologies=matched_tech,
            matched_cves=[],
        )

    chain_names = [str(c.get("name") or "") for c in attack_chains if isinstance(c, dict)]
    graph_paths = attack_graph.get("paths", []) if isinstance(attack_graph, dict) else []
    if chain_names or graph_paths:
        path_labels = [str(p.get("name") or "") for p in graph_paths[:3] if isinstance(p, dict)]
        evidence = [name for name in chain_names[:3] if name]
        evidence.extend([p for p in path_labels if p and p not in evidence])
        chain_signals = [f"chains={len(chain_names)}", f"graph_paths={len(graph_paths)}", "fixed → 72"]
        why_text = f"Engine {len(evidence[:5])} adet chain/path sinyali üretti ({', '.join(evidence[:3])}). Bu yüzden ilgili akışları manuel doğrulama ile teyit etmek gerekir."
        _add_suggestion(
            "Attack Path Validation Suggestions",
            72,
            "Attack Chains",
            why_text,
            [
                "chain-specific manual validation",
                "entrypoint-to-impact walkthrough",
                "pivot dependency checks",
                "false-positive elimination",
            ],
            evidence[:5],
            nuclei_families=[
                "workflows",
                "rce",
                "misconfiguration",
            ],
            contributing_signals=chain_signals,
            matched_endpoints=[],
            matched_technologies=[],
            matched_cves=[],
        )

    return sorted(suggestions, key=lambda item: int(item.get("priority", 0)), reverse=True)

def _detect_target_mode(raw_target: str) -> str:
    """Detect target mode.

    Returns one of: "domain", "ip", "url".

    Rules:
    - If input starts with http(s):// -> url
    - Else if it's a valid IPv4/IPv6 -> ip
    - Else if it looks like host:port or localhost -> url
    - Else -> domain
    """
    t = (raw_target or "").strip()
    if not t:
        return "domain"

    parts = urlsplit(t)
    if parts.scheme in ("http", "https"):
        return "url"

    # Raw IP (no scheme)
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass

    # Host:port or localhost should behave like URL mode
    if t.startswith("localhost"):
        return "url"

    # If there is a ':' it's most likely host:port (IPv6 is handled above)
    if ":" in t:
        return "url"

    # If there is a path-like component, treat as URL seed
    if "/" in t:
        return "url"

    return "domain"


def _normalize_target_url(raw_target: str, default_scheme: str = "http") -> str:
    """Ensure the target is a usable URL.

    If scheme is missing, prefixes with default_scheme://.
    """
    t = (raw_target or "").strip()
    if not t:
        return ""

    parts = urlsplit(t)
    if parts.scheme in ("http", "https"):
        return t

    # If user gave host:port or host/path, assume default_scheme
    return f"{default_scheme}://{t}"


def is_ip(value: str) -> bool:
    """Return True if value is a valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def parçalayıcı(items: list[str], size: int = 500) -> Iterator[list[str]]:
    """Yield `items` in consecutive batches of `size` (default 500)."""
    if size <= 0:
        size = 500
    n = len(items)
    for i in range(0, n, size):
        yield items[i : i + size]
        

# Katana expansion: prioritize high-signal endpoints for a second crawl pass
_EXPANSION_KEYWORDS = (
    "admin",
    "login",
    "signin",
    "sign-in",
    "auth",
    "oauth",
    "sso",
    "dashboard",
    "manage",
    "panel",
    "wp-admin",
    "phpmyadmin",
    "pma",
    "swagger",
    "openapi",
    "api",
    "graphql",
    "actuator",
)


def _is_high_value_url(u: str) -> bool:
    url_text = (u or "").lower()
    return any(keyword in url_text for keyword in _EXPANSION_KEYWORDS)
        

# Nuclei target hygiene: avoid wasting time on static assets
_ASSET_EXTENSIONS = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".pdf",
    ".zip",
    ".rar",
    ".7z",
)

_STATIC_PATH_HINTS = (
    "/assets/",
    "/static/",
    "/images/",
    "/img/",
    "/css/",
    "/js/",
)

_NUCLEI_QUERY_PRESERVE_MARKERS = (
    "page=",
    "file=",
    "path=",
    "include=",
    "template=",
    "lang=",
    "module=",
    "route=",
    "redirect=",
    "url=",
    "login",
    "signin",
    "auth",
    "timesheet",
    "cgi-bin",
    "cgiserver",
    "passwd",
)

_NUCLEI_TRAVERSAL_MARKERS = (
    "../",
    "..\\",
    "..%2f",
    "..%5c",
    "%2e%2e%2f",
    "%2e%2e%5c",
    "..%252f",
    "..%255c",
    "%252e%252e%252f",
    "%252e%252e%255c",
    "/etc/passwd",
    "etc/passwd",
    "etc%2fpasswd",
    "etc%252fpasswd",
    "boot.ini",
    "win.ini",
    "proc/self/environ",
)

_NUCLEI_HIGH_VALUE_PATH_MARKERS = (
    "cgi-bin",
    "cgiserver",
    "timesheet",
    "login",
    "signin",
    "auth",
    "passwd",
)


def _is_lfi_or_traversal_like(text: str) -> bool:
    low = (text or "").lower()
    if not low:
        return False
    return any(marker in low for marker in _NUCLEI_TRAVERSAL_MARKERS)


def _should_preserve_query_for_nuclei(path: str, query: str) -> bool:
    """Return True when query appears high-value for nuclei targeting."""
    q = (query or "").lower()
    if not q:
        return False

    combined = f"{(path or '').lower()}?{q}"
    if _is_lfi_or_traversal_like(combined):
        return True
    return any(marker in q for marker in _NUCLEI_QUERY_PRESERVE_MARKERS)


def _is_high_value_nuclei_candidate(u: str) -> bool:
    """Heuristic high-value URL detector for nuclei prioritization."""
    value = (u or "").strip()
    if not value:
        return False

    parts = urlsplit(value)
    path = (parts.path or "").lower()
    query = parts.query or ""
    low = value.lower()

    if _should_preserve_query_for_nuclei(path, query):
        return True
    if _is_lfi_or_traversal_like(low):
        return True
    return any(marker in path for marker in _NUCLEI_HIGH_VALUE_PATH_MARKERS)


def _normalize_for_nuclei(
    u: str,
    drop_query: bool = True,
    *,
    preserve_high_value_query: bool = False,
) -> str:
    """Normalize URL for nuclei targets.

    - Drops fragment always.
    - Optionally drops query (default True) to reduce target explosion.
    - Can preserve query for high-value suspicious patterns.
    """
    url_text = (u or "").strip()
    if not url_text:
        return ""

    parts = urlsplit(url_text)
    scheme = parts.scheme
    netloc = parts.netloc
    path = parts.path or "/"

    preserve_query = (
        not drop_query
        or (
            preserve_high_value_query
            and _should_preserve_query_for_nuclei(path, parts.query or "")
        )
    )
    # Always drop fragment; optionally drop query
    query = (parts.query or "") if preserve_query else ""

    return urlunsplit((scheme, netloc, path, query, ""))


def _is_static_asset(u: str) -> bool:
    """Return True if URL looks like a static asset (likely low-value for nuclei)."""
    try:
        parts = urlsplit(u)
        path = (parts.path or "").lower()
    except Exception:
        path = (u or "").lower()

    if any(h in path for h in _STATIC_PATH_HINTS):
        return True

    return path.endswith(_ASSET_EXTENSIONS)


# --- JSON output helpers ---


def _resolve_output_base_dir(config_output_dir: str | None) -> Path:
    """Return the base output directory.

    If `config_output_dir` is provided, use it as the base. If it points to a
    `.../latest` folder, treat its parent as the base.

    Default base is `reconbot/output`.
    """
    project_dir = Path(__file__).resolve().parent.parent  # reconbot/

    if config_output_dir:
        p = Path(config_output_dir).expanduser()
        # If user points directly to .../latest, normalize to its parent.
        if p.name == "latest":
            return p.parent
        return p

    return project_dir / "output"


def _ensure_output_dirs(config_output_dir: str | None, run_id: str) -> tuple[Path, Path]:
    """Create output folders and return (run_dir, latest_dir).

    When config_output_dir is set, it is an explicit run directory owned by the
    caller. The engine must not add another runs/<timestamp> level.
    """
    if config_output_dir:
        run_dir = Path(config_output_dir).expanduser().resolve()
        if run_dir.parent.name == "runs":
            latest_dir = run_dir.parent.parent / "latest"
        else:
            latest_dir = run_dir.parent / "latest"
    else:
        base_dir = _resolve_output_base_dir(None)
        runs_dir = base_dir / "runs"
        run_dir = runs_dir / run_id
        latest_dir = base_dir / "latest"

    run_dir.mkdir(parents=True, exist_ok=True)
    latest_dir.mkdir(parents=True, exist_ok=True)
    return run_dir, latest_dir


# --- Stage helpers and artifact helpers ---

def _now_iso() -> str:
    """UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _artifact_ref(path: Path | None) -> str | None:
    return str(path) if path else None

def _coerce_absolute_http_url(value: str, base_url: str | None = None) -> str:
    """Return a browser-clickable absolute HTTP(S) URL when possible."""
    raw = (value or "").strip()
    if not raw:
        return ""

    low = raw.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return raw

    if low.startswith("javascript:") or low.startswith("data:"):
        return raw

    if base_url:
        try:
            base = _normalize_target_url(base_url)
            base_parts = urlsplit(base)
            if base_parts.scheme in ("http", "https") and base_parts.netloc:
                if raw.startswith("//"):
                    return f"{base_parts.scheme}:{raw}"
                if raw.startswith("/"):
                    return urlunsplit((base_parts.scheme, base_parts.netloc, raw, "", ""))
                return urlunsplit((base_parts.scheme, base_parts.netloc, f"/{raw.lstrip('/')}", "", ""))
        except Exception:
            pass

    return raw


def _prepare_clickable_urls(urls: list[str] | None, base_url: str | None = None, limit: int | None = None) -> list[str]:
    prepared: list[str] = []
    seen: set[str] = set()

    for item in urls or []:
        absolute = _coerce_absolute_http_url(str(item or "").strip(), base_url=base_url)
        if not absolute:
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        prepared.append(absolute)
        if limit is not None and len(prepared) >= limit:
            break

    return prepared

def _init_stage_state() -> dict[str, dict[str, Any]]:
    names = [
        "nmap",
        "subfinder",
        "dnsx",
        "httpx",
        "katana",
        "gobuster",
        "ffuf",
        "historical_urls",
        "screenshots",
        "wafw00f",
        "whatweb",
        "checks",
        "nuclei",
    ]
    return {
        name: {
            "status": "pending",
            "started_at": None,
            "ended_at": None,
            "artifacts": {},
        }
        for name in names
    }


_LIVE_STAGE_STATE_PATH: Path | None = None


def _write_live_stage_state(stages: dict[str, dict[str, Any]]) -> None:
    if _LIVE_STAGE_STATE_PATH is None:
        return
    try:
        atomic_json(_LIVE_STAGE_STATE_PATH, _json_safe_value(stages or {}))
    except Exception:
        pass


def _stage_set_running(stages: dict[str, dict[str, Any]], name: str, **extra: Any) -> None:
    stage = stages.setdefault(name, {"status": "pending", "started_at": None, "ended_at": None, "artifacts": {}})
    stage["status"] = "running"
    stage["started_at"] = stage.get("started_at") or _now_iso()
    stage["ended_at"] = None
    if extra:
        stage.update(extra)
    _write_live_stage_state(stages)


def _stage_finish(
    stages: dict[str, dict[str, Any]],
    name: str,
    status: str,
    *,
    artifacts: dict[str, Any] | None = None,
    **extra: Any,
) -> None:
    stage = stages.setdefault(name, {"status": "pending", "started_at": None, "ended_at": None, "artifacts": {}})
    if stage.get("started_at") is None:
        stage["started_at"] = _now_iso()
    stage["status"] = status
    stage["ended_at"] = _now_iso()
    if artifacts:
        merged = dict(stage.get("artifacts") or {})
        merged.update(artifacts)
        stage["artifacts"] = merged
    if extra:
        stage.update(extra)
    _write_live_stage_state(stages)


def _write_text_artifact(path: Path, content: str) -> None:
    path.write_text(content or "", encoding="utf-8")


def _write_json_artifact(path: Path, data: Any) -> None:
    atomic_json(path, _json_safe_value(data))


def _resolve_traffic_profile(
    profile_name: str,
    explicit_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve high-level traffic profile via centralized runtime registry."""
    return resolve_runtime_traffic_profile(profile_name, explicit_overrides=explicit_overrides)


# --- Traffic state helpers ---

def _make_traffic_state(requested_profile: str, resolved_profile: dict[str, Any]) -> dict[str, Any]:
    profile = (requested_profile or "balanced").strip().lower() or "balanced"
    return {
        "requested_profile": profile,
        "effective_profile": profile,
        "risk_level": str(resolved_profile.get("risk_level") or "unknown"),
        "auto_throttle_applied": False,
        "auto_throttle_events": [],
        "recommended_profile": profile,
    }


def _record_auto_throttle(
    traffic_state: dict[str, Any],
    *,
    stage: str,
    from_profile: str,
    to_profile: str,
    reason: str,
) -> None:
    traffic_state["auto_throttle_applied"] = True
    traffic_state["effective_profile"] = to_profile
    traffic_state.setdefault("auto_throttle_events", []).append(
        {
            "stage": stage,
            "from_profile": from_profile,
            "to_profile": to_profile,
            "reason": reason,
        }
    )
    
def _apply_adaptive_recon(
    *,
    requested_profile: str,
    current_effective_profile: str,
    base_checks_traffic: dict[str, Any],
    wafw00f_results: dict[str, Any] | None,
    traffic_state: dict[str, Any],
) -> dict[str, Any]:
    """Apply simple WAF-aware adaptive recon decisions.

    Current scope:
    - if a WAF/CDN signal exists, downgrade the post-WAF traffic profile for lightweight web checks
    - store advisory data in traffic_state so report/GUI can explain decisions
    """
    wafw00f_results = wafw00f_results or {}
    effective_checks_traffic = dict(base_checks_traffic or {})

    detected_vendors: list[str] = []
    for item in wafw00f_results.values():
        if not isinstance(item, dict):
            continue
        if item.get("detected") and item.get("vendor"):
            vendor = str(item.get("vendor") or "").strip()
            if vendor and vendor not in detected_vendors:
                detected_vendors.append(vendor)

    adaptive_summary: dict[str, Any] = {
        "active": False,
        "mode": "standard",
        "reason": None,
        "waf_detected_count": len(detected_vendors),
        "waf_vendors": detected_vendors,
        "effective_profile": current_effective_profile,
        "effective_checks": effective_checks_traffic,
        "nuclei_advice": {
            "suggested_rate_limit": 2 if current_effective_profile != "safe" else 1,
            "note": "standard traffic assumptions",
        },
    }

    if not detected_vendors:
        traffic_state["adaptive_recon"] = adaptive_summary
        traffic_state["recommended_profile"] = current_effective_profile
        return adaptive_summary

    target_profile = current_effective_profile
    if current_effective_profile == "fast":
        target_profile = "balanced"
    elif current_effective_profile == "balanced":
        target_profile = "safe"
    else:
        target_profile = "safe"

    if target_profile != current_effective_profile:
        resolved = _resolve_traffic_profile(target_profile)
        effective_checks_traffic = dict(resolved["web_checks"])
        _record_auto_throttle(
            traffic_state,
            stage="post_waf_checks",
            from_profile=current_effective_profile,
            to_profile=target_profile,
            reason=f"WAF/CDN signal detected ({', '.join(detected_vendors[:3])})",
        )

    adaptive_summary = {
        "active": True,
        "mode": "waf-aware",
        "reason": f"WAF/CDN signal detected ({', '.join(detected_vendors[:3])})",
        "waf_detected_count": len(detected_vendors),
        "waf_vendors": detected_vendors,
        "effective_profile": target_profile,
        "effective_checks": effective_checks_traffic,
        "nuclei_advice": {
            "suggested_rate_limit": 1 if target_profile == "safe" else 2,
            "note": "WAF/CDN signal nedeniyle nuclei tarafında daha kontrollü rate-limit önerilir",
        },
    }
    traffic_state["adaptive_recon"] = adaptive_summary
    traffic_state["recommended_profile"] = target_profile
    return adaptive_summary


def _summarize_gobuster(gobuster_results: dict) -> dict:
    """Create a lightweight summary for gobuster results."""
    base_url_count = len(gobuster_results or {})
    total_hits = 0
    status_counts: dict[int, int] = {}

    for results in (gobuster_results or {}).values():
        if not results:
            continue
        total_hits += len(results)
        for item in results:
            try:
                s = int(item.get("status", 0))
            except Exception:
                s = 0
            status_counts[s] = status_counts.get(s, 0) + 1

    # Sort status codes for stable output
    status_counts_sorted = {k: status_counts[k] for k in sorted(status_counts)}

    return {
        "base_url_count": base_url_count,
        "total_hits": total_hits,
        "status_counts": status_counts_sorted,
    }


def _summarize_ffuf(ffuf_results: dict[str, list[dict[str, Any]]] | None) -> dict[str, Any]:
    ffuf_results = ffuf_results or {}
    base_url_count = len(ffuf_results)
    total_hits = 0
    status_counts: dict[int, int] = {}
    for hits in ffuf_results.values():
        if not isinstance(hits, list):
            continue
        total_hits += len(hits)
        for item in hits:
            if not isinstance(item, dict):
                continue
            try:
                status_code = int(item.get("status", 0) or 0)
            except Exception:
                status_code = 0
            status_counts[status_code] = status_counts.get(status_code, 0) + 1
    return {
        "base_url_count": base_url_count,
        "total_hits": total_hits,
        "status_counts": {k: status_counts[k] for k in sorted(status_counts)},
    }


def _write_run_json(
    *,
    target: str,
    mode: str,
    skipped_tools: list[str],
    nmap_output: str,
    gobuster_results: dict,
    ffuf_results: dict | None,
    katana_urls: list[str],
    checks_results: dict,
    nuclei_targets_count: int,
    nuclei_output_path: Path | None,
    nuclei_running: bool,
    run_dir: Path,
    latest_dir: Path,
    run_id: str,
    stages: dict[str, dict[str, Any]] | None = None,
    traffic_state: dict[str, Any] | None = None,
) -> Path:
    """Write a stable JSON output for this run.

    Output standard:
      - Per-run file:   <base>/runs/<run_id>/run_result.json
      - Latest pointer: <base>/latest/run_result.json
    """

    per_run_path = run_dir / "run_result.json"

    ffuf_summary = _summarize_ffuf(ffuf_results if isinstance(ffuf_results, dict) else {})
    historical_results = (checks_results or {}).get("historical_urls", {}) if isinstance(checks_results, dict) else {}
    if not isinstance(historical_results, dict):
        historical_results = {}
    screenshots_results = (checks_results or {}).get("screenshots", {}) if isinstance(checks_results, dict) else {}
    if not isinstance(screenshots_results, dict):
        screenshots_results = {}
    soft_error_filter = (checks_results or {}).get("soft_error_filter", {}) if isinstance(checks_results, dict) else {}
    if not isinstance(soft_error_filter, dict):
        soft_error_filter = {}
    candidate_validation = (checks_results or {}).get("candidate_validation", {}) if isinstance(checks_results, dict) else {}
    if not isinstance(candidate_validation, dict):
        candidate_validation = {}
    ip_enrichment = (checks_results or {}).get("ip_enrichment", {}) if isinstance(checks_results, dict) else {}
    if not isinstance(ip_enrichment, dict):
        ip_enrichment = {}
    data = {
        "meta": {
            "timestamp": run_id,
            "target": target,
            "mode": mode,
            "skipped_tools": skipped_tools or [],
        },
        "summary": {
            "katana_count": len(katana_urls or []),
            "checks_checked": int((checks_results or {}).get("checked_count", 0) or 0),
            "checks_login": len((checks_results or {}).get("login_pages", []) or []),
            "checks_captcha": len((checks_results or {}).get("captcha_pages", []) or []),
            "checks_docs": len((checks_results or {}).get("docs_pages", []) or []),
            "checks_ratelimit": len((checks_results or {}).get("rate_limit_signals", []) or []),
            "endpoint_analysis_present": bool(
                isinstance((checks_results or {}).get("endpoint_analysis"), dict)
            ),
            "endpoint_analysis_raw_discovery_count": int(
                ((checks_results or {}).get("endpoint_analysis", {}) or {}).get("raw_discovery_count", 0) or 0
            ),
            "endpoint_analysis_clustered_count": int(
                ((checks_results or {}).get("endpoint_analysis", {}) or {}).get("clustered_count", 0) or 0
            ),
            "endpoint_analysis_suppressed_noise_count": int(
                ((checks_results or {}).get("endpoint_analysis", {}) or {}).get("suppressed_noise_count", 0) or 0
            ),
            "ffuf_hits": int(ffuf_summary.get("total_hits", 0) or 0),
            "soft_error_suppressed_count": int(soft_error_filter.get("suppressed_count", 0) or 0),
            "candidate_validation_suppressed_count": int(candidate_validation.get("suppressed_count", 0) or 0),
            "historical_urls_count": len(historical_results.get("normalized_urls", []) or []),
            "historical_live_count": int(historical_results.get("live_count", 0) or 0),
            "historical_interesting_live_count": int(historical_results.get("interesting_live_count", 0) or 0),
            "screenshots_selected_count": int(screenshots_results.get("selected_count", 0) or 0),
            "screenshots_captured_count": len(
                [
                    item
                    for item in screenshots_results.get("entries", []) or []
                    if isinstance(item, dict) and str(item.get("screenshot_path") or "").strip()
                ]
            ),
            "nuclei_targets_count": int(nuclei_targets_count or 0),
            "nuclei_running": bool(nuclei_running),
        },
        "traffic": traffic_state or {},
        "ip_enrichment": ip_enrichment,
        "stages": stages or {},
        "nmap": {
            "output": nmap_output or "",
        },
        "gobuster": {
            "summary": _summarize_gobuster(gobuster_results),
            "results": gobuster_results or {},
        },
        "ffuf": {
            "summary": ffuf_summary,
            "results": ffuf_results or {},
        },
        "katana": {
            "urls": katana_urls or [],
        },
        "checks": checks_results or {},
        "historical_urls": historical_results,
        "screenshots": screenshots_results,
        "nuclei": {
            "output_path": str(nuclei_output_path) if nuclei_output_path else None,
        },
    }

    payload = json.dumps(_json_safe_value(data), ensure_ascii=False, indent=2)
    per_run_path.write_text(payload, encoding="utf-8")
    return per_run_path


def _empty_auth_profile() -> dict[str, Any]:
    """Stable empty/fallback auth profile structure for all run paths."""
    return {
        "auth_candidates": [],
        "auth_summary": {},
        "auth_flows": {},
    }

def _clone_classified_endpoints(
    classified_endpoints: dict[str, list[str]] | None,
) -> dict[str, list[str]]:
    """Return a detached copy of endpoint buckets to prevent accidental mutation."""
    cloned: dict[str, list[str]] = {}
    if not isinstance(classified_endpoints, dict):
        return cloned
    for bucket, urls in classified_endpoints.items():
        if not isinstance(bucket, str) or not isinstance(urls, list):
            continue
        cloned[bucket] = list(urls)
    return cloned


def _build_checks_results_base(
    *,
    classified_endpoints: dict[str, list[str]],
    ffuf_results: dict[str, list[dict[str, Any]]],
    endpoint_analysis_dict: dict[str, Any],
    wafw00f_results: dict[str, Any],
    whatweb_results: dict[str, Any],
    traffic_state: dict[str, Any],
    technology_fingerprint: list[dict[str, Any]] | None = None,
    attack_chains: list[dict[str, Any]] | None = None,
    attack_graph: dict[str, Any] | None = None,
    exploit_suggestions: list[dict[str, Any]] | None = None,
    node_relationships: list[dict[str, Any]] | None = None,
    auth_profile: dict[str, Any] | None = None,
    checks_signal_payload: dict[str, Any] | None = None,
    blocked_structural_candidates: list[str] | None = None,
    soft_error_filter: dict[str, Any] | None = None,
    candidate_validation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Common checks_results structure shared across success/error/skipped paths."""
    tech_fp: list[dict[str, Any]] = []
    if isinstance(technology_fingerprint, list):
        tech_fp = list(technology_fingerprint)
    checks_signal_payload = checks_signal_payload if isinstance(checks_signal_payload, dict) else {}

    base: dict[str, Any] = {
        "classified_endpoints": _clone_classified_endpoints(classified_endpoints),
        "ffuf_findings": ffuf_results,
        "ffuf_summary": _summarize_ffuf(ffuf_results),
        "endpoint_analysis": endpoint_analysis_dict,
        "cluster_insights": endpoint_analysis_dict.get("cluster_insights", []),
        "reportworthy_endpoints": endpoint_analysis_dict.get("reportworthy_endpoints_by_bucket", {}),
        "suspicious_families": endpoint_analysis_dict.get("suspicious_families", []),
        "duplicate_families": endpoint_analysis_dict.get("duplicate_families", []),
        "katana_cleaned_urls": endpoint_analysis_dict.get("katana_cleaned_urls", []),
        "attack_chains": attack_chains or [],
        "attack_graph": attack_graph or {},
        "exploit_suggestions": exploit_suggestions or [],
        "node_relationships": node_relationships or [],
        "waf_signals": wafw00f_results,
        "whatweb_signals": whatweb_results,
        "adaptive_recon": (traffic_state or {}).get("adaptive_recon", {}),
        "technology_fingerprint": tech_fp,
        "auth_profile": auth_profile or _empty_auth_profile(),
        "blocked_structural_candidates": sorted(set(blocked_structural_candidates or [])),
        "soft_error_filter": soft_error_filter if isinstance(soft_error_filter, dict) else {"suppressed_count": 0, "suppressed": [], "baselines": {}},
        "candidate_validation": candidate_validation if isinstance(candidate_validation, dict) else {"records": [], "confirmed_urls": [], "suppressed": [], "suppressed_count": 0, "by_status": {}},
    }
    base["checked_count"] = int(checks_signal_payload.get("checked_count", 0) or 0)
    base["errors"] = checks_signal_payload.get("errors", []) if isinstance(checks_signal_payload.get("errors"), list) else []
    base["login_pages"] = checks_signal_payload.get("login_pages", []) if isinstance(checks_signal_payload.get("login_pages"), list) else []
    base["captcha_pages"] = checks_signal_payload.get("captcha_pages", []) if isinstance(checks_signal_payload.get("captcha_pages"), list) else []
    base["docs_pages"] = checks_signal_payload.get("docs_pages", []) if isinstance(checks_signal_payload.get("docs_pages"), list) else []
    base["rate_limit_signals"] = checks_signal_payload.get("rate_limit_signals", []) if isinstance(checks_signal_payload.get("rate_limit_signals"), list) else []
    base["captcha_coverage"] = checks_signal_payload.get("captcha_coverage", []) if isinstance(checks_signal_payload.get("captcha_coverage"), list) else []
    base["captcha_risk_notes"] = checks_signal_payload.get("captcha_risk_notes", []) if isinstance(checks_signal_payload.get("captcha_risk_notes"), list) else []
    base["throttle"] = checks_signal_payload.get("throttle", {}) if isinstance(checks_signal_payload.get("throttle"), dict) else {}

    base["waf_detected_count"] = sum(
        1
        for item in wafw00f_results.values()
        if isinstance(item, dict) and bool(item.get("detected"))
    )

    return _json_safe_value(base)


def _augment_attack_graph_with_auth_profile(
    attack_graph: dict[str, Any],
    auth_profile: dict[str, Any],
) -> dict[str, Any]:
    """Conservatively add auth-related nodes/edges without spamming."""
    if not isinstance(attack_graph, dict):
        return attack_graph
    if not isinstance(auth_profile, dict):
        return attack_graph

    nodes = attack_graph.get("nodes", [])
    edges = attack_graph.get("edges", [])
    paths = attack_graph.get("paths", [])
    if not isinstance(nodes, list) or not isinstance(edges, list) or not isinstance(paths, list):
        return attack_graph

    def _has_node(node_id: str) -> bool:
        return any(isinstance(n, dict) and str(n.get("id") or "") == node_id for n in nodes)

    def _add_node(node_id: str, label: str, node_type: str, count: int = 0, details: list[str] | None = None) -> None:
        if _has_node(node_id):
            return
        nodes.append(
            {
                "id": node_id,
                "label": label,
                "type": node_type,
                "count": int(count or 0),
                "details": details or [],
            }
        )

    def _add_edge(src: str, dst: str, reason: str, confidence: int) -> None:
        if any(isinstance(e, dict) and e.get("from") == src and e.get("to") == dst for e in edges):
            return
        edges.append(
            {
                "from": src,
                "to": dst,
                "reason": reason,
                "confidence": max(0, min(100, int(confidence))),
            }
        )

    summary = auth_profile.get("auth_summary", {}) if isinstance(auth_profile.get("auth_summary"), dict) else {}
    flows = auth_profile.get("auth_flows", {}) if isinstance(auth_profile.get("auth_flows"), dict) else {}

    def _flow_urls(flow_key: str, limit: int = 6) -> list[str]:
        items = flows.get(flow_key) or []
        out: list[str] = []
        if not isinstance(items, list):
            return out
        for it in items[:limit]:
            if isinstance(it, dict):
                u = str(it.get("url") or it.get("from") or "").strip()
                if u:
                    out.append(u)
        return out

    login_forms = int(summary.get("login_form_count", 0) or 0)
    reset_hints = int(summary.get("candidates_with_reset", 0) or 0)
    register_hints = int(summary.get("candidates_with_register", 0) or 0)
    logout_hints = int(summary.get("candidates_with_logout", 0) or 0)
    xmlrpc = int(summary.get("xmlrpc_count", 0) or 0)
    oauth_sso = int(summary.get("oauth_sso_count", 0) or 0)
    with_captcha = int(summary.get("candidates_with_captcha", 0) or 0)
    with_csrf = int(summary.get("candidates_with_csrf", 0) or 0)
    with_rate = int(summary.get("candidates_with_rate_limit_hints", 0) or 0)
    with_lockout = int(summary.get("candidates_with_lockout_hints", 0) or 0)

    if login_forms > 0:
        _add_node("auth_login_flow", "Login Flow", "surface", login_forms, _flow_urls("login"))
        _add_edge("auth", "auth_login_flow", "Auth profiler: login forms detected", 74)
        if reset_hints > 0:
            _add_node("auth_reset_flow", "Password Reset Flow", "surface", reset_hints, _flow_urls("reset"))
            _add_edge("auth_login_flow", "auth_reset_flow", "Reset flow hints present", 62)
        if register_hints > 0:
            _add_node("auth_register_surface", "Registration Surface", "surface", register_hints, _flow_urls("register"))
            _add_edge("auth_login_flow", "auth_register_surface", "Register hints present", 56)
        if logout_hints > 0:
            _add_node("auth_logout_surface", "Logout Surface", "surface", logout_hints, _flow_urls("logout"))
            _add_edge("auth_login_flow", "auth_logout_surface", "Logout hints present", 48)

    if xmlrpc > 0:
        _add_node("xmlrpc_auth_channel", "XML-RPC Auth Channel", "surface", xmlrpc, _flow_urls("xmlrpc"))
        _add_edge("auth", "xmlrpc_auth_channel", "Auth profiler: XML-RPC hints", 70)
    if oauth_sso > 0:
        _add_node("oauth_sso_entry", "OAuth/SSO Entry", "surface", oauth_sso, _flow_urls("oauth_sso"))
        _add_edge("auth", "oauth_sso_entry", "Auth profiler: OAuth/SSO hints", 66)

    admin_redirects = flows.get("admin_to_login_redirect") or []
    if isinstance(admin_redirects, list) and admin_redirects:
        details: list[str] = []
        for it in admin_redirects[:6]:
            if isinstance(it, dict):
                frm = str(it.get("from") or "").strip()
                to = str(it.get("to") or "").strip()
                if frm and to:
                    details.append(f"{frm} -> {to}")
        _add_node("admin_to_login_redirect", "Admin → Login Redirect", "surface", len(admin_redirects), details)
        _add_edge("admin", "admin_to_login_redirect", "Admin redirects to auth surface", 68)
        _add_edge("admin_to_login_redirect", "auth", "Auth gate suspected", 62)

    # Weak hardening (single outcome node)
    weak_notes: list[str] = []
    if login_forms > 0 and with_captcha == 0:
        weak_notes.append("captcha not observed on auth surface")
    if login_forms > 0 and with_csrf == 0:
        weak_notes.append("csrf token hint not observed")
    if login_forms > 0 and with_rate == 0 and with_lockout == 0:
        weak_notes.append("rate-limit/lockout hints not observed")
    if weak_notes:
        _add_node("weak_auth_hardening", "Weak Auth Hardening Signals", "outcome", len(weak_notes), weak_notes)
        if login_forms > 0:
            _add_edge("auth_login_flow", "weak_auth_hardening", "Hardening may be weak; verify controls", 64)
        else:
            _add_edge("auth", "weak_auth_hardening", "Hardening may be weak; verify controls", 52)

    attack_graph["nodes"] = nodes
    attack_graph["edges"] = edges
    attack_graph["paths"] = paths
    return attack_graph


def _augment_exploit_suggestions_with_auth_profile(
    suggestions: list[dict[str, Any]],
    auth_profile: dict[str, Any],
) -> list[dict[str, Any]]:
    """Add review-oriented auth suggestions (no brute force)."""
    if not isinstance(suggestions, list):
        suggestions = []
    if not isinstance(auth_profile, dict):
        return suggestions

    existing_titles = {str(s.get("title") or "").strip().lower() for s in suggestions if isinstance(s, dict)}
    summary = auth_profile.get("auth_summary", {}) if isinstance(auth_profile.get("auth_summary"), dict) else {}
    flows = auth_profile.get("auth_flows", {}) if isinstance(auth_profile.get("auth_flows"), dict) else {}

    login_forms = int(summary.get("login_form_count", 0) or 0)
    reset_hints = int(summary.get("candidates_with_reset", 0) or 0)
    register_hints = int(summary.get("candidates_with_register", 0) or 0)
    xmlrpc = int(summary.get("xmlrpc_count", 0) or 0)
    oauth_sso = int(summary.get("oauth_sso_count", 0) or 0)
    with_captcha = int(summary.get("candidates_with_captcha", 0) or 0)
    with_csrf = int(summary.get("candidates_with_csrf", 0) or 0)
    with_rate = int(summary.get("candidates_with_rate_limit_hints", 0) or 0)
    with_lockout = int(summary.get("candidates_with_lockout_hints", 0) or 0)

    def _sample_flow(flow_key: str, limit: int = 3) -> list[str]:
        items = flows.get(flow_key) or []
        out: list[str] = []
        if not isinstance(items, list):
            return out
        for it in items[:limit]:
            if isinstance(it, dict):
                u = str(it.get("url") or it.get("from") or "").strip()
                if u:
                    out.append(u)
        return out

    if login_forms > 0 and "login workflow review" not in existing_titles:
        signals = [f"login_forms={login_forms}"]
        if with_captcha == 0:
            signals.append("captcha_not_observed")
        if with_csrf == 0:
            signals.append("csrf_not_observed")
        if with_rate == 0 and with_lockout == 0:
            signals.append("no_rate_limit_lockout_hints")
        suggestions.append(
            {
                "title": "Login workflow review",
                "priority": 78 if (with_captcha == 0 or with_csrf == 0) else 70,
                "surface": "Authentication",
                "why": "Auth profiler login surface tespit etti. Hardening kontrollerini doğrulamak yüksek değer taşır.",
                "tests": [
                    "captcha enforcement check",
                    "rate-limit / lockout behavior check (no brute-force)",
                    "CSRF token presence and validation review",
                    "redirect safety (open redirect / return URL validation) review",
                    "session fixation and cookie flags review",
                ],
                "evidence": _sample_flow("login") or signals,
                "nuclei_template_families": [],
                "resolved_nuclei": {"families": [], "all_tags": [], "suggested_cli": ""},
                "contributing_signals": signals,
                "matched_endpoints": _sample_flow("login"),
                "matched_technologies": [],
                "matched_cves": [],
            }
        )

    if reset_hints > 0 and "password reset flow review" not in existing_titles:
        suggestions.append(
            {
                "title": "Password reset flow review",
                "priority": 72,
                "surface": "Authentication",
                "why": "Reset/forgot password akışı sinyali görüldü. Token ve user enumeration riskleri açısından incelenmeli.",
                "tests": [
                    "reset token entropy/TTL and reuse behavior review",
                    "user enumeration behavior review (error messages / timing)",
                    "rate-limit / lockout on reset endpoint review",
                    "redirect/return parameter validation review",
                ],
                "evidence": _sample_flow("reset") or [f"reset_hints={reset_hints}"],
                "nuclei_template_families": [],
                "resolved_nuclei": {"families": [], "all_tags": [], "suggested_cli": ""},
                "contributing_signals": [f"reset_hints={reset_hints}"],
                "matched_endpoints": _sample_flow("reset"),
                "matched_technologies": [],
                "matched_cves": [],
            }
        )

    if register_hints > 0 and "registration flow review" not in existing_titles:
        suggestions.append(
            {
                "title": "Registration flow review",
                "priority": 66,
                "surface": "Authentication",
                "why": "Register/signup akışı sinyali görüldü. Abuse ve account takeover riskleri açısından incelenmeli.",
                "tests": [
                    "email/phone verification enforcement review",
                    "rate-limit / anti-automation controls review (no brute-force)",
                    "weak password policy checks",
                ],
                "evidence": _sample_flow("register") or [f"register_hints={register_hints}"],
                "nuclei_template_families": [],
                "resolved_nuclei": {"families": [], "all_tags": [], "suggested_cli": ""},
                "contributing_signals": [f"register_hints={register_hints}"],
                "matched_endpoints": _sample_flow("register"),
                "matched_technologies": [],
                "matched_cves": [],
            }
        )

    if xmlrpc > 0 and "xml-rpc exposure review" not in existing_titles:
        suggestions.append(
            {
                "title": "XML-RPC exposure review",
                "priority": 74,
                "surface": "Authentication",
                "why": "XML-RPC yüzeyi görüldü. Gereksizse kapatılmalı veya sıkı şekilde kısıtlanmalı.",
                "tests": [
                    "xmlrpc endpoint access control review",
                    "rate-limit / abuse prevention review",
                    "method exposure review",
                ],
                "evidence": _sample_flow("xmlrpc") or [f"xmlrpc={xmlrpc}"],
                "nuclei_template_families": [],
                "resolved_nuclei": {"families": [], "all_tags": [], "suggested_cli": ""},
                "contributing_signals": [f"xmlrpc={xmlrpc}"],
                "matched_endpoints": _sample_flow("xmlrpc"),
                "matched_technologies": [],
                "matched_cves": [],
            }
        )

    if oauth_sso > 0 and "oauth/sso entry review" not in existing_titles:
        suggestions.append(
            {
                "title": "OAuth/SSO entry review",
                "priority": 70,
                "surface": "Authentication",
                "why": "OAuth/SSO entrypoint sinyali görüldü. redirect_uri/state doğrulaması ve token güvenliği incelenmeli.",
                "tests": [
                    "redirect_uri / return URL allowlist validation review",
                    "state/nonce validation review",
                    "token leakage via referer/logs review",
                ],
                "evidence": _sample_flow("oauth_sso") or [f"oauth_sso={oauth_sso}"],
                "nuclei_template_families": [],
                "resolved_nuclei": {"families": [], "all_tags": [], "suggested_cli": ""},
                "contributing_signals": [f"oauth_sso={oauth_sso}"],
                "matched_endpoints": _sample_flow("oauth_sso"),
                "matched_technologies": [],
                "matched_cves": [],
            }
        )

    return suggestions


def _augment_node_relationships_with_auth_profile(
    node_relationships: dict[str, Any],
    auth_profile: dict[str, Any],
) -> dict[str, Any]:
    """Inject relationships for auth-specific nodes added to the graph."""
    if not isinstance(node_relationships, dict):
        node_relationships = {}
    if not isinstance(auth_profile, dict):
        return node_relationships
    flows = auth_profile.get("auth_flows", {}) if isinstance(auth_profile.get("auth_flows"), dict) else {}
    summary = auth_profile.get("auth_summary", {}) if isinstance(auth_profile.get("auth_summary"), dict) else {}

    def _flow_endpoints(flow_key: str, limit: int = 10) -> list[str]:
        items = flows.get(flow_key) or []
        out: list[str] = []
        if not isinstance(items, list):
            return out
        for it in items[:limit]:
            if isinstance(it, dict):
                u = str(it.get("url") or it.get("from") or "").strip()
                if u:
                    out.append(u)
        return out

    def _put(node_id: str, label: str, endpoints: list[str], notes: list[str] | None = None) -> None:
        if node_id in node_relationships:
            return
        node_relationships[node_id] = {
            "node_id": node_id,
            "node_label": label,
            "related_suggestions": [],
            "related_cves": [],
            "related_nuclei_tags": [],
            "related_endpoints": endpoints,
            "related_technologies": [],
            "notes": notes or [],
        }

    if int(summary.get("login_form_count", 0) or 0) > 0:
        _put("auth_login_flow", "Login Flow", _flow_endpoints("login"))
    if int(summary.get("candidates_with_reset", 0) or 0) > 0:
        _put("auth_reset_flow", "Password Reset Flow", _flow_endpoints("reset"))
    if int(summary.get("candidates_with_register", 0) or 0) > 0:
        _put("auth_register_surface", "Registration Surface", _flow_endpoints("register"))
    if int(summary.get("candidates_with_logout", 0) or 0) > 0:
        _put("auth_logout_surface", "Logout Surface", _flow_endpoints("logout"))
    if int(summary.get("xmlrpc_count", 0) or 0) > 0:
        _put("xmlrpc_auth_channel", "XML-RPC Auth Channel", _flow_endpoints("xmlrpc"))
    if int(summary.get("oauth_sso_count", 0) or 0) > 0:
        _put("oauth_sso_entry", "OAuth/SSO Entry", _flow_endpoints("oauth_sso"))

    admin_redirects = flows.get("admin_to_login_redirect") or []
    if isinstance(admin_redirects, list) and admin_redirects:
        endpoints: list[str] = []
        notes: list[str] = []
        for it in admin_redirects[:10]:
            if isinstance(it, dict):
                frm = str(it.get("from") or "").strip()
                to = str(it.get("to") or "").strip()
                if frm:
                    endpoints.append(frm)
                if frm and to:
                    notes.append(f"{frm} -> {to}")
        _put("admin_to_login_redirect", "Admin → Login Redirect", endpoints, notes=notes)

    return node_relationships


@dataclass
class RunConfig:
    # Required
    target: str
    wordlist: str

    # Global
    verbose: bool = True
    traffic_profile: str = "balanced"
    run_mode: str = "normal_scan_only"
    scan_profile: str = "balanced"
    osint_enabled: bool = False
    osint_profile: str = "safe_mvp"
    tool_settings: dict[str, Any] | None = None

    # Tool enable/disable (control panel)
    nmap_enabled: bool = True
    subfinder_enabled: bool = True
    dnsx_enabled: bool = True
    httpx_enabled: bool = True
    katana_enabled: bool = True
    gobuster_enabled: bool = True
    ffuf_enabled: bool = False
    checks_enabled: bool = True
    nuclei_enabled: bool = True
    wafw00f_enabled: bool = True
    whatweb_enabled: bool = True

    # Network tool throttling/timing
    nmap_timing: str | None = None
    subfinder_rate_limit: int | None = None
    dnsx_rate_limit: int | None = None
    httpx_rate_limit: int | None = None

    # Batch sizes
    dnsx_batch: int = 500
    httpx_batch: int = 500

    nmap_top_ports: int = 1000
    nmap_timeout_sec: int = 120
    katana_timeout_sec: int = 120
    katana_rate_limit: int | None = None
    katana_max_urls: int = 0
    nuclei_timeout_sec: int = 10

    # Katana
    katana_depth: int = 3
    katana_js_crawl: bool = False
    katana_auto_js_crawl: bool = True

    # Katana expansion
    expansion_enabled: bool = False
    expansion_cap: int = 20
    expansion_depth: int = 2

    # Gobuster
    gobuster_threads: int | None = None
    gobuster_timeout: int = 10
    gobuster_allowed_status: list[int] | None = None
    gobuster_log_each: bool = True

    # FFUF
    ffuf_threads: int | None = None
    ffuf_rate: int | None = None
    ffuf_timeout: int = 10
    ffuf_allowed_status: list[int] | None = None
    ffuf_max_base_urls: int = 30

    # Historical URL discovery (external archives). Disabled by default.
    historical_urls_enabled: bool = False
    historical_urls_max_urls: int = 300
    historical_urls_max_domains: int | None = None
    historical_urls_live_check_limit: int = 80
    historical_urls_timeout_sec: int = 45

    # Optional visual evidence via gowitness. Disabled by default.
    screenshots_enable: bool = False
    screenshots_limit: int | None = None
    screenshots_timeout: int = 90

    # Web checks
    checks_pool_limit: int = 300
    checks_max_urls: int = 60
    checks_timeout_sec: int = 8
    checks_max_body_bytes: int = 200_000
    checks_follow_redirects: bool = True

    # Nuclei target hygiene
    nuclei_severity: str | None = None
    nuclei_rate_limit: int | None = None
    nuclei_drop_query: bool = True
    nuclei_pool_limit: int = 3000

    # Operator-controlled IP enrichment metadata.
    detailed_nmap_enabled: bool = True
    ip_enrichment: dict[str, Any] | None = None

    # Output
    output_dir: str | None = None
    report_depth: str = "balanced"


    def __post_init__(self):
        validate_scanner_settings(self)


@dataclass
class RunResult:
    nmap_output: str
    gobuster_results: dict
    katana_urls: list[str]
    checks_results: dict
    nuclei_results: dict
    nuclei_proc: subprocess.Popen | None = None
    nuclei_output_path: Path | None = None
    nuclei_log_path: Path | None = None


def run(config: RunConfig) -> RunResult:
    """CLI/GUI ortak pipeline çalıştırıcısı.

    CLI sadece config toplar ve rapor üretir. Asıl tarama sırası burada.
    """
    global _LIVE_STAGE_STATE_PATH

    target = config.target.strip()
    wordlist = config.wordlist

    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    run_dir, latest_dir = _ensure_output_dirs(config.output_dir, run_id)
    run_id = run_dir.name
    _LIVE_STAGE_STATE_PATH = run_dir / "stages_live.json"

    stages = _init_stage_state()
    _write_live_stage_state(stages)

    nmap_txt_path = run_dir / "nmap.txt"
    subfinder_txt_path = run_dir / "subfinder.txt"
    subfinder_json_path = run_dir / "subfinder.json"
    dnsx_txt_path = run_dir / "dnsx.txt"
    dnsx_json_path = run_dir / "dnsx.json"
    httpx_txt_path = run_dir / "httpx.txt"
    httpx_json_path = run_dir / "httpx.json"
    katana_txt_path = run_dir / "katana.txt"
    katana_json_path = run_dir / "katana.json"
    gobuster_json_path = run_dir / "gobuster.json"
    ffuf_json_path = run_dir / "ffuf.json"
    gau_txt_path = run_dir / "gau_urls.txt"
    wayback_txt_path = run_dir / "waybackurls.txt"
    historical_txt_path = run_dir / "historical_urls.txt"
    historical_json_path = run_dir / "historical_urls.json"
    wafw00f_json_path = run_dir / "wafw00f.json"
    whatweb_json_path = run_dir / "whatweb.json"
    checks_json_path = run_dir / "checks.json"
    targets_txt_path = run_dir / "targets.txt"
    prioritized_targets_txt_path = run_dir / "nuclei_prioritized_targets.txt"
    nuclei_candidates_debug_path = run_dir / "nuclei_candidates_debug.txt"
    nuclei_normalized_debug_path = run_dir / "nuclei_normalized_debug.txt"
    nuclei_dropped_debug_path = run_dir / "nuclei_dropped_debug.txt"
    nuclei_prioritized_debug_path = run_dir / "nuclei_prioritized_debug.txt"
    run_log_path = run_dir / "reconbot.log"

    def _append_run_log(message: str) -> None:
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with run_log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"{timestamp} {message}\n")
        except Exception:
            pass

    _append_run_log(f"[+] Run initialized: target={target} output={run_dir}")

    def log(message: str) -> None:
        """Verbose logs (can be silenced from config)."""
        _append_run_log(message)
        if config.verbose:
            print(message)

    def info(message: str) -> None:
        """Important logs that should ALWAYS be visible."""
        _append_run_log(message)
        print(message)

    # Keep output dirs available for JSON/report writers; CLI may also print them.
    # (We avoid printing them here to prevent duplicate/noisy output.)

    mode = _detect_target_mode(target)
    requested_traffic_profile = (config.traffic_profile or "balanced").strip().lower() or "balanced"
    explicit_traffic_overrides: dict[str, Any] = {
        "nmap": {"timing": config.nmap_timing},
        "katana": {"rate_limit": config.katana_rate_limit or None},
        "subfinder": {"rate_limit": config.subfinder_rate_limit},
        "dnsx": {"rate_limit": config.dnsx_rate_limit},
        "httpx": {"rate_limit": config.httpx_rate_limit},
        "gobuster": {"threads": config.gobuster_threads},
        "ffuf": {"threads": config.ffuf_threads, "rate": config.ffuf_rate},
        "historical_urls": {
            "max_urls": config.historical_urls_max_urls,
            "max_domains": config.historical_urls_max_domains,
            "live_check_limit": config.historical_urls_live_check_limit,
        },
        "screenshots": {
            "limit": config.screenshots_limit,
        },
        "nuclei": {"rate_limit": config.nuclei_rate_limit},
    }
    traffic_profile = _resolve_traffic_profile(
        requested_traffic_profile,
        explicit_overrides=explicit_traffic_overrides,
    )
    traffic_state = _make_traffic_state(requested_traffic_profile, traffic_profile)
    katana_traffic = traffic_profile["katana"]
    checks_traffic = traffic_profile["web_checks"]
    effective_checks_traffic = dict(checks_traffic)
    resolved_nmap_timing = str((traffic_profile.get("nmap") or {}).get("timing", "T3"))
    resolved_subfinder_rate_limit = int((traffic_profile.get("subfinder") or {}).get("rate_limit", 20))
    resolved_dnsx_rate_limit = int((traffic_profile.get("dnsx") or {}).get("rate_limit", 50))
    resolved_httpx_rate_limit = int((traffic_profile.get("httpx") or {}).get("rate_limit", 50))
    resolved_gobuster_threads = int((traffic_profile.get("gobuster") or {}).get("threads", 20))
    resolved_ffuf_threads = int((traffic_profile.get("ffuf") or {}).get("threads", 20))
    resolved_ffuf_rate = int((traffic_profile.get("ffuf") or {}).get("rate", 50))
    historical_profile = traffic_profile.get("historical_urls") if isinstance(traffic_profile.get("historical_urls"), dict) else {}
    resolved_historical_max_urls = int(historical_profile.get("max_urls", config.historical_urls_max_urls) or 0)
    resolved_historical_max_domains = int(historical_profile.get("max_domains", config.historical_urls_max_domains or 50) or 0)
    resolved_historical_live_check_limit = int(
        historical_profile.get("live_check_limit", config.historical_urls_live_check_limit) or 0
    )
    screenshots_profile = traffic_profile.get("screenshots") if isinstance(traffic_profile.get("screenshots"), dict) else {}
    resolved_screenshots_limit = int(screenshots_profile.get("limit", config.screenshots_limit or 20) or 0)
    try:
        resolved_screenshots_timeout = max(1, int(config.screenshots_timeout or 90))
    except Exception:
        resolved_screenshots_timeout = 90
    resolved_nuclei_rate_limit = int((traffic_profile.get("nuclei") or {}).get("rate_limit", 3))

    effective = {
        "run_id": run_id, "target": target, "traffic_profile": requested_traffic_profile,
        "tools": {name: True for name in enabled_scanners(config, mode)},
        "limits": {key: value for key, value in vars(config).items() if any(word in key for word in ("timeout", "limit", "max_urls", "max_base_urls", "top_ports", "depth"))},
        "traffic": traffic_profile,
        "nmap_mode": "all_ports" if mode == "ip" and config.detailed_nmap_enabled else "top_ports",
    }
    effective["limits"]["screenshots_limit"] = resolved_screenshots_limit
    effective["limits"]["checks_max_body_bytes"] = config.checks_max_body_bytes
    effective["limits"]["checks_follow_redirects"] = config.checks_follow_redirects
    effective["runtime"] = runtime_metadata(enabled_scanners(config, mode))
    atomic_json(run_dir / "effective_config.json", effective)
    info(f"[i] Etkin ayarlar: Nmap={resolved_nmap_timing}, port={effective['nmap_mode']}, "
         f"timeout={config.nmap_timeout_sec}s; Katana={katana_traffic['rate_limit']} istek/s, "
         f"timeout={config.katana_timeout_sec}s; Nuclei={resolved_nuclei_rate_limit} istek/s, "
         f"timeout={config.nuclei_timeout_sec}s, URL sınırı={config.nuclei_pool_limit}")

    if config.nmap_timing is not None and resolved_nmap_timing != str(config.nmap_timing).strip().upper():
        info(f"[i] Nmap timing normalize edildi: {config.nmap_timing} -> {resolved_nmap_timing} (T5 kullanılmaz).")

    uses_subfinder = mode == "domain" and config.subfinder_enabled
    uses_dnsx = mode == "domain" and config.dnsx_enabled
    uses_httpx = mode == "domain" and config.httpx_enabled

    traffic_parts: list[str] = [
        f"[i] Traffic profile: {requested_traffic_profile}",
        f"risk={traffic_profile['risk_level']}",
        f"katana(c={katana_traffic['concurrency']},p={katana_traffic['parallelism']},rl={katana_traffic['rate_limit']},d={katana_traffic['delay_sec']}s)",
        f"web_checks(rps={checks_traffic['requests_per_second']},delay={checks_traffic['delay_ms']}ms)",
    ]
    if config.nuclei_enabled:
        traffic_parts.append(f"nuclei(rl={resolved_nuclei_rate_limit})")
    if config.nmap_enabled:
        traffic_parts.append(f"nmap(timing={resolved_nmap_timing})")
    if config.gobuster_enabled:
        traffic_parts.append(f"gobuster(t={resolved_gobuster_threads})")
    if config.ffuf_enabled:
        traffic_parts.append(f"ffuf(t={resolved_ffuf_threads},rate={resolved_ffuf_rate})")
    if config.historical_urls_enabled:
        traffic_parts.append(
            f"historical_urls(domains={resolved_historical_max_domains},max={resolved_historical_max_urls},live={resolved_historical_live_check_limit})"
        )
    if config.screenshots_enable:
        traffic_parts.append(f"screenshots(limit={resolved_screenshots_limit},timeout={resolved_screenshots_timeout})")
    if uses_subfinder:
        traffic_parts.append(f"subfinder(rl={resolved_subfinder_rate_limit})")
    if uses_dnsx:
        traffic_parts.append(f"dnsx(rl={resolved_dnsx_rate_limit})")
    if uses_httpx:
        traffic_parts.append(f"httpx(rl={resolved_httpx_rate_limit})")

    info(" | ".join(traffic_parts))
    if traffic_profile["risk_level"] == "high":
        info("[!] Rate-limit risk warning: FAST profil daha fazla noise üretir; 429/WAF/captcha/log görünürlüğü riski artar.")


    # Build separate skip groups so the user can clearly see
    # which tools were auto-skipped by the program vs disabled by config.
    auto_skipped_tools: list[str] = []
    config_skipped_tools: list[str] = []

    # Mode-enforced skips
    if mode == "url":
        # URL mode: we already have an explicit seed URL. No need for subdomain discovery or liveness probing.
        auto_skipped_tools.extend(["subfinder", "dnsx", "httpx"])
    elif mode == "ip":
        # IP mode: subdomain discovery is not applicable
        auto_skipped_tools.append("subfinder")

    # Config-enforced skips
    if not config.nmap_enabled:
        config_skipped_tools.append("nmap")
    if not config.subfinder_enabled:
        config_skipped_tools.append("subfinder")
    if not config.dnsx_enabled:
        config_skipped_tools.append("dnsx")
    if not config.httpx_enabled:
        config_skipped_tools.append("httpx")
    if not config.katana_enabled:
        config_skipped_tools.append("katana")
    if not config.gobuster_enabled:
        config_skipped_tools.append("gobuster")
    if not config.ffuf_enabled:
        config_skipped_tools.append("ffuf")
    if not config.historical_urls_enabled:
        config_skipped_tools.append("historical_urls")
    if not config.screenshots_enable:
        config_skipped_tools.append("screenshots")
    if not config.checks_enabled:
        config_skipped_tools.append("web_checks")
    if not config.nuclei_enabled:
        config_skipped_tools.append("nuclei")
    if not config.wafw00f_enabled:
        config_skipped_tools.append("wafw00f")
    if not config.whatweb_enabled:
        config_skipped_tools.append("whatweb")

    auto_skipped_tools = sorted(set(auto_skipped_tools))
    # Important: if a tool is already auto-skipped by mode, do NOT also report it
    # as user/config-skipped. Otherwise URL mode falsely looks like the user disabled it.
    config_skipped_tools = sorted(set(config_skipped_tools) - set(auto_skipped_tools))
    skipped_tools = sorted(set(auto_skipped_tools + config_skipped_tools))

    for tool_name in skipped_tools:
        if tool_name == "web_checks":
            stage_name = "checks"
        else:
            stage_name = tool_name
        if stage_name in stages:
            _stage_finish(stages, stage_name, "skipped")

    # Reasons are separated too, so terminal output stays explicit.
    auto_reason = ""
    if mode == "url":
        auto_reason = " (URL modu: hedef adresi açıkça verildiği için keşif/canlılık doğrulama adımları atlanır)"
    elif mode == "ip":
        auto_reason = " (IP modu: subdomain keşfi uygulanamaz)"

    if auto_skipped_tools:
        log(f"[i] Program tarafından skip edilen tool(lar): {', '.join(auto_skipped_tools)}{auto_reason}")
    if config_skipped_tools:
        log(f"[i] Kullanıcı/config tarafından skip edilen tool(lar): {', '.join(config_skipped_tools)}")
    if not auto_skipped_tools and not config_skipped_tools:
        log("[i] Skip edilen tool yok (hepsi aktif).")

    raw_ip_enrichment = config.ip_enrichment if isinstance(config.ip_enrichment, dict) else {}

    def _ip_enrichment_snapshot() -> dict[str, Any]:
        if not raw_ip_enrichment:
            return {}
        request_status = str(raw_ip_enrichment.get("status") or raw_ip_enrichment.get("state") or "").strip()
        status = request_status
        scan_mode = str(raw_ip_enrichment.get("scan_mode") or raw_ip_enrichment.get("scanMode") or "").strip()
        requested_statuses = {"quick_ip_scan_requested", "detailed_nmap_requested"}
        if status in requested_statuses:
            nmap_status = str((stages.get("nmap") or {}).get("status") or "").strip().lower()
            if nmap_status == "error":
                status = "failed"
            elif nmap_status in {"done", "skipped"}:
                status = "completed"
        snapshot = {
            "status": status or "available_skipped",
            "request_status": request_status,
            "original_target": str(raw_ip_enrichment.get("original_target") or raw_ip_enrichment.get("originalTarget") or "").strip(),
            "resolved_ip": str(raw_ip_enrichment.get("resolved_ip") or raw_ip_enrichment.get("resolvedIp") or (target if mode == "ip" else "")).strip(),
            "hostname": str(raw_ip_enrichment.get("hostname") or "").strip(),
            "scan_mode": scan_mode or ("detailed" if config.detailed_nmap_enabled else "quick" if mode == "ip" else "skipped"),
            "requested_at": str(raw_ip_enrichment.get("requested_at") or raw_ip_enrichment.get("requestedAt") or "").strip(),
            "note": str(raw_ip_enrichment.get("note") or "").strip(),
            "secondary_run": request_status in requested_statuses or bool(raw_ip_enrichment.get("secondary_run")),
            "detailed_nmap_enabled": bool(config.detailed_nmap_enabled),
        }
        return _json_safe_value(snapshot)

    def _attach_ip_enrichment_snapshot(results: dict[str, Any]) -> dict[str, Any]:
        if isinstance(results, dict):
            snapshot = _ip_enrichment_snapshot()
            if snapshot:
                results["ip_enrichment"] = snapshot
        return results

    gobuster_results: dict = {}
    ffuf_results: dict[str, list[dict[str, Any]]] = {}
    soft_error_filter: dict[str, Any] = {"suppressed_count": 0, "suppressed": [], "baselines": {}}
    candidate_validation: dict[str, Any] = {"records": [], "confirmed_urls": [], "suppressed": [], "suppressed_count": 0, "by_status": {}}
    nuclei_results: dict = {}
    nmap_output: str = ""
    katana_urls: list[str] = []
    checks_results: dict = {}
    wafw00f_results: dict = {}
    whatweb_results: dict = {}
    historical_results: dict[str, Any] = {"enabled": bool(config.historical_urls_enabled), "records": []}
    historical_live_urls: list[str] = []
    historical_interesting_live_urls: list[str] = []
    screenshots_results: dict[str, Any] = {"enabled": bool(config.screenshots_enable), "entries": []}
    nuclei_targets_count: int = 0

    if mode == "url":
        seed_url = _normalize_target_url(target)
        log(f"[+] Target (URL): {seed_url}")
        log(f"[+] Wordlist: {wordlist}")

        # Optional: run nmap against the host IP (info-only). Note: quick scans may miss non-top ports.
        if config.nmap_enabled:
            _stage_set_running(stages, "nmap")
            try:
                host = urlsplit(seed_url).hostname or ""
                if host == "localhost":
                    ip_for_nmap = "127.0.0.1"
                else:
                    infos = socket.getaddrinfo(host, None)
                    apex_ips = sorted({info[4][0] for info in infos if info and info[4]})
                    ip_for_nmap = apex_ips[0] if apex_ips else ""
                if ip_for_nmap:
                    nmap_output, _xml_path = run_nmap(ip_for_nmap, timing=resolved_nmap_timing, top_ports=config.nmap_top_ports, timeout_sec=config.nmap_timeout_sec, run_dir=run_dir)
                else:
                    nmap_output = "(Nmap: host IP resolve failed)"
                _write_text_artifact(nmap_txt_path, nmap_output)
                _stage_finish(
                    stages,
                    "nmap",
                    "done",
                    artifacts={"txt": _artifact_ref(nmap_txt_path)},
                )
            except Exception as e:
                print(f"[!] Nmap (url host) hata: {e}")
                nmap_output = ""
                _write_text_artifact(nmap_txt_path, nmap_output)
                _stage_finish(
                    stages,
                    "nmap",
                    "error",
                    artifacts={"txt": _artifact_ref(nmap_txt_path)},
                    error=str(e),
                )
        else:
            nmap_output = "(Nmap skipped by config)"
            log("[+] Nmap atlandı (config).")

        # URL mode bypasses subfinder/dnsx/httpx. We already have a live seed.
        web_urls = [seed_url]

    elif not is_ip(target):
        # DOMAIN mode: subfinder -> dnsx -> httpx
        log(f"[+] Target (Domain): {target}")
        log(f"[+] Wordlist: {wordlist}")

        # Nmap on apex domain IP(s) only (port/service info)
        try:
            infos = socket.getaddrinfo(target, None)
            apex_ips = sorted({info[4][0] for info in infos if info and info[4]})
        except Exception:
            apex_ips = []

        if config.nmap_enabled:
            _stage_set_running(stages, "nmap")
            if apex_ips:
                log(f"[+] Apex IP(ler) bulundu: {', '.join(apex_ips[:3])}{'...' if len(apex_ips) > 3 else ''}")
                # Run nmap on first resolved IP to avoid heavy scans on CDN/anycast lists
                ip_for_nmap = apex_ips[0]
                try:
                    nmap_output, _xml_path = run_nmap(ip_for_nmap, timing=resolved_nmap_timing, top_ports=config.nmap_top_ports, timeout_sec=config.nmap_timeout_sec, run_dir=run_dir)
                    _write_text_artifact(nmap_txt_path, nmap_output)
                    _stage_finish(
                        stages,
                        "nmap",
                        "done",
                        artifacts={"txt": _artifact_ref(nmap_txt_path)},
                    )
                except Exception as e:
                    print(f"[!] Nmap (domain apex IP) hata: {e}")
                    nmap_output = ""
                    _write_text_artifact(nmap_txt_path, nmap_output)
                    _stage_finish(
                        stages,
                        "nmap",
                        "error",
                        artifacts={"txt": _artifact_ref(nmap_txt_path)},
                        error=str(e),
                    )
            else:
                nmap_output = "(Nmap: apex IP bulunamadı)"
                log("[+] Nmap atlandı (apex IP bulunamadı).")
                _write_text_artifact(nmap_txt_path, nmap_output)
                _stage_finish(
                    stages,
                    "nmap",
                    "skipped",
                    artifacts={"txt": _artifact_ref(nmap_txt_path)},
                    reason="apex IP bulunamadı",
                )
        else:
            nmap_output = "(Nmap skipped by config)"
            log("[+] Nmap atlandı (config).")

        if config.subfinder_enabled:
            _stage_set_running(stages, "subfinder")
            log(f"[+] Subfinder başlatılıyor... (rl={resolved_subfinder_rate_limit})")
            try:
                raw_subs = run_subfinder(target, rate_limit=resolved_subfinder_rate_limit)
                _write_text_artifact(subfinder_txt_path, "\n".join(raw_subs))
            except Exception as e:
                print(f"[!] Subfinder hata: {e}")
                raw_subs = []
                _write_text_artifact(subfinder_txt_path, "")
                _write_json_artifact(subfinder_json_path, {"target": target, "raw_subdomains": [], "error": str(e)})
                _stage_finish(
                    stages,
                    "subfinder",
                    "error",
                    artifacts={
                        "txt": _artifact_ref(subfinder_txt_path),
                        "json": _artifact_ref(subfinder_json_path),
                    },
                    error=str(e),
                )
        else:
            log("[+] Subfinder atlandı (config).")
            raw_subs = []

        # Scope filter: keep only true subdomains of the target (e.g. *.example.com)
        t = target.lower().strip(".")
        filtered = [s for s in raw_subs if (s or "").lower().strip(".").endswith("." + t)]

        subs = sorted(set(filtered))
        log(f"[+] Subfinder bitti. Bulunan subdomain: {len(raw_subs)} | Scope içi: {len(subs)}")
        if config.subfinder_enabled and stages["subfinder"]["status"] != "error":
            subfinder_meta = scanner_metadata(raw_subs)
            _write_json_artifact(
                subfinder_json_path,
                {
                    "target": target,
                    "raw_count": len(raw_subs),
                    "scoped_count": len(subs),
                    "scoped_subdomains": subs,
                    **subfinder_meta,
                },
            )
            _stage_finish(
                stages,
                "subfinder",
                subfinder_meta["status"],
                error=subfinder_meta["error"],
                returncode=subfinder_meta["returncode"],
                artifacts={
                    "txt": _artifact_ref(subfinder_txt_path),
                    "json": _artifact_ref(subfinder_json_path),
                },
            )

        hosts = sorted(set([target] + subs))

        if config.dnsx_enabled:
            _stage_set_running(stages, "dnsx")
            log(f"[+] DNSX başlatılıyor (batch={config.dnsx_batch}, rl={resolved_dnsx_rate_limit})...")
            try:
                resolved_all: list[str] = []
                batch_records: list[dict[str, Any]] = []
                processed = 0
                total = len(hosts)
                for batch in parçalayıcı(hosts, config.dnsx_batch):
                    try:
                        resolved_batch = run_dnsx(batch, rate_limit=resolved_dnsx_rate_limit)
                    except Exception as exc:
                        resolved_batch = ScannerItems(returncode=1, error=str(exc))
                    batch_records.append({"input_count": len(batch), **scanner_metadata(resolved_batch)})
                    resolved_all.extend(resolved_batch)
                    processed += len(batch)
                    log(f"[+] DNSX progress: {processed}/{total} (resolved_total={len(set(resolved_all))})")

                resolved = sorted(set(resolved_all))
                _write_text_artifact(dnsx_txt_path, "\n".join(resolved))
                batch_status, batch_error = aggregate_scanner_status(batch_records)
                _write_json_artifact(dnsx_json_path, {"input_hosts": hosts, "resolved_hosts": resolved, "batches": batch_records, "error": batch_error})
                log(f"[+] DNSX bitti. Resolve olan host: {len(resolved)}")
                _stage_finish(
                    stages,
                    "dnsx",
                    batch_status if batch_records else "skipped",
                    error=batch_error,
                    failed_batch_count=sum(row["status"] in {"error", "partial"} for row in batch_records),
                    artifacts={
                        "txt": _artifact_ref(dnsx_txt_path),
                        "json": _artifact_ref(dnsx_json_path),
                    },
                )
            except Exception as e:
                print(f"[!] DNSX hata: {e}")
                resolved = []
                _write_text_artifact(dnsx_txt_path, "")
                _write_json_artifact(dnsx_json_path, {"input_hosts": hosts, "resolved_hosts": [], "error": str(e)})
                _stage_finish(
                    stages,
                    "dnsx",
                    "error",
                    artifacts={
                        "txt": _artifact_ref(dnsx_txt_path),
                        "json": _artifact_ref(dnsx_json_path),
                    },
                    error=str(e),
                )
        else:
            log("[+] DNSX atlandı (config).")
            resolved = hosts

        if config.httpx_enabled:
            _stage_set_running(stages, "httpx")
            log(f"[+] HTTPX başlatılıyor (batch={config.httpx_batch}, rl={resolved_httpx_rate_limit})...")
            try:
                urls_all: list[str] = []
                batch_records: list[dict[str, Any]] = []
                processed = 0
                total = len(resolved)
                for batch in parçalayıcı(resolved, config.httpx_batch):
                    try:
                        urls_batch = run_httpx(batch, rate_limit=resolved_httpx_rate_limit)
                    except Exception as exc:
                        urls_batch = ScannerItems(returncode=1, error=str(exc))
                    batch_records.append({"input_count": len(batch), **scanner_metadata(urls_batch)})
                    urls_all.extend(urls_batch)
                    processed += len(batch)
                    log(f"[+] HTTPX progress: {processed}/{total} (urls_total={len(set(urls_all))})")

                web_urls = sorted(set(urls_all))
                _write_text_artifact(httpx_txt_path, "\n".join(web_urls))
                batch_status, batch_error = aggregate_scanner_status(batch_records)
                _write_json_artifact(httpx_json_path, {"input_hosts": resolved, "live_urls": web_urls, "batches": batch_records, "error": batch_error})
                log(f"[+] HTTPX bitti. Canlı URL: {len(web_urls)}")
                _stage_finish(
                    stages,
                    "httpx",
                    batch_status if batch_records else "skipped",
                    error=batch_error,
                    failed_batch_count=sum(row["status"] in {"error", "partial"} for row in batch_records),
                    artifacts={
                        "txt": _artifact_ref(httpx_txt_path),
                        "json": _artifact_ref(httpx_json_path),
                    },
                )
            except Exception as e:
                print(f"[!] HTTPX hata: {e}")
                web_urls = []
                _write_text_artifact(httpx_txt_path, "")
                _write_json_artifact(httpx_json_path, {"input_hosts": resolved, "live_urls": [], "error": str(e)})
                _stage_finish(
                    stages,
                    "httpx",
                    "error",
                    artifacts={
                        "txt": _artifact_ref(httpx_txt_path),
                        "json": _artifact_ref(httpx_json_path),
                    },
                    error=str(e),
                )
        else:
            log("[+] HTTPX atlandı (config).")
            web_urls = []

    else:
        # IP mode
        log(f"[+] Target (IP): {target}")
        log(f"[+] Wordlist: {wordlist}")

        if config.nmap_enabled:
            _stage_set_running(stages, "nmap")
            try:
                nmap_output, xml_path = run_nmap(
                    target, timing=resolved_nmap_timing, top_ports=config.nmap_top_ports,
                    timeout_sec=config.nmap_timeout_sec, detailed=config.detailed_nmap_enabled, run_dir=run_dir,
                )
                web_urls = parse_nmap_xml(xml_path, target)
                _write_text_artifact(nmap_txt_path, nmap_output)
                _stage_finish(
                    stages,
                    "nmap",
                    "done",
                    artifacts={"txt": _artifact_ref(nmap_txt_path)},
                )
            except Exception as e:
                _write_text_artifact(nmap_txt_path, nmap_output)
                _stage_finish(
                    stages,
                    "nmap",
                    "error",
                    artifacts={"txt": _artifact_ref(nmap_txt_path)},
                    error=str(e),
                )
                raise RuntimeError(f"Nmap veya XML parse hatası: {e}")
        else:
            log("[+] Nmap atlandı (config).")
            nmap_output = "(Nmap skipped by config)"
            web_urls = []

    # Optional historical URL discovery from external archives. This is disabled by
    # default and only feeds live, normalized URLs into later analysis.
    if config.historical_urls_enabled:
        _stage_set_running(stages, "historical_urls")
        candidate_domains: list[str] = []
        selected_domain_meta: dict[str, Any] = {}
        if mode == "url":
            host = urlsplit(web_urls[0]).hostname if web_urls else urlsplit(_normalize_target_url(target)).hostname
            if host and not is_ip(host):
                candidate_domains.append(host)
            selected_domain_meta = select_historical_domains(
                root_domain=host or "",
                received_candidates=candidate_domains,
                resolved_hosts=[],
                live_urls=web_urls,
                max_domains=resolved_historical_max_domains,
                allow_root_fallback=True,
            )
        elif mode == "domain":
            if isinstance(locals().get("hosts"), list):
                candidate_domains.extend(locals().get("hosts") or [])
            resolved_hosts = (
                locals().get("resolved")
                if config.dnsx_enabled and isinstance(locals().get("resolved"), list)
                else []
            )
            selected_domain_meta = select_historical_domains(
                root_domain=target,
                received_candidates=candidate_domains,
                resolved_hosts=resolved_hosts,
                live_urls=web_urls,
                max_domains=resolved_historical_max_domains,
                allow_root_fallback=True,
            )

        selected_historical_domains = [
            str(domain or "").strip()
            for domain in selected_domain_meta.get("domains", [])
            if str(domain or "").strip()
        ]
        log(
            "[+] Historical URL discovery: "
            f"received={int(selected_domain_meta.get('received_count', len(candidate_domains)) or 0)}, "
            f"selected={len(selected_historical_domains)}, "
            f"reason={selected_domain_meta.get('selection_reason', 'none')}, "
            f"max_domains={resolved_historical_max_domains}, "
            f"max_urls={resolved_historical_max_urls}"
        )

        if not selected_historical_domains:
            historical_results = {
                "enabled": True,
                "domains": [],
                "records": [],
                "warnings": ["No domain candidates available for historical URL discovery"],
                "domain_selection": selected_domain_meta,
            }
            _write_text_artifact(gau_txt_path, "")
            _write_text_artifact(wayback_txt_path, "")
            _write_text_artifact(historical_txt_path, "")
            _write_json_artifact(historical_json_path, historical_results)
            _stage_finish(
                stages,
                "historical_urls",
                "skipped",
                artifacts={
                    "gau": _artifact_ref(gau_txt_path),
                    "waybackurls": _artifact_ref(wayback_txt_path),
                    "txt": _artifact_ref(historical_txt_path),
                    "json": _artifact_ref(historical_json_path),
                },
                reason="domain adayı bulunamadı",
            )
        else:
            try:
                historical_results = collect_historical_urls(
                    selected_historical_domains,
                    max_urls=resolved_historical_max_urls,
                    max_domains=resolved_historical_max_domains,
                    timeout_sec=int(config.historical_urls_timeout_sec),
                )
                historical_results["domain_selection"] = selected_domain_meta
                raw_by_tool = historical_results.get("raw_by_tool") if isinstance(historical_results.get("raw_by_tool"), dict) else {}
                _write_text_artifact(gau_txt_path, "\n".join(raw_by_tool.get("gau", []) or []))
                _write_text_artifact(wayback_txt_path, "\n".join(raw_by_tool.get("waybackurls", []) or []))
                normalized_historical_urls = [
                    str(url or "").strip()
                    for url in historical_results.get("normalized_urls", [])
                    if str(url or "").strip()
                ]
                _write_text_artifact(historical_txt_path, "\n".join(normalized_historical_urls))

                live_probe_candidates = normalized_historical_urls[: max(0, int(resolved_historical_live_check_limit))]
                historical_live_urls = []
                if live_probe_candidates:
                    historical_live_urls = run_httpx(live_probe_candidates, rate_limit=resolved_httpx_rate_limit)
                    historical_live_urls = [
                        normalize_historical_url(url)
                        for url in historical_live_urls
                        if normalize_historical_url(url)
                    ]
                historical_results = mark_live_historical_urls(
                    historical_results,
                    historical_live_urls,
                    checked_urls=live_probe_candidates,
                )
                historical_results["artifacts"] = {
                    "gau": _artifact_ref(gau_txt_path),
                    "waybackurls": _artifact_ref(wayback_txt_path),
                    "combined_txt": _artifact_ref(historical_txt_path),
                    "combined_json": _artifact_ref(historical_json_path),
                }
                historical_interesting_live_urls = [
                    str(item.get("url") or "").strip()
                    for item in historical_results.get("interesting_live_urls", [])
                    if isinstance(item, dict) and str(item.get("url") or "").strip()
                ]
                _write_json_artifact(historical_json_path, historical_results)
                if historical_results.get("warnings"):
                    for warning in historical_results.get("warnings", [])[:5]:
                        info(f"[!] Historical URL warning: {warning}")
                log(
                    "[+] Historical URL discovery bitti. "
                    f"normalized={len(normalized_historical_urls)} live={len(historical_live_urls)} "
                    f"interesting_live={len(historical_interesting_live_urls)}"
                )
                _stage_finish(
                    stages,
                    "historical_urls",
                    "partial" if historical_results.get("warnings") else "done",
                    error="; ".join(historical_results.get("warnings", [])[:3]) or None,
                    artifacts=historical_results["artifacts"],
                    normalized_count=len(normalized_historical_urls),
                    live_count=len(historical_live_urls),
                    interesting_live_count=len(historical_interesting_live_urls),
                    warnings=historical_results.get("warnings", []),
                )
            except Exception as e:
                print(f"[!] Historical URL discovery hata: {e}")
                historical_results = {"enabled": True, "records": [], "error": str(e)}
                _write_text_artifact(gau_txt_path, "")
                _write_text_artifact(wayback_txt_path, "")
                _write_text_artifact(historical_txt_path, "")
                _write_json_artifact(historical_json_path, historical_results)
                _stage_finish(
                    stages,
                    "historical_urls",
                    "error",
                    artifacts={
                        "gau": _artifact_ref(gau_txt_path),
                        "waybackurls": _artifact_ref(wayback_txt_path),
                        "txt": _artifact_ref(historical_txt_path),
                        "json": _artifact_ref(historical_json_path),
                    },
                    error=str(e),
                )

    if not web_urls and not historical_live_urls:
        log("[+] Web listesi bulunamadı!")
        log("[+] Gobuster/FFUF ve Nuclei adımları atlanıyor.")
        classified_endpoints = _classify_endpoints([])
        endpoint_analysis_dict = summary_to_dict(
            analyze_endpoints(
                web_urls=[],
                katana_urls=[],
                gobuster_results={},
                ffuf_results={},
                classified_endpoints=classified_endpoints,
            )
        )
        checks_results = _build_checks_results_base(
            classified_endpoints=classified_endpoints,
            ffuf_results={},
            endpoint_analysis_dict=endpoint_analysis_dict,
            wafw00f_results={},
            whatweb_results={},
            traffic_state=traffic_state,
            technology_fingerprint=[],
            attack_chains=[],
            attack_graph={},
            exploit_suggestions=[],
            node_relationships=[],
            auth_profile=_empty_auth_profile(),
        )
        checks_results = _attach_ip_enrichment_snapshot(checks_results)
        checks_results["cve_enrichment"] = {"query_count": 0, "matches": []}
        checks_results["historical_urls"] = historical_results
        checks_results["screenshots"] = screenshots_results
        # A downstream empty URL pool must never erase upstream evidence/errors.
        for path, data in ((subfinder_txt_path, ""), (dnsx_txt_path, ""), (httpx_txt_path, "")):
            if not path.exists():
                _write_text_artifact(path, data)
        for path, data in ((subfinder_json_path, {"raw_subdomains": []}), (dnsx_json_path, {"resolved_hosts": []}), (httpx_json_path, {"live_urls": []})):
            if not path.exists():
                _write_json_artifact(path, data)
        if not historical_json_path.exists():
            _write_text_artifact(gau_txt_path, "")
            _write_text_artifact(wayback_txt_path, "")
            _write_text_artifact(historical_txt_path, "")
            _write_json_artifact(historical_json_path, historical_results)
        _write_text_artifact(katana_txt_path, "")
        _write_json_artifact(katana_json_path, {"urls": []})
        _write_json_artifact(gobuster_json_path, {})
        _write_json_artifact(ffuf_json_path, {})
        _write_json_artifact(wafw00f_json_path, {})
        _write_json_artifact(whatweb_json_path, {})
        _write_json_artifact(checks_json_path, checks_results)
        _write_text_artifact(targets_txt_path, "")
        for stage_name in ("katana", "gobuster", "ffuf", "historical_urls", "screenshots", "wafw00f", "whatweb", "checks", "nuclei"):
            if stages[stage_name]["status"] == "pending":
                _stage_finish(stages, stage_name, "skipped")
        _write_run_json(
            target=target,
            mode=mode,
            skipped_tools=skipped_tools,
            nmap_output=nmap_output,
            gobuster_results=gobuster_results,
            ffuf_results=ffuf_results,
            katana_urls=katana_urls,
            checks_results=checks_results,
            nuclei_targets_count=0,
            nuclei_output_path=None,
            nuclei_running=False,
            run_dir=run_dir,
            latest_dir=latest_dir,
            run_id=run_id,
            stages=stages,
            traffic_state=traffic_state,
        )
        return RunResult(
            nmap_output=nmap_output,
            gobuster_results=gobuster_results,
            katana_urls=katana_urls,
            checks_results=checks_results,
            nuclei_results=nuclei_results,
            nuclei_proc=None,
            nuclei_output_path=None,
            nuclei_log_path=None,
        )

    # Katana: discover additional endpoints from live base URLs
    if config.katana_enabled:
        _stage_set_running(stages, "katana")
        log(f"[+] Katana başlatılıyor... (seed URLs: {len(web_urls)})")
        try:
            katana_diagnostics = {}
            katana_urls = run_katana(
                web_urls,
                depth=config.katana_depth,
                js_crawl=config.katana_js_crawl,
                auto_js_crawl=config.katana_auto_js_crawl,
                timeout_sec=config.katana_timeout_sec,
                max_urls=config.katana_max_urls,
                diagnostics=katana_diagnostics,
                concurrency=katana_traffic["concurrency"],
                parallelism=katana_traffic["parallelism"],
                rate_limit=katana_traffic["rate_limit"],
                delay_sec=katana_traffic["delay_sec"],
            )
            _write_text_artifact(katana_txt_path, "\n".join(katana_urls))
            _write_json_artifact(katana_json_path, {"seed_urls": web_urls, "urls": katana_urls, **katana_diagnostics})
            log(f"[+] Katana bitti. Bulunan endpoint/URL: {len(katana_urls)}")
            _stage_finish(
                stages,
                "katana",
                "partial" if katana_diagnostics.get("errors") else "done",
                error="; ".join(katana_diagnostics.get("errors", [])[:3]) or None,
                artifacts={
                    "txt": _artifact_ref(katana_txt_path),
                    "json": _artifact_ref(katana_json_path),
                },
            )
        except Exception as e:
            print(f"[!] Katana hata: {e}")
            katana_urls = []
            _write_text_artifact(katana_txt_path, "")
            _write_json_artifact(katana_json_path, {"seed_urls": web_urls, "urls": [], "error": str(e)})
            _stage_finish(
                stages,
                "katana",
                "error",
                artifacts={
                    "txt": _artifact_ref(katana_txt_path),
                    "json": _artifact_ref(katana_json_path),
                },
                error=str(e),
            )
    else:
        log("[+] Katana atlandı (config).")
        katana_urls = []

    # Gobuster per discovered web URL
    if config.gobuster_enabled:
        _stage_set_running(stages, "gobuster")
        # Gobuster: run directory enumeration on each live base URL.
        # We avoid spamming the terminal for every URL by default; you can enable
        # `gobuster_log_each` to print per-URL lines.
        log(f"[+] Gobuster başlatılıyor... (base URLs: {len(web_urls)}, threads={resolved_gobuster_threads})")
        gobuster_failures: list[dict[str, str]] = []
        gobuster_records: list[dict[str, Any]] = []
        for base_url in web_urls:
            try:
                if config.gobuster_log_each:
                    log(f"[+] Gobuster başlatılıyor: {base_url}")

                gobuster_sonuc = _run_gobuster_compat(
                    base_url,
                    wordlist,
                    threads=resolved_gobuster_threads,
                    timeout=int(config.gobuster_timeout),
                    allowed_status=config.gobuster_allowed_status,
                )
                gobuster_results[base_url] = gobuster_sonuc
                record = {"base_url": base_url, **scanner_metadata(gobuster_sonuc)}
                gobuster_records.append(record)
                if record["status"] in {"error", "partial"}:
                    gobuster_failures.append({"base_url": base_url, "error": str(record["error"])})
            except Exception as e:
                print(f"[!] Gobuster hata ({base_url}): {e}")
                gobuster_failures.append({"base_url": base_url, "error": str(e)})
                gobuster_records.append({"status": "error", "error": str(e)})

        gobuster_summary = _summarize_gobuster(gobuster_results)
        gobuster_artifact: dict[str, Any] = {
            "summary": gobuster_summary,
            "results": gobuster_results,
            "runs": gobuster_records,
        }
        if gobuster_failures:
            gobuster_artifact["failures"] = gobuster_failures
        _write_json_artifact(gobuster_json_path, gobuster_artifact)
        log(
            "[+] Gobuster bitti. "
            f"base_url={gobuster_summary.get('base_url_count', 0)} "
            f"hits={gobuster_summary.get('total_hits', 0)} "
            f"status_counts={gobuster_summary.get('status_counts', {})}"
        )
        gobuster_stage_status, _ = aggregate_scanner_status(gobuster_records)
        if not gobuster_records:
            gobuster_stage_status = "skipped"
        _stage_finish(
            stages,
            "gobuster",
            gobuster_stage_status,
            artifacts={"json": _artifact_ref(gobuster_json_path)},
            attempted_base_url_count=len(web_urls),
            failed_base_url_count=len(gobuster_failures),
            failed_base_urls=[item["base_url"] for item in gobuster_failures],
            error="; ".join(item["error"] for item in gobuster_failures[:3]) if gobuster_failures else None,
        )
    else:
        log("[i] Gobuster skip (config: gobuster_enabled=False).")
        gobuster_results = {}

    # FFUF per validated live base URL
    if config.ffuf_enabled:
        _stage_set_running(stages, "ffuf")
        ffuf_runs: dict[str, dict[str, Any]] = {}
        ffuf_targets = list(web_urls)[: max(1, int(config.ffuf_max_base_urls))]
        ffuf_outputs_dir = run_dir / "ffuf"
        ffuf_outputs_dir.mkdir(parents=True, exist_ok=True)
        log(
            f"[+] FFUF başlatılıyor... (base URLs: {len(ffuf_targets)}, "
            f"threads={resolved_ffuf_threads}, rate={resolved_ffuf_rate})"
        )
        ffuf_failures: list[dict[str, str]] = []
        ffuf_records: list[dict[str, Any]] = []
        for idx, base_url in enumerate(ffuf_targets, start=1):
            try:
                parsed = urlsplit(base_url)
                host_part = (parsed.netloc or f"target-{idx}").replace(":", "_")
                output_path = ffuf_outputs_dir / f"{idx:03d}-{host_part}.json"
                ffuf_run = run_ffuf(
                    base_url=base_url,
                    wordlist=wordlist,
                    output_json_path=output_path,
                    threads=resolved_ffuf_threads,
                    rate=resolved_ffuf_rate,
                    timeout=int(config.ffuf_timeout),
                    allowed_status=config.ffuf_allowed_status,
                )
                ffuf_runs[base_url] = ffuf_run
                record = {"base_url": base_url, **scanner_metadata(ffuf_run)}
                ffuf_records.append(record)
                if record["status"] in {"error", "partial"}:
                    ffuf_failures.append({"base_url": base_url, "error": str(record["error"])})
                ffuf_results[base_url] = ffuf_run.get("findings", []) if isinstance(ffuf_run.get("findings"), list) else []
            except Exception as e:
                print(f"[!] FFUF hata ({base_url}): {e}")
                ffuf_failures.append({"base_url": base_url, "error": str(e)})
                ffuf_records.append({"status": "error", "error": str(e)})

        ffuf_summary = _summarize_ffuf(ffuf_results)
        ffuf_artifact: dict[str, Any] = {
            "summary": ffuf_summary,
            "runs": ffuf_runs,
            "findings_by_base": ffuf_results,
        }
        if ffuf_failures:
            ffuf_artifact["failures"] = ffuf_failures
        _write_json_artifact(ffuf_json_path, ffuf_artifact)
        log(
            "[+] FFUF bitti. "
            f"base_url={ffuf_summary.get('base_url_count', 0)} "
            f"hits={ffuf_summary.get('total_hits', 0)} "
            f"status_counts={ffuf_summary.get('status_counts', {})}"
        )
        ffuf_stage_status, _ = aggregate_scanner_status(ffuf_records)
        if not ffuf_records:
            ffuf_stage_status = "skipped"
        _stage_finish(
            stages,
            "ffuf",
            ffuf_stage_status,
            artifacts={"json": _artifact_ref(ffuf_json_path)},
            attempted_base_url_count=len(ffuf_targets),
            failed_base_url_count=len(ffuf_failures),
            failed_base_urls=[item["base_url"] for item in ffuf_failures],
            error="; ".join(item["error"] for item in ffuf_failures[:3]) if ffuf_failures else None,
        )
    else:
        log("[i] FFUF skip (config: ffuf_enabled=False).")
        ffuf_results = {}

    gobuster_results, ffuf_results, soft_error_filter = _filter_soft_error_discovery(
        web_urls=web_urls,
        gobuster_results=gobuster_results,
        ffuf_results=ffuf_results,
        timeout=max(3, int(config.ffuf_timeout or config.gobuster_timeout or 8)),
    )
    suppressed_soft_error_count = int(soft_error_filter.get("suppressed_count", 0) or 0)
    if suppressed_soft_error_count:
        log(f"[i] Soft-error/generic redirect filter: suppressed={suppressed_soft_error_count}")
        if config.gobuster_enabled:
            gobuster_artifact = {
                "summary": _summarize_gobuster(gobuster_results),
                "results": gobuster_results,
                "soft_error_filter": soft_error_filter,
            }
            if "gobuster_failures" in locals() and gobuster_failures:
                gobuster_artifact["failures"] = gobuster_failures
            _write_json_artifact(gobuster_json_path, gobuster_artifact)
        if config.ffuf_enabled:
            ffuf_artifact = {
                "summary": _summarize_ffuf(ffuf_results),
                "runs": ffuf_runs if "ffuf_runs" in locals() else {},
                "findings_by_base": ffuf_results,
                "soft_error_filter": soft_error_filter,
            }
            if "ffuf_failures" in locals() and ffuf_failures:
                ffuf_artifact["failures"] = ffuf_failures
            _write_json_artifact(ffuf_json_path, ffuf_artifact)

    # Katana expansion: crawl a limited set of high-value Gobuster hits
    expansion_seeds: list[str] = []
    for results in gobuster_results.values():
        if not results:
            continue
        for item in results:
            u = item.get("url")
            if u:
                expansion_seeds.append(u)

    # de-dup and prioritize keywords
    expansion_seeds = sorted(set(expansion_seeds))
    high_value = [u for u in expansion_seeds if _is_high_value_url(u)]

    # If there are no high-value URLs, fall back to a small sample of whatever Gobuster found
    if high_value:
        expansion_seeds = high_value

    # Cap to avoid overload (batch/scheduler will improve later)
    expansion_seeds = expansion_seeds[: max(1, int(config.expansion_cap))]

    if config.katana_enabled and config.expansion_enabled and expansion_seeds:
        expansion_katana_traffic = dict(katana_traffic)
        if requested_traffic_profile == "fast" and len(expansion_seeds) > 10:
            expansion_katana_traffic = dict(_resolve_traffic_profile("balanced")["katana"])
            _record_auto_throttle(
                traffic_state,
                stage="katana_expansion",
                from_profile="fast",
                to_profile="balanced",
                reason=f"expansion seed sayısı yüksek ({len(expansion_seeds)})",
            )
            info(f"[!] Auto throttle aktif: Katana expansion FAST -> BALANCED (seed={len(expansion_seeds)})")

        log(f"[+] Katana expansion başlatılıyor... (seed URLs: {len(expansion_seeds)})")
        expansion_diagnostics = {}
        try:
            katana_expanded = run_katana(
                expansion_seeds,
                depth=config.expansion_depth,
                js_crawl=config.katana_js_crawl,
                auto_js_crawl=config.katana_auto_js_crawl,
                timeout_sec=config.katana_timeout_sec,
                max_urls=config.katana_max_urls,
                diagnostics=expansion_diagnostics,
                concurrency=expansion_katana_traffic["concurrency"],
                parallelism=expansion_katana_traffic["parallelism"],
                rate_limit=expansion_katana_traffic["rate_limit"],
                delay_sec=expansion_katana_traffic["delay_sec"],
            )
            log(f"[+] Katana expansion bitti. Bulunan ek endpoint/URL: {len(katana_expanded)}")
        except Exception as e:
            print(f"[!] Katana expansion hata: {e}")
            expansion_diagnostics["errors"] = [str(e)]
            katana_expanded = []

        if expansion_diagnostics.get("errors"):
            _stage_finish(stages, "katana", "partial", error="; ".join(expansion_diagnostics["errors"][:3]))

        # Merge into main katana URL pool
        if katana_expanded:
            katana_urls = sorted(set(katana_urls).union(katana_expanded))
            if config.katana_max_urls:
                katana_urls = katana_urls[:config.katana_max_urls]
            _write_text_artifact(katana_txt_path, "\n".join(katana_urls))
            _write_json_artifact(katana_json_path, {"seed_urls": web_urls, "urls": katana_urls, "expanded_urls": katana_expanded})
            if stages["katana"]["status"] == "done":
                stages["katana"]["artifacts"] = {
                    "txt": _artifact_ref(katana_txt_path),
                    "json": _artifact_ref(katana_json_path),
                }


    # WAF detection per live base URL
    if web_urls and config.wafw00f_enabled:
        _stage_set_running(stages, "wafw00f")
        log(f"[+] WAFW00F başlatılıyor... (base URLs: {len(web_urls)})")
        try:
            for base_url in web_urls:
                waf_result = run_wafw00f(base_url)
                wafw00f_results[base_url] = waf_result

            _write_json_artifact(wafw00f_json_path, wafw00f_results)

            detected_count = sum(
                1 for item in wafw00f_results.values()
                if isinstance(item, dict) and bool(item.get("detected"))
            )
            log(f"[+] WAFW00F bitti. scanned={len(wafw00f_results)} detected={detected_count}")
            adaptive_recon = _apply_adaptive_recon(
                requested_profile=requested_traffic_profile,
                current_effective_profile=str(traffic_state.get("effective_profile") or requested_traffic_profile),
                base_checks_traffic=checks_traffic,
                wafw00f_results=wafw00f_results,
                traffic_state=traffic_state,
            )
            effective_checks_traffic = dict(adaptive_recon.get("effective_checks", checks_traffic) or checks_traffic)
            if adaptive_recon.get("active"):
                info(
                    f"[!] Adaptive recon aktif: post-WAF checks profile -> {adaptive_recon.get('effective_profile')} "
                    f"| vendors={', '.join(adaptive_recon.get('waf_vendors', [])[:3])} "
                    f"| checks(rps={effective_checks_traffic.get('requests_per_second')},delay={effective_checks_traffic.get('delay_ms')}ms)"
                )
                
            _stage_finish(
                stages,
                "wafw00f",
                result_coverage_status(wafw00f_results)[0],
                error=result_coverage_status(wafw00f_results)[1],
                artifacts={"json": _artifact_ref(wafw00f_json_path)},
            )
        except Exception as e:
            print(f"[!] WAFW00F hata: {e}")
            wafw00f_results = {}
            _write_json_artifact(wafw00f_json_path, {"error": str(e), "results": {}})
            traffic_state["adaptive_recon"] = {"active": False, "mode": "standard", "reason": f"wafw00f error: {e}"}
            _stage_finish(
                stages,
                "wafw00f",
                "error",
                artifacts={"json": _artifact_ref(wafw00f_json_path)},
                error=str(e),
            )
    else:
        _stage_finish(stages, "wafw00f", "skipped")
        traffic_state["adaptive_recon"] = {"active": False, "mode": "standard", "reason": "wafw00f skipped"}

    # WhatWeb: technology fingerprint enrichment per live base URL
    if web_urls and config.whatweb_enabled:
        _stage_set_running(stages, "whatweb")
        log(f"[+] WhatWeb başlatılıyor... (base URLs: {len(web_urls)})")
        try:
            for base_url in web_urls[:50]:
                whatweb_result = run_whatweb(
                    base_url,
                    timeout_seconds=90,
                    aggression=1,
                    follow_redirect="never",
                )
                whatweb_results[base_url] = whatweb_result

            _write_json_artifact(whatweb_json_path, whatweb_results)

            detected_count = sum(
                1 for item in whatweb_results.values()
                if isinstance(item, dict) and bool(item.get("plugin_names"))
            )
            plugin_names = sorted(
                {
                    plugin_name
                    for item in whatweb_results.values()
                    if isinstance(item, dict)
                    for plugin_name in (item.get("plugin_names") or [])
                    if plugin_name
                }
            )
            log(
                f"[+] WhatWeb bitti. scanned={len(whatweb_results)} detected={detected_count} "
                f"plugins={', '.join(plugin_names[:8]) if plugin_names else '-'}"
            )
            _stage_finish(
                stages,
                "whatweb",
                result_coverage_status(whatweb_results)[0],
                error=result_coverage_status(whatweb_results)[1],
                artifacts={"json": _artifact_ref(whatweb_json_path)},
            )
        except Exception as e:
            print(f"[!] WhatWeb hata: {e}")
            whatweb_results = {}
            _write_json_artifact(whatweb_json_path, {"error": str(e), "results": {}})
            _stage_finish(
                stages,
                "whatweb",
                "error",
                artifacts={"json": _artifact_ref(whatweb_json_path)},
                error=str(e),
            )
    else:
         _stage_finish(stages, "whatweb", "skipped")

    # Active candidate validation: only confirmed discovered endpoint candidates
    # feed classification, endpoint analysis, checks, graph evidence, and nuclei targets.
    validation_candidates: list[dict[str, str]] = []

    def _add_validation_candidate(source: str, url: object, detail: str = "") -> None:
        candidate_url = str(url or "").strip()
        if not candidate_url:
            return
        validation_candidates.append(
            {"source": source, "url": candidate_url, "detail": str(detail or "")}
        )

    for url in katana_urls:
        _add_validation_candidate("katana", url)
    for url in historical_interesting_live_urls or historical_live_urls:
        _add_validation_candidate("historical_urls", url)
    for base_url, results in gobuster_results.items():
        if not isinstance(results, list):
            continue
        for item in results:
            if isinstance(item, dict):
                _add_validation_candidate("gobuster", item.get("url"), base_url)
    for base_url, results in ffuf_results.items():
        if not isinstance(results, list):
            continue
        for item in results:
            if isinstance(item, dict):
                _add_validation_candidate("ffuf", item.get("url"), base_url)

    candidate_validation = _active_validate_endpoint_candidates(
        candidate_records=validation_candidates,
        base_urls=web_urls,
        existing_baselines=soft_error_filter.get("baselines") if isinstance(soft_error_filter, dict) else {},
        timeout=max(3, int(config.checks_timeout_sec or config.ffuf_timeout or config.gobuster_timeout or 8)),
    )
    candidate_suppressed_count = int(candidate_validation.get("suppressed_count", 0) or 0)
    if candidate_suppressed_count:
        log(f"[i] Active endpoint validation: suppressed={candidate_suppressed_count}")
    confirmed_candidate_urls = [
        str(url or "").strip()
        for url in (candidate_validation.get("confirmed_urls") or [])
        if str(url or "").strip()
    ]

    # Build URL pool for lightweight web checks (login/captcha/docs/rate-limit)
    checks_urls: list[str] = []
    checks_urls.extend(web_urls)
    checks_urls.extend(confirmed_candidate_urls)

    # Add Gobuster-discovered URLs (from ALL base URLs)
    for results in gobuster_results.values():
        if not results:
            continue
        for item in results:
            u = item.get("url")
            if u and _validated_url_allowed(u, candidate_validation):
                checks_urls.append(u)
    for results in ffuf_results.values():
        if not results:
            continue
        for item in results:
            if not isinstance(item, dict):
                continue
            u = item.get("url")
            if u and _validated_url_allowed(u, candidate_validation):
                checks_urls.append(str(u))

    # Normalize + filter (reuse nuclei hygiene helpers)
    cleaned_checks: list[str] = []
    for target_url in checks_urls:
        normalized_url = _normalize_for_nuclei(target_url, drop_query=True)
        if not normalized_url:
            continue
        if _is_static_asset(normalized_url):
            continue
        cleaned_checks.append(normalized_url)

    checks_urls = sorted(set(cleaned_checks))
    checks_urls = checks_urls[: max(0, int(config.checks_pool_limit))]
    log(f"[+] Checks URL havuzu: {len(checks_urls)}")

    # --- Sensitive endpoint classification ---
    endpoint_pool: list[str] = []
    endpoint_pool.extend(web_urls)
    endpoint_pool.extend(confirmed_candidate_urls)

    for results in gobuster_results.values():
        if not results:
            continue
        for item in results:
            u = item.get("url")
            if u and _validated_url_allowed(u, candidate_validation):
                endpoint_pool.append(u)
    for results in ffuf_results.values():
        if not results:
            continue
        for item in results:
            if not isinstance(item, dict):
                continue
            u = item.get("url")
            if u and _validated_url_allowed(u, candidate_validation):
                endpoint_pool.append(str(u))

    validated_gobuster_results: dict[str, list[dict[str, Any]]] = {}
    for base_url, results in gobuster_results.items():
        if not isinstance(results, list):
            continue
        kept = [item for item in results if isinstance(item, dict) and _validated_url_allowed(item.get("url"), candidate_validation)]
        if kept:
            validated_gobuster_results[base_url] = kept

    validated_ffuf_results: dict[str, list[dict[str, Any]]] = {}
    for base_url, results in ffuf_results.items():
        if not isinstance(results, list):
            continue
        kept = [item for item in results if isinstance(item, dict) and _validated_url_allowed(item.get("url"), candidate_validation)]
        if kept:
            validated_ffuf_results[base_url] = kept

    readable_surface_urls, forbidden_surface_urls = _collect_scanner_urls_by_status(
        validated_gobuster_results,
        validated_ffuf_results,
    )
    fallback_classified_endpoints, blocked_structural_candidates = _classify_endpoints_with_status(
        endpoint_pool,
        readable_urls=readable_surface_urls,
        forbidden_urls=forbidden_surface_urls,
    )
    endpoint_analysis_dict = summary_to_dict(
        analyze_endpoints(
            web_urls=web_urls,
            katana_urls=confirmed_candidate_urls,
            gobuster_results=validated_gobuster_results,
            ffuf_results=validated_ffuf_results,
            classified_endpoints=fallback_classified_endpoints,
        )
    )
    # TODO(phase-2): consider a lightweight second-pass endpoint_analysis enrichment
    # using web checks / auth_profile signals (e.g., login/reset flows) to improve
    # bucket labeling, without changing the main run flow in this phase.
    # Two-layer model:
    # - Base inventory: fallback_classified_endpoints (authoritative for surface/scoring/graph)
    # - Analysis overlay: endpoint_analysis_dict["reportworthy_endpoints_by_bucket"] (high-signal subset for reporting)
    classified_endpoints = fallback_classified_endpoints

    # Run lightweight web checks (login/captcha/docs/rate-limit + captcha coverage heuristics)
    if config.checks_enabled:
        effective_checks_traffic = dict(checks_traffic)
        if requested_traffic_profile == "fast" and len(checks_urls) > 40:
            effective_checks_traffic = dict(_resolve_traffic_profile("balanced")["web_checks"])
            _record_auto_throttle(
                traffic_state,
                stage="web_checks",
                from_profile="fast",
                to_profile="balanced",
                reason=f"checks URL havuzu yüksek ({len(checks_urls)})",
            )
            info(f"[!] Auto throttle aktif: Web checks FAST -> BALANCED (pool={len(checks_urls)})")

        _stage_set_running(stages, "checks")
        log("[+] Web checks başlatılıyor...")
        try:
            checks_results = run_web_checks(
                checks_urls,
                max_urls=config.checks_max_urls,
                timeout_sec=config.checks_timeout_sec,
                max_body_bytes=config.checks_max_body_bytes,
                follow_redirects=config.checks_follow_redirects,
                requests_per_second=effective_checks_traffic["requests_per_second"],
                delay_ms=effective_checks_traffic["delay_ms"],
            )
            
            checks_results["waf_signals"] = wafw00f_results
            checks_results["whatweb_signals"] = whatweb_results
            checks_results["adaptive_recon"] = traffic_state.get("adaptive_recon", {})
            tech_fp: Any = checks_results.get("technology_fingerprint", []) or []
            if not isinstance(tech_fp, list):
                tech_fp = []

            whatweb_plugins = sorted(
            {
                plugin_name
                for item in whatweb_results.values()
                if isinstance(item, dict)
                for plugin_name in (item.get("plugin_names") or [])
                if plugin_name
            }
            )

            if whatweb_plugins:
                tech_fp.append(
                    {
                        "site": "whatweb-derived",
                        "source_type": "derived_whatweb",
                        "derived": True,
                        "server": None,
                        "x_powered_by": None,
                        "technologies": whatweb_plugins,
                        "waf_signals": [],
                        "owasp_hint": "WhatWeb fingerprint present",
                    }
                )
            # Unified auth surface / login flow profiler
            try:
                # Provide the full base classified inventory to the profiler as context
                # (auth profiler is additive; it should not be limited to the analysis overlay).
                auth_profiler_context = dict(checks_results)
                auth_profiler_context["classified_endpoints"] = _clone_classified_endpoints(
                    classified_endpoints
                )
                auth_profile = build_auth_profile(
                    checks_results=auth_profiler_context,
                    endpoint_analysis=endpoint_analysis_dict,
                )
            except Exception as e:
                auth_profile = _empty_auth_profile() | {"error": str(e)}

            attack_chains = _build_attack_chains(
                classified_endpoints,
                checks_results.get("technology_fingerprint", []),
            )
            
            # Fold wafw00f vendor detections into technology fingerprint as WAF signals
            tech_fp = checks_results.get("technology_fingerprint", []) or []
            if not isinstance(tech_fp, list):
                tech_fp = []

            waf_vendors = []
            for item in wafw00f_results.values():
                if not isinstance(item, dict):
                    continue
                if item.get("detected") and item.get("vendor"):
                    waf_vendors.append(str(item.get("vendor")))

            if waf_vendors:
                tech_fp.append(
                    {
                        "site": "wafw00f-derived",
                        "source_type": "derived_wafw00f",
                        "derived": True,
                        "server": "",
                        "x_powered_by": "",
                        "technologies": [],
                        "waf_signals": sorted(set(waf_vendors)),
                    }
                )

            checks_results["technology_fingerprint"] = tech_fp

            attack_graph = _build_attack_graph(
                classified_endpoints,
                checks_results.get("technology_fingerprint", []),
                attack_chains,
            )
            attack_graph = _augment_attack_graph_with_auth_profile(attack_graph, auth_profile)

            # --- CVE Enrichment (technology -> NVD lookup) ---
            cve_queries = _extract_cve_queries(tech_fp)

            cve_matches: list[dict[str, Any]] = []

            for q in cve_queries:
                keyword = q.get("keyword")
                if not keyword:
                    continue

                raw_cves = _fetch_nvd_keyword_cves(keyword)
                cves = [
                    _score_cve_relevance(
                        {
                            **raw_cve,
                            "query_product": q.get("product"),
                            "query_version": q.get("version"),
                        },
                        classified_endpoints,
                        tech_fp,
                    )
                    for raw_cve in raw_cves
                ]
                cves = sorted(
                    cves,
                    key=lambda item: int(item.get("relevance_score", 0)),
                    reverse=True,
                )

                if not cves:
                    continue

                cve_matches.append(
                    {
                        "product": q.get("product"),
                        "version": q.get("version"),
                        "evidence": q.get("evidence"),
                        "keyword": keyword,
                        "cves": cves,
                    }
                )

            cve_enrichment = {
                "query_count": len(cve_queries),
                "matches": cve_matches,
            }
            exploit_suggestions = _build_exploit_suggestions(
                classified_endpoints,
                tech_fp,
                attack_chains,
                attack_graph,
                cve_enrichment,
            )
            exploit_suggestions = _augment_exploit_suggestions_with_auth_profile(exploit_suggestions, auth_profile)
            node_relationships = _build_node_relationships(
                classified_endpoints,
                attack_graph,
                exploit_suggestions,
                checks_results.get("technology_fingerprint", []),
                cve_enrichment,
            )
            node_relationships = _augment_node_relationships_with_auth_profile(node_relationships, auth_profile)

            checks_signal_payload = checks_results if isinstance(checks_results, dict) else {}
            checks_results = _build_checks_results_base(
                classified_endpoints=classified_endpoints,
                ffuf_results=validated_ffuf_results,
                endpoint_analysis_dict=endpoint_analysis_dict,
                wafw00f_results=wafw00f_results,
                whatweb_results=whatweb_results,
                traffic_state=traffic_state,
                technology_fingerprint=checks_results.get("technology_fingerprint", []),
                attack_chains=attack_chains,
                attack_graph=attack_graph,
                exploit_suggestions=exploit_suggestions,
                node_relationships=node_relationships,
                auth_profile=auth_profile,
                checks_signal_payload=checks_signal_payload,
                blocked_structural_candidates=blocked_structural_candidates,
                soft_error_filter=soft_error_filter,
                candidate_validation=candidate_validation,
            )
            checks_results = _attach_ip_enrichment_snapshot(checks_results)
            checks_results["cve_enrichment"] = cve_enrichment
            checks_results["historical_urls"] = historical_results

            _write_json_artifact(checks_json_path, checks_results)
            log(
                "[+] Web checks bitti. "
                f"checked={checks_results.get('checked_count', 0)} "
                f"login={len(checks_results.get('login_pages', []))} "
                f"captcha={len(checks_results.get('captcha_pages', []))} "
                f"docs={len(checks_results.get('docs_pages', []))} "
                f"ratelimit={len(checks_results.get('rate_limit_signals', []))}"
            )
            if checks_results.get("rate_limit_signals") or checks_results.get("captcha_pages"):
                traffic_state["recommended_profile"] = "safe"
                info("[!] Rate-limit/captcha sinyali görüldü. Sonraki run için SAFE profil önerilir.")
            check_errors = checks_results.get("errors") or []
            check_status = ("partial" if checks_results.get("checked_count", 0) else "error") if check_errors else "done"
            _stage_finish(
                stages,
                "checks",
                check_status,
                error="; ".join(str(item) for item in check_errors[:3]) or None,
                failed_url_count=len(check_errors),
                artifacts={"json": _artifact_ref(checks_json_path)},
            )
        except Exception as e:
            print(f"[!] Web checks hata: {e}")
            attack_chains = _build_attack_chains(classified_endpoints, [])
            attack_graph = _build_attack_graph(classified_endpoints, [], attack_chains)
            exploit_suggestions = _build_exploit_suggestions(
                classified_endpoints,
                [],
                attack_chains,
                attack_graph,
                {},
            )

            node_relationships = _build_node_relationships(
                classified_endpoints,
                attack_graph,
                exploit_suggestions,
                [],
                {},
            )

            checks_results = _build_checks_results_base(
                classified_endpoints=classified_endpoints,
                ffuf_results=validated_ffuf_results,
                endpoint_analysis_dict=endpoint_analysis_dict,
                wafw00f_results=wafw00f_results,
                whatweb_results=whatweb_results,
                traffic_state=traffic_state,
                technology_fingerprint=[],
                attack_chains=attack_chains,
                attack_graph=attack_graph,
                exploit_suggestions=exploit_suggestions,
                node_relationships=node_relationships,
                auth_profile=_empty_auth_profile() | {"error": str(e)},
                blocked_structural_candidates=blocked_structural_candidates,
                soft_error_filter=soft_error_filter,
                candidate_validation=candidate_validation,
            )
            checks_results = _attach_ip_enrichment_snapshot(checks_results)
            checks_results["error"] = str(e)
            checks_results["cve_enrichment"] = {"query_count": 0, "matches": []}
            checks_results["historical_urls"] = historical_results
            _write_json_artifact(checks_json_path, checks_results)
            _stage_finish(
                stages,
                "checks",
                "error",
                artifacts={"json": _artifact_ref(checks_json_path)},
                error=str(e),
            )
    else:
        log("[+] Web checks atlandı (config).")
        attack_chains = _build_attack_chains(classified_endpoints, [])
        attack_graph = _build_attack_graph(classified_endpoints, [], attack_chains)
        exploit_suggestions = _build_exploit_suggestions(
            classified_endpoints,
            [],
            attack_chains,
            attack_graph,
            {},
        )
        node_relationships = _build_node_relationships(
            classified_endpoints,
            attack_graph,
            exploit_suggestions,
            [],
            {},
        )

        checks_results = _build_checks_results_base(
            classified_endpoints=classified_endpoints,
            ffuf_results=validated_ffuf_results,
            endpoint_analysis_dict=endpoint_analysis_dict,
            wafw00f_results=wafw00f_results,
            whatweb_results=whatweb_results,
            traffic_state=traffic_state or {},
            technology_fingerprint=[],
            attack_chains=attack_chains,
            attack_graph=attack_graph,
            exploit_suggestions=exploit_suggestions,
            node_relationships=node_relationships,
            auth_profile=_empty_auth_profile(),
            blocked_structural_candidates=blocked_structural_candidates,
            soft_error_filter=soft_error_filter,
            candidate_validation=candidate_validation,
        )
        checks_results = _attach_ip_enrichment_snapshot(checks_results)
        checks_results["cve_enrichment"] = {"query_count": 0, "matches": []}
        checks_results["historical_urls"] = historical_results

    if config.screenshots_enable:
        _stage_set_running(stages, "screenshots")
        try:
            screenshots_results = capture_screenshots(
                target=target,
                run_dir=run_dir,
                httpx_live_urls=web_urls,
                checks_results=checks_results,
                historical_results=historical_results,
                limit=resolved_screenshots_limit,
                timeout_sec=resolved_screenshots_timeout,
            )
            checks_results["screenshots"] = screenshots_results
            _write_json_artifact(checks_json_path, checks_results)
            selection = screenshots_results.get("selection") if isinstance(screenshots_results.get("selection"), dict) else {}
            received = int(screenshots_results.get("received", selection.get("received", 0)) or 0)
            selected_count = int(screenshots_results.get("selected_count", selection.get("selected_count", 0)) or 0)
            max_count = int(screenshots_results.get("max", resolved_screenshots_limit) or 0)
            reason = str(screenshots_results.get("reason", selection.get("reason", "none")) or "none")
            info(
                "[i] Screenshot capture: "
                f"received={received}, selected={selected_count}, max={max_count}, reason={reason}"
            )
            warnings = screenshots_results.get("warnings") if isinstance(screenshots_results.get("warnings"), list) else []
            for warning in warnings[:3]:
                info(f"[!] Screenshot warning: {warning}")
            screenshot_status = str(screenshots_results.get("status") or "done").strip().lower()
            if screenshot_status in {"failed", "partial", "error", "timeout"}:
                artifacts = screenshots_results.get("artifacts") if isinstance(screenshots_results.get("artifacts"), dict) else {}
                stderr_tail = str(screenshots_results.get("stderr_tail") or "").strip()
                info(
                    "[!] Screenshot debug: "
                    f"selected_count={selected_count}, "
                    f"produced_file_count={int(screenshots_results.get('produced_file_count', 0) or 0)}, "
                    f"output_dir={artifacts.get('output_dir', 'screenshots/files')}, "
                    f"gowitness_exit_code={screenshots_results.get('exit_code', 'n/a')}"
                )
                if stderr_tail:
                    info(f"[!] Screenshot stderr tail: {stderr_tail[-500:]}")
            stage_status = "skipped" if screenshot_status in {"missing_tool", "empty"} else ("partial" if screenshot_status == "partial" else ("error" if screenshot_status in {"error", "timeout", "failed"} else "done"))
            _stage_finish(
                stages,
                "screenshots",
                stage_status,
                artifacts={
                    "json": "screenshots.json",
                    "index": "screenshots/index.json",
                    "input": "screenshots/targets.txt",
                    "files": "screenshots/files",
                },
                received=received,
                selected=selected_count,
                max=max_count,
                reason=reason,
                warnings=warnings,
            )
        except Exception as e:
            print(f"[!] Screenshot capture hata: {e}")
            screenshots_results = {
                "enabled": True,
                "tool": "gowitness",
                "status": "error",
                "entries": [],
                "warnings": [str(e)],
            }
            checks_results["screenshots"] = screenshots_results
            _write_json_artifact(checks_json_path, checks_results)
            _stage_finish(
                stages,
                "screenshots",
                "error",
                artifacts={"json": "screenshots.json", "index": "screenshots/index.json"},
                error=str(e),
            )
    else:
        checks_results["screenshots"] = screenshots_results

    # Collect targets for nuclei and retain source labels for diagnostics.
    nuclei_candidate_records: list[dict[str, str]] = []

    def _add_nuclei_candidate(source: str, url: object, detail: str = "") -> None:
        candidate_url = str(url or "").strip()
        if not candidate_url:
            return
        nuclei_candidate_records.append(
            {"source": source, "url": candidate_url, "detail": str(detail or "")}
        )

    for base_url, results in gobuster_results.items():
        if not results:
            continue
        for item in results:
            if not isinstance(item, dict):
                continue
            if _validated_url_allowed(item.get("url"), candidate_validation):
                _add_nuclei_candidate("gobuster", item.get("url"), base_url)
    for base_url, results in ffuf_results.items():
        if not results:
            continue
        for item in results:
            if not isinstance(item, dict):
                continue
            if _validated_url_allowed(item.get("url"), candidate_validation):
                _add_nuclei_candidate("ffuf", item.get("url"), base_url)

    for url in web_urls:
        _add_nuclei_candidate("web_urls", url)
    for url in katana_urls:
        if _validated_url_allowed(url, candidate_validation):
            _add_nuclei_candidate("katana", url)
    for url in historical_interesting_live_urls:
        if _validated_url_allowed(url, candidate_validation):
            _add_nuclei_candidate("historical_urls", url, "interesting_live")

    # Some CGI/LFI labs expose the dangerous handler behind a front controller:
    # /index.php/cgi-bin/cgiServer.exx?page=../../../etc/passwd. If discovery
    # finds both /cgi-bin/ and /index.php on the same origin, add this single
    # high-signal candidate instead of expanding every discovered URL.
    cgi_origins: set[tuple[str, str]] = set()
    index_origins: set[tuple[str, str]] = set()
    for record in nuclei_candidate_records:
        parts = urlsplit(record["url"])
        if not parts.scheme or not parts.netloc:
            continue
        origin = (parts.scheme, parts.netloc)
        path = (parts.path or "/").lower()
        if "/cgi-bin" in path:
            cgi_origins.add(origin)
        if path == "/index.php" or path.startswith("/index.php/"):
            index_origins.add(origin)

    derived_cgi_lfi_urls: list[str] = []
    lfi_payload = "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    for scheme, netloc in sorted(cgi_origins):
        derived_cgi_lfi_urls.append(
            urlunsplit((scheme, netloc, "/cgi-bin/cgiServer.exx", f"page={lfi_payload}", ""))
        )
        if (scheme, netloc) in index_origins:
            derived_cgi_lfi_urls.append(
                urlunsplit(
                    (scheme, netloc, "/index.php/cgi-bin/cgiServer.exx", f"page={lfi_payload}", "")
                )
            )
    existing_candidate_urls = {record["url"] for record in nuclei_candidate_records}
    for derived_url in derived_cgi_lfi_urls:
        if derived_url not in existing_candidate_urls:
            _add_nuclei_candidate("derived_cgi_lfi", derived_url, "cgi-bin+index.php")
            existing_candidate_urls.add(derived_url)

    raw_nuclei_candidates = [record["url"] for record in nuclei_candidate_records]
    nuclei_drop_reasons: dict[str, int] = {}
    nuclei_drop_debug: list[dict[str, str]] = []

    def _bump_drop(reason: str, count: int = 1) -> None:
        nuclei_drop_reasons[reason] = nuclei_drop_reasons.get(reason, 0) + max(0, int(count))

    def _record_drop(
        stage: str,
        reason: str,
        record: dict[str, str],
        normalized_url: str = "",
    ) -> None:
        _bump_drop(reason)
        nuclei_drop_debug.append(
            {
                "stage": stage,
                "reason": reason,
                "source": str(record.get("source") or ""),
                "detail": str(record.get("detail") or ""),
                "raw": str(record.get("url") or ""),
                "normalized": normalized_url,
            }
        )

    _write_text_artifact(
        nuclei_candidates_debug_path,
        "\n".join(
            f"{idx}\t{record['source']}\t{record.get('detail', '')}\t{record['url']}"
            for idx, record in enumerate(nuclei_candidate_records, start=1)
        ),
    )

    # Normalize targets first
    normalized_records: list[dict[str, str]] = []
    for record in nuclei_candidate_records:
        target_url = record["url"]
        if not str(target_url or "").strip():
            _record_drop("normalize", "empty_input", record)
            continue
        normalized_url = _normalize_for_nuclei(
            target_url,
            drop_query=config.nuclei_drop_query,
            preserve_high_value_query=True,
        )
        if not normalized_url:
            _record_drop("normalize", "normalization_empty", record)
            continue
        normalized_record = dict(record)
        normalized_record["normalized"] = normalized_url
        normalized_record["high_value"] = str(_is_high_value_nuclei_candidate(target_url)).lower()
        normalized_records.append(normalized_record)

    _write_text_artifact(
        nuclei_normalized_debug_path,
        "\n".join(
            f"{idx}\t{record['source']}\t{record.get('detail', '')}\t"
            f"high_value={record.get('high_value', 'false')}\t{record['url']}\t"
            f"=>\t{record['normalized']}"
            for idx, record in enumerate(normalized_records, start=1)
        ),
    )

    # Filter static assets
    filtered_records: list[dict[str, str]] = []
    for record in normalized_records:
        normalized_url = record["normalized"]
        if _is_static_asset(normalized_url):
            _record_drop("filter", "static_asset", record, normalized_url)
            continue
        filtered_records.append(record)

    # Deduplicate (stable) then keep sorted output for deterministic artifacts
    deduped_records: list[dict[str, str]] = []
    seen_targets: set[str] = set()
    for record in filtered_records:
        normalized_url = record["normalized"]
        if normalized_url in seen_targets:
            _record_drop("dedupe", "duplicate", record, normalized_url)
            continue
        seen_targets.add(normalized_url)
        deduped_records.append(record)

    targets = sorted(record["normalized"] for record in deduped_records)
    pool_limit = max(0, int(config.nuclei_pool_limit))
    trimmed_targets = set(targets[pool_limit:]) if len(targets) > pool_limit else set()
    if trimmed_targets:
        _bump_drop("pool_limit_trim", len(trimmed_targets))
        for record in deduped_records:
            normalized_url = record["normalized"]
            if normalized_url in trimmed_targets:
                nuclei_drop_debug.append(
                    {
                        "stage": "final",
                        "reason": "pool_limit_trim",
                        "source": str(record.get("source") or ""),
                        "detail": str(record.get("detail") or ""),
                        "raw": str(record.get("url") or ""),
                        "normalized": normalized_url,
                    }
                )
    targets = targets[:pool_limit]

    nuclei_targets_count = len(targets)
    _write_text_artifact(targets_txt_path, "\n".join(targets))

    # Analysis-driven prioritized subset for future staged nuclei targeting.
    # TODO(phase-2): feed this subset into adaptive template/family selection logic.
    prioritized_candidate_records: list[dict[str, str]] = []

    def _add_prioritized_candidate(source: str, url: object, detail: str = "") -> None:
        candidate_url = str(url or "").strip()
        if not candidate_url:
            return
        prioritized_candidate_records.append(
            {"source": source, "url": candidate_url, "detail": str(detail or "")}
        )

    reportworthy_endpoints = checks_results.get("reportworthy_endpoints", {}) if isinstance(checks_results, dict) else {}
    if isinstance(reportworthy_endpoints, dict):
        for bucket, urls in reportworthy_endpoints.items():
            if isinstance(urls, list):
                for u in urls:
                    _add_prioritized_candidate("checks_reportworthy", u, str(bucket))
    for fam in checks_results.get("suspicious_families", []) if isinstance(checks_results, dict) else []:
        if isinstance(fam, dict):
            rep = str(fam.get("representative_url") or "").strip()
            if rep:
                _add_prioritized_candidate("checks_suspicious_family", rep, str(fam.get("family") or ""))
    for u in checks_results.get("katana_cleaned_urls", []) if isinstance(checks_results, dict) else []:
        url = str(u or "").strip()
        if url:
            _add_prioritized_candidate("checks_katana_cleaned", url)
    # Promote suspicious/LFI-looking URLs seen during raw target collection.
    for record in nuclei_candidate_records:
        raw_url = record["url"]
        if _is_high_value_nuclei_candidate(raw_url) and _validated_url_allowed(raw_url, candidate_validation):
            _add_prioritized_candidate(
                f"high_value_{record.get('source', 'candidate')}",
                raw_url,
                record.get("detail", ""),
            )

    prioritized_normalized: list[str] = []
    prioritized_seen: set[str] = set()
    prioritized_debug: list[dict[str, str]] = []
    for record in prioritized_candidate_records:
        target_url = record["url"]
        normalized_url = _normalize_for_nuclei(
            target_url,
            drop_query=config.nuclei_drop_query,
            preserve_high_value_query=True,
        )
        drop_reason = ""
        if not normalized_url:
            drop_reason = "normalization_empty"
        elif _is_static_asset(normalized_url):
            drop_reason = "static_asset"
        elif normalized_url in prioritized_seen:
            drop_reason = "duplicate"
        prioritized_debug.append(
            {
                "source": str(record.get("source") or ""),
                "detail": str(record.get("detail") or ""),
                "raw": target_url,
                "normalized": normalized_url,
                "status": "dropped" if drop_reason else "kept",
                "reason": drop_reason,
            }
        )
        if drop_reason:
            continue
        prioritized_seen.add(normalized_url)
        prioritized_normalized.append(normalized_url)
    prioritized_normalized = prioritized_normalized[: max(0, min(int(config.nuclei_pool_limit), 1000))]
    checks_results["nuclei_prioritized_targets"] = prioritized_normalized
    _write_text_artifact(prioritized_targets_txt_path, "\n".join(prioritized_normalized))
    _write_text_artifact(
        nuclei_prioritized_debug_path,
        "\n".join(
            f"{idx}\t{record['status']}\t{record['reason']}\t{record['source']}\t"
            f"{record.get('detail', '')}\t{record['raw']}\t=>\t{record['normalized']}"
            for idx, record in enumerate(prioritized_debug, start=1)
        ),
    )
    _write_text_artifact(
        nuclei_dropped_debug_path,
        "\n".join(
            f"{idx}\t{record['stage']}\t{record['reason']}\t{record['source']}\t"
            f"{record.get('detail', '')}\t{record['raw']}\t=>\t{record['normalized']}"
            for idx, record in enumerate(nuclei_drop_debug, start=1)
        ),
    )

    dropped_total = sum(int(v) for v in nuclei_drop_reasons.values())
    dropped_reason_summary = ", ".join(
        f"{k}={v}" for k, v in sorted(nuclei_drop_reasons.items()) if int(v) > 0
    ) or "-"
    log(
        "[i] Nuclei target selection: "
        f"candidates={len(raw_nuclei_candidates)} "
        f"normalized={len(normalized_records)} "
        f"filtered={len(filtered_records)} "
        f"prioritized={len(prioritized_normalized)} "
        f"final={nuclei_targets_count} "
        f"dropped={dropped_total} "
        f"reasons={dropped_reason_summary}"
    )

    if not config.nuclei_enabled:
        log("[+] Nuclei atlandı (config).")
        _stage_finish(
            stages,
            "nuclei",
            "skipped",
            artifacts={
                "targets": _artifact_ref(targets_txt_path),
                "prioritized_targets": _artifact_ref(prioritized_targets_txt_path),
            },
        )
        _write_run_json(
            target=target,
            mode=mode,
            skipped_tools=skipped_tools,
            nmap_output=nmap_output,
            gobuster_results=gobuster_results,
            ffuf_results=ffuf_results,
            katana_urls=katana_urls,
            checks_results=checks_results,
            nuclei_targets_count=nuclei_targets_count,
            nuclei_output_path=None,
            nuclei_running=False,
            run_dir=run_dir,
            latest_dir=latest_dir,
            run_id=run_id,
            stages=stages,
            traffic_state=traffic_state,
        )
        return RunResult(
            nmap_output=nmap_output,
            gobuster_results=gobuster_results,
            katana_urls=katana_urls,
            checks_results=checks_results,
            nuclei_results=nuclei_results,
            nuclei_proc=None,
            nuclei_output_path=None,
            nuclei_log_path=None,
        )

    if not targets:
        log("[+] Nuclei için uygun target bulunamadı. Nuclei atlanıyor.")
        _stage_finish(
            stages,
            "nuclei",
            "skipped",
            artifacts={
                "targets": _artifact_ref(targets_txt_path),
                "prioritized_targets": _artifact_ref(prioritized_targets_txt_path),
            },
            reason="uygun target bulunamadı",
        )
        _write_run_json(
            target=target,
            mode=mode,
            skipped_tools=skipped_tools,
            nmap_output=nmap_output,
            gobuster_results=gobuster_results,
            ffuf_results=ffuf_results,
            katana_urls=katana_urls,
            checks_results=checks_results,
            nuclei_targets_count=nuclei_targets_count,
            nuclei_output_path=None,
            nuclei_running=False,
            run_dir=run_dir,
            latest_dir=latest_dir,
            run_id=run_id,
            stages=stages,
            traffic_state=traffic_state,
        )
        return RunResult(
            nmap_output=nmap_output,
            gobuster_results=gobuster_results,
            katana_urls=katana_urls,
            checks_results=checks_results,
            nuclei_results=nuclei_results,
            nuclei_proc=None,
            nuclei_output_path=None,
            nuclei_log_path=None,
        )

    # --- Nuclei (non-blocking; CLI will wait + update report) ---
    _stage_set_running(stages, "nuclei")
    nuclei_args: list[str] = []
    if config.nuclei_severity:
        nuclei_args.extend(["-severity", str(config.nuclei_severity)])
    nuclei_args.extend(["-rl", str(resolved_nuclei_rate_limit), "-timeout", str(config.nuclei_timeout_sec)])
    nuclei_proc, nuclei_output_path, nuclei_log_path, _targets_path = start_nuclei(
        targets,
        run_dir=run_dir,
        nuclei_args=nuclei_args,
    )

    if nuclei_proc is None or nuclei_output_path is None:
        log("[+] Nuclei başlatılamadı (proc/output yok). Nuclei atlanıyor.")
        _stage_finish(
            stages,
            "nuclei",
            "error",
            artifacts={
                "targets": _artifact_ref(targets_txt_path),
                "prioritized_targets": _artifact_ref(prioritized_targets_txt_path),
                "log": _artifact_ref(nuclei_log_path),
                "output": _artifact_ref(nuclei_output_path),
            },
            pid=None,
            log_path=_artifact_ref(nuclei_log_path),
            output_path=_artifact_ref(nuclei_output_path),
        )
        _write_run_json(
            target=target,
            mode=mode,
            skipped_tools=skipped_tools,
            nmap_output=nmap_output,
            gobuster_results=gobuster_results,
            ffuf_results=ffuf_results,
            katana_urls=katana_urls,
            checks_results=checks_results,
            nuclei_targets_count=nuclei_targets_count,
            nuclei_output_path=None,
            nuclei_running=False,
            run_dir=run_dir,
            latest_dir=latest_dir,
            run_id=run_id,
            stages=stages,
            traffic_state=traffic_state,
        )
        return RunResult(
            nmap_output=nmap_output,
            gobuster_results=gobuster_results,
            katana_urls=katana_urls,
            checks_results=checks_results,
            nuclei_results={},
            nuclei_proc=None,
            nuclei_output_path=None,
            nuclei_log_path=None,
        )

    _stage_set_running(
        stages,
        "nuclei",
        artifacts={
            "targets": _artifact_ref(targets_txt_path),
            "prioritized_targets": _artifact_ref(prioritized_targets_txt_path),
            "log": _artifact_ref(nuclei_log_path),
            "output": _artifact_ref(nuclei_output_path),
        },
        pid=nuclei_proc.pid,
        log_path=_artifact_ref(nuclei_log_path),
        output_path=_artifact_ref(nuclei_output_path),
    )

    # Snapshot JSON: nuclei is running (report will be updated later by CLI)
    _write_run_json(
        target=target,
        mode=mode,
        skipped_tools=skipped_tools,
        nmap_output=nmap_output,
        gobuster_results=gobuster_results,
        ffuf_results=ffuf_results,
        katana_urls=katana_urls,
        checks_results=checks_results,
        nuclei_targets_count=nuclei_targets_count,
        nuclei_output_path=nuclei_output_path,
        nuclei_running=True,
        run_dir=run_dir,
        latest_dir=latest_dir,
        run_id=run_id,
        stages=stages,
        traffic_state=traffic_state,
    )

    return RunResult(
        nmap_output=nmap_output,
        gobuster_results=gobuster_results,
        katana_urls=katana_urls,
        checks_results=checks_results,
        nuclei_results={},
        nuclei_proc=nuclei_proc,
        nuclei_output_path=nuclei_output_path,
        nuclei_log_path=nuclei_log_path,
    )
