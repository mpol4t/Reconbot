from __future__ import annotations

import re
import shutil
from reconbot.runtime import processes as subprocess
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from typing import Any


AUTH_KEYWORDS = (
    "login",
    "signin",
    "sign-in",
    "admin",
    "dashboard",
    "wp-login",
    "wp-admin",
    "phpmyadmin",
    "pma",
)
API_KEYWORDS = (
    "/api/",
    "/v1/",
    "/v2/",
    "/v3/",
    "graphql",
)
FILE_EXPOSURE_KEYWORDS = (
    ".env",
    ".bak",
    ".backup",
    ".zip",
    ".tar.gz",
    ".tgz",
    ".sql",
    "config",
    "dump",
    "backup",
)
LEGACY_KEYWORDS = (
    "old",
    "backup",
    "staging",
    "stage",
    "dev",
    "test",
    "legacy",
)
UPLOAD_KEYWORDS = (
    "upload",
    "uploads",
    "file",
    "files",
    "import",
)


def _clean_domain_candidate(value: object) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if not text or len(text) > 253:
        return ""
    if "://" in text or "/" in text or "\\" in text or any(ch.isspace() for ch in text):
        return ""
    if text.startswith("*."):
        text = text[2:]
    if text.startswith(".") or text.endswith(".") or ".." in text:
        return ""
    labels = text.split(".")
    if len(labels) < 2:
        return ""
    for label in labels:
        if not label or len(label) > 63:
            return ""
        if label.startswith("-") or label.endswith("-"):
            return ""
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return ""
    return text


def _extract_domain_from_url(value: object) -> str:
    try:
        parsed = urlsplit(str(value or "").strip())
    except Exception:
        return ""
    if parsed.scheme.lower() not in {"http", "https"}:
        return ""
    return _clean_domain_candidate(parsed.hostname or "")


def _is_in_scope_domain(domain: str, root_domain: str) -> bool:
    root = _clean_domain_candidate(root_domain)
    value = _clean_domain_candidate(domain)
    if not root or not value:
        return False
    return value == root or value.endswith("." + root)


def _dedupe_in_scope_domains(values: list[object], *, root_domain: str) -> list[str]:
    cleaned: list[str] = []
    for item in values or []:
        value = _clean_domain_candidate(item)
        if value and _is_in_scope_domain(value, root_domain) and value not in cleaned:
            cleaned.append(value)
    return cleaned


def select_historical_domains(
    *,
    root_domain: str,
    received_candidates: list[object] | None = None,
    resolved_hosts: list[object] | None = None,
    live_urls: list[object] | None = None,
    max_domains: int = 50,
    allow_root_fallback: bool = True,
) -> dict[str, Any]:
    """Select the small domain set allowed to reach archive tools.

    Priority is intentionally conservative: resolved hosts first, live HTTP hosts
    second, and root-domain fallback only when no verified host source exists.
    """
    cap = max(0, int(max_domains))
    root = _clean_domain_candidate(root_domain)
    received_count = len(received_candidates or [])

    resolved = _dedupe_in_scope_domains(list(resolved_hosts or []), root_domain=root)
    live_hosts = _dedupe_in_scope_domains(
        [_extract_domain_from_url(url) for url in (live_urls or [])],
        root_domain=root,
    )

    reason = "none"
    selected: list[str] = []
    if resolved:
        selected = resolved
        reason = "resolved_hosts"
    elif live_hosts:
        selected = live_hosts
        reason = "live_http_hosts"
    elif allow_root_fallback and root:
        selected = [root]
        reason = "root_domain_fallback"

    selected = selected[:cap]
    if cap == 0:
        reason = "max_domain_cap_zero"

    dropped_out_of_scope = 0
    for item in received_candidates or []:
        value = _clean_domain_candidate(item)
        if not value or not _is_in_scope_domain(value, root):
            dropped_out_of_scope += 1

    return {
        "domains": selected,
        "received_count": received_count,
        "selected_count": len(selected),
        "max_domains": cap,
        "selection_reason": reason,
        "resolved_count": len(resolved),
        "live_host_count": len(live_hosts),
        "root_domain": root,
        "dropped_out_of_scope": dropped_out_of_scope,
    }


@dataclass(frozen=True)
class HistoricalUrlRecord:
    url: str
    sources: list[str]
    categories: list[str]
    live: bool = False
    live_check_status: str = "not_checked"

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "sources": list(self.sources),
            "categories": list(self.categories),
            "live": bool(self.live),
            "live_check_status": self.live_check_status,
        }


def normalize_historical_url(raw_url: object) -> str:
    """Normalize archive URLs without collapsing scheme, host, port, or path identity."""
    text = str(raw_url or "").strip()
    if not text:
        return ""

    try:
        parsed = urlsplit(text)
    except Exception:
        return ""

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return ""

    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return ""

    try:
        port = parsed.port
    except ValueError:
        return ""

    netloc = host
    if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"

    path = parsed.path or "/"
    path = re.sub(r"/{2,}", "/", path)
    if not path.startswith("/"):
        path = "/" + path

    query = ""
    if parsed.query:
        try:
            query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
        except Exception:
            query = parsed.query

    return urlunsplit((scheme, netloc, path, query, ""))


def classify_historical_url(url: object) -> list[str]:
    normalized = normalize_historical_url(url)
    if not normalized:
        return []

    parsed = urlsplit(normalized)
    path = (parsed.path or "/").lower()
    query = (parsed.query or "").lower()
    haystack = f"{path}?{query}" if query else path
    categories: list[str] = []

    if any(keyword in haystack for keyword in AUTH_KEYWORDS):
        categories.append("auth_surface")
    if any(keyword in haystack for keyword in API_KEYWORDS):
        categories.append("api_surface")
    if any(keyword in haystack for keyword in FILE_EXPOSURE_KEYWORDS):
        categories.append("file_exposure_candidate")
    if any(keyword in haystack for keyword in LEGACY_KEYWORDS):
        categories.append("legacy_or_hidden_path")
    if parsed.query:
        categories.append("parameterized_endpoint")
    if any(keyword in haystack for keyword in UPLOAD_KEYWORDS):
        categories.append("upload_surface")

    return categories


def _run_archive_tool(
    tool_name: str,
    domain: str,
    *,
    timeout_sec: int,
) -> tuple[list[str], str | None]:
    if not shutil.which(tool_name):
        return [], f"{tool_name} is not installed"

    try:
        if tool_name == "waybackurls":
            result = subprocess.run(
                [tool_name],
                input=f"{domain}\n",
                capture_output=True,
                text=True,
                timeout=max(1, int(timeout_sec)),
            )
        else:
            result = subprocess.run(
                [tool_name, domain],
                capture_output=True,
                text=True,
                timeout=max(1, int(timeout_sec)),
            )
    except subprocess.TimeoutExpired:
        return [], f"{tool_name} timed out for {domain}"
    except Exception as exc:
        return [], f"{tool_name} failed for {domain}: {exc}"

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        return [], f"{tool_name} returned {result.returncode} for {domain}: {stderr[:240]}"

    return [line.strip() for line in (result.stdout or "").splitlines() if line.strip()], None


def build_historical_url_results_from_raw(
    raw_by_tool: dict[str, list[str]],
    *,
    domains: list[str] | None = None,
    warnings: list[str] | None = None,
    max_urls: int = 300,
    timeout_sec: int = 45,
) -> dict[str, Any]:
    normalized_sources: dict[str, set[str]] = {}
    invalid_count = 0
    url_cap = max(0, int(max_urls))
    for tool_name, raw_lines in (raw_by_tool or {}).items():
        if url_cap == 0:
            break
        for raw_url in raw_lines or []:
            normalized = normalize_historical_url(raw_url)
            if not normalized:
                invalid_count += 1
                continue
            normalized_sources.setdefault(normalized, set()).add(str(tool_name))
            if len(normalized_sources) >= url_cap:
                break
        if len(normalized_sources) >= url_cap:
            break

    records = [
        HistoricalUrlRecord(
            url=url,
            sources=sorted(sources),
            categories=classify_historical_url(url),
            live=False,
        ).to_dict()
        for url, sources in sorted(normalized_sources.items())
    ]
    return {
        "enabled": True,
        "domains": domains or [],
        "raw_by_tool": raw_by_tool or {},
        "normalized_urls": [record["url"] for record in records],
        "records": records,
        "warnings": warnings or [],
        "invalid_count": invalid_count,
        "max_urls": url_cap,
        "timeout_sec": max(1, int(timeout_sec)),
    }


def collect_historical_urls(
    domains: list[str],
    *,
    max_urls: int = 300,
    max_domains: int = 50,
    timeout_sec: int = 45,
    tools: tuple[str, ...] = ("gau", "waybackurls"),
) -> dict[str, Any]:
    raw_by_tool: dict[str, list[str]] = {tool: [] for tool in tools}
    warnings: list[str] = []
    normalized_sources: dict[str, set[str]] = {}
    invalid_count = 0

    domain_cap = max(0, int(max_domains))
    cleaned_domains = []
    if domain_cap > 0:
        for domain in domains:
            value = _clean_domain_candidate(domain)
            if value and value not in cleaned_domains:
                cleaned_domains.append(value)
            if len(cleaned_domains) >= domain_cap:
                break

    url_cap = max(0, int(max_urls))
    if url_cap == 0:
        return {
            "enabled": True,
            "domains": cleaned_domains,
            "raw_by_tool": raw_by_tool,
            "normalized_urls": [],
            "records": [],
            "warnings": ["Historical URL collection cap is 0"],
            "invalid_count": 0,
            "max_urls": 0,
            "max_domains": domain_cap,
            "timeout_sec": max(1, int(timeout_sec)),
        }

    for tool_name in tools:
        for domain in cleaned_domains:
            raw_lines, warning = _run_archive_tool(tool_name, domain, timeout_sec=timeout_sec)
            if warning:
                if warning not in warnings:
                    warnings.append(warning)
                continue
            raw_by_tool.setdefault(tool_name, []).extend(raw_lines)
            for raw_url in raw_lines:
                normalized = normalize_historical_url(raw_url)
                if not normalized:
                    invalid_count += 1
                    continue
                normalized_sources.setdefault(normalized, set()).add(tool_name)
                if len(normalized_sources) >= url_cap:
                    break
            if len(normalized_sources) >= url_cap:
                break

    records = [
        HistoricalUrlRecord(
            url=url,
            sources=sorted(sources),
            categories=classify_historical_url(url),
            live=False,
        ).to_dict()
        for url, sources in sorted(normalized_sources.items())
    ]

    return {
        "enabled": True,
        "domains": cleaned_domains,
        "raw_by_tool": raw_by_tool,
        "normalized_urls": [record["url"] for record in records],
        "records": records,
        "warnings": warnings,
        "invalid_count": invalid_count,
        "max_urls": url_cap,
        "max_domains": domain_cap,
        "timeout_sec": max(1, int(timeout_sec)),
    }


def mark_live_historical_urls(
    results: dict[str, Any],
    live_urls: list[str],
    *,
    checked_urls: list[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(results, dict):
        return {}

    live_set = {normalize_historical_url(url) for url in live_urls if normalize_historical_url(url)}
    checked_set = {normalize_historical_url(url) for url in (checked_urls or []) if normalize_historical_url(url)}
    records = results.get("records") if isinstance(results.get("records"), list) else []
    updated_records: list[dict[str, Any]] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        url = normalize_historical_url(item.get("url"))
        if not url:
            continue
        updated = dict(item)
        updated["url"] = url
        updated["live"] = url in live_set
        if url in live_set:
            updated["live_check_status"] = "live"
        elif url in checked_set:
            updated["live_check_status"] = "dead_or_unresponsive"
        else:
            updated["live_check_status"] = "not_checked"
        updated["categories"] = item.get("categories") if isinstance(item.get("categories"), list) else classify_historical_url(url)
        updated["sources"] = item.get("sources") if isinstance(item.get("sources"), list) else []
        updated_records.append(updated)

    live_records = [item for item in updated_records if item.get("live")]
    interesting_live_records = [
        item for item in live_records
        if isinstance(item.get("categories"), list) and item.get("categories")
    ]
    output = dict(results)
    output["records"] = updated_records
    output["live_urls"] = [item["url"] for item in live_records]
    output["interesting_live_urls"] = interesting_live_records
    output["live_count"] = len(live_records)
    output["interesting_live_count"] = len(interesting_live_records)
    return output
