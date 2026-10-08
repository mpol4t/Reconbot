"""Intermediate endpoint analysis layer for ReconBot.

Sits between raw tool output (katana, gobuster, httpx, web_checks) and the
report / attack-graph consumers.  Provides canonical dedup, noise separation,
semantic clustering, and explainable summaries.

Pipeline:  raw → canonical → clustered → summary
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit, unquote


# ---------------------------------------------------------------------------
# Constants — query-param classification
# ---------------------------------------------------------------------------

NOISE_PARAMS: frozenset[str] = frozenset({
    "replytocom", "author", "feed", "format", "embed",
    "toggle-hints", "bubble-hints", "enforce-ssl",
    "toggle-security", "toggle-bubble", "toggle-enforce",
    "do", "ver", "v", "t", "ts", "timestamp", "cb", "cache",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "ref", "source", "share",
    "_", "nonce",
    "lang", "locale", "hl",
    "cat", "tag", "p",
    "feed-comments",
})

ROUTING_PARAMS: frozenset[str] = frozenset({
    "page", "paged", "action", "view", "tab", "section",
    "step", "state", "mode", "type", "sort", "order",
    "limit", "offset", "start", "from", "to",
    "redirect_to", "return", "next", "back",
    "q", "query", "search", "s", "keyword",
})

SECURITY_RELEVANT_PARAMS: frozenset[str] = frozenset({
    "file", "include", "require", "path", "dir", "directory",
    "module", "plugin", "template", "theme",
    "cmd", "exec", "command", "run", "shell",
    "url", "uri", "src", "dest", "target", "redirect",
    "id", "uid", "user_id", "account",
    "api", "api_key", "key", "secret", "token",
    "wsdl", "callback", "jsonp",
    "upload", "download", "export", "import",
    "sql", "table", "db", "database",
    "debug", "test", "admin", "config",
})

# ---------------------------------------------------------------------------
# Constants — static-asset / noise detection
# ---------------------------------------------------------------------------

STATIC_EXTENSIONS: frozenset[str] = frozenset({
    ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".pdf", ".zip", ".gz", ".tar", ".rar",
    ".bmp", ".tiff", ".tif", ".avif",
})

STATIC_PATH_HINTS: tuple[str, ...] = (
    "/wp-includes/js/", "/wp-includes/css/",
    "/wp-content/themes/", "/wp-content/plugins/", "/wp-content/uploads/",
    "/static/", "/assets/", "/dist/", "/vendor/",
    "/node_modules/", "/fonts/", "/images/", "/img/", "/media/",
)

BUCKET_PATTERNS: dict[str, tuple[str, ...]] = {
    "admin_like": (
        "admin", "dashboard", "panel", "manage", "wp-admin",
        "phpmyadmin", "pma", "console", "backend",
    ),
    "auth_like": (
        "login", "signin", "sign-in", "auth", "oauth", "sso",
        "register", "signup", "sign-up", "logout", "forgot",
        "lostpassword", "reset", "recover", "xmlrpc",
    ),
    "api_like": (
        "api", "graphql", "swagger", "openapi", "actuator",
        "rest", "soap", "wsdl", "webservices",
    ),
    "upload_like": ("upload", "file", "import", "attachment", "multipart"),
    "debug_like": (
        "debug", "internal", "test", "dev", "phpinfo",
        "server-status", "diagnostic", "trace", "errors",
    ),
    "docs_like": (
        "docs", "documentation", "redoc", "swagger-ui", "help",
        "install", "readme", "manual", "tutorial",
    ),
}

PUBLIC_CONTENT_PATH_MARKERS: tuple[str, ...] = (
    "/blog/",
    "/news/",
    "/resources/",
    "/help/",
    "/docs/",
    "/services/",
    "/products/",
    "/legal/",
    "/company/",
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class RawEndpointRecord:
    """One observed URL from any tool output."""

    original_url: str
    source_tool: str
    status_code: int | None = None
    content_length: int | None = None
    title: str = ""
    content_type: str = ""
    words_count: int | None = None
    lines_count: int | None = None
    discovered_reason: str = ""
    bucket_labels: list[str] = field(default_factory=list)
    response_fingerprint: str = ""
    is_static_asset: bool = False
    is_noise_candidate: bool = False


@dataclass
class EndpointVariant:
    """One specific URL variant within a cluster."""

    url: str
    source_tool: str
    status_code: int | None = None
    content_length: int | None = None
    words_count: int | None = None
    lines_count: int | None = None
    query_params: dict[str, list[str]] = field(default_factory=dict)
    noise_params: dict[str, list[str]] = field(default_factory=dict)
    routing_params: dict[str, list[str]] = field(default_factory=dict)
    security_relevant_params: dict[str, list[str]] = field(default_factory=dict)
    response_fingerprint: str = ""
    title: str = ""


@dataclass
class CanonicalEndpoint:
    """A URL normalized to its canonical form for dedup/clustering."""

    canonical_key: str
    representative_url: str
    scheme: str
    netloc: str
    path: str
    family_type: str
    bucket_labels: list[str] = field(default_factory=list)
    noise_params: dict[str, list[str]] = field(default_factory=dict)
    routing_params: dict[str, list[str]] = field(default_factory=dict)
    security_relevant_params: dict[str, list[str]] = field(default_factory=dict)
    has_security_relevant_query: bool = False
    is_static_asset: bool = False
    is_noise_candidate: bool = False
    raw: RawEndpointRecord | None = None


@dataclass
class EndpointCluster:
    """A group of URL variants sharing the same canonical identity."""

    canonical_key: str
    representative_url: str
    family_type: str
    bucket_labels: list[str] = field(default_factory=list)
    unique_statuses: list[int] = field(default_factory=list)
    unique_content_lengths: list[int] = field(default_factory=list)
    unique_titles: list[str] = field(default_factory=list)
    variants_count: int = 0
    variants: list[EndpointVariant] = field(default_factory=list)
    has_security_relevant_query: bool = False
    risk_signals: list[str] = field(default_factory=list)
    explanatory_notes: list[str] = field(default_factory=list)
    is_suppressed: bool = False
    has_meaningful_response_diversity: bool = False


@dataclass
class AnalysisSummary:
    """Final output of the endpoint analysis pipeline."""

    reportworthy_endpoints_by_bucket: dict[str, list[str]] = field(
        default_factory=dict
    )
    raw_discovery_count: int = 0
    clustered_count: int = 0
    suppressed_noise_count: int = 0
    representative_endpoints: list[str] = field(default_factory=list)
    suspicious_families: list[dict[str, Any]] = field(default_factory=list)
    duplicate_families: list[dict[str, Any]] = field(default_factory=list)
    scoring_inputs: dict[str, Any] = field(default_factory=dict)
    graph_inputs: dict[str, Any] = field(default_factory=dict)
    clusters: list[dict[str, Any]] = field(default_factory=list)
    cluster_insights: list[dict[str, Any]] = field(default_factory=list)
    katana_cleaned_urls: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pipeline helpers
# ---------------------------------------------------------------------------

def _is_static_asset(url: str) -> bool:
    parts = urlsplit(url)
    path_low = (parts.path or "").lower()

    if any(path_low.endswith(ext) for ext in STATIC_EXTENSIONS):
        if not _has_surface_marker(url):
            return True

    if any(hint in path_low for hint in STATIC_PATH_HINTS):
        if not _has_surface_marker(url):
            return True

    return False


def _has_surface_marker(url: str) -> bool:
    low = (url or "").lower()
    for patterns in BUCKET_PATTERNS.values():
        if any(m in low for m in patterns):
            return True
    return False


def _is_public_content_context_url(url: str) -> bool:
    low = (url or "").lower()
    path = urlsplit(low).path or low
    return any(marker in path for marker in PUBLIC_CONTENT_PATH_MARKERS)


def _dashboard_has_admin_context(url: str) -> bool:
    low = (url or "").lower()
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
    auth_context = ("/login", "/signin", "/auth", "login=", "redirect_to=", "reauth=")
    return (
        any(marker in low for marker in strong_markers)
        or any(marker in path for marker in dashboard_admin_paths)
        or any(marker in low or marker in query for marker in auth_context)
    )


def classify_query_params(
    query_string: str,
) -> tuple[dict[str, list[str]], dict[str, list[str]], dict[str, list[str]]]:
    """Classify query parameters into (noise, routing, security_relevant)."""
    params = parse_qs(query_string, keep_blank_values=True)
    noise: dict[str, list[str]] = {}
    routing: dict[str, list[str]] = {}
    security: dict[str, list[str]] = {}

    for key, values in params.items():
        low_key = key.lower().strip()
        if low_key in NOISE_PARAMS:
            noise[key] = values
        elif low_key in SECURITY_RELEVANT_PARAMS:
            security[key] = values
        elif low_key in ROUTING_PARAMS:
            routing[key] = values
        else:
            routing[key] = values

    return noise, routing, security


def _compute_bucket_labels(url: str) -> list[str]:
    low = (url or "").lower()
    labels: list[str] = []
    for bucket, patterns in BUCKET_PATTERNS.items():
        if not any(m in low for m in patterns):
            continue
        if bucket == "admin_like":
            if "dashboard" in low and not _dashboard_has_admin_context(low):
                continue
            if _is_public_content_context_url(low) and not _dashboard_has_admin_context(low):
                continue
        if bucket in {"auth_like", "debug_like"} and _is_public_content_context_url(low):
            continue
        labels.append(bucket)
    return labels


def _content_length_band(cl: int | None) -> str:
    if cl is None or cl == 0:
        return "empty"
    if cl <= 500:
        return "tiny"
    if cl <= 5000:
        return "small"
    if cl <= 50000:
        return "medium"
    return "large"



# --- Canonical key helpers ---

def _normalize_param_value(val: str) -> str:
    """Normalize routing/security parameter value for endpoint identity."""
    # Lowercase, trim, remove trailing slash, unquote, and strip obvious prefixes.
    v = (val or "").strip().lower()
    v = unquote(v)
    v = v.rstrip("/")
    # Remove protocol and netloc if present (for url/path-like)
    if "://" in v:
        # Only keep the path/query
        try:
            parts = urlsplit(v)
            v = (parts.path or "/")
            if parts.query:
                v += "?" + parts.query
        except Exception:
            pass
    # Remove leading ./
    if v.startswith("./"):
        v = v[2:]
    # Remove obvious noise fragments
    return v

def _compute_canonical_key(
    netloc: str,
    path: str,
    security_params: dict[str, list[str]],
    routing_params: dict[str, list[str]],
) -> str:
    """Build conservative canonical key.

    Rules:
    - Noise params are excluded upstream.
    - Identity-changing routing/security values are preserved.
    - Weak params (pagination/sort/cache/timestamps) do not define identity.
    """
    norm_path = path.rstrip("/") or "/"

    def _looks_identity_changing_value(v: str) -> bool:
        low = (v or "").lower().strip()
        if not low:
            return False
        if any(marker in low for marker in (
            ".php", ".asp", ".aspx", ".jsp", ".cgi",
            "admin", "login", "register", "signup", "signin",
            "phpmyadmin", "graphql", "swagger", "openapi", "wsdl",
            "documentation", "docs", "xmlrpc", "server-status", "lostpassword",
            "debug", "upload", "config", "module", "include",
            "/", "?", "=",
        )):
            return True
        return False

    # For routing/security params, only include those not weak (pagination/sorting/cache/timestamps)
    WEAK_PARAMS = frozenset({
        "limit", "offset", "start", "from", "to", "sort", "order",
        "t", "ts", "timestamp", "cb", "cache", "v", "_",
    })

    ROUTING_NUMERIC_WEAK = frozenset({
        "page", "paged", "p", "q", "query", "s", "keyword",
    })

    # For security params, always include all param values.
    sec_items = []
    for k, vs in security_params.items():
        for v in vs:
            normv = _normalize_param_value(v)
            sec_items.append((k.lower().strip(), normv))

    # For routing params:
    # - exclude known weak params
    # - keep identity-changing values (e.g. page=register.php, page=phpmyadmin.php)
    # - suppress plain numeric pagination variants
    routing_items = []
    for k, vs in routing_params.items():
        low_k = k.lower().strip()
        if low_k in WEAK_PARAMS:
            continue
        for v in vs:
            normv = _normalize_param_value(v)
            if low_k in ROUTING_NUMERIC_WEAK:
                if normv.isdigit() and not _looks_identity_changing_value(normv):
                    continue
                if not _looks_identity_changing_value(normv) and not normv.isdigit():
                    continue
            routing_items.append((low_k, normv))

    # Sort and build param part
    all_items = sorted(sec_items + routing_items)
    param_part = "&".join(f"{k}={v}" for k, v in all_items) if all_items else ""
    raw_key = f"{netloc.lower()}{norm_path}"
    if param_part:
        raw_key += f"?{param_part}"
    return raw_key


def _determine_family_type(path: str, bucket_labels: list[str]) -> str:
    for fam in ("api_like", "admin_like", "auth_like", "upload_like", "debug_like", "docs_like"):
        if fam in bucket_labels:
            return fam.replace("_like", "")
    if any((path or "").lower().endswith(ext) for ext in STATIC_EXTENSIONS):
        return "static"
    return "page"


def _compute_response_fingerprint(
    status_code: int | None, content_length: int | None, title: str
) -> str:
    parts = [
        str(status_code or "?"),
        _content_length_band(content_length),
        (title or "").strip().lower()[:50],
    ]
    raw = "|".join(parts)
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

def ingest_raw_endpoints(
    web_urls: list[str] | None,
    katana_urls: list[str] | None,
    gobuster_results: dict[str, list[dict[str, Any]]] | None,
    checks_results: dict[str, Any] | None = None,
    ffuf_results: dict[str, list[dict[str, Any]]] | None = None,
) -> list[RawEndpointRecord]:
    """Stage 1: Ingest URLs from all tool outputs into RawEndpointRecords."""
    records: list[RawEndpointRecord] = []
    seen_map: dict[tuple[str, int | None, int | None, str], int] = {}

    def _normalize_observed_url(url: str) -> str:
        parts = urlsplit(url)
        scheme = (parts.scheme or "http").lower()
        netloc = (parts.netloc or "").lower()
        path = parts.path or "/"
        if path != "/":
            path = path.rstrip("/") or "/"
        query = parts.query or ""
        return urlunsplit((scheme, netloc, path, query, ""))

    def _add(
        url: str,
        source: str,
        *,
        status: int | None = None,
        content_length: int | None = None,
        words_count: int | None = None,
        lines_count: int | None = None,
        title: str = "",
        reason: str = "",
    ) -> None:
        url = (url or "").strip()
        if not url:
            return
        normalized_observed = _normalize_observed_url(url)
        record_key = (
            normalized_observed,
            int(status) if status is not None else None,
            int(content_length) if content_length is not None else None,
            (title or "").strip().lower()[:80],
        )
        existing_idx = seen_map.get(record_key)
        if existing_idx is not None:
            existing = records[existing_idx]
            if existing.words_count is None and words_count is not None:
                existing.words_count = int(words_count)
            if existing.lines_count is None and lines_count is not None:
                existing.lines_count = int(lines_count)
            if not existing.title and title:
                existing.title = title
            return

        buckets = _compute_bucket_labels(url)
        is_static = _is_static_asset(url)
        fp = _compute_response_fingerprint(status, content_length, title)
        is_noise = is_static and not buckets

        records.append(
            RawEndpointRecord(
                original_url=url,
                source_tool=source,
                status_code=status,
                content_length=content_length,
                title=title,
                discovered_reason=reason,
                words_count=int(words_count) if words_count is not None else None,
                lines_count=int(lines_count) if lines_count is not None else None,
                bucket_labels=buckets,
                response_fingerprint=fp,
                is_static_asset=is_static,
                is_noise_candidate=is_noise,
            )
        )
        seen_map[record_key] = len(records) - 1

    for u in web_urls or []:
        _add(u, "httpx", reason="live host probe")

    for u in katana_urls or []:
        _add(u, "katana", reason="crawl discovery")

    for _base_url, hits in (gobuster_results or {}).items():
        if not isinstance(hits, list):
            continue
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            _add(
                hit.get("url", ""),
                "gobuster",
                status=hit.get("status"),
                content_length=hit.get("content_length") if hit.get("content_length") is not None else hit.get("size"),
                words_count=hit.get("words"),
                lines_count=hit.get("lines"),
                reason="directory brute-force",
            )

    for _base_url, hits in (ffuf_results or {}).items():
        if not isinstance(hits, list):
            continue
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            _add(
                hit.get("url", ""),
                "ffuf",
                status=hit.get("status"),
                content_length=hit.get("content_length") if hit.get("content_length") is not None else hit.get("length"),
                words_count=hit.get("words"),
                lines_count=hit.get("lines"),
                reason="directory fuzzing",
            )

    if isinstance(checks_results, dict):
        for page_key in ("login_pages", "captcha_pages", "docs_pages"):
            for item in checks_results.get(page_key, []) or []:
                if not isinstance(item, dict):
                    continue
                url = str(item.get("url") or "").strip()
                if url:
                    _add(
                        url,
                        "web_checks",
                        status=item.get("status_code") or item.get("status"),
                        title=item.get("title", ""),
                        reason=f"checks:{page_key}",
                    )

    return records


def canonicalize_endpoints(
    records: list[RawEndpointRecord],
) -> list[CanonicalEndpoint]:
    """Stage 2: Normalize each record to a CanonicalEndpoint."""
    results: list[CanonicalEndpoint] = []

    for record in records:
        parts = urlsplit(record.original_url)
        scheme = parts.scheme or "http"
        netloc = parts.netloc or ""
        path = parts.path or "/"

        noise, routing, security = classify_query_params(parts.query or "")
        has_sec_query = bool(security)
        bucket_labels = record.bucket_labels or _compute_bucket_labels(
            record.original_url
        )
        family = _determine_family_type(path, bucket_labels)

        kept_params: dict[str, list[str]] = {}
        kept_params.update(routing)
        kept_params.update(security)
        clean_query = (
            urlencode(
                [(k, v) for k, vs in sorted(kept_params.items()) for v in vs],
                doseq=False,
            )
            if kept_params
            else ""
        )
        representative = urlunsplit((scheme, netloc, path, clean_query, ""))
        canonical_key = _compute_canonical_key(netloc, path, security, routing)

        results.append(
            CanonicalEndpoint(
                canonical_key=canonical_key,
                representative_url=representative,
                scheme=scheme,
                netloc=netloc,
                path=path,
                family_type=family,
                bucket_labels=bucket_labels,
                noise_params=noise,
                routing_params=routing,
                security_relevant_params=security,
                has_security_relevant_query=has_sec_query,
                is_static_asset=record.is_static_asset,
                is_noise_candidate=record.is_noise_candidate,
                raw=record,
            )
        )

    return results


def cluster_endpoints(
    canonical_endpoints: list[CanonicalEndpoint],
) -> list[EndpointCluster]:
    """Stage 3: Group endpoints by canonical key into clusters."""
    cluster_map: dict[str, list[CanonicalEndpoint]] = {}
    for ep in canonical_endpoints:
        cluster_map.setdefault(ep.canonical_key, []).append(ep)

    clusters: list[EndpointCluster] = []

    for key, members in cluster_map.items():
        representative = members[0]
        for m in members:
            if m.raw and m.raw.status_code is not None and not m.is_noise_candidate:
                representative = m
                break

        statuses: set[int] = set()
        lengths: set[int] = set()
        words: set[int] = set()
        lines: set[int] = set()
        titles: set[str] = set()
        fingerprints: set[str] = set()
        all_buckets: set[str] = set()
        has_sec_query = False
        source_tools: set[str] = set()
        risk_signals: list[str] = []
        variants: list[EndpointVariant] = []

        for m in members:
            raw = m.raw
            if raw and raw.status_code is not None:
                statuses.add(raw.status_code)
            if raw and raw.content_length is not None:
                lengths.add(raw.content_length)
            if raw and raw.words_count is not None:
                words.add(raw.words_count)
            if raw and raw.lines_count is not None:
                lines.add(raw.lines_count)
            if raw and raw.title:
                titles.add(raw.title)
            all_buckets.update(m.bucket_labels)
            if m.has_security_relevant_query:
                has_sec_query = True
            fp = ""
            t = ""
            if raw:
                fp = raw.response_fingerprint
                t = raw.title
                if fp:
                    fingerprints.add(fp)
            variants.append(
                EndpointVariant(
                    url=raw.original_url if raw else m.representative_url,
                    source_tool=raw.source_tool if raw else "unknown",
                    status_code=raw.status_code if raw else None,
                    content_length=raw.content_length if raw else None,
                    words_count=raw.words_count if raw else None,
                    lines_count=raw.lines_count if raw else None,
                    query_params={
                        **m.noise_params,
                        **m.routing_params,
                        **m.security_relevant_params,
                    },
                    noise_params=m.noise_params,
                    routing_params=m.routing_params,
                    security_relevant_params=m.security_relevant_params,
                    response_fingerprint=fp,
                    title=t,
                )
            )
            source_tools.add(raw.source_tool if raw and raw.source_tool else "unknown")

        # Diversity check: meaningful response difference
        has_diversity = False
        diversity_notes = []
        if len(statuses) > 1:
            has_diversity = True
            diversity_notes.append(f"Status codes: {sorted(statuses)}")
        if len(lengths) > 1:
            has_diversity = True
            diversity_notes.append(f"Content lengths: {sorted(lengths)}")
        if len(words) > 1:
            has_diversity = True
            diversity_notes.append(f"Word counts: {sorted(words)}")
        if len(lines) > 1:
            has_diversity = True
            diversity_notes.append(f"Line counts: {sorted(lines)}")
        if len(titles) > 1:
            has_diversity = True
            diversity_notes.append(f"Titles: {sorted(titles)}")
        if len(fingerprints) > 1:
            has_diversity = True
            diversity_notes.append(f"Response fingerprints: {sorted(fingerprints)}")

        if has_sec_query:
            risk_signals.append("security-relevant query parameters present")
        high_value = [b for b in ("upload_like", "debug_like", "admin_like") if b in all_buckets]
        if high_value:
            risk_signals.append(f"high-value surface: {', '.join(high_value)}")
        if len(members) > 5:
            risk_signals.append(f"high variant count ({len(members)})")
        if has_diversity:
            risk_signals.append("materially different responses in one family")
        # If routing/security param values present, note parameter-driven family
        param_keys = set()
        for m in members:
            param_keys.update(m.routing_params.keys())
            param_keys.update(m.security_relevant_params.keys())
        if param_keys:
            risk_signals.append("parameter-driven endpoint family")
        has_ffuf = "ffuf" in source_tools
        has_non_ffuf = any(src != "ffuf" for src in source_tools)
        if has_ffuf and has_non_ffuf:
            risk_signals.append("confirmed by multiple discovery tools (including ffuf)")
        elif has_ffuf and not has_non_ffuf:
            risk_signals.append("ffuf-unique discovery")

        notes: list[str] = []
        if len(members) > 1:
            notes.append(f"Clustered {len(members)} URL variants under one canonical key")
        suppressed_in_cluster = sum(1 for m in members if m.is_noise_candidate)
        if suppressed_in_cluster:
            notes.append(
                f"{suppressed_in_cluster}/{len(members)} variants are noise candidates"
            )
        if has_ffuf:
            if has_non_ffuf:
                notes.append("FFUF finding overlaps with other discovery sources for this family")
            else:
                notes.append("This family is discovered only via FFUF")
        if has_diversity:
            notes.append("Materially different responses within this endpoint family: " + "; ".join(diversity_notes))

        # Suppression: only if all are static/noise, AND no buckets,
        # AND no security params, AND no meaningful response diversity.
        is_suppressed = (
            all(m.is_noise_candidate or m.is_static_asset for m in members)
            and not all_buckets
            and not has_sec_query
            and not has_diversity
        )

        clusters.append(
            EndpointCluster(
                canonical_key=key,
                representative_url=representative.representative_url,
                family_type=representative.family_type,
                bucket_labels=sorted(all_buckets),
                unique_statuses=sorted(statuses),
                unique_content_lengths=sorted(lengths),
                unique_titles=sorted(titles),
                variants_count=len(members),
                variants=variants,
                has_security_relevant_query=has_sec_query,
                risk_signals=risk_signals,
                explanatory_notes=notes,
                is_suppressed=is_suppressed,
                has_meaningful_response_diversity=has_diversity,
            )
        )

    return clusters


def build_analysis_summary(
    clusters: list[EndpointCluster],
    raw_records: list[RawEndpointRecord],
    classified_endpoints: dict[str, list[str]] | None = None,
) -> AnalysisSummary:
    """Stage 4: Produce the final AnalysisSummary from clusters."""
    classified_endpoints = classified_endpoints or {}

    active_clusters = [c for c in clusters if not c.is_suppressed]
    suppressed_clusters = [c for c in clusters if c.is_suppressed]

    reportworthy: dict[str, list[str]] = {
        "admin_like": [], "auth_like": [], "api_like": [],
        "upload_like": [], "debug_like": [], "docs_like": [],
    }
    representative_urls: list[str] = []
    seen_reps: set[str] = set()

    for cluster in active_clusters:
        rep = cluster.representative_url
        if rep in seen_reps:
            continue
        seen_reps.add(rep)
        representative_urls.append(rep)
        for bucket in cluster.bucket_labels:
            if bucket in reportworthy:
                reportworthy[bucket].append(rep)

    for bucket, originals in classified_endpoints.items():
        if bucket in reportworthy and not reportworthy[bucket] and originals:
            reportworthy[bucket] = list(originals)

    # Build cleaned katana URL list (katana-sourced, non-suppressed representatives)
    katana_originals: set[str] = {
        r.original_url for r in raw_records if r.source_tool == "katana"
    }
    # Use separate sets for original and representative tracking
    katana_cleaned: list[str] = []
    katana_seen_orig: set[str] = set()
    katana_seen_rep: set[str] = set()
    for cluster in active_clusters:
        # If any variant in cluster comes from katana, emit representative_url once
        found_katana = False
        for v in cluster.variants:
            if v.url in katana_originals and v.url not in katana_seen_orig:
                katana_seen_orig.add(v.url)
                found_katana = True
        if found_katana and cluster.representative_url not in katana_seen_rep:
            katana_seen_rep.add(cluster.representative_url)
            katana_cleaned.append(cluster.representative_url)

    suspicious: list[dict[str, Any]] = []
    ffuf_raw_records = sum(1 for r in raw_records if r.source_tool == "ffuf")
    ffuf_clusters = 0
    ffuf_unique_clusters = 0
    ffuf_confirmed_clusters = 0
    ffuf_high_value_clusters = 0
    ffuf_sensitive_marker_clusters = 0
    ffuf_security_relevant_clusters = 0
    ffuf_diverse_response_clusters = 0
    ffuf_family_signals: list[dict[str, Any]] = []
    sensitive_path_markers = (
        ".git", "phpinfo", "server-status", "robots.txt", ".htaccess", ".htpasswd",
    )
    high_value_buckets = ("upload_like", "admin_like", "auth_like", "api_like", "docs_like", "debug_like")
    for cluster in active_clusters:
        cluster_sources = {str(v.source_tool or "").strip().lower() for v in (cluster.variants or []) if str(v.source_tool or "").strip()}
        rep_low = str(cluster.representative_url or "").lower()
        has_sensitive_marker = any(marker in rep_low for marker in sensitive_path_markers)
        has_high_value_bucket = any(b in (cluster.bucket_labels or []) for b in high_value_buckets)
        if "ffuf" in cluster_sources:
            ffuf_clusters += 1
            if any(src != "ffuf" for src in cluster_sources):
                ffuf_confirmed_clusters += 1
            else:
                ffuf_unique_clusters += 1
            if has_high_value_bucket:
                ffuf_high_value_clusters += 1
            if has_sensitive_marker:
                ffuf_sensitive_marker_clusters += 1
            if cluster.has_security_relevant_query:
                ffuf_security_relevant_clusters += 1
            if cluster.has_meaningful_response_diversity:
                ffuf_diverse_response_clusters += 1
            ffuf_family_signals.append(
                {
                    "canonical_key": cluster.canonical_key,
                    "representative_url": cluster.representative_url,
                    "ffuf_unique": not any(src != "ffuf" for src in cluster_sources),
                    "ffuf_confirmed_by_other_tools": any(src != "ffuf" for src in cluster_sources),
                    "high_value_bucket": has_high_value_bucket,
                    "sensitive_marker": has_sensitive_marker,
                    "security_relevant_query": bool(cluster.has_security_relevant_query),
                    "meaningful_response_diversity": bool(cluster.has_meaningful_response_diversity),
                    "bucket_labels": list(cluster.bucket_labels or []),
                    "source_tools": sorted(cluster_sources),
                }
            )
        if cluster.has_security_relevant_query or cluster.risk_signals:
            suspicious.append({
                "canonical_key": cluster.canonical_key,
                "representative_url": cluster.representative_url,
                "risk_signals": cluster.risk_signals,
                "variants_count": cluster.variants_count,
                "bucket_labels": cluster.bucket_labels,
                "source_tools": sorted(cluster_sources),
            })

    duplicate_families: list[dict[str, Any]] = []
    for cluster in clusters:
        if cluster.variants_count >= 3:
            duplicate_families.append({
                "canonical_key": cluster.canonical_key,
                "representative_url": cluster.representative_url,
                "variants_count": cluster.variants_count,
                "is_suppressed": cluster.is_suppressed,
                "explanatory_notes": cluster.explanatory_notes,
            })

    scoring_inputs: dict[str, Any] = {
        "active_cluster_count": len(active_clusters),
        "suppressed_count": len(suppressed_clusters),
        "buckets": {b: len(urls) for b, urls in reportworthy.items()},
        "security_relevant_clusters": len(suspicious),
        "high_variant_clusters": sum(
            1 for c in clusters if c.variants_count > 5
        ),
        "ffuf_raw_records": ffuf_raw_records,
        "ffuf_clusters": ffuf_clusters,
        "ffuf_unique_clusters": ffuf_unique_clusters,
        "ffuf_confirmed_clusters": ffuf_confirmed_clusters,
        "ffuf_high_value_clusters": ffuf_high_value_clusters,
        "ffuf_sensitive_marker_clusters": ffuf_sensitive_marker_clusters,
        "ffuf_security_relevant_clusters": ffuf_security_relevant_clusters,
        "ffuf_diverse_response_clusters": ffuf_diverse_response_clusters,
        "ffuf_overlap_ratio": (
            round(ffuf_confirmed_clusters / max(1, ffuf_clusters), 3)
            if ffuf_clusters > 0
            else 0.0
        ),
        "ffuf_family_signals": ffuf_family_signals[:200],
    }

    graph_inputs: dict[str, Any] = {
        "surface_counts": {b: len(urls) for b, urls in reportworthy.items()},
        "representative_endpoints": representative_urls[:50],
        "suspicious_endpoints": [s["representative_url"] for s in suspicious[:20]],
    }

    cluster_data: list[dict[str, Any]] = []
    cluster_insights: list[dict[str, Any]] = []
    for cluster in clusters[:200]:
        # For cluster_insights, add more detail
        insight = {
            "canonical_key": cluster.canonical_key,
            "representative_url": cluster.representative_url,
            "family_type": cluster.family_type,
            "bucket_labels": cluster.bucket_labels,
            "variants_count": cluster.variants_count,
            "unique_statuses": cluster.unique_statuses,
            "unique_content_lengths": cluster.unique_content_lengths,
            "unique_titles": cluster.unique_titles,
            "has_security_relevant_query": cluster.has_security_relevant_query,
            "has_meaningful_response_diversity": cluster.has_meaningful_response_diversity,
            "risk_signals": cluster.risk_signals,
            "explanatory_notes": cluster.explanatory_notes,
            "source_tools": sorted({
                str(v.source_tool or "").strip().lower()
                for v in (cluster.variants or [])
                if str(v.source_tool or "").strip()
            }),
            "variant_urls": [v.url for v in cluster.variants[:10]],
        }
        cluster_insights.append(insight)
        # For backward compatibility, keep clusters as before
        cluster_data.append({
            "canonical_key": cluster.canonical_key,
            "representative_url": cluster.representative_url,
            "family_type": cluster.family_type,
            "bucket_labels": cluster.bucket_labels,
            "unique_statuses": cluster.unique_statuses,
            "variants_count": cluster.variants_count,
            "has_security_relevant_query": cluster.has_security_relevant_query,
            "risk_signals": cluster.risk_signals,
            "explanatory_notes": cluster.explanatory_notes,
            "is_suppressed": cluster.is_suppressed,
            "variant_urls": [v.url for v in cluster.variants[:10]],
        })

    summary = AnalysisSummary(
        reportworthy_endpoints_by_bucket=reportworthy,
        raw_discovery_count=len(raw_records),
        clustered_count=len(active_clusters),
        suppressed_noise_count=sum(
            c.variants_count for c in suppressed_clusters
        ),
        representative_endpoints=representative_urls,
        suspicious_families=suspicious,
        duplicate_families=duplicate_families,
        scoring_inputs=scoring_inputs,
        graph_inputs=graph_inputs,
        clusters=cluster_data,
        cluster_insights=cluster_insights,
        katana_cleaned_urls=katana_cleaned,
    )
    return summary


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_endpoints(
    web_urls: list[str] | None = None,
    katana_urls: list[str] | None = None,
    gobuster_results: dict[str, list[dict[str, Any]]] | None = None,
    classified_endpoints: dict[str, list[str]] | None = None,
    checks_results: dict[str, Any] | None = None,
    ffuf_results: dict[str, list[dict[str, Any]]] | None = None,
) -> AnalysisSummary:
    """Run the full endpoint analysis pipeline.

    1. Ingests raw endpoints from all tool outputs
    2. Canonicalizes each (normalize, classify params, detect static/noise)
    3. Clusters variants by canonical key
    4. Builds an explainable summary for report and graph consumers

    Returns an AnalysisSummary whose fields are all JSON-serializable.
    """
    raw_records = ingest_raw_endpoints(
        web_urls=web_urls,
        katana_urls=katana_urls,
        gobuster_results=gobuster_results,
        checks_results=checks_results,
        ffuf_results=ffuf_results,
    )
    canonical = canonicalize_endpoints(raw_records)
    clusters = cluster_endpoints(canonical)
    return build_analysis_summary(clusters, raw_records, classified_endpoints)


def summary_to_dict(summary: AnalysisSummary) -> dict[str, Any]:
    """Serialize an AnalysisSummary to a plain dict for JSON storage."""
    d = {
        "reportworthy_endpoints_by_bucket": summary.reportworthy_endpoints_by_bucket,
        "raw_discovery_count": summary.raw_discovery_count,
        "clustered_count": summary.clustered_count,
        "suppressed_noise_count": summary.suppressed_noise_count,
        "representative_endpoints": summary.representative_endpoints,
        "suspicious_families": summary.suspicious_families,
        "duplicate_families": summary.duplicate_families,
        "scoring_inputs": summary.scoring_inputs,
        "graph_inputs": summary.graph_inputs,
        "clusters": summary.clusters,
        "cluster_insights": summary.cluster_insights,
        "katana_cleaned_urls": summary.katana_cleaned_urls,
    }
    return d
