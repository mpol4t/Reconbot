from __future__ import annotations

import json
import os
import re
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlparse, urlunparse

from reconbot.core.models import nuclei_to_findings
from reconbot.core.scoring_policy import compute_ffuf_scoring_contribution
from reconbot.core.screenshots import repair_screenshot_metadata
from reconbot.report.client_state import build_report_state_script
from reconbot.report.correlation import build_correlation_insights
from reconbot.report.depth import ReportDepthConfig, resolve_report_depth
from reconbot.report.graph_payload import build_graph_report_payload
from reconbot.report.graph_section import render_attack_graph_section
from reconbot.report.graph_ui import (
    graph_library_script_tag,
    graph_ui_css,
    render_interactive_graph_block,
    serialize_json_for_script_tag,
)
from reconbot.report.sections.sqlmap import render_sqlmap_validations
from reconbot.report.sections.ip_enrichment import render_ip_enrichment_section as _render_ip_enrichment_section
from reconbot.report.sections.osint import render_osint_section as _render_osint_section
from reconbot.report.sections import (
    pill as _pill,
    render_progressive_list as _render_progressive_list,
    render_progressive_table as _render_progressive_table,
    render_report_group as _render_report_group,
    render_report_panel as _render_report_panel,
    render_score_pill as _render_score_pill,
    render_summary_strip_counts as _render_summary_strip_counts,
    risk_band_tone as _risk_band_tone,
    truncate_text as _truncate_text,
    render_post_discovery_sections as _render_post_discovery_sections,
    render_nuclei_findings_section as _render_nuclei_findings_section,
)
from reconbot.report.layout import (
    render_report_mode_banner,
    render_report_sidebar,
    render_report_style_block,
    render_report_topbar,
)
from reconbot.report.nuclei_integration import augment_report_model_with_nuclei
from reconbot.report.decision import (
    DISCOVERY_CONFIDENCE_FACTORS as _DISCOVERY_CONFIDENCE_FACTORS,
    merge_confidence_labels as _merge_confidence_labels,
    scale_confidence_value as _scale_confidence_value,
)
from reconbot.report.texts import text as _txt
from reconbot.report.suggestions import (
    build_context_aware_suggestions as _build_context_aware_suggestions,
    normalize_node_relationships_for_report as _normalize_node_relationships_for_report,
    normalize_related_suggestion_title as _normalize_related_suggestion_title,
    operator_text_to_english as _operator_text_to_english,
    soften_suggestion_text as _soften_suggestion_text,
)

def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default
    
def _safe_len(value: Any) -> int:
    try:
        if value is None:
            return 0
        return len(value)
    except Exception:
        return 0


_REPORT_PUBLIC_CONTENT_PATH_MARKERS = (
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


def _report_url_path_segments(url: str) -> list[str]:
    path = urlparse((url or "").lower()).path or (url or "").lower()
    return [segment for segment in path.strip("/").split("/") if segment]


def _report_is_public_content_context_url(url: str) -> bool:
    low = (url or "").lower()
    path = urlparse(low).path or low
    if any(marker in path for marker in _REPORT_PUBLIC_CONTENT_PATH_MARKERS):
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


def _report_has_strong_debug_surface_evidence(url: str) -> bool:
    low = (url or "").lower()
    path = urlparse(low).path or low
    segments = set(_report_url_path_segments(low))

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
    )
    if any(token in low for token in strong_tokens):
        return True

    return path.endswith(("/phpinfo", "/server-status"))


def _report_is_source_control_exposure_url(url: str) -> bool:
    low = (url or "").lower()
    path = urlparse(low).path or low
    return path == "/.git" or path.startswith("/.git/") or "/.git/" in path


def _report_is_strong_backup_exposure_url(url: str) -> bool:
    low = (url or "").lower()
    path = urlparse(low).path or low
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


def _report_is_backup_manual_review_url(url: str) -> bool:
    low = (url or "").lower()
    path = urlparse(low).path or low
    if _report_is_public_content_context_url(low):
        return False
    if _report_is_strong_backup_exposure_url(low):
        return False
    return path.rstrip("/") in {"/backup", "/backups"} or path.startswith(("/backup/", "/backups/"))


def _report_dashboard_has_admin_context(url: str) -> bool:
    low = (url or "").lower()
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


def _filter_report_admin_like(urls: list[str]) -> list[str]:
    filtered: list[str] = []
    for url in urls or []:
        low = str(url or "").lower()
        if "dashboard" in low and not _report_dashboard_has_admin_context(low):
            continue
        if _report_is_public_content_context_url(low) and not _report_dashboard_has_admin_context(low):
            continue
        filtered.append(url)
    return filtered


def _filter_report_auth_like(urls: list[str]) -> list[str]:
    filtered: list[str] = []
    for url in urls or []:
        low = str(url or "").lower()
        if _report_is_public_content_context_url(low):
            continue
        filtered.append(url)
    return filtered


def _filter_report_debug_like(urls: list[str]) -> list[str]:
    filtered: list[str] = []
    for url in urls or []:
        low = str(url or "").lower()
        if _report_is_source_control_exposure_url(low):
            continue
        if not _report_has_strong_debug_surface_evidence(low):
            continue
        if _report_is_public_content_context_url(low) and not _report_has_strong_debug_surface_evidence(low):
            continue
        filtered.append(url)
    return filtered


def _report_prune_debug_false_positive_artifacts(
    attack_chains: Any,
    attack_graph: Any,
    exploit_suggestions: Any,
    *,
    keep_debug_config_artifacts: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    chains = [item for item in (attack_chains or []) if isinstance(item, dict)]
    graph = dict(attack_graph) if isinstance(attack_graph, dict) else {}
    suggestions = [item for item in (exploit_suggestions or []) if isinstance(item, dict)]
    if keep_debug_config_artifacts:
        return chains, graph, suggestions

    def _is_debug_config_text(value: Any) -> bool:
        low = str(value or "").lower()
        return "debug/test" in low or "debug / config" in low or "config leak" in low

    chains = [
        item for item in chains
        if not _is_debug_config_text(item.get("name"))
    ]

    graph["nodes"] = [
        node for node in (graph.get("nodes", []) if isinstance(graph.get("nodes"), list) else [])
        if isinstance(node, dict)
        and str(node.get("id") or "").lower() not in {"debug", "config_leak"}
        and not _is_debug_config_text(node.get("label"))
    ]
    graph["edges"] = [
        edge for edge in (graph.get("edges", []) if isinstance(graph.get("edges"), list) else [])
        if isinstance(edge, dict)
        and str(edge.get("from") or "").lower() not in {"debug", "config_leak"}
        and str(edge.get("to") or "").lower() not in {"debug", "config_leak"}
        and not _is_debug_config_text(edge.get("reason"))
    ]
    graph["paths"] = [
        path for path in (graph.get("paths", []) if isinstance(graph.get("paths"), list) else [])
        if isinstance(path, dict)
        and not _is_debug_config_text(path.get("name"))
    ]
    graph["chain_names"] = [
        name for name in (graph.get("chain_names", []) if isinstance(graph.get("chain_names"), list) else [])
        if not _is_debug_config_text(name)
    ]

    suggestions = [
        item for item in suggestions
        if not (
            _is_debug_config_text(item.get("title"))
            or _is_debug_config_text(item.get("surface"))
        )
    ]
    return chains, graph, suggestions


def _report_structural_exposure_groups(urls: list[str]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {
        "source_control": [],
        "config": [],
        "backup": [],
        "logs": [],
        "debug_console": [],
        "runtime": [],
        "internal_api": [],
        "admin_export": [],
    }
    for url in sorted(set(str(item or "") for item in urls or [] if str(item or "").strip())):
        low = url.lower()
        path = urlparse(low).path or low
        if _report_is_public_content_context_url(low) and not _report_has_strong_debug_surface_evidence(low):
            continue
        if _report_is_source_control_exposure_url(low):
            groups["source_control"].append(url)
        if any(token in low for token in ("/config/env", ".env", "wp-config", "app-config", "config.php", "config.json", "config.yml", "config.yaml")):
            groups["config"].append(url)
        if _report_is_strong_backup_exposure_url(url):
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


def _report_has_upload_execution_evidence(upload_urls: list[str]) -> bool:
    for url in upload_urls or []:
        low = str(url or "").lower()
        path = urlparse(low).path or low
        if path.endswith((".php", ".phtml", ".phar", ".asp", ".aspx", ".jsp", ".cgi", ".pl", ".sh")):
            return True
        if any(token in low for token in ("webshell", "shell.php", "execute", "handler", "parser", "deserial", "unrestricted-upload")):
            return True
    return False


def _report_has_strong_docs_signal(api_urls: list[str], docs_urls: list[str], tech_labels: list[str]) -> bool:
    non_public_docs = [
        url for url in (docs_urls or [])
        if not _report_is_public_content_context_url(str(url or ""))
    ]
    combined = " ".join((api_urls or []) + non_public_docs + (tech_labels or [])).lower()
    return any(
        token in combined
        for token in (
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
    )


def _now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _read_run_result_json(path: Path) -> dict[str, Any]:
    try:
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return raw
    except Exception:
        pass
    return {}


# --- Lightweight Nuclei JSONL reader for live/fallback findings ---
def _read_nuclei_jsonl_findings(path: Path | str | None) -> list[dict[str, str]]:
    """Best-effort lightweight reader for nuclei JSONL output.

    Used for live report refresh and as a fallback if the final parser returns
    no findings even though JSONL lines exist.
    """
    if not path:
        return []

    try:
        jsonl_path = Path(path)
        if not jsonl_path.exists():
            return []
    except Exception:
        return []

    findings: list[dict[str, str]] = []
    try:
        for raw_line in jsonl_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = (raw_line or "").strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue

            info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
            findings.append(
                {
                    "matched_at": str(obj.get("matched-at") or obj.get("host") or obj.get("url") or ""),
                    "name": str(info.get("name") or obj.get("template-id") or "Unknown"),
                    "severity": str(info.get("severity") or "unknown"),
                    "template_id": str(obj.get("template-id") or "Unknown"),
                }
            )
    except Exception:
        return []

    return findings



def _update_nuclei_stage(existing: dict[str, Any], nuclei_results: dict, nuclei_output_path: Path | None) -> dict[str, Any]:
    stages = existing.get("stages") if isinstance(existing.get("stages"), dict) else {}
    nuclei_stage = stages.get("nuclei") if isinstance(stages.get("nuclei"), dict) else {
        "status": "pending",
        "started_at": None,
        "ended_at": None,
        "artifacts": {},
    }

    status_value = str((nuclei_results or {}).get("Status") or "")
    error_value = str((nuclei_results or {}).get("Error") or "")

    findings_count = 0
    try:
        findings_count = len(nuclei_to_findings(nuclei_results or {}))
    except Exception:
        findings_count = 0

    if status_value == "Success":
        stage_status = "done"
    elif status_value == "Clean":
        stage_status = "done"
    elif status_value == "Partial":
        stage_status = "error"
    elif status_value == "Error":
        stage_status = "error"
    else:
        stage_status = "done" if findings_count >= 0 else "error"

    artifacts = nuclei_stage.get("artifacts") if isinstance(nuclei_stage.get("artifacts"), dict) else {}
    if nuclei_output_path is not None:
        artifacts["output"] = str(nuclei_output_path)

    nuclei_stage["status"] = stage_status
    nuclei_stage["ended_at"] = _now_iso()
    nuclei_stage["artifacts"] = artifacts
    nuclei_stage["findings_count"] = findings_count
    if error_value:
        nuclei_stage["error"] = error_value

    stages["nuclei"] = nuclei_stage
    existing["stages"] = stages

    # --- Run lifecycle flags (used by report auto-refresh) ---
    # If the run was already marked as interrupted by the user, keep that.
    if str(existing.get("run_state") or "").strip().lower() != "interrupted":
        if stage_status == "done":
            existing["run_state"] = "completed"
            existing["auto_refresh_enabled"] = False
            existing["interrupted_by_user"] = bool(existing.get("interrupted_by_user", False))
        elif stage_status == "error":
            existing["run_state"] = "failed"
            existing["auto_refresh_enabled"] = False
            existing["interrupted_by_user"] = bool(existing.get("interrupted_by_user", False))
    return existing


# --- HTML report helpers ---


def _html_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )



def _load_report_context(output_dir: Path | str | None) -> dict[str, Any]:
    if output_dir is None:
        report_dir = Path(__file__).resolve().parent
    else:
        report_dir = Path(output_dir)
    report_dir = report_dir.resolve()
    return _read_run_result_json(report_dir / "run_result.json")


def _target_identity_key(value: object) -> str:
    text = str(value or "").strip().lower().rstrip("/")
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else f"//{text}")
    host = parsed.hostname or text.split("/", 1)[0].split(":", 1)[0]
    return host.strip(".").lower() or text


def _extract_log_target(log_path: Path) -> str:
    try:
        if not log_path.exists():
            return ""
        text = log_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""
    patterns = (
        r"Run initialized:\s*target=(?P<target>\S+)",
        r"App scan requested:\s*target=(?P<target>\S+)",
        r"Target \((?:URL|Domain|IP)\):\s*(?P<target>\S+)",
    )
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return str(match.group("target") or "").strip()
    return ""


def _render_artifact_identity_block(
    *,
    report_dir: Path,
    report_path: Path,
    run_context: dict[str, Any],
    target: object,
) -> str:
    meta = run_context.get("meta") if isinstance(run_context.get("meta"), dict) else {}
    run_id = str(run_context.get("timestamp") or meta.get("timestamp") or report_dir.name or "-")
    started_at = str(run_context.get("started_at") or meta.get("started_at") or "-")
    run_target = str(meta.get("target") or run_context.get("target") or target or "-")
    report_target = str(target or run_target or "-")
    log_path = report_dir / "reconbot.log"
    log_target = _extract_log_target(log_path)
    log_target_display = log_target or "not available in this run directory"
    mismatch = bool(
        log_target
        and _target_identity_key(log_target)
        and _target_identity_key(report_target)
        and _target_identity_key(log_target) != _target_identity_key(report_target)
    )
    warning_html = (
        '<div class="artifact-identity-warning">Artifact mismatch: this log appears to belong to a different target.</div>'
        if mismatch
        else ""
    )
    return f"""
    <div class="artifact-identity" aria-label="Run artifact identity">
      <div><div class="label">run_id / timestamp</div><code>{_html_escape(run_id)}{_html_escape(' | ' + started_at if started_at and started_at != '-' else '')}</code></div>
      <div><div class="label">target</div><code>{_html_escape(run_target)}</code></div>
      <div><div class="label">report file target</div><code>{_html_escape(report_target)}</code></div>
      <div><div class="label">report file</div><code>{_html_escape(str(report_path))}</code></div>
      <div><div class="label">log target</div><code>{_html_escape(log_target_display)}</code></div>
      {warning_html}
    </div>
    """


def _report_element_ids(html: str) -> set[str]:
    return {match.group(1) for match in re.finditer(r'\bid=["\']([^"\']+)["\']', html or "")}


def _report_internal_href_anchors(html: str) -> set[str]:
    return {match.group(1) for match in re.finditer(r'href=["\']#([^"\']+)["\']', html or "") if match.group(1)}


def _disable_broken_internal_hrefs(html: str) -> tuple[str, list[str]]:
    ids = _report_element_ids(html)
    missing = sorted(anchor for anchor in _report_internal_href_anchors(html) if anchor not in ids)
    fixed = html
    for anchor in missing:
        fixed = fixed.replace(
            f'href="#{anchor}"',
            f'data-disabled-anchor="#{anchor}" aria-disabled="true"',
        )
    marker = (
        f"<!-- reconbot-internal-link-audit: disabled missing anchors {', '.join(missing)} -->"
        if missing
        else "<!-- reconbot-internal-link-audit: ok -->"
    )
    return fixed.replace("</body>", f"{marker}\n    </body>"), missing

def _derive_report_base_url(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
        return raw.rstrip("/")
    return f"http://{raw}"


def _is_probably_static_asset_url(url: str) -> bool:
    low = (url or "").lower()
    static_exts = (
        ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".otf", ".webp", ".mp4", ".mp3", ".pdf",
    )
    if any(low.endswith(ext) for ext in static_exts):
        return True

    static_markers = (
        "/wp-includes/js/",
        "/wp-includes/fonts/",
        "/wp-admin/load-scripts.php",
        "/wp-admin/load-styles.php",
        "/assets/",
        "/static/",
        "/dist/",
        "/fonts/",
        "/css/",
        "/js/",
    )
    return any(marker in low for marker in static_markers)

def _is_reportworthy_endpoint_url(url: str) -> bool:
    low = (url or "").lower().strip()
    if not low:
        return False

    keep_markers = (
        "wp-admin",
        "wp-login",
        "lostpassword",
        "xmlrpc",
        "server-status",
        "phpmyadmin",
        "register",
        "upload",
        "documentation",
        "swagger",
        "redoc",
        "openapi",
        "graphql",
        "actuator",
        "webservices",
        "api/",
        "/api",
        "debug",
        "test",
        "framer",
    )
    if any(marker in low for marker in keep_markers):
        return True

    noisy_markers = (
        "do=toggle-",
        "bubble-hints",
        "enforce-ssl",
        "toggle-hints",
        "toggle-security",
        "toggle-bubble",
        "toggle-enforce",
        "?p=",
        "?cat=",
        "feed=rss",
        "feed-comments",
        "author=",
        "replytocom=",
        "format=xml",
        "embed=true",
    )
    if any(marker in low for marker in noisy_markers):
        return False

    parsed = urlparse(low)
    path = parsed.path or ""
    if path in {"", "/", "/index.php", "/index.html"}:
        return False

    return True

# --- Inserted helper: _normalize_report_scheme ---
def _normalize_report_scheme(raw_url: str, base_url: str = "") -> str:
    raw = str(raw_url or "").strip()
    if not raw or not base_url:
        return raw

    try:
        parsed_raw = urlparse(raw)
        parsed_base = urlparse(base_url)
    except Exception:
        return raw

    if parsed_raw.scheme not in {"http", "https"}:
        return raw
    if parsed_base.scheme not in {"http", "https"}:
        return raw

    raw_host = (parsed_raw.hostname or "").lower()
    base_host = (parsed_base.hostname or "").lower()
    if not raw_host or not base_host:
        return raw
    if raw_host != base_host:
        return raw

    localhost_aliases = {"localhost", "127.0.0.1", "::1"}
    same_local_target = raw_host in localhost_aliases or base_host in localhost_aliases
    if not same_local_target:
        return raw

    if parsed_raw.scheme == parsed_base.scheme:
        return raw

    normalized = parsed_raw._replace(scheme=parsed_base.scheme)
    return urlunparse(normalized)


def _sanitize_report_url(url: Any, base_url: str = "") -> str:
    raw = str(url or "").strip()
    if not raw:
        return ""
    if raw.startswith("data:"):
        return ""
    if raw.startswith("//"):
        raw = "http:" + raw
    if raw.startswith("/"):
        safe = urljoin(base_url.rstrip("/") + "/", raw.lstrip("/")) if base_url else raw
        return _normalize_report_scheme(safe, base_url)
    if raw.startswith("?"):
        safe = urljoin(base_url.rstrip("/") + "/", raw) if base_url else ""
        return _normalize_report_scheme(safe, base_url)

    parsed = urlparse(raw)
    if parsed.scheme in {"http", "https"}:
        return _normalize_report_scheme(raw, base_url)

    if not parsed.scheme and not parsed.netloc:
        safe = urljoin(base_url.rstrip("/") + "/", raw.lstrip("/")) if base_url else raw
        return _normalize_report_scheme(safe, base_url)

    return ""


def _dedupe_urls_by_path(urls: list[str]) -> list[str]:
    seen: set[tuple[str, str]] = set()
    out: list[str] = []

    for raw_url in urls:
        parsed = urlparse(raw_url)
        key = ((parsed.netloc or "").lower(), (parsed.path or "/").lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(raw_url)

    return out


def _normalize_report_endpoint_bucket(
    values: list[Any],
    base_url: str,
    *,
    drop_static_assets: bool = True,
) -> list[str]:
    cleaned: list[str] = []
    source_values = values if isinstance(values, list) else []

    for value in source_values:
        safe = _sanitize_report_url(value, base_url)
        if not safe:
            continue
        if drop_static_assets and _is_probably_static_asset_url(safe):
            continue
        if not _is_reportworthy_endpoint_url(safe):
            continue
        cleaned.append(safe)

    return _dedupe_urls_by_path(cleaned)


def _normalize_report_item_bucket(
    values: list[dict[str, Any]],
    base_url: str,
    *,
    drop_static_assets: bool = True,
) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    source_values = values if isinstance(values, list) else []

    for item in source_values:
        if not isinstance(item, dict):
            continue

        safe_url = _sanitize_report_url(item.get("url"), base_url)
        if not safe_url:
            continue
        if drop_static_assets and _is_probably_static_asset_url(safe_url):
            continue
        if not _is_reportworthy_endpoint_url(safe_url):
            continue

        parsed = urlparse(safe_url)
        key = ((parsed.netloc or "").lower(), (parsed.path or "/").lower())
        reason = str(item.get("reason") or item.get("type") or item.get("status") or "")
        dedupe_key = (key[0] + key[1], reason)

        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        new_item = dict(item)
        new_item["url"] = safe_url
        cleaned.append(new_item)

    return cleaned


def _render_report_link(url: Any, base_url: str) -> str:
    safe = _sanitize_report_url(url, base_url)
    if not safe:
        return "-"
    return f'<a class="report-link" href="{_html_escape(safe)}" target="_blank">{_html_escape(safe)}</a>'


def _render_detail_value(value: Any, base_url: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return _html_escape(value)
    if raw.startswith(("http://", "https://", "//", "/")):
        safe = _sanitize_report_url(raw, base_url)
        if safe:
            return _render_report_link(safe, base_url)
    return _html_escape(value)


def _render_endpoint_list_with_details(urls: list[str], base_url: str, preview_count: int = 5) -> str:
    cleaned = [u for u in (urls or []) if u]
    if not cleaned:
        return '<span class="note">-</span>'

    preview = cleaned[:preview_count]
    preview_html = "".join(
        f"<li>{_render_report_link(u, base_url)}</li>" for u in preview
    )

    if len(cleaned) <= preview_count:
        return f'<ul class="compact-list">{preview_html}</ul>'

    remaining = cleaned[preview_count:]
    remaining_html = "".join(
        f"<li>{_render_report_link(u, base_url)}</li>" for u in remaining
    )

    return (
        f'<ul class="compact-list">{preview_html}</ul>'
        f'<details><summary>+{len(remaining)} more</summary>'
        f'<ul class="compact-list">{remaining_html}</ul></details>'
    )


def _is_url_like_text(value: Any) -> bool:
    raw = str(value or "").strip()
    return raw.startswith(("http://", "https://", "//", "/"))


def _normalize_compare_path(path: str) -> str:
    raw = str(path or "").strip()
    if not raw:
        return "/"
    normalized = raw if raw.startswith("/") else "/" + raw
    if normalized != "/":
        normalized = normalized.rstrip("/")
        if not normalized:
            normalized = "/"
    return normalized


def _build_enum_finding_record(
    *,
    source: str,
    base_url: Any,
    item: Any,
    report_base_url: str,
) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None

    safe_base = _sanitize_report_url(base_url, report_base_url)
    safe_url = _sanitize_report_url(item.get("url", ""), report_base_url)
    raw_path = str(item.get("path") or "").strip()
    if not safe_url and raw_path:
        if raw_path.startswith(("http://", "https://", "//", "/")):
            safe_url = _sanitize_report_url(raw_path, report_base_url)
        elif safe_base:
            safe_url = _sanitize_report_url(urljoin(safe_base.rstrip("/") + "/", raw_path.lstrip("/")), report_base_url)

    if not safe_url and not raw_path:
        return None

    parsed = urlparse(safe_url) if safe_url else urlparse("")
    normalized_path = _normalize_compare_path(parsed.path or raw_path or "/")
    if parsed.query:
        display_path = f"{normalized_path}?{parsed.query}"
    else:
        display_path = normalized_path

    try:
        status_value = int(item.get("status", 0) or 0)
    except Exception:
        status_value = 0

    compare_host = (parsed.netloc or "").strip().lower()
    if not compare_host and safe_base:
        compare_host = (urlparse(safe_base).netloc or "").strip().lower()
    if not compare_host:
        compare_host = "unknown-host"

    compare_key = (compare_host, normalized_path.lower(), status_value)

    metadata_parts: list[str] = []
    for label, keys in (
        ("len", ("content_length", "length", "size")),
        ("words", ("words",)),
        ("lines", ("lines",)),
    ):
        value_text = ""
        for key in keys:
            raw_val = item.get(key)
            if raw_val is None:
                continue
            candidate = str(raw_val).strip()
            if candidate:
                value_text = candidate
                break
        if value_text:
            metadata_parts.append(f"{label}={value_text}")

    return {
        "source": source,
        "base_url": safe_base or str(base_url or "").strip(),
        "url": safe_url,
        "path": display_path,
        "status": status_value,
        "metadata": ", ".join(metadata_parts) if metadata_parts else "-",
        "compare_key": compare_key,
    }


def _normalize_analysis_cluster_insights(
    cluster_insights: Any,
    base_url: str,
) -> list[dict[str, Any]]:
    clusters: list[dict[str, Any]] = []
    if not isinstance(cluster_insights, list):
        return clusters

    for item in cluster_insights:
        if not isinstance(item, dict):
            continue

        representative = _sanitize_report_url(item.get("representative_url"), base_url)
        if not representative:
            continue

        raw_variants = item.get("variant_urls", []) if isinstance(item.get("variant_urls"), list) else []
        variants: list[str] = []
        seen_variants: set[str] = set()
        for raw_u in raw_variants:
            safe_u = _sanitize_report_url(raw_u, base_url)
            if not safe_u:
                continue
            if safe_u in seen_variants:
                continue
            seen_variants.add(safe_u)
            variants.append(safe_u)

        if representative not in seen_variants:
            variants.insert(0, representative)

        bucket_labels = [
            str(label or "").strip()
            for label in (item.get("bucket_labels", []) or [])
            if str(label or "").strip()
        ]
        risk_signals = [
            str(signal or "").strip()
            for signal in (item.get("risk_signals", []) or [])
            if str(signal or "").strip()
        ]
        notes = [
            str(note or "").strip()
            for note in (item.get("explanatory_notes", []) or [])
            if str(note or "").strip()
        ]

        clusters.append(
            {
                "canonical_key": str(item.get("canonical_key") or ""),
                "representative_url": representative,
                "family_type": str(item.get("family_type") or "page"),
                "bucket_labels": bucket_labels,
                "variants_count": max(
                    int(item.get("variants_count", 0) or 0),
                    len(variants),
                ),
                "variant_urls": variants,
                "unique_statuses": item.get("unique_statuses", []) if isinstance(item.get("unique_statuses"), list) else [],
                "unique_content_lengths": item.get("unique_content_lengths", []) if isinstance(item.get("unique_content_lengths"), list) else [],
                "unique_titles": item.get("unique_titles", []) if isinstance(item.get("unique_titles"), list) else [],
                "has_security_relevant_query": bool(item.get("has_security_relevant_query")),
                "has_meaningful_response_diversity": bool(item.get("has_meaningful_response_diversity")),
                "risk_signals": risk_signals,
                "explanatory_notes": notes,
            }
        )

    return clusters


def _build_analysis_cluster_maps(
    normalized_clusters: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    rep_map: dict[str, dict[str, Any]] = {}
    variant_to_rep: dict[str, str] = {}
    for cluster in normalized_clusters:
        rep = str(cluster.get("representative_url") or "").strip()
        if not rep:
            continue
        rep_map[rep] = cluster
        variant_to_rep[rep] = rep
        for variant in cluster.get("variant_urls", []) or []:
            variant_url = str(variant or "").strip()
            if variant_url and variant_url not in variant_to_rep:
                variant_to_rep[variant_url] = rep
    return rep_map, variant_to_rep


def _prepare_representative_urls(
    urls: list[Any],
    *,
    base_url: str,
    variant_to_rep: dict[str, str] | None = None,
    drop_static_assets: bool = True,
    require_reportworthy: bool = True,
) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    mapper = variant_to_rep or {}

    for raw_u in urls if isinstance(urls, list) else []:
        safe_u = _sanitize_report_url(raw_u, base_url)
        if not safe_u:
            continue
        if drop_static_assets and _is_probably_static_asset_url(safe_u):
            continue
        if require_reportworthy and not _is_reportworthy_endpoint_url(safe_u):
            continue
        rep = mapper.get(safe_u, safe_u)
        if rep in seen:
            continue
        seen.add(rep)
        out.append(rep)
    return out


def _prepare_source_bucket_urls(
    urls: list[Any],
    *,
    base_url: str,
    drop_static_assets: bool = True,
) -> list[str]:
    """Normalize upstream bucket URLs without representative remapping."""
    out: list[str] = []
    seen: set[str] = set()
    for raw_u in urls if isinstance(urls, list) else []:
        safe_u = _sanitize_report_url(raw_u, base_url)
        if not safe_u:
            continue
        if drop_static_assets and _is_probably_static_asset_url(safe_u):
            continue
        if safe_u in seen:
            continue
        seen.add(safe_u)
        out.append(safe_u)
    return out


def _render_representative_endpoint(
    representative_url: str,
    base_url: str,
    cluster: dict[str, Any] | None = None,
    *,
    preview_variants: int = 8,
) -> str:
    primary = _render_report_link(representative_url, base_url)
    if not cluster:
        return primary

    rep_safe = _sanitize_report_url(representative_url, base_url)
    seen: set[str] = set()
    renderable_variants: list[str] = []

    for raw_variant in (cluster.get("variant_urls", []) or []):
        if raw_variant is None:
            continue
        if isinstance(raw_variant, (dict, list, tuple, set)):
            # Skip malformed/non-string variant entries entirely.
            continue

        raw_text = str(raw_variant).strip()
        if not raw_text:
            continue

        safe_variant = _sanitize_report_url(raw_text, base_url)
        if not safe_variant:
            continue
        if rep_safe and safe_variant == rep_safe:
            continue
        if safe_variant in seen:
            continue
        seen.add(safe_variant)
        renderable_variants.append(safe_variant)

    total_renderable = len(renderable_variants)
    if total_renderable <= 0:
        return primary

    if preview_variants > 0 and total_renderable > preview_variants:
        shown_variants = renderable_variants[:preview_variants]
    else:
        shown_variants = renderable_variants

    rendered_items = [
        f"<li>{_render_report_link(variant_url, base_url)}</li>"
        for variant_url in shown_variants
    ]
    if not rendered_items:
        return primary

    shown_count = len(shown_variants)
    if shown_count < total_renderable:
        summary_label = f"Varyantları göster ({shown_count}/{total_renderable})"
    else:
        summary_label = f"Varyantları göster ({shown_count})"

    more_count = max(0, total_renderable - shown_count)
    more_note = (
        f'<div class="small-note">+{more_count} ek geçerli varyant gösterilmedi</div>'
        if more_count
        else ""
    )

    return (
        f"{primary}"
        f'<details><summary>{summary_label}</summary>'
        f'<ul class="compact-list">{"".join(rendered_items)}</ul>'
        f"{more_note}"
        f"</details>"
    )


def _render_stage_rows(run_context: dict[str, Any]) -> str:
    stages = run_context.get("stages") if isinstance(run_context.get("stages"), dict) else {}
    ordered_names = ["nmap", "subfinder", "dnsx", "httpx", "katana", "gobuster", "ffuf", "historical_urls", "wafw00f", "whatweb", "checks", "nuclei"]

    if not stages:
        return """
            <tr>
                <td colspan=\"5\">""" + _html_escape(_txt("pipeline_table_missing")) + """</td>
            </tr>
        """

    rows: list[str] = []
    status_labels = {
        "done": "tamamlandı",
        "success": "tamamlandı",
        "completed": "tamamlandı",
        "skipped": "atlanmış",
        "pending": "bekliyor",
        "running": "çalışıyor",
        "interrupted": "kesildi",
        "error": "hata",
        "failed": "hata",
        "empty": "boş",
    }
    for name in ordered_names:
        stage = stages.get(name) if isinstance(stages.get(name), dict) else {}
        status = str(stage.get("status") or "pending")
        status_display = status_labels.get(status.strip().lower(), status)
        started_at = _html_escape(stage.get("started_at") or "-")
        ended_at = _html_escape(stage.get("ended_at") or "-")
        artifacts = stage.get("artifacts") if isinstance(stage.get("artifacts"), dict) else {}

        artifact_parts: list[str] = []
        for artifact_name, artifact_path in artifacts.items():
            if artifact_path:
                artifact_parts.append(f"<code>{_html_escape(artifact_name)}</code>: {_html_escape(artifact_path)}")

        if not artifact_parts:
            artifact_html = f'<span class="note">{_html_escape(_txt("pipeline_no_artifacts"))}</span>'
        else:
            artifact_html = "<br>".join(artifact_parts)

        status_class = f"stage-{status.lower()}"
        rows.append(
            f"""
            <tr>
                <td><strong>{_html_escape(name)}</strong></td>
                <td class=\"{status_class}\">{_html_escape(status_display)}</td>
                <td>{started_at}</td>
                <td>{ended_at}</td>
                <td>{artifact_html}</td>
            </tr>
            """
        )

    return "\n".join(rows)



def _render_nuclei_state_note(run_context: dict[str, Any], nuclei_results: dict) -> str:
    stages = run_context.get("stages") if isinstance(run_context.get("stages"), dict) else {}
    nuclei_stage = stages.get("nuclei") if isinstance(stages.get("nuclei"), dict) else {}
    stage_status = str(nuclei_stage.get("status") or "").strip().lower()
    findings_count = _safe_int(nuclei_stage.get("findings_count"), 0)
    run_state = str(run_context.get("run_state") or "").strip().lower()
    result_status = str((nuclei_results or {}).get("Status") or "").strip().lower()
    error_value = str((nuclei_results or {}).get("Error") or nuclei_stage.get("error") or "").strip()
    output_path = ""
    artifacts = nuclei_stage.get("artifacts") if isinstance(nuclei_stage.get("artifacts"), dict) else {}
    if artifacts.get("output"):
        output_path = str(artifacts.get("output"))

    if run_state == "interrupted" or stage_status == "interrupted":
        return _txt("nuclei_state_interrupted")

    if result_status == "live":
        extra = f" Output: <code>{_html_escape(output_path)}</code>" if output_path else ""
        return _txt("nuclei_state_live_snapshot", extra=extra)

    if (stage_status == "running" or run_state == "running") and not nuclei_results:
        extra = f" Output: <code>{_html_escape(output_path)}</code>" if output_path else ""
        return _txt("nuclei_state_live", extra=extra)

    if stage_status in {"done", "completed", "success"} and not nuclei_results:
        return _txt("nuclei_state_done_without_result")

    if stage_status in {"error", "failed"} and not nuclei_results:
        if error_value:
            return _txt("nuclei_state_error_with_value", error=_html_escape(error_value[:220]))
        return _txt("nuclei_state_error")

    if nuclei_results:
        note_parts = [
            f"<strong>Nuclei stage:</strong> {_html_escape(stage_status or 'unknown')}",
            f"<strong>Findings:</strong> {findings_count}",
        ]
        if result_status:
            note_parts.append(f"<strong>Status:</strong> {_html_escape(result_status)}")
        return f'<p class="note">{" | ".join(note_parts)}</p>'

    return _txt("nuclei_state_no_result")


def _normalize_nuclei_severity(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw in {"", "-", "none", "n/a"}:
        return "unknown"
    if raw in {"critical", "high", "medium", "low", "info", "unknown"}:
        return raw
    if raw == "informational":
        return "info"
    if "crit" in raw:
        return "critical"
    if "high" in raw:
        return "high"
    if "med" in raw:
        return "medium"
    if "low" in raw:
        return "low"
    if "info" in raw:
        return "info"
    return "unknown"


def _nuclei_severity_rank(severity: Any) -> int:
    normalized = _normalize_nuclei_severity(severity)
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
        "unknown": 0,
    }.get(normalized, 0)


def _nuclei_severity_bucket(severity: Any) -> str:
    normalized = _normalize_nuclei_severity(severity)
    if normalized == "critical":
        return "critical"
    if normalized == "high":
        return "high"
    if normalized == "medium":
        return "medium"
    return "low_info_unknown"


def _nuclei_severity_badge_html(severity: Any) -> str:
    normalized = _normalize_nuclei_severity(severity)
    if normalized in {"critical", "high"}:
        tone = "bad"
    elif normalized == "medium":
        tone = "warn"
    elif normalized in {"low", "info"}:
        tone = "ok"
    else:
        tone = "warn"
    label = "Info" if normalized == "info" else normalized.capitalize()
    return f'<span class="pill {tone}">{_html_escape(label)}</span>'


def _nuclei_trust_badge_html(trust_level: Any) -> str:
    trust = str(trust_level or "").strip().lower()
    if trust == "high":
        return '<span class="pill ok">Güven: High</span>'
    if trust == "medium":
        return '<span class="pill warn">Güven: Medium</span>'
    if trust == "low":
        return '<span class="pill bad">Güven: Low</span>'
    return '<span class="pill">Güven: Unknown</span>'


def _nuclei_evidence_text(entry: dict[str, Any] | None) -> str:
    if not isinstance(entry, dict):
        return ""
    parts: list[str] = []

    def _collect(value: Any, *, depth: int = 0) -> None:
        if depth > 3:
            return
        if isinstance(value, bytes):
            try:
                text = value[:2048].decode("utf-8", errors="replace")
            except Exception:
                text = ""
            if text:
                parts.append(text)
            return
        if isinstance(value, str):
            if value.strip():
                parts.append(value[:2048])
            return
        if isinstance(value, (int, float, bool)):
            parts.append(str(value))
            return
        if isinstance(value, list):
            for item in value[:8]:
                _collect(item, depth=depth + 1)
            return
        if isinstance(value, dict):
            for key in (
                "evidence",
                "extracted-results",
                "extracted_results",
                "matcher-name",
                "matcherName",
                "matched-at",
                "matchedAt",
                "curl-command",
                "request",
                "response",
                "body",
                "data",
            ):
                if key in value:
                    _collect(value.get(key), depth=depth + 1)

    _collect(entry)
    return " ".join(part for part in parts if part).lower()


def _detect_nuclei_observed_evidence_type(
    *,
    template_id: Any,
    name: Any,
    description: Any,
    evidence: Any,
    raw: dict[str, Any] | None,
) -> str:
    text = " ".join(
        [
            str(template_id or ""),
            str(name or ""),
            str(description or ""),
            str(evidence or ""),
            _nuclei_evidence_text(raw),
        ]
    ).lower()
    passwd_markers = (
        "/etc/passwd",
        "root:x:0:0",
        "daemon:x:",
        "bin:x:",
        "nobody:x:",
        "passwd-like",
    )
    if any(marker in text for marker in passwd_markers):
        return "file_disclosure_passwd"
    if any(marker in text for marker in ("path traversal", "directory traversal", "local file inclusion", " lfi", "file read")):
        return "file_disclosure"
    if any(marker in text for marker in ("private key", "api_key", "secret", "token", ".env", "password=")):
        return "secret_or_config_disclosure"
    return ""


def _nuclei_observed_evidence_label(value: Any) -> str:
    key = str(value or "").strip().lower()
    labels = {
        "file_disclosure_passwd": "Observed evidence: file disclosure / passwd-like content",
        "file_disclosure": "Observed evidence: file disclosure / file-read behavior",
        "secret_or_config_disclosure": "Observed evidence: secret/config disclosure pattern",
    }
    return labels.get(key, "")


def _nuclei_product_specific_note(template_id: Any, name: Any, observed_type: Any) -> str:
    if not str(observed_type or "").strip():
        return ""
    text = f"{template_id or ''} {name or ''}".lower()
    generic_tokens = {
        "lfi",
        "local",
        "file",
        "read",
        "disclosure",
        "exposure",
        "path",
        "traversal",
        "generic",
        "misconfiguration",
        "config",
        "secret",
    }
    words = [
        token
        for token in re.split(r"[^a-z0-9]+", text)
        if len(token) >= 4 and token not in generic_tokens
    ]
    if not words:
        return ""
    return (
        "Template name is not proof that the target uses this exact product; "
        "treat it as evidence pattern matched by Nuclei and validate manually."
    )


def _nuclei_discovery_dependency_note(entry: dict[str, Any]) -> str:
    deps = entry.get("discovery_dependencies") if isinstance(entry.get("discovery_dependencies"), list) else []
    failed = set(
        str(item or "").strip().lower()
        for item in (entry.get("failed_dependencies") if isinstance(entry.get("failed_dependencies"), list) else [])
        if str(item or "").strip()
    )
    succeeded = set(
        str(item or "").strip().lower()
        for item in (entry.get("successful_dependencies") if isinstance(entry.get("successful_dependencies"), list) else [])
        if str(item or "").strip()
    )
    dep_parts: list[str] = []
    for dep in deps:
        dep_text = str(dep or "").strip()
        if not dep_text:
            continue
        dep_low = dep_text.lower()
        if dep_low in failed:
            dep_parts.append(f"{dep_text}=failed")
        elif dep_low in succeeded:
            dep_parts.append(f"{dep_text}=ok")
        else:
            dep_parts.append(f"{dep_text}=unknown")
    if not dep_parts:
        return ""
    return "deps: " + ", ".join(dep_parts)


def _nuclei_endpoint_identity_keys(endpoint: Any, base_url: str) -> set[str]:
    raw = str(endpoint or "").strip()
    if not raw:
        return set()

    keys: set[str] = {raw.lower()}
    safe = _sanitize_report_url(raw, base_url)
    if safe:
        keys.add(safe.lower())

    candidate = safe or raw
    parsed = urlparse(candidate)
    path = str(parsed.path or "").strip().lower()
    if path:
        if not path.startswith("/"):
            path = "/" + path
        path = path.rstrip("/") or "/"
        keys.add(path)

    host = str(parsed.hostname or "").strip().lower()
    if host:
        norm_path = path or "/"
        keys.add(f"{host}{norm_path}")

    return {key for key in keys if key}


def _build_nuclei_endpoint_context_index(
    *,
    base_url: str,
    classified_endpoints: dict[str, Any] | None = None,
    login_pages: list[dict[str, Any]] | None = None,
    docs_pages: list[dict[str, Any]] | None = None,
) -> dict[str, set[str]]:
    classified_map = classified_endpoints if isinstance(classified_endpoints, dict) else {}
    index: dict[str, set[str]] = {}

    def _ingest(values: Any, badge: str) -> None:
        if not isinstance(values, list):
            return
        for item in values:
            endpoint_value = item.get("url") if isinstance(item, dict) else item
            for key in _nuclei_endpoint_identity_keys(endpoint_value, base_url):
                index.setdefault(key, set()).add(badge)

    for bucket_name, badge_name in (
        ("admin_like", "admin"),
        ("auth_like", "auth"),
        ("api_like", "api"),
        ("upload_like", "upload"),
        ("debug_like", "debug"),
        ("docs_like", "docs"),
    ):
        _ingest(classified_map.get(bucket_name, []), badge_name)

    _ingest(login_pages or [], "auth")
    _ingest(docs_pages or [], "docs")
    return index


def _infer_nuclei_endpoint_badges(
    endpoint: Any,
    *,
    base_url: str,
    context_index: dict[str, set[str]] | None = None,
) -> list[str]:
    raw = str(endpoint or "").strip()
    if not raw:
        return []

    ordered_badges = [
        "admin",
        "auth",
        "api",
        "upload",
        "debug",
        "docs",
        "php",
        "static",
        "sensitive",
        "localhost-only",
        "query-heavy",
    ]
    context_index = context_index or {}

    detected: set[str] = set()
    keys = _nuclei_endpoint_identity_keys(raw, base_url)
    for key in keys:
        detected.update(context_index.get(key, set()))

    safe = _sanitize_report_url(raw, base_url)
    candidate = safe or raw
    parsed = urlparse(candidate)
    path = str(parsed.path or "").lower()
    query = str(parsed.query or "").lower()
    host = str(parsed.hostname or "").lower()
    combined = candidate.lower()
    public_content_context = _report_is_public_content_context_url(candidate)

    def _has(tokens: tuple[str, ...]) -> bool:
        return any(token in combined for token in tokens)

    if (
        not public_content_context
        and _has(("phpmyadmin", "/admin", "/administrator", "/manage", "/console", "wp-admin", "/dashboard", "/cpanel"))
    ):
        detected.add("admin")
    if (
        not public_content_context
        and _has((
        "/login",
        "wp-login",
        "/signin",
        "/sign-in",
        "/auth",
        "auth/",
        "/oauth",
        "/sso",
        "/session",
        "/token",
        "/register",
        "/signup",
        "reset-password",
        "forgot-password",
    ))
    ):
        detected.add("auth")
    if _has(("/api", "api/", "/graphql", "graphql", "webservice", "webservices", "/v1/", "/v2/", "/v3/", "/rest/")):
        detected.add("api")
    if _has(("/upload", "file-upload", "fileupload", "multipart", "/attachment", "/import", "/uploader", "dropzone")):
        detected.add("upload")
    if (
        (not public_content_context or _report_has_strong_debug_surface_evidence(candidate))
        and _has(("/debug", "server-status", "php-errors", "stacktrace", "/trace", "/profiler", "/actuator", "/diagnostic", "/__debug"))
    ):
        detected.add("debug")
    if _has(("/documentation", "/swagger", "/redoc", "/openapi", "/api-doc", "/apidoc", "/docs", "graphql-playground")):
        detected.add("docs")
    if path.endswith(".php") or _has((".php", "phpmyadmin", "phpinfo")):
        detected.add("php")
    if _is_probably_static_asset_url(candidate) or _has(("/static/", "/assets/", "/css/", "/js/", "/fonts/", "/img/")):
        detected.add("static")
    if (not public_content_context or _report_has_strong_debug_surface_evidence(candidate)) and _has((
        ".env",
        ".git",
        ".svn",
        ".hg",
        "wp-config",
        "id_rsa",
        ".htaccess",
        ".htpasswd",
        "phpmyadmin",
        "adminer",
        "backup",
        ".bak",
        ".old",
        ".sql",
        "secret",
        "credential",
        "passwd",
        "password",
        "token",
        "private",
        "server-status",
        "php-errors",
    )):
        detected.add("sensitive")

    if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        detected.add("localhost-only")

    query_parts = [part for part in query.split("&") if part.strip()]
    if (query and len(query) >= 70) or len(query_parts) >= 4:
        detected.add("query-heavy")

    # Cross-signal enrichments for operator triage.
    if "admin" in detected and "php" in detected:
        detected.add("sensitive")
    if "auth" in detected and ("token" in combined or "session" in combined):
        detected.add("sensitive")
    if "debug" in detected and ("localhost-only" in detected or "internal" in combined):
        detected.add("sensitive")

    return [badge for badge in ordered_badges if badge in detected]


def _nuclei_surface_badge_weights() -> dict[str, int]:
    return {
        "upload": 16,
        "admin": 15,
        "auth": 14,
        "sensitive": 13,
        "php": 9,
        "localhost-only": 9,
        "api": 8,
        "debug": 8,
        "docs": 4,
        "query-heavy": 3,
        "static": -6,
    }


def _rank_nuclei_surface_badges(badges: set[str]) -> list[str]:
    weights = _nuclei_surface_badge_weights()
    order = [
        "upload",
        "admin",
        "auth",
        "sensitive",
        "php",
        "localhost-only",
        "api",
        "debug",
        "docs",
        "query-heavy",
        "static",
    ]
    index_map = {name: idx for idx, name in enumerate(order)}
    return sorted(
        [badge for badge in badges if badge in weights],
        key=lambda badge: (-weights.get(badge, 0), index_map.get(badge, 999), badge),
    )


def _nuclei_review_priority_label(score: int) -> str:
    if score >= 85:
        return "Critical inceleme"
    if score >= 70:
        return "High inceleme"
    if score >= 45:
        return "Medium inceleme"
    return "Low inceleme"


def _nuclei_review_priority_pill_html(score: Any, label: Any) -> str:
    score_value = max(0, min(100, _safe_int(score, 0)))
    label_text = str(label or _nuclei_review_priority_label(score_value)).strip() or "Low inceleme"
    if score_value >= 85:
        tone = "review-critical"
    elif score_value >= 70:
        tone = "review-high"
    elif score_value >= 45:
        tone = "review-medium"
    else:
        tone = "review-low"
    return (
        f'<span class="pill nuclei-review-pill {tone}">'
        f'{_html_escape(label_text)} · {_html_escape(f"{score_value}/100")}'
        f"</span>"
    )


def _render_nuclei_endpoint_badges_html(badges: list[str]) -> str:
    if not badges:
        return ""
    rendered = "".join(
        f'<span class="nuclei-context-badge nuclei-context-{_html_escape(badge)}">{_html_escape(badge)}</span>'
        for badge in badges
    )
    return f'<span class="nuclei-endpoint-badges">{rendered}</span>'


def _looks_state_changing_endpoint(endpoint: str) -> bool:
    low = str(endpoint or "").lower()
    if not low:
        return False
    return any(
        marker in low
        for marker in (
            "update",
            "delete",
            "remove",
            "create",
            "save",
            "edit",
            "change",
            "reset",
            "upload",
            "import",
            "admin",
            "password",
            "profile",
            "account",
        )
    )


def _detect_nuclei_exploit_practicality(
    *,
    text: str,
    endpoints: list[str],
    all_badges: set[str],
) -> tuple[int, str]:
    low = str(text or "").lower()
    if not low:
        return 0, ""

    rules: list[tuple[str, int, tuple[str, ...]]] = [
        ("rce/command execution", 34, ("rce", "remote code execution", "command injection", "code execution", "deserialization")),
        ("sql injection", 30, ("sql injection", "sqli", "blind sql", "union select")),
        ("lfi/path traversal", 28, ("lfi", "local file inclusion", "path traversal", "directory traversal", "/etc/passwd", "file inclusion")),
        ("auth bypass/access control", 26, ("auth bypass", "authentication bypass", "authorization bypass", "idor", "access control", "privilege escalation")),
        ("ssrf", 24, ("ssrf", "server-side request forgery", "server side request forgery")),
        ("csrf", 14, ("csrf", "cross-site request forgery", "cross site request forgery")),
        ("xss", 12, ("xss", "cross site scripting", "dom-xss", "stored xss", "reflected xss")),
        ("open redirect", 8, ("open redirect", "redirect")),
        ("disclosure/misconfig", 6, ("information disclosure", "disclosure", "misconfiguration", "exposure")),
    ]

    matched: list[tuple[str, int]] = []
    for label, score, keywords in rules:
        if any(keyword in low for keyword in keywords):
            matched.append((label, score))

    if not matched:
        return 0, ""

    matched.sort(key=lambda item: item[1], reverse=True)
    points = matched[0][1]
    signal_label = matched[0][0]
    if len(matched) > 1 and matched[1][1] >= 18:
        points += 4

    if signal_label == "csrf":
        has_stateful_surface = any(
            badge in all_badges for badge in ("upload", "admin", "auth", "api")
        ) or any(_looks_state_changing_endpoint(endpoint) for endpoint in endpoints)
        if has_stateful_surface:
            points += 8
            signal_label = "csrf on state-changing surface"
        else:
            points += 2

    return min(points, 36), signal_label


def _compute_nuclei_review_priority(
    *,
    template_id: str,
    name: str,
    description: str,
    issue_preview: str,
    severity: str,
    endpoints: list[str],
    entries: list[dict[str, Any]],
    endpoint_badges: dict[str, list[str]],
) -> dict[str, Any]:
    severity_points = {
        "critical": 32,
        "high": 24,
        "medium": 16,
        "low": 8,
        "info": 3,
        "unknown": 5,
    }.get(_normalize_nuclei_severity(severity), 5)
    severity_norm = _normalize_nuclei_severity(severity)

    unique_endpoint_count = len(endpoints)
    endpoint_points = 0
    if unique_endpoint_count > 0:
        endpoint_points = min(14, 4 + min(unique_endpoint_count, 5) * 2)

    all_badges: set[str] = set()
    high_sensitivity_endpoints = 0
    for endpoint in endpoints:
        endpoint_set = set(endpoint_badges.get(endpoint, []))
        all_badges.update(endpoint_set)
        if any(
            badge in endpoint_set
            for badge in ("upload", "admin", "auth", "sensitive", "localhost-only")
        ):
            high_sensitivity_endpoints += 1

    badge_weights = _nuclei_surface_badge_weights()
    context_points = sum(
        weight
        for badge, weight in badge_weights.items()
        if badge in all_badges and weight > 0
    )
    context_points = min(30, context_points)

    context_penalty = 0
    if all_badges == {"static"}:
        context_penalty -= 10
    elif all_badges.issubset({"docs", "static", "query-heavy"}) and all_badges:
        context_penalty -= 4

    text_for_exploit = " ".join(
        [
            str(template_id or ""),
            str(name or ""),
            str(description or ""),
            str(issue_preview or ""),
            " ".join(str(item.get("evidence") or "") for item in entries[:4] if isinstance(item, dict)),
        ]
    )
    exploit_points, exploit_label = _detect_nuclei_exploit_practicality(
        text=text_for_exploit,
        endpoints=endpoints,
        all_badges=all_badges,
    )

    operational_points = 0
    if any(badge in all_badges for badge in ("upload", "admin", "auth")):
        operational_points += 10
    elif any(badge in all_badges for badge in ("api", "debug")):
        operational_points += 6
    if high_sensitivity_endpoints >= 2:
        operational_points += 3
    if unique_endpoint_count >= 3:
        operational_points += 2
    operational_points = min(14, operational_points)

    match_count = len(entries)
    match_points = 0
    if match_count > unique_endpoint_count and exploit_points >= 16:
        match_points = min(4, match_count - unique_endpoint_count)

    noisy_penalty = 0
    noisy_tokens = (
        "missing security header",
        "security headers",
        "x-powered-by",
        "server header",
        "favicon",
        "wappalyzer",
        "technology detection",
        "robots.txt",
    )
    if any(token in text_for_exploit.lower() for token in noisy_tokens) and exploit_points < 12:
        noisy_penalty -= 8
    if severity_norm in {"info", "low"} and exploit_points < 10 and not any(
        badge in all_badges for badge in ("upload", "admin", "auth", "sensitive", "debug")
    ):
        noisy_penalty -= 8

    raw_score = (
        severity_points
        + endpoint_points
        + context_points
        + context_penalty
        + exploit_points
        + operational_points
        + match_points
        + noisy_penalty
    )
    score = max(0, min(100, raw_score))
    label = _nuclei_review_priority_label(score)

    ranked_surface_badges = _rank_nuclei_surface_badges(all_badges)
    top_surface_badges = ranked_surface_badges[:3]
    highest_surface = ranked_surface_badges[0] if ranked_surface_badges else "general"

    factors: list[str] = []
    factors.append(f"severity {severity_norm} (+{severity_points})")
    if exploit_points > 0 and exploit_label:
        factors.append(f"exploit-practical signal: {exploit_label} (+{exploit_points})")
    if context_points or context_penalty:
        if top_surface_badges:
            surface_label = "/".join(top_surface_badges)
            factors.append(f"surface context: {surface_label} ({context_points + context_penalty:+d})")
        else:
            factors.append(f"surface context weighting ({context_points + context_penalty:+d})")
    if endpoint_points > 0:
        factors.append(f"{unique_endpoint_count} unique endpoints (+{endpoint_points})")
    if operational_points > 0:
        factors.append(f"operational relevance (+{operational_points})")
    if noisy_penalty < 0:
        factors.append(f"informational/noisy dampener ({noisy_penalty})")

    reasons = factors[:4]
    if len(reasons) < 2:
        reasons.append("deterministic baseline weighting applied")

    return {
        "score": score,
        "label": label,
        "reasons": reasons[:4],
        "surface_badges": top_surface_badges,
        "highest_surface": highest_surface,
    }


def _extract_nuclei_result_events(nuclei_results: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(nuclei_results, dict):
        return []

    events: list[dict[str, Any]] = []
    for key in ("findings", "Findings", "results", "Results", "data", "Data"):
        value = nuclei_results.get(key)
        if isinstance(value, list):
            events.extend(item for item in value if isinstance(item, dict))
            if events:
                break

    if not events and any(k in nuclei_results for k in ("template-id", "templateID", "id")):
        events = [nuclei_results]

    return events


def _build_nuclei_report_entries(nuclei_results: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(nuclei_results, dict):
        return []

    entries: list[dict[str, Any]] = []
    index_by_key: dict[tuple[str, str, str, str, str], int] = {}

    def _append_entry(
        *,
        endpoint: Any,
        name: Any,
        severity: Any,
        template_id: Any,
        description: Any = "",
        evidence: Any = "",
        source: str = "parsed",
        raw: dict[str, Any] | None = None,
    ) -> None:
        endpoint_text = str(endpoint or "").strip() or "unknown"
        name_text = str(name or "").strip() or "Unknown"
        severity_text = _normalize_nuclei_severity(severity)
        template_text = str(template_id or "").strip() or "Unknown"
        description_text = str(description or "").strip()
        evidence_text = str(evidence or "").strip()
        source_text = str(source or "parsed").strip().lower() or "parsed"
        observed_evidence_type = _detect_nuclei_observed_evidence_type(
            template_id=template_text,
            name=name_text,
            description=description_text,
            evidence=evidence_text,
            raw=raw,
        )
        product_note = _nuclei_product_specific_note(template_text, name_text, observed_evidence_type)
        key = (
            template_text.lower(),
            endpoint_text.lower(),
            name_text.lower(),
            severity_text,
            evidence_text.lower(),
        )

        existing_index = index_by_key.get(key)
        if existing_index is not None:
            existing = entries[existing_index]
            if description_text and not str(existing.get("description") or "").strip():
                existing["description"] = description_text
            if evidence_text and not str(existing.get("evidence") or "").strip():
                existing["evidence"] = evidence_text
            if source_text != "live" and str(existing.get("source") or "").strip().lower() == "live":
                existing["source"] = source_text
            if isinstance(raw, dict) and raw and (
                not isinstance(existing.get("raw"), dict) or not existing.get("raw")
            ):
                existing["raw"] = raw
            if observed_evidence_type and not str(existing.get("observed_evidence_type") or "").strip():
                existing["observed_evidence_type"] = observed_evidence_type
            if product_note and not str(existing.get("validation_note") or "").strip():
                existing["validation_note"] = product_note
            return

        entry = {
            "endpoint": endpoint_text,
            "name": name_text,
            "severity": severity_text,
            "template_id": template_text,
            "description": description_text,
            "evidence": evidence_text,
            "source": source_text,
            "raw": raw if isinstance(raw, dict) else {},
            "observed_evidence_type": observed_evidence_type,
            "validation_note": product_note,
        }
        index_by_key[key] = len(entries)
        entries.append(entry)

    for event in _extract_nuclei_result_events(nuclei_results):
        info = event.get("info") if isinstance(event.get("info"), dict) else {}
        template_id = event.get("template-id") or event.get("templateID") or event.get("id") or "Unknown"
        name = info.get("name") or event.get("name") or template_id or "Unknown"
        severity = info.get("severity") or event.get("severity") or "unknown"
        endpoint = event.get("matched-at") or event.get("matchedAt") or event.get("host") or event.get("url") or "unknown"
        description = (
            info.get("description")
            or event.get("description")
            or info.get("impact")
            or ""
        )

        evidence_parts: list[str] = []
        if event.get("type"):
            evidence_parts.append(f"type={event.get('type')}")
        if event.get("matcher-name") or event.get("matcherName"):
            matcher = event.get("matcher-name") or event.get("matcherName")
            evidence_parts.append(f"matcher={matcher}")
        extracted = event.get("extracted-results")
        if isinstance(extracted, list) and extracted:
            preview = ", ".join(str(item) for item in extracted[:3] if str(item or "").strip())
            if preview:
                if len(extracted) > 3:
                    preview += f" (+{len(extracted) - 3})"
                evidence_parts.append(f"extracted={preview}")
        elif extracted:
            evidence_parts.append(f"extracted={extracted}")
        if event.get("ip"):
            evidence_parts.append(f"ip={event.get('ip')}")
        if event.get("port"):
            evidence_parts.append(f"port={event.get('port')}")
        evidence = "; ".join(str(part) for part in evidence_parts if str(part or "").strip())

        _append_entry(
            endpoint=endpoint,
            name=name,
            severity=severity,
            template_id=template_id,
            description=description,
            evidence=evidence,
            source="parsed",
            raw=event if isinstance(event, dict) else {},
        )

    try:
        normalized_findings = nuclei_to_findings(nuclei_results)
    except Exception:
        normalized_findings = []

    for finding in normalized_findings:
        _append_entry(
            endpoint=getattr(finding, "matched_at", "unknown"),
            name=getattr(finding, "name", "Unknown"),
            severity=getattr(finding, "severity", "unknown"),
            template_id=getattr(finding, "template_id", "Unknown"),
            description="",
            evidence=getattr(finding, "evidence", "") or "",
            source="normalized",
            raw={},
        )

    live_findings = nuclei_results.get("_live_findings", []) if isinstance(nuclei_results, dict) else []
    if isinstance(live_findings, list):
        for finding in live_findings:
            if not isinstance(finding, dict):
                continue
            _append_entry(
                endpoint=finding.get("matched_at") or finding.get("host") or finding.get("url") or "unknown",
                name=finding.get("name") or finding.get("template_id") or "Unknown",
                severity=finding.get("severity") or "unknown",
                template_id=finding.get("template_id") or finding.get("id") or "Unknown",
                description=finding.get("description") or "",
                evidence=finding.get("evidence") or "",
                source="live",
                raw=finding,
            )

    entries.sort(
        key=lambda item: (
            -_nuclei_severity_rank(item.get("severity")),
            str(item.get("template_id") or "").lower(),
            str(item.get("endpoint") or "").lower(),
            str(item.get("name") or "").lower(),
        )
    )
    return entries


def _resolve_nuclei_report_state(run_context: dict[str, Any], nuclei_results: dict[str, Any] | None) -> str:
    stages = run_context.get("stages") if isinstance(run_context.get("stages"), dict) else {}
    nuclei_stage = stages.get("nuclei") if isinstance(stages.get("nuclei"), dict) else {}
    stage_status = str(nuclei_stage.get("status") or "").strip().lower()
    run_state = str(run_context.get("run_state") or "").strip().lower()
    status = str((nuclei_results or {}).get("Status") or "").strip().lower() if isinstance(nuclei_results, dict) else ""

    if run_state == "interrupted" or stage_status == "interrupted":
        return "interrupted"
    if status == "live":
        return "live"
    if run_state == "running" or stage_status == "running":
        return "running"
    if run_state == "failed" or stage_status in {"error", "failed"} or status in {"error", "partial"}:
        return "error"
    if run_state == "completed" or stage_status in {"done", "success", "completed", "skipped"} or status in {"success", "clean", "skipped"}:
        return "final"
    return "unknown"


def _derive_nuclei_empty_message(run_context: dict[str, Any], nuclei_results: dict[str, Any] | None) -> str:
    stages = run_context.get("stages") if isinstance(run_context.get("stages"), dict) else {}
    nuclei_stage = stages.get("nuclei") if isinstance(stages.get("nuclei"), dict) else {}
    stage_status = str(nuclei_stage.get("status") or "").strip().lower()
    state = _resolve_nuclei_report_state(run_context, nuclei_results)
    status = str((nuclei_results or {}).get("Status") or "").strip().lower() if isinstance(nuclei_results, dict) else ""
    error = str((nuclei_results or {}).get("Error") or nuclei_stage.get("error") or "").strip() if isinstance(nuclei_results, dict) else str(nuclei_stage.get("error") or "").strip()
    error_preview = error[:220] + ("..." if len(error) > 220 else "") if error else ""

    if state in {"live", "running"}:
        return "Nuclei hâlâ çalışıyor. Bu canlı snapshot; JSONL kayıtları geldikçe bulgular burada görünecek."
    if state == "interrupted":
        return "Nuclei çalışması finalleşmeden kesildi. Snapshot eksik olabilir."
    if state == "error":
        if error_preview:
            return f"Nuclei hata ile bitti: {error_preview}"
        return "Nuclei hata ile bitti. Detay için artifact/log kontrol et."
    if status == "clean":
        return "Nuclei bu çalıştırma için bulgu raporlamadı."
    if stage_status == "skipped":
        return "Nuclei bu çalıştırmada atlanmış veya uygun hedef yoktu."
    if not nuclei_results:
        return "Nuclei çalışmadı veya tüketilebilir bulgu üretmedi."
    return "Nuclei bulgu üretmedi."


def _compute_nuclei_summary(
    run_context: dict[str, Any],
    nuclei_results: dict[str, Any] | None,
    entries: list[dict[str, Any]],
) -> dict[str, Any]:
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }
    unique_templates: set[str] = set()
    unique_endpoints: set[str] = set()

    for entry in entries:
        severity = _normalize_nuclei_severity(entry.get("severity"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        template_id = str(entry.get("template_id") or "").strip()
        if template_id:
            unique_templates.add(template_id)

        endpoint = str(entry.get("endpoint") or "").strip()
        if endpoint and endpoint.lower() != "unknown":
            unique_endpoints.add(endpoint)

    stages = run_context.get("stages") if isinstance(run_context.get("stages"), dict) else {}
    nuclei_stage = stages.get("nuclei") if isinstance(stages.get("nuclei"), dict) else {}
    stage_status = str(nuclei_stage.get("status") or "").strip().lower()
    status_value = str((nuclei_results or {}).get("Status") or "").strip() if isinstance(nuclei_results, dict) else ""
    error_value = str((nuclei_results or {}).get("Error") or nuclei_stage.get("error") or "").strip() if isinstance(nuclei_results, dict) else str(nuclei_stage.get("error") or "").strip()

    return {
        "total_findings": len(entries),
        "severity_counts": severity_counts,
        "unique_templates_count": len(unique_templates),
        "unique_endpoints_count": len(unique_endpoints),
        "state": _resolve_nuclei_report_state(run_context, nuclei_results),
        "stage_status": stage_status,
        "status_value": status_value,
        "error": error_value,
    }


def _manual_verification_ideas_for_nuclei(
    *,
    template_id: Any,
    name: Any,
    description: Any,
    severity: Any,
) -> list[str]:
    text = " ".join(
        [
            str(template_id or ""),
            str(name or ""),
            str(description or ""),
            str(severity or ""),
        ]
    ).lower()

    if any(token in text for token in ("lfi", "local file inclusion", "path traversal", "directory traversal", "/etc/passwd")):
        return [
            "Traversal varyantlarını dene (`../`, nested traversal, double-encoded traversal).",
            "Okunabilir dosya impact’ini doğrula (system files, app config, secrets).",
            "Server-side path normalization / allowlist davranışını doğrula.",
        ]
    if any(token in text for token in ("xss", "cross site scripting", "dom-xss", "stored-xss", "reflected-xss")):
        return [
            "Reflection/storage path’i doğrula ve exact sink context’i teyit et (HTML/attr/JS/URL).",
            "Bu context için sanitization bypass ve encoding kırılmalarını test et.",
            "Zararsız proof payload ile JavaScript execution durumunu teyit et.",
        ]
    if any(token in text for token in ("csrf", "cross-site request forgery")):
        return [
            "Aksiyonun state-changing olduğunu ve victim session ile erişilebilir olduğunu doğrula.",
            "CSRF token yokluğu, reuse, predictability ve origin/referrer enforcement durumunu kontrol et.",
            "Attacker-controlled sayfadan cross-origin form/image/fetch gönderimini dene.",
        ]
    if any(
        token in text
        for token in (
            "auth",
            "authorization",
            "access control",
            "idor",
            "admin",
            "default",
            "credential",
            "config",
            "misconfig",
            "exposure",
            ".env",
            ".git",
            "phpinfo",
            "swagger",
            "openapi",
            "disclosure",
        )
    ):
        return [
            "Kullanıcı privilege seviyeleri arasında role boundary ve direct object access kontrollerini yap.",
            "Unauthenticated/internal access varsayımlarını ve default credential durumunu doğrula.",
            "Disclosure scope’u değerlendir (credentials, tokens, internal topology, config secrets).",
        ]
    if _nuclei_severity_rank(severity) >= _nuclei_severity_rank("high"):
        return [
            "Transient response ihtimalini elemek için iki bağımsız request ile yeniden üret.",
            "Least-privileged ve authenticated senaryolarla business impact’i doğrula.",
            "Request/response kanıtını ve exploitation önkoşullarını kaydet.",
        ]
    return [
        "Temiz request ile yeniden üret ve deterministik davranışı doğrula.",
        "Eşleşmeyi tetikleyen response farklarını incele (status/body/header).",
        "Exploitability, gerekli koşullar ve false-positive olasılığına karar ver.",
    ]


def _group_nuclei_findings_by_template(
    entries: list[dict[str, Any]],
    *,
    base_url: str = "",
    endpoint_context_index: dict[str, set[str]] | None = None,
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    unknown_name_tokens = {"", "-", "unknown", "n/a"}
    endpoint_context_index = endpoint_context_index or {}

    for entry in entries:
        template_id = str(entry.get("template_id") or "").strip() or "Unknown"
        key = template_id.lower()
        if key not in grouped:
            grouped[key] = {
                "template_id": template_id,
                "name": str(entry.get("name") or template_id or "Unknown").strip() or "Unknown",
                "severity": _normalize_nuclei_severity(entry.get("severity")),
                "description": str(entry.get("description") or "").strip(),
                "entries": [],
                "endpoints_set": set(),
                "observed_evidence_types": set(),
                "validation_notes": set(),
            }

        group = grouped[key]
        group["entries"].append(entry)

        endpoint = str(entry.get("endpoint") or "").strip()
        if endpoint:
            group["endpoints_set"].add(endpoint)
        observed_evidence_type = str(entry.get("observed_evidence_type") or "").strip()
        if observed_evidence_type:
            group["observed_evidence_types"].add(observed_evidence_type)
        validation_note = str(entry.get("validation_note") or "").strip()
        if validation_note:
            group["validation_notes"].add(validation_note)

        current_name = str(group.get("name") or "").strip().lower()
        candidate_name = str(entry.get("name") or "").strip()
        if current_name in unknown_name_tokens and candidate_name and candidate_name.lower() not in unknown_name_tokens:
            group["name"] = candidate_name

        current_severity = _normalize_nuclei_severity(group.get("severity"))
        candidate_severity = _normalize_nuclei_severity(entry.get("severity"))
        if _nuclei_severity_rank(candidate_severity) > _nuclei_severity_rank(current_severity):
            group["severity"] = candidate_severity

        if not str(group.get("description") or "").strip():
            candidate_desc = str(entry.get("description") or "").strip()
            if candidate_desc:
                group["description"] = candidate_desc

    groups_out: list[dict[str, Any]] = []
    for group in grouped.values():
        raw_entries = [item for item in (group.get("entries") or []) if isinstance(item, dict)]
        raw_entries.sort(
            key=lambda item: (
                str(item.get("endpoint") or "").lower(),
                -_nuclei_severity_rank(item.get("severity")),
                str(item.get("name") or "").lower(),
            )
        )

        all_endpoints = [str(ep) for ep in (group.get("endpoints_set") or set()) if str(ep or "").strip()]
        all_endpoints.sort()
        known_endpoints = [ep for ep in all_endpoints if ep.lower() != "unknown"]
        endpoints = known_endpoints if known_endpoints else all_endpoints

        description = str(group.get("description") or "").strip()
        issue_preview = description[:220] + ("..." if len(description) > 220 else "") if description else ""
        group_name = str(group.get("name") or "").strip()
        if not group_name:
            group_name = str(group.get("template_id") or "Unknown")
        observed_types = sorted(
            str(item)
            for item in (group.get("observed_evidence_types") or set())
            if str(item or "").strip()
        )
        observed_label = _nuclei_observed_evidence_label(observed_types[0]) if observed_types else ""
        validation_notes = sorted(
            str(item)
            for item in (group.get("validation_notes") or set())
            if str(item or "").strip()
        )

        severity = _normalize_nuclei_severity(group.get("severity"))
        endpoint_badges: dict[str, list[str]] = {
            endpoint: _infer_nuclei_endpoint_badges(
                endpoint,
                base_url=base_url,
                context_index=endpoint_context_index,
            )
            for endpoint in endpoints
        }
        review_priority = _compute_nuclei_review_priority(
            template_id=str(group.get("template_id") or "Unknown"),
            name=group_name,
            description=description,
            issue_preview=issue_preview,
            severity=severity,
            endpoints=endpoints,
            entries=raw_entries,
            endpoint_badges=endpoint_badges,
        )
        groups_out.append(
            {
                "template_id": str(group.get("template_id") or "Unknown"),
                "name": group_name,
                "severity": severity,
                "issue_preview": issue_preview,
                "description": description,
                "observed_evidence_type": observed_types[0] if observed_types else "",
                "observed_evidence_label": observed_label,
                "validation_notes": validation_notes,
                "endpoint_count": len(endpoints),
                "endpoints": endpoints,
                "endpoint_badges": endpoint_badges,
                "entries": raw_entries,
                "review_priority_score": _safe_int(review_priority.get("score"), 0),
                "review_priority_label": str(review_priority.get("label") or "Low inceleme"),
                "review_priority_factors": review_priority.get("reasons", []),
                "surface_badges": review_priority.get("surface_badges", []),
                "highest_surface": str(review_priority.get("highest_surface") or "general"),
                "manual_verification": _manual_verification_ideas_for_nuclei(
                    template_id=group.get("template_id"),
                    name=group_name,
                    description=description,
                    severity=severity,
                ),
                "trust_levels": [
                    str(item.get("trust_level") or "").strip().lower()
                    for item in raw_entries
                    if isinstance(item, dict) and str(item.get("trust_level") or "").strip()
                ],
            }
        )

    groups_out.sort(
        key=lambda item: (
            -_nuclei_severity_rank(item.get("severity")),
            -_safe_int(item.get("review_priority_score"), 0),
            -_safe_int(item.get("endpoint_count"), 0),
            str(item.get("name") or item.get("template_id") or "").lower(),
            str(item.get("template_id") or "").lower(),
        )
    )
    return groups_out


def _group_template_findings_by_severity(
    template_groups: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped = {
        "critical": [],
        "high": [],
        "medium": [],
        "low_info_unknown": [],
    }
    for group in template_groups:
        bucket = _nuclei_severity_bucket(group.get("severity"))
        grouped.setdefault(bucket, []).append(group)
    for bucket_groups in grouped.values():
        bucket_groups.sort(
            key=lambda item: (
                -_safe_int(item.get("review_priority_score"), 0),
                -_safe_int(item.get("endpoint_count"), 0),
                str(item.get("name") or item.get("template_id") or "").lower(),
                str(item.get("template_id") or "").lower(),
            )
        )
    return grouped


def _render_nuclei_endpoint_value(
    endpoint: Any,
    base_url: str,
    *,
    badges: list[str] | None = None,
) -> str:
    raw = str(endpoint or "").strip()
    if not raw:
        return "-"

    value_html = ""
    if raw.startswith(("http://", "https://", "//", "/", "?")):
        safe = _sanitize_report_url(raw, base_url)
        if safe:
            value_html = _render_report_link(safe, base_url)
    if not value_html:
        value_html = _html_escape(raw)

    badge_html = _render_nuclei_endpoint_badges_html(badges or [])
    if badge_html:
        return f'<span class="nuclei-endpoint-line">{value_html}{badge_html}</span>'
    return value_html


def _render_nuclei_endpoints_preview(
    endpoints: list[str],
    *,
    base_url: str,
    endpoint_badges: dict[str, list[str]] | None = None,
    preview_count: int = 3,
) -> str:
    cleaned: list[str] = []
    seen: set[str] = set()
    endpoint_badges = endpoint_badges if isinstance(endpoint_badges, dict) else {}
    for endpoint in endpoints or []:
        text = str(endpoint or "").strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(text)

    if not cleaned:
        return '<p class="note">No affected endpoint detail.</p>'

    preview = cleaned[:preview_count] if preview_count > 0 else cleaned
    remaining = cleaned[preview_count:] if preview_count > 0 else []

    preview_html = "".join(
        f"<li>{_render_nuclei_endpoint_value(endpoint, base_url, badges=endpoint_badges.get(endpoint, []))}</li>"
        for endpoint in preview
    )
    html = f'<ul class="compact-list">{preview_html}</ul>'

    if remaining:
        remaining_html = "".join(
            f"<li>{_render_nuclei_endpoint_value(endpoint, base_url, badges=endpoint_badges.get(endpoint, []))}</li>"
            for endpoint in remaining
        )
        html += (
            f'<details class="show-more">'
            f"<summary>{len(remaining)} ek endpoint göster</summary>"
            f'<ul class="compact-list">{remaining_html}</ul>'
            f"</details>"
        )

    return html


def _render_nuclei_template_raw_entries(entries: list[dict[str, Any]], base_url: str) -> str:
    if _safe_len(entries) <= 1:
        return ""

    rows: list[str] = []
    for entry in entries:
        endpoint_cell = _render_nuclei_endpoint_value(entry.get("endpoint"), base_url)
        severity_cell = _nuclei_severity_badge_html(entry.get("severity"))
        trust_cell = _nuclei_trust_badge_html(entry.get("trust_level"))
        issue_cell = _html_escape(entry.get("name") or "Unknown")
        evidence_raw = str(entry.get("evidence") or "").strip()
        evidence_cell = _html_escape(evidence_raw) if evidence_raw else '<span class="note">-</span>'
        trust_reason = str(entry.get("trust_reason") or "").strip()
        confidence_score = int(entry.get("finding_confidence_score", 0) or 0)
        dependency_note = _nuclei_discovery_dependency_note(entry)
        trust_note_parts = []
        trust_note_parts.append(f"confidence={confidence_score}/100")
        if trust_reason:
            trust_note_parts.append(_truncate_text(trust_reason, 120))
        if dependency_note:
            trust_note_parts.append(dependency_note)
        trust_meta = (
            f"{trust_cell}<br><span class=\"note\">{_html_escape(' | '.join(trust_note_parts))}</span>"
            if trust_note_parts
            else trust_cell
        )
        rows.append(
            f"<tr><td>{endpoint_cell}</td><td>{severity_cell}</td><td>{trust_meta}</td><td>{issue_cell}</td><td>{evidence_cell}</td></tr>"
        )

    table_html = _render_progressive_table(
        header_html="<th>Endpoint</th><th>Severity</th><th>Güven</th><th>Bulgu</th><th>Kanıt</th>",
        rows=rows,
        empty_row_html='<tr><td colspan="5">Template eşleşmesi yok.</td></tr>',
        preview_rows=5,
        summary_label="Daha fazla template eşleşmesi göster",
    )

    return (
        f'<details class="show-more nuclei-raw-inline">'
        f"<summary>Template eşleşmeleri ({len(rows)})</summary>"
        f"{table_html}"
        f"</details>"
    )


def _render_nuclei_template_card(
    template_group: dict[str, Any],
    *,
    base_url: str,
    endpoint_preview_count: int = 3,
) -> str:
    template_id = str(template_group.get("template_id") or "Unknown")
    name = str(template_group.get("name") or template_id or "Unknown")
    observed_label = str(template_group.get("observed_evidence_label") or "").strip()
    headline = observed_label or name
    validation_notes = [
        str(item).strip()
        for item in (template_group.get("validation_notes") or [])
        if str(item or "").strip()
    ]
    severity = _normalize_nuclei_severity(template_group.get("severity"))
    endpoint_count = _safe_int(template_group.get("endpoint_count"), 0)
    entries = template_group.get("entries", []) if isinstance(template_group.get("entries"), list) else []
    match_count = len(entries)
    issue_preview = str(template_group.get("issue_preview") or "").strip()
    if not issue_preview:
        issue_preview = "Template çıktısı açıklama içermiyor; eşleşme davranışını manuel doğrula."

    endpoints = template_group.get("endpoints", []) if isinstance(template_group.get("endpoints"), list) else []
    endpoint_badges = template_group.get("endpoint_badges", {}) if isinstance(template_group.get("endpoint_badges"), dict) else {}
    endpoints_html = _render_nuclei_endpoints_preview(
        endpoints,
        base_url=base_url,
        endpoint_badges=endpoint_badges,
        preview_count=endpoint_preview_count,
    )
    raw_entries_html = _render_nuclei_template_raw_entries(entries, base_url)
    manual_ideas = template_group.get("manual_verification", []) if isinstance(template_group.get("manual_verification"), list) else []
    manual_html = (
        "<ul class=\"compact-list nuclei-checklist\">"
        + "".join(f"<li>{_html_escape(idea)}</li>" for idea in manual_ideas)
        + "</ul>"
    ) if manual_ideas else '<p class="note">Öneri yok.</p>'
    review_score = _safe_int(template_group.get("review_priority_score"), 0)
    review_label = str(template_group.get("review_priority_label") or _nuclei_review_priority_label(review_score))
    review_factors = [
        str(item).strip()
        for item in (template_group.get("review_priority_factors") or [])
        if str(item or "").strip()
    ]
    surface_badges = [
        str(item).strip()
        for item in (template_group.get("surface_badges") or [])
        if str(item or "").strip()
    ]
    surface_text = "/".join(surface_badges[:3]) if surface_badges else "general"
    highest_surface = str(template_group.get("highest_surface") or "general")
    trust_levels = [str(item or "").strip().lower() for item in (template_group.get("trust_levels") or []) if str(item or "").strip()]
    trust_scores = [
        int(item.get("finding_confidence_score", 0) or 0)
        for item in entries
        if isinstance(item, dict)
    ]
    avg_trust_score = int(round(sum(trust_scores) / max(1, len(trust_scores)))) if trust_scores else 0
    trust_low_count = len([item for item in trust_levels if item == "low"])
    trust_medium_count = len([item for item in trust_levels if item == "medium"])
    trust_high_count = len([item for item in trust_levels if item == "high"])
    if trust_low_count > 0:
        group_trust = "low"
        group_trust_note = "Bazı eşleşmeler düşük güvenli çünkü bağlı discovery kapsamı eksik."
    elif trust_medium_count > 0:
        group_trust = "medium"
        group_trust_note = "Kısmi discovery/zenginleştirme zayıflaması nedeniyle eşleşmeler orta güvenli."
    else:
        group_trust = "high"
        group_trust_note = "Mevcut discovery kapsamı altında eşleşmeler yüksek güvenli."
    meta_summary = (
        f"İnceleme önceliği: {review_score}/100 ({review_label}) • "
        f"Yüzey: {surface_text} • "
        f"En yüksek hassasiyet: {highest_surface} • "
        f"{endpoint_count} unique endpoint • "
        f"{match_count} ham eşleşme • "
        f"Güven: {group_trust.upper()} ({avg_trust_score}/100)"
    )
    why_prioritized = (
        f'<p class="note nuclei-priority-why"><strong>Neden önceliklendirildi?</strong> {_html_escape(" • ".join(review_factors[:4]))}</p>'
        if review_factors
        else ""
    )
    observed_html = (
        f'<p class="note nuclei-observed-evidence"><strong>Observed evidence:</strong> {_html_escape(observed_label.replace("Observed evidence: ", ""))}</p>'
        if observed_label
        else ""
    )
    template_note_html = (
        f'<p class="note nuclei-template-note"><strong>Template adı:</strong> {_html_escape(name)} '
        f'(<code>{_html_escape(template_id)}</code>)</p>'
        if observed_label
        else ""
    )
    validation_note_html = (
        '<p class="note nuclei-validation-note"><strong>Doğrulama notu:</strong> '
        + _html_escape(validation_notes[0])
        + "</p>"
        if validation_notes
        else ""
    )

    return (
        f'<article class="panel nuclei-card nuclei-severity-{_html_escape(severity)}">'
        f'<div class="panel-head nuclei-card-head">'
        f"<div>"
        f"<h3>{_html_escape(headline)}</h3>"
        f'<p class="panel-summary"><code>{_html_escape(template_id)}</code> · {endpoint_count} endpoint · {match_count} template eşleşmesi</p>'
        f'<p class="nuclei-meta-row">{_html_escape(meta_summary)}</p>'
        f"</div>"
        f'<div class="panel-badges">{_nuclei_severity_badge_html(severity)}{_nuclei_trust_badge_html(group_trust)}{_nuclei_review_priority_pill_html(review_score, review_label)}</div>'
        f"</div>"
        f'<p class="note nuclei-issue-preview">{_html_escape(issue_preview)}</p>'
        f'<h4>Etkilenen Endpoint’ler</h4>{endpoints_html}'
        f'<details class="show-more report-evidence-disclosure report-depth-evidence-detail">'
        f'<summary>Kanıt gerekçesi ve manuel doğrulama</summary>'
        f"{observed_html}"
        f"{template_note_html}"
        f'<p class="note nuclei-trust-note"><strong>Güven gerekçesi:</strong> {_html_escape(group_trust_note)} '
        f'({_html_escape(str(trust_high_count))} high / {_html_escape(str(trust_medium_count))} medium / {_html_escape(str(trust_low_count))} low)</p>'
        f"{validation_note_html}"
        f"{why_prioritized}"
        f'<div class="nuclei-card-grid">'
        f"<div><h4>Manuel Doğrulama Fikirleri</h4>{manual_html}</div>"
        f"</div>"
        f"{raw_entries_html}"
        f"</details>"
        f"</article>"
    )


def _render_nuclei_severity_sections(
    grouped_templates: dict[str, list[dict[str, Any]]],
    *,
    base_url: str,
    endpoint_preview_count: int = 3,
    preview_templates_per_group: int = 4,
    empty_message: str = "",
) -> str:
    sections: list[str] = []
    severity_layout = [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low_info_unknown", "Low / Info / Unknown"),
    ]

    for bucket_key, title in severity_layout:
        groups = grouped_templates.get(bucket_key, [])
        if not groups:
            continue

        cards = [
            _render_nuclei_template_card(
                group,
                base_url=base_url,
                endpoint_preview_count=endpoint_preview_count,
            )
            for group in groups
        ]
        visible_cards = cards[:preview_templates_per_group] if preview_templates_per_group > 0 else cards
        hidden_cards = cards[preview_templates_per_group:] if preview_templates_per_group > 0 else []

        hidden_html = ""
        if hidden_cards:
            hidden_html = (
                f'<details class="show-more nuclei-more-templates">'
                f"<summary>{len(hidden_cards)} ek template grubu göster</summary>"
                f"{''.join(hidden_cards)}"
                f"</details>"
            )

        sections.append(
            f'<section class="nuclei-severity-group nuclei-bucket-{_html_escape(bucket_key)}">'
            f'<h3>{_html_escape(title)} <span class="stat-badge"><span class="val">{len(groups)}</span> template</span></h3>'
            f"{''.join(visible_cards)}"
            f"{hidden_html}"
            f"</section>"
        )

    if not sections:
        return f'<p class="note">{_html_escape(empty_message or "Gruplanmış Nuclei bulgusu yok.")}</p>'
    return "".join(sections)


def _render_nuclei_summary_block(summary: dict[str, Any]) -> str:
    severity_counts = summary.get("severity_counts") if isinstance(summary.get("severity_counts"), dict) else {}
    state = str(summary.get("state") or "unknown").strip().lower()
    state_label = {
        "live": "Canlı",
        "running": "Çalışıyor",
        "final": "Final",
        "error": "Hata",
        "interrupted": "Kesildi",
        "unknown": "Bilinmiyor",
    }.get(state, "Bilinmiyor")
    if state in {"live", "running"}:
        state_tone = "warn"
    elif state in {"error", "interrupted"}:
        state_tone = "bad"
    else:
        state_tone = "ok"

    lifecycle_note = ""
    if state in {"live", "running"}:
        lifecycle_note = "<p class='live-note'><strong>Canlı anlık görünüm:</strong> Çalıştırma final duruma ulaşana kadar Nuclei çıktısı değişebilir.</p>"
    elif state == "interrupted":
        lifecycle_note = "<p class='risk-note'><strong>Kesildi:</strong> auto-refresh durdu; bulgular kısmi olabilir.</p>"
    elif state == "error":
        err = str(summary.get("error") or "").strip()
        if err:
            err_preview = err[:220] + ("..." if len(err) > 220 else "")
            lifecycle_note = f"<p class='risk-note'><strong>Hata:</strong> {_html_escape(err_preview)}</p>"
        else:
            lifecycle_note = "<p class='risk-note'><strong>Hata:</strong> run Nuclei hatasıyla bitti.</p>"
    elif state == "final":
        lifecycle_note = "<p class='note'><strong>Final anlık görünüm:</strong> Bu run için ek otomatik güncelleme beklenmez.</p>"

    severity_badges = []
    for severity_key, label in (
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("info", "Info"),
        ("unknown", "Unknown"),
    ):
        count = _safe_int(severity_counts.get(severity_key), 0)
        severity_badges.append(
            f'<span class="stat-badge nuclei-count nuclei-count-{_html_escape(severity_key)}">'
            f"{_html_escape(label)}: <span class=\"val\">{count}</span></span>"
        )

    stage_status = str(summary.get("stage_status") or "").strip()
    status_value = str(summary.get("status_value") or "").strip()
    state_meta_parts = []
    if stage_status:
        state_meta_parts.append(f"stage={stage_status}")
    if status_value:
        state_meta_parts.append(f"status={status_value}")
    state_meta_text = " | ".join(state_meta_parts) if state_meta_parts else "state metadata yok"

    return (
        f'<div class="nuclei-summary-block">'
        f'<div class="kpi-grid nuclei-kpi-grid">'
        f'<div class="kpi"><div class="label">Toplam bulgu</div><div class="value">{_safe_int(summary.get("total_findings"), 0)}</div></div>'
        f'<div class="kpi"><div class="label">Unique template</div><div class="value">{_safe_int(summary.get("unique_templates_count"), 0)}</div></div>'
        f'<div class="kpi"><div class="label">Unique etkilenen endpoint</div><div class="value">{_safe_int(summary.get("unique_endpoints_count"), 0)}</div></div>'
        f'<div class="kpi"><div class="label">Nuclei durumu</div><div class="value"><span class="pill {state_tone}">{_html_escape(state_label)}</span></div><div class="note">{_html_escape(state_meta_text)}</div></div>'
        f"</div>"
        f'<div class="summary-strip nuclei-severity-strip">{"".join(severity_badges)}</div>'
        f"{lifecycle_note}"
        f"</div>"
    )


def _render_nuclei_raw_table(
    entries: list[dict[str, Any]],
    *,
    base_url: str,
    empty_message: str,
    preview_rows: int = 12,
) -> str:
    rows: list[str] = []
    for entry in entries:
        endpoint_cell = _render_nuclei_endpoint_value(entry.get("endpoint"), base_url)
        issue_cell = _html_escape(entry.get("name") or "Unknown")
        severity_cell = _nuclei_severity_badge_html(entry.get("severity"))
        trust_cell = _nuclei_trust_badge_html(entry.get("trust_level"))
        trust_reason = str(entry.get("trust_reason") or "").strip()
        confidence_score = int(entry.get("finding_confidence_score", 0) or 0)
        dependency_note = _nuclei_discovery_dependency_note(entry)
        trust_note_parts = []
        trust_note_parts.append(f"confidence={confidence_score}/100")
        if trust_reason:
            trust_note_parts.append(_truncate_text(trust_reason, 120))
        if dependency_note:
            trust_note_parts.append(dependency_note)
        trust_meta = (
            f"{trust_cell}<br><span class=\"note\">{_html_escape(' | '.join(trust_note_parts))}</span>"
            if trust_note_parts
            else trust_cell
        )
        template_cell = _html_escape(entry.get("template_id") or "Unknown")
        rows.append(
            f"<tr><td>{endpoint_cell}</td><td>{issue_cell}</td><td>{severity_cell}</td><td>{trust_meta}</td><td><code>{template_cell}</code></td></tr>"
        )

    return _render_progressive_table(
        header_html="<th>Endpoint</th><th>Bulgu</th><th>Severity</th><th>Güven</th><th>Template</th>",
        rows=rows,
        empty_row_html=f'<tr><td colspan="5">{_html_escape(empty_message)}</td></tr>',
        preview_rows=preview_rows,
        summary_label="Tüm ham eşleşmeleri göster",
    )


def _build_run_quality_model(
    *,
    run_state_value: str,
    run_stability_label: str,
    coverage_status_label: str,
    coverage_note: str,
    discovery_reliability: str,
    discovery_scope_label: str,
    tool_coverage_label: str,
    working_core_tools: list[str],
    closed_surface_discovery_tools: list[str],
    decision_confidence: str,
    decision_confidence_display: str,
    has_any_tier_failure: bool,
    failed_stages: list[str],
    skipped_tools: list[str],
    stages_ctx: dict[str, Any],
    nmap_output: str,
    katana_representative_urls: list[str],
    gobuster_results: dict[str, Any],
    ffuf_findings_by_base: dict[str, Any],
    nuclei_findings_count: int,
    waf_detected_count: int,
    waf_signals: dict[str, Any],
    whatweb_detected_count: int,
    whatweb_signals: dict[str, Any],
    screenshot_count: int,
    checks_results: dict[str, Any],
) -> dict[str, Any]:
    skipped_set = {str(name or "").strip().lower() for name in (skipped_tools or []) if str(name or "").strip()}
    confidence_labels_tr = {
        "high": "yüksek",
        "medium": "orta",
        "low": "düşük",
    }
    display_value = str(decision_confidence_display or "").strip()
    decision_confidence_tr = (
        confidence_labels_tr.get(display_value.lower(), display_value)
        if display_value
        else confidence_labels_tr.get(
            str(decision_confidence or "").strip().lower(),
            str(decision_confidence or "").strip().lower() or "-",
        )
    )

    def _stage(name: str) -> dict[str, Any]:
        value = stages_ctx.get(name) if isinstance(stages_ctx, dict) else {}
        return value if isinstance(value, dict) else {}

    def _status(name: str) -> str:
        if name.lower() in skipped_set:
            return "atlanmış"
        raw = str(_stage(name).get("status") or "").strip().lower()
        if raw in {"done", "success", "completed"}:
            return "tamamlandı"
        if raw in {"error", "failed"}:
            return "hata"
        if raw == "interrupted":
            return "kesildi"
        if raw == "running":
            return "çalışıyor"
        if raw == "empty":
            return "boş"
        if raw == "skipped":
            return "atlanmış"
        return raw or "bilinmiyor"

    def _artifact_hint(name: str) -> str:
        artifacts = _stage(name).get("artifacts")
        if isinstance(artifacts, dict) and artifacts:
            return ", ".join(str(key) for key in list(artifacts.keys())[:4])
        return ""

    def _impact(status: str, evidence_count: int, positive_text: str) -> str:
        if status in {"hata", "kesildi"}:
            return "Kapsama sınırlı; bu aracın yokluğu temiz sonuç anlamına gelmez."
        if "skip" in status or "atlan" in status:
            return "Bu araç bu çalıştırmada karar sinyaline katkı vermedi."
        if evidence_count > 0:
            return positive_text
        if status == "tamamlandı":
            return "Çalıştı ancak bu snapshot’ta karar artıran belirgin çıktı üretmedi."
        return "Durum belirsiz; operatör bu eksikliği triyaj sırasında not etmeli."

    gobuster_hits = sum(len(value) for value in (gobuster_results or {}).values() if isinstance(value, list))
    ffuf_hits = sum(len(value) for value in (ffuf_findings_by_base or {}).values() if isinstance(value, list))
    historical = checks_results.get("historical_urls") if isinstance(checks_results.get("historical_urls"), dict) else {}
    historical_live = len(historical.get("interesting_live_urls") or []) if isinstance(historical.get("interesting_live_urls"), list) else 0
    historical_total = int(historical.get("normalized_count") or historical.get("total_urls") or historical.get("collected_count") or 0)

    tool_specs = [
        ("nmap", "Nmap", 1 if str(nmap_output or "").strip() else 0, "Servis/port bağlamı risk yorumuna destek verir.", "Nmap text output"),
        ("subfinder", "subfinder", 0, "Domain modunda subdomain kapsamının başlangıç sinyalidir.", _artifact_hint("subfinder")),
        ("dnsx", "dnsx", 0, "DNS çözümleme kapsamının doğrulanmasına destek verir.", _artifact_hint("dnsx")),
        ("httpx", "httpx", 0, "Canlı HTTP yüzeyini belirleyerek downstream web araçlarını besler.", _artifact_hint("httpx")),
        ("katana", "Katana", len(katana_representative_urls), "Endpoint keşfi ve attack surface yorumunu doğrudan besler.", f"{len(katana_representative_urls)} temsilci endpoint"),
        ("gobuster", "Gobuster", gobuster_hits, "Path enumeration kanıtı discovery kapsamını güçlendirir.", f"{gobuster_hits} hit"),
        ("ffuf", "FFUF", ffuf_hits, "Benzersiz path/fuzzing sinyali önceliklendirmeye destek verir.", f"{ffuf_hits} tekilleştirilmiş hit"),
        ("nuclei", "Nuclei", nuclei_findings_count, "Bulgular strongest path ve öneri önceliğini etkiler.", f"{nuclei_findings_count} bulgu"),
        ("wafw00f", "WAFW00F", len(waf_signals), "WAF/CDN sinyali doğrulama hızını ve confidence yorumunu etkiler.", f"{waf_detected_count} WAF/CDN tespiti"),
        ("whatweb", "WhatWeb", len(whatweb_signals), "Teknoloji fingerprint bağlamı CVE ve validation yorumuna destek verir.", f"{whatweb_detected_count} fingerprint"),
        ("screenshots", "gowitness", screenshot_count, "Görsel kanıt erişilebilir yüzeyin UI bağlamını doğrular.", f"{screenshot_count} screenshot"),
        ("historical_urls", "historical_urls", historical_live or historical_total, "Archive kaynaklı URL’ler korelasyon ve eski endpoint triyajını destekler.", f"{historical_live} canlı ilginç URL / {historical_total} toplam"),
    ]

    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    for key, label, evidence_count, impact_text, evidence_text in tool_specs:
        status = _status(key)
        if key == "screenshots" and status == "bilinmiyor":
            status = "tamamlandı" if screenshot_count > 0 else "boş"
        if key == "historical_urls":
            historical_status = str(historical.get("status") or "").strip().lower()
            if historical_status and key not in skipped_set:
                status = "tamamlandı" if historical_status in {"done", "success", "completed"} else historical_status
        detail = _artifact_hint(key)
        if key == "historical_urls":
            artifacts = historical.get("artifacts") if isinstance(historical.get("artifacts"), dict) else {}
            detail = ", ".join(str(v) for v in list(artifacts.values())[:3] if str(v or "").strip())
        rows.append(
            {
                "tool": label,
                "status": status,
                "evidence": evidence_text or ("kanıt yok" if evidence_count == 0 else f"{evidence_count} öğe"),
                "impact": _impact(status, evidence_count, impact_text),
                "detail": detail,
                "evidence_count": evidence_count,
            }
        )
        if status in {"hata", "kesildi"} or "skip" in status or "atlan" in status:
            warnings.append(f"{label}: {status}; kapsama sınırlı.")
        elif evidence_count == 0 and status in {"tamamlandı", "boş"} and key in {"subfinder", "dnsx", "httpx", "katana", "nuclei"}:
            warnings.append(f"{label}: belirgin çıktı yok; temiz sonuç olarak yorumlama.")

    state_lower = str(run_state_value or "").strip().lower()
    if state_lower == "interrupted":
        run_state_label = "kesilmiş anlık görünüm"
    elif state_lower == "running":
        run_state_label = "canlı anlık görünüm"
    elif state_lower == "completed":
        run_state_label = "tamamlandı"
    elif state_lower == "failed":
        run_state_label = "başarısız"
    else:
        run_state_label = "partial/bilinmiyor"
    if state_lower == "completed" and not has_any_tier_failure:
        triage_safety = "İlk triyaj için güvenli; yine de bulgu yokluğu kesin temizlik kanıtı değildir."
        quality_tone = "ok"
    elif state_lower == "interrupted" or has_any_tier_failure or discovery_reliability in {"LOW", "CRITICAL"}:
        triage_safety = "İlk triyaj için kullanılabilir, ancak final temiz/temiz değil kararı için eksik kapsama giderilmeli."
        quality_tone = "bad" if discovery_reliability in {"LOW", "CRITICAL"} else "warn"
    else:
        triage_safety = "İlk triyaj için kullanılabilir; eksik veya zayıf araç sinyallerini yorumda ayrı tut."
        quality_tone = "warn"

    missing_parts: list[str] = []
    if failed_stages:
        missing_parts.append(f"Başarısız stage: {', '.join(sorted(failed_stages)[:5])}.")
    if skipped_tools:
        missing_parts.append(f"Seçilen kapsam dışında (hata değildir): {', '.join(str(x) for x in skipped_tools[:6])}.")
    if discovery_reliability != "HIGH":
        missing_parts.append(f"Discovery güvenilirliği: {discovery_reliability}.")
    if not missing_parts:
        missing_parts.append("Belirgin kritik kapsama eksiği raporlanmadı.")

    return {
        "run_state": run_state_label,
        "run_stability": run_stability_label,
        "report_integrity": "tamamlandı" if state_lower == "completed" else run_state_label,
        "tool_coverage": tool_coverage_label,
        "discovery_scope": discovery_scope_label,
        "working_core_tools": ", ".join(working_core_tools) if working_core_tools else "yok",
        "closed_surface_discovery_tools": ", ".join(closed_surface_discovery_tools) if closed_surface_discovery_tools else "yok",
        "triage_safety": triage_safety,
        "quality_tone": quality_tone,
        "missing_or_weak": " ".join(missing_parts),
        "interpretation": f"Karar güveni: {decision_confidence_tr}. Kapsama: {coverage_status_label}. {coverage_note}",
        "warnings": warnings[:4],
        "rows": rows,
    }


def _render_run_quality_section(model: dict[str, Any]) -> str:
    rows = model.get("rows") if isinstance(model.get("rows"), list) else []
    warnings = model.get("warnings") if isinstance(model.get("warnings"), list) else []
    warning_html = (
        "<ul class='compact-list'>" + "".join(f"<li>{_html_escape(str(item))}</li>" for item in warnings[:4]) + "</ul>"
        if warnings
        else "<p class='note'>Öne çıkan araç kapsama uyarısı yok.</p>"
    )
    matrix_rows: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        detail = str(row.get("detail") or "").strip()
        detail_html = (
            f'<br><span class="note report-depth-body-deep-only" data-depth-body="deep">Kaynak/artifact: {_html_escape(_truncate_text(detail, 180))}</span>'
            if detail
            else ""
        )
        matrix_rows.append(
            "<tr>"
            f"<td><strong>{_html_escape(row.get('tool') or '-')}</strong></td>"
            f"<td>{_html_escape(row.get('status') or '-')}</td>"
            f"<td class=\"wrap-cell\">{_html_escape(row.get('evidence') or '-')}{detail_html}</td>"
            f"<td class=\"wrap-cell\">{_html_escape(row.get('impact') or '-')}</td>"
            "</tr>"
        )

    return f"""
    <div class="section compact report-depth-body-all run-quality-section" data-depth-body="summary balanced deep" id="run-quality">
      <h2>Rapor Güvenilirliği ve Araç Kapsamı</h2>
      <div class="run-quality-grid">
        <div class="kpi">
          <div class="label">Rapor bütünlüğü</div>
          <div class="value"><span class="pill {_html_escape(str(model.get('quality_tone') or 'warn'))}">{_html_escape(model.get('report_integrity') or '-')}</span></div>
          <div class="note">{_html_escape(model.get('run_stability') or '-')}</div>
        </div>
        <div class="kpi">
          <div class="label">Araç kapsamı</div>
          <div class="value" style="font-size:15px; line-height:1.35;">{_html_escape(model.get('tool_coverage') or '-')}</div>
          <div class="note">Discovery kapsamı: {_html_escape(model.get('discovery_scope') or '-')}</div>
        </div>
        <div class="kpi">
          <div class="label">İlk triyaj yorumu</div>
          <div class="value" style="font-size:15px; line-height:1.35;">{_html_escape(model.get('triage_safety') or '-')}</div>
        </div>
      </div>
      <p class="operator-view-note"><strong>Eksik/zayıf alan:</strong> {_html_escape(model.get('missing_or_weak') or '-')}</p>
      <p class="operator-view-note"><strong>Çalışan çekirdek araçlar:</strong> {_html_escape(model.get('working_core_tools') or '-')} | <strong>Kapalı yüzey keşfi araçları:</strong> {_html_escape(model.get('closed_surface_discovery_tools') or '-')}</p>
      <p class="note report-depth-balanced-preview"><strong>Operatör yorumu:</strong> {_html_escape(model.get('interpretation') or '-')}</p>
      <div class="run-quality-warnings">
        <h3>Öne çıkan araç uyarıları</h3>
        {warning_html}
      </div>
      <div class="report-depth-body-balanced-deep" data-depth-body="balanced deep">
        <h3>Araç Kapsam Matrisi</h3>
        <table>
          <tr><th>Araç</th><th>Durum</th><th>Üretilen Kanıt / Çıktı</th><th>Karara Etkisi</th></tr>
          {''.join(matrix_rows)}
        </table>
      </div>
    </div>
    """


def _build_operator_plan_actions(
    *,
    first_test_text: str,
    first_action_why: str,
    top_chain_label: str,
    top_chain_reason: str,
    top_chain_confidence: int,
    correlation_insights: list[Any],
    nuclei_report_entries: list[dict[str, Any]],
    admin_like: list[str],
    auth_like: list[str],
    waf_detected_count: int,
    screenshot_count: int,
    screenshot_entries: list[dict[str, Any]],
    run_state_value: str,
    coverage_note: str,
    report_base_url: str,
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    seen_titles: set[str] = set()

    def _clean(value: Any, fallback: str = "-") -> str:
        text = _operator_text_to_english(str(value or "").strip())
        text = text.replace("Kontrollü exploit path çalıştır", "Exploitability önkoşullarını güvenli biçimde doğrula")
        text = text.replace("exploit path çalıştır", "exploitability önkoşullarını güvenli biçimde doğrula")
        return text if text else fallback

    def _first_url(items: list[str]) -> str:
        for item in items:
            text = str(item or "").strip()
            if text:
                return text
        return ""

    def _evidence_link(value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return "-"
        if text.startswith(("http://", "https://")):
            return _render_report_link(text, report_base_url)
        return _html_escape(_truncate_text(text, 160))

    def _add(
        priority: int,
        title: str,
        why: str,
        validation: str,
        evidence: str = "",
        source: str = "",
        source_detail: str = "",
    ) -> None:
        title_clean = _clean(title)
        key = title_clean.lower()
        if key in seen_titles:
            return
        seen_titles.add(key)
        actions.append(
            {
                "priority": max(0, min(100, int(priority or 0))),
                "title": title_clean,
                "why": _clean(why),
                "validation": _clean(validation),
                "evidence": evidence.strip() if isinstance(evidence, str) else str(evidence or "").strip(),
                "source": _clean(source, ""),
                "source_detail": _clean(source_detail, ""),
            }
        )

    if str(run_state_value or "").strip().lower() in {"interrupted", "running"}:
        _add(
            98,
            "Çalıştırma kapsamasını karar vermeden önce teyit et",
            "Bu rapor tamamlanmamış veya canlı bir anlık görünüm olabilir; temiz scan varsayımı risklidir.",
            "Önce eksik/kesilmiş aşamaları ve kapsama notunu kontrol et; kritik karar öncesi aynı scope ile final çalıştırma üret.",
            coverage_note,
            "run_state / pipeline coverage",
            coverage_note,
        )

    if first_test_text:
        first_action_evidence = top_chain_label if top_chain_label and top_chain_label != "-" else ""
        if not first_action_evidence and "yüksek öncelikli yüzey oluşmadı" in f"{first_test_text} {first_action_why}":
            first_action_evidence = "Araç kapsamı sınırlı / bulgu yok"
        if "yüksek öncelikli yüzey oluşmadı" in f"{first_test_text} {first_action_why}":
            _add(
                96,
                "Doğrulanmış aksiyon oluşmadı",
                first_action_why or "Bu run’da aksiyon üretilecek doğrulanmış yüzey oluşmadı.",
                (
                    "Bu sınırlı run’da aksiyon üretilecek doğrulanmış yüzey oluşmadı. "
                    "Kapsam izin veriyorsa kapalı keşif araçlarıyla yeniden çalıştır."
                ),
                first_action_evidence,
                "overview first action",
                f"İlk aksiyon gerekçesi: {first_action_why}" if first_action_why else "",
            )
        else:
            _add(
                96,
                "İlk önerilen doğrulamayı uygula",
                first_action_why or "Önceliklendirme motoru bu aksiyonu mevcut kanıt ve kapsama durumuna göre ilk sıraya koydu.",
                first_test_text,
                first_action_evidence,
                "overview first action",
                f"İlk aksiyon gerekçesi: {first_action_why}" if first_action_why else "",
            )

    if top_chain_label and top_chain_label != "-":
        _add(
            94,
            "Strongest path bağlamını manuel olarak teyit et",
            top_chain_reason or "Saldırı grafiği en yüksek güvenli path’i operator incelemesi için öne çıkardı.",
            "Path üzerindeki her node’un gerçekten erişilebilir ve scope içinde olduğunu kanıtla; request/response ve auth gereksinimini karşılaştır.",
            top_chain_label,
            "strongest path / attack graph",
            f"Güven: {top_chain_confidence}/100. Path: {top_chain_label}",
        )

    high_entries = [
        entry
        for entry in nuclei_report_entries
        if isinstance(entry, dict)
        and _normalize_nuclei_severity(entry.get("severity")) in {"critical", "high"}
    ]
    high_entries.sort(
        key=lambda entry: (
            _nuclei_severity_rank(entry.get("severity")),
            int(entry.get("finding_confidence_score", 0) or 0),
        ),
        reverse=True,
    )
    if high_entries:
        top = high_entries[0]
        finding_name = _clean(top.get("name") or top.get("template_id") or "Nuclei bulgusu")
        endpoint = str(top.get("endpoint") or "").strip()
        template_id = str(top.get("template_id") or "").strip()
        _add(
            92,
            "High/Critical Nuclei bulgusunu doğrula",
            f"{finding_name} high/critical severity ile rapora girdi; otomatik template sonucu olduğu için request/response ile teyit edilmelidir.",
            "Aynı endpoint üzerinde güvenli, tekrarlanabilir request ile bulgunun deterministik olup olmadığını kontrol et; false positive koşullarını not et.",
            endpoint or template_id,
            "Nuclei",
            f"Template: {template_id or '-'} | Endpoint: {endpoint or '-'} | Severity: {_normalize_nuclei_severity(top.get('severity'))}",
        )

    for insight in correlation_insights[:2] if isinstance(correlation_insights, list) else []:
        item = insight.to_dict() if hasattr(insight, "to_dict") else insight
        if not isinstance(item, dict):
            continue
        title = _clean(item.get("title") or "Korelasyon içgörüsü")
        affected_asset = str(item.get("affected_asset") or "").strip()
        validation_steps = item.get("manual_validation_steps") if isinstance(item.get("manual_validation_steps"), list) else []
        validation = _clean(validation_steps[0] if validation_steps else item.get("recommended_first_action") or "İlgili asset üzerinde kanıt kaynaklarını karşılaştır.")
        _add(
            88,
            f"Korelasyon sinyalini doğrula: {title}",
            item.get("why_it_matters") or "Birden fazla kaynak aynı asset/workflow üzerinde sinyal üretti.",
            validation,
            affected_asset or str(item.get("evidence_summary") or ""),
            "correlation insights",
            str(item.get("evidence_summary") or ""),
        )

    admin_auth_evidence = _first_url(admin_like) or _first_url(auth_like)
    admin_auth_count = len(admin_like) + len(auth_like)
    if admin_auth_count:
        _add(
            84,
            "Auth/admin yüzeylerinde erişim kontrolünü incele",
            f"Rapor {admin_auth_count} auth/admin sinyali gördü; bu yüzeyler yanlış yetkilendirme ve yanlış yönlendirme riskini artırır.",
            "Unauthenticated, düşük yetkili ve beklenen yetkili kullanıcı bağlamlarında aynı URL ailesini karşılaştır; role boundary ve redirect davranışını kaydet.",
            admin_auth_evidence,
            "classified_endpoints / auth profiler",
            f"admin={len(admin_like)}, auth={len(auth_like)}",
        )

    if waf_detected_count == 0 and (high_entries or admin_auth_count):
        _add(
            74,
            "WAF/CDN yokluğu varsayımını not ederek doğrulama hızını ayarla",
            "WAF/CDN sinyali raporda görünmüyor; bu koruma yokluğu kanıtı değildir ama doğrulamada rate ve scope disiplinini daha önemli hale getirir.",
            "wafw00f/WhatWeb sinyallerini ve response header’larını karşılaştır; doğrulama request’lerini düşük hızda ve scope içinde tut.",
            "WAF/CDN sinyali: tespit yok",
            "wafw00f / WhatWeb",
            "WAF/CDN absence yalnızca fingerprint sinyalidir; koruma olmadığı anlamına tek başına gelmez.",
        )

    if screenshot_count > 0:
        screenshot_path = ""
        screenshot_url = ""
        for entry in screenshot_entries:
            if not isinstance(entry, dict):
                continue
            screenshot_path = str(entry.get("screenshot_path") or "").strip()
            screenshot_url = str(entry.get("url") or "").strip()
            if screenshot_path:
                break
        _add(
            68,
            "Screenshot kanıtını ilgili bulguyla eşleştir",
            "Görsel kanıt, endpoint’in gerçekten erişilebilir olduğunu ve operatörün gördüğü UI bağlamını hızlıca doğrular.",
            "Öncelikli URL için screenshot, HTTP durum ve başlık bilgisini karşılaştır; görsel kanıtı tek başına zafiyet kanıtı olarak kabul etme.",
            screenshot_path or screenshot_url,
            "gowitness screenshot",
            f"Yakalanan screenshot sayısı: {screenshot_count}",
        )

    actions.sort(key=lambda item: int(item.get("priority", 0) or 0), reverse=True)
    return actions[:6]


def _render_operator_plan_section(actions: list[dict[str, Any]]) -> str:
    if not actions:
        actions = [
            {
                "priority": 50,
                "title": "Scope ve kapsama notunu gözden geçir",
                "why": "Bu run için yüksek öncelikli otomatik sinyal üretilmedi.",
                "validation": "Önce hedef, scope, tamamlanan stage’ler ve eksik tool durumunu kontrol et.",
                "evidence": "Araç kapsamı sınırlı / bulgu yok",
                "source": "report overview",
                "source_detail": "",
            }
        ]

    cards: list[str] = []
    for idx, action in enumerate(actions, start=1):
        extra_classes: list[str] = []
        if idx > 3:
            extra_classes.append("report-depth-summary-extra")
        if idx > 5:
            extra_classes.append("report-depth-balanced-extra")
        class_suffix = f" {' '.join(extra_classes)}" if extra_classes else ""
        evidence = str(action.get("evidence") or "").strip()
        evidence_html = _render_plan_evidence(evidence)
        source = str(action.get("source") or "").strip()
        source_detail = str(action.get("source_detail") or "").strip()
        source_line = f"<p><strong>Kaynak:</strong> {_html_escape(source)}</p>" if source else ""
        source_detail_html = (
            f'<div class="operator-plan-source-detail report-depth-body-deep-only" data-depth-body="deep">'
            f"{source_line}<p><strong>Detay:</strong> {_html_escape(_truncate_text(source_detail, 260))}</p></div>"
            if source_detail or source
            else ""
        )
        cards.append(
            f"""
            <article class="operator-plan-card{class_suffix}">
                <div class="operator-plan-rank">{idx}</div>
                <div>
                    <h3>{_html_escape(str(action.get("title") or "-"))}</h3>
                    <p><strong>Neden önemli?</strong> {_html_escape(str(action.get("why") or "-"))}</p>
                    <p><strong>Ne yapmalıyım?</strong> {_html_escape(str(action.get("validation") or "-"))}</p>
                    <p><strong>İlgili kanıt:</strong> {evidence_html}</p>
                    {source_detail_html}
                </div>
            </article>
            """
        )

    return f"""
    <div class="section compact report-depth-body-all operator-plan-section" data-depth-body="summary balanced deep" id="operator-plan">
      <h2>İlk 15 Dakika Operatör Planı</h2>
      <p class="operator-view-note">İlk kontrol sırası mevcut rapor kanıtlarından türetilir. Amaç, en yüksek sinyalli alanları güvenli doğrulama ve kapsam teyidiyle hızlıca ayırmaktır.</p>
      <div class="operator-plan-list">
        {''.join(cards)}
      </div>
    </div>
    """


def _render_plan_evidence(value: str) -> str:
    text = str(value or "").strip()
    if not text or text == "-":
        return "-"
    if text.startswith(("http://", "https://")):
        return _render_report_link(text, "")
    if text.startswith("screenshots/"):
        escaped = _html_escape(text)
        return f'<a href="{escaped}" target="_blank"><code>{escaped}</code></a>'
    return _html_escape(_truncate_text(text, 180))


def _build_nuclei_validation_suggestions(nuclei_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries = [entry for entry in (nuclei_entries or []) if isinstance(entry, dict)]
    if not entries:
        return []

    entries.sort(
        key=lambda item: (
            -_nuclei_severity_rank(item.get("severity")),
            str(item.get("template_id") or "").lower(),
            str(item.get("endpoint") or "").lower(),
        )
    )
    endpoints: list[str] = []
    template_ids: list[str] = []
    evidence_refs: list[dict[str, Any]] = []
    observed_labels: list[str] = []
    for entry in entries[:12]:
        endpoint = str(entry.get("endpoint") or "").strip()
        if endpoint and endpoint.lower() != "unknown" and endpoint not in endpoints:
            endpoints.append(endpoint)
        template_id = str(entry.get("template_id") or "").strip()
        if template_id and template_id != "Unknown" and template_id not in template_ids:
            template_ids.append(template_id)
        observed_label = _nuclei_observed_evidence_label(entry.get("observed_evidence_type"))
        if observed_label and observed_label not in observed_labels:
            observed_labels.append(observed_label)
        evidence_refs.append(
            {
                "source": "nuclei",
                "template_id": template_id or "Unknown",
                "category": observed_label or str(entry.get("name") or "template-match"),
                "status": "needs_manual_validation",
                "score": entry.get("finding_confidence_score", ""),
                "url": endpoint,
            }
        )

    highest = entries[0]
    severity = _normalize_nuclei_severity(highest.get("severity"))
    priority = 88 if severity in {"critical", "high"} else (72 if severity == "medium" else 55)
    evidence = [f"nuclei findings={len(entries)}", f"top severity={severity}"]
    if observed_labels:
        evidence.append(observed_labels[0])
    if template_ids:
        evidence.append(f"templates={', '.join(template_ids[:3])}")

    return [
        {
            "title": "Nuclei Evidence Validation",
            "priority": priority,
            "surface": "Nuclei",
            "why": (
                "Nuclei response evidence produced one or more matches. Treat template names as pattern labels; "
                "validate the affected URL and observed response behavior manually."
            ),
            "tests": [
                "repeat the exact affected URL with a controlled request",
                "compare response body/status against expected evidence markers",
                "record whether the behavior is confirmed, transient, or false-positive",
            ],
            "evidence": evidence,
            "matched_endpoints": endpoints[:10],
            "recommended_urls": endpoints[:10],
            "evidence_refs": evidence_refs[:12],
            "artifact_refs": [f"nuclei_template:{template_id}" for template_id in template_ids[:10]],
            "validation_state": "needs_manual_validation",
            "contributing_signals": [f"nuclei_entries={len(entries)}", f"severity={severity}"],
            "matched_technologies": [],
            "matched_cves": [],
        }
    ]


def _enrich_recommendation_references(
    suggestions: list[dict[str, Any]],
    *,
    candidate_validation: dict[str, Any],
    report_base_url: str,
) -> list[dict[str, Any]]:
    validation_by_url = candidate_validation.get("by_url") if isinstance(candidate_validation.get("by_url"), dict) else {}

    def _url_key(value: Any) -> str:
        safe = _sanitize_report_url(value, report_base_url)
        return (safe or str(value or "").strip()).lower()

    validation_lookup: dict[str, dict[str, Any]] = {}
    for key, record in validation_by_url.items() if isinstance(validation_by_url, dict) else []:
        if not isinstance(record, dict):
            continue
        for candidate in (key, record.get("url"), record.get("original_url")):
            lookup_key = _url_key(candidate)
            if lookup_key:
                validation_lookup[lookup_key] = record

    enriched: list[dict[str, Any]] = []
    for item in suggestions:
        if not isinstance(item, dict):
            continue
        copy = dict(item)
        raw_urls = copy.get("recommended_urls") if isinstance(copy.get("recommended_urls"), list) else copy.get("matched_endpoints", [])
        recommended_urls: list[str] = []
        suppressed_refs: list[dict[str, Any]] = []
        seen_urls: set[str] = set()
        for raw_url in raw_urls if isinstance(raw_urls, list) else []:
            safe_url = _sanitize_report_url(raw_url, report_base_url) or str(raw_url or "").strip()
            if not safe_url or _is_probably_static_asset_url(safe_url):
                continue
            record = validation_lookup.get(_url_key(safe_url))
            state = str((record or {}).get("classification_status") or "").strip()
            if state and state != "confirmed":
                suppressed_refs.append(
                    {
                        "source": (record or {}).get("source") or "candidate_validation",
                        "url": safe_url,
                        "status": state,
                        "category": ", ".join(str(v) for v in ((record or {}).get("categories") or [])[:4]),
                    }
                )
                continue
            key = safe_url.lower()
            if key in seen_urls:
                continue
            seen_urls.add(key)
            recommended_urls.append(safe_url)

        refs = copy.get("evidence_refs") if isinstance(copy.get("evidence_refs"), list) else []
        evidence_refs = [ref for ref in refs if isinstance(ref, dict)]
        for url in recommended_urls:
            record = validation_lookup.get(_url_key(url))
            if isinstance(record, dict):
                validation = record.get("validation") if isinstance(record.get("validation"), dict) else {}
                evidence_refs.append(
                    {
                        "source": record.get("source") or "candidate_validation",
                        "url": url,
                        "category": ", ".join(str(v) for v in (record.get("categories") or [])[:4]),
                        "status": record.get("classification_status") or "confirmed",
                        "score": validation.get("status_code") or "",
                    }
                )
        evidence_refs.extend(suppressed_refs)
        if not recommended_urls and suppressed_refs:
            copy["validation_state"] = "suppressed"
        elif str(copy.get("validation_state") or "").strip():
            copy["validation_state"] = str(copy.get("validation_state") or "").strip()
        elif recommended_urls:
            copy["validation_state"] = "confirmed"
        else:
            copy["validation_state"] = "needs_manual_validation"
        copy["recommended_urls"] = recommended_urls[:12]
        copy["evidence_refs"] = evidence_refs[:20]
        copy["artifact_refs"] = [
            str(ref or "").strip()
            for ref in (copy.get("artifact_refs") if isinstance(copy.get("artifact_refs"), list) else [])
            if str(ref or "").strip()
        ][:12]
        enriched.append(copy)
    return enriched



def generate_report(
    gobuster_results: dict,
    katana_urls: list[str],
    checks_results: dict,
    nuclei_results: dict,
    target: str,
    nmap_output: str,
    skipped_tools: list[str] | None = None,
    output_dir: Path | str | None = None,
    report_depth: str | None = None,
    open_browser: bool = True,
    quiet: bool = False,
):
    
    if output_dir is None:
        report_dir = Path(__file__).resolve().parent
    else:
        report_dir = Path(output_dir)
    report_dir = report_dir.resolve()
    report_path = report_dir / "report.html"
    depth_config: ReportDepthConfig = resolve_report_depth(report_depth)

    run_context = _load_report_context(report_dir)
    report_scope_seed = "|".join(
        [
            str(report_dir),
            str(run_context.get("started_at") or ""),
            str(run_context.get("target") or target or ""),
        ]
    ).strip() or str(report_dir)
    stage_rows_html = _render_stage_rows(run_context)
    nuclei_state_note_html = _render_nuclei_state_note(run_context, nuclei_results or {})
    stages_ctx = run_context.get("stages") if isinstance(run_context.get("stages"), dict) else {}
    nuclei_stage_ctx = stages_ctx.get("nuclei") if isinstance(stages_ctx.get("nuclei"), dict) else {}
    nuclei_stage_status = str(nuclei_stage_ctx.get("status") or "").strip().lower()
    run_state_value = str(run_context.get("run_state") or "").strip().lower()
    auto_refresh_enabled_raw = run_context.get("auto_refresh_enabled", None)
    osint_context = run_context.get("osint") if isinstance(run_context.get("osint"), dict) else {}
    auto_refresh_enabled = bool(auto_refresh_enabled_raw) if isinstance(auto_refresh_enabled_raw, bool) else False
    run_config_context = run_context.get("run_config") if isinstance(run_context.get("run_config"), dict) else {}
    osint_only_report = str(run_config_context.get("run_mode") or "").strip() == "osint_only"
    auto_refresh_meta = ""
    if isinstance(auto_refresh_enabled_raw, bool):
        auto_refresh_meta = (
            '<meta http-equiv="refresh" content="5">'
            if (auto_refresh_enabled and run_state_value == "running")
            else ""
        )
    else:
        # Backward compatibility fallback (older snapshots might not have lifecycle flags).
        if run_state_value in {"interrupted", "failed", "completed", "incomplete"}:
            auto_refresh_meta = ""
        else:
            auto_refresh_meta = '<meta http-equiv="refresh" content="5">' if nuclei_stage_status == "running" else ""

    run_lifecycle_note_html = ""
    if run_state_value == "interrupted":
        run_lifecycle_note_html = _txt("run_lifecycle_interrupted")
    elif run_state_value == "failed":
        run_lifecycle_note_html = _txt("run_lifecycle_failed")
    elif run_state_value == "incomplete":
        run_lifecycle_note_html = "Tarama sona erdi ancak bazı aşamalar başarısız: kapsam eksik."
    elif run_state_value == "completed":
        run_lifecycle_note_html = _txt("run_lifecycle_completed")
    elif run_state_value == "running":
        run_lifecycle_note_html = _txt("run_lifecycle_running")
    run_lifecycle_block_html = f'<div id="run-lifecycle-note">{run_lifecycle_note_html}</div>'
    live_refresh_running = bool(auto_refresh_meta)
    refresh_interval_seconds = 5
    report_state_script = build_report_state_script()
    traffic_context = run_context.get("traffic") if isinstance(run_context.get("traffic"), dict) else {}
    traffic_html = ""
    if traffic_context:
        requested_profile = traffic_context.get("requested_profile") or "-"
        effective_profile = traffic_context.get("effective_profile") or requested_profile
        risk_level = traffic_context.get("risk_level") or "-"
        recommended_profile = traffic_context.get("recommended_profile") or effective_profile
        auto_events = traffic_context.get("auto_throttle_events") if isinstance(traffic_context.get("auto_throttle_events"), list) else []
        auto_html = "<br>".join(
            f"<code>{_html_escape(str(event.get('stage') or '-'))}</code>: {_html_escape(str(event.get('from_profile') or '-'))} → {_html_escape(str(event.get('to_profile') or '-'))} ({_html_escape(str(event.get('reason') or '-'))})"
            for event in auto_events
        ) or f'<span class="note">{_html_escape(_txt("traffic_no_auto"))}</span>'
        traffic_html = f"""
        <div class=\"section report-depth-body-all\" data-depth-body=\"summary balanced deep\" id=\"traffic-profile\">
            <h2>{_html_escape(_txt("traffic_title"))}</h2>
            <p><strong>{_html_escape(_txt("traffic_requested"))}:</strong> {_html_escape(requested_profile)} | <strong>{_html_escape(_txt("traffic_effective"))}:</strong> {_html_escape(effective_profile)} | <strong>{_html_escape(_txt("traffic_risk"))}:</strong> {_html_escape(risk_level)} | <strong>{_html_escape(_txt("traffic_recommended"))}:</strong> {_html_escape(recommended_profile)}</p>
            <p class=\"note\">{_html_escape(_txt("traffic_events"))}</p>
            <p class=\"note\">{auto_html}</p>
        </div>
        """
    else:
        traffic_html = f"""
        <div class=\"section report-depth-body-all\" data-depth-body=\"summary balanced deep\" id=\"traffic-profile\">
            <h2>{_html_escape(_txt("traffic_title"))}</h2>
            <p class=\"note\">Traffic profile metadata is not available in this run snapshot.</p>
        </div>
        """

    skipped_tools = skipped_tools or []
    skipped_tool_names = {str(name or "").strip().lower() for name in skipped_tools if str(name or "").strip()}
    checks_skipped = "checks" in skipped_tool_names
    skipped_html = "Yok" if not skipped_tools else ", ".join(skipped_tools)
    report_base_url = _derive_report_base_url(target)
    surface_discovery_tool_order = [
        "subfinder",
        "dnsx",
        "httpx",
        "katana",
        "gobuster",
        "ffuf",
        "historical_urls",
        "screenshots",
    ]
    core_tool_order = ["nmap", "wafw00f", "whatweb", "checks"]
    closed_surface_discovery_tools = [
        name for name in surface_discovery_tool_order if name in skipped_tool_names
    ]
    working_core_tools = [name for name in core_tool_order if name not in skipped_tool_names]
    limited_surface_discovery = bool(closed_surface_discovery_tools)
    tool_coverage_label = "seçilen araçlarla sınırlı" if skipped_tool_names else "yapılandırılmış araçlar"
    discovery_scope_label = "sınırlı" if limited_surface_discovery else "normal"
    discovery_scope_note = (
        "Seçilen keşif kapsamı. "
        f"Çalışan çekirdek araçlar: {', '.join(working_core_tools) if working_core_tools else 'yok'}. "
        f"Kapalı yüzey keşfi araçları: {', '.join(closed_surface_discovery_tools) if closed_surface_discovery_tools else 'yok'}."
    )

    # --- Web Checks / Endpoint data (must be available before summary sections) ---
    checks_results = checks_results or {}
    if isinstance(checks_results, dict):
        repaired_screenshots, _ = repair_screenshot_metadata(
            report_dir,
            checks_results.get("screenshots") if isinstance(checks_results.get("screenshots"), dict) else None,
        )
        if repaired_screenshots:
            checks_results["screenshots"] = repaired_screenshots
            data_ctx = run_context.get("data") if isinstance(run_context.get("data"), dict) else {}
            if isinstance(data_ctx, dict):
                data_ctx["screenshots"] = repaired_screenshots
                checks_ctx = data_ctx.get("checks_results") if isinstance(data_ctx.get("checks_results"), dict) else {}
                if isinstance(checks_ctx, dict):
                    checks_ctx["screenshots"] = repaired_screenshots
    ffuf_findings_by_base = checks_results.get("ffuf_findings", {}) if isinstance(checks_results, dict) else {}
    if not isinstance(ffuf_findings_by_base, dict):
        ffuf_findings_by_base = {}
    soft_error_filter = checks_results.get("soft_error_filter", {}) if isinstance(checks_results, dict) else {}
    if not isinstance(soft_error_filter, dict):
        soft_error_filter = {}
    soft_error_suppressed_count = _safe_int(soft_error_filter.get("suppressed_count"), 0)
    candidate_validation = checks_results.get("candidate_validation", {}) if isinstance(checks_results, dict) else {}
    if not isinstance(candidate_validation, dict):
        candidate_validation = {}
    candidate_suppressed_count = _safe_int(candidate_validation.get("suppressed_count"), 0)
    endpoint_analysis = checks_results.get("endpoint_analysis", {}) if isinstance(checks_results, dict) else {}
    if not isinstance(endpoint_analysis, dict):
        endpoint_analysis = {}
    analysis_scoring_inputs = endpoint_analysis.get("scoring_inputs", {}) if isinstance(endpoint_analysis.get("scoring_inputs"), dict) else {}
    ffuf_scoring = compute_ffuf_scoring_contribution(analysis_scoring_inputs)
    ffuf_scoring_metrics = ffuf_scoring.get("metrics", {}) if isinstance(ffuf_scoring.get("metrics"), dict) else {}
    ffuf_unique_clusters = int(ffuf_scoring_metrics.get("ffuf_unique_clusters", 0) or 0)
    ffuf_confirmed_clusters = int(ffuf_scoring_metrics.get("ffuf_confirmed_clusters", 0) or 0)
    ffuf_high_value_clusters = int(ffuf_scoring_metrics.get("ffuf_high_value_clusters", 0) or 0)
    ffuf_sensitive_marker_clusters = int(ffuf_scoring_metrics.get("ffuf_sensitive_marker_clusters", 0) or 0)
    ffuf_security_relevant_clusters = int(ffuf_scoring_metrics.get("ffuf_security_relevant_clusters", 0) or 0)
    ffuf_diverse_response_clusters = int(ffuf_scoring_metrics.get("ffuf_diverse_response_clusters", 0) or 0)
    ffuf_overlap_ratio = float(ffuf_scoring_metrics.get("ffuf_overlap_ratio", 0.0) or 0.0)
    ffuf_effective_units = int(ffuf_scoring_metrics.get("ffuf_effective_units", 0) or 0)
    raw_cluster_insights = checks_results.get("cluster_insights")
    if not isinstance(raw_cluster_insights, list):
        raw_cluster_insights = endpoint_analysis.get("cluster_insights", [])
    normalized_cluster_insights = _normalize_analysis_cluster_insights(
        raw_cluster_insights,
        report_base_url,
    )
    representative_cluster_map, variant_to_representative = _build_analysis_cluster_maps(
        normalized_cluster_insights
    )

    login_pages = _normalize_report_item_bucket(checks_results.get("login_pages", []) or [], report_base_url, drop_static_assets=True)
    captcha_pages = _normalize_report_item_bucket(checks_results.get("captcha_pages", []) or [], report_base_url, drop_static_assets=True)
    docs_pages = _normalize_report_item_bucket(checks_results.get("docs_pages", []) or [], report_base_url, drop_static_assets=False)
    # Normalize docs_pages to remove query/protocol duplicates
    docs_pages_normalized: dict[str, dict] = {}
    for item in docs_pages:
        try:
            url = item.get("url", "")
            parsed = urlparse(url)
            path = (parsed.path or "").lower()

            if "documentation/" in url.lower():
                import re
                m = re.search(r"documentation/[^?&#]+", url.lower())
                if m:
                    path = m.group(0)

            if path and path not in docs_pages_normalized:
                docs_pages_normalized[path] = item
        except Exception:
            continue

    docs_pages = list(docs_pages_normalized.values())
    rate_signals = _normalize_report_item_bucket(checks_results.get("rate_limit_signals", []) or [], report_base_url, drop_static_assets=False)
    captcha_coverage = checks_results.get("captcha_coverage", []) or []
    captcha_risk_notes = checks_results.get("captcha_risk_notes", []) or []
    auth_profile = checks_results.get("auth_profile") or {}
    auth_candidates = auth_profile.get("auth_candidates") or []
    auth_summary = auth_profile.get("auth_summary") or {}
    classified_endpoints_primary = checks_results.get("classified_endpoints", {}) or {}
    if not isinstance(classified_endpoints_primary, dict):
        classified_endpoints_primary = {}
    classified_endpoints = classified_endpoints_primary
    technology_fingerprint = []
    for item in (checks_results.get("technology_fingerprint", []) or []):
        if not isinstance(item, dict):
            continue
        safe_site = _sanitize_report_url(item.get("site"), report_base_url)
        if not safe_site:
            continue
        if _is_probably_static_asset_url(safe_site):
            continue
        if safe_site.lower().endswith("/whatweb-derived"):
            continue
        normalized_item = dict(item)
        normalized_item["site"] = safe_site
        technology_fingerprint.append(normalized_item)
    attack_chains = checks_results.get("attack_chains", []) or []
    attack_graph = checks_results.get("attack_graph", {}) or {}
    
    if isinstance(attack_graph, dict):
        graph_nodes = attack_graph.get("nodes", []) if isinstance(attack_graph.get("nodes"), list) else []
        normalized_graph_nodes: list[dict[str, Any]] = []

        for node in graph_nodes:
            if not isinstance(node, dict):
                continue

            normalized_node = dict(node)
            details = normalized_node.get("details", [])
            normalized_details: list[str] = []

            for detail in details if isinstance(details, list) else []:
                text_detail = str(detail or "").strip()
                if not text_detail:
                    continue
                if text_detail.startswith(("http://", "https://", "//", "/")):
                    safe_detail = _sanitize_report_url(text_detail, report_base_url)
                    if safe_detail and not _is_probably_static_asset_url(safe_detail):
                        normalized_details.append(
                            variant_to_representative.get(safe_detail, safe_detail)
                        )
                        continue
                normalized_details.append(text_detail)

            normalized_node["details"] = normalized_details
            normalized_graph_nodes.append(normalized_node)

        attack_graph["nodes"] = normalized_graph_nodes    
    cve_enrichment = checks_results.get("cve_enrichment", {}) or {}
    exploit_suggestions = checks_results.get("exploit_suggestions", []) or []
    node_relationships = checks_results.get("node_relationships", {}) or {}
    
    if isinstance(node_relationships, dict):
        normalized_node_relationships: dict[str, Any] = {}
        for node_key, node_value in node_relationships.items():
            if not isinstance(node_value, dict):
                normalized_node_relationships[node_key] = node_value
                continue

            normalized_node = dict(node_value)
            normalized_related_endpoints: list[str] = []
            seen_related: set[str] = set()
            for endpoint_value in (normalized_node.get("related_endpoints", []) or []):
                text_value = str(endpoint_value or "").strip()
                if not text_value:
                    continue
                if _is_url_like_text(text_value):
                    safe_endpoint = _sanitize_report_url(text_value, report_base_url)
                    if not safe_endpoint:
                        continue
                    if _is_probably_static_asset_url(safe_endpoint):
                        continue
                    representative_endpoint = variant_to_representative.get(
                        safe_endpoint,
                        safe_endpoint,
                    )
                    if representative_endpoint in seen_related:
                        continue
                    seen_related.add(representative_endpoint)
                    normalized_related_endpoints.append(representative_endpoint)
                else:
                    if text_value in seen_related:
                        continue
                    seen_related.add(text_value)
                    normalized_related_endpoints.append(text_value)
            normalized_node["related_endpoints"] = normalized_related_endpoints
            normalized_node["related_nuclei_tags"] = [
                str(tag or "").strip()
                for tag in (normalized_node.get("related_nuclei_tags", []) or [])
                if str(tag or "").strip()
            ]
            normalized_node_relationships[node_key] = normalized_node

        node_relationships = normalized_node_relationships
    waf_signals = checks_results.get("waf_signals", {}) or {}
    whatweb_signals = checks_results.get("whatweb_signals", {}) or {}
    waf_detected_count = int(checks_results.get("waf_detected_count", 0) or 0)
    # --- Discovery-aware decision reliability layer ---
    tier_1_critical = {"katana", "httpx", "subfinder"}
    tier_2_enrichment = {"whatweb", "wafw00f"}
    tier_3_auxiliary = {"ffuf", "gobuster"}

    stage_lookup: dict[str, dict[str, Any]] = {}
    for _stage_name, _stage_data in (stages_ctx.items() if isinstance(stages_ctx, dict) else []):
        if not isinstance(_stage_data, dict):
            continue
        _stage_key = str(_stage_name or "").strip().lower()
        if not _stage_key:
            continue
        stage_lookup[_stage_key] = _stage_data

    def _failed_stage_entry(stage_name: str) -> dict[str, str] | None:
        _stage = stage_lookup.get(stage_name)
        if not isinstance(_stage, dict):
            return None
        _status = str(_stage.get("status") or "").strip().lower()
        if _status not in {"error", "failed", "partial", "interrupted"}:
            return None
        _error = str(_stage.get("error") or _stage.get("reason") or "").strip()
        return {"tool": stage_name, "error": _error}

    failed_tier_1: list[dict[str, str]] = []
    for _tool in sorted(tier_1_critical):
        _entry = _failed_stage_entry(_tool)
        if _entry:
            failed_tier_1.append(_entry)

    failed_tier_2: list[dict[str, str]] = []
    for _tool in sorted(tier_2_enrichment):
        _entry = _failed_stage_entry(_tool)
        if _entry:
            failed_tier_2.append(_entry)

    failed_tier_3: list[dict[str, str]] = []
    for _tool in sorted(tier_3_auxiliary):
        _entry = _failed_stage_entry(_tool)
        if _entry:
            failed_tier_3.append(_entry)

    failed_tier_1_text = ", ".join(
        str(item.get("tool") or "").strip()
        for item in failed_tier_1
        if str(item.get("tool") or "").strip()
    )
    failed_tier_2_text = ", ".join(
        str(item.get("tool") or "").strip()
        for item in failed_tier_2
        if str(item.get("tool") or "").strip()
    )
    failed_tier_3_text = ", ".join(
        str(item.get("tool") or "").strip()
        for item in failed_tier_3
        if str(item.get("tool") or "").strip()
    )

    if len(failed_tier_1) >= 2:
        discovery_reliability = "CRITICAL"
    elif len(failed_tier_1) >= 1:
        discovery_reliability = "LOW"
    elif failed_tier_2:
        discovery_reliability = "MEDIUM"
    else:
        discovery_reliability = "HIGH"

    discovery_confidence_factor = _DISCOVERY_CONFIDENCE_FACTORS.get(discovery_reliability, 1.0)
    has_any_tier_failure = bool(failed_tier_1 or failed_tier_2 or failed_tier_3)

    critical_coverage_degradation = discovery_reliability == "CRITICAL"
    low_coverage_degradation = discovery_reliability == "LOW"
    partial_coverage_degradation = discovery_reliability == "MEDIUM"
    auxiliary_coverage_degradation = bool(discovery_reliability == "HIGH" and failed_tier_3)
    discovery_coverage_degraded = bool(discovery_reliability != "HIGH")
    discovery_low_or_critical = discovery_reliability in {"LOW", "CRITICAL"}

    if critical_coverage_degradation:
        coverage_status_label = "Critical discovery güvenilirliği"
        coverage_status_detail = (
            f"Discovery kapsamı Tier-1 hataları nedeniyle kritik düzeyde zayıfladı ({failed_tier_1_text})."
        )
        failure_details_source = failed_tier_1
    elif low_coverage_degradation:
        coverage_status_label = "Low discovery güvenilirliği"
        coverage_status_detail = (
            f"Discovery kapsamı Tier-1 hatası nedeniyle zayıfladı ({failed_tier_1_text})."
        )
        failure_details_source = failed_tier_1
    elif partial_coverage_degradation:
        coverage_status_label = "Medium discovery güvenilirliği"
        coverage_status_detail = (
            f"Discovery güvenilirliği Tier-2 zayıflaması nedeniyle azaldı ({failed_tier_2_text})."
        )
        failure_details_source = failed_tier_2
    elif auxiliary_coverage_degradation:
        coverage_status_label = "Minor auxiliary zayıflama"
        coverage_status_detail = (
            f"Auxiliary tooling zayıfladı ({failed_tier_3_text}); discovery güvenilirliği yüksek kalıyor."
        )
        failure_details_source = failed_tier_3
    else:
        coverage_status_label = "Normal"
        coverage_status_detail = "Yapılandırılmış critical/enrichment katmanları için kapsama tamam."
        failure_details_source = []
    skipped_coverage_blockers = {
        "nuclei",
        "screenshots",
        "katana",
        "ffuf",
        "gobuster",
        "historical_urls",
        "checks",
    }
    if coverage_status_label == "Normal" and skipped_tool_names:
        coverage_status_label = "seçilen kapsam"
        coverage_status_detail = (
            "Kapalı veya hedefe uygulanmayan araçlar hata değildir. "
            "Sonuçlar yalnız çalıştırılan kontroller için geçerlidir."
        )

    structural_confidence = int(round(discovery_confidence_factor * 100))
    if auxiliary_coverage_degradation:
        structural_confidence = max(85, structural_confidence - min(10, len(failed_tier_3) * 5))
    structural_confidence = max(20, min(100, structural_confidence))

    if failure_details_source:
        failure_details_preview = "; ".join(
            f"{item.get('tool')}: {_truncate_text(item.get('error') or 'error/timeout', 72)}"
            for item in failure_details_source[:3]
        )
    else:
        failure_details_preview = ""
    whatweb_detected_count = sum(
        1 for item in whatweb_signals.values()
        if isinstance(item, dict) and bool(item.get("plugin_names"))
    )
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

    tech_owasp_notes: list[str] = []
    lower_techs = [t.lower() for t in tech_labels]
    if any(t in lower_techs for t in ["php", "apache httpd"]):
        tech_owasp_notes.append("A05 Security Misconfiguration / legacy PHP-Apache stack ihtimali")
    if any("swagger" in t for t in lower_techs) or any("redoc" in t for t in lower_techs):
        tech_owasp_notes.append("A05 Security Misconfiguration / API dokümantasyon exposure")
    if any("graphql" in t for t in lower_techs):
        tech_owasp_notes.append("API schema exposure / mass assignment / excessive data exposure analizi")
    if any(t in lower_techs for t in ["wordpress", "drupal", "joomla"]):
        tech_owasp_notes.append("CMS attack surface / plugin-tema exposure / patch hygiene kontrolü")
    if any(t in lower_techs for t in ["django", "laravel", "asp.net", "next.js", "react", "vue.js", "angular"]):
        tech_owasp_notes.append("Framework-specific misconfiguration ve auth/session kontrolleri")
    if waf_labels or waf_detected_count > 0:
        tech_owasp_notes.append("WAF/CDN presence: bypass-resistant davranış ve rate-limit stratejisi düşünülmeli")

    def _get_bucket_urls(source: Any, bucket: str) -> list[Any]:
        if not isinstance(source, dict):
            return []
        values = source.get(bucket, [])
        return values if isinstance(values, list) else []

    def _enum_urls_by_status(statuses: set[int]) -> list[str]:
        urls: list[str] = []
        if not isinstance(gobuster_results, dict):
            return urls
        for values in gobuster_results.values():
            if not isinstance(values, list):
                continue
            for item in values:
                if not isinstance(item, dict):
                    continue
                try:
                    status = int(item.get("status") or 0)
                except (TypeError, ValueError):
                    status = 0
                url = str(item.get("url") or "").strip()
                if status in statuses and url:
                    urls.append(url)
        return urls

    def _url_identity(url: str) -> tuple[str, str]:
        normalized = _sanitize_report_url(str(url or ""), report_base_url) or str(url or "")
        parsed = urlparse(normalized)
        path = (parsed.path or "/").rstrip("/") or "/"
        return (parsed.netloc.lower(), path.lower())

    # Render/scoring lists: always use the full classified inventory as source-of-truth.
    admin_like = _prepare_source_bucket_urls(
        _get_bucket_urls(classified_endpoints, "admin_like"),
        base_url=report_base_url,
        drop_static_assets=True,
    )
    admin_like = _filter_report_admin_like(admin_like)
    auth_like = _prepare_source_bucket_urls(
        _get_bucket_urls(classified_endpoints, "auth_like"),
        base_url=report_base_url,
        drop_static_assets=True,
    )
    auth_like = _filter_report_auth_like(auth_like)
    api_like = _prepare_source_bucket_urls(
        _get_bucket_urls(classified_endpoints, "api_like"),
        base_url=report_base_url,
        drop_static_assets=True,
    )
    upload_like = _prepare_source_bucket_urls(
        _get_bucket_urls(classified_endpoints, "upload_like"),
        base_url=report_base_url,
        drop_static_assets=True,
    )
    debug_like = _prepare_source_bucket_urls(
        _get_bucket_urls(classified_endpoints, "debug_like"),
        base_url=report_base_url,
        drop_static_assets=True,
    )
    debug_like = _filter_report_debug_like(debug_like)
    readable_enum_urls = _prepare_source_bucket_urls(
        _enum_urls_by_status({200}),
        base_url=report_base_url,
        drop_static_assets=True,
    )
    review_enum_urls = _prepare_source_bucket_urls(
        _enum_urls_by_status({200, 201, 202, 204, 301, 302, 307, 308, 401, 403}),
        base_url=report_base_url,
        drop_static_assets=True,
    )
    forbidden_enum_keys = {_url_identity(url) for url in _enum_urls_by_status({401, 403})}
    readable_enum_keys = {_url_identity(url) for url in readable_enum_urls}
    forbidden_only_server_status_keys = {
        key for key in forbidden_enum_keys - readable_enum_keys
        if key[1] == "/server-status"
    }
    if forbidden_only_server_status_keys:
        debug_like = [
            url for url in debug_like
            if _url_identity(url) not in forbidden_only_server_status_keys
        ]
    docs_like = _prepare_source_bucket_urls(
        _get_bucket_urls(classified_endpoints, "docs_like"),
        base_url=report_base_url,
        drop_static_assets=False,
    )
    source_control_like = _prepare_source_bucket_urls(
        _get_bucket_urls(classified_endpoints, "source_control_like"),
        base_url=report_base_url,
        drop_static_assets=True,
    )
    admin_like_for_score = admin_like
    auth_like_for_score = auth_like
    api_like_for_score = api_like
    upload_like_for_score = upload_like
    debug_like_for_score = debug_like
    docs_like_for_score = docs_like
    source_control_like_for_score = source_control_like
    combined_surface_urls = (
        admin_like_for_score
        + auth_like_for_score
        + api_like_for_score
        + upload_like_for_score
        + debug_like_for_score
        + docs_like_for_score
        + source_control_like_for_score
        + readable_enum_urls
    )
    structural_exposure_groups = _report_structural_exposure_groups(combined_surface_urls)
    structural_exposure_count = sum(len(urls) for urls in structural_exposure_groups.values())
    upload_execution_evidence = _report_has_upload_execution_evidence(upload_like_for_score)
    backup_manual_review_urls = [
        url for url in review_enum_urls
        if _report_is_backup_manual_review_url(url)
    ]
    debug_config_structural_evidence = any(
        key in structural_exposure_groups
        for key in ("config", "logs", "debug_console", "runtime", "internal_api", "admin_export")
    )
    attack_chains, attack_graph, exploit_suggestions = _report_prune_debug_false_positive_artifacts(
        attack_chains,
        attack_graph,
        exploit_suggestions,
        keep_debug_config_artifacts=bool(debug_like_for_score or debug_config_structural_evidence),
    )

    katana_cleaned_urls = checks_results.get("katana_cleaned_urls")
    if not isinstance(katana_cleaned_urls, list):
        katana_cleaned_urls = endpoint_analysis.get("katana_cleaned_urls", [])
    analysis_cluster_representatives = _prepare_representative_urls(
        [cluster.get("representative_url") for cluster in normalized_cluster_insights],
        base_url=report_base_url,
        variant_to_rep=variant_to_representative,
        drop_static_assets=True,
        require_reportworthy=False,
    )
    analysis_representative_fallback = _prepare_representative_urls(
        endpoint_analysis.get("representative_endpoints", [])
        if isinstance(endpoint_analysis.get("representative_endpoints"), list)
        else [],
        base_url=report_base_url,
        variant_to_rep=variant_to_representative,
        drop_static_assets=True,
        require_reportworthy=False,
    )
    katana_representative_urls = analysis_cluster_representatives or analysis_representative_fallback
    katana_analysis_active = bool(katana_representative_urls)
    endpoint_analysis_baseline_only = bool(
        checks_skipped
        and len(katana_representative_urls) <= 1
        and not (katana_urls or [])
        and not normalized_cluster_insights
    )
    if not katana_representative_urls:
        katana_representative_urls = _prepare_representative_urls(
            (
                (katana_urls or [])
                + (katana_cleaned_urls if isinstance(katana_cleaned_urls, list) else [])
            ),
            base_url=report_base_url,
            variant_to_rep=variant_to_representative,
            drop_static_assets=True,
            require_reportworthy=False,
        )
    if "katana" in (skipped_tools or []):
        katana_representative_urls = []
        katana_analysis_active = False
        endpoint_analysis_baseline_only = checks_skipped
    nuclei_findings = nuclei_to_findings(nuclei_results) if isinstance(nuclei_results, dict) and nuclei_results else []
    live_fallback_findings = nuclei_results.get("_live_findings", []) if isinstance(nuclei_results, dict) else []
    nuclei_results_map = nuclei_results if isinstance(nuclei_results, dict) else {}
    nuclei_report_entries = _build_nuclei_report_entries(nuclei_results_map)
    # Per-finding trust model (discovery dependency aware).
    _mode_meta = str((run_context.get("meta") or {}).get("mode") or "").strip().lower() if isinstance(run_context.get("meta"), dict) else ""
    if _mode_meta == "url":
        _default_discovery_dependencies = ["katana"]
    elif _mode_meta == "ip":
        _default_discovery_dependencies = ["httpx", "katana"]
    else:
        _default_discovery_dependencies = ["subfinder", "httpx", "katana"]

    def _is_stage_success(stage_name: str) -> bool:
        _stage = stages_ctx.get(stage_name) if isinstance(stages_ctx, dict) else {}
        if not isinstance(_stage, dict):
            return False
        _st = str(_stage.get("status") or "").strip().lower()
        return _st in {"done", "success", "completed"}

    def _is_stage_failed(stage_name: str) -> bool:
        _stage = stages_ctx.get(stage_name) if isinstance(stages_ctx, dict) else {}
        if not isinstance(_stage, dict):
            return False
        _st = str(_stage.get("status") or "").strip().lower()
        return _st in {"error", "failed", "partial", "interrupted"}

    for _entry in nuclei_report_entries:
        if not isinstance(_entry, dict):
            continue
        _endpoint_value = str(_entry.get("endpoint") or "").strip()
        _deps = [dep for dep in _default_discovery_dependencies if dep not in skipped_tool_names]
        # If endpoint is directly visible in katana representatives/raw list, keep Katana dependency explicit.
        if _endpoint_value and any(_endpoint_value == str(_k or "").strip() for _k in (katana_urls or [])):
            if "katana" not in _deps:
                _deps.append("katana")
        _failed_deps = [_dep for _dep in _deps if _is_stage_failed(_dep)]
        _successful_deps = [_dep for _dep in _deps if _is_stage_success(_dep)]

        if _failed_deps:
            _trust = "low"
            _trust_reason = (
                f"Bağımlı discovery stage başarısız: {', '.join(_failed_deps)}. "
                f"Endpoint discovery kapsamı eksik."
            )
        elif discovery_coverage_degraded:
            _trust = "medium"
            _trust_reason = (
                f"Discovery kapsamı zayıfladı ({coverage_status_label.lower()}); "
                f"bulgu kısmen doğrulanmış olarak ele alınmalı."
            )
        elif has_any_tier_failure:
            _trust = "medium"
            _trust_reason = (
                f"Bazı supporting stage’ler zayıfladı ({coverage_status_label.lower()}); "
                f"bulgu confidence değeri kısmi."
            )
        elif any(not _is_stage_success(dep) for dep in _deps):
            _trust = "medium"
            _trust_reason = "Seçilen discovery aşamalarının tamamlanma kaydı eksik. Tarayıcı eşleşmesi bağımsız doğrulama gerektirir."
        else:
            _trust = "high"
            _trust_reason = "Kaydedilen keşif kapsamı eşleşmeyi destekliyor. Keşif, istismarın bağımsız doğrulaması değildir."

        # Numeric trust/confidence score for decision engine usage.
        if _trust == "high":
            _confidence_score = 85
        elif _trust == "medium":
            _confidence_score = 62
        else:
            _confidence_score = 35

        # Dependency-tier penalties (failed dependencies hurt confidence more if Tier-1).
        for _dep in _failed_deps:
            if _dep in tier_1_critical:
                _confidence_score -= 30
            elif _dep in tier_2_enrichment:
                _confidence_score -= 14
            elif _dep in tier_3_auxiliary:
                _confidence_score -= 5

        # Reward complete dependency success slightly.
        if _deps and len(_successful_deps) == len(_deps):
            _confidence_score += 8

        # Global coverage degradation nudges confidence down.
        if critical_coverage_degradation:
            _confidence_score -= 10
        elif partial_coverage_degradation:
            _confidence_score -= 5

        _confidence_score = max(0, min(100, int(_confidence_score)))

        _entry["trust_level"] = _trust
        _entry["trust_reason"] = _trust_reason
        _entry["finding_confidence_score"] = _confidence_score
        _entry["discovery_dependencies"] = _deps
        _entry["failed_dependencies"] = _failed_deps
        _entry["successful_dependencies"] = _successful_deps
    nuclei_endpoint_context_index = _build_nuclei_endpoint_context_index(
        base_url=report_base_url,
        classified_endpoints=classified_endpoints,
        login_pages=login_pages,
        docs_pages=docs_pages,
    )
    nuclei_template_groups = _group_nuclei_findings_by_template(
        nuclei_report_entries,
        base_url=report_base_url,
        endpoint_context_index=nuclei_endpoint_context_index,
    )
    nuclei_grouped_templates = _group_template_findings_by_severity(nuclei_template_groups)
    nuclei_summary_data = _compute_nuclei_summary(run_context, nuclei_results_map, nuclei_report_entries)
    nuclei_empty_message = _derive_nuclei_empty_message(run_context, nuclei_results_map)
    nuclei_findings_count = (
        len(nuclei_report_entries)
        if nuclei_report_entries
        else (len(nuclei_findings) if nuclei_findings else len(live_fallback_findings))
    )
    correlation_insights = build_correlation_insights(
        target=target,
        nmap_output=nmap_output,
        gobuster_results=gobuster_results,
        katana_urls=katana_urls,
        checks_results=checks_results,
        nuclei_entries=nuclei_report_entries,
        nuclei_results=nuclei_results_map,
        run_context=run_context,
    )
    low_conf_high_severity_count = len(
        [
            _entry
            for _entry in nuclei_report_entries
            if isinstance(_entry, dict)
            and _normalize_nuclei_severity(_entry.get("severity")) in {"critical", "high"}
            and int(_entry.get("finding_confidence_score", 0) or 0) <= 45
        ]
    )
    medium_conf_high_severity_count = len(
        [
            _entry
            for _entry in nuclei_report_entries
            if isinstance(_entry, dict)
            and _normalize_nuclei_severity(_entry.get("severity")) in {"critical", "high"}
            and 45 < int(_entry.get("finding_confidence_score", 0) or 0) <= 75
        ]
    )
    high_severity_findings_count = len(
        [
            _entry
            for _entry in nuclei_report_entries
            if isinstance(_entry, dict)
            and _normalize_nuclei_severity(_entry.get("severity")) in {"critical", "high"}
        ]
    )
    high_trust_high_severity_count = len(
        [
            _entry
            for _entry in nuclei_report_entries
            if isinstance(_entry, dict)
            and _normalize_nuclei_severity(_entry.get("severity")) in {"critical", "high"}
            and str(_entry.get("trust_level") or "").strip().lower() == "high"
            and int(_entry.get("finding_confidence_score", 0) or 0) >= 75
        ]
    )
    medium_trust_high_severity_count = len(
        [
            _entry
            for _entry in nuclei_report_entries
            if isinstance(_entry, dict)
            and _normalize_nuclei_severity(_entry.get("severity")) in {"critical", "high"}
            and str(_entry.get("trust_level") or "").strip().lower() == "medium"
        ]
    )
    low_trust_high_severity_count = len(
        [
            _entry
            for _entry in nuclei_report_entries
            if isinstance(_entry, dict)
            and _normalize_nuclei_severity(_entry.get("severity")) in {"critical", "high"}
            and (
                str(_entry.get("trust_level") or "").strip().lower() == "low"
                or int(_entry.get("finding_confidence_score", 0) or 0) <= 45
            )
        ]
    )
    high_trust_findings_count = len(
        [
            _entry
            for _entry in nuclei_report_entries
            if isinstance(_entry, dict)
            and str(_entry.get("trust_level") or "").strip().lower() == "high"
        ]
    )
    medium_trust_findings_count = len(
        [
            _entry
            for _entry in nuclei_report_entries
            if isinstance(_entry, dict)
            and str(_entry.get("trust_level") or "").strip().lower() == "medium"
        ]
    )
    low_trust_findings_count = len(
        [
            _entry
            for _entry in nuclei_report_entries
            if isinstance(_entry, dict)
            and str(_entry.get("trust_level") or "").strip().lower() == "low"
        ]
    )
    nuclei_model = augment_report_model_with_nuclei(
        attack_graph=attack_graph,
        attack_chains=attack_chains,
        node_relationships=node_relationships,
        classified_endpoints=classified_endpoints,
        nuclei_entries=nuclei_report_entries,
        grouped_findings=nuclei_template_groups,
    )
    if isinstance(nuclei_model, dict):
        attack_graph = nuclei_model.get("attack_graph", attack_graph) if isinstance(nuclei_model.get("attack_graph"), dict) else attack_graph
        attack_chains = nuclei_model.get("attack_chains", attack_chains) if isinstance(nuclei_model.get("attack_chains"), list) else attack_chains
        node_relationships = nuclei_model.get("node_relationships", node_relationships) if isinstance(nuclei_model.get("node_relationships"), dict) else node_relationships
    else:
        nuclei_model = {}
    if discovery_confidence_factor < 1.0:
        # Decision-safe scaling: chain/path confidence is multiplied by discovery reliability.
        _degraded_note = (
            f"Karar güveni discovery güvenilirliğine göre ayarlandı "
            f"({discovery_reliability.lower()}, factor={discovery_confidence_factor:.2f})."
        )
        if discovery_low_or_critical:
            _degraded_note += " Discovery kapsamı zayıfladı - bulgularla aksiyon almadan önce yüzeyi doğrula."

        degraded_chains: list[dict[str, Any]] = []
        for _chain_item in attack_chains if isinstance(attack_chains, list) else []:
            if not isinstance(_chain_item, dict):
                continue
            _chain_copy = dict(_chain_item)
            _base_chain_conf = _safe_int(
                _chain_copy.get("base_confidence", _chain_item.get("confidence", 0)),
                0,
            )
            _scaled_chain_conf = _scale_confidence_value(
                _chain_item.get("confidence", 0),
                discovery_confidence_factor,
            )
            _chain_copy["base_confidence"] = max(0, min(100, _base_chain_conf))
            _chain_copy["confidence"] = _scaled_chain_conf
            _rank_source = _safe_int(_chain_copy.get("rank_score", _scaled_chain_conf), _scaled_chain_conf)
            _chain_copy["rank_score"] = max(0, int(round(_rank_source * discovery_confidence_factor)))

            _chain_why = str(_chain_copy.get("why") or "").strip()
            _chain_copy["why"] = f"{_chain_why} {_degraded_note}".strip() if _chain_why else _degraded_note

            _chain_signals = _chain_copy.get("signals")
            if isinstance(_chain_signals, list):
                _chain_signals = [str(signal) for signal in _chain_signals if str(signal or "").strip()]
                _chain_signals.append(
                    f"discovery_reliability={discovery_reliability.lower()} factor={discovery_confidence_factor:.2f}"
                )
                if discovery_low_or_critical:
                    _chain_signals.append("chain_reliability: low (tier-1 discovery failure)")
                _chain_copy["signals"] = _chain_signals
            degraded_chains.append(_chain_copy)
        attack_chains = sorted(
            degraded_chains,
            key=lambda item: (
                _safe_int(item.get("rank_score", item.get("confidence", 0)), 0),
                _safe_int(item.get("confidence", 0), 0),
                str(item.get("name") or item.get("chain") or "").lower(),
            ),
            reverse=True,
        )

        if isinstance(attack_graph, dict):
            _graph_copy = dict(attack_graph)
            _degraded_paths: list[dict[str, Any]] = []
            for _path_item in (_graph_copy.get("paths", []) if isinstance(_graph_copy.get("paths"), list) else []):
                if not isinstance(_path_item, dict):
                    continue
                _path_copy = dict(_path_item)
                _path_base_conf = _safe_int(
                    _path_copy.get("base_confidence", _path_copy.get("confidence", 0)),
                    0,
                )
                _path_scaled_conf = _scale_confidence_value(
                    _path_item.get("confidence", 0),
                    discovery_confidence_factor,
                )
                _path_copy["base_confidence"] = max(0, min(100, _path_base_conf))
                _path_copy["confidence"] = _path_scaled_conf
                _path_evidence_boost = max(0, _safe_int(_path_copy.get("evidence_boost"), 0))
                _path_copy["rank_score"] = max(
                    0,
                    int(round((_path_scaled_conf * 7) + (_path_evidence_boost * 6))),
                )
                _path_why = str(_path_copy.get("why") or "").strip()
                _path_copy["why"] = f"{_path_why} {_degraded_note}".strip() if _path_why else _degraded_note
                _degraded_paths.append(_path_copy)
            _graph_copy["paths"] = _degraded_paths

            _degraded_edges: list[dict[str, Any]] = []
            for _edge_item in (_graph_copy.get("edges", []) if isinstance(_graph_copy.get("edges"), list) else []):
                if not isinstance(_edge_item, dict):
                    continue
                _edge_copy = dict(_edge_item)
                _edge_copy["confidence"] = _scale_confidence_value(
                    _edge_item.get("confidence", 0),
                    discovery_confidence_factor,
                )
                _degraded_edges.append(_edge_copy)
            _graph_copy["edges"] = _degraded_edges
            attack_graph = _graph_copy

    nuclei_priority_items = nuclei_model.get("priority_items", []) if isinstance(nuclei_model.get("priority_items"), list) else []
    nuclei_risk_points = int(nuclei_model.get("risk_points", 0) or 0)
    nuclei_risk_reason = str(nuclei_model.get("risk_reason") or "")
    graph_payload: dict[str, Any] = {}
    graph_payload_json = "{}"
    graph_payload_meta: dict[str, Any] = {}
    graph_payload_paths: list[dict[str, Any]] = []

    surface_breadth_candidate_urls = (
        admin_like_for_score
        + auth_like_for_score
        + api_like_for_score
        + upload_like_for_score
        + docs_like_for_score
        + source_control_like_for_score
        + readable_enum_urls
        + review_enum_urls
        + katana_representative_urls
    )
    non_content_review_urls: list[str] = []
    seen_review_keys: set[tuple[str, str]] = set()
    for candidate_url in surface_breadth_candidate_urls:
        safe_url = _sanitize_report_url(str(candidate_url or ""), report_base_url) or str(candidate_url or "").strip()
        if not safe_url:
            continue
        low_url = safe_url.lower()
        parsed_url = urlparse(low_url)
        path = (parsed_url.path or "/").rstrip("/") or "/"
        if path == "/" or _report_is_public_content_context_url(low_url) or _is_probably_static_asset_url(safe_url):
            continue
        identity = _url_identity(safe_url)
        if identity in seen_review_keys:
            continue
        seen_review_keys.add(identity)
        non_content_review_urls.append(safe_url)

    review_surface_classes: list[str] = []
    if admin_like_for_score or auth_like_for_score:
        review_surface_classes.append("admin/auth")
    if upload_like_for_score:
        review_surface_classes.append("upload/manual-review")
    if backup_manual_review_urls:
        review_surface_classes.append("backup/manual-review")
    if api_like_for_score or _report_has_strong_docs_signal(api_like_for_score, docs_like_for_score, tech_labels):
        review_surface_classes.append("api/docs/dev")
    if len(non_content_review_urls) >= 6:
        review_surface_classes.append("application-path-breadth")

    operator_review_breadth_points = 0
    if len(review_surface_classes) >= 3 and (
        len(non_content_review_urls) >= 4 or len(review_surface_classes) >= 4
    ):
        path_breadth_bonus = min(4, max(0, len(non_content_review_urls) - 4) // 3)
        operator_review_breadth_points = min(
            16,
            4 + len(review_surface_classes) * 3 + path_breadth_bonus,
        )
        if structural_exposure_count:
            operator_review_breadth_points = 0

    # --- Risk Score Engine ---
    risk_score = 0
    risk_reasons: list[str] = []

    def _add_risk(points: int, reason: str) -> None:
        nonlocal risk_score
        risk_score += points
        risk_reasons.append(f"+{points}: {reason}")

    if admin_like_for_score:
        _add_risk(min(20, len(admin_like_for_score) * 4), f"Admin panel yüzeyi ({len(admin_like_for_score)})")
    if auth_like_for_score:
        _add_risk(min(12, len(auth_like_for_score) * 3), f"Authentication endpoint’leri ({len(auth_like_for_score)})")
    if api_like_for_score:
        _add_risk(min(15, len(api_like_for_score) * 2), f"API / GraphQL / actuator yüzeyi ({len(api_like_for_score)})")
    if upload_like_for_score:
        upload_points = (
            min(18, len(upload_like_for_score) * 3)
            if upload_execution_evidence
            else min(8, len(upload_like_for_score) * 2)
        )
        _add_risk(
            upload_points,
            (
                f"Upload execution evidence surface ({len(upload_like_for_score)})"
                if upload_execution_evidence
                else f"Public upload/listing exposure signal ({len(upload_like_for_score)})"
            ),
        )
    if debug_like_for_score:
        _add_risk(min(20, len(debug_like_for_score) * 4), f"Debug / test exposure ({len(debug_like_for_score)})")
    if docs_like_for_score:
        docs_points = (
            min(12, len(docs_like_for_score) * 2)
            if _report_has_strong_docs_signal(api_like_for_score, docs_like_for_score, tech_labels)
            else min(5, len(docs_like_for_score))
        )
        _add_risk(docs_points, f"Public docs/help/resource surface ({len(docs_like_for_score)})")
    if operator_review_breadth_points:
        _add_risk(
            operator_review_breadth_points,
            (
                "Operator review surface breadth "
                f"({len(review_surface_classes)} classes: {', '.join(review_surface_classes)})"
            ),
        )
    if structural_exposure_count:
        structural_points = min(42, 14 + structural_exposure_count * 5 + len(structural_exposure_groups) * 3)
        structural_labels = ", ".join(sorted(structural_exposure_groups))
        _add_risk(
            structural_points,
            f"High-risk structural exposure signal ({structural_exposure_count}: {structural_labels})",
        )
    # Auth profiler (additive signal layer; does NOT replace endpoint-analysis surface scoring)
    auth_summary = auth_profile.get("auth_summary") if isinstance(auth_profile, dict) else {}
    auth_scoring_summary = auth_profile.get("auth_scoring_summary") if isinstance(auth_profile, dict) else {}
    if not isinstance(auth_summary, dict):
        auth_summary = {}
    if not isinstance(auth_scoring_summary, dict):
        auth_scoring_summary = {}

    canonical_login_flows = int(auth_scoring_summary.get("canonical_login_flows_count", 0) or 0)
    canonical_admin_auth_flows = int(auth_scoring_summary.get("canonical_admin_auth_flows_count", 0) or 0)
    canonical_reset_flows = int(auth_scoring_summary.get("canonical_reset_flows_count", 0) or 0)
    canonical_xmlrpc = int(auth_scoring_summary.get("canonical_xmlrpc_count", 0) or 0)
    canonical_oauth_sso = int(auth_scoring_summary.get("canonical_oauth_sso_count", 0) or 0)
    hardening_gap_families = int(auth_scoring_summary.get("hardening_gaps_on_real_login_flows_count", 0) or 0)

    # Canonical auth scoring: one bounded contribution per auth flow family type.
    if canonical_login_flows > 0:
        _add_risk(min(12, 6 + canonical_login_flows * 2), f"Kanonik auth login akışları ({canonical_login_flows})")
    if canonical_admin_auth_flows > 0:
        _add_risk(4, f"Admin → login redirect aileleri ({canonical_admin_auth_flows})")
    if canonical_reset_flows > 0:
        _add_risk(4, f"Password reset alt akışları ({canonical_reset_flows})")
    if canonical_xmlrpc > 0:
        _add_risk(5, f"XML-RPC auth channel aileleri ({canonical_xmlrpc})")
    if canonical_oauth_sso > 0:
        _add_risk(5, f"OAuth/SSO giriş aileleri ({canonical_oauth_sso})")
    if hardening_gap_families > 0 and canonical_login_flows > 0:
        _add_risk(
            min(8, 2 * hardening_gap_families),
            f"Gerçek login akışlarında auth hardening boşlukları ({hardening_gap_families})",
        )
    if any(t.lower() in {"graphql", "swagger ui", "redoc", "wordpress", "drupal", "joomla"} for t in tech_labels):
        _add_risk(6, "Teknoloji fingerprint exposed yüksek ilgi yüzeyini işaret ediyor")
    if any(t.lower() in {"php", "apache httpd"} for t in tech_labels):
        _add_risk(4, "Legacy/common web stack fingerprint (PHP/Apache)")
    if waf_detected_count > 0:
        _add_risk(min(8, waf_detected_count * 4), f"WAF/CDN signal present ({waf_detected_count})")
    ffuf_risk_bonus = int(ffuf_scoring.get("risk_bonus", 0) or 0)
    if ffuf_risk_bonus > 0:
        _add_risk(
            ffuf_risk_bonus,
            f"FFUF normalized signal (units={ffuf_effective_units}, overlap={ffuf_overlap_ratio:.2f})",
        )
    if nuclei_risk_points > 0:
        _add_risk(
            nuclei_risk_points,
            nuclei_risk_reason or f"Nuclei weighted signal ({nuclei_findings_count})",
        )
    if has_any_tier_failure:
        risk_reasons.append(
            f"confidence-warning: {coverage_status_detail}"
        )

    risk_score = max(0, min(100, risk_score))
    if risk_score >= 75:
        risk_band = "Critical"
    elif risk_score >= 55:
        risk_band = "High"
    elif risk_score >= 30:
        risk_band = "Medium"
    else:
        risk_band = "Low"

    if _mode_meta == "url":
        required_tier1_tools = ["katana"]
    elif _mode_meta == "ip":
        required_tier1_tools = ["httpx", "katana"]
    else:
        required_tier1_tools = ["subfinder", "httpx", "katana"]

    _tier1_success_statuses = {"done", "success", "completed"}
    _tier1_statuses = [
        str((stage_lookup.get(_tool) or {}).get("status") or "").strip().lower()
        for _tool in required_tier1_tools
    ]
    tier1_success_count = len([_st for _st in _tier1_statuses if _st in _tier1_success_statuses])
    tier1_empty_count = len([_st for _st in _tier1_statuses if _st == "empty"])
    discovery_surface_signal_count = (
        len(katana_representative_urls)
        + len(admin_like_for_score)
        + len(auth_like_for_score)
        + len(api_like_for_score)
        + len(upload_like_for_score)
        + len(debug_like_for_score)
        + len(docs_like_for_score)
        + len(source_control_like_for_score)
    )
    sparse_discovery_evidence = bool(
        discovery_reliability == "HIGH"
        and required_tier1_tools
        and tier1_success_count == 0
        and tier1_empty_count > 0
        and discovery_surface_signal_count == 0
    )
    partial_discovery_evidence = bool(
        discovery_reliability == "HIGH"
        and required_tier1_tools
        and tier1_empty_count > 0
        and tier1_success_count < len(required_tier1_tools)
        and discovery_surface_signal_count == 0
    )
    discovery_confidence_reason = ""
    if discovery_reliability in {"CRITICAL", "LOW"}:
        discovery_confidence_label = "Low"
    elif discovery_reliability == "MEDIUM":
        discovery_confidence_label = "Medium"
    elif sparse_discovery_evidence:
        discovery_confidence_label = "Low"
        discovery_confidence_reason = (
            "Tier-1 discovery produced empty coverage and no representative surface signals."
        )
    elif partial_discovery_evidence:
        discovery_confidence_label = "Medium"
        discovery_confidence_reason = (
            "Tier-1 discovery coverage is partially empty with no representative surface signals."
        )
    else:
        discovery_confidence_label = "High"

    nuclei_state_value_for_decision = str(nuclei_summary_data.get("state") or "unknown").strip().lower()
    nuclei_pending = bool(
        nuclei_state_value_for_decision in {"live", "running"}
        or nuclei_stage_status == "running"
        or run_state_value == "running"
    )
    nuclei_skipped = bool(
        nuclei_findings_count == 0
        and (
            nuclei_state_value_for_decision in {"skipped", "disabled"}
            or nuclei_stage_status in {"skipped", "disabled"}
            or "nuclei" in {str(name or "").strip().lower() for name in (skipped_tools or [])}
        )
    )
    structural_high_risk_evidence = structural_exposure_count > 0

    if high_severity_findings_count > 0:
        if low_trust_high_severity_count > 0:
            nuclei_confidence_label = "Low"
            nuclei_confidence_reason = (
                f"{low_trust_high_severity_count} high/critical bulgu low-trust olarak sınıflandı."
            )
        elif high_trust_high_severity_count > 0 and medium_trust_high_severity_count == 0:
            nuclei_confidence_label = "High"
            nuclei_confidence_reason = (
                f"{high_trust_high_severity_count} high/critical bulgu high-trust olarak sınıflandı."
            )
        else:
            nuclei_confidence_label = "Medium"
            nuclei_confidence_reason = (
                "High/critical bulgular var ancak trust karışık; exploitation öncesinde doğrula."
            )
    elif nuclei_findings_count == 0 and nuclei_pending:
        nuclei_confidence_label = "Medium"
        if structural_high_risk_evidence:
            nuclei_confidence_reason = (
                "Nuclei stage is still running; final Nuclei confidence is pending. "
                "Nuclei bulgusu henüz yok; ancak yapısal yüksek riskli exposure sinyalleri mevcut."
            )
        else:
            nuclei_confidence_reason = (
                "Nuclei stage is still running; final Nuclei confidence is pending."
            )
    elif nuclei_skipped:
        nuclei_confidence_label = "Low"
        nuclei_confidence_reason = "Nuclei çalıştırılmadı; bu run’da template tabanlı zafiyet kanıtı toplanmadı."
    elif nuclei_findings_count == 0 and structural_high_risk_evidence:
        nuclei_confidence_label = "Medium"
        nuclei_confidence_reason = (
            "Nuclei bulgusu yok; ancak yapısal yüksek riskli exposure sinyalleri mevcut."
        )
    elif nuclei_findings_count == 0:
        nuclei_confidence_label = "High"
        nuclei_confidence_reason = "Bulgu yok; confidence ağırlıklı olarak discovery güvenilirliğine bağlı."
    elif low_trust_findings_count > 0:
            nuclei_confidence_label = "Medium"
            nuclei_confidence_reason = (
            f"{low_trust_findings_count} low-trust bulgu decision certainty değerini düşürüyor."
        )
    elif medium_trust_findings_count > 0:
            nuclei_confidence_label = "Medium"
            nuclei_confidence_reason = (
            f"{medium_trust_findings_count} medium-trust bulgu doğrulama gerektiriyor."
        )
    else:
        nuclei_confidence_label = "High"
        nuclei_confidence_reason = (
            f"{high_trust_findings_count} bulgu high-trust olarak sınıflandı."
        )

    decision_confidence = _merge_confidence_labels(
        discovery_confidence_label,
        nuclei_confidence_label,
    )
    decision_confidence_tone = (
        "ok"
        if decision_confidence == "High"
        else ("warn" if decision_confidence == "Medium" else "bad")
    )
    discovery_confidence_prefix = (
        "Discovery kapsamı: sınırlı"
        if limited_surface_discovery
        else f"Discovery güvenilirliği ({discovery_reliability})"
    )
    if nuclei_skipped:
        decision_confidence_note = (
            f"{discovery_confidence_prefix} ve kapalı Nuclei kapsamı üzerinden türetildi. "
            f"{nuclei_confidence_reason}"
        )
    else:
        decision_confidence_note = (
            f"{discovery_confidence_prefix} ve Nuclei trust ({nuclei_confidence_label}) üzerinden türetildi. "
            f"{nuclei_confidence_reason}"
        )
    if limited_surface_discovery:
        decision_confidence_note += f" {discovery_scope_note}"
    if discovery_confidence_reason:
        decision_confidence_note += f" {discovery_confidence_reason}"
    if discovery_low_or_critical:
        decision_confidence_note += " Discovery kapsamı zayıfladı - bulgularla aksiyon almadan önce yüzeyi doğrula."
    if risk_band == "Critical" and nuclei_pending and structural_high_risk_evidence:
        decision_confidence_note += " Critical structural risk, pending Nuclei completion."

    recommendation_sources = [item for item in (exploit_suggestions or []) if isinstance(item, dict)]
    recommendation_sources.extend(_build_nuclei_validation_suggestions(nuclei_report_entries))
    context_aware_suggestions = _build_context_aware_suggestions(
        recommendation_sources,
        risk_score=risk_score,
        discovery_reliability=discovery_reliability,
        decision_confidence=decision_confidence,
        failed_tier_1=failed_tier_1,
        failed_tier_2=failed_tier_2,
        failed_tier_3=failed_tier_3,
    )
    context_aware_suggestions = _enrich_recommendation_references(
        context_aware_suggestions,
        candidate_validation=candidate_validation,
        report_base_url=report_base_url,
    )
    manual_nuclei_next_run = bool(
        nuclei_findings_count == 0
        or nuclei_state_value_for_decision in {"interrupted", "running", "live", "skipped", "disabled"}
        or nuclei_stage_status in {"interrupted", "running", "skipped", "disabled"}
    )
    coverage_confidence_caution = bool(
        run_state_value == "interrupted"
        or any(
            str((stages_ctx.get(tool) if isinstance(stages_ctx.get(tool), dict) else {}).get("status") or "").strip().lower()
            in {"interrupted", "error", "failed", "partial"}
            for tool in skipped_coverage_blockers
        )
    )
    confidence_display_labels = {"High": "yüksek", "Medium": "orta", "Low": "düşük"}
    decision_confidence_display = confidence_display_labels.get(decision_confidence, decision_confidence)
    decision_confidence_note_display = decision_confidence_note
    decision_confidence_tone_display = decision_confidence_tone
    if coverage_confidence_caution and decision_confidence == "High":
        decision_confidence_display = "sınırlı kapsam nedeniyle temkinli"
        decision_confidence_note_display = (
            f"Risk {risk_band.lower()}; karar güveni kapsam sınırlı olduğu için temkinli. "
            "Bu anlık görünüm tamamlanmış temiz scan değildir."
        )
        decision_confidence_tone_display = "warn"
        for _sug in context_aware_suggestions:
            if isinstance(_sug, dict):
                _sug["reasoning"] = str(_sug.get("reasoning") or "").replace(
                    "decision_confidence=High",
                    "decision_confidence=sınırlı kapsam nedeniyle temkinli",
                )
                if str(_sug.get("uncertainty_note") or "").strip() == "":
                    _sug["uncertainty_note"] = "Kapsam sınırlı olduğu için öneri manuel doğrulama planı olarak ele alınmalıdır."

    # Keep node relationship suggestions consistent with decision-safe suggestion layer.
    node_relationships = _normalize_node_relationships_for_report(
        node_relationships,
        discovery_reliability=discovery_reliability,
        decision_confidence=decision_confidence,
        failed_tier_1=failed_tier_1,
    )
    graph_scope_id = report_scope_seed
    graph_payload = build_graph_report_payload(
        attack_graph,
        node_relationships,
        scope_id=graph_scope_id,
    )
    if isinstance(graph_payload, dict):
        for _path in graph_payload.get("paths", []) if isinstance(graph_payload.get("paths"), list) else []:
            if not isinstance(_path, dict):
                continue
            _path["name"] = str(_path.get("name") or "").replace("Upload → Possible RCE", "Upload → RCE Validation Candidate")
            if isinstance(_path.get("sequence"), list):
                _path["sequence"] = [
                    "RCE Validation Candidate" if str(item or "") == "Possible RCE" else item
                    for item in _path.get("sequence", [])
                ]
            _path["selection_reason"] = _operator_text_to_english(_path.get("selection_reason") or "")
            _path["why"] = _operator_text_to_english(_path.get("why") or "")
            if nuclei_pending and not bool(_path.get("evidence_supported", False)):
                pending_note = "Nuclei still running; no direct Nuclei evidence yet; manual validation required."
                _path["selection_reason"] = f"{_path.get('selection_reason') or ''} {pending_note}".strip()
                _path["why"] = f"{_path.get('why') or ''} {pending_note}".strip()
            _path_text = " ".join(
                str(_path.get(key) or "")
                for key in ("name", "selection_reason", "why")
            ).lower()
            if "upload" in _path_text and ("rce" in _path_text or "executable" in _path_text):
                upload_note = "Upload yüzeyi bulundu; zafiyet kanıtı değildir, manuel doğrulama gerektirir."
                if upload_note.lower() not in _path["selection_reason"].lower():
                    _path["selection_reason"] = f"{_path.get('selection_reason') or ''} {upload_note}".strip()
                if upload_note.lower() not in _path["why"].lower():
                    _path["why"] = f"{_path.get('why') or ''} {upload_note}".strip()
        for _edge in graph_payload.get("edges", []) if isinstance(graph_payload.get("edges"), list) else []:
            if not isinstance(_edge, dict):
                continue
            _edge["reason"] = _operator_text_to_english(_edge.get("reason") or "")
        for _node in graph_payload.get("nodes", []) if isinstance(graph_payload.get("nodes"), list) else []:
            if not isinstance(_node, dict):
                continue
            if str(_node.get("label") or "") == "Possible RCE":
                _node["label"] = "RCE Validation Candidate"
            _normalized_related_suggestions: list[dict[str, Any]] = []
            for _sug in _node.get("related_suggestions", []) if isinstance(_node.get("related_suggestions"), list) else []:
                if not isinstance(_sug, dict):
                    continue
                _sug_copy = dict(_sug)
                _sug_copy["title"] = _normalize_related_suggestion_title(
                    _operator_text_to_english(_sug_copy.get("title") or "-"),
                    low_visibility=bool(discovery_low_or_critical or decision_confidence == "Low"),
                ).replace("Validateation", "Validation")
                _normalized_related_suggestions.append(_sug_copy)
            _node["related_suggestions"] = _normalized_related_suggestions
        _meta = graph_payload.get("meta", {})
        if isinstance(_meta, dict):
            _meta["best_path_reason"] = _operator_text_to_english(_meta.get("best_path_reason") or "")
            _paths_for_meta = graph_payload.get("paths", []) if isinstance(graph_payload.get("paths"), list) else []
            if _paths_for_meta and isinstance(_paths_for_meta[0], dict):
                _meta["best_path_reason"] = str(_paths_for_meta[0].get("selection_reason") or _paths_for_meta[0].get("why") or _meta.get("best_path_reason") or "")
            graph_payload["meta"] = _meta

    graph_payload_json = serialize_json_for_script_tag(graph_payload)
    graph_payload_meta = graph_payload.get("meta", {}) if isinstance(graph_payload, dict) else {}
    graph_payload_paths = (
        graph_payload.get("paths", [])
        if isinstance(graph_payload.get("paths"), list)
        else []
    )

    # --- Attack Priority Engine ---
    priority_items: list[dict[str, Any]] = []

    def _add_priority(
        label: str,
        count: int,
        priority_score: int,
        why: str,
        test_first: str,
        *,
        signals: list[str] | None = None,
        urls: list[str] | None = None,
        evidence_refs: list[dict[str, Any]] | None = None,
        artifact_refs: list[str] | None = None,
        validation_state: str = "needs_manual_validation",
    ) -> None:
        if count <= 0:
            return
        priority_items.append(
            {
                "label": label,
                "count": count,
                "priority_score": priority_score,
                "why": why,
                "test_first": test_first,
                "signals": signals or [],
                "urls": urls or [],
                "evidence_refs": evidence_refs or [],
                "artifact_refs": artifact_refs or [],
                "validation_state": validation_state,
            }
        )

    has_php_apache = any(t.lower() in {"php", "apache httpd"} for t in tech_labels)
    has_graphql = any(t.lower() == "graphql" for t in tech_labels)
    has_swagger = any(("swagger" in t.lower()) or ("redoc" in t.lower()) for t in tech_labels)

    upload_priority = 95 if (upload_execution_evidence and has_php_apache) else (82 if upload_execution_evidence else 58)
    debug_priority = 90
    admin_priority = 86
    api_priority = 80 if has_graphql else 72
    docs_priority = 70 if has_swagger else (52 if _report_has_strong_docs_signal(api_like_for_score, docs_like_for_score, tech_labels) else 38)
    auth_priority = 67
    nuclei_priority = 99 if nuclei_findings_count > 0 else 0
    nuclei_priority_urls = []
    nuclei_priority_templates = []
    for _nuc_entry in nuclei_report_entries:
        if not isinstance(_nuc_entry, dict):
            continue
        _nuc_url = str(_nuc_entry.get("endpoint") or "").strip()
        if _nuc_url and _nuc_url.lower() != "unknown" and _nuc_url not in nuclei_priority_urls:
            nuclei_priority_urls.append(_nuc_url)
        _nuc_template = str(_nuc_entry.get("template_id") or "").strip()
        if _nuc_template and _nuc_template != "Unknown" and _nuc_template not in nuclei_priority_templates:
            nuclei_priority_templates.append(_nuc_template)

    _add_priority(
        "Nuclei Bulguları",
        nuclei_findings_count,
        nuclei_priority,
        _txt("priority_nuclei_why"),
        _txt("priority_nuclei_test"),
        signals=[f"nuclei_findings={nuclei_findings_count}", "fixed → 99"],
        urls=nuclei_priority_urls[:10],
        evidence_refs=[
            {"source": "nuclei", "template_id": item, "status": "needs_manual_validation"}
            for item in nuclei_priority_templates[:10]
        ],
        artifact_refs=[f"nuclei_template:{item}" for item in nuclei_priority_templates[:10]],
        validation_state="needs_manual_validation",
    )
    for nuclei_item in nuclei_priority_items:
        if not isinstance(nuclei_item, dict):
            continue
        _add_priority(
            str(nuclei_item.get("label") or "Nuclei Yüzeyi"),
            int(nuclei_item.get("count", 0) or 0),
            int(nuclei_item.get("priority_score", 0) or 0),
            str(nuclei_item.get("why") or _txt("priority_nuclei_surface_fallback")),
            str(nuclei_item.get("test_first") or _txt("priority_nuclei_test_fallback")),
            signals=nuclei_item.get("signals") if isinstance(nuclei_item.get("signals"), list) else [],
            urls=nuclei_priority_urls[:10],
            evidence_refs=[
                {"source": "nuclei", "template_id": item, "status": "needs_manual_validation"}
                for item in nuclei_priority_templates[:10]
            ],
            artifact_refs=[f"nuclei_template:{item}" for item in nuclei_priority_templates[:10]],
            validation_state="needs_manual_validation",
        )
    ffuf_priority_count = int(ffuf_scoring.get("priority_count", 0) or 0)
    ffuf_priority = int(ffuf_scoring.get("priority_score", 0) or 0)
    _add_priority(
        "FFUF Benzersiz Keşifleri",
        ffuf_priority_count,
        ffuf_priority,
        str(ffuf_scoring.get("why") or _txt("priority_ffuf_why_fallback")),
        str(ffuf_scoring.get("test_first") or _txt("priority_ffuf_test_fallback")),
        signals=ffuf_scoring.get("signals") if isinstance(ffuf_scoring.get("signals"), list) else [],
    )
    _add_priority(
        "Upload yüzeyi bulundu; zafiyet kanıtı değildir, manuel doğrulama gerektirir.",
        len(upload_like_for_score),
        upload_priority,
        (
            _txt("priority_upload_why")
            if upload_execution_evidence
            else "Upload yüzeyi bulundu; zafiyet kanıtı değildir, manuel doğrulama gerektirir."
        ),
        (
            _txt("priority_upload_test")
            if upload_execution_evidence
            else "Checklist: auth gereksinimi, kabul edilen dosya tipleri, dış erişim, server-side execution ve guessable storage path durumunu doğrula"
        ),
        signals=[
            f"upload_endpoints={len(upload_like_for_score)}",
            f"execution_evidence={'yes' if upload_execution_evidence else 'no'}",
            f"php_apache={'yes → 95' if has_php_apache and upload_execution_evidence else ('no → 82' if upload_execution_evidence else 'not-used → 58')}",
        ],
        urls=upload_like_for_score[:10],
        evidence_refs=[{"source": "classified_endpoints", "category": "upload", "status": "confirmed" if upload_like_for_score else "needs_manual_validation"}],
        validation_state="confirmed" if upload_like_for_score else "needs_manual_validation",
    )
    _add_priority(
        "Debug / Test Endpoint’leri",
        len(debug_like_for_score),
        debug_priority,
        _txt("priority_debug_why"),
        _txt("priority_debug_test"),
        signals=[f"debug_endpoints={len(debug_like_for_score)}", "fixed → 90"],
        urls=debug_like_for_score[:10],
        evidence_refs=[{"source": "classified_endpoints", "category": "debug/test", "status": "confirmed"}],
        validation_state="confirmed",
    )
    _add_priority(
        "Admin Panelleri",
        len(admin_like_for_score),
        admin_priority,
        _txt("priority_admin_why"),
        _txt("priority_admin_test"),
        signals=[f"admin_panels={len(admin_like_for_score)}", "fixed → 86"],
        urls=admin_like_for_score[:10],
        evidence_refs=[{"source": "classified_endpoints", "category": "admin", "status": "confirmed"}],
        validation_state="confirmed",
    )
    _add_priority(
        "API / GraphQL / Actuator",
        len(api_like_for_score),
        api_priority,
        _txt("priority_api_why"),
        _txt("priority_api_test"),
        signals=[
            f"api_endpoints={len(api_like_for_score)}",
            f"graphql={'yes → 80' if has_graphql else 'no → 72'}",
        ],
        urls=api_like_for_score[:10],
        evidence_refs=[{"source": "classified_endpoints", "category": "api", "status": "confirmed"}],
        validation_state="confirmed",
    )
    _add_priority(
        "Dokümantasyon / Dev Sayfaları",
        len(docs_like_for_score),
        docs_priority,
        (
            _txt("priority_docs_why")
            if docs_priority >= 52
            else "Public docs/help/resource surface normal içerik olabilir; attack path değildir."
        ),
        (
            _txt("priority_docs_test")
            if docs_priority >= 52
            else "Public documentation surface için manuel içerik incelemesi yap"
        ),
        signals=[
            f"docs_pages={len(docs_like_for_score)}",
            f"swagger_redoc={'yes → 70' if has_swagger else 'no'}",
            f"strong_docs_signal={'yes → 52' if docs_priority == 52 else ('yes' if docs_priority >= 52 else 'no → 38')}",
        ],
        urls=docs_like_for_score[:10],
        evidence_refs=[{"source": "classified_endpoints", "category": "docs/dev", "status": "confirmed"}],
        validation_state="confirmed" if docs_priority >= 52 else "needs_manual_validation",
    )
    structural_priority_labels = {
        "source_control": ("Source Control Exposure Signal", 96, "Repository metadata exposure detected; code/secret leakage requires manual validation.", "Confirm repository metadata exposure, block public .git access, and check leaked remotes/config/history"),
        "config": ("Config/Env Exposure Signal", 94, "Secret/config exposure pattern detected; manual validation required.", "Response body, auth requirement ve demo/fake marker durumunu doğrula"),
        "backup": ("Backup/Dump Exposure Signal", 92, "Backup/dump exposure signal detected; manual validation required.", "Dump/backup preview kapsamını ve auth gereksinimini doğrula"),
        "debug_console": ("Debug Console Exposure Signal", 91, "Debug console exposure signal detected; manual validation required.", "Debug route response body ve internal route/config kapsamını doğrula"),
        "logs": ("Logs/Error Exposure Signal", 89, "Public logs/error exposure signal detected; manual validation required.", "Log içeriğinde token, path, stack trace ve internal host bilgisini doğrula"),
        "internal_api": ("Internal API Exposure Signal", 90, "Internal users/status/build/version API signal detected; manual validation required.", "Internal API yanıtını, auth gereksinimini ve veri kapsamını doğrula"),
        "admin_export": ("Admin Export Exposure Signal", 88, "Admin export/download surface signal detected; manual validation required.", "Export endpoint erişilebilirliğini ve veri kapsamını doğrula"),
        "runtime": ("Runtime Disclosure Signal", 84, "Runtime/phpinfo/server-status disclosure signal detected; manual validation required.", "Runtime disclosure içeriğini ve auth gereksinimini doğrula"),
    }
    for _struct_key, _struct_urls in structural_exposure_groups.items():
        _label, _score, _why, _test = structural_priority_labels.get(
            _struct_key,
            ("Structural Exposure Signal", 84, "High-risk exposure signal detected; manual validation required.", "Manual validation required"),
        )
        _add_priority(
            _label,
            len(_struct_urls),
            _score,
            _why,
            _test,
            signals=[f"{_struct_key}_endpoints={len(_struct_urls)}", "structural exposure signal", f"fixed → {_score}"],
            urls=_struct_urls[:10],
            evidence_refs=[{"source": "structural_exposure_groups", "category": _struct_key, "status": "confirmed"}],
            validation_state="confirmed",
        )
    canonical_login_flows = int(auth_scoring_summary.get("canonical_login_flows_count", 0) or 0)
    canonical_admin_auth_flows = int(auth_scoring_summary.get("canonical_admin_auth_flows_count", 0) or 0)
    canonical_xmlrpc = int(auth_scoring_summary.get("canonical_xmlrpc_count", 0) or 0)
    canonical_oauth_sso = int(auth_scoring_summary.get("canonical_oauth_sso_count", 0) or 0)

    auth_family_count = (
        canonical_login_flows
        + canonical_admin_auth_flows
        + canonical_xmlrpc
        + canonical_oauth_sso
    )
    clean_single_login_review = bool(
        risk_score < 10
        and len(auth_like_for_score) == 1
        and not admin_like_for_score
        and nuclei_findings_count == 0
        and canonical_login_flows <= 1
        and canonical_admin_auth_flows == 0
        and canonical_reset_flows == 0
        and canonical_xmlrpc == 0
        and canonical_oauth_sso == 0
        and hardening_gap_families == 0
        and not rate_signals
        and not captcha_pages
    )
    if clean_single_login_review:
        auth_priority = 45
    _add_priority(
        "Authentication Endpoint’leri",
        auth_family_count,
        auth_priority,
        (
            "Normal login surface; access-control hardening review only."
            if clean_single_login_review
            else _txt("priority_auth_why")
        ),
        (
            "Normal login akışında temel hardening ve access-control kontrollerini düşük öncelikle doğrula"
            if clean_single_login_review
            else _txt("priority_auth_test")
        ),
        signals=[
            f"canonical_login_flows={canonical_login_flows}",
            f"canonical_admin_auth_flows={canonical_admin_auth_flows}",
            f"canonical_xmlrpc={canonical_xmlrpc}",
            f"canonical_oauth_sso={canonical_oauth_sso}",
            "clean_single_login → 45" if clean_single_login_review else "fixed → 67",
        ],
        urls=(auth_like_for_score[:6] + admin_like_for_score[:6])[:10],
        evidence_refs=[{"source": "auth_profile / classified_endpoints", "category": "auth", "status": "confirmed"}],
        validation_state="confirmed" if (auth_like_for_score or admin_like_for_score) else "needs_manual_validation",
    )

    priority_items = sorted(
        priority_items,
        key=lambda item: (int(item.get("priority_score", 0)), int(item.get("count", 0))),
        reverse=True,
    )
    
    top_surface_label = priority_items[0]["label"] if priority_items else "-"
    top_surface_score = int(priority_items[0].get("priority_score", 0)) if priority_items else 0
    top_surface_why = str(priority_items[0].get("why", "") or "") if priority_items else ""

    top_chain_label = "-"
    top_chain_confidence = 0
    top_chain_reason = ""
    top_chain_next_test = ""
    top_path_evidence_supported = bool(graph_payload_meta.get("best_path_evidence_supported", False))
    if graph_payload_paths:
        top_path = graph_payload_paths[0] if isinstance(graph_payload_paths[0], dict) else {}
        top_chain_label = " → ".join(top_path.get("sequence", []) or []) or str(top_path.get("id") or "-")
        top_chain_confidence = int(
            graph_payload_meta.get(
                "best_confidence",
                top_path.get("confidence", 0),
            )
            or 0
        )
        top_chain_reason = str(
            graph_payload_meta.get("best_path_reason")
            or top_path.get("selection_reason")
            or top_path.get("why")
            or ""
        )
    elif isinstance(attack_chains, list) and attack_chains:
        best_chain = sorted(
            [item for item in attack_chains if isinstance(item, dict)],
            key=lambda item: int(item.get("confidence", 0) or 0),
            reverse=True,
        )
        if best_chain:
            top_chain_label = str(best_chain[0].get("name") or best_chain[0].get("chain") or "-")
            top_chain_confidence = int(best_chain[0].get("confidence", 0) or 0)
            top_chain_reason = str(best_chain[0].get("selection_reason") or best_chain[0].get("why") or "")
    if isinstance(attack_chains, list):
        for _chain_item in attack_chains:
            if not isinstance(_chain_item, dict):
                continue
            _name = str(_chain_item.get("name") or _chain_item.get("chain") or "").strip()
            if _name and top_chain_label and _name.lower() in top_chain_label.lower():
                _next_tests = _chain_item.get("next_tests", [])
                if isinstance(_next_tests, list):
                    for _test in _next_tests:
                        _test_text = str(_test or "").strip()
                        if _test_text:
                            top_chain_next_test = _test_text
                            break
                if top_chain_next_test:
                    break
    if not top_chain_next_test and isinstance(attack_chains, list):
        _ranked_chains = sorted(
            [item for item in attack_chains if isinstance(item, dict)],
            key=lambda item: (
                int(item.get("rank_score", item.get("confidence", 0)) or 0),
                int(item.get("confidence", 0) or 0),
            ),
            reverse=True,
        )
        for _chain_item in _ranked_chains:
            _next_tests = _chain_item.get("next_tests", [])
            if not isinstance(_next_tests, list):
                continue
            _first_chain_test = str(_next_tests[0] or "").strip() if _next_tests else ""
            if _first_chain_test:
                top_chain_next_test = _first_chain_test
                break

    if discovery_low_or_critical:
        _decision_warning = "Discovery kapsamı zayıfladı - bulgularla aksiyon almadan önce yüzeyi doğrula."
        if _decision_warning.lower() not in top_chain_reason.lower():
            top_chain_reason = f"{_decision_warning} {top_chain_reason}".strip()

    default_first_test_text = priority_items[0]["test_first"] if priority_items else ""
    surface_validation_action = "Bulgularla aksiyon almadan önce attack surface kapsamını doğrula (katana/httpx)"
    exploit_first_allowed = bool(discovery_reliability == "HIGH" and high_trust_high_severity_count > 0)

    if discovery_reliability != "HIGH":
        first_test_text = surface_validation_action
        first_action_why = "Discovery kapsamı zayıfladı - bulgularla aksiyon almadan önce yüzeyi doğrula."
    elif exploit_first_allowed:
        first_test_text = top_chain_next_test or default_first_test_text or "Kontrollü exploit path çalıştır"
        first_action_why = (
            top_chain_reason
            if top_chain_reason
            else (
                "Discovery kapsamı sağlıklıyken high/critical bulgular yüksek güvenlidir; "
                "exploit odaklı ilk aksiyon kabul edilebilir."
            )
        )
    elif high_severity_findings_count > 0:
        first_test_text = "Exploit öncesinde high-severity bulguyu doğrula"
        first_action_why = (
            "High/critical bulgular var ancak güven exploit-first önceliklendirme için yeterli değil. "
            "Exploit öncesinde bulguyu doğrula."
        )
    else:
        if default_first_test_text or top_surface_why:
            first_test_text = default_first_test_text or "Kapsamı ve doğrulanmış yüzeyleri manuel gözden geçir"
            first_action_why = (
                top_surface_why
                if top_surface_why
                else "Yüksek güvenli exploit kanıtı sınırlı olduğu için doğrulama odaklı ilk aksiyon seçildi."
            )
        else:
            first_test_text = "Bu sınırlı run’da doğrulanabilir yüksek öncelikli yüzey oluşmadı. Kapsam izin veriyorsa kapalı araçları açarak yeniden çalıştır."
            first_action_why = (
                "Bu run’da doğrulanabilir yüksek öncelikli yüzey oluşmadı. "
                "Araç kapsamı sınırlıysa kapalı araçları açarak yeniden çalıştır."
            )
    first_test_text = _operator_text_to_english(first_test_text)
    first_action_why = _operator_text_to_english(first_action_why)
    skipped_count = len([name for name in (skipped_tools or []) if str(name or "").strip()])
    failed_stages = [
        name
        for name, stage in stages_ctx.items()
        if isinstance(stage, dict)
        and str(stage.get("status") or "").strip().lower() in {"error", "failed", "partial", "interrupted"}
    ]
    empty_done_stages: list[str] = []
    katana_stage = stages_ctx.get("katana") if isinstance(stages_ctx.get("katana"), dict) else {}
    if (
        str(katana_stage.get("status") or "").strip().lower() in {"done", "success", "completed"}
        and not (katana_urls or [])
    ):
        empty_done_stages.append("katana")
    result_done_stages: list[str] = []
    if (
        str(katana_stage.get("status") or "").strip().lower() in {"done", "success", "completed"}
        and (katana_urls or [])
    ):
        result_done_stages.append("katana")
    pipeline_stage_count = len(stages_ctx) if isinstance(stages_ctx, dict) else 0
    nuclei_state_value = str(nuclei_summary_data.get("state") or "unknown").strip().lower()
    nuclei_live_count = int(nuclei_summary_data.get("total_findings", nuclei_findings_count) or nuclei_findings_count)
    nuclei_pending_live = bool(
        nuclei_state_value in {"live", "running"}
        or nuclei_stage_status == "running"
        or run_state_value == "running"
    )
    if nuclei_pending_live and structural_high_risk_evidence and nuclei_findings_count == 0:
        live_findings_status = "Nuclei beklemede; yapısal exposure yüksek"
        live_findings_note = (
            "Nuclei bulgusu henüz yok; ancak yapısal yüksek riskli exposure sinyalleri mevcut. "
            "Nuclei stage is still running; final Nuclei confidence is pending."
        )
    elif nuclei_state_value in {"live", "running"}:
        live_findings_status = f"Canlı snapshot ({nuclei_live_count} bulgu)"
        live_findings_note = "Çalıştırma hâlâ aktif; bulguları yön gösterici kanıt olarak kullan ve final snapshot sonrası yeniden teyit et."
    elif nuclei_state_value == "interrupted":
        live_findings_status = f"Kesilmiş snapshot ({nuclei_live_count} bulgu)"
        live_findings_note = "Çalıştırma kesildi; görünür critical/high bulguları önceliklendir ama kapsamanın kısmi olmasını bekle."
    elif nuclei_skipped:
        live_findings_status = "Nuclei çalıştırılmadı"
        live_findings_note = "Nuclei çalıştırılmadı; bu run’da template tabanlı zafiyet kanıtı toplanmadı."
    elif nuclei_live_count > 0:
        live_findings_status = f"Kanıt mevcut ({nuclei_live_count} bulgu)"
        live_findings_note = "Bulgular strongest-path ve first-action önceliklendirmesine dahil edildi."
    else:
        live_findings_status = "Henüz bulgu yok"
        live_findings_note = "Şu anda chain confidence değerini artıran Nuclei kanıtı yok; çıkarılan yüzey önceliklerine dayan."

    if low_conf_high_severity_count > 0:
        live_findings_status = f"High severity mevcut, low confidence ({low_conf_high_severity_count})"
        live_findings_note = (
            "High severity bulgu tespit edildi ancak eksik discovery kapsamı nedeniyle confidence düşük "
            f"({coverage_status_label.lower()}). Discovery boşlukları giderilene kadar doğrulanmamış kabul et."
        )
    elif medium_conf_high_severity_count > 0:
        live_findings_status = f"High severity mevcut, medium confidence ({medium_conf_high_severity_count})"
        live_findings_note = (
            "Kısmi discovery/enrichment zayıflaması altında high severity bulgu var. "
            "Araç kapsamını toparladıktan sonra doğrulamayı önceliklendir."
        )
    elif (
        nuclei_findings_count == 0
        and not has_any_tier_failure
        and not structural_high_risk_evidence
        and not nuclei_pending_live
        and not nuclei_skipped
        and skipped_count == 0
        and risk_score < 55
    ):
        live_findings_status = "Çalıştırılan kontrollerde bulgu yok"
        live_findings_note = (
            "Nuclei eşleşmesi ve öncelikli yapısal kanıt bulunmadı. "
            "Bu sonuç hedefte hiçbir zafiyet olmadığı anlamına gelmez."
        )
    elif (
        nuclei_findings_count == 0
        and not has_any_tier_failure
        and not structural_high_risk_evidence
        and not nuclei_pending_live
        and not nuclei_skipped
        and skipped_count > 0
        and risk_score < 55
    ):
        live_findings_status = "Seçilen kontrollerde bulgu yok"
        live_findings_note = "Seçilen araçlar tamamlandı. Kapalı araçlar hata değildir; sonuç yalnız çalıştırılan kontrolleri kapsar."
    elif nuclei_findings_count == 0 and structural_high_risk_evidence and not nuclei_pending_live and not nuclei_skipped:
        live_findings_status = "Nuclei bulgusu yok; yapısal exposure mevcut"
        live_findings_note = (
            "No direct Nuclei evidence yet; structural exposure evidence is high. "
            "Manual validation required before exploitability claims."
        )
    elif nuclei_findings_count == 0 and has_any_tier_failure and not nuclei_skipped:
        live_findings_status = "Bulgu yok, low confidence"
        live_findings_note = (
            "Nuclei bulgusu yok ancak discovery/enrichment kapsamı zayıf; "
            "bunu low-confidence absence of evidence olarak değerlendir."
        )
    if run_state_value == "interrupted":
        if nuclei_findings_count == 0:
            if structural_high_risk_evidence:
                live_findings_status = "Nuclei/direct exploit bulgusu yok; yapısal yüzey sinyalleri ayrıca listelenmiştir."
            else:
                live_findings_status = "Doğrulanmış bulgu yok; çalışma kesildiyse bu temiz scan anlamına gelmez."
            live_findings_note = "Çalıştırma kesildiği için kapsama eksik; bunu tamamlanmış temiz scan olarak değerlendirme."
        else:
            live_findings_note = (
                f"{live_findings_note} Çalıştırma kesildiği için kapsama eksik; görünür bulguları tam rerun ile doğrula."
            )
    if run_state_value == "interrupted":
        run_stability_label = "Kesilmiş anlık görünüm - kapsam sınırlı"
    elif run_state_value == "incomplete":
        run_stability_label = "Kısmi rapor - başarısız aşamalar nedeniyle kapsam eksik"
    elif run_state_value in {"completed", "failed"}:
        run_stability_label = "Final rapor görünümü"
    else:
        run_stability_label = "Canlı anlık görünüm"
    coverage_parts: list[str] = []
    if failed_stages:
        coverage_parts.append(
            f"{len(failed_stages)} başarısız/timeout stage: {_truncate_text(', '.join(sorted(failed_stages)), 48)}."
        )
    if empty_done_stages:
        coverage_parts.append(f"Çalıştı ve bulgu üretmedi: {_truncate_text(', '.join(empty_done_stages), 48)}.")
    if result_done_stages:
        coverage_parts.append(f"Sonuçla çalıştı: {_truncate_text(', '.join(result_done_stages), 48)}.")
    if skipped_count > 0:
        coverage_parts.append("Kapalı veya hedefe uygulanmayan araçlar hata değildir.")
        coverage_parts.append(f"Seçilen kapsam dışında: {_truncate_text(skipped_html, 72)} (hata değildir).")
        if nuclei_findings_count == 0:
            coverage_parts.append("Sonuçlar çalıştırılan kontroller için geçerlidir; tüm olası zafiyetlerin yokluğunu kanıtlamaz.")
        if "nuclei" in skipped_tool_names:
            coverage_parts.append("Nuclei çalıştırılmadı; bu run’da template tabanlı zafiyet kanıtı toplanmadı.")
        if "screenshots" in skipped_tool_names:
            coverage_parts.append("Screenshots kapalı; görsel kanıt toplanmadı.")
    if limited_surface_discovery:
        coverage_parts.append(discovery_scope_note)
    coverage_note = " ".join(coverage_parts) if coverage_parts else "Yapılandırılmış core araçlar için kapsama tamamlandı."
    if has_any_tier_failure:
        coverage_note = (
            f"{coverage_status_detail} "
            f"{coverage_note}"
        )
    coverage_note = f"{run_stability_label}. {coverage_note}"

    operator_warning_html = ""
    if discovery_reliability != "HIGH":
        if failed_tier_1:
            failed_focus = failed_tier_1_text
            degraded_scope_line = (
                _txt("operator_warning_discovery_failures", failed_focus=failed_focus)
            )
        elif failed_tier_2:
            failed_focus = failed_tier_2_text
            degraded_scope_line = (
                _txt("operator_warning_enrichment_failures", failed_focus=failed_focus)
            )
        else:
            failed_focus = failed_tier_3_text or _txt("operator_warning_pipeline_fallback")
            degraded_scope_line = (
                _txt("operator_warning_pipeline_failures", failed_focus=failed_focus)
            )
        operator_warning_html = (
            f'<div class="risk-note"><strong>{_html_escape(_txt("operator_warning_strong"))}</strong> '
            f'{_html_escape(degraded_scope_line)} '
            f'{_html_escape(_txt("operator_warning_tail"))}</div>'
        )

    coverage_degraded_warning_html = ""
    if has_any_tier_failure:
        coverage_degraded_warning_html = (
            f'<p class="risk-note"><strong>{_html_escape(coverage_status_detail)}</strong> '
            f'{_html_escape(_truncate_text(failure_details_preview or "error/timeout", 220))}</p>'
        )
    if run_state_value == "interrupted":
        coverage_degraded_warning_html += (
            '<p class="risk-note"><strong>Kesilmiş çalışma:</strong> Kapsama eksik; '
            'görünmeyen bulguları yalnızca bu anlık çalıştırmanın sonucu olarak değerlendir ve temiz scan kararı vermeden önce yeniden çalıştır.</p>'
        )
    discovery_pipeline_details_html = ""
    if depth_config.show_full_pipeline_details:
        discovery_pipeline_details_html = f"""
      <details class="show-more">
        <summary style="font-size:15px; font-weight:600; color:var(--accent2);">{_html_escape(_txt("discovery_pipeline_summary"))}</summary>
        <p class="note" style="margin:8px 0;">{_txt("pipeline_stage_note")}</p>
        <table>
            <tr>
                <th>Aşama</th>
                <th>Durum</th>
                <th>Başlangıç</th>
                <th>Bitiş</th>
                <th>Artifact’lar</th>
            </tr>
            {stage_rows_html}
        </table>
      </details>
      <details class="show-more" style="margin-top:8px;">
        <summary style="font-size:15px; font-weight:600; color:var(--accent2);">{_html_escape(_txt("discovery_nmap_summary"))}</summary>
        <pre style="background:#161b22;padding:12px;overflow:auto;font-size:12px;margin-top:8px;">
{nmap_output if (nmap_output or "").strip() else _txt("discovery_nmap_empty")}
        </pre>
      </details>
        """
    else:
        discovery_pipeline_details_html = (
            '<p class="note">Özet mod pipeline çıktısını kısa tutar. '
            'Tam stage artifact’ları ve ham Nmap çıktısı için dengeli veya derin rapor derinliğini kullan.</p>'
        )
    graph_ui_styles = graph_ui_css()
    graph_library_script = graph_library_script_tag(report_dir)
    report_style_block = render_report_style_block(graph_ui_styles)
    screenshots_payload = checks_results.get("screenshots") if isinstance(checks_results.get("screenshots"), dict) else {}
    screenshot_entries = screenshots_payload.get("entries") if isinstance(screenshots_payload.get("entries"), list) else []
    screenshot_count = len(
        [
            item
            for item in screenshot_entries
            if isinstance(item, dict) and str(item.get("screenshot_path") or "").strip()
        ]
    )
    operator_plan_actions = _build_operator_plan_actions(
        first_test_text=first_test_text,
        first_action_why=first_action_why,
        top_chain_label=top_chain_label,
        top_chain_reason=top_chain_reason,
        top_chain_confidence=top_chain_confidence,
        correlation_insights=correlation_insights,
        nuclei_report_entries=nuclei_report_entries,
        admin_like=admin_like_for_score,
        auth_like=auth_like_for_score,
        waf_detected_count=waf_detected_count,
        screenshot_count=screenshot_count,
        screenshot_entries=screenshot_entries,
        run_state_value=run_state_value,
        coverage_note=coverage_note,
        report_base_url=report_base_url,
    )
    operator_plan_html = _render_operator_plan_section(operator_plan_actions)
    run_quality_model = _build_run_quality_model(
        run_state_value=run_state_value,
        run_stability_label=run_stability_label,
        coverage_status_label=coverage_status_label,
        coverage_note=coverage_note,
        discovery_reliability=discovery_reliability,
        discovery_scope_label=discovery_scope_label,
        tool_coverage_label=tool_coverage_label,
        working_core_tools=working_core_tools,
        closed_surface_discovery_tools=closed_surface_discovery_tools,
        decision_confidence=decision_confidence,
        decision_confidence_display=decision_confidence_display,
        has_any_tier_failure=has_any_tier_failure,
        failed_stages=failed_stages,
        skipped_tools=skipped_tools,
        stages_ctx=stages_ctx,
        nmap_output=nmap_output,
        katana_representative_urls=katana_representative_urls,
        gobuster_results=gobuster_results,
        ffuf_findings_by_base=ffuf_findings_by_base,
        nuclei_findings_count=nuclei_findings_count,
        waf_detected_count=waf_detected_count,
        waf_signals=waf_signals,
        whatweb_detected_count=whatweb_detected_count,
        whatweb_signals=whatweb_signals,
        screenshot_count=screenshot_count,
        checks_results=checks_results,
    )
    run_quality_html = _render_run_quality_section(run_quality_model)
    command_profile = "-"
    if traffic_context:
        command_profile = str(
            traffic_context.get("effective_profile")
            or traffic_context.get("requested_profile")
            or "-"
        )
    report_topbar_html = render_report_topbar(
        str(target),
        run_state=run_state_value or "unknown",
        profile=command_profile,
        depth=depth_config.name,
        screenshot_count=screenshot_count,
        nuclei_findings_count=nuclei_findings_count,
    )
    artifact_identity_html = _render_artifact_identity_block(
        report_dir=report_dir,
        report_path=report_path,
        run_context=run_context,
        target=target,
    )
    report_mode_banner_html = render_report_mode_banner(depth_config.name)
    ip_enrichment_html = _render_ip_enrichment_section(
        {
            **locals(),
            "_html_escape": _html_escape,
            "_render_detail_value": _render_detail_value,
        }
    )
    osint_html = _render_osint_section({"osint": osint_context})
    report_sidebar_html = "__REPORT_SIDEBAR__"

    html = f"""
    <html>
    <head>
        <title>ReconBot Raporu</title>
        <meta charset="UTF-8">
        <meta name="reconbot-report-scope" content="{_html_escape(report_scope_seed)}">
        <meta name="reconbot-report-depth" content="{_html_escape(depth_config.name)}">
        <meta name="reconbot-run-state" content="{_html_escape(run_state_value)}">
        <meta name="reconbot-auto-refresh" content="{'true' if live_refresh_running else 'false'}">
        <meta name="reconbot-refresh-interval" content="{refresh_interval_seconds}">
        {auto_refresh_meta}
        {report_style_block}
        {graph_library_script}
        {report_state_script}
    </head>
    <body class="report-depth-{_html_escape(depth_config.name)}{' osint-only-report' if osint_only_report else ''}">

    <div class="app-shell">
    {report_sidebar_html}
    <main class="report-main">
    {report_topbar_html}
    {artifact_identity_html}
    {report_mode_banner_html}

    <div class="container">

    <div class="section compact report-depth-body-all" data-depth-body="summary balanced deep" id="overview">
      <h2>{_html_escape(_txt("overview_title"))}</h2>
      <p class="executive-intro">{_html_escape(_txt("overview_intro"))}</p>
      {operator_warning_html}
      {coverage_degraded_warning_html}
      <div class="kpi-grid overview-core-grid">
        <div class="kpi">
          <div class="label">{_html_escape(_txt("overview_label_risk"))}</div>
          <div class="value">{risk_score} / 100</div>
          <div class="note">{_html_escape(_txt("overview_band_prefix"))}: <span class="pill {'bad' if risk_score >= 75 else ('warn' if risk_score >= 55 else ('ok' if risk_score < 30 else 'warn'))}">{_html_escape(risk_band)}</span> | {_html_escape(_truncate_text(risk_reasons[0] if risk_reasons else _txt("overview_no_dominant_driver"), 92))}</div>
        </div>
        <div class="kpi">
          <div class="label">{_html_escape(_txt("overview_label_decision_confidence"))}</div>
          <div class="value"><span class="pill {decision_confidence_tone_display}">{_html_escape(decision_confidence_display)}</span></div>
          <div class="note">{_html_escape(_truncate_text(decision_confidence_note_display, 128))}</div>
        </div>
        <div class="kpi">
          <div class="label">{_html_escape(_txt("overview_label_top_surface"))}</div>
          <div class="value">{_html_escape(top_surface_label)}</div>
          <div class="note">{_html_escape(_txt("overview_top_surface_priority"))}: {top_surface_score}/100 | {_html_escape(_truncate_text(top_surface_why or _txt("overview_top_surface_fallback"), 92))}</div>
        </div>
        <div class="kpi">
          <div class="label">{_html_escape(_txt("overview_label_top_chain"))}</div>
          <div class="value">{_html_escape(_truncate_text(top_chain_label, 64) or "-")}</div>
          <div class="note">{_html_escape(_txt("overview_top_chain_confidence"))}: {top_chain_confidence}/100{(" | " + _html_escape(_truncate_text(top_chain_reason, 88))) if top_chain_reason else ""}</div>
        </div>
        <div class="kpi">
          <div class="label">{_html_escape(_txt("overview_label_first_action"))}</div>
          <div class="value" style="font-size:16px; line-height:1.3;">{_html_escape(_truncate_text(first_test_text, 80))}</div>
          <div class="note">{_html_escape(_truncate_text(first_action_why, 106))}</div>
        </div>
        <div class="kpi">
          <div class="label">{_html_escape(_txt("overview_label_live_findings"))}</div>
          <div class="value" style="font-size:16px;">{_html_escape(live_findings_status)}</div>
          <div class="note">{_html_escape(_truncate_text(live_findings_note, 106))}</div>
        </div>
        <div class="kpi">
          <div class="label">{_html_escape(_txt("overview_label_coverage_note"))}</div>
          <div class="value" style="font-size:14px; font-weight:600;">{_html_escape(run_stability_label)}</div>
          <div class="note">Rapor bütünlüğü: {"tamamlandı" if run_state_value == "completed" else _html_escape(run_stability_label or run_state_value or "bilinmiyor")}</div>
          <div class="note">Araç kapsamı: {_html_escape(tool_coverage_label)}</div>
          <div class="note">{_html_escape(_truncate_text(coverage_note, 106))}</div>
        </div>
      </div>
    </div>

    {operator_plan_html}

    {run_quality_html}

    {run_lifecycle_block_html}
    {traffic_html}
    {ip_enrichment_html}
    {osint_html}
    """

    if osint_only_report:
        html += """
    <details class="show-more" id="normal-scan-sections-hidden">
      <summary>Normal scan sections hidden for OSINT-only run</summary>
      <p class="operator-view-note">This report was generated in osint_only mode. Active scanner sections such as discovery, web checks, auth profiling, raw scanner output, and Nuclei are intentionally hidden because those tools were skipped.</p>
    </details>
    </div>
    </main>
    </div>
    </body>
    </html>
    """
        available_section_ids = _report_element_ids(html)
        report_sidebar_html = render_report_sidebar(
            str(target),
            run_state=run_stability_label,
            risk_score=risk_score,
            risk_band=risk_band,
            depth=depth_config.name,
            include_ip_enrichment=bool(str(ip_enrichment_html or "").strip()),
            include_osint=bool(str(osint_html or "").strip()),
            osint_only=osint_only_report,
            available_section_ids=available_section_ids,
        )
        html = html.replace("__REPORT_SIDEBAR__", report_sidebar_html)
        html, _missing_internal_links = _disable_broken_internal_hrefs(html)

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)

        if not quiet:
            print(f"[+] HTML report created: {report_path.resolve()}")
        if open_browser:
            webbrowser.open(report_path.as_uri())
        return

    html += f"""
    <div class="section compact report-depth-operator-detail report-depth-body-balanced-deep" data-depth-body="balanced deep" id="discovery">
      <p class="report-depth-explainer"><strong>Bu bölüm neyi gösterir?</strong> Keşif, ReconBot’un neyi enumerate edip doğrulayabildiğini özetler. Bulgu yokluğuna güvenmeden önce kapsamı değerlendirmek için kullan.</p>
      <p class="operator-view-note">{_html_escape(_txt("discovery_operator_note"))}</p>
      {_render_summary_strip_counts([
          ("pipeline stages", pipeline_stage_count),
          ("atlanmış araç", skipped_count),
          ("temsili endpoint", len(katana_representative_urls)),
      ])}
      {discovery_pipeline_details_html}
    </div>

    """

    html += f"""
    <div class="report-depth-discovery-detail report-depth-audit-section report-depth-body-deep-only" data-depth-body="deep">
    <div class="section">
        <h2 id="discovery-gobuster">{_html_escape(_txt("gobuster_title"))}</h2>
        <p class="operator-view-note">{_html_escape(_txt("gobuster_note"))}</p>
    """

    gobuster_results = gobuster_results or {}
    gobuster_records: list[dict[str, Any]] = []
    ffuf_records: list[dict[str, Any]] = []
    validation_by_url = candidate_validation.get("by_url") if isinstance(candidate_validation.get("by_url"), dict) else {}

    def _validation_status_for_url(url: object) -> str:
        record = validation_by_url.get(str(url or "").strip()) if isinstance(validation_by_url, dict) else None
        if isinstance(record, dict):
            return str(record.get("classification_status") or "")
        return ""

    def _is_suppressed_or_unconfirmed(url: object) -> bool:
        status = _validation_status_for_url(url)
        return bool(status and status != "confirmed")

    for base_url, results in gobuster_results.items():
        hits = results if isinstance(results, list) else []
        for item in hits:
            rec = _build_enum_finding_record(
                source="gobuster",
                base_url=base_url,
                item=item,
                report_base_url=report_base_url,
            )
            if rec and not _is_suppressed_or_unconfirmed(rec.get("url")):
                gobuster_records.append(rec)

    for base_url, findings in ffuf_findings_by_base.items():
        hits = findings if isinstance(findings, list) else []
        for item in hits:
            rec = _build_enum_finding_record(
                source="ffuf",
                base_url=base_url,
                item=item,
                report_base_url=report_base_url,
            )
            if rec and not _is_suppressed_or_unconfirmed(rec.get("url")):
                ffuf_records.append(rec)

    gobuster_by_key: dict[tuple[str, str, int], dict[str, Any]] = {}
    for rec in gobuster_records:
        key = rec.get("compare_key")
        if isinstance(key, tuple) and key not in gobuster_by_key:
            gobuster_by_key[key] = rec

    ffuf_by_key: dict[tuple[str, str, int], dict[str, Any]] = {}
    for rec in ffuf_records:
        key = rec.get("compare_key")
        if isinstance(key, tuple) and key not in ffuf_by_key:
            ffuf_by_key[key] = rec

    common_keys = set(gobuster_by_key.keys()).intersection(ffuf_by_key.keys())
    ffuf_only_keys = set(ffuf_by_key.keys()) - set(gobuster_by_key.keys())
    ffuf_only_records = [ffuf_by_key[key] for key in sorted(ffuf_only_keys)]
    gobuster_status_200 = sum(
        1
        for rec in gobuster_by_key.values()
        if int(rec.get("status", 0) or 0) == 200
    )
    gobuster_status_403 = sum(
        1
        for rec in gobuster_by_key.values()
        if int(rec.get("status", 0) or 0) == 403
    )

    def _render_enum_row(rec: dict[str, Any]) -> str:
        status_value = int(rec.get("status", 0) or 0)
        if status_value == 200:
            status_class = "status-200"
        elif status_value == 403:
            status_class = "status-403"
        elif status_value == 404:
            status_class = "status-404"
        else:
            status_class = "status-other"

        base_cell = _render_report_link(rec.get("base_url", ""), report_base_url)
        url_value = rec.get("url", "")
        url_cell = _render_report_link(url_value, report_base_url) if url_value else "-"
        path_cell = _html_escape(rec.get("path", "-") or "-")
        metadata_cell = _html_escape(rec.get("metadata", "-") or "-")
        return f"""
            <tr>
                <td>{base_cell}</td>
                <td class="{status_class}">{status_value}</td>
                <td>{path_cell}</td>
                <td>{url_cell}</td>
                <td>{metadata_cell}</td>
            </tr>
        """

    _enum_hdr = "<th>Base URL</th><th>Durum</th><th>Path</th><th>URL</th><th>Metadata</th>"
    html += _render_summary_strip_counts(
        [
            ("findings", len(gobuster_by_key)),
            ("status 200", gobuster_status_200),
            ("status 403", gobuster_status_403),
            ("FFUF overlap", len(common_keys)),
            ("FFUF-only", len(ffuf_only_records)),
            ("candidate noise", candidate_suppressed_count),
        ]
    )
    html += f'<details class="show-more" open><summary>{_html_escape(_txt("gobuster_preview"))}</summary>'
    if "gobuster" in (skipped_tools or []):
        _gobuster_empty = f'<tr><td colspan="5">{_txt("gobuster_skipped")}</td></tr>'
        html += _render_progressive_table(
            header_html=_enum_hdr,
            rows=[_gobuster_empty],
            empty_row_html=_gobuster_empty,
            preview_rows=0,
        )
    elif not gobuster_by_key:
        _gobuster_empty = f'<tr><td colspan="5">{_txt("gobuster_empty")}</td></tr>'
        html += _render_progressive_table(
            header_html=_enum_hdr,
            rows=[_gobuster_empty],
            empty_row_html=_gobuster_empty,
            preview_rows=0,
        )
    else:
        gobuster_rows_rendered = [_render_enum_row(rec) for rec in gobuster_by_key.values()]
        html += _render_progressive_table(
            header_html=_enum_hdr,
            rows=gobuster_rows_rendered,
            empty_row_html=f'<tr><td colspan="5">{_html_escape(_txt("gobuster_empty_short"))}</td></tr>',
            preview_rows=depth_config.max_gobuster_preview,
            summary_label=_txt("gobuster_show_all"),
        )
    html += "</details>"
    html += "</div>"

    # --- FFUF Results ---
    html += f"""
    <div class="section">
        <h2 id="discovery-ffuf">{_html_escape(_txt("ffuf_title"))}</h2>
        <p class="note">{_html_escape(_txt("ffuf_note"))}</p>
        <p class="operator-view-note">{_html_escape(_txt("ffuf_operator_note"))}</p>
    """
    html += _render_summary_strip_counts(
        [
            ("total deduped", len(ffuf_by_key)),
            ("overlap w/ Gobuster", len(common_keys)),
            ("FFUF-only", len(ffuf_only_records)),
            ("soft-error suppressed", soft_error_suppressed_count + candidate_suppressed_count),
        ]
    )
    total_suppressed_noise_count = soft_error_suppressed_count + candidate_suppressed_count
    if total_suppressed_noise_count:
        html += (
            '<p class="note">'
            + _html_escape(
                f"{total_suppressed_noise_count} candidate endpoints suppressed as generic error/redirect/noise."
            )
            + "</p>"
        )
    if soft_error_suppressed_count:
        html += (
            '<p class="note">'
            + _html_escape(
                f"{soft_error_suppressed_count} candidates suppressed as soft-error / generic redirect."
            )
            + "</p>"
        )

    if "ffuf" in (skipped_tools or []):
        html += f"""
        <p class="note">{_txt("ffuf_skipped")}</p>
        """
    elif not ffuf_by_key:
        html += """
        <p class="note">""" + _html_escape(_txt("ffuf_empty")) + """</p>
        """
    elif not ffuf_only_records:
        html += f"""
        <p class="note">{_txt("ffuf_full_overlap", common=len(common_keys))}</p>
        """
    else:
        html += f"""
        <p class="note">{_txt("ffuf_partial_overlap", common=len(common_keys), unique=len(ffuf_only_records))}</p>
        """
        html += f'<details class="show-more" open><summary>{_html_escape(_txt("ffuf_preview"))}</summary>'
        ffuf_unique_rows = [_render_enum_row(rec) for rec in ffuf_only_records]
        html += _render_progressive_table(
            header_html=_enum_hdr,
            rows=ffuf_unique_rows,
            empty_row_html=f'<tr><td colspan="5">{_html_escape(_txt("ffuf_no_unique"))}</td></tr>',
            preview_rows=depth_config.max_ffuf_preview,
            summary_label=_txt("ffuf_show_all"),
        )
        html += "</details>"

    html += """
    </div>
    """

    if candidate_suppressed_count:
        noise_records = [
            record
            for record in (candidate_validation.get("suppressed", []) if isinstance(candidate_validation.get("suppressed"), list) else [])
            if isinstance(record, dict)
        ]

        def _render_noise_row(record: dict[str, Any]) -> str:
            validation = record.get("validation") if isinstance(record.get("validation"), dict) else {}
            url_value = str(record.get("url") or "")
            status_value = _safe_int(validation.get("status_code"), 0)
            final_value = str(validation.get("final_url") or "")
            status_text = str(record.get("classification_status") or "suppressed")
            category_text = ", ".join(str(item) for item in (record.get("categories") or [])[:4])
            return (
                "<tr>"
                f"<td>{_html_escape(status_text)}</td>"
                f"<td>{status_value}</td>"
                f"<td>{_html_escape(category_text or '-')}</td>"
                f"<td>{_render_report_link(url_value, report_base_url)}</td>"
                f"<td>{_render_report_link(final_value, report_base_url) if final_value else '-'}</td>"
                "</tr>"
            )

        html += '<div class="section"><h2 id="suppressed-noise">Suppressed / Noise</h2>'
        html += (
            '<p class="note">'
            + _html_escape(
                f"{candidate_suppressed_count} candidate endpoints suppressed as generic error/redirect/noise."
            )
            + "</p>"
        )
        html += '<details class="show-more"><summary>Suppressed candidate endpoints</summary>'
        html += _render_progressive_table(
            header_html="<th>Status</th><th>HTTP</th><th>Category</th><th>Original URL</th><th>Final URL</th>",
            rows=[_render_noise_row(record) for record in noise_records[:200]],
            empty_row_html='<tr><td colspan="5">Suppressed candidate yok.</td></tr>',
            preview_rows=0,
            summary_label="Suppressed candidate endpointleri göster",
        )
        html += "</details></div>"

    # --- WAF / CDN Signals ---
    _waf_hdr = "<th>Base URL</th><th>Tespit</th><th>Vendor</th><th>Durum</th><th>Kanıt</th>"
    _waf_rows: list[str] = []
    for _waf_base_url, _waf_item in list((waf_signals or {}).items()):
        if not isinstance(_waf_item, dict):
            continue
        _waf_detected = bool(_waf_item.get("detected"))
        _waf_vendor = _html_escape(_waf_item.get("vendor", "-") or "-")
        _waf_status_text = "detected" if _waf_detected else "not detected"
        _waf_status_class = "stage-done" if _waf_detected else "stage-skipped"
        _waf_error = _html_escape(_waf_item.get("error", "") or "")
        if _waf_error and _waf_error != "-":
            _waf_evidence = _waf_error
        elif _waf_detected and _waf_vendor and _waf_vendor != "-":
            _waf_evidence = f"{_waf_vendor} fingerprint wafw00f ile tespit edildi"
        elif not _waf_detected:
            _waf_evidence = "WAF fingerprint tespit edilmedi"
        else:
            _waf_evidence = "-"
        _waf_rows.append(
            f"<tr><td>{_render_report_link(_waf_base_url, report_base_url)}</td>"
            f"<td class=\"{_waf_status_class}\">{'Evet' if _waf_detected else 'Hayır'}</td>"
            f"<td>{_waf_vendor}</td><td>{_waf_status_text}</td>"
            f"<td class=\"wrap-cell\">{_waf_evidence}</td></tr>"
        )
    html += f"""
    <div class="section">
        <h2>{_html_escape(_txt("waf_title"))}</h2>
        <p class="note">{_txt("waf_note", detected=waf_detected_count)}</p>
    """
    html += _render_progressive_table(
        header_html=_waf_hdr,
        rows=_waf_rows,
        empty_row_html=f'<tr><td colspan="5">{_html_escape(_txt("waf_empty"))}</td></tr>',
        preview_rows=depth_config.max_waf_preview,
        summary_label=_txt("waf_show_all"),
    )
    html += "</div>"

    # --- WhatWeb Signals ---
    _ww_hdr = "<th>Base URL</th><th>Durum</th><th>Plugins</th><th>En Önemli Plugins</th><th>Özet</th><th>Hata</th>"
    _ww_rows: list[str] = []
    for _ww_base_url, _ww_item in list((whatweb_signals or {}).items()):
        if not isinstance(_ww_item, dict):
            continue
        _ww_plugins = [str(p) for p in (_ww_item.get("plugin_names") or []) if p]
        _ww_entries = _ww_item.get("entries", []) or []
        _ww_summary_parts: list[str] = []
        for _ww_entry in _ww_entries[:2]:
            if isinstance(_ww_entry, dict):
                _ww_st = str(_ww_entry.get("summary") or "").strip()
                if _ww_st:
                    _ww_summary_parts.append(_ww_st)
        if _ww_summary_parts:
            _ww_summary_v = " | ".join(_ww_summary_parts)
        elif _ww_plugins:
            _ww_summary_v = f"Plugins ile tespit edildi: {', '.join(_ww_plugins[:5])}" + (f" (+{len(_ww_plugins)-5})" if len(_ww_plugins) > 5 else "")
        else:
            _ww_summary_v = "-"
        _ww_status_text = "detected" if _ww_plugins else "no fingerprint"
        _ww_status_class = "stage-done" if _ww_plugins else "stage-skipped"
        _ww_plugin_preview = ", ".join(_ww_plugins[:10]) + (f" (+{len(_ww_plugins)-10})" if len(_ww_plugins) > 10 else "") if _ww_plugins else "-"
        _ww_error = _html_escape(_ww_item.get("error", "") or "-")
        _ww_rows.append(
            f"<tr><td>{_render_report_link(_ww_base_url, report_base_url)}</td>"
            f"<td class=\"{_ww_status_class}\">{_ww_status_text}</td>"
            f"<td>{len(_ww_plugins)}</td>"
            f"<td class=\"wrap-cell\">{_html_escape(_ww_plugin_preview)}</td>"
            f"<td class=\"wrap-cell\">{_html_escape(_ww_summary_v)}</td>"
            f"<td class=\"wrap-cell\">{_ww_error}</td></tr>"
        )
    html += f"""
    <div class="section">
        <h2>{_html_escape(_txt("whatweb_title"))}</h2>
        <p class="note">{_txt("whatweb_note", detected=whatweb_detected_count)}</p>
    """
    html += _render_progressive_table(
        header_html=_ww_hdr,
        rows=_ww_rows,
        empty_row_html=f'<tr><td colspan="6">{_html_escape(_txt("whatweb_empty"))}</td></tr>',
        preview_rows=depth_config.max_whatweb_preview,
        summary_label=_txt("whatweb_show_all"),
    )
    html += "</div>"
    html += "</div>"

    html += _render_post_discovery_sections(
        {
            **locals(),
            "_html_escape": _html_escape,
            "_is_url_like_text": _is_url_like_text,
            "_operator_text_to_english": _operator_text_to_english,
            "_pill": _pill,
            "_render_detail_value": _render_detail_value,
            "_render_progressive_list": _render_progressive_list,
            "_render_progressive_table": _render_progressive_table,
            "_render_report_link": _render_report_link,
            "_render_representative_endpoint": _render_representative_endpoint,
            "_render_score_pill": _render_score_pill,
            "_render_summary_strip_counts": _render_summary_strip_counts,
            "_sanitize_report_url": _sanitize_report_url,
            "_soften_suggestion_text": _soften_suggestion_text,
            "_truncate_text": _truncate_text,
            "_txt": _txt,
            "report_depth_config": depth_config,
            "render_attack_graph_section": render_attack_graph_section,
            "render_interactive_graph_block": render_interactive_graph_block,
        }
    )

    # --- Raw Section Header ---
    html += f"""
    <div class="raw-section-header report-depth-raw-anchor report-depth-body-deep-only" data-depth-body="deep" id="raw">
      <h2>{_html_escape(_txt("raw_title"))}</h2>
      <p>{_txt("raw_note")}</p>
      <p class="dense-view-note">Ham artifact’lar audit incelemesi için saklanır. Dengeli mod bu alanı ikincil tutar; tam satır seviyesinde bağlam, uzun listeler ve kapsamlı çapraz kontroller gerektiğinde Derin modu kullan.</p>
    </div>
    <div class="report-depth-raw-detail report-depth-body-deep-only" data-depth-body="deep">
    """

    # --- Katana Results ---
    _katana_hdr = "<th>#</th><th>Temsili URL</th><th>Varyantlar</th>"
    _katana_rows: list[str] = []
    for _kat_i, _kat_u in enumerate(katana_representative_urls, start=1):
        _kat_safe = _sanitize_report_url(_kat_u, report_base_url)
        _kat_cluster = representative_cluster_map.get(_kat_safe) if _kat_safe else None
        _kat_link = _render_representative_endpoint(_kat_safe, report_base_url, _kat_cluster) if _kat_safe else _html_escape(str(_kat_u))
        _kat_variants = int(_kat_cluster.get("variants_count", 1) or 1) if isinstance(_kat_cluster, dict) else 1
        _katana_rows.append(f"<tr><td>{_kat_i}</td><td>{_kat_link}</td><td>{_kat_variants}</td></tr>")

    if "katana" in (skipped_tools or []):
        _katana_rows = [f'<tr><td colspan="3">{_txt("katana_skipped")}</td></tr>']
    elif not katana_representative_urls:
        _katana_rows = [f'<tr><td colspan="3">{_html_escape(_txt("katana_empty"))}</td></tr>']

    _katana_note_html = (
        _html_escape("Web checks yalnızca ana hedef üzerinde çalıştı; içerik keşfi kapalı olduğu için ek endpoint kontrolü yapılmadı.")
        if endpoint_analysis_baseline_only
        else _txt("katana_note", mode_text=_html_escape(_txt("katana_mode_clusters") if katana_analysis_active else _txt("katana_mode_fallback")))
    )
    html += f"""
    <div class="section">
        <h2>Katana Sonuçları (Temsili Endpoint’ler)</h2>
        <p class="note">{_katana_note_html}</p>
        <p class="dense-view-note">{_html_escape(_txt("katana_dense_note"))}</p>
    """
    html += _render_summary_strip_counts(
        [
            ("temsilciler", len(katana_representative_urls)),
            ("cluster mode", "active" if katana_analysis_active else "fallback"),
        ]
    )
    html += '<details class="show-more" open><summary>Katana temsilci önizlemesi</summary>'
    html += _render_progressive_table(
        header_html=_katana_hdr,
        rows=_katana_rows,
        empty_row_html=f'<tr><td colspan="3">{_html_escape(_txt("katana_empty"))}</td></tr>',
        preview_rows=depth_config.max_katana_preview,
        summary_label="Tüm Katana endpoint’lerini göster",
    )
    html += "</details>"
    html += "</div>"

    # --- Auth Surface / Login Flow Profiler ---

    auth_profile = checks_results.get("auth_profile") if isinstance(checks_results, dict) else {}
    if not isinstance(auth_profile, dict):
        auth_profile = {}
    auth_candidates = auth_profile.get("auth_candidates") or []
    auth_summary = auth_profile.get("auth_summary") or {}
    auth_flows = auth_profile.get("auth_flows") or {}
    if not isinstance(auth_candidates, list):
        auth_candidates = []
    if not isinstance(auth_summary, dict):
        auth_summary = {}
    if not isinstance(auth_flows, dict):
        auth_flows = {}

    html += f"""
    <div class="section">
        <h2 id="auth">{_html_escape(_txt("auth_title"))}</h2>
        <p class="note">
            {_html_escape(_txt("auth_note"))}
        </p>
        {('<p class="note">' + _txt("auth_checks_skipped") + '</p>' if 'checks' in (skipped_tools or []) else '')}
    """

    if not auth_candidates:
        html += f"""
        <p class="note">{_html_escape(_txt("auth_no_candidates"))}</p>
        """
    else:
        # Auth summary as count badges
        _auth_s = auth_summary
        _auth_summary_strip_items = [
            ("Login formları", int(_auth_s.get("login_form_count", 0) or 0)),
            ("API auth", int(_auth_s.get("api_auth_count", 0) or 0)),
            ("XML-RPC", int(_auth_s.get("xmlrpc_count", 0) or 0)),
            ("OAuth/SSO", int(_auth_s.get("oauth_sso_count", 0) or 0)),
            ("Captcha içeren", int(_auth_s.get("candidates_with_captcha", 0) or 0)),
            ("CSRF içeren", int(_auth_s.get("candidates_with_csrf", 0) or 0)),
            ("Rate-limit", int(_auth_s.get("candidates_with_rate_limit_hints", 0) or 0)),
            ("Lockout", int(_auth_s.get("candidates_with_lockout_hints", 0) or 0)),
            ("Reset", int(_auth_s.get("candidates_with_reset", 0) or 0)),
            ("Register", int(_auth_s.get("candidates_with_register", 0) or 0)),
        ]
        _auth_strip_html = "".join(
            f'<span class="stat-badge"><span class="val">{v}</span> {_html_escape(k)}</span>'
            for k, v in _auth_summary_strip_items
        )
        html += f"""
        <div class="summary-strip">{_auth_strip_html}</div>
        """

        # Auth candidates progressive table
        _auth_cand_hdr = "<th>URL</th><th>Tür</th><th>HTTP</th><th>Form</th><th>Pwd</th><th>CSRF</th><th>Captcha</th><th>Güven</th><th>Detay</th>"
        _auth_cand_rows: list[str] = []
        for _ac_item in auth_candidates:
            if not isinstance(_ac_item, dict):
                continue
            _ac_url = _render_detail_value(_ac_item.get("url"), report_base_url)
            _ac_kind = _html_escape(_ac_item.get("kind", "unknown"))
            _ac_http = _html_escape(_ac_item.get("http_status", _ac_item.get("status", "")))
            _ac_form = "evet" if _ac_item.get("has_form") else "hayır"
            _ac_pwd = "evet" if _ac_item.get("has_password_field") else "hayır"
            _ac_csrf = "evet" if _ac_item.get("has_csrf_token_hint") else "hayır"
            _ac_cap = "evet" if _ac_item.get("has_captcha") else "hayır"
            _ac_conf = _html_escape(_ac_item.get("confidence", 0))
            _ac_rate = _ac_item.get("rate_limit_hints") or []
            _ac_lock = _ac_item.get("lockout_hints") or []
            _ac_rl = _html_escape(", ".join([str(x) for x in (_ac_rate + _ac_lock) if str(x or "").strip()][:3]) or "-")
            _ac_redirect = _ac_item.get("redirect_target") or _ac_item.get("final_url") or ""
            _ac_redirect_cell = _render_detail_value(_ac_redirect, report_base_url) if str(_ac_redirect or "").strip() else "-"
            _ac_rem = "evet" if _ac_item.get("has_remember_me_hint") else "hayır"
            _ac_more = (
                f'<details><summary class="row-details-toggle">Detay</summary>'
                f'<dl class="suggestion-detail">'
                f'<dt>Remember-me:</dt><dd>{_ac_rem}</dd>'
                f'<dt>Rate/Lockout:</dt><dd>{_ac_rl}</dd>'
                f'<dt>Redirect:</dt><dd>{_ac_redirect_cell}</dd>'
                f'</dl></details>'
            )
            _auth_cand_rows.append(
                f"<tr><td>{_ac_url}</td><td>{_ac_kind}</td><td>{_ac_http}</td>"
                f"<td>{_ac_form}</td><td>{_ac_pwd}</td><td>{_ac_csrf}</td>"
                f"<td>{_ac_cap}</td><td>{_ac_conf}</td><td>{_ac_more}</td></tr>"
            )

        html += "<h3>Temsili Auth Adayları</h3>"
        html += _render_progressive_table(
            header_html=_auth_cand_hdr,
            rows=_auth_cand_rows,
            empty_row_html='<tr><td colspan="9">Auth candidate yok.</td></tr>',
            preview_rows=depth_config.max_auth_preview,
            summary_label="Tüm auth adaylarını göster",
        )

        # Flow groups
        def _render_flow_list(flow_key: str, title: str) -> str:
            items = auth_flows.get(flow_key) or []
            if not isinstance(items, list) or not items:
                return f"<p class='note'><b>{_html_escape(title)}:</b> -</p>"
            rendered: list[str] = []
            for it in items[:12]:
                if isinstance(it, dict):
                    u = it.get("url") or it.get("from") or ""
                    v = it.get("to") or it.get("final_url") or ""
                    if flow_key == "admin_to_login_redirect" and v:
                        rendered.append(f"<li>{_render_detail_value(u, report_base_url)} → {_render_detail_value(v, report_base_url)}</li>")
                    else:
                        rendered.append(f"<li>{_render_detail_value(u, report_base_url)}</li>")
            return f"<details><summary>{_html_escape(title)} ({len(items)})</summary><ul>{''.join(rendered)}</ul></details>"

        html += """
        <h3>Auth Flow Grupları</h3>
        """
        html += _render_flow_list("login", "Login")
        html += _render_flow_list("register", "Register")
        html += _render_flow_list("reset", "Reset / Forgot Password")
        html += _render_flow_list("logout", "Logout")
        html += _render_flow_list("xmlrpc", "XML-RPC")
        html += _render_flow_list("oauth_sso", "OAuth / SSO")
        html += _render_flow_list("admin_to_login_redirect", "Admin → Login Redirects")

    html += """
    </div>
    """
    html += "</div>"


    html += _render_nuclei_findings_section(
        {
            **locals(),
            "_render_nuclei_summary_block": _render_nuclei_summary_block,
            "_render_nuclei_severity_sections": _render_nuclei_severity_sections,
            "_render_nuclei_raw_table": _render_nuclei_raw_table,
            "_html_escape": _html_escape,
            "_txt": _txt,
            "_safe_int": _safe_int,
            "report_depth_config": depth_config,
        }
    )

    html += """
    </div>
    </main>
    </div>
    </body>
    </html>
    """

    html = html.replace("</main>", render_sqlmap_validations(report_dir) + "</main>", 1)

    available_section_ids = _report_element_ids(html)
    report_sidebar_html = render_report_sidebar(
        str(target),
        run_state=run_stability_label,
        risk_score=risk_score,
        risk_band=risk_band,
        depth=depth_config.name,
        include_ip_enrichment=bool(str(ip_enrichment_html or "").strip()),
        include_osint=bool(str(osint_html or "").strip()),
        osint_only=osint_only_report,
        available_section_ids=available_section_ids,
    )
    html = html.replace("__REPORT_SIDEBAR__", report_sidebar_html)
    html, _missing_internal_links = _disable_broken_internal_hrefs(html)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    if not quiet:
        print(f"[+] HTML report created: {report_path.resolve()}")
    if open_browser:
        webbrowser.open(report_path.as_uri())
