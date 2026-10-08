from __future__ import annotations
from reconbot.runtime.run_lifecycle import atomic_json, summarize_coverage

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reconbot.core.models import nuclei_to_findings

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


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")




def _read_run_result_json(path: Path) -> dict[str, Any]:
    try:
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return raw
    except Exception:
        pass
    return {}


def _count_nuclei_findings(nuclei_results: dict[str, Any] | None) -> int:
    if not isinstance(nuclei_results, dict):
        return 0
    try:
        normalized_count = len(nuclei_to_findings(nuclei_results or {}))
    except Exception:
        normalized_count = 0
    if normalized_count > 0:
        return normalized_count
    live_findings = nuclei_results.get("_live_findings", [])
    return _safe_len(live_findings if isinstance(live_findings, list) else [])


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

    findings_count = _count_nuclei_findings(nuclei_results or {})

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
            existing["run_state"] = "incomplete" if summarize_coverage(stages)["failed"] else "completed"
            existing["auto_refresh_enabled"] = False
            existing["interrupted_by_user"] = bool(existing.get("interrupted_by_user", False))
        elif stage_status == "error":
            existing["run_state"] = "failed"
            existing["auto_refresh_enabled"] = False
            existing["interrupted_by_user"] = bool(existing.get("interrupted_by_user", False))
    return existing


# --- HTML report helpers ---


def _write_run_result_json(
    output_dir: Path,
    *,
    target: str,
    mode: str,
    skipped_tools: list[str],
    nmap_output: str,
    gobuster_results: dict,
    katana_urls: list[str],
    checks_results: dict,
    nuclei_results: dict,
    run_config: dict[str, Any] | None = None,
    osint: dict[str, Any] | None = None,
) -> Path:
    """Write a stable, tool-oriented JSON summary for the run.

    This file is intended to be the single source of truth for:
      - HTML report rendering
      - future GUI/dashboard
      - debugging and comparisons across runs

    Important:
      - engine.py may already have written `run_result.json` with `stages`
      - CLI must preserve and enrich that data instead of replacing it
    """
    output_dir = Path(output_dir).resolve()
    out_path = output_dir / "run_result.json"

    existing = _read_run_result_json(out_path)
    existing_meta = existing.get("meta") if isinstance(existing.get("meta"), dict) else {}
    existing_summary = existing.get("summary") if isinstance(existing.get("summary"), dict) else {}
    existing_artifacts = existing.get("artifacts") if isinstance(existing.get("artifacts"), dict) else {}

    checks_results = checks_results or {}
    login_pages = checks_results.get("login_pages", []) or []
    captcha_pages = checks_results.get("captcha_pages", []) or []
    docs_pages = checks_results.get("docs_pages", []) or []
    rate_signals = checks_results.get("rate_limit_signals", []) or []
    historical_results = checks_results.get("historical_urls", {}) if isinstance(checks_results, dict) else {}
    if not isinstance(historical_results, dict):
        historical_results = {}
    screenshots_results = checks_results.get("screenshots", {}) if isinstance(checks_results, dict) else {}
    if not isinstance(screenshots_results, dict):
        screenshots_results = {}
    screenshot_entries = screenshots_results.get("entries", []) if isinstance(screenshots_results.get("entries"), list) else []
    screenshots_captured_count = len(
        [
            item
            for item in screenshot_entries
            if isinstance(item, dict) and str(item.get("screenshot_path") or "").strip()
        ]
    )
    ffuf_findings_by_base = checks_results.get("ffuf_findings", {}) if isinstance(checks_results, dict) else {}
    ffuf_hits = 0
    if isinstance(ffuf_findings_by_base, dict):
        for hits in ffuf_findings_by_base.values():
            if isinstance(hits, list):
                ffuf_hits += len(hits)

    # Gobuster summary
    gobuster_results = gobuster_results or {}
    gobuster_base_count = len(list(gobuster_results.keys()))
    gobuster_total_hits = 0
    gobuster_status_counts: dict[str, int] = {}
    for _base, items in gobuster_results.items():
        if not items:
            continue
        gobuster_total_hits += len(items)
        for it in items:
            s = str(it.get("status", ""))
            if not s:
                continue
            gobuster_status_counts[s] = gobuster_status_counts.get(s, 0) + 1

    # Nuclei summary (best-effort; nuclei_results shape may vary)
    nuclei_status = "skipped" if "nuclei" in (skipped_tools or []) else "unknown"
    nuclei_error = ""
    nuclei_findings_count = 0
    if isinstance(nuclei_results, dict) and nuclei_results:
        nuclei_status = str(nuclei_results.get("Status") or nuclei_status)
        nuclei_error = str(nuclei_results.get("Error") or "")
        nuclei_findings_count = _count_nuclei_findings(nuclei_results)
    else:
        nuclei_status = str(existing_summary.get("nuclei_status") or nuclei_status)
        nuclei_findings_count = _safe_int(existing_summary.get("nuclei_findings_count"), 0)

    existing_run_state = str(existing.get("run_state") or "").strip().lower()
    if existing_run_state == "interrupted":
        nuclei_status = "Interrupted"

    payload: dict[str, Any] = dict(existing)
    payload["meta"] = {
        "timestamp": existing_meta.get("timestamp") or datetime.now().strftime("%Y%m%d-%H%M%S"),
        "target": target,
        "mode": mode,
        "skipped_tools": sorted(set(skipped_tools or [])),
    }
    if isinstance(run_config, dict) and run_config:
        payload["run_config"] = run_config
        payload["meta"]["run_mode"] = str(run_config.get("run_mode") or "")
        payload["meta"]["scan_profile"] = str(run_config.get("scan_profile") or "")
        payload["meta"]["osint_enabled"] = bool(run_config.get("osint_enabled", False))
        payload["meta"]["osint_profile"] = str(run_config.get("osint_profile") or "")
    if isinstance(osint, dict) and osint:
        payload["osint"] = osint
    payload["artifacts"] = {
        **existing_artifacts,
        "report_html": str((output_dir / "report.html").resolve()),
        "run_result_json": str(out_path.resolve()),
    }
    payload["summary"] = {
        **existing_summary,
        "katana_count": len(katana_urls or []),
        "checks_checked": _safe_int(checks_results.get("checked_count", checks_results.get("checked", 0)), 0),
        "checks_login": len(login_pages),
        "checks_captcha": len(captcha_pages),
        "checks_docs": len(docs_pages),
        "checks_ratelimit": len(rate_signals),
        "waf_detected_count": _safe_int(checks_results.get("waf_detected_count", 0), 0),
        "gobuster_base_url_count": gobuster_base_count,
        "gobuster_total_hits": gobuster_total_hits,
        "gobuster_status_counts": gobuster_status_counts,
        "ffuf_hits": ffuf_hits,
        "historical_urls_count": _safe_len(historical_results.get("normalized_urls", [])),
        "historical_live_count": _safe_int(historical_results.get("live_count", 0), 0),
        "historical_interesting_live_count": _safe_int(historical_results.get("interesting_live_count", 0), 0),
        "screenshots_selected_count": _safe_int(screenshots_results.get("selected_count", 0), 0),
        "screenshots_captured_count": screenshots_captured_count,
        "nuclei_status": nuclei_status,
        "nuclei_findings_count": nuclei_findings_count,
    }
    payload["skipped_tools"] = sorted(set(skipped_tools or []))
    stages_existing = existing.get("stages") if isinstance(existing.get("stages"), dict) else {}
    katana_stage = stages_existing.get("katana") if isinstance(stages_existing.get("katana"), dict) else {}
    katana_stage_status = str(katana_stage.get("status") or "").strip().lower()
    if "katana" in (skipped_tools or []) or katana_stage_status == "skipped":
        katana_status = "skipped"
    elif katana_stage_status in {"error", "failed"}:
        katana_status = "error"
    elif katana_stage_status in {"done", "success", "completed"}:
        katana_status = "success" if (katana_urls or []) else "empty"
    else:
        katana_status = "success" if (katana_urls or []) else "unknown"
    payload["tools"] = {
        "nmap": {
            "status": "skipped" if "nmap" in (skipped_tools or []) else ("success" if (nmap_output or "").strip() else "unknown"),
        },
        "katana": {
            "status": katana_status,
            "discovered_count": len(katana_urls or []),
            "error": str(katana_stage.get("error") or ""),
        },
        "gobuster": {
            "status": "skipped" if "gobuster" in (skipped_tools or []) else ("success" if gobuster_results else "unknown"),
            "base_url_count": gobuster_base_count,
            "total_hits": gobuster_total_hits,
            "status_counts": gobuster_status_counts,
        },
        "ffuf": {
            "status": "skipped" if "ffuf" in (skipped_tools or []) else ("success" if ffuf_hits > 0 else "unknown"),
            "total_hits": ffuf_hits,
        },
        "historical_urls": {
            "status": "skipped" if "historical_urls" in (skipped_tools or []) else ("success" if historical_results else "unknown"),
            "normalized_count": _safe_len(historical_results.get("normalized_urls", [])),
            "live_count": _safe_int(historical_results.get("live_count", 0), 0),
            "interesting_live_count": _safe_int(historical_results.get("interesting_live_count", 0), 0),
        },
        "screenshots": {
            "status": str(screenshots_results.get("status") or ("skipped" if "screenshots" in (skipped_tools or []) else "unknown")),
            "selected_count": _safe_int(screenshots_results.get("selected_count", 0), 0),
            "captured_count": screenshots_captured_count,
            "warning_count": _safe_len(screenshots_results.get("warnings", [])),
        },
        "web_checks": {
            "status": "skipped" if "checks" in (skipped_tools or []) else ("success" if checks_results else "unknown"),
            "checked": _safe_int(checks_results.get("checked_count", checks_results.get("checked", 0)), 0),
            "login_count": len(login_pages),
            "captcha_count": len(captcha_pages),
            "docs_count": len(docs_pages),
            "ratelimit_count": len(rate_signals),
        },
        "wafw00f": {
            "status": "success" if checks_results.get("waf_signals") else ("skipped" if "wafw00f" in (skipped_tools or []) else "unknown"),
            "detected_count": _safe_int(checks_results.get("waf_detected_count", 0), 0),
        },
        "whatweb": {
            "status": "success" if checks_results.get("whatweb_signals") else ("skipped" if "whatweb" in (skipped_tools or []) else "unknown"),
            "detected_count": sum(
                1
                for item in (checks_results.get("whatweb_signals", {}) or {}).values()
                if isinstance(item, dict) and bool(item.get("plugin_names"))
            ),
            "plugin_count": len(
                {
                    plugin_name
                    for item in (checks_results.get("whatweb_signals", {}) or {}).values()
                    if isinstance(item, dict)
                    for plugin_name in (item.get("plugin_names") or [])
                    if plugin_name
                }
            ),
        },
        
        "nuclei": {
            "status": nuclei_status,
            "error": nuclei_error,
            "findings_count": nuclei_findings_count,
        },
    }
    payload["data"] = {
        "nmap_output": nmap_output,
        "katana_urls": katana_urls or [],
        "gobuster_results": gobuster_results,
        "checks_results": checks_results,
        "ffuf_results": ffuf_findings_by_base if isinstance(ffuf_findings_by_base, dict) else {},
        "whatweb_results": checks_results.get("whatweb_signals", {}) if isinstance(checks_results, dict) else {},
        "waf_results": checks_results.get("waf_signals", {}) if isinstance(checks_results, dict) else {},
        "historical_urls": historical_results,
        "screenshots": screenshots_results,
        "nuclei_results": nuclei_results,
    }

    # --- Run lifecycle flags (used by report auto-refresh) ---
    # Preserve explicit flags if already present (e.g. Ctrl+C handler).
    nuclei_stage_existing = (
        stages_existing.get("nuclei") if isinstance(stages_existing.get("nuclei"), dict) else {}
    )
    nuclei_stage_status = str(nuclei_stage_existing.get("status") or "").strip().lower()

    run_state_existing = existing.get("run_state")
    interrupted_existing = bool(existing.get("interrupted_by_user", False))
    auto_refresh_existing = existing.get("auto_refresh_enabled")

    if isinstance(run_state_existing, str) and run_state_existing.strip():
        run_state_value = str(run_state_existing).strip().lower()
    else:
        if nuclei_stage_status == "interrupted":
            run_state_value = "interrupted"
            interrupted_existing = True
        elif nuclei_stage_status == "running":
            run_state_value = "running"
        elif nuclei_stage_status in ("done", "success", "completed", "skipped"):
            run_state_value = "completed"
        elif nuclei_stage_status in ("error", "failed"):
            run_state_value = "failed"
        else:
            # Best-effort fallback using summary.nuclei_status.
            nuclei_summary = str(payload.get("summary", {}).get("nuclei_status") or "").strip().lower()
            if nuclei_summary in ("success", "clean", "done", "skipped"):
                run_state_value = "completed"
            elif nuclei_summary in ("error", "failed"):
                run_state_value = "failed"
            elif nuclei_stage_status:
                run_state_value = nuclei_stage_status
            else:
                nuclei_running_existing = bool(existing_summary.get("nuclei_running", False)) if isinstance(existing_summary, dict) else False
                run_state_value = "running" if nuclei_running_existing else "completed"

    if isinstance(auto_refresh_existing, bool):
        auto_refresh_value = auto_refresh_existing
    else:
        auto_refresh_value = bool(run_state_value == "running" and not interrupted_existing)

    payload["coverage"] = summarize_coverage(payload.get("stages", {}))
    if run_state_value == "completed" and payload["coverage"]["failed"]:
        run_state_value = "incomplete"
    payload["run_state"] = run_state_value
    payload["interrupted_by_user"] = interrupted_existing
    payload["auto_refresh_enabled"] = auto_refresh_value

    try:
        atomic_json(out_path, payload)
    except Exception as exc:
        print(f"[!] run_result.json yazılamadı: {exc}")

    return out_path
