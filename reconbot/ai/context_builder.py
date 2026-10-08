from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import AIContext, ContextReference
from .redaction import redact_obj, redact_text


PROFILE_LIMITS = {
    "general_chat": {"max_chars": 3000, "log_lines": 0, "error_lines": 0, "findings": 0, "source_health": 0, "signals": 0},
    "ai_failure_diagnostics": {"max_chars": 6000, "log_lines": 40, "error_lines": 10, "findings": 0, "source_health": 0, "signals": 0},
    "operational_question": {"max_chars": 8000, "log_lines": 40, "error_lines": 10, "findings": 5, "source_health": 5, "signals": 5},
    "report_summary": {"max_chars": 8000, "log_lines": 6, "error_lines": 3, "findings": 5, "source_health": 3, "signals": 2},
    "finding_question": {"max_chars": 8000, "log_lines": 0, "error_lines": 3, "findings": 8, "source_health": 3, "signals": 3},
    "logs": {"max_chars": 12000, "log_lines": 200, "error_lines": 60, "findings": 0, "source_health": 4, "signals": 0},
    "settings": {"max_chars": 12000, "log_lines": 20, "error_lines": 12, "findings": 2, "source_health": 4, "signals": 2},
    "trust": {"max_chars": 10000, "log_lines": 20, "error_lines": 12, "findings": 8, "source_health": 10, "signals": 6},
    "continuation": {"max_chars": 1600, "log_lines": 0, "error_lines": 0, "findings": 0, "source_health": 0, "signals": 0},
    "report_qa": {"max_chars": 10000, "log_lines": 60, "error_lines": 16, "findings": 8, "source_health": 8, "signals": 8},
    "quick_report_summary": {"max_chars": 8000, "log_lines": 6, "error_lines": 3, "findings": 5, "source_health": 3, "signals": 2},
    "question_answer": {"max_chars": 24000, "log_lines": 120, "error_lines": 30, "findings": 10, "source_health": 10, "signals": 10},
    "log_troubleshooting": {"max_chars": 16000, "log_lines": 200, "error_lines": 60, "findings": 5, "source_health": 10, "signals": 5},
    "settings_advice": {"max_chars": 18000, "log_lines": 80, "error_lines": 30, "findings": 5, "source_health": 10, "signals": 5},
    "settings_recommendation": {"max_chars": 18000, "log_lines": 80, "error_lines": 30, "findings": 5, "source_health": 10, "signals": 5},
}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        if not path.exists():
            return {}
        parsed = json.loads(path.read_text(encoding="utf-8"))
        return parsed if isinstance(parsed, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _tail_lines(path: Path, limit: int = 80) -> list[str]:
    try:
        if limit <= 0:
            return []
        if not path.exists():
            return []
        return [redact_text(line) for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]]
    except OSError:
        return []


def _as_record(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _get(source: dict[str, Any], *keys: str, fallback: Any = None) -> Any:
    current: Any = source
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return fallback
        current = current[key]
    return current


def _first_present(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _safe_int(value: Any, default: int | None = None) -> int | None:
    try:
        if value is None or value == "":
            return default
        parsed = int(float(value))
        return parsed
    except (TypeError, ValueError):
        return default


def _risk_band(score: Any, verdict: Any = None) -> str:
    verdict_text = str(verdict or "").strip().lower()
    if verdict_text and verdict_text not in {"pending", "monitoring", "unknown"}:
        if verdict_text in {"medium", "moderate"}:
            return "elevated"
        return verdict_text
    parsed = _safe_int(score)
    if parsed is None:
        return verdict_text or "unknown"
    if parsed >= 90:
        return "critical"
    if parsed >= 70:
        return "high"
    if parsed >= 40:
        return "elevated"
    return "low"


def _risk_score_from_report_html(report_path: Path) -> int | None:
    try:
        if not report_path.exists():
            return None
        html = report_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    patterns = (
        r'<div class="label">\s*Risk Skoru\s*</div>\s*<div class="value">\s*(\d{1,3})\s*/\s*100\s*</div>',
        r"Risk\s+(\d{1,3})\s*/\s*100",
    )
    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if not match:
            continue
        score = _safe_int(match.group(1))
        if score is not None and 0 <= score <= 100:
            return score
    return None


def _normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    if "critical" in text:
        return "critical"
    if "high" in text:
        return "high"
    if "medium" in text or "moderate" in text:
        return "medium"
    if "low" in text:
        return "low"
    if "info" in text:
        return "info"
    return "unknown"


def _severity_rank(value: Any) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}.get(_normalize_severity(value), 9)


def _is_within(parent: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _read_nuclei_jsonl(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    try:
        if not path.exists():
            return []
        rows: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            text = line.strip()
            if not text or not text.startswith("{"):
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                rows.append(parsed)
        return rows
    except OSError:
        return []


def _nuclei_jsonl_candidates(run_path: Path, run_result: dict[str, Any]) -> list[Path]:
    nuclei = _as_record(run_result.get("nuclei"))
    tools_nuclei = _as_record(_as_record(run_result.get("tools")).get("nuclei"))
    artifacts = _as_record(tools_nuclei.get("artifacts"))
    candidates: list[Path] = []
    for raw in (nuclei.get("output_path"), artifacts.get("output"), run_path / "nuclei_output.jsonl"):
        if not raw:
            continue
        path = Path(str(raw))
        if not path.is_absolute():
            path = run_path / path
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if _is_within(run_path, resolved):
            candidates.append(resolved)
    return candidates


def _nuclei_rows_from_run_result(run_result: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    sources = [
        _as_record(run_result.get("nuclei")),
        _as_record(run_result.get("nuclei_results")),
        _as_record(_as_record(run_result.get("data")).get("nuclei_results")),
    ]
    for source in sources:
        for key in ("findings", "Findings", "results", "Results", "items", "data", "Data"):
            for item in _as_list(source.get(key)):
                if isinstance(item, dict):
                    rows.append(item)
    for item in _as_list(run_result.get("findings")):
        if isinstance(item, dict):
            rows.append(item)
    return rows


def _compact_evidence_value(value: Any, *, max_chars: int = 500) -> Any:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return redact_text(value.strip())[:max_chars] or None
    if isinstance(value, list):
        compact = [_compact_evidence_value(item, max_chars=160) for item in value[:8]]
        return [item for item in compact if item not in (None, "", [], {})] or None
    if isinstance(value, dict):
        compact = {
            str(key): _compact_evidence_value(item, max_chars=160)
            for key, item in list(value.items())[:8]
        }
        return {key: item for key, item in compact.items() if item not in (None, "", [], {})} or None
    return redact_text(str(value))[:max_chars] or None


def _first_evidence_value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", [], {}):
            return _compact_evidence_value(value)
    return None


def _verification_state(
    row: dict[str, Any],
    *,
    validation: str,
    status_code: Any,
    redirect: Any,
    fingerprint: Any,
    validation_evidence: Any,
    response_evidence_present: bool,
) -> str:
    explicit = str(
        row.get("verification_state")
        or row.get("verificationState")
        or row.get("validation_state")
        or row.get("validationState")
        or validation
        or ""
    ).strip().lower()
    has_explicit_validation_evidence = validation_evidence not in (None, "", [], {})
    explicitly_verified = explicit in {"verified", "validated", "confirmed", "manually_verified", "operator_verified"}
    if explicitly_verified and has_explicit_validation_evidence:
        return "verified"
    has_observed_response_detail = any(
        value not in (None, "", [], {})
        for value in (status_code, redirect, fingerprint)
    ) or response_evidence_present
    if explicit in {"partially_verified", "partial", "partially_validated"} or has_observed_response_detail:
        return "partially_verified"
    return "unverified"


def _compact_finding_row(item: dict[str, Any]) -> dict[str, Any]:
    row = _as_record(item)
    info = _as_record(row.get("info"))
    tags = [str(tag) for tag in _as_list(info.get("tags") or row.get("tags")) if str(tag).strip()][:8]
    template_id = row.get("template-id") or row.get("templateID") or row.get("template_id") or row.get("id")
    title = row.get("title") or row.get("name") or info.get("name") or template_id or "Nuclei finding"
    source = row.get("source") or row.get("tool") or "nuclei"
    url = row.get("matched-at") or row.get("matchedAt") or row.get("matched_at") or row.get("matched_url") or row.get("url") or row.get("host")
    validation = row.get("validation") or row.get("validation_status") or row.get("validationState") or "operator_validation_required"
    status_code = _first_evidence_value(row, "status_code", "status-code", "http_status", "httpStatus")
    redirect = _first_evidence_value(row, "redirect", "redirect_url", "redirectUrl", "final_url", "finalUrl", "location", "redirect_chain")
    fingerprint = _first_evidence_value(
        row,
        "fingerprint",
        "response_fingerprint",
        "responseFingerprint",
        "technology_fingerprint",
        "technologyFingerprint",
        "product_fingerprint",
        "productFingerprint",
        "detected_product",
    )
    validation_evidence = _first_evidence_value(
        row,
        "validation_evidence",
        "validationEvidence",
        "validated_evidence",
        "validatedEvidence",
        "manual_validation",
        "manualValidation",
        "proof",
        "validation_details",
    )
    request_evidence = _first_evidence_value(row, "request", "matched_request", "matched-request")
    response_evidence = _first_evidence_value(row, "response", "matched_response", "matched-response")
    response_evidence_present = request_evidence not in (None, "", [], {}) or response_evidence not in (None, "", [], {})
    verification_state = _verification_state(
        row,
        validation=str(validation),
        status_code=status_code,
        redirect=redirect,
        fingerprint=fingerprint,
        validation_evidence=validation_evidence,
        response_evidence_present=response_evidence_present,
    )
    missing_evidence_fields: list[str] = []
    if not url:
        missing_evidence_fields.append("matched_url")
    if status_code in (None, "", [], {}) and redirect in (None, "", [], {}):
        missing_evidence_fields.append("status_or_redirect")
    if fingerprint in (None, "", [], {}):
        missing_evidence_fields.append("product_fingerprint")
    if validation_evidence in (None, "", [], {}):
        missing_evidence_fields.append("explicit_validation_evidence")
    return {
        "title": str(title),
        "severity": _normalize_severity(row.get("severity") or info.get("severity")),
        "source": str(source or "nuclei"),
        "tool": str(source or "nuclei"),
        "template_id": str(template_id) if template_id else None,
        "url": str(url) if url else None,
        "matched_url": str(url) if url else None,
        "tags": tags,
        "validation": str(validation),
        "verification_state": verification_state,
        "status_code": status_code,
        "redirect": redirect,
        "fingerprint": fingerprint,
        "response_evidence_present": response_evidence_present,
        "request_evidence": request_evidence,
        "response_evidence": response_evidence,
        "validation_evidence": validation_evidence,
        "missing_evidence_fields": missing_evidence_fields,
        "operator_validation_required": False if row.get("operator_validation_required") is False else True,
        "confidence": row.get("confidence") or info.get("confidence"),
    }


def _all_nuclei_findings(run_path: Path, run_result: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _nuclei_rows_from_run_result(run_result)
    for candidate in _nuclei_jsonl_candidates(run_path, run_result):
        rows.extend(_read_nuclei_jsonl(candidate))
    unique: dict[str, dict[str, Any]] = {}
    for item in rows:
        compact = _compact_finding_row(item)
        key = "|".join(str(compact.get(part) or "") for part in ("source", "template_id", "url", "title")).lower()
        unique.setdefault(key, compact)
    return sorted(unique.values(), key=lambda item: (_severity_rank(item.get("severity")), str(item.get("title") or "")))


def _severity_counts(findings: list[dict[str, Any]], total_count: int) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = _normalize_severity(finding.get("severity"))
        counts[severity] = counts.get(severity, 0) + 1
    known_count = sum(counts.values())
    if total_count > known_count:
        counts["unknown"] = counts.get("unknown", 0) + (total_count - known_count)
    return counts


def _run_state_flags(run_state: Any, interrupted_by_user: Any = None) -> tuple[bool, bool, bool]:
    state = str(run_state or "").strip().lower()
    is_running = state in {"running", "in_progress", "active", "scanning", "started"}
    is_interrupted = state in {"interrupted", "stopped", "cancelled", "canceled", "failed", "error"} or interrupted_by_user is True
    is_completed = state in {"completed", "done", "finished", "historical_loaded"} and not is_interrupted
    return is_running, is_interrupted, is_completed


def _source_health_summary(osint: dict[str, Any]) -> dict[str, Any]:
    summary = _as_record(osint.get("osint_source_health_summary"))
    source_health = _as_record(osint.get("source_health"))
    nested = _as_record(_as_record(osint.get("summary")).get("source_health"))
    merged = {**nested, **source_health, **summary}
    if not merged.get("coverage_confidence") and merged:
        attempted = _safe_int(merged.get("attempted_live_sources"), 0) or 0
        skipped = _safe_int(merged.get("skipped"), 0) or 0
        suggestions = (_safe_int(merged.get("suggestions_only"), 0) or 0) + (_safe_int(merged.get("suggestions_generated_count"), 0) or 0)
        if attempted == 0 and (skipped or suggestions):
            merged["coverage_confidence"] = "low"
            merged["coverage_note"] = "Canlı ana OSINT kaynağı çalıştırılmadı; kanıt yokluğu temiz sonuç değildir."
    return merged


def _partial_coverage_notes(
    run_state: Any,
    interrupted_by_user: Any,
    stages: dict[str, Any],
    source_health: dict[str, Any],
) -> list[str]:
    notes: list[str] = []
    is_running, is_interrupted, _is_completed = _run_state_flags(run_state, interrupted_by_user)
    if is_running:
        notes.append("Run is still running; this is not a final report.")
    if is_interrupted:
        notes.append("Run was interrupted or failed; this is not a final report.")
    coverage = str(source_health.get("coverage_confidence") or "").lower()
    if coverage and coverage != "high":
        notes.append(f"Source coverage is {coverage}; do not claim a clean result.")
    for name, stage in stages.items():
        status = str(_as_record(stage).get("status") or "").lower()
        if status in {"error", "failed", "skipped"}:
            notes.append(f"{name} stage status is {status}.")
    return list(dict.fromkeys(notes))[:12]


def _last_errors(log_tail: list[str], limit: int = 8) -> list[str]:
    markers = ("error", "timeout", "failed", "forbidden", "interrupted", "cancelled", "canceled")
    return [line for line in log_tail if any(marker in line.lower() for marker in markers)][-limit:]


def build_ai_run_context_snapshot(
    run_dir: str | Path | None,
    run_result: dict[str, Any] | None = None,
    stages: dict[str, Any] | None = None,
    settings: dict[str, Any] | None = None,
    profile: str = "question_answer",
    request_id: str | None = None,
    provided_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    run_path = Path(run_dir).resolve() if run_dir else Path()
    source = _as_record(run_result or {})
    stage_source = _as_record(stages or {})
    if not source and provided_snapshot:
        snapshot = dict(provided_snapshot)
        snapshot["top_findings"] = [
            _compact_finding_row(item)
            for item in _as_list(snapshot.get("top_findings"))[:8]
            if isinstance(item, dict)
        ]
        return snapshot
    meta = _as_record(source.get("meta"))
    summary = _as_record(source.get("summary"))
    run_config = _as_record(source.get("run_config") or source.get("config"))
    traffic = _as_record(source.get("traffic"))
    osint = _as_record(source.get("osint"))
    report = _as_record(source.get("report"))
    decision = _as_record(source.get("decision"))
    risk = _as_record(source.get("risk"))
    tools_nuclei = _as_record(_as_record(source.get("tools")).get("nuclei"))
    nuclei_stage = _as_record(stage_source.get("nuclei") or _as_record(source.get("stages")).get("nuclei"))
    findings = _all_nuclei_findings(run_path, source) if run_dir else _all_nuclei_findings(Path(), source)
    nuclei_count = max(
        _safe_int(summary.get("nuclei_findings_count"), 0) or 0,
        _safe_int(nuclei_stage.get("findings_count"), 0) or 0,
        _safe_int(tools_nuclei.get("findings_count"), 0) or 0,
        len(findings),
    )
    findings_count = max(_safe_int(summary.get("findings_count"), 0) or 0, _safe_int(summary.get("total_findings"), 0) or 0, nuclei_count)
    risk_score = _first_present(
        report.get("risk_score"),
        _get(report, "overview", "risk_score"),
        _get(report, "summary", "risk_score"),
        decision.get("risk_score"),
        decision.get("score"),
        summary.get("risk_score"),
        risk.get("score"),
        source.get("risk_score"),
    )
    risk_score_int = _safe_int(risk_score)
    risk_source = "run_result/report/decision"
    if risk_score_int is None and run_dir:
        report_score = _risk_score_from_report_html(run_path / "report.html")
        if report_score is not None:
            risk_score_int = report_score
            risk_source = "report.html risk overview"
    verdict = _first_present(report.get("verdict"), decision.get("verdict"), risk.get("verdict"), source.get("verdict"))
    run_state = str(source.get("run_state") or _as_record(provided_snapshot).get("run_state") or ("idle" if not run_dir else "running"))
    is_running, is_interrupted, is_completed = _run_state_flags(run_state, source.get("interrupted_by_user"))
    source_health = _source_health_summary(osint)
    top_findings = findings[:8]
    return {
        "target": meta.get("target") or source.get("target") or _as_record(provided_snapshot).get("target"),
        "run_id": meta.get("timestamp") or (run_path.name if run_dir else ""),
        "run_dir": str(run_path) if run_dir else "",
        "report_path": str(run_path / "report.html") if run_dir else "",
        "run_state": run_state,
        "is_running": is_running,
        "is_interrupted": is_interrupted,
        "is_completed": is_completed,
        "profile": run_config.get("scan_profile") or traffic.get("requested_profile") or traffic.get("profile") or _as_record(settings or {}).get("scan_profile"),
        "mode": run_config.get("run_mode") or meta.get("run_mode"),
        "risk_score": risk_score_int,
        "risk_band": _risk_band(risk_score_int, verdict),
        "findings_count": findings_count,
        "nuclei_findings_count": nuclei_count,
        "findings_by_severity": _severity_counts(findings, findings_count),
        "top_findings": top_findings,
        "tool_stage_status": stage_source or _as_record(source.get("stages")),
        "source_health_summary": source_health,
        "osint_summary": _as_record(osint.get("summary")),
        "darkweb_summary": _as_record(_as_record(osint.get("darkweb_intelligence")).get("summary")),
        "validation_notes": (
            ["Nuclei template matches require operator validation."]
            + [f"{item.get('title')}: {item.get('validation')}" for item in top_findings[:3]]
        ) if top_findings else [],
        "current_report_confidence": {
            "risk_source": risk_source,
            "coverage_confidence": source_health.get("coverage_confidence"),
            "report_exists": bool(run_dir and (run_path / "report.html").exists()),
        },
        "last_errors": [],
        "partial_coverage_notes": _partial_coverage_notes(run_state, source.get("interrupted_by_user"), stage_source or _as_record(source.get("stages")), source_health),
        "context_profile": profile,
        "request_id": request_id or _as_record(provided_snapshot).get("request_id") or "",
    }


def _compact_findings(run_result: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    return _all_nuclei_findings(Path(), run_result)[:limit]


def _source_health(osint: dict[str, Any], limit: int = 10) -> dict[str, Any]:
    rows: dict[str, Any] = {}
    candidates = osint.get("source_health")
    if isinstance(candidates, dict):
        iterable = candidates.items()
    else:
        iterable = ((str(_as_record(item).get("source") or _as_record(item).get("id") or idx), item) for idx, item in enumerate(_as_list(candidates)))
    for key, value in iterable:
        if len(rows) >= limit:
            break
        row = _as_record(value)
        rows[str(key)] = {
            "status": row.get("status"),
            "coverage_impact": row.get("coverage_impact"),
            "finding_impact": row.get("finding_impact"),
            "user_message_tr": row.get("user_message_tr"),
            "operator_action_tr": row.get("operator_action_tr"),
            "error_class": row.get("error_class"),
            "retryable": row.get("retryable"),
        }
    for source in _as_list(osint.get("sources")):
        if len(rows) >= limit:
            break
        row = _as_record(source)
        name = str(row.get("name") or row.get("source") or row.get("id") or "")
        if not name:
            continue
        rows.setdefault(
            name,
            {
                "status": row.get("status"),
                "coverage_impact": row.get("coverage_impact"),
                "error_class": row.get("error_class"),
                "errors": row.get("errors"),
            },
        )
    return rows


def _compact_osint(osint: dict[str, Any], source_health_limit: int = 10, signals_limit: int = 10) -> dict[str, Any]:
    organization = _as_record(osint.get("organization_intelligence"))
    org_summary = _as_record(organization.get("summary"))
    infrastructure = _as_record(osint.get("infrastructure"))
    darkweb = _as_record(osint.get("darkweb_intelligence"))
    leak = _as_record(osint.get("leak_intelligence"))
    return {
        "enabled": osint.get("enabled"),
        "mode": osint.get("mode"),
        "status": osint.get("status"),
        "verdict": osint.get("verdict"),
        "verdict_reason": osint.get("verdict_reason"),
        "summary": _as_record(osint.get("summary")),
        "osint_source_health_summary": _as_record(osint.get("osint_source_health_summary")),
        "source_health": _source_health(osint, source_health_limit),
        "darkweb_intelligence": {
            "mode": darkweb.get("mode"),
            "status": darkweb.get("status"),
            "summary": _as_record(darkweb.get("summary")),
            "tor_onion_crawling": _as_record(darkweb.get("tor_onion_crawling")),
            "risk_score_impact": darkweb.get("risk_score_impact"),
            "references_count": len(_as_list(darkweb.get("observed_references"))),
        },
        "leak_intelligence": {
            "enabled": leak.get("enabled"),
            "status": leak.get("status"),
            "summary": _as_record(leak.get("summary")),
        },
        "organization_intelligence": {
            "summary": org_summary,
            "contact_counters": {
                "target_observed_public_contacts": org_summary.get("target_observed_public_contacts"),
                "parent_org_observed_public_contacts": org_summary.get("parent_org_observed_public_contacts"),
                "target_observed_phone_numbers": org_summary.get("target_observed_phone_numbers"),
                "target_observed_locations": org_summary.get("target_observed_locations"),
                "target_validated_public_documents": org_summary.get("target_validated_public_documents"),
                "target_observed_social_profiles": org_summary.get("target_observed_social_profiles"),
            },
        },
        "infrastructure": {
            "summary": _as_record(infrastructure.get("summary")),
            "dns": infrastructure.get("dns") or infrastructure.get("dns_records"),
            "cdn_or_proxy": infrastructure.get("cdn_or_proxy"),
        },
        "signals_sample": _as_list(osint.get("signals"))[:signals_limit],
    }


def _tool_settings(run_config: dict[str, Any], settings: dict[str, Any] | None) -> dict[str, Any]:
    current = _as_record(settings or {})
    if current.get("toolSettings"):
        return _as_record(current.get("toolSettings"))
    if current.get("tool_settings"):
        return _as_record(current.get("tool_settings"))
    return _as_record(run_config.get("tool_settings"))


def _references(context: dict[str, Any]) -> list[ContextReference]:
    refs: list[ContextReference] = []

    def add(path: str, label_tr: str = "") -> None:
        parts = path.replace("[", ".").replace("]", "").split(".")
        current: Any = context
        for part in parts:
            if part == "":
                continue
            if isinstance(current, list) and part.isdigit():
                idx = int(part)
                current = current[idx] if idx < len(current) else None
            elif isinstance(current, dict):
                current = current.get(part)
            else:
                current = None
            if current is None:
                return
        refs.append(ContextReference(path=path, value=current, label_tr=label_tr))

    for path, label in (
        ("target", "Hedef"),
        ("current_run_context.run_state", "Güncel run durumu"),
        ("current_run_context.risk_score", "Güncel risk skoru"),
        ("current_run_context.nuclei_findings_count", "Güncel Nuclei bulgu sayısı"),
        ("run.mode", "Run modu"),
        ("risk.score", "Risk skoru"),
        ("risk.verdict", "Risk kararı"),
        ("osint.osint_source_health_summary.coverage_confidence", "Kaynak kapsam güveni"),
        ("osint.source_health.public_code_search.status", "Public code search durumu"),
        ("osint.darkweb_intelligence.summary.credential_material_collected", "Credential toplama durumu"),
        ("osint.darkweb_intelligence.mode", "Darkweb modu"),
        ("tool_stage_status.nuclei.status", "Nuclei stage durumu"),
        ("run_config.tool_settings.nuclei.rateLimit", "Nuclei rate limit"),
    ):
        add(path, label)
    findings = context.get("findings")
    if isinstance(findings, list):
        for idx, _item in enumerate(findings[:5]):
            add(f"findings[{idx}].title", "Bulgu başlığı")
    return refs


def _truncate_context(context: dict[str, Any], max_chars: int) -> tuple[dict[str, Any], bool]:
    text = json.dumps(context, ensure_ascii=False, sort_keys=True)
    if len(text) <= max_chars:
        return context, False
    if context.get("context_profile") in {"settings_recommendation", "settings_advice", "settings"}:
        settings_context = {
            "context_profile": context.get("context_profile"),
            "current_run_context": {
                key: _as_record(context.get("current_run_context")).get(key)
                for key in ("target", "run_state", "risk_score", "risk_band", "findings_count")
            },
            "summary": context.get("summary"),
            "run_config": context.get("run_config"),
            "log": {"recent_errors": _as_list(_as_record(context.get("log")).get("recent_errors"))[:10], "tail": []},
            "source_boundaries": context.get("source_boundaries"),
        }
        if len(json.dumps(settings_context, ensure_ascii=False, sort_keys=True)) <= max_chars:
            return settings_context, True
    compact = dict(context)
    compact["log"] = {"recent_errors": _as_record(context.get("log")).get("recent_errors", [])[:20], "tail": []}
    compact["osint"] = {**_as_record(context.get("osint")), "signals_sample": _as_list(_as_record(context.get("osint")).get("signals_sample"))[:8]}
    compact["findings"] = _as_list(context.get("findings"))[:12]
    compact["important_findings"] = _as_list(context.get("important_findings"))[:12]
    compact["current_run_context"] = {
        **_as_record(context.get("current_run_context")),
        "top_findings": _as_list(_as_record(context.get("current_run_context")).get("top_findings"))[:8],
        "tool_stage_status": _as_record(_as_record(context.get("current_run_context")).get("tool_stage_status")),
        "last_errors": _as_list(_as_record(context.get("current_run_context")).get("last_errors"))[:8],
    }
    if len(json.dumps(compact, ensure_ascii=False, sort_keys=True)) <= max_chars:
        return compact, True

    osint = _as_record(context.get("osint"))
    minimal = {
        "target": context.get("target"),
        "current_run_context": {
            key: _as_record(context.get("current_run_context")).get(key)
            for key in (
                "target",
                "run_id",
                "run_dir",
                "report_path",
                "run_state",
                "is_running",
                "is_interrupted",
                "is_completed",
                "profile",
                "mode",
                "risk_score",
                "risk_band",
                "findings_count",
                "nuclei_findings_count",
                "findings_by_severity",
                "top_findings",
                "source_health_summary",
                "partial_coverage_notes",
                "context_profile",
            )
        },
        "run": {
            "state": _as_record(context.get("run")).get("state"),
            "mode": _as_record(context.get("run")).get("mode"),
            "scan_profile": _as_record(context.get("run")).get("scan_profile"),
            "osint_profile": _as_record(context.get("run")).get("osint_profile"),
            "report_path": _as_record(context.get("run")).get("report_path"),
        },
        "risk": context.get("risk"),
        "summary": context.get("summary"),
        "important_findings": _as_list(context.get("important_findings"))[:3],
        "findings": _as_list(context.get("findings"))[:3],
        "osint": {
            "enabled": osint.get("enabled"),
            "mode": osint.get("mode"),
            "status": osint.get("status"),
            "verdict": osint.get("verdict"),
            "summary": _as_record(osint.get("summary")),
            "osint_source_health_summary": _as_record(osint.get("osint_source_health_summary")),
            "source_health": dict(list(_as_record(osint.get("source_health")).items())[:3]),
            "darkweb_intelligence": {
                "mode": _as_record(osint.get("darkweb_intelligence")).get("mode"),
                "status": _as_record(osint.get("darkweb_intelligence")).get("status"),
                "summary": _as_record(_as_record(osint.get("darkweb_intelligence")).get("summary")),
            },
        },
        "tool_stage_status": {
            name: {
                "status": _as_record(stage).get("status"),
                "reason": _as_record(stage).get("reason"),
                "findings_count": _as_record(stage).get("findings_count"),
            }
            for name, stage in list(_as_record(context.get("tool_stage_status")).items())[:8]
        },
        "log": {"recent_errors": _as_list(_as_record(context.get("log")).get("recent_errors"))[:3], "tail": []},
        "context_profile": context.get("context_profile"),
        "source_boundaries": context.get("source_boundaries"),
    }
    if len(json.dumps(minimal, ensure_ascii=False, sort_keys=True)) <= max_chars:
        return minimal, True

    minimal["summary"] = {
        key: _as_record(context.get("summary")).get(key)
        for key in ("nuclei_findings_count", "katana_count", "gobuster_total_hits", "ffuf_hits", "risk_score")
    }
    minimal["osint"]["summary"] = {}
    minimal["tool_stage_status"] = {
        name: {"status": _as_record(stage).get("status"), "findings_count": _as_record(stage).get("findings_count")}
        for name, stage in list(_as_record(context.get("tool_stage_status")).items())[:4]
    }
    if len(json.dumps(minimal, ensure_ascii=False, sort_keys=True)) <= max_chars:
        return minimal, True

    minimal["summary"] = {
        key: value for key, value in _as_record(minimal.get("summary")).items() if value not in (None, "", [], {})
    }
    minimal["findings"] = _as_list(minimal.get("findings"))[:2]
    minimal["important_findings"] = _as_list(minimal.get("important_findings"))[:2]
    minimal["current_run_context"] = {
        key: _as_record(minimal.get("current_run_context")).get(key)
        for key in (
            "target",
            "run_id",
            "run_dir",
            "report_path",
            "run_state",
            "risk_score",
            "risk_band",
            "is_running",
            "is_interrupted",
            "is_completed",
            "findings_count",
            "nuclei_findings_count",
            "findings_by_severity",
            "top_findings",
            "partial_coverage_notes",
        )
    }
    minimal["current_run_context"]["top_findings"] = _as_list(
        _as_record(minimal.get("current_run_context")).get("top_findings")
    )[:5]
    minimal["osint"] = {
        "enabled": _as_record(minimal.get("osint")).get("enabled"),
        "mode": _as_record(minimal.get("osint")).get("mode"),
        "osint_source_health_summary": _as_record(_as_record(minimal.get("osint")).get("osint_source_health_summary")),
    }
    minimal["source_boundaries"] = {
        "ai_may_create_findings": False,
        "ai_may_change_risk_score": False,
        "credentials_or_raw_dumps_collected": False,
        "tor_onion_crawling_supported": False,
    }
    if len(json.dumps(minimal, ensure_ascii=False, sort_keys=True)) <= max_chars:
        return minimal, True

    # Do not let duplicated finding inventories consume the entire small-model
    # budget and cause the caller to drop all run facts. Retain one authoritative
    # snapshot first, then add as many compact findings as will fit.
    snapshot = _as_record(context.get("current_run_context"))
    essential = {"context_profile": context.get("context_profile"), "current_run_context": {
        key: snapshot[key] for key in (
            "target", "run_state", "risk_score", "risk_band", "findings_count",
            "nuclei_findings_count", "source_health_summary", "partial_coverage_notes",
            "current_report_confidence",
        ) if key in snapshot
    }}
    if not snapshot:
        return minimal, True
    for key in ("partial_coverage_notes", "source_health_summary", "current_report_confidence"):
        if len(json.dumps(essential, ensure_ascii=False, sort_keys=True)) <= max_chars:
            break
        essential["current_run_context"].pop(key, None)
    findings = []
    for row in _as_list(snapshot.get("top_findings")):
        item = {key: row[key] for key in (
            "title", "template_id", "severity", "url", "verification_state",
        ) if key in row}
        candidate = {**essential, "findings": findings + [item]}
        if len(json.dumps(candidate, ensure_ascii=False, sort_keys=True)) > max_chars:
            break
        findings.append(item)
    if findings:
        essential["findings"] = findings
    return essential, True


def build_ai_context(
    run_dir: str | Path | None,
    settings: dict[str, Any] | None = None,
    max_chars: int = 60000,
    profile: str = "question_answer",
    provided_snapshot: dict[str, Any] | None = None,
) -> AIContext:
    limits = PROFILE_LIMITS.get(profile, PROFILE_LIMITS["question_answer"])
    effective_max_chars = min(max_chars, int(limits["max_chars"]))
    log_line_limit = int(limits["log_lines"])
    error_line_limit = int(limits["error_lines"])
    finding_limit = int(limits["findings"])
    source_health_limit = int(limits["source_health"])
    signals_limit = int(limits["signals"])
    run_path = Path(run_dir).resolve() if run_dir else Path()
    run_result = _read_json(run_path / "run_result.json") if run_dir else {}
    stages = _read_json(run_path / "stages_live.json") if run_dir else {}
    meta = _as_record(run_result.get("meta"))
    summary = _as_record(run_result.get("summary"))
    run_config = _as_record(run_result.get("run_config") or run_result.get("config"))
    osint = _as_record(run_result.get("osint"))
    report = _as_record(run_result.get("report"))
    decision = _as_record(run_result.get("decision"))
    risk = _as_record(run_result.get("risk"))
    traffic = _as_record(run_result.get("traffic"))
    log_tail = _tail_lines(run_path / "reconbot.log", limit=log_line_limit)
    recent_errors = [line for line in log_tail if any(marker in line.lower() for marker in ("error", "timeout", "failed", "auth", "forbidden"))][-error_line_limit:]
    tool_status = {
        name: {
            "status": _as_record(stage).get("status"),
            "reason": _as_record(stage).get("reason"),
            "error": _as_record(stage).get("error"),
            "findings_count": _as_record(stage).get("findings_count"),
        }
        for name, stage in stages.items()
    }
    current_run_context = build_ai_run_context_snapshot(
        run_dir,
        run_result=run_result,
        stages=stages,
        settings=settings,
        profile=profile,
        provided_snapshot=provided_snapshot,
    )
    # Request/transport identifiers are useful to IPC diagnostics, not LM context.
    current_run_context.pop("request_id", None)
    current_run_context["last_errors"] = recent_errors[-error_line_limit:]
    snapshot_findings = _as_list(current_run_context.get("top_findings"))
    summary_with_snapshot = {
        **summary,
        "risk_score": current_run_context.get("risk_score"),
        "risk_band": current_run_context.get("risk_band"),
        "findings_count": current_run_context.get("findings_count"),
        "nuclei_findings_count": current_run_context.get("nuclei_findings_count"),
        "findings_by_severity": current_run_context.get("findings_by_severity"),
        "run_state": current_run_context.get("run_state"),
    }
    context: dict[str, Any] = {
        "target": current_run_context.get("target") or meta.get("target") or run_result.get("target"),
        "current_run_context": current_run_context,
        "run": {
            "state": current_run_context.get("run_state"),
            "mode": current_run_context.get("mode") or run_config.get("run_mode") or meta.get("run_mode"),
            "scan_profile": current_run_context.get("profile") or run_config.get("scan_profile") or traffic.get("requested_profile") or traffic.get("profile"),
            "osint_profile": run_config.get("osint_profile"),
            "current_run_dir": str(run_path) if run_dir else "",
            "report_path": str(run_path / "report.html") if run_dir else "",
            "is_running": current_run_context.get("is_running"),
            "is_interrupted": current_run_context.get("is_interrupted"),
            "is_completed": current_run_context.get("is_completed"),
        },
        "risk": {
            "score": current_run_context.get("risk_score"),
            "verdict": current_run_context.get("risk_band") or _first_present(report.get("verdict"), decision.get("verdict"), risk.get("verdict"), run_result.get("verdict")),
            "source": _as_record(current_run_context.get("current_report_confidence")).get("risk_source") or "run_result/report/decision",
        },
        "summary": summary_with_snapshot,
        "important_findings": snapshot_findings[:finding_limit],
        "findings": snapshot_findings[:finding_limit],
        "osint": _compact_osint(osint, source_health_limit=source_health_limit, signals_limit=signals_limit),
        "run_config": {
            "tool_settings": _tool_settings(run_config, settings),
            "tools": run_config.get("tools"),
            "output_dir": run_config.get("output_dir"),
            "scan_profile": current_run_context.get("profile") or run_config.get("scan_profile") or _as_record(settings or {}).get("scan_profile"),
            "run_mode": current_run_context.get("mode") or run_config.get("run_mode"),
            "traffic_settings": {
                "profile": current_run_context.get("profile") or traffic.get("requested_profile") or traffic.get("profile"),
                "current_settings": _tool_settings(run_config, settings),
            },
        },
        "tool_stage_status": tool_status,
        "log": {
            "recent_errors": recent_errors[-error_line_limit:],
            "tail": log_tail if profile == "log_troubleshooting" else log_tail[-20:],
        },
        "context_profile": profile,
        "source_boundaries": {
            "ai_may_create_findings": False,
            "ai_may_change_risk_score": False,
            "darkweb_metadata_is_active_vulnerability_evidence": False,
            "credentials_or_raw_dumps_collected": False,
            "tor_onion_crawling_supported": False,
        },
    }
    if profile in {"general_chat", "continuation"}:
        context = {
            "context_profile": profile,
            "source_boundaries": context["source_boundaries"],
        }
    elif profile == "ai_failure_diagnostics":
        ai_markers = ("ai", "provider", "lm studio", "model", "chat/completions", "http 400", "context", "timeout", "zaman aşımı")
        relevant_ai_lines = [line for line in log_tail if any(marker in line.lower() for marker in ai_markers)][-40:]
        relevant_ai_errors = [
            line for line in relevant_ai_lines
            if any(marker in line.lower() for marker in ("error", "failed", "timeout", "http 400", "context"))
        ][-10:]
        diagnostics = _as_record(_as_record(settings or {}).get("ai_diagnostics"))
        context = {
            "context_profile": profile,
            "ai_request_diagnostics": {
                "latest_request_status": diagnostics.get("latestRequestStatus"),
                "provider_http_status": diagnostics.get("providerHttpStatus"),
                "provider_error": diagnostics.get("providerError"),
                "effective_request_plan": diagnostics.get("effectiveRequestPlan"),
                "configured_timeout_sec": diagnostics.get("configuredTimeoutSec"),
                "effective_attempt_timeout_sec": diagnostics.get("effectiveAttemptTimeoutSec"),
                "configured_max_output_tokens": diagnostics.get("configuredMaxOutputTokens"),
                "effective_max_output_tokens": diagnostics.get("effectiveMaxOutputTokens"),
                "conversation_turns": diagnostics.get("conversationTurns"),
                "latest_provider_log_lines": relevant_ai_lines,
                "latest_provider_errors": relevant_ai_errors,
            },
            "source_boundaries": context["source_boundaries"],
        }
    elif profile == "operational_question":
        context["summary"] = {}
        context["osint"] = {
            "enabled": context["osint"].get("enabled"),
            "mode": context["osint"].get("mode"),
            "osint_source_health_summary": context["osint"].get("osint_source_health_summary", {}),
        }
        context["run_config"] = {"tool_settings": {}, "tools": None, "output_dir": None}
        context["log"] = {"recent_errors": [], "tail": []}
    if profile in {"quick_report_summary", "report_summary", "report_qa", "finding_question", "trust", "log_troubleshooting", "logs"}:
        context["run_config"]["tool_settings"] = {}
    if profile in {"quick_report_summary", "report_summary"}:
        context["run"]["current_run_dir"] = ""
        context["tool_stage_status"] = {
            name: {
                "status": _as_record(stage).get("status"),
                "reason": _as_record(stage).get("reason"),
                "findings_count": _as_record(stage).get("findings_count"),
            }
            for name, stage in tool_status.items()
        }
        context["log"] = {"recent_errors": recent_errors[-error_line_limit:], "tail": []}
    if profile in {"log_troubleshooting", "logs"}:
        context["important_findings"] = []
        context["findings"] = []
        context["run_config"] = {"tool_settings": {}, "tools": None, "output_dir": None}
        context["osint"] = {"osint_source_health_summary": context["osint"].get("osint_source_health_summary", {})}
    if profile == "finding_question":
        context["log"] = {"recent_errors": [], "tail": []}
        context["osint"] = {"osint_source_health_summary": context["osint"].get("osint_source_health_summary", {})}
    if profile in {"settings_recommendation", "settings_advice", "settings"}:
        context["summary"] = {
            "risk_score": summary_with_snapshot.get("risk_score"),
            "run_state": summary_with_snapshot.get("run_state"),
            "findings_count": summary_with_snapshot.get("findings_count"),
            "nuclei_findings_count": summary_with_snapshot.get("nuclei_findings_count"),
            "katana_count": summary.get("katana_count"),
            "gobuster_total_hits": summary.get("gobuster_total_hits"),
            "ffuf_hits": summary.get("ffuf_hits"),
        }
    context = redact_obj(context)
    context, truncated = _truncate_context(context, max_chars=effective_max_chars)
    return AIContext(context=context, references=_references(context), truncated=truncated)


def context_as_prompt_text(ai_context: AIContext) -> str:
    if not ai_context.context and not ai_context.references:
        return ""
    payload = {
        "context": ai_context.context,
        "context_references": [ref.__dict__ for ref in ai_context.references],
        "truncated": ai_context.truncated,
    }
    return json.dumps(redact_obj(payload), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
