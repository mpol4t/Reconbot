"""Persist terminal states even when scanning stops before report generation."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def summarize_coverage(stages):
    groups = {"completed": [], "skipped": [], "failed": [], "pending": []}
    for name, stage in (stages or {}).items():
        if not isinstance(stage, dict):
            continue
        status = str(stage.get("status", "")).lower()
        if status in {"done", "success", "completed"}:
            group = "completed"
        elif status == "skipped":
            group = "skipped"
        elif status in {"error", "failed", "partial", "interrupted"}:
            group = "failed"
        else:
            group = "pending"
        groups[group].append(name)
    groups["complete"] = not groups["failed"] and not groups["pending"]
    return groups


def result_coverage_status(results):
    """Scanner wrappers can return error records without raising exceptions."""
    records = [value for value in results.values() if isinstance(value, dict)]
    failed = [value for value in records if value.get("error") or value.get("available") is False or value.get("returncode") not in (None, 0)]
    if not failed:
        return "done", None
    status = "error" if len(failed) == len(records) else "partial"
    return status, "; ".join(str(value.get("error") or f"exit code {value.get('returncode')}") for value in failed[:3])


def atomic_json(path: Path, payload):
    import os
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def mark_terminal(run_dir: Path, target: str, state: str, error: str):
    now = datetime.now(timezone.utc).isoformat()
    def read(path):
        try:
            data = json.loads(path.read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}
    result_path = run_dir / "run_result.json"
    result = read(result_path)
    result.setdefault("meta", {}).update({"target": target})
    result.update(run_state=state, auto_refresh_enabled=False, error=error)
    if state == "interrupted":
        result["interrupted_by_user"] = True
    live_path = run_dir / "stages_live.json"
    live = read(live_path)
    stages = live.get("stages") or {key: value for key, value in live.items() if isinstance(value, dict) and "status" in value} or result.get("stages", {})
    for stage in stages.values():
        if isinstance(stage, dict) and stage.get("status") in {"running", "pending"}:
            stage.update(status="interrupted" if state == "interrupted" else "error", ended_at=now, error=error)
    result["stages"] = stages
    result["coverage"] = summarize_coverage(stages)
    atomic_json(result_path, result)
    atomic_json(live_path, stages)
