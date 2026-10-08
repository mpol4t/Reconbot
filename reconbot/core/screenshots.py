from __future__ import annotations

import json
import shutil
from reconbot.runtime import processes as subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _relative_artifact(path: Path, run_dir: Path) -> str:
    try:
        return path.resolve().relative_to(run_dir.resolve()).as_posix()
    except Exception:
        return path.as_posix()


def _is_within_run_dir(path: Path, run_dir: Path) -> bool:
    try:
        path.resolve().relative_to(run_dir.resolve())
        return True
    except Exception:
        return False


_SCREENSHOT_EXTENSIONS = (".jpeg", ".jpg", ".png", ".webp")


def _normalize_http_url(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parts = urlsplit(raw)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return ""
    host = (parts.hostname or "").lower().strip(".")
    if not host:
        return ""
    port = ""
    try:
        if parts.port is not None:
            port = f":{parts.port}"
    except ValueError:
        return ""
    netloc = f"{host}{port}"
    if parts.username or parts.password:
        return ""
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def _host_in_scope(host: str, scope_hosts: set[str], root_domain: str = "") -> bool:
    clean_host = (host or "").lower().strip(".")
    if not clean_host:
        return False
    if clean_host in scope_hosts:
        return True
    root = (root_domain or "").lower().strip(".")
    if root and (clean_host == root or clean_host.endswith("." + root)):
        return True
    return False


def _scope_from_target(target: str) -> tuple[set[str], str]:
    scope_hosts: set[str] = set()
    root_domain = ""

    target_text = str(target or "").strip()
    target_parts = urlsplit(target_text if "://" in target_text else f"http://{target_text}")
    target_host = (target_parts.hostname or "").lower().strip(".")
    if target_host:
        scope_hosts.add(target_host)
        if "://" not in target_text:
            root_domain = target_host

    return scope_hosts, root_domain


def select_screenshot_urls(
    *,
    target: str,
    httpx_live_urls: list[Any] | None = None,
    web_check_urls: list[Any] | None = None,
    historical_live_urls: list[Any] | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Select capped, in-scope, already-live URLs for visual evidence."""
    sources: list[tuple[str, Any]] = []
    for item in httpx_live_urls or []:
        sources.append(("httpx", item))
    for item in web_check_urls or []:
        sources.append(("web_checks", item))
    for item in historical_live_urls or []:
        sources.append(("historical_urls", item))

    normalized_all: list[tuple[str, str]] = []
    for source, raw_url in sources:
        normalized = _normalize_http_url(raw_url)
        if normalized:
            normalized_all.append((source, normalized))

    scope_hosts, root_domain = _scope_from_target(target)

    selected: list[dict[str, str]] = []
    seen: set[str] = set()
    dropped_out_of_scope = 0
    dropped_duplicate = 0
    max_items = max(0, int(limit or 0))

    for source, url in normalized_all:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().strip(".")
        if not _host_in_scope(host, scope_hosts, root_domain):
            dropped_out_of_scope += 1
            continue
        if url in seen:
            dropped_duplicate += 1
            continue
        seen.add(url)
        if len(selected) >= max_items:
            continue
        selected.append({"url": url, "source": source})

    reason_order = []
    for item in selected:
        source = item["source"]
        if source not in reason_order:
            reason_order.append(source)

    return {
        "received": len(normalized_all),
        "selected": selected,
        "selected_count": len(selected),
        "max": max_items,
        "reason": ",".join(reason_order) if reason_order else "none",
        "dropped_out_of_scope": dropped_out_of_scope,
        "dropped_duplicate": dropped_duplicate,
    }


def _extract_web_check_urls(checks_results: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for item in checks_results.get("technology_fingerprint", []) if isinstance(checks_results, dict) else []:
        if isinstance(item, dict) and item.get("site"):
            urls.append(str(item.get("site")))
    for key in ("login_pages", "captcha_pages", "docs_pages", "rate_limit_signals"):
        for item in checks_results.get(key, []) if isinstance(checks_results.get(key), list) else []:
            if isinstance(item, dict) and item.get("url"):
                urls.append(str(item.get("url")))
    return urls


def _extract_historical_live_urls(historical_results: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    if not isinstance(historical_results, dict):
        return urls
    interesting = historical_results.get("interesting_live_urls")
    if isinstance(interesting, list):
        for item in interesting:
            if isinstance(item, dict) and item.get("url"):
                urls.append(str(item.get("url")))
    if urls:
        return urls
    for item in historical_results.get("records", []) if isinstance(historical_results.get("records"), list) else []:
        if isinstance(item, dict) and item.get("live") and item.get("url"):
            urls.append(str(item.get("url")))
    return urls


def _parse_gowitness_jsonl(path: Path) -> dict[str, dict[str, Any]]:
    by_url: dict[str, dict[str, Any]] = {}
    if not path.exists():
        return by_url
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return by_url
    for line in lines:
        text = line.strip()
        if not text.startswith("{"):
            continue
        try:
            item = json.loads(text)
        except Exception:
            continue
        if not isinstance(item, dict):
            continue
        url = _normalize_http_url(
            item.get("url")
            or item.get("target")
            or item.get("final_url")
            or item.get("input")
        )
        if not url:
            continue
        by_url[url] = item
    return by_url


def _resolve_screenshot_file_path(raw_path: Any, *, output_dir: Path, run_dir: Path) -> Path | None:
    raw = str(raw_path or "").strip()
    if not raw:
        return None
    p = Path(raw)
    candidates: list[Path]
    if p.is_absolute():
        candidates = [p]
    else:
        candidates = [run_dir / p]
        if len(p.parts) == 1:
            candidates.append(output_dir / p)
        else:
            candidates.append(output_dir / p.name)
    for candidate in candidates:
        try:
            if (
                candidate.exists()
                and candidate.is_file()
                and candidate.suffix.lower() in _SCREENSHOT_EXTENSIONS
                and _is_within_run_dir(candidate, run_dir)
            ):
                return candidate
        except Exception:
            continue
    return None


def _iter_json_objects(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        found.append(value)
        for child in value.values():
            found.extend(_iter_json_objects(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_iter_json_objects(child))
    return found


def _parse_gowitness_index_mapping(index_path: Path, *, output_dir: Path, run_dir: Path) -> dict[str, str]:
    """Return URL -> relative screenshot path from a gowitness-style index, when present."""
    if not index_path.exists():
        return {}
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    by_url: dict[str, str] = {}
    url_keys = ("url", "target", "final_url", "input")
    path_keys = ("screenshot_path", "screenshot", "path", "file", "filename")
    for item in _iter_json_objects(payload):
        url = ""
        for key in url_keys:
            url = _normalize_http_url(item.get(key))
            if url:
                break
        if not url:
            continue
        for key in path_keys:
            candidate = _resolve_screenshot_file_path(
                item.get(key),
                output_dir=output_dir,
                run_dir=run_dir,
            )
            if candidate is not None:
                by_url[url] = _relative_artifact(candidate, run_dir)
                break
    return by_url


def _gowitness_filename_stem(url: str) -> str:
    """Map a selected URL to the gowitness screenshot filename stem."""
    normalized = _normalize_http_url(url) or str(url or "").strip()
    parts = urlsplit(normalized)
    if not parts.scheme or not parts.netloc:
        return ""
    netloc = parts.netloc
    if "@" in netloc:
        return ""
    raw = f"{parts.scheme}://{netloc}{parts.path or '/'}"
    if parts.query:
        raw = f"{raw}?{parts.query}"
    replacements = {
        "://": "---",
        ":": "-",
        "/": "-",
        "\\": "-",
        "?": "-",
        "&": "-",
        "=": "-",
        "#": "-",
        "%": "-",
        "[": "-",
        "]": "-",
    }
    stem = raw
    for old, new in replacements.items():
        stem = stem.replace(old, new)
    return stem


def _looks_like_flag_or_command_error(stderr_text: str, stdout_text: str = "") -> bool:
    text = f"{stderr_text or ''}\n{stdout_text or ''}".lower()
    return any(
        marker in text
        for marker in (
            "unknown flag",
            "unknown shorthand",
            "unknown command",
            "flag provided but not defined",
            "unknown subcommand",
        )
    )


def _discover_image_files(output_dir: Path, *, run_dir: Path) -> list[Path]:
    files: list[Path] = []
    if not output_dir.exists():
        return files
    for ext in _SCREENSHOT_EXTENSIONS:
        for candidate in output_dir.rglob(f"*{ext}"):
            try:
                if candidate.is_file() and _is_within_run_dir(candidate, run_dir):
                    files.append(candidate)
            except Exception:
                continue
    return sorted(set(files), key=lambda item: item.as_posix())


def _command_for_metadata(command: list[str], *, run_dir: Path) -> list[str]:
    display: list[str] = []
    for idx, part in enumerate(command):
        if idx == 0:
            display.append("gowitness")
            continue
        text = str(part)
        try:
            p = Path(text)
            if p.is_absolute():
                display.append(_relative_artifact(p, run_dir))
                continue
        except Exception:
            pass
        display.append(text)
    return display


def _run_command_with_deadline(command: list[str], *, deadline: float) -> subprocess.CompletedProcess[str]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired(command, 0)
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=remaining,
        shell=False,
    )


def _find_screenshot_file(
    *,
    url: str,
    output_dir: Path,
    json_item: dict[str, Any] | None,
    run_dir: Path,
    index_mapping: dict[str, str] | None = None,
) -> str:
    candidates: list[Path] = []
    normalized_url = _normalize_http_url(url)
    if normalized_url and isinstance(index_mapping, dict):
        indexed = _resolve_screenshot_file_path(
            index_mapping.get(normalized_url),
            output_dir=output_dir,
            run_dir=run_dir,
        )
        if indexed is not None:
            return _relative_artifact(indexed, run_dir)

    if isinstance(json_item, dict):
        for key in ("screenshot_path", "screenshot", "path", "file", "filename"):
            resolved = _resolve_screenshot_file_path(
                json_item.get(key),
                output_dir=output_dir,
                run_dir=run_dir,
            )
            if resolved is not None:
                return _relative_artifact(resolved, run_dir)

    stem = _gowitness_filename_stem(url)
    files = _discover_image_files(output_dir, run_dir=run_dir)
    if stem:
        for p in files:
            if p.stem == stem:
                candidates.append(p)
        for p in files:
            if p.stem.lower() == stem.lower():
                candidates.append(p)

    for candidate in candidates:
        try:
            if candidate.exists() and candidate.is_file() and _is_within_run_dir(candidate, run_dir):
                return _relative_artifact(candidate, run_dir)
        except Exception:
            continue
    return ""


def _metadata_from_selection(
    selected: list[dict[str, str]],
    *,
    status: str,
    capture_error: str = "",
) -> list[dict[str, Any]]:
    timestamp = _now_iso()
    return [
        {
            "url": item["url"],
            "screenshot_path": "",
            "status": status,
            "title": "",
            "source": item["source"],
            "capture_error": capture_error,
            "timestamp": timestamp,
        }
        for item in selected
    ]


def _write_metadata(
    *,
    run_dir: Path,
    screenshots_dir: Path,
    payload: dict[str, Any],
) -> dict[str, Any]:
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "screenshots.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (screenshots_dir / "index.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return payload


def repair_screenshot_metadata(
    run_dir: Path | str,
    screenshots: dict[str, Any] | None = None,
    *,
    write: bool = True,
) -> tuple[dict[str, Any], int]:
    """Repair screenshot metadata by mapping selected URLs to files already on disk."""
    run_path = Path(run_dir).resolve()
    screenshots_path = run_path / "screenshots.json"
    screenshots_dir = run_path / "screenshots"
    files_dir = screenshots_dir / "files"

    payload: dict[str, Any] = {}
    if isinstance(screenshots, dict) and screenshots:
        payload = dict(screenshots)
    elif screenshots_path.exists():
        try:
            loaded = json.loads(screenshots_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                payload = loaded
        except Exception:
            payload = {}

    entries = payload.get("entries") if isinstance(payload.get("entries"), list) else []
    if not payload or not entries or not files_dir.exists():
        return payload, 0

    index_mapping = _parse_gowitness_index_mapping(
        screenshots_dir / "index.json",
        output_dir=files_dir,
        run_dir=run_path,
    )

    repaired = 0
    captured_count = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        url = _normalize_http_url(entry.get("url"))
        if not url:
            continue
        existing = _resolve_screenshot_file_path(
            entry.get("screenshot_path"),
            output_dir=files_dir,
            run_dir=run_path,
        )
        screenshot_path = (
            _relative_artifact(existing, run_path)
            if existing is not None
            else _find_screenshot_file(
                url=url,
                output_dir=files_dir,
                json_item=None,
                run_dir=run_path,
                index_mapping=index_mapping,
            )
        )
        if screenshot_path:
            if entry.get("screenshot_path") != screenshot_path or entry.get("status") != "captured" or entry.get("capture_error"):
                repaired += 1
            entry["screenshot_path"] = screenshot_path
            entry["status"] = "captured"
            entry["capture_error"] = ""
            captured_count += 1
        elif entry.get("status") == "missing_file" or not entry.get("screenshot_path"):
            entry["status"] = "missing_file"
            entry["screenshot_path"] = ""
            entry["capture_error"] = "screenshot file not found for selected URL"

    if captured_count:
        payload["status"] = "done"
    if write and repaired:
        _write_metadata(run_dir=run_path, screenshots_dir=screenshots_dir, payload=payload)
    return payload, repaired


def capture_screenshots(
    *,
    target: str,
    run_dir: Path,
    httpx_live_urls: list[Any] | None,
    checks_results: dict[str, Any],
    historical_results: dict[str, Any],
    limit: int = 20,
    timeout_sec: int = 90,
) -> dict[str, Any]:
    screenshots_dir = run_dir / "screenshots"
    files_dir = screenshots_dir / "files"
    input_path = screenshots_dir / "targets.txt"
    jsonl_path = screenshots_dir / "gowitness.jsonl"

    web_check_urls = _extract_web_check_urls(checks_results)
    historical_live_urls = _extract_historical_live_urls(historical_results)
    selection = select_screenshot_urls(
        target=target,
        httpx_live_urls=httpx_live_urls or [],
        web_check_urls=web_check_urls,
        historical_live_urls=historical_live_urls,
        limit=limit,
    )
    selected = selection["selected"]
    received = int(selection.get("received", 0) or 0)
    selected_count = int(selection.get("selected_count", 0) or 0)
    max_items = int(selection.get("max", 0) or 0)
    reason = str(selection.get("reason") or "none")

    base_payload: dict[str, Any] = {
        "enabled": True,
        "tool": "gowitness",
        "received": received,
        "selected_count": selected_count,
        "max": max_items,
        "reason": reason,
        "warnings": [],
        "selection": selection,
        "artifacts": {
            "index_json": "screenshots/index.json",
            "metadata_json": "screenshots.json",
            "input": "screenshots/targets.txt",
            "output_dir": "screenshots/files",
        },
        "entries": [],
    }

    screenshots_dir.mkdir(parents=True, exist_ok=True)
    files_dir.mkdir(parents=True, exist_ok=True)
    input_path.write_text("\n".join(item["url"] for item in selected), encoding="utf-8")

    if not selected:
        base_payload["status"] = "empty"
        return _write_metadata(run_dir=run_dir, screenshots_dir=screenshots_dir, payload=base_payload)

    binary = shutil.which("gowitness")
    if not binary:
        warning = "gowitness not installed; screenshot capture skipped"
        base_payload["status"] = "missing_tool"
        base_payload["warnings"].append(warning)
        base_payload["entries"] = _metadata_from_selection(
            selected,
            status="skipped",
            capture_error=warning,
        )
        return _write_metadata(run_dir=run_dir, screenshots_dir=screenshots_dir, payload=base_payload)

    command = [
        binary,
        "scan",
        "file",
        "-f",
        str(input_path),
        "--screenshot-path",
        str(files_dir),
        "--write-jsonl",
        "--jsonl-file",
        str(jsonl_path),
        "--quiet",
    ]
    fallback_command = [
        binary,
        "scan",
        "file",
        "-f",
        str(input_path),
        "--screenshot-path",
        str(files_dir),
        "--quiet",
    ]
    legacy_command = [
        binary,
        "--disable-db",
        "--screenshot-path",
        str(files_dir),
        "file",
        "--source",
        str(input_path),
    ]
    command_status = "success"
    command_error = ""
    stdout = ""
    stderr = ""
    exit_code: int | None = None
    executed_command = command
    try:
        timeout_value = max(1, int(timeout_sec or 90))
    except Exception:
        timeout_value = 90
    deadline = time.monotonic() + timeout_value
    try:
        completed = _run_command_with_deadline(command, deadline=deadline)
        exit_code = int(completed.returncode)
        stdout = (completed.stdout or "")[-4000:]
        stderr = (completed.stderr or "")[-4000:]
        if completed.returncode != 0:
            command_status = "error"
            command_error = stderr or stdout or f"gowitness exited with {completed.returncode}"
            if _looks_like_flag_or_command_error(stderr, stdout):
                retry = _run_command_with_deadline(fallback_command, deadline=deadline)
                executed_command = fallback_command
                exit_code = int(retry.returncode)
                stdout = (retry.stdout or "")[-4000:]
                stderr = (retry.stderr or "")[-4000:]
                if retry.returncode == 0:
                    command_status = "success"
                    command_error = ""
                else:
                    command_error = stderr or stdout or f"gowitness exited with {retry.returncode}"
                    if _looks_like_flag_or_command_error(stderr, stdout):
                        legacy = _run_command_with_deadline(legacy_command, deadline=deadline)
                        executed_command = legacy_command
                        exit_code = int(legacy.returncode)
                        stdout = (legacy.stdout or "")[-4000:]
                        stderr = (legacy.stderr or "")[-4000:]
                        if legacy.returncode == 0:
                            command_status = "success"
                            command_error = ""
                        else:
                            command_error = stderr or stdout or f"gowitness exited with {legacy.returncode}"
    except subprocess.TimeoutExpired as exc:
        command_status = "timeout"
        command_error = f"gowitness timed out after {timeout_value} seconds"
        exit_code = None
        stdout = str(getattr(exc, "stdout", "") or "")[-4000:]
        stderr = str(getattr(exc, "stderr", "") or "")[-4000:]
    except Exception as exc:
        command_status = "error"
        command_error = str(exc)
        exit_code = None

    produced_files = _discover_image_files(files_dir, run_dir=run_dir)
    json_by_url = _parse_gowitness_jsonl(jsonl_path)
    index_mapping = _parse_gowitness_index_mapping(
        screenshots_dir / "index.json",
        output_dir=files_dir,
        run_dir=run_dir,
    )
    entries: list[dict[str, Any]] = []
    timestamp = _now_iso()
    for item in selected:
        url = item["url"]
        json_item = json_by_url.get(url, {})
        screenshot_path = _find_screenshot_file(
            url=url,
            output_dir=files_dir,
            json_item=json_item,
            run_dir=run_dir,
            index_mapping=index_mapping,
        )
        if screenshot_path:
            status = "captured"
        elif command_status == "success":
            status = "missing_file"
        else:
            status = command_status
        title = ""
        if isinstance(json_item, dict):
            title = str(json_item.get("title") or json_item.get("page_title") or "")
        entries.append(
            {
                "url": url,
                "screenshot_path": screenshot_path,
                "status": status,
                "title": title,
                "source": item["source"],
                "capture_error": "" if screenshot_path else (command_error or "screenshot file not found for selected URL"),
                "timestamp": timestamp,
            }
        )

    captured_count = sum(1 for entry in entries if entry.get("screenshot_path"))
    missing_url_count = sum(1 for entry in entries if not entry.get("screenshot_path"))
    final_status = command_status
    if selected_count > 0:
        if captured_count == 0:
            final_status = "failed" if command_status == "success" else command_status
            no_file_warning = "Screenshot capture ran but produced no image files."
            if no_file_warning not in base_payload["warnings"]:
                base_payload["warnings"].append(no_file_warning)
            if not command_error:
                command_error = no_file_warning
        elif missing_url_count > 0:
            final_status = "partial"
        elif command_status == "success":
            final_status = "done"

    base_payload.update(
        {
            "status": final_status,
            "command": _command_for_metadata(executed_command, run_dir=run_dir),
            "exit_code": exit_code,
            "stdout_tail": stdout,
            "stderr_tail": stderr,
            "produced_file_count": len(produced_files),
            "produced_files": [_relative_artifact(path, run_dir) for path in produced_files[:100]],
            "captured_count": captured_count,
            "missing_url_count": missing_url_count,
            "entries": entries,
        }
    )
    if command_error and command_error not in base_payload["warnings"]:
        base_payload["warnings"].append(command_error)

    return _write_metadata(run_dir=run_dir, screenshots_dir=screenshots_dir, payload=base_payload)
