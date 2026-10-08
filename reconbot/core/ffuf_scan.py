from __future__ import annotations

import json
from reconbot.runtime import processes as subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urljoin


DEFAULT_ALLOWED_STATUS: tuple[int, ...] = (200, 204, 301, 302, 307, 308, 401, 403, 405)


def _normalize_base_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if raw.startswith("//"):
        return "https:" + raw
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    return "http://" + raw


def build_ffuf_command(
    *,
    base_url: str,
    wordlist: str,
    output_json_path: str,
    threads: int,
    rate: int,
    timeout: int,
    allowed_status: list[int] | None,
) -> list[str]:
    normalized = _normalize_base_url(base_url)
    target = normalized.rstrip("/") + "/FUZZ"
    allowed = allowed_status or list(DEFAULT_ALLOWED_STATUS)
    allowed_csv = ",".join(str(int(x)) for x in sorted(set(allowed)))

    cmd = [
        "ffuf",
        "-u",
        target,
        "-w",
        str(Path(wordlist).expanduser()),
        "-of",
        "json",
        "-o",
        output_json_path,
        "-mc",
        allowed_csv,
        "-t",
        str(max(1, int(threads))),
        "-timeout",
        str(max(1, int(timeout))),
        "-s",
    ]
    if int(rate or 0) > 0:
        cmd.extend(["-rate", str(int(rate))])
    return cmd


def parse_ffuf_json(
    output_json_path: str | Path,
    *,
    base_url: str = "",
) -> list[dict[str, Any]]:
    path = Path(output_json_path)
    if not path.exists():
        return []

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []

    rows = payload.get("results") if isinstance(payload, dict) else []
    if not isinstance(rows, list):
        return []

    normalized_base = _normalize_base_url(base_url)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int | None]] = set()

    for row in rows:
        if not isinstance(row, dict):
            continue
        url_value = str(row.get("url") or "").strip()
        if not url_value:
            raw_input = str(row.get("input") or "").strip()
            if raw_input and normalized_base:
                url_value = urljoin(normalized_base.rstrip("/") + "/", raw_input.lstrip("/"))
        if not url_value:
            continue

        try:
            status = int(row.get("status", 0) or 0)
        except Exception:
            status = 0
        if status <= 0:
            continue

        length: int | None
        try:
            length = int(row.get("length")) if row.get("length") is not None else None
        except Exception:
            length = None

        words: int | None
        try:
            words = int(row.get("words")) if row.get("words") is not None else None
        except Exception:
            words = None

        lines: int | None
        try:
            lines = int(row.get("lines")) if row.get("lines") is not None else None
        except Exception:
            lines = None

        key = (url_value, status, length)
        if key in seen:
            continue
        seen.add(key)

        findings.append(
            {
                "url": url_value,
                "status": status,
                "content_length": length,
                "words": words,
                "lines": lines,
                "redirect_location": str(
                    row.get("redirectlocation")
                    or row.get("redirect_location")
                    or row.get("location")
                    or ""
                ).strip(),
                "source_tool": "ffuf",
            }
        )

    return findings


def run_ffuf(
    *,
    base_url: str,
    wordlist: str,
    output_json_path: str | Path,
    threads: int = 40,
    rate: int = 0,
    timeout: int = 10,
    allowed_status: list[int] | None = None,
) -> dict[str, Any]:
    output_path = Path(output_json_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = build_ffuf_command(
        base_url=base_url,
        wordlist=wordlist,
        output_json_path=str(output_path),
        threads=threads,
        rate=rate,
        timeout=timeout,
        allowed_status=allowed_status,
    )

    result: dict[str, Any] = {
        "base_url": _normalize_base_url(base_url),
        "output_path": str(output_path),
        "command": cmd,
        "returncode": None,
        "stderr": "",
        "findings": [],
    }

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        result["returncode"] = int(proc.returncode)
        result["stderr"] = (proc.stderr or "").strip()
    except FileNotFoundError:
        result["returncode"] = 127
        result["stderr"] = "ffuf binary not found"
        result["error"] = "ffuf binary not found"
        return result
    except Exception as exc:
        result["returncode"] = 1
        result["stderr"] = str(exc)
        result["error"] = str(exc)
        return result

    try:
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            raise ValueError("ffuf output must contain a results array")
    except (OSError, ValueError) as exc:
        result["error"] = f"Invalid or missing ffuf output: {exc}"
        return result

    findings = parse_ffuf_json(output_path, base_url=base_url)
    result["findings"] = findings

    if int(result.get("returncode") or 0) != 0:
        result["error"] = result.get("stderr") or f"ffuf failed rc={result.get('returncode')}"

    return result
