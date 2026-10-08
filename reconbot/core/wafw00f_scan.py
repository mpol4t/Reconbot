from __future__ import annotations

import json
import shutil
from reconbot.runtime import processes as subprocess
from typing import Any



def _looks_like_json(text: str) -> bool:
    text = (text or "").strip()
    return text.startswith("{") or text.startswith("[")


def _normalize_vendor_text(text: str) -> str | None:
    cleaned = (text or "").strip().strip(".:-")
    if not cleaned:
        return None

    lower = cleaned.lower()
    negative_markers = [
        "no waf detected",
        "not detected",
        "generic detection",
        "none",
        "seems to be behind no waf",
        "no firewall",
    ]
    if any(marker in lower for marker in negative_markers):
        return None

    return cleaned


def _is_negative_waf_line(text: str) -> bool:
    lower = (text or "").strip().lower()
    if not lower:
        return False

    negative_markers = [
        "no waf detected",
        "not detected",
        "generic detection results: none",
        "seems to be behind no waf",
        "no firewall detected",
        "no waf was detected",
    ]
    return any(marker in lower for marker in negative_markers)



def _parse_wafw00f_output(target: str, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
    """Best-effort parse for wafw00f output.

    Supports both JSON-like output (if available in the user's wafw00f version)
    and normal text output. Parsing is intentionally conservative.
    """
    stdout = stdout or ""
    stderr = stderr or ""

    result: dict[str, Any] = {
        "target": target,
        "available": True,
        "detected": False,
        "vendor": None,
        "raw_output": stdout.strip(),
        "stderr": stderr.strip(),
        "returncode": int(returncode),
        "error": None,
    }

    if _looks_like_json(stdout):
        try:
            data = json.loads(stdout)
            result["parsed_json"] = data

            if isinstance(data, dict):
                vendor = _normalize_vendor_text(str(data.get("vendor") or data.get("name") or data.get("waf") or ""))
                detected = data.get("detected")
                if vendor:
                    result["vendor"] = vendor
                if isinstance(detected, bool):
                    result["detected"] = detected and bool(vendor or detected)
                    if not result["detected"]:
                        result["vendor"] = None
                elif result["vendor"]:
                    result["detected"] = True
            elif isinstance(data, list) and data:
                first = data[0]
                if isinstance(first, dict):
                    vendor = _normalize_vendor_text(str(first.get("vendor") or first.get("name") or first.get("waf") or ""))
                    if vendor:
                        result["vendor"] = vendor
                        result["detected"] = True
        except Exception:
            pass

    lower_out = stdout.lower()

    if not result["vendor"]:
        for line in stdout.splitlines():
            clean = line.strip()
            lower = clean.lower()
            if not clean:
                continue

            if _is_negative_waf_line(clean):
                result["detected"] = False
                result["vendor"] = None
                continue

            # Common text patterns from wafw00f style output.
            if "is behind" in lower:
                # Example: "The site is behind Cloudflare"
                vendor = _normalize_vendor_text(clean.split("behind", 1)[-1])
                if vendor:
                    result["vendor"] = vendor
                    result["detected"] = True
                    break

            if "waf" in lower and any(token in lower for token in ["detected", "identified", "behind"]):
                vendor = _normalize_vendor_text(clean)
                if vendor:
                    result["vendor"] = vendor
                    result["detected"] = True
                    break

    no_waf_markers = [
        "no waf detected",
        "seems to be behind no waf",
        "generic detection results: none",
        "no firewall detected",
        "no waf was detected",
        "not detected",
    ]
    if any(marker in lower_out for marker in no_waf_markers):
        result["detected"] = False
        result["vendor"] = None

    if returncode != 0 and not stdout.strip():
        result["error"] = stderr.strip() or f"wafw00f exited with code {returncode}"

    return result



def run_wafw00f(target: str, timeout_sec: int = 90) -> dict[str, Any]:
    """Run wafw00f against a URL target and return normalized results.

    Minimal first version:
    - checks binary availability
    - runs wafw00f with a simple subprocess call
    - returns best-effort parsed output
    """
    target = (target or "").strip()
    if not target:
        return {
            "target": target,
            "available": False,
            "detected": False,
            "vendor": None,
            "raw_output": "",
            "stderr": "",
            "returncode": -1,
            "error": "empty target",
        }

    binary = shutil.which("wafw00f")
    if not binary:
        return {
            "target": target,
            "available": False,
            "detected": False,
            "vendor": None,
            "raw_output": "",
            "stderr": "",
            "returncode": -1,
            "error": "wafw00f binary not found",
        }

    commands_to_try = [
        [binary, target],
        [binary, "-a", target],
    ]

    last_stdout = ""
    last_stderr = ""
    last_returncode = -1

    for cmd in commands_to_try:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                check=False,
            )
            last_stdout = proc.stdout or ""
            last_stderr = proc.stderr or ""
            last_returncode = int(proc.returncode)

            # Accept first command that produced meaningful output.
            if last_stdout.strip() or last_returncode == 0:
                return _parse_wafw00f_output(target, last_stdout, last_stderr, last_returncode)
        except subprocess.TimeoutExpired:
            return {
                "target": target,
                "available": True,
                "detected": False,
                "vendor": None,
                "raw_output": last_stdout.strip(),
                "stderr": last_stderr.strip(),
                "returncode": -1,
                "error": f"wafw00f timeout after {timeout_sec}s",
            }
        except Exception as exc:
            return {
                "target": target,
                "available": True,
                "detected": False,
                "vendor": None,
                "raw_output": last_stdout.strip(),
                "stderr": last_stderr.strip(),
                "returncode": -1,
                "error": str(exc),
            }

    return _parse_wafw00f_output(target, last_stdout, last_stderr, last_returncode)