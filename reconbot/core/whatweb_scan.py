

from __future__ import annotations

import json
import shutil
from reconbot.runtime import processes as subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable


WHATWEB_TIMEOUT_SEC = 120


def _safe_json_loads(raw_text: str) -> list[dict[str, Any]]:
    """WhatWeb JSON çıktısını toleranslı şekilde parse et."""
    raw_text = (raw_text or "").strip()
    if not raw_text:
        return []

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        rows: list[dict[str, Any]] = []
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                rows.append(parsed)
        return rows

    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def _normalize_plugin_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        joined = ", ".join(str(v) for v in value if v is not None)
        return joined or None
    return str(value)


def _extract_plugins(entry: dict[str, Any]) -> list[dict[str, Any]]:
    plugins = entry.get("plugins")
    if not isinstance(plugins, dict):
        return []

    extracted: list[dict[str, Any]] = []
    for plugin_name, plugin_data in plugins.items():
        item: dict[str, Any] = {
            "name": str(plugin_name),
            "version": None,
            "string": None,
            "os": None,
            "module": None,
            "account": None,
            "website": None,
            "certainty": None,
        }

        if isinstance(plugin_data, dict):
            for field in ("version", "string", "os", "module", "account", "website", "certainty"):
                item[field] = _normalize_plugin_value(plugin_data.get(field))

        extracted.append(item)

    return extracted


def _normalize_entry(target_url: str, entry: dict[str, Any]) -> dict[str, Any]:
    target = str(entry.get("target") or entry.get("url") or target_url)
    summary_text = entry.get("summary")
    http_status = entry.get("http_status")

    if isinstance(http_status, int):
        normalized_status: int | None = http_status
    elif isinstance(http_status, str) and http_status.isdigit():
        normalized_status = int(http_status)
    else:
        normalized_status = None

    plugins = _extract_plugins(entry)

    return {
        "target": target,
        "http_status": normalized_status,
        "summary": str(summary_text) if summary_text is not None else "",
        "plugins": plugins,
        "plugin_names": sorted({plugin.get("name", "") for plugin in plugins if plugin.get("name")}),
        "raw": entry,
    }


def is_whatweb_installed(whatweb_path: str = "whatweb") -> bool:
    return shutil.which(whatweb_path) is not None


def build_whatweb_command(
    target: str,
    *,
    whatweb_path: str = "whatweb",
    aggression: int = 1,
    follow_redirect: str = "never",
    timeout_seconds: int = 90,
    user_agent: str | None = None,
    extra_args: Iterable[str] | None = None,
    json_log_path: str | None = None,
) -> list[str]:
    if not target or not target.strip():
        raise ValueError("target boş olamaz")

    aggression_value = aggression if aggression in {1, 2, 3, 4} else 1
    redirect_value = follow_redirect if follow_redirect in {"never", "same-site", "all"} else "never"
    timeout_value = max(1, int(timeout_seconds))

    command: list[str] = [
        whatweb_path,
        "--color=never",
        "--no-errors",
        f"--aggression={aggression_value}",
        f"--open-timeout={timeout_value}",
        f"--read-timeout={timeout_value}",
        f"--follow-redirect={redirect_value}",
    ]

    if user_agent:
        command.extend(["--user-agent", user_agent])

    if json_log_path:
        command.append(f"--log-json={json_log_path}")
    else:
        command.append("--log-json=-")

    if extra_args:
        command.extend(list(extra_args))

    command.append(target.strip())
    return command


def run_whatweb(
    target: str,
    *,
    whatweb_path: str = "whatweb",
    aggression: int = 1,
    follow_redirect: str = "never",
    timeout_seconds: int = 90,
    user_agent: str | None = None,
    extra_args: Iterable[str] | None = None,
) -> dict[str, Any]:
    """WhatWeb'i subprocess ile çalıştır ve ReconBot pipeline'ına uygun dict döndür.

    Return contract:
    {
        "target": str,
        "available": bool,
        "ok": bool,
        "detected": bool,
        "command": str,
        "entries": list[dict],
        "plugin_names": list[str],
        "stdout": str,
        "stderr": str,
        "returncode": int | None,
        "error": str | None,
    }
    """
    target = (target or "").strip()
    if not target:
        return {
            "target": target,
            "available": False,
            "ok": False,
            "detected": False,
            "command": "",
            "entries": [],
            "plugin_names": [],
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "error": "empty target",
        }

    if not is_whatweb_installed(whatweb_path):
        return {
            "target": target,
            "available": False,
            "ok": False,
            "detected": False,
            "command": "",
            "entries": [],
            "plugin_names": [],
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "error": f"whatweb binary not found: {whatweb_path}",
        }

    with tempfile.TemporaryDirectory(prefix="reconbot_whatweb_") as tmpdir:
        json_log_path = str(Path(tmpdir) / "whatweb.json")
        command = build_whatweb_command(
            target,
            whatweb_path=whatweb_path,
            aggression=aggression,
            follow_redirect=follow_redirect,
            timeout_seconds=timeout_seconds,
            user_agent=user_agent,
            extra_args=extra_args,
            json_log_path=json_log_path,
        )

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=max(5, int(timeout_seconds) + 5),
            )
        except subprocess.TimeoutExpired:
            return {
                "target": target,
                "available": True,
                "ok": False,
                "detected": False,
                "command": " ".join(command),
                "entries": [],
                "plugin_names": [],
                "stdout": "",
                "stderr": "",
                "returncode": None,
                "error": f"whatweb timeout after {timeout_seconds}s",
            }
        except FileNotFoundError:
            return {
                "target": target,
                "available": False,
                "ok": False,
                "detected": False,
                "command": " ".join(command),
                "entries": [],
                "plugin_names": [],
                "stdout": "",
                "stderr": "",
                "returncode": None,
                "error": f"whatweb binary could not be executed: {whatweb_path}",
            }
        except OSError as exc:
            return {
                "target": target,
                "available": True,
                "ok": False,
                "detected": False,
                "command": " ".join(command),
                "entries": [],
                "plugin_names": [],
                "stdout": "",
                "stderr": "",
                "returncode": None,
                "error": f"whatweb os error: {exc}",
            }

        stdout_text = (completed.stdout or "").strip()
        stderr_text = (completed.stderr or "").strip()

        raw_log_text = ""
        json_path = Path(json_log_path)
        if json_path.exists():
            raw_log_text = json_path.read_text(encoding="utf-8", errors="replace")

        parsed_entries = [_normalize_entry(target, item) for item in _safe_json_loads(raw_log_text)]
        plugin_names = sorted(
            {
                plugin.get("name", "")
                for entry in parsed_entries
                for plugin in (entry.get("plugins") or [])
                if isinstance(plugin, dict) and plugin.get("name")
            }
        )
        detected = bool(plugin_names)
        ok = completed.returncode == 0 or bool(parsed_entries)

        error: str | None = None
        if not ok:
            error = stderr_text or stdout_text or f"whatweb exited with code {completed.returncode}"

        return {
            "target": target,
            "available": True,
            "ok": ok,
            "detected": detected,
            "command": " ".join(command),
            "entries": parsed_entries,
            "plugin_names": plugin_names,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "returncode": completed.returncode,
            "error": error,
        }