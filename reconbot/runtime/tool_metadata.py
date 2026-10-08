"""Bounded, best-effort version evidence for the scanners selected in a run."""
from __future__ import annotations

import shutil
import sys

from reconbot.runtime import processes

VERSION_COMMANDS = {
    "nmap": ("nmap", "--version"),
    "subfinder": ("subfinder", "-version"),
    "dnsx": ("dnsx", "-version"),
    "httpx": ("httpx", "-version"),
    "katana": ("katana", "-version"),
    "gobuster": ("gobuster", "version"),
    "ffuf": ("ffuf", "-V"),
    "nuclei": ("nuclei", "-version"),
    "whatweb": ("whatweb", "--version"),
    "wafw00f": ("wafw00f", "--version"),
    "screenshots": ("gowitness", "version"),
    "historical_urls": ("gau", "--version"),
}


def runtime_metadata(scanners):
    versions = {}
    commands = [VERSION_COMMANDS[name] for name in scanners if name in VERSION_COMMANDS]
    if "historical_urls" in scanners:
        # waybackurls has no stable version flag; record its actual executable.
        versions["waybackurls"] = {"path": shutil.which("waybackurls"), "status": "version_unavailable"}
    for binary, flag in commands:
        executable = shutil.which(binary)
        record = {"path": executable, "status": "missing" if not executable else "version_unavailable"}
        if executable:
            try:
                result = processes.run([executable, flag], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    record.update(status="recorded", version=(result.stdout or result.stderr or "").strip()[:1000])
            except (OSError, processes.TimeoutExpired):
                pass
        versions[binary] = record
    return {"python": {"executable": sys.executable, "version": sys.version.split()[0]}, "tool_versions": versions}
