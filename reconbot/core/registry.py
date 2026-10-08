# reconbot/core/registry.py
from dataclasses import dataclass

@dataclass
class ToolSpec:
    name: str
    binary: str
    required: bool = True
    phase: str = "core"  # core/optional/phase2

TOOLS: list[ToolSpec] = [
    # --- Core discovery / validation ---
    ToolSpec("subfinder", "subfinder", True, "core"),
    ToolSpec("amass", "amass", True, "core"),
    ToolSpec("dnsx", "dnsx", True, "core"),
    ToolSpec("httpx", "httpx", True, "core"),
    ToolSpec("naabu", "naabu", True, "core"),
    ToolSpec("nmap", "nmap", True, "core"),

    # --- Core web/content enumeration ---
    ToolSpec("katana", "katana", True, "core"),
    ToolSpec("ffuf", "ffuf", True, "core"),
    ToolSpec("gobuster", "gobuster", True, "core"),
    ToolSpec("nuclei", "nuclei", True, "core"),
    ToolSpec("testssl.sh", "testssl.sh", True, "core"),
    ToolSpec("jq", "jq", True, "core"),
    ToolSpec("wget", "wget", True, "core"),

    # --- Optional fingerprinting / evidence ---
    ToolSpec("gau", "gau", False, "optional"),
    ToolSpec("waybackurls", "waybackurls", False, "optional"),
    ToolSpec("whatweb", "whatweb", False, "optional"),
    ToolSpec("gowitness", "gowitness", False, "optional"),

    # --- Phase 2 candidates: add engine/CLI integration before GUI ---
    ToolSpec("wafw00f", "wafw00f", False, "phase2"),
    ToolSpec("nikto", "nikto", False, "phase2"),
    ToolSpec("feroxbuster", "feroxbuster", False, "phase2"),
    ToolSpec("dirsearch", "dirsearch", False, "phase2"),
    ToolSpec("sqlmap", "sqlmap", False, "phase2"),
    ToolSpec("hydra", "hydra", False, "phase2"),
]
