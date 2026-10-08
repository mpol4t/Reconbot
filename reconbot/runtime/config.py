from __future__ import annotations

from pathlib import Path
from typing import Any
from reconbot.runtime.scanner_settings import flatten_scanner_settings

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore

def _detect_skipped_tools(config: Any) -> list[str]:
    """Return a list of tool names that are explicitly disabled in RunConfig.

    We treat `*_enabled == False` as "skipped".
    """
    tool_fields = [
        ("nmap", "nmap_enabled"),
        ("subfinder", "subfinder_enabled"),
        ("dnsx", "dnsx_enabled"),
        ("httpx", "httpx_enabled"),
        ("katana", "katana_enabled"),
        ("gobuster", "gobuster_enabled"),
        ("ffuf", "ffuf_enabled"),
        ("historical_urls", "historical_urls_enabled"),
        ("screenshots", "screenshots_enable"),
        ("wafw00f", "wafw00f_enabled"),
        ("whatweb", "whatweb_enabled"),
        ("checks", "checks_enabled"),
        ("nuclei", "nuclei_enabled"),
    ]

    skipped: list[str] = []
    for name, field in tool_fields:
        try:
            val = getattr(config, field, None)
        except Exception:
            val = None
        if val is False:
            skipped.append(name)

    return skipped

def _load_yaml_config(path: str) -> dict[str, Any]:
    """Read YAML config and return a dict of defaults.

    Supports two shapes:
      - top-level keys (e.g., {wordlist: ..., output_dir: ...})
      - nested under `reconbot:` (e.g., {reconbot: {wordlist: ...}})

    Missing or malformed files raise ValueError; scanning must not silently use defaults.
    """
    if not path:
        return {}

    cfg_path = Path(path).expanduser().resolve()
    if not cfg_path.exists():
        print(f"[!] Config bulunamadı: {cfg_path}")
        raise ValueError(f"Config bulunamadı: {cfg_path}")

    if yaml is None:
        print("[!] YAML desteği yok. Kur: pip install pyyaml")
        raise ValueError("YAML desteği yok; PyYAML kurulmalı.")

    try:
        raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[!] Config okunamadı: {cfg_path} ({exc})")
        raise ValueError(f"Config okunamadı: {cfg_path}") from exc

    if not isinstance(raw, dict):
        print(f"[!] Config formatı dict olmalı: {cfg_path}")
        raise ValueError("Config formatı dict olmalı")

    # Accept either top-level or nested under `reconbot:`
    inner = raw.get("reconbot") if isinstance(raw.get("reconbot"), dict) else raw
    if not isinstance(inner, dict):
        return {}

    def merge_tool_settings(section: str, values: dict[str, Any]) -> None:
        existing = flat.get("tool_settings") if isinstance(flat.get("tool_settings"), dict) else {}
        merged = dict(existing)
        existing_section = merged.get(section) if isinstance(merged.get(section), dict) else {}
        merged[section] = {**dict(existing_section), **values}
        flat["tool_settings"] = merged

    def merge_top_level_tool_settings(values: dict[str, Any]) -> None:
        existing = flat.get("tool_settings") if isinstance(flat.get("tool_settings"), dict) else {}
        merged = dict(values)
        for section, section_values in dict(existing).items():
            if isinstance(section_values, dict) and isinstance(merged.get(section), dict):
                merged[section] = {**dict(merged[section]), **section_values}
            else:
                merged[section] = section_values
        flat["tool_settings"] = merged

    # Flatten nested sections like:
    # reconbot:
    #   gobuster:
    #     threads: 50
    # into keys like: gobuster_threads=50
    flat: dict[str, Any] = {}
    for k, v in inner.items():
        if isinstance(v, dict) and k in {"traffic", "report", "expansion", "gobuster", "katana", "dnsx", "httpx", "checks", "nuclei", "nmap", "subfinder", "ffuf", "historical_urls", "screenshots", "osint"}:
            if k == "osint":
                merge_tool_settings("osint", dict(v))
            for subk, subv in v.items():
                # Map friendly YAML keys to RunConfig field names
                if k == "screenshots" and subk == "enabled":
                    flat["screenshots_enable"] = subv
                elif k == "osint" and subk == "enabled":
                    flat["osint_enabled"] = subv
                elif k == "osint" and subk == "profile":
                    flat["osint_profile"] = subv
                elif k == "report" and subk == "depth":
                    flat["report_depth"] = subv
                elif subk == "enabled":
                    flat[f"{k}_enabled"] = subv
                elif k == "traffic" and subk == "profile":
                    flat["traffic_profile"] = subv
                elif k == "expansion" and subk == "enabled":
                    flat["expansion_enabled"] = subv
                elif k == "expansion" and subk == "depth":
                    flat["expansion_depth"] = subv
                elif k == "osint":
                    flat[f"osint_{subk}"] = subv
                elif k == "gobuster" and subk == "log_each":
                    flat["gobuster_log_each"] = subv
                elif k == "katana" and subk == "js":
                    flat["katana_js_crawl"] = subv
                elif k == "katana" and subk == "auto_js":
                    flat["katana_auto_js_crawl"] = subv
                elif k == "checks" and subk == "timeout":
                    flat["checks_timeout_sec"] = subv
                elif k == "checks" and subk == "pool_limit":
                    flat["checks_pool_limit"] = subv
                elif k == "nuclei" and subk == "drop_query":
                    flat["nuclei_drop_query"] = subv
                elif k == "nuclei" and subk == "pool_limit":
                    flat["nuclei_pool_limit"] = subv
                elif k == "gobuster" and subk == "allowed_status":
                    flat["gobuster_allowed_status"] = subv
                else:
                    flat[f"{k}_{subk}"] = subv
        elif k == "tool_settings" and isinstance(v, dict):
            merge_top_level_tool_settings(dict(v))
        else:
            flat[k] = v

    return flatten_scanner_settings(flat)


def _apply_config_defaults(args: Any, cfg: dict[str, Any]) -> Any:
    """Apply YAML config values as DEFAULTS to argparse args.

    Rule: if the user provided a CLI value, keep it.
    We only fill fields that are None/"".

    Important: YAML may contain keys that are NOT defined as argparse options
    (e.g., gobuster_enabled). In that case, we still attach them to `args`
    so the engine can receive them via `RunConfig(**config_kwargs)`.
    """
    if not cfg:
        return args

    for key, value in cfg.items():
        if hasattr(args, key):
            current = getattr(args, key)
            is_empty = current is None or current == ""
            if is_empty:
                setattr(args, key, value)
        else:
            # Key exists only in YAML (not a CLI flag). Still keep it.
            setattr(args, key, value)

    return args
