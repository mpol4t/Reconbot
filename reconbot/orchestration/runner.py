from __future__ import annotations

import inspect
import json
import os
import time
import webbrowser
from pathlib import Path
from typing import Any

from reconbot.core.engine import RunConfig, run as run_engine
from reconbot.core.models import nuclei_to_findings
from reconbot.core.nuclei_scan import parse_nuclei_output
from reconbot.orchestration.gui_bootstrap import _start_gui_app_server, _start_gui_bootstrap_server
from reconbot.orchestration.osint import build_osint_enrichment
from reconbot.report.builder import generate_report
from reconbot.report.depth import resolve_report_depth
from reconbot.runtime.config import _apply_config_defaults, _detect_skipped_tools, _load_yaml_config
from reconbot.runtime.processes import process_scope
from reconbot.runtime.run_lifecycle import mark_terminal, atomic_json
from reconbot.core.checks import preflight_check
from reconbot.runtime.scanner_settings import enabled_scanners
from reconbot.runtime.tool_metadata import runtime_metadata
from reconbot.runtime.output import _prepare_output_dirs, sync_latest
from reconbot.runtime.state import (
    _now_iso,
    _read_nuclei_jsonl_findings,
    _read_run_result_json,
    _update_nuclei_stage,
    _write_run_result_json,
)


def _normalize_status_codes(value: Any) -> list[int]:
    parsed_codes: list[int] = []
    if isinstance(value, list):
        for x in value:
            try:
                parsed_codes.append(int(x))
            except Exception:
                pass
        return parsed_codes
    raw_codes = str(value)
    for part in raw_codes.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            parsed_codes.append(int(part))
        except Exception:
            pass
    return parsed_codes


def _normalize_run_mode(value: Any) -> str:
    normalized = str(value or "normal_scan_only").strip().lower()
    allowed = {"normal_scan_only", "osint_only", "normal_scan_plus_osint"}
    return normalized if normalized in allowed else "normal_scan_only"


def _normalize_scan_profile(value: Any) -> str:
    normalized = str(value or "balanced").strip().lower()
    allowed = {"fast", "balanced", "slow"}
    return normalized if normalized in allowed else "balanced"


def _normalize_osint_profile(value: Any) -> str:
    normalized = str(value or "safe_mvp").strip().lower()
    return "safe_mvp" if normalized != "safe_mvp" else normalized


def _tool_settings_from_args(args: Any) -> dict[str, Any]:
    raw = getattr(args, "tool_settings", None)
    return raw if isinstance(raw, dict) else {}


def _run_config_snapshot(config: RunConfig) -> dict[str, Any]:
    return {
        "run_mode": _normalize_run_mode(getattr(config, "run_mode", None)),
        "scan_profile": _normalize_scan_profile(getattr(config, "scan_profile", None)),
        "osint_enabled": bool(getattr(config, "osint_enabled", False)),
        "osint_profile": _normalize_osint_profile(getattr(config, "osint_profile", None)),
        "tool_settings": getattr(config, "tool_settings", None) if isinstance(getattr(config, "tool_settings", None), dict) else {},
    }


def run_from_parsed_args(args: Any) -> None:
    try:
        with process_scope():
            _run_from_parsed_args(args)
    except SystemExit as exc:
        if exc.code and getattr(args, "_run_dir", None):
            mark_terminal(Path(args._run_dir), args.target, "interrupted" if exc.code == 130 else "failed", f"Çıkış kodu: {exc.code}")
        raise
    except KeyboardInterrupt:
        if getattr(args, "_run_dir", None):
            mark_terminal(Path(args._run_dir), args.target, "interrupted", "Operatör tarafından durduruldu")
        raise SystemExit(130)
    except Exception as exc:
        if getattr(args, "_run_dir", None):
            mark_terminal(Path(args._run_dir), args.target, "failed", str(exc))
        print(f"[!] {exc}", flush=True)
        raise SystemExit(1) from exc


def _run_from_parsed_args(args: Any) -> None:
    target = args.target
    target_text = str(target or "").strip().lower()

    if target_text in {"app", "gui", "dashboard"}:
        config_path = getattr(args, "config", None)
        if not config_path:
            default_config = Path("config.yaml")
            if default_config.exists():
                config_path = str(default_config)
        cfg = _load_yaml_config(config_path or "") if config_path else {}
        if cfg:
            print(f"[+] Config yüklendi: {config_path}")
        base_output_dir = getattr(args, "output_dir", None) or cfg.get("output_dir")
        if target_text in {"app", "gui"} and not bool(getattr(args, "web", False)):
            from reconbot.gui.desktop_app import start_desktop_app

            raise SystemExit(
                start_desktop_app(
                    base_output_dir=base_output_dir,
                    config_defaults=cfg,
                    project_root=Path(__file__).resolve().parents[2],
                )
            )

        gui_server, gui_url = _start_gui_app_server(
            base_output_dir=base_output_dir,
            config_defaults=cfg,
        )
        if not gui_server or not gui_url:
            print("[!] Reconbot app başlatılamadı.")
            return
        print(f"[+] Reconbot app hazır: {gui_url}")
        try:
            webbrowser.open(gui_url)
        except Exception:
            pass
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print("[i] Reconbot app kapatılıyor.")
            try:
                gui_server.shutdown()
            except Exception:
                pass
        return

    if target_text == "generate-report":
        cfg = _load_yaml_config(args.config or "") if getattr(args, "config", None) else {}
        if cfg:
            print(f"[+] Config yüklendi: {args.config}")
        args = _apply_config_defaults(args, cfg)
        try:
            resolve_report_depth(getattr(args, "report_depth", None))
        except ValueError as exc:
            raise

        run_dir_raw = str(getattr(args, "run_dir", "") or "").strip()
        if not run_dir_raw:
            raise ValueError("generate-report modu için --run-dir zorunlu.")

        run_dir = Path(run_dir_raw).expanduser().resolve()
        run_result_path = run_dir / "run_result.json"
        if not run_result_path.exists():
            raise ValueError(f"run_result.json bulunamadı: {run_result_path}")

        run_payload = _read_run_result_json(run_result_path)
        if not isinstance(run_payload, dict) or not run_payload:
            raise ValueError(f"Geçerli run_result.json okunamadı: {run_result_path}")

        data = run_payload.get("data") if isinstance(run_payload.get("data"), dict) else {}
        meta = run_payload.get("meta") if isinstance(run_payload.get("meta"), dict) else {}
        target_value = str(meta.get("target") or run_payload.get("target") or "")
        mode_value = str(meta.get("mode") or run_payload.get("mode") or "")
        skipped_tools_value = run_payload.get("skipped_tools")
        if not isinstance(skipped_tools_value, list):
            skipped_tools_value = []

        gobuster_results = data.get("gobuster_results", run_payload.get("gobuster_results", {}))
        katana_urls = data.get("katana_urls", run_payload.get("katana_urls", []))
        checks_results = data.get("checks_results", run_payload.get("checks_results", {}))
        nuclei_results = data.get("nuclei_results", run_payload.get("nuclei_results", {}))
        nmap_output = data.get("nmap_output", run_payload.get("nmap_output", ""))

        generate_report(
            gobuster_results if isinstance(gobuster_results, dict) else {},
            katana_urls if isinstance(katana_urls, list) else [],
            checks_results if isinstance(checks_results, dict) else {},
            nuclei_results if isinstance(nuclei_results, dict) else {},
            target_value,
            str(nmap_output or ""),
            skipped_tools=skipped_tools_value,
            output_dir=run_dir,
            report_depth=getattr(args, "report_depth", None),
            open_browser=False,
            quiet=False,
        )
        print(f"[+] report.html fixture'dan yeniden üretildi: {run_dir / 'report.html'}")
        if not target_value:
            print("[i] Not: run_result.json içinde target bulunamadı; rapor boş target ile üretildi.")
        if not mode_value:
            print("[i] Not: run_result.json içinde mode bulunamadı.")
        return

    if target_text == "validate-decision-fixtures":
        from reconbot.report.fixtures_validation import (
            validate_decision_fixtures,
        )

        project_root = Path(__file__).resolve().parents[2]
        is_ok = validate_decision_fixtures(project_root=project_root)
        if not is_ok:
            raise SystemExit(1)
        return

    if target_text == "validate-correlation-fixtures":
        from reconbot.report.correlation_fixtures import (
            validate_correlation_fixtures,
        )

        project_root = Path(__file__).resolve().parents[2]
        is_ok = validate_correlation_fixtures(project_root=project_root)
        if not is_ok:
            raise SystemExit(1)
        return

    cfg = _load_yaml_config(args.config or "") if getattr(args, "config", None) else {}
    if cfg:
        print(f"[+] Config yüklendi: {args.config}")
    args = _apply_config_defaults(args, cfg)
    try:
        resolve_report_depth(getattr(args, "report_depth", None))
    except ValueError as exc:
        raise

    if getattr(args, "gobuster_allowed_status", None) is not None:
        args.gobuster_allowed_status = _normalize_status_codes(args.gobuster_allowed_status)
    if getattr(args, "ffuf_allowed_status", None) is not None:
        args.ffuf_allowed_status = _normalize_status_codes(args.ffuf_allowed_status)

    target = args.target
    run_mode_value = _normalize_run_mode(getattr(args, "run_mode", None))
    osint_enabled_value = run_mode_value in {"osint_only", "normal_scan_plus_osint"}
    setattr(args, "run_mode", run_mode_value)
    setattr(args, "osint_enabled", osint_enabled_value)
    setattr(args, "scan_profile", _normalize_scan_profile(getattr(args, "scan_profile", None)))
    setattr(args, "osint_profile", _normalize_osint_profile(getattr(args, "osint_profile", None)))
    gobuster_enabled_flag = getattr(args, "gobuster_enabled", None)
    gobuster_enabled = True if gobuster_enabled_flag is None else bool(gobuster_enabled_flag)
    ffuf_enabled_flag = getattr(args, "ffuf_enabled", None)
    ffuf_enabled = False if ffuf_enabled_flag is None else bool(ffuf_enabled_flag)

    wordlist = args.wordlist
    if run_mode_value != "osint_only" and (gobuster_enabled or ffuf_enabled) and not wordlist:
        print("[!] Wordlist zorunlu (Gobuster/FFUF aktif). CLI ile -w/--wordlist ver veya config.yaml içine 'wordlist' koy.")
        raise ValueError("Wordlist zorunlu (Gobuster/FFUF aktif).")

    if wordlist:
        wordlist = str(Path(wordlist).expanduser())
        args.wordlist = wordlist

    target_text = (target or "").strip().lower()
    is_url_target = target_text.startswith("http://") or target_text.startswith("https://")

    run_dir, latest_dir, base_dir_str = _prepare_output_dirs(getattr(args, "output_dir", None))

    args._run_dir = str(run_dir)

    print(f"[+] Output (base):   {base_dir_str}")
    print(f"[+] Output (run):    {run_dir}")
    print(f"[+] Output (latest): {latest_dir}")

    config_kwargs: dict[str, Any] = {"target": target, "wordlist": wordlist or ""}
    config_kwargs["output_dir"] = str(run_dir)

    pass_through_fields = [
        "verbose",
        "traffic_profile",
        "nmap_timing",
        "nmap_top_ports",
        "nmap_timeout_sec",
        "katana_timeout_sec",
        "katana_rate_limit",
        "katana_max_urls",
        "nuclei_timeout_sec",
        "subfinder_rate_limit",
        "dnsx_rate_limit",
        "httpx_rate_limit",
        "dnsx_batch",
        "httpx_batch",
        "gobuster_threads",
        "gobuster_timeout",
        "gobuster_allowed_status",
        "ffuf_threads",
        "ffuf_rate",
        "ffuf_timeout",
        "ffuf_allowed_status",
        "historical_urls_enabled",
        "historical_urls_max_domains",
        "historical_urls_max_urls",
        "historical_urls_live_check_limit",
        "historical_urls_timeout_sec",
        "screenshots_enable",
        "screenshots_limit",
        "screenshots_timeout",
        "report_depth",
        "katana_depth",
        "expansion_enabled",
        "expansion_depth",
        "katana_js_crawl",
        "katana_auto_js_crawl",
        "checks_max_urls",
        "checks_timeout_sec",
        "checks_max_body_bytes",
        "checks_follow_redirects",
        "checks_pool_limit",
        "nuclei_severity",
        "nuclei_rate_limit",
        "nuclei_drop_query",
        "nuclei_pool_limit",
        "detailed_nmap_enabled",
        "ip_enrichment",
        "nmap_enabled",
        "subfinder_enabled",
        "dnsx_enabled",
        "httpx_enabled",
        "katana_enabled",
        "gobuster_enabled",
        "ffuf_enabled",
        "checks_enabled",
        "nuclei_enabled",
        "wafw00f_enabled",
        "whatweb_enabled",
        "gobuster_log_each",
        "run_mode",
        "scan_profile",
        "osint_enabled",
        "osint_profile",
        "tool_settings",
    ]

    try:
        sig = inspect.signature(RunConfig)
        if is_url_target:
            for forced_field in ("subfinder_enabled", "dnsx_enabled", "httpx_enabled"):
                if forced_field in sig.parameters:
                    config_kwargs[forced_field] = False

        for field in pass_through_fields:
            if field in sig.parameters and getattr(args, field, None) is not None:
                if is_url_target and field in {"subfinder_enabled", "dnsx_enabled", "httpx_enabled"}:
                    continue
                config_kwargs[field] = getattr(args, field)

        config = RunConfig(**config_kwargs)
        config.run_mode = _normalize_run_mode(getattr(config, "run_mode", None))
        config.scan_profile = _normalize_scan_profile(getattr(config, "scan_profile", None))
        config.osint_profile = _normalize_osint_profile(getattr(config, "osint_profile", None))
        config.osint_enabled = config.run_mode in {"osint_only", "normal_scan_plus_osint"}
        skipped_tools = _detect_skipped_tools(config)

    except Exception as exc:
        raise ValueError(f"Tarama ayarları geçersiz: {exc}") from exc

    if config.run_mode != "osint_only" and not os.environ.get("RECONBOT_SKIP_PREFLIGHT"):
        from reconbot.core.nmap_scan import _detect_target_mode
        # Fingerprinting/evidence tools may be missing without blocking the run;
        # their stages will explicitly record missing/failed coverage.
        optional = {"historical_urls", "screenshots", "wafw00f", "whatweb", "checks"}
        required = [name for name in enabled_scanners(config, _detect_target_mode(target)) if name not in optional]
        preflight_check(required)

    atomic_json(run_dir / "app_config.yaml", {"reconbot": vars(config)})
    mode = "url" if is_url_target else "domain_or_ip"
    suppress_report_open = os.environ.get("RECONBOT_SUPPRESS_REPORT_OPEN") == "1"
    gui_server = None
    gui_url = None
    if bool(getattr(args, "gui", False)):
        gui_initial_state = {
            "target": target,
            "mode": mode,
            "skipped_tools": skipped_tools,
            "traffic_profile": getattr(config, "traffic_profile", None),
            "report_depth": getattr(config, "report_depth", None),
        }
        gui_server, gui_url = _start_gui_bootstrap_server(run_dir, initial_state=gui_initial_state)
        if gui_url:
            print(f"[+] GUI dashboard hazır: {gui_url}")
            try:
                webbrowser.open(gui_url)
            except Exception:
                pass
        else:
            print("[!] GUI dashboard başlatılamadı.")

    run_config_payload = _run_config_snapshot(config)
    osint_payload: dict[str, Any] | None = None

    def _run_osint_if_enabled() -> dict[str, Any] | None:
        if not bool(run_config_payload.get("osint_enabled")):
            return None
        return build_osint_enrichment(
            target=target,
            enabled=True,
            mode=run_config_payload.get("osint_profile", "safe_mvp"),
            scan_profile=str(run_config_payload.get("scan_profile") or "balanced"),
            tool_settings=run_config_payload.get("tool_settings") if isinstance(run_config_payload.get("tool_settings"), dict) else {},
            output_dir=run_dir,
        )

    if run_config_payload.get("run_mode") == "osint_only":
        atomic_json(run_dir / "effective_config.json", {
            "run_id": run_dir.name, "target": target, "run_mode": "osint_only",
            "tools": {}, "limits": {}, "traffic": {},
            "runtime": runtime_metadata([]),
        })
        osint_payload = _run_osint_if_enabled()
        scanner_tools = [
            "nmap",
            "subfinder",
            "dnsx",
            "httpx",
            "katana",
            "gobuster",
            "ffuf",
            "historical_urls",
            "screenshots",
            "wafw00f",
            "whatweb",
            "checks",
            "nuclei",
        ]
        skipped_tools = sorted(set(scanner_tools))
        _write_run_result_json(
            run_dir,
            target=target,
            mode=mode,
            skipped_tools=skipped_tools,
            nmap_output="",
            gobuster_results={},
            katana_urls=[],
            checks_results={},
            nuclei_results={},
            run_config=run_config_payload,
            osint=osint_payload,
        )
        generate_report(
            {},
            [],
            {},
            {},
            target,
            "",
            skipped_tools=skipped_tools,
            output_dir=run_dir,
            report_depth=config.report_depth,
            open_browser=not bool(getattr(args, "gui", False)) and not suppress_report_open,
            quiet=False,
        )
        sync_latest(run_dir, latest_dir)
        print("[+] OSINT-only passive run completed. Active scanners were skipped.", flush=True)
        return

    try:
        result = run_engine(config)
    except Exception as e:
        print(f"[!] Çalıştırma hatası: {e}")
        print("[!] Program sonlandırılıyor.")
        raise

    osint_payload = _run_osint_if_enabled()

    def _write_state_then_report(
        nuclei_payload: dict[str, Any],
        *,
        open_browser: bool,
        quiet: bool,
    ) -> None:
        _write_run_result_json(
            run_dir,
            target=target,
            mode=mode,
            skipped_tools=skipped_tools,
            nmap_output=result.nmap_output,
            gobuster_results=result.gobuster_results,
            katana_urls=result.katana_urls,
            checks_results=result.checks_results,
            nuclei_results=nuclei_payload if isinstance(nuclei_payload, dict) else {},
            run_config=run_config_payload,
            osint=osint_payload,
        )
        generate_report(
            result.gobuster_results,
            result.katana_urls,
            result.checks_results,
            nuclei_payload if isinstance(nuclei_payload, dict) else {},
            target,
            result.nmap_output,
            skipped_tools=skipped_tools,
            output_dir=run_dir,
            report_depth=config.report_depth,
            open_browser=open_browser,
            quiet=quiet,
        )
        sync_latest(run_dir, latest_dir)

    _write_state_then_report(
        {},
        open_browser=not bool(getattr(args, "gui", False)) and not suppress_report_open,
        quiet=False,
    )

    if bool(getattr(args, "gui", False)) and gui_server is None:
        gui_server, gui_url = _start_gui_bootstrap_server(run_dir)
        if gui_url:
            print(f"[+] GUI dashboard hazır: {gui_url}")
            try:
                webbrowser.open(gui_url)
            except Exception:
                pass
        else:
            print("[!] GUI dashboard başlatılamadı.")

    if result.nuclei_proc and result.nuclei_output_path:
        if suppress_report_open:
            print("[*] Nuclei başlatıldı. Rapor üretildi; Nuclei bittiğinde rapor otomatik güncellenecek.", flush=True)
        else:
            print("[*] Nuclei başlatıldı. Rapor açıldı; Nuclei bittiğinde rapor otomatik güncellenecek.", flush=True)
        if getattr(result, "nuclei_log_path", None):
            print(f"[*] Nuclei log: {result.nuclei_log_path}")

        nuclei_results: dict[str, Any] = {}
        try:
            while True:
                rc = result.nuclei_proc.poll()
                if rc is not None:
                    break

                live_findings = _read_nuclei_jsonl_findings(result.nuclei_output_path)
                if live_findings:
                    nuclei_results = {"Status": "Live", "_live_findings": live_findings}
                else:
                    nuclei_results = {}

                _write_state_then_report(nuclei_results, open_browser=False, quiet=True)

                print("[*] Nuclei live update: rapor güncellendi.", flush=True)
                time.sleep(5)

            rc = result.nuclei_proc.wait()
        except KeyboardInterrupt:
            print("[!] Program interrupted by user (Ctrl+C). Shutting down gracefully...", flush=True)
            print("[i] Run state marked as interrupted. Auto-refresh disabled.", flush=True)

            try:
                if getattr(result, "nuclei_proc", None) is not None and result.nuclei_proc.poll() is None:
                    try:
                        result.nuclei_proc.terminate()
                        result.nuclei_proc.wait(timeout=5)
                    except Exception:
                        try:
                            result.nuclei_proc.kill()
                        except Exception:
                            pass
            except Exception:
                pass

            try:
                interrupted_payload = dict(nuclei_results) if isinstance(nuclei_results, dict) else {}
                if interrupted_payload.get("Status") == "Live":
                    interrupted_payload["Status"] = "Partial"
                existing_run_result = _read_run_result_json(run_dir / "run_result.json")
                existing_run_result["run_state"] = "interrupted"
                existing_run_result["interrupted_by_user"] = True
                existing_run_result["auto_refresh_enabled"] = False

                stages = existing_run_result.get("stages") if isinstance(existing_run_result.get("stages"), dict) else {}
                nuclei_stage = stages.get("nuclei") if isinstance(stages.get("nuclei"), dict) else {}
                if not isinstance(nuclei_stage, dict):
                    nuclei_stage = {}
                nuclei_stage["status"] = "interrupted"
                nuclei_stage["ended_at"] = _now_iso()
                stages["nuclei"] = nuclei_stage
                existing_run_result["stages"] = stages

                summary = existing_run_result.get("summary") if isinstance(existing_run_result.get("summary"), dict) else {}
                if isinstance(summary, dict):
                    summary["nuclei_status"] = "Interrupted"
                    existing_run_result["summary"] = summary

                atomic_json(run_dir / "run_result.json", existing_run_result)
                _write_state_then_report(interrupted_payload, open_browser=False, quiet=True)
            except Exception:
                pass

            print("[i] Partial results were saved to report/output.", flush=True)
            raise SystemExit(130)
        except Exception as exc:
            print(f"[!] Nuclei processing failed: {exc}", flush=True)

            try:
                existing_run_result = _read_run_result_json(run_dir / "run_result.json")
                existing_run_result["run_state"] = "failed"
                existing_run_result["auto_refresh_enabled"] = False

                stages = existing_run_result.get("stages") if isinstance(existing_run_result.get("stages"), dict) else {}
                nuclei_stage = stages.get("nuclei") if isinstance(stages.get("nuclei"), dict) else {}
                if not isinstance(nuclei_stage, dict):
                    nuclei_stage = {}
                nuclei_stage["status"] = "error"
                nuclei_stage["ended_at"] = _now_iso()
                stages["nuclei"] = nuclei_stage
                existing_run_result["stages"] = stages

                summary = existing_run_result.get("summary") if isinstance(existing_run_result.get("summary"), dict) else {}
                if isinstance(summary, dict):
                    summary["nuclei_status"] = "Error"
                    existing_run_result["summary"] = summary

                atomic_json(run_dir / "run_result.json", existing_run_result)
                _write_state_then_report(
                    nuclei_results if isinstance(nuclei_results, dict) else {},
                    open_browser=False,
                    quiet=True,
                )
            except Exception:
                pass

            raise SystemExit(1)

        nuclei_results = parse_nuclei_output(
            result.nuclei_output_path,
            rc,
            log_path=getattr(result, "nuclei_log_path", None),
        )

        fallback_findings = _read_nuclei_jsonl_findings(result.nuclei_output_path)
        parsed_findings_count = 0
        try:
            parsed_findings_count = len(nuclei_to_findings(nuclei_results or {}))
        except Exception:
            parsed_findings_count = 0
        if fallback_findings and parsed_findings_count == 0:
            if not isinstance(nuclei_results, dict):
                nuclei_results = {}
            nuclei_results["_live_findings"] = fallback_findings
            if not nuclei_results.get("Status"):
                nuclei_results["Status"] = "Success"

        existing_run_result = _read_run_result_json(run_dir / "run_result.json")
        existing_run_result = _update_nuclei_stage(
            existing_run_result,
            nuclei_results,
            result.nuclei_output_path,
        )
        try:
            atomic_json(run_dir / "run_result.json", existing_run_result)
        except Exception as exc:
            print(f"[!] nuclei stage güncellenemedi: {exc}")

        atomic_json(run_dir / "stages_live.json", existing_run_result.get("stages", {}))
        _write_state_then_report(
            nuclei_results,
            open_browser=not bool(getattr(args, "gui", False)) and not suppress_report_open,
            quiet=False,
        )

        print("[+] Nuclei sonuçları işlendi ve rapor güncellendi.", flush=True)
        if nuclei_results.get("Status") in {"Error", "Partial"}:
            raise SystemExit(1)

    return
