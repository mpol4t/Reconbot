from __future__ import annotations

import json
import hashlib
import http.client
import re
import socket
import ssl
from reconbot.runtime import processes as subprocess
from reconbot.runtime.processes import process_scope
from reconbot.runtime.run_lifecycle import atomic_json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reconbot.report.builder import generate_report


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        data = bytes(value)
        return {"bytes_length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, set):
        return [_json_safe(item) for item in sorted(value, key=lambda item: str(item))]
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return value


def _read_json(path: Path) -> dict[str, Any]:
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    atomic_json(path, _json_safe(data))


def _append_run_log(run_dir: Path, line: str) -> None:
    try:
        with (run_dir / "reconbot.log").open("a", encoding="utf-8") as handle:
            handle.write(f"{line.rstrip()}\n")
    except Exception:
        pass


def _emit_lifecycle(run_dir: Path, line: str) -> None:
    print(line)
    _append_run_log(run_dir, line)


def _parse_open_ports(nmap_output: str) -> list[dict[str, str]]:
    ports: list[dict[str, str]] = []
    for raw_line in (nmap_output or "").splitlines():
        line = raw_line.strip()
        match = re.match(r"^(?P<port>\d+)/(?:tcp|udp)\s+open\s+(?P<service>\S+)(?:\s+(?P<detail>.*))?$", line)
        if not match:
            continue
        ports.append(
            {
                "port": match.group("port"),
                "protocol": "tcp" if "/tcp" in line else "udp",
                "service": match.group("service") or "",
                "detail": (match.group("detail") or "").strip(),
                "raw": line,
                "validation_state": "informational",
                "source": "ip_enrichment_nmap_context",
            }
        )
    return ports


def _services_from_open_ports(open_ports: list[dict[str, str]]) -> list[dict[str, str]]:
    services: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in open_ports:
        service = str(item.get("service") or "").strip()
        detail = str(item.get("detail") or "").strip()
        if not service and not detail:
            continue
        record = {
            "port": str(item.get("port") or "").strip(),
            "protocol": str(item.get("protocol") or "tcp").strip() or "tcp",
            "service": service,
            "detail": detail,
            "validation_state": "candidate_manual_validation",
            "risk_note": "Service/version data is candidate context only without behavioral proof.",
        }
        key = (record["port"], record["protocol"], record["service"], record["detail"])
        if key in seen:
            continue
        seen.add(key)
        services.append(record)
    return services


def _primary_nmap_output(run_result: dict[str, Any]) -> str:
    nmap = run_result.get("nmap") if isinstance(run_result.get("nmap"), dict) else {}
    output = str(nmap.get("output") or "").strip()
    if output:
        return output
    data = run_result.get("data") if isinstance(run_result.get("data"), dict) else {}
    return str(data.get("nmap_output") or "").strip()


def _primary_nmap_covers_resolved_ip(run_result: dict[str, Any], resolved_ip: str) -> bool:
    output = _primary_nmap_output(run_result)
    if not output or not resolved_ip:
        return False
    lowered = output.lower()
    if "nmap skipped" in lowered or "resolve failed" in lowered or "apex ip bulunamad" in lowered:
        return False
    return resolved_ip in output and bool(_parse_open_ports(output))


def _primary_nmap_artifacts(run_dir: Path) -> dict[str, Any]:
    nmap_txt = run_dir / "nmap.txt"
    if nmap_txt.exists():
        return {"primary_nmap_text": "nmap.txt"}
    return {"primary_nmap_output": "run_result.json:nmap.output"}


def _probe_record(
    probe_type: str,
    target: str,
    status: str,
    *,
    status_code: int | None = None,
    title: str = "",
    location: str = "",
    server: str = "",
    note: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "type": probe_type,
        "probe": probe_type,
        "target": target,
        "status": status,
        "note": note,
        "validation_state": "informational",
    }
    if status_code is not None:
        record["status_code"] = status_code
        record["http_status"] = status_code
    if title:
        record["title"] = title
    if location:
        record["location"] = location
    if server:
        record["server"] = server
    if extra:
        record.update(extra)
    return record


def _reverse_dns_probe(resolved_ip: str) -> dict[str, Any] | None:
    try:
        ptr, aliases, addresses = socket.gethostbyaddr(resolved_ip)
    except Exception as exc:
        return _probe_record(
            "ptr",
            resolved_ip,
            "not_found",
            note=f"PTR lookup produced no reverse DNS name: {exc.__class__.__name__}.",
        )
    return _probe_record(
        "ptr",
        resolved_ip,
        "ok",
        note=f"PTR resolved to {ptr}.",
        extra={"ptr": ptr, "aliases": aliases[:5], "addresses": addresses[:5]},
    )


def _http_probe(resolved_ip: str, scheme: str, *, host_header: str = "", timeout: float = 3.0) -> dict[str, Any] | None:
    scheme = scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    port = 443 if scheme == "https" else 80
    conn: http.client.HTTPConnection | http.client.HTTPSConnection | None = None
    headers = {
        "User-Agent": "ReconBot-IP-Enrichment/1.0",
        "Accept": "*/*",
    }
    if host_header:
        headers["Host"] = host_header
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(
                resolved_ip,
                port=port,
                timeout=timeout,
                context=ssl._create_unverified_context(),
            )
        else:
            conn = http.client.HTTPConnection(resolved_ip, port=port, timeout=timeout)
        conn.request("HEAD", "/", headers=headers)
        response = conn.getresponse()
        response.read(512)
        probe_type = f"{'host_header' if host_header else 'direct'}_{scheme}"
        target = f"{scheme}://{resolved_ip}/"
        return _probe_record(
            probe_type,
            target,
            "responded",
            status_code=response.status,
            location=response.getheader("Location") or "",
            server=response.getheader("Server") or "",
            note="HTTP response observed from resolved IP context only.",
            extra={"url": target, "host_header": host_header, "reason": response.reason},
        )
    except Exception as exc:
        probe_type = f"{'host_header' if host_header else 'direct'}_{scheme}"
        target = f"{scheme}://{resolved_ip}/"
        return _probe_record(
            probe_type,
            target,
            "no_response",
            note=f"Probe did not return an HTTP response: {exc.__class__.__name__}.",
            extra={"url": target, "host_header": host_header},
        )
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _tls_probe(resolved_ip: str, hostname: str, *, timeout: float = 3.0) -> dict[str, Any] | None:
    server_name = hostname or resolved_ip
    target = f"{server_name}:443 via {resolved_ip}:443"
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((resolved_ip, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_name) as tls_sock:
                cert_der = tls_sock.getpeercert(binary_form=True) or b""
                cert = tls_sock.getpeercert() or {}
        subject = ", ".join("=".join(item) for group in cert.get("subject", []) for item in group if len(item) == 2)
        issuer = ", ".join("=".join(item) for group in cert.get("issuer", []) for item in group if len(item) == 2)
        return _probe_record(
            "tls",
            target,
            "ok",
            note="TLS certificate observed with SNI context; auxiliary metadata only.",
            extra={
                "certificate_sha256": hashlib.sha256(cert_der).hexdigest() if cert_der else "",
                "subject": subject,
                "issuer": issuer,
                "not_after": str(cert.get("notAfter") or ""),
            },
        )
    except Exception as exc:
        return _probe_record(
            "tls",
            target,
            "no_response",
            note=f"TLS certificate summary unavailable: {exc.__class__.__name__}.",
        )


def _run_lightweight_probes(resolved_ip: str, hostname: str) -> tuple[list[dict[str, Any]], list[str]]:
    probes: list[dict[str, Any]] = []
    tools_used = ["ptr_lookup", "direct_ip_http_probe", "direct_ip_https_probe"]
    ptr_probe = _reverse_dns_probe(resolved_ip)
    if ptr_probe:
        probes.append(ptr_probe)
    for scheme in ("http", "https"):
        probe = _http_probe(resolved_ip, scheme)
        if probe:
            probes.append(probe)
    if hostname:
        tools_used.extend(["host_header_http_probe", "host_header_https_probe"])
        for scheme in ("http", "https"):
            probe = _http_probe(resolved_ip, scheme, host_header=hostname)
            if probe:
                probes.append(probe)
    tls_probe = _tls_probe(resolved_ip, hostname)
    if tls_probe:
        probes.append(tls_probe)
        tools_used.append("tls_certificate_probe")
    return probes, tools_used


def _normalize_nmap_timing(timing: str | None, *, fallback: str = "T4") -> str:
    raw = str(timing or "").strip().upper()
    if raw.startswith("-T"):
        raw = raw[2:]
    elif raw.startswith("T"):
        raw = raw[1:]
    if raw.isdigit():
        value = int(raw)
        if 0 <= value <= 4:
            return f"T{value}"
        if value >= 5:
            return "T4"
    return fallback


def _run_attached_detailed_nmap(resolved_ip: str, run_dir: Path, *, timing: str = "T4", timeout_sec: int = 120) -> tuple[str, dict[str, Any], int, str]:
    timing_arg = "-" + _normalize_nmap_timing(timing, fallback="T4")
    command = ["nmap", "-Pn", "-p-", "-sV", "-v", timing_arg, "--stats-every", "5s", resolved_ip]
    stdout_path = run_dir / "ip_enrichment_detailed_nmap.txt"
    stderr_path = run_dir / "ip_enrichment_detailed_nmap.stderr.txt"
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_sec)
    stdout_path.write_text(result.stdout or "", encoding="utf-8")
    artifacts: dict[str, Any] = {
        "detailed_nmap_text": stdout_path.name,
        "detailed_nmap_exit_code": result.returncode,
        "detailed_nmap_command": " ".join(command),
    }
    if result.stderr:
        stderr_path.write_text(result.stderr, encoding="utf-8")
        artifacts["detailed_nmap_stderr"] = stderr_path.name
    return result.stdout or "", artifacts, result.returncode, result.stderr or ""


def _merge_ip_enrichment(run_result: dict[str, Any], enrichment: dict[str, Any]) -> dict[str, Any]:
    merged = dict(run_result)
    merged["ip_enrichment"] = enrichment

    data = merged.get("data") if isinstance(merged.get("data"), dict) else {}
    checks = data.get("checks_results") if isinstance(data.get("checks_results"), dict) else {}
    checks["ip_enrichment"] = enrichment
    data["checks_results"] = checks
    merged["data"] = data

    summary = merged.get("summary") if isinstance(merged.get("summary"), dict) else {}
    results = enrichment.get("results") if isinstance(enrichment.get("results"), dict) else {}
    open_ports = results.get("open_ports") if isinstance(results.get("open_ports"), list) else []
    services = results.get("services") if isinstance(results.get("services"), list) else []
    probes = results.get("probes") if isinstance(results.get("probes"), list) else []
    summary["ip_enrichment_open_ports_count"] = len(open_ports)
    summary["ip_enrichment_services_count"] = len(services)
    summary["ip_enrichment_probes_count"] = len(probes)
    summary["ip_enrichment_status"] = enrichment.get("status") or ""
    merged["summary"] = summary
    return merged


def _regenerate_report(run_dir: Path, run_result: dict[str, Any]) -> None:
    data = run_result.get("data") if isinstance(run_result.get("data"), dict) else {}
    meta = run_result.get("meta") if isinstance(run_result.get("meta"), dict) else {}
    target = str(meta.get("target") or data.get("target") or run_result.get("target") or "")
    generate_report(
        data.get("gobuster_results") if isinstance(data.get("gobuster_results"), dict) else {},
        data.get("katana_urls") if isinstance(data.get("katana_urls"), list) else [],
        data.get("checks_results") if isinstance(data.get("checks_results"), dict) else {},
        data.get("nuclei_results") if isinstance(data.get("nuclei_results"), dict) else {"Status": "Success", "findings": []},
        target,
        str(data.get("nmap_output") or ""),
        skipped_tools=meta.get("skipped_tools") if isinstance(meta.get("skipped_tools"), list) else None,
        output_dir=run_dir,
        open_browser=False,
        quiet=True,
    )


def _enrichment_counts(enrichment: dict[str, Any]) -> tuple[int, int, int]:
    results = enrichment.get("results") if isinstance(enrichment.get("results"), dict) else {}
    open_ports = results.get("open_ports") if isinstance(results.get("open_ports"), list) else []
    services = results.get("services") if isinstance(results.get("services"), list) else []
    probes = results.get("probes") if isinstance(results.get("probes"), list) else []
    return len(open_ports), len(services), len(probes)


def _print_completion_lines(enrichment: dict[str, Any], run_dir: Path | None = None) -> None:
    open_ports_count, services_count, probes_count = _enrichment_counts(enrichment)
    lines = [
        f"[i] IP enrichment finished: open_ports={open_ports_count}, services={services_count}, probes={probes_count}",
        "[i] IP enrichment attached to current URL/domain run. Primary target preserved.",
        "[i] Report updated with IP enrichment.",
    ]
    for line in lines:
        if run_dir is None:
            print(line)
        else:
            _emit_lifecycle(run_dir, line)


def run_ip_enrichment(request: dict[str, Any]) -> dict[str, Any]:
    run_dir = Path(str(request.get("run_dir") or "")).expanduser().resolve()
    run_result_path = run_dir / "run_result.json"
    run_result = _read_json(run_result_path)
    if not run_dir.exists() or not run_result:
        raise RuntimeError(f"Primary run_result.json not found for IP enrichment: {run_result_path}")

    existing_meta = run_result.get("meta") if isinstance(run_result.get("meta"), dict) else {}
    primary_target = str(existing_meta.get("target") or run_result.get("target") or "").strip()
    requested_target = str(request.get("original_target") or "").strip()
    if not primary_target or requested_target != primary_target:
        raise ValueError("IP enrichment hedefi çalışma kaydıyla eşleşmiyor.")
    if request.get("run_id") and request["run_id"] != run_dir.name:
        raise ValueError("IP enrichment çalışma kimliği eşleşmiyor.")
    resolved_ip = str(request.get("resolved_ip") or "").strip()
    import ipaddress
    ipaddress.ip_address(resolved_ip)
    hostname = str(request.get("hostname") or "").strip()
    scan_mode = str(request.get("scan_mode") or "quick").strip().lower()
    operator_action = str(request.get("operator_action") or "").strip().lower()
    detailed_requested = scan_mode == "detailed"
    requested_at = str(request.get("requested_at") or _now_iso())
    note = "IP enrichment is auxiliary context, not proof by itself."

    if operator_action == "skip" or scan_mode == "skipped":
        _emit_lifecycle(run_dir, "[i] IP enrichment skipped by operator.")
        enrichment = {
            "status": "skipped",
            "original_target": primary_target,
            "resolved_ip": resolved_ip,
            "hostname": hostname,
            "scan_mode": "skipped",
            "already_covered_by_primary_nmap": False,
            "tools_used": [],
            "requested_at": requested_at,
            "started_at": "",
            "ended_at": _now_iso(),
            "note": "IP enrichment skipped by operator.",
            "risk_note": "Auxiliary context only; does not increase risk without behavioral proof.",
            "results": {"open_ports": [], "services": [], "probes": [], "open_ports_count": 0, "services_count": 0, "probes_count": 0},
            "artifacts": {},
        }
        refreshed = _merge_ip_enrichment(run_result, enrichment)
        _write_json(run_result_path, refreshed)
        _regenerate_report(run_dir, refreshed)
        _print_completion_lines(enrichment, run_dir)
        return enrichment

    _emit_lifecycle(run_dir, f"[i] IP enrichment accepted: {resolved_ip}")
    enrichment: dict[str, Any] = {
        "status": "running",
        "original_target": primary_target,
        "resolved_ip": resolved_ip,
        "hostname": hostname,
        "scan_mode": "detailed_nmap" if detailed_requested else "lightweight",
        "already_covered_by_primary_nmap": False,
        "tools_used": [],
        "requested_at": requested_at,
        "started_at": _now_iso(),
        "ended_at": "",
        "note": note,
        "risk_note": "Auxiliary context only; does not increase risk without behavioral proof.",
        "results": {},
        "artifacts": {},
    }
    _write_json(run_result_path, _merge_ip_enrichment(run_result, enrichment))

    try:
        already_covered = False
        probes: list[dict[str, Any]] = []
        artifacts: dict[str, Any] = {}
        if detailed_requested:
            effective = _read_json(run_dir / "effective_config.json")
            timing = (effective.get("traffic", {}).get("nmap", {}) or {}).get("timing", "T3")
            timeout_sec = int((effective.get("limits") or {}).get("nmap_timeout_sec", 120))
            if not 1 <= timeout_sec <= 86400:
                raise ValueError("Geçersiz Nmap timeout")
            nmap_output, artifacts, detailed_exit_code, detailed_stderr = _run_attached_detailed_nmap(resolved_ip, run_dir, timing=timing, timeout_sec=timeout_sec)
            open_ports = _parse_open_ports(nmap_output)
            services = _services_from_open_ports(open_ports)
            if detailed_exit_code != 0:
                raise RuntimeError(f"Detailed nmap failed with exit code {detailed_exit_code}: {detailed_stderr.strip()[:500]}")
            tools_used = ["detailed_nmap"]
            final_scan_mode = "detailed_nmap"
            final_note = "Attached detailed nmap completed. Open ports alone do not raise risk."
        else:
            print(f"[i] Reusing primary nmap result for {resolved_ip} if available.")
            if _primary_nmap_covers_resolved_ip(run_result, resolved_ip):
                nmap_output = _primary_nmap_output(run_result)
                open_ports = _parse_open_ports(nmap_output)
                services = _services_from_open_ports(open_ports)
                artifacts = _primary_nmap_artifacts(run_dir)
                tools_used = ["primary_nmap_reuse"]
                final_scan_mode = "already_covered"
                already_covered = True
                final_note = "Primary nmap already scanned the resolved IP. ReconBot reused that output as auxiliary IP context."
                _emit_lifecycle(run_dir, "[i] Primary Nmap already covered resolved IP; reusing as auxiliary context.")
                print("[i] Open ports are auxiliary context only; risk unchanged.")
            else:
                open_ports = []
                services = []
                tools_used = []
                final_scan_mode = "lightweight"
                final_note = "Lightweight IP enrichment completed with PTR, direct IP, Host-header HTTP, and TLS context probes. No URL discovery tools were run."
            _emit_lifecycle(run_dir, "[i] Starting attached lightweight IP enrichment...")
            probes, probe_tools = _run_lightweight_probes(resolved_ip, hostname)
            tools_used.extend(tool for tool in probe_tools if tool not in tools_used)

        enrichment.update(
            {
                "status": "done",
                "scan_mode": final_scan_mode,
                "ended_at": _now_iso(),
                "detailed_nmap_enabled": detailed_requested,
                "already_covered_by_primary_nmap": already_covered,
                "tools_used": tools_used,
                "artifacts": artifacts,
                "note": final_note,
                "risk_note": "Auxiliary context only; does not increase risk without behavioral proof.",
                "results": {
                    "open_ports": open_ports,
                    "services": services,
                    "probes": probes,
                    "open_ports_count": len(open_ports),
                    "services_count": len(services),
                    "probes_count": len(probes),
                    "artifacts": artifacts,
                    "tools_used": tools_used,
                    "already_covered_by_primary_nmap": already_covered,
                    "source": "primary_nmap_reuse" if already_covered else final_scan_mode,
                    "validation_state": "informational",
                    "risk_note": "Auxiliary context only; does not increase risk without behavioral proof.",
                },
            }
        )
    except Exception as exc:
        enrichment.update(
            {
                "status": "error",
                "ended_at": _now_iso(),
                "error": str(exc),
                "already_covered_by_primary_nmap": False,
                "tools_used": ["detailed_nmap"] if detailed_requested else ["ptr_lookup", "direct_ip_http_probe", "direct_ip_https_probe"],
                "artifacts": artifacts if "artifacts" in locals() and isinstance(artifacts, dict) else {},
                "risk_note": "Auxiliary context only; does not increase risk without behavioral proof.",
                "results": {
                    "open_ports": [],
                    "services": [],
                    "probes": [],
                    "open_ports_count": 0,
                    "services_count": 0,
                    "probes_count": 0,
                    "artifacts": artifacts if "artifacts" in locals() and isinstance(artifacts, dict) else {},
                    "tools_used": ["detailed_nmap"] if detailed_requested else ["ptr_lookup", "direct_ip_http_probe", "direct_ip_https_probe"],
                    "validation_state": "error",
                    "risk_note": "Auxiliary context only; does not increase risk without behavioral proof.",
                },
            }
        )
        print(f"[!] IP enrichment failed: {exc}")

    refreshed = _merge_ip_enrichment(run_result, enrichment)
    _write_json(run_result_path, refreshed)
    _regenerate_report(run_dir, refreshed)
    _print_completion_lines(enrichment, run_dir)
    return enrichment


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("Usage: python3 -m reconbot.orchestration.ip_enrichment <request.json>")
        return 2
    request_path = Path(args[0]).expanduser().resolve()
    request = _read_json(request_path)
    if not request:
        print(f"[!] IP enrichment request not found or invalid: {request_path}")
        return 2
    with process_scope():
        result = run_ip_enrichment(request)
    print(f"[+] IP enrichment status: {result.get('status')}")
    return 0 if result.get("status") in {"done", "skipped"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
