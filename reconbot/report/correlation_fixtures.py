from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reconbot.core.historical_urls import (
    build_historical_url_results_from_raw,
    collect_historical_urls,
    normalize_historical_url,
)
from reconbot.report.correlation import build_correlation_insights


@dataclass(frozen=True)
class CorrelationFixtureCase:
    name: str
    slug: str
    payload: dict[str, Any]
    expected_titles: list[str]
    expected_empty: bool = False
    expected_absent_titles: list[str] = field(default_factory=list)
    expected_insights: list[dict[str, Any]] = field(default_factory=list)


def _stage(status: str) -> dict[str, Any]:
    return {"status": status, "artifacts": {}}


def _base_run_result(*, target: str) -> dict[str, Any]:
    return {
        "meta": {
            "timestamp": "20260427-010000",
            "target": target,
            "mode": "url" if target.startswith(("http://", "https://")) else "domain_or_ip",
            "skipped_tools": [],
        },
        "summary": {},
        "run_state": "completed",
        "interrupted_by_user": False,
        "auto_refresh_enabled": False,
        "stages": {
            "nmap": _stage("done"),
            "httpx": _stage("done"),
            "katana": _stage("done"),
            "gobuster": _stage("done"),
            "historical_urls": _stage("done"),
            "wafw00f": _stage("done"),
            "whatweb": _stage("done"),
            "checks": _stage("done"),
            "nuclei": _stage("done"),
        },
        "skipped_tools": [],
        "tools": {},
        "data": {
            "nmap_output": "",
            "katana_urls": [],
            "gobuster_results": {},
            "checks_results": {
                "checked_count": 0,
                "classified_endpoints": {},
                "technology_fingerprint": [],
                "waf_signals": {},
                "whatweb_signals": {},
                "login_pages": [],
                "docs_pages": [],
                "captcha_pages": [],
                "rate_limit_signals": [],
                "attack_chains": [],
                "attack_graph": {},
                "node_relationships": {},
                "exploit_suggestions": [],
            },
            "nuclei_results": {"Status": "Clean", "findings": []},
        },
    }


def _case_technology_nuclei() -> CorrelationFixtureCase:
    payload = _base_run_result(target="http://tech-cve.test")
    payload["data"]["nmap_output"] = "Nmap scan report for tech-cve.test\n80/tcp open http Apache httpd 2.4.49"
    payload["data"]["httpx_results"] = {"live_urls": ["http://tech-cve.test"]}
    checks = payload["data"]["checks_results"]
    checks["technology_fingerprint"] = [
        {
            "site": "http://tech-cve.test",
            "server": "Apache/2.4.49",
            "x_powered_by": "",
            "technologies": ["Apache HTTPD"],
            "waf_signals": [],
        }
    ]
    checks["whatweb_signals"] = {
        "http://tech-cve.test": {
            "target": "http://tech-cve.test",
            "plugin_names": ["Apache", "HTTPServer"],
            "entries": [
                {
                    "target": "http://tech-cve.test",
                    "plugins": [
                        {"name": "Apache", "version": "2.4.49", "string": None},
                        {"name": "HTTPServer", "version": None, "string": "Apache/2.4.49"},
                    ],
                }
            ],
        }
    }
    payload["data"]["nuclei_results"] = {
        "Status": "Success",
        "findings": [
            {
                "template-id": "CVE-2021-41773-apache-path-traversal",
                "matched-at": "http://tech-cve.test",
                "info": {
                    "name": "Apache path traversal indicator",
                    "severity": "high",
                    "description": "Apache HTTP Server path traversal signal",
                },
            }
        ],
    }
    return CorrelationFixtureCase(
        name="TECHNOLOGY + NUCLEI",
        slug="technology_nuclei",
        payload=payload,
        expected_titles=["Tespit edilen teknolojiyle eşleşen zafiyet sinyali var"],
        expected_insights=[
            {
                "finding_type": "technology_nuclei_correlation",
                "severity": {"high"},
                "min_confidence": 75,
                "required_text": ["Confidence high", "önkoşullar teyit edilmelidir", "aynı scheme/host/port"],
            }
        ],
    )


def _case_waf_nuclei() -> CorrelationFixtureCase:
    payload = _base_run_result(target="http://no-waf.test")
    payload["data"]["httpx_results"] = {"live_urls": ["http://no-waf.test"]}
    checks = payload["data"]["checks_results"]
    checks["waf_signals"] = {
        "http://no-waf.test": {
            "target": "http://no-waf.test",
            "detected": False,
            "vendor": None,
            "raw_output": "No WAF detected by the generic detection",
        }
    }
    payload["data"]["nuclei_results"] = {
        "Status": "Success",
        "findings": [
            {
                "template-id": "critical-exposure-template",
                "matched-at": "http://no-waf.test",
                "info": {"name": "Critical exposure", "severity": "critical"},
            }
        ],
    }
    return CorrelationFixtureCase(
        name="WAF ABSENT + CRITICAL NUCLEI",
        slug="waf_nuclei",
        payload=payload,
        expected_titles=["High severity bulgu net WAF koruması olmadan erişilebilir görünüyor"],
        expected_insights=[
            {
                "finding_type": "waf_nuclei_correlation",
                "severity": {"critical"},
                "min_confidence": 60,
                "required_text": ["Confidence", "Birleşik sinyal doğrulama önceliğini artırır", "exploitability kanıtı değildir"],
            }
        ],
    )


def _case_auth_surface() -> CorrelationFixtureCase:
    payload = _base_run_result(target="http://auth-surface.test")
    checks = payload["data"]["checks_results"]
    checks["classified_endpoints"] = {
        "admin_like": ["http://auth-surface.test/admin/dashboard"],
        "auth_like": ["http://auth-surface.test/login"],
    }
    checks["login_pages"] = [{"url": "http://auth-surface.test/login", "status": 200}]
    payload["data"]["gobuster_results"] = {
        "http://auth-surface.test": [
            {"path": "/admin", "status": 301, "url": "http://auth-surface.test/admin"},
            {"path": "/wp-login.php", "status": 200, "url": "http://auth-surface.test/wp-login.php"},
        ]
    }
    return CorrelationFixtureCase(
        name="LOGIN/ADMIN SURFACE WITHOUT NUCLEI",
        slug="auth_surface",
        payload=payload,
        expected_titles=["Olası authentication yüzeyi keşfedildi"],
        expected_insights=[
            {
                "finding_type": "login_admin_surface",
                "severity": {"low", "medium"},
                "max_confidence": 66,
                "required_text": ["tek başına zafiyet değil", "access control incelemesi", "yalnızca yüzey keyword sinyali"],
                "forbidden_text": ["confirmed vulnerability", "critical"],
            }
        ],
    )


def _case_service_http_surface() -> CorrelationFixtureCase:
    payload = _base_run_result(target="http://service-http.test")
    payload["data"]["nmap_output"] = (
        "Nmap scan report for service-http.test\n"
        "22/tcp open ssh OpenSSH 9.0\n"
        "80/tcp open http nginx\n"
        "5432/tcp open postgresql PostgreSQL\n"
    )
    payload["data"]["httpx_results"] = {"live_urls": ["http://service-http.test"]}
    return CorrelationFixtureCase(
        name="NMAP SERVICES + HTTPX LIVE HOST",
        slug="service_http_surface",
        payload=payload,
        expected_titles=["Host birden fazla erişilebilir service sunuyor"],
        expected_insights=[
            {
                "finding_type": "service_http_surface",
                "severity": {"low", "medium"},
                "max_confidence": 78,
                "required_text": ["attack-surface genişlemesidir", "otomatik zafiyet değil", "nmap service inventory"],
            }
        ],
    )


def _case_nuclei_critical_no_technology() -> CorrelationFixtureCase:
    payload = _base_run_result(target="http://critical-only.test")
    payload["data"]["httpx_results"] = {"live_urls": ["http://critical-only.test"]}
    payload["data"]["nuclei_results"] = {
        "Status": "Success",
        "findings": [
            {
                "template-id": "critical-only-template",
                "matched-at": "http://critical-only.test/admin",
                "info": {"name": "Critical standalone signal", "severity": "critical"},
            }
        ],
    }
    return CorrelationFixtureCase(
        name="NUCLEI CRITICAL WITHOUT TECHNOLOGY",
        slug="nuclei_critical_no_technology",
        payload=payload,
        expected_titles=["High severity scanner bulgusu doğrulama kuyruğunda"],
        expected_insights=[
            {
                "finding_type": "nuclei_validation",
                "severity": {"critical"},
                "max_confidence": 68,
                "required_text": ["doğrulanmamış scanner sinyali", "WhatWeb/web-check teknoloji kanıtı yok", "eksik teknoloji/version kanıt"],
            }
        ],
    )


def _case_same_host_different_ports() -> CorrelationFixtureCase:
    payload = _base_run_result(target="http://port-split.test:8080")
    checks = payload["data"]["checks_results"]
    checks["technology_fingerprint"] = [
        {
            "site": "http://port-split.test:8081",
            "server": "Apache/2.4.49",
            "x_powered_by": "",
            "technologies": ["Apache HTTPD"],
            "waf_signals": [],
        }
    ]
    payload["data"]["httpx_results"] = {"live_urls": ["http://port-split.test:8080", "http://port-split.test:8081"]}
    payload["data"]["nuclei_results"] = {
        "Status": "Success",
        "findings": [
            {
                "template-id": "CVE-2021-41773-apache-path-traversal",
                "matched-at": "http://port-split.test:8080/app",
                "info": {"name": "Apache path traversal indicator", "severity": "high"},
            }
        ],
    }
    return CorrelationFixtureCase(
        name="SAME HOST DIFFERENT PORTS",
        slug="same_host_different_ports",
        payload=payload,
        expected_titles=["High severity scanner bulgusu doğrulama kuyruğunda"],
        expected_absent_titles=["Tespit edilen teknolojiyle eşleşen zafiyet sinyali var"],
        expected_insights=[
            {
                "finding_type": "nuclei_validation",
                "severity": {"high"},
                "max_confidence": 68,
                "required_text": ["bu asset için WhatWeb/web-check teknoloji kanıtı yok"],
            }
        ],
    )


def _case_same_hostname_http_https() -> CorrelationFixtureCase:
    payload = _base_run_result(target="https://scheme-split.test")
    checks = payload["data"]["checks_results"]
    checks["technology_fingerprint"] = [
        {
            "site": "http://scheme-split.test",
            "server": "Apache/2.4.49",
            "x_powered_by": "",
            "technologies": ["Apache HTTPD"],
            "waf_signals": [],
        }
    ]
    payload["data"]["httpx_results"] = {"live_urls": ["http://scheme-split.test", "https://scheme-split.test"]}
    payload["data"]["nuclei_results"] = {
        "Status": "Success",
        "findings": [
            {
                "template-id": "CVE-2021-41773-apache-path-traversal",
                "matched-at": "https://scheme-split.test",
                "info": {"name": "Apache path traversal indicator", "severity": "high"},
            }
        ],
    }
    return CorrelationFixtureCase(
        name="SAME HOSTNAME HTTP AND HTTPS",
        slug="same_hostname_http_https",
        payload=payload,
        expected_titles=["High severity scanner bulgusu doğrulama kuyruğunda"],
        expected_absent_titles=["Tespit edilen teknolojiyle eşleşen zafiyet sinyali var"],
        expected_insights=[
            {
                "finding_type": "nuclei_validation",
                "severity": {"high"},
                "max_confidence": 68,
                "required_text": ["bu asset için WhatWeb/web-check teknoloji kanıtı yok"],
            }
        ],
    )


def _case_nmap_ip_domain_no_merge() -> CorrelationFixtureCase:
    payload = _base_run_result(target="http://service-domain.test")
    payload["data"]["nmap_output"] = (
        "Nmap scan report for 192.0.2.10\n"
        "22/tcp open ssh OpenSSH 9.0\n"
        "80/tcp open http nginx\n"
    )
    payload["data"]["httpx_results"] = {"live_urls": ["http://service-domain.test"]}
    return CorrelationFixtureCase(
        name="NMAP IP DOES NOT MERGE WITH DOMAIN URL",
        slug="nmap_ip_domain_no_merge",
        payload=payload,
        expected_titles=[],
        expected_absent_titles=["Host birden fazla erişilebilir service sunuyor"],
        expected_empty=True,
    )


def _add_historical(
    payload: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    warnings: list[str] | None = None,
) -> None:
    checks = payload["data"]["checks_results"]
    live_records = [record for record in records if record.get("live")]
    interesting_live = [
        record for record in live_records
        if isinstance(record.get("categories"), list) and record.get("categories")
    ]
    checks["historical_urls"] = {
        "enabled": True,
        "domains": ["historical.test"],
        "normalized_urls": [record["url"] for record in records],
        "records": records,
        "live_urls": [record["url"] for record in live_records],
        "interesting_live_urls": interesting_live,
        "live_count": len(live_records),
        "interesting_live_count": len(interesting_live),
        "warnings": warnings or [],
        "artifacts": {"combined_txt": "historical_urls.txt"},
    }


def _case_historical_auth_live_no_nuclei() -> CorrelationFixtureCase:
    payload = _base_run_result(target="http://historical-auth.test")
    _add_historical(
        payload,
        [
            {
                "url": "http://historical-auth.test/admin/login",
                "sources": ["gau"],
                "categories": ["auth_surface"],
                "live": True,
            }
        ],
    )
    return CorrelationFixtureCase(
        name="HISTORICAL AUTH URL LIVE WITHOUT NUCLEI",
        slug="historical_auth_live_no_nuclei",
        payload=payload,
        expected_titles=["Historical authentication yüzeyi hâlâ erişilebilir"],
        expected_insights=[
            {
                "finding_type": "historical_auth_surface",
                "severity": {"low"},
                "max_confidence": 74,
                "required_text": ["confirmed exploitability değil", "access control beklentileri", "keyword tabanlı"],
                "forbidden_text": ["confirmed vulnerability"],
            }
        ],
    )


def _case_historical_wayback_only() -> CorrelationFixtureCase:
    payload = _base_run_result(target="http://historical-api.test")
    _add_historical(
        payload,
        [
            {
                "url": "https://historical-api.test/api/v1/users",
                "sources": ["waybackurls"],
                "categories": ["api_surface"],
                "live": True,
            }
        ],
    )
    return CorrelationFixtureCase(
        name="HISTORICAL WAYBACKURLS ONLY",
        slug="historical_wayback_only",
        payload=payload,
        expected_titles=["Historical API endpoint hâlâ erişilebilir"],
        expected_insights=[
            {
                "finding_type": "historical_api_surface",
                "severity": {"medium"},
                "required_text": ["waybackurls", "httpx canlı kanıtı", "authentication gereksinimleri"],
            }
        ],
    )


def _case_historical_backup_live() -> CorrelationFixtureCase:
    payload = _base_run_result(target="http://historical-backup.test")
    _add_historical(
        payload,
        [
            {
                "url": "http://historical-backup.test/backup/db.sql",
                "sources": ["gau", "waybackurls"],
                "categories": ["file_exposure_candidate", "legacy_or_hidden_path"],
                "live": True,
            }
        ],
    )
    return CorrelationFixtureCase(
        name="HISTORICAL BACKUP LOOKING URL LIVE",
        slug="historical_backup_live",
        payload=payload,
        expected_titles=["Sensitive görünümlü historical dosya path’i hâlâ erişilebilir"],
        expected_insights=[
            {
                "finding_type": "historical_file_exposure_candidate",
                "severity": {"high"},
                "min_confidence": 70,
                "required_text": ["manuel inceleme", "backup/configuration içeriği", "güvenli"],
            }
        ],
    )


def _case_historical_plus_nuclei_same_asset() -> CorrelationFixtureCase:
    payload = _base_run_result(target="https://historical-nuclei.test")
    _add_historical(
        payload,
        [
            {
                "url": "https://historical-nuclei.test/old/api",
                "sources": ["gau", "waybackurls"],
                "categories": ["legacy_or_hidden_path", "api_surface"],
                "live": True,
            }
        ],
    )
    payload["data"]["nuclei_results"] = {
        "Status": "Success",
        "findings": [
            {
                "template-id": "high-signal-template",
                "matched-at": "https://historical-nuclei.test/app",
                "info": {"name": "High signal", "severity": "high"},
            }
        ],
    }
    return CorrelationFixtureCase(
        name="HISTORICAL URL + HIGH NUCLEI SAME ASSET",
        slug="historical_plus_nuclei_same_asset",
        payload=payload,
        expected_titles=["Historical exposure ve high severity bulgu aynı asset üzerinde"],
        expected_insights=[
            {
                "finding_type": "historical_url_nuclei_correlation",
                "severity": {"high"},
                "min_confidence": 75,
                "required_text": ["varsayma", "aynı base asset", "path seviyesinde kanıt olmadan"],
            }
        ],
    )


def _case_historical_ports_do_not_merge() -> CorrelationFixtureCase:
    payload = _base_run_result(target="http://historical-port.test:8081")
    _add_historical(
        payload,
        [
            {
                "url": "http://historical-port.test:8081/admin",
                "sources": ["gau"],
                "categories": ["auth_surface"],
                "live": True,
            }
        ],
    )
    payload["data"]["nuclei_results"] = {
        "Status": "Success",
        "findings": [
            {
                "template-id": "high-other-port",
                "matched-at": "http://historical-port.test:8080/admin",
                "info": {"name": "High other port", "severity": "high"},
            }
        ],
    }
    return CorrelationFixtureCase(
        name="HISTORICAL SAME HOST DIFFERENT PORTS",
        slug="historical_ports_do_not_merge",
        payload=payload,
        expected_titles=["Historical authentication yüzeyi hâlâ erişilebilir"],
        expected_absent_titles=["Historical exposure ve high severity bulgu aynı asset üzerinde"],
        expected_insights=[
            {
                "finding_type": "historical_auth_surface",
                "severity": {"low"},
                "required_text": ["aynı scheme/host/port"],
            }
        ],
    )


def _case_historical_scheme_do_not_merge() -> CorrelationFixtureCase:
    payload = _base_run_result(target="http://historical-scheme.test")
    _add_historical(
        payload,
        [
            {
                "url": "http://historical-scheme.test/admin",
                "sources": ["waybackurls"],
                "categories": ["auth_surface"],
                "live": True,
            }
        ],
    )
    payload["data"]["nuclei_results"] = {
        "Status": "Success",
        "findings": [
            {
                "template-id": "high-https-only",
                "matched-at": "https://historical-scheme.test/admin",
                "info": {"name": "High HTTPS only", "severity": "high"},
            }
        ],
    }
    return CorrelationFixtureCase(
        name="HISTORICAL HTTP AND HTTPS DO NOT MERGE",
        slug="historical_scheme_do_not_merge",
        payload=payload,
        expected_titles=["Historical authentication yüzeyi hâlâ erişilebilir"],
        expected_absent_titles=["Historical exposure ve high severity bulgu aynı asset üzerinde"],
        expected_insights=[
            {
                "finding_type": "historical_auth_surface",
                "severity": {"low"},
                "required_text": ["aynı scheme/host/port"],
            }
        ],
    )


def _case_empty() -> CorrelationFixtureCase:
    payload: dict[str, Any] = {}
    return CorrelationFixtureCase(
        name="EMPTY CORRELATION DATA",
        slug="empty",
        payload=payload,
        expected_titles=[],
        expected_empty=True,
    )


def _run_generate_report(project_root: Path, run_dir: Path) -> tuple[bool, str]:
    cmd = [sys.executable, "-m", "reconbot", "generate-report", "--run-dir", str(run_dir)]
    proc = subprocess.run(
        cmd,
        cwd=str(project_root),
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        return True, ""
    return False, (proc.stderr or proc.stdout or "Unknown generate-report failure.").strip()


def validate_correlation_fixtures(project_root: Path | None = None) -> bool:
    root = (project_root or Path(__file__).resolve().parents[2]).resolve()
    fixture_cases = [
        _case_technology_nuclei(),
        _case_waf_nuclei(),
        _case_auth_surface(),
        _case_service_http_surface(),
        _case_nuclei_critical_no_technology(),
        _case_same_host_different_ports(),
        _case_same_hostname_http_https(),
        _case_nmap_ip_domain_no_merge(),
        _case_historical_auth_live_no_nuclei(),
        _case_historical_wayback_only(),
        _case_historical_backup_live(),
        _case_historical_plus_nuclei_same_asset(),
        _case_historical_ports_do_not_merge(),
        _case_historical_scheme_do_not_merge(),
        _case_empty(),
    ]
    direct_failures = _validate_historical_url_helpers()
    overall_pass = not direct_failures
    for failure in direct_failures:
        print(f"HISTORICAL URL HELPER VALIDATION: FAIL - {failure}")
    if not direct_failures:
        print("HISTORICAL URL HELPER VALIDATION: PASS")
        print("")

    with tempfile.TemporaryDirectory(prefix="reconbot-correlation-fixtures-") as temp_dir:
        temp_root = Path(temp_dir)
        for case in fixture_cases:
            run_dir = temp_root / case.slug
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "run_result.json").write_text(
                json.dumps(case.payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

            generated, error_text = _run_generate_report(root, run_dir)
            report_path = run_dir / "report.html"
            if not generated or not report_path.exists():
                case_pass = False
                reason = f"generate-report failed: {error_text[:280]}"
            else:
                report_html = report_path.read_text(encoding="utf-8", errors="ignore")
                missing = [title for title in case.expected_titles if title not in report_html]
                unexpectedly_present = [title for title in case.expected_absent_titles if title in report_html]
                empty_ok = (not case.expected_empty) or ("korelasyon içgörüsü üretilmedi" in report_html)
                insight_failures = _evaluate_insight_assertions(case)
                case_pass = not missing and not unexpectedly_present and empty_ok and not insight_failures
                if case_pass:
                    reason = "All correlation assertions satisfied."
                else:
                    parts = []
                    if missing:
                        parts.append("missing titles: " + ", ".join(missing))
                    if unexpectedly_present:
                        parts.append("unexpected titles: " + ", ".join(unexpectedly_present))
                    if not empty_ok:
                        parts.append("empty fallback text missing")
                    if insight_failures:
                        parts.extend(insight_failures)
                    reason = "; ".join(parts)

            overall_pass = overall_pass and case_pass
            print(f"{case.name}:")
            print(f"- expected_titles: {', '.join(case.expected_titles) if case.expected_titles else '-'}")
            print(f"- absent_titles: {', '.join(case.expected_absent_titles) if case.expected_absent_titles else '-'}")
            print(f"- empty_expected: {case.expected_empty}")
            print(f"- result: {'PASS' if case_pass else 'FAIL'}")
            print(f"- reason: {reason}")
            print("")

    return overall_pass


def _validate_historical_url_helpers() -> list[str]:
    failures: list[str] = []
    cases = {
        "https://example.com/a?b=2&a=1": "https://example.com/a?a=1&b=2",
        "http://example.com:80/a": "http://example.com/a",
        "https://example.com:8443/a//b#frag": "https://example.com:8443/a/b",
        "ftp://example.com/file": "",
        "not a url": "",
    }
    for raw, expected in cases.items():
        actual = normalize_historical_url(raw)
        if actual != expected:
            failures.append(f"normalize_historical_url({raw!r}) => {actual!r}, expected {expected!r}")

    http_url = normalize_historical_url("http://scheme.test/admin")
    https_url = normalize_historical_url("https://scheme.test/admin")
    if http_url == https_url:
        failures.append("http and https historical URLs collapsed unexpectedly")

    port_a = normalize_historical_url("http://port.test:8080/admin")
    port_b = normalize_historical_url("http://port.test:8081/admin")
    if port_a == port_b:
        failures.append("different ports collapsed unexpectedly")

    gau_only = build_historical_url_results_from_raw(
        {"gau": ["http://gau-only.test/login"]},
        domains=["gau-only.test"],
    )
    if gau_only.get("normalized_urls") != ["http://gau-only.test/login"]:
        failures.append("gau-only raw historical URL output did not normalize as expected")

    wayback_only = build_historical_url_results_from_raw(
        {"waybackurls": ["https://wayback-only.test/api/v1/users"]},
        domains=["wayback-only.test"],
    )
    if wayback_only.get("normalized_urls") != ["https://wayback-only.test/api/v1/users"]:
        failures.append("waybackurls-only raw historical URL output did not normalize as expected")

    duplicated = build_historical_url_results_from_raw(
        {
            "gau": ["https://dup.test/a?b=2&a=1", "not-a-url"],
            "waybackurls": ["https://dup.test/a?a=1&b=2#fragment"],
        },
        domains=["dup.test"],
    )
    if duplicated.get("normalized_urls") != ["https://dup.test/a?a=1&b=2"]:
        failures.append("duplicate historical URLs from gau/waybackurls were not collapsed safely")
    records = duplicated.get("records") if isinstance(duplicated.get("records"), list) else []
    sources = records[0].get("sources") if records and isinstance(records[0], dict) else []
    if set(sources) != {"gau", "waybackurls"}:
        failures.append("duplicate historical URL did not retain both source tools")
    if int(duplicated.get("invalid_count", 0) or 0) != 1:
        failures.append("malformed historical URL count was not tracked")

    missing_tool_result = collect_historical_urls(
        ["missing-tool.test"],
        max_urls=10,
        timeout_sec=1,
        tools=("definitely-missing-gau",),
    )
    warnings = missing_tool_result.get("warnings") if isinstance(missing_tool_result, dict) else []
    if not warnings:
        failures.append("missing historical URL tool did not produce a warning")
    if missing_tool_result.get("records"):
        failures.append("missing historical URL tool unexpectedly produced records")

    return failures


def _evaluate_insight_assertions(case: CorrelationFixtureCase) -> list[str]:
    if not case.expected_insights:
        return []

    data = case.payload.get("data") if isinstance(case.payload.get("data"), dict) else {}
    checks_results = data.get("checks_results") if isinstance(data.get("checks_results"), dict) else {}
    insights = build_correlation_insights(
        target=str((case.payload.get("meta") or {}).get("target") or "") if isinstance(case.payload.get("meta"), dict) else "",
        nmap_output=str(data.get("nmap_output") or ""),
        gobuster_results=data.get("gobuster_results") if isinstance(data.get("gobuster_results"), dict) else {},
        katana_urls=data.get("katana_urls") if isinstance(data.get("katana_urls"), list) else [],
        checks_results=checks_results,
        nuclei_results=data.get("nuclei_results") if isinstance(data.get("nuclei_results"), dict) else {},
        run_context=case.payload,
    )
    failures: list[str] = []
    for expected in case.expected_insights:
        finding_type = str(expected.get("finding_type") or "")
        candidates = [item for item in insights if item.finding_type == finding_type]
        if not candidates:
            failures.append(f"missing insight type: {finding_type}")
            continue
        insight = candidates[0]
        allowed_severities = expected.get("severity")
        if isinstance(allowed_severities, set) and insight.severity not in allowed_severities:
            failures.append(f"{finding_type} severity {insight.severity} not in {sorted(allowed_severities)}")
        min_conf = expected.get("min_confidence")
        if isinstance(min_conf, int) and insight.confidence < min_conf:
            failures.append(f"{finding_type} confidence {insight.confidence} < {min_conf}")
        max_conf = expected.get("max_confidence")
        if isinstance(max_conf, int) and insight.confidence > max_conf:
            failures.append(f"{finding_type} confidence {insight.confidence} > {max_conf}")

        combined_text = " ".join(
            [
                insight.title,
                insight.evidence_summary,
                insight.why_it_matters,
                insight.exploitability_assessment,
                insight.false_positive_notes,
                insight.recommended_first_action,
                " ".join(insight.manual_validation_steps),
            ]
        )
        for required in expected.get("required_text", []) or []:
            if str(required).lower() not in combined_text.lower():
                failures.append(f"{finding_type} missing text: {required}")
        for forbidden in expected.get("forbidden_text", []) or []:
            if str(forbidden).lower() in combined_text.lower():
                failures.append(f"{finding_type} contains forbidden text: {forbidden}")
    return failures
