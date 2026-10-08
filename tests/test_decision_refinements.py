from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

from reconbot.core.engine import (
    RunConfig,
    _build_attack_chains,
    _build_attack_graph,
    _active_validate_endpoint_candidates,
    _classify_endpoints,
    _classify_endpoints_with_status,
    _filter_soft_error_discovery,
    _score_cve_relevance,
    run,
)
from reconbot.core.endpoint_analysis import analyze_endpoints, summary_to_dict
from reconbot.orchestration.ip_enrichment import run_ip_enrichment
from reconbot.report.builder import generate_report
from reconbot.report.correlation import build_correlation_insights
from reconbot.report.suggestions import build_context_aware_suggestions


def _write_run_result(
    run_dir: Path,
    checks_results: dict,
    katana_urls: list[str],
    *,
    gobuster_results: dict | None = None,
    nuclei_results: dict | None = None,
    ip_enrichment: dict | None = None,
    nmap_output: str = "",
    run_state: str = "completed",
    stages: dict | None = None,
    target: str = "example.com",
) -> None:
    checks_payload = dict(checks_results)
    if ip_enrichment:
        checks_payload["ip_enrichment"] = ip_enrichment
    (run_dir / "run_result.json").write_text(
        json.dumps(
            {
                "meta": {"target": target, "mode": "domain", "skipped_tools": []},
                "ip_enrichment": ip_enrichment or {},
                "run_state": run_state,
                "data": {
                    "nmap_output": nmap_output,
                    "katana_urls": katana_urls,
                    "gobuster_results": gobuster_results or {},
                    "checks_results": checks_payload,
                    "nuclei_results": nuclei_results or {"Status": "Success", "findings": []},
                },
                "stages": stages or {},
            }
        ),
        encoding="utf-8",
    )


def _risk_score(html: str) -> int:
    match = re.search(r'<div class="value">(\d+) / 100</div>', html)
    if not match:
        raise AssertionError("risk score not found")
    return int(match.group(1))


def _contains_bytes(value: object) -> bool:
    if isinstance(value, bytes):
        return True
    if isinstance(value, dict):
        return any(_contains_bytes(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_bytes(item) for item in value)
    return False


def _minimal_engine_config(tmpdir: str, *, gobuster_enabled: bool, ffuf_enabled: bool) -> RunConfig:
    return RunConfig(
        target="example.test",
        wordlist=str(Path(tmpdir) / "wordlist.txt"),
        verbose=False,
        nmap_enabled=False,
        subfinder_enabled=False,
        dnsx_enabled=False,
        httpx_enabled=True,
        katana_enabled=False,
        gobuster_enabled=gobuster_enabled,
        ffuf_enabled=ffuf_enabled,
        checks_enabled=False,
        nuclei_enabled=False,
        wafw00f_enabled=False,
        whatweb_enabled=False,
        historical_urls_enabled=False,
        screenshots_enable=False,
        output_dir=tmpdir,
    )


class DecisionRefinementTests(unittest.TestCase):
    def test_dashboard_content_pages_are_not_admin_surfaces(self) -> None:
        classified = _classify_endpoints(
            [
                "https://example.com/blog/dashboard-design-principles.html",
                "https://example.com/services/bi-dashboard.html",
                "https://example.com/blog/dashboard-mistakes.html",
                "https://example.com/dashboard/settings",
                "https://example.com/admin/dashboard",
            ]
        )

        self.assertNotIn("https://example.com/blog/dashboard-design-principles.html", classified["admin_like"])
        self.assertNotIn("https://example.com/services/bi-dashboard.html", classified["admin_like"])
        self.assertNotIn("https://example.com/blog/dashboard-mistakes.html", classified["admin_like"])
        self.assertIn("https://example.com/dashboard/settings", classified["admin_like"])
        self.assertIn("https://example.com/admin/dashboard", classified["admin_like"])

    def test_endpoint_analysis_public_dashboard_pages_are_not_admin_families(self) -> None:
        urls = [
            "https://example.com/blog/dashboard-mistakes.html",
            "https://example.com/services/bi-dashboard.html",
            "https://example.com/admin/dashboard.html",
        ]
        summary = summary_to_dict(
            analyze_endpoints(
                web_urls=[],
                katana_urls=urls,
                gobuster_results={},
                classified_endpoints=_classify_endpoints(urls),
            )
        )

        clusters = {
            str(item.get("representative_url") or ""): item
            for item in summary.get("cluster_insights", [])
            if isinstance(item, dict)
        }
        for public_url in urls[:2]:
            self.assertIn(public_url, clusters)
            self.assertNotEqual("admin", clusters[public_url].get("family_type"))
            self.assertNotIn("admin_like", clusters[public_url].get("bucket_labels", []))
        self.assertEqual("admin", clusters[urls[2]].get("family_type"))
        self.assertIn("admin_like", clusters[urls[2]].get("bucket_labels", []))
        self.assertNotIn("https://example.com/blog/dashboard-mistakes.html", summary["reportworthy_endpoints_by_bucket"]["admin_like"])
        self.assertNotIn("https://example.com/services/bi-dashboard.html", summary["reportworthy_endpoints_by_bucket"]["admin_like"])
        self.assertIn("https://example.com/admin/dashboard.html", summary["reportworthy_endpoints_by_bucket"]["admin_like"])

    def test_public_blog_pages_are_not_debug_test_or_auth_surfaces(self) -> None:
        urls = [
            "https://example.com/blog/dashboard-design-principles.html",
            "https://example.com/blog/category/security/index.html",
            "https://example.com/blog/category/ops/index.html",
            "https://example.com/blog/customer-success-signals.html",
            "https://example.com/blog/incident-review-template.html",
        ]
        classified = _classify_endpoints(urls)

        self.assertNotIn("https://example.com/blog/dashboard-design-principles.html", classified["admin_like"])
        self.assertNotIn("https://example.com/blog/dashboard-design-principles.html", classified["auth_like"])
        self.assertNotIn("https://example.com/blog/dashboard-design-principles.html", classified["debug_like"])
        self.assertNotIn("https://example.com/blog/category/security/index.html", classified["debug_like"])
        self.assertEqual([], classified["debug_like"])

    def test_public_blog_urls_do_not_create_debug_config_chain(self) -> None:
        urls = [
            "https://example.com/blog/category/security/index.html",
            "https://example.com/blog/dashboard-design-principles.html",
            "https://example.com/blog/release-notes-2026-05.html",
            "https://example.com/blog/remote-team-routines.html",
        ]
        classified = _classify_endpoints(urls)
        chains = _build_attack_chains(classified, [])
        graph = _build_attack_graph(classified, [], chains)

        self.assertNotIn("Debug/Test → Config Leak", [str(item.get("name") or "") for item in chains])
        self.assertNotIn("Debug/Test → Config Leak", [str(item.get("name") or "") for item in graph.get("paths", [])])
        self.assertFalse(any(str(node.get("label") or "") == "Config Leak" for node in graph.get("nodes", [])))

    def test_correlation_ignores_dashboard_blog_auth_surface(self) -> None:
        insights = build_correlation_insights(
            target="https://example.com",
            katana_urls=["https://example.com/blog/dashboard-design-principles.html"],
            checks_results={"classified_endpoints": {}},
            gobuster_results={},
            run_context={"data": {}},
        )

        self.assertFalse(any(insight.title == "Olası authentication yüzeyi keşfedildi" for insight in insights))

    def test_upload_folder_uses_manual_validation_not_rce(self) -> None:
        classified = _classify_endpoints(["https://example.com/uploads/"])
        chains = _build_attack_chains(classified, [])
        graph = _build_attack_graph(classified, [], chains)
        names = [str(item.get("name") or "") for item in chains]
        path_names = [str(item.get("name") or "") for item in graph.get("paths", [])]

        self.assertIn("Upload → Manual Validation", names)
        self.assertIn("Upload → Manual Validation", path_names)
        self.assertNotIn("Upload → Possible RCE", names)
        self.assertNotIn("Upload → Possible RCE", path_names)

    def test_structural_exposure_outranks_public_docs_path(self) -> None:
        classified = _classify_endpoints(
            [
                "https://example.com/docs/getting-started.html",
                "https://example.com/config/env",
                "https://example.com/backup/db-dump.sql",
                "https://example.com/debug/console",
                "https://example.com/logs/error.log",
                "https://example.com/internal/users",
            ]
        )
        chains = _build_attack_chains(classified, [])
        graph = _build_attack_graph(classified, [], chains)
        top_path = graph["paths"][0]

        self.assertIn(
            top_path["name"],
            {
                "Config Mirror → Secret/Config Exposure",
                "Backup Area → Sensitive Data Exposure",
                "Debug Console → Internal Routes/Config Exposure",
            },
        )
        self.assertNotEqual(top_path["name"], "Public documentation surface → manual review")

    def test_structural_exposure_raises_report_risk_without_nuclei(self) -> None:
        urls = [
            "https://example.com/docs/getting-started.html",
            "https://example.com/config/env",
            "https://example.com/backup/db-dump.sql",
            "https://example.com/debug/console",
            "https://example.com/logs/error.log",
            "https://example.com/internal/users",
        ]
        classified = _classify_endpoints(urls)
        chains = _build_attack_chains(classified, [])
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": classified,
            "attack_chains": chains,
            "attack_graph": _build_attack_graph(classified, [], chains),
            "exploit_suggestions": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, urls)
            generate_report({}, urls, checks, {"Status": "Success", "findings": []}, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertGreaterEqual(_risk_score(html), 55)
        self.assertIn("High-risk structural exposure signal", html)
        self.assertIn("Config Mirror", html)

    def test_noisy_docs_report_stays_low_and_filters_dashboard_admin(self) -> None:
        urls = [f"https://example.com/blog/dashboard-design-principles-{idx}.html" for idx in range(30)]
        urls += [f"https://example.com/docs/resource-{idx}.html" for idx in range(30)]
        classified = _classify_endpoints(urls)
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": classified,
            "attack_chains": _build_attack_chains(classified, []),
            "attack_graph": _build_attack_graph(classified, [], []),
            "exploit_suggestions": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, urls)
            generate_report({}, urls, checks, {"Status": "Success", "findings": []}, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertLess(_risk_score(html), 30)
        self.assertNotIn("Admin panel yüzeyi", html)
        self.assertNotIn("Debug / Test Endpoint’leri", html)
        self.assertNotIn("Debug/Test → Config Leak", html)

    def test_clean_single_login_report_stays_low(self) -> None:
        urls = ["https://example.com/login.html"]
        classified = _classify_endpoints(urls)
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": classified,
            "attack_chains": _build_attack_chains(classified, []),
            "attack_graph": _build_attack_graph(classified, [], []),
            "exploit_suggestions": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, urls)
            generate_report({}, urls, checks, {"Status": "Success", "findings": []}, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertLess(_risk_score(html), 30)
        self.assertNotIn("Operator review surface breadth", html)

    def test_medium_review_surface_diversity_lands_medium_without_overclaims(self) -> None:
        urls = [
            "https://example.com/admin/login.html",
            "https://example.com/login.html",
            "https://example.com/dashboard/settings",
            "https://example.com/uploads/",
            "https://example.com/api/docs",
            "https://example.com/docs/api-reference.html",
            "https://example.com/profile",
        ]
        classified = _classify_endpoints(urls)
        chains = _build_attack_chains(classified, [])
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": classified,
            "attack_chains": chains,
            "attack_graph": _build_attack_graph(classified, [], chains),
            "exploit_suggestions": [],
        }
        gobuster = {
            "example.com": [
                {"url": "https://example.com/admin/login.html", "status": 200},
                {"url": "https://example.com/login.html", "status": 200},
                {"url": "https://example.com/dashboard/settings", "status": 200},
                {"url": "https://example.com/uploads/", "status": 200},
                {"url": "https://example.com/api/docs", "status": 200},
                {"url": "https://example.com/profile", "status": 200},
                {"url": "https://example.com/backup", "status": 301},
            ]
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, urls, gobuster_results=gobuster)
            generate_report(gobuster, urls, checks, {"Status": "Success", "findings": []}, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        score = _risk_score(html)
        self.assertGreaterEqual(score, 35)
        self.assertLessEqual(score, 50)
        self.assertIn("Operator review surface breadth", html)
        self.assertNotIn("Backup Area → Sensitive Data Exposure", html)
        self.assertNotIn("Debug/Test → Config Leak", html)
        self.assertNotIn("Upload → Possible RCE", html)

    def test_report_prunes_stale_public_content_debug_artifacts(self) -> None:
        urls = [
            "https://example.com/blog/dashboard-design-principles.html",
            "https://example.com/blog/category/security/index.html",
        ]
        stale_classified = {key: [] for key in _classify_endpoints([])}
        stale_classified["debug_like"] = urls[:]
        stale_chains = [
            {
                "name": "Debug/Test → Config Leak",
                "confidence": 75,
                "signals": ["debug/test endpoints=2"],
                "why": "stale public-content false positive",
                "next_tests": ["env/config leak review"],
            }
        ]
        stale_graph = {
            "nodes": [
                {"id": "debug", "label": "Debug/Test Surface", "type": "surface", "count": 2, "details": urls},
                {"id": "config_leak", "label": "Config Leak", "type": "outcome", "count": 1, "details": []},
            ],
            "edges": [{"from": "debug", "to": "config_leak", "reason": "Debug/test yüzeyi config/env leak ihtimalini artırır.", "confidence": 75}],
            "paths": [{"name": "Debug/Test → Config Leak", "confidence": 75, "sequence": ["Debug/Test Surface", "Config Leak"], "why": "stale"}],
        }
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": stale_classified,
            "attack_chains": stale_chains,
            "attack_graph": stale_graph,
            "exploit_suggestions": [
                {
                    "title": "Debug / Config Leak Suggestions",
                    "priority": 74,
                    "surface": "Debug/Test",
                    "why": "2 debug/test endpoint bulundu.",
                    "tests": ["env/config disclosure review"],
                    "matched_endpoints": urls,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, urls)
            generate_report({}, urls, checks, {"Status": "Success", "findings": []}, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertLess(_risk_score(html), 30)
        self.assertNotIn("Debug / Test Endpoint’leri", html)
        self.assertNotIn("Debug/Test → Config Leak", html)
        self.assertNotIn("Config Leak", html)

    def test_real_debug_config_admin_and_login_still_classify(self) -> None:
        urls = [
            "https://example.com/debug/console.html",
            "https://example.com/config/env.html",
            "https://example.com/admin/login",
            "https://example.com/login",
        ]
        classified = _classify_endpoints(urls)

        self.assertIn("https://example.com/debug/console.html", classified["debug_like"])
        self.assertIn("https://example.com/config/env.html", classified["debug_like"])
        chains = _build_attack_chains(classified, [])
        self.assertIn("Config Mirror → Secret/Config Exposure", [str(item.get("name") or "") for item in chains])
        self.assertIn("https://example.com/admin/login", classified["admin_like"])
        self.assertIn("https://example.com/admin/login", classified["auth_like"])
        self.assertIn("https://example.com/login", classified["auth_like"])

    def test_source_control_exposure_creates_structural_candidate(self) -> None:
        urls = [
            "https://example.com/.git/config",
            "https://example.com/.git/HEAD",
            "https://example.com/.git/index",
            "https://example.com/.git/logs/",
        ]
        classified = _classify_endpoints(urls)
        chains = _build_attack_chains(classified, [])
        graph = _build_attack_graph(classified, [], chains)

        self.assertEqual(sorted(urls), sorted(classified["source_control_like"]))
        self.assertEqual([], classified["debug_like"])
        self.assertIn(
            "Source Control Exposure → Code/Secret Leakage → Manual Validation",
            [str(item.get("name") or "") for item in chains],
        )
        self.assertEqual(
            "Source Control Exposure → Code/Secret Leakage → Manual Validation",
            graph["paths"][0]["name"],
        )

    def test_upload_php_apache_is_validation_candidate_not_confirmed_rce(self) -> None:
        urls = ["https://example.com/index.php?page=upload-file.php"]
        tech = [{"technologies": ["PHP", "Apache HTTPD"]}]
        classified = _classify_endpoints(urls)
        chains = _build_attack_chains(classified, tech)
        graph = _build_attack_graph(classified, tech, chains)
        chain_text = json.dumps(chains + graph.get("paths", []), ensure_ascii=False)

        self.assertIn("Upload → RCE Validation Candidate", chain_text)
        self.assertIn("manual validation", chain_text.lower())
        self.assertNotIn("Upload → Possible RCE", chain_text)
        self.assertNotIn('"Possible RCE"', chain_text)

    def test_running_nuclei_zero_findings_structural_report_is_pending_not_clean(self) -> None:
        urls = [
            "https://example.com/.git/config",
            "https://example.com/.git/HEAD",
            "https://example.com/phpinfo.php",
            "https://example.com/index.php?page=upload-file.php",
        ]
        tech = [{"technologies": ["PHP", "Apache HTTPD"]}]
        classified = _classify_endpoints(urls)
        chains = _build_attack_chains(classified, tech)
        checks = {
            "technology_fingerprint": tech,
            "classified_endpoints": classified,
            "attack_chains": chains,
            "attack_graph": _build_attack_graph(classified, tech, chains),
            "exploit_suggestions": [],
        }
        gobuster = {
            "example.com": [
                {"url": "https://example.com/.git/config", "status": 200},
                {"url": "https://example.com/.git/HEAD", "status": 200},
                {"url": "https://example.com/phpinfo.php", "status": 200},
            ]
        }
        nuclei = {"Status": "Running", "findings": []}
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(
                run_dir,
                checks,
                urls,
                gobuster_results=gobuster,
                nuclei_results=nuclei,
                run_state="running",
                stages={"nuclei": {"status": "running", "findings_count": 0}},
            )
            generate_report(gobuster, urls, checks, nuclei, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertNotIn("Bulgu yok, high confidence", html)
        self.assertIn("Nuclei stage is still running", html)
        self.assertIn("Nuclei bulgusu henüz yok", html)
        self.assertIn("Source Control Exposure", html)
        self.assertIn("RCE Validation Candidate", html)
        self.assertIn("Upload yüzeyi bulundu; zafiyet kanıtı değildir, manuel doğrulama gerektirir.", html)

    def test_server_status_403_is_lower_signal_than_readable_runtime_disclosure(self) -> None:
        forbidden_urls = ["https://example.com/server-status"]
        forbidden_classified = _classify_endpoints(forbidden_urls)
        forbidden_checks = {
            "technology_fingerprint": [],
            "classified_endpoints": forbidden_classified,
            "attack_chains": _build_attack_chains(forbidden_classified, []),
            "attack_graph": _build_attack_graph(forbidden_classified, [], []),
            "exploit_suggestions": [],
        }
        readable_urls = ["https://example.com/phpinfo.php"]
        readable_classified = _classify_endpoints(readable_urls)
        readable_checks = {
            "technology_fingerprint": [],
            "classified_endpoints": readable_classified,
            "attack_chains": _build_attack_chains(readable_classified, []),
            "attack_graph": _build_attack_graph(readable_classified, [], []),
            "exploit_suggestions": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            forbidden_dir = Path(tmpdir) / "forbidden"
            forbidden_dir.mkdir()
            forbidden_gobuster = {"example.com": [{"url": forbidden_urls[0], "status": 403}]}
            _write_run_result(forbidden_dir, forbidden_checks, forbidden_urls, gobuster_results=forbidden_gobuster)
            generate_report(forbidden_gobuster, forbidden_urls, forbidden_checks, {"Status": "Success", "findings": []}, "example.com", "", output_dir=forbidden_dir, open_browser=False, quiet=True)
            forbidden_html = (forbidden_dir / "report.html").read_text(encoding="utf-8")

            readable_dir = Path(tmpdir) / "readable"
            readable_dir.mkdir()
            readable_gobuster = {"example.com": [{"url": readable_urls[0], "status": 200}]}
            _write_run_result(readable_dir, readable_checks, readable_urls, gobuster_results=readable_gobuster)
            generate_report(readable_gobuster, readable_urls, readable_checks, {"Status": "Success", "findings": []}, "example.com", "", output_dir=readable_dir, open_browser=False, quiet=True)
            readable_html = (readable_dir / "report.html").read_text(encoding="utf-8")

        self.assertNotIn("Runtime Disclosure Signal", forbidden_html)
        self.assertIn("Runtime Disclosure Signal", readable_html)
        self.assertLess(_risk_score(forbidden_html), _risk_score(readable_html))

    def test_gobuster_partial_results_survive_one_base_failure(self) -> None:
        ok_base = "https://ok.example.test"
        bad_base = "https://bad.example.test"
        ok_hit = {"url": f"{ok_base}/health", "status": 200}
        def fake_gobuster(base_url: str, *_args: object, **_kwargs: object) -> list[dict]:
            if base_url == bad_base:
                raise RuntimeError("gobuster boom")
            return [ok_hit]

        with tempfile.TemporaryDirectory() as tmpdir:
            config = _minimal_engine_config(tmpdir, gobuster_enabled=True, ffuf_enabled=False)
            with (
                patch("reconbot.core.engine.socket.getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 0))]),
                patch("reconbot.core.engine.run_httpx", return_value=[ok_base, bad_base]),
                patch("reconbot.core.engine._run_gobuster_compat", side_effect=fake_gobuster),
            ):
                result = run(config)
            payload = json.loads((Path(tmpdir) / "run_result.json").read_text(encoding="utf-8"))

        self.assertEqual([ok_hit], result.gobuster_results[ok_base])
        self.assertNotIn(bad_base, result.gobuster_results)
        self.assertEqual([ok_hit], payload["gobuster"]["results"][ok_base])
        self.assertEqual(1, payload["gobuster"]["summary"]["total_hits"])
        self.assertEqual("partial", payload["stages"]["gobuster"]["status"])
        self.assertEqual(1, payload["stages"]["gobuster"]["failed_base_url_count"])
        self.assertEqual([bad_base], payload["stages"]["gobuster"]["failed_base_urls"])

    def test_ffuf_partial_results_survive_one_base_failure(self) -> None:
        ok_base = "https://ok.example.test"
        bad_base = "https://bad.example.test"
        ok_hit = {"url": f"{ok_base}/health", "status": 200}
        def fake_ffuf(*_args: object, **kwargs: object) -> dict:
            if kwargs.get("base_url") == bad_base:
                raise RuntimeError("ffuf boom")
            return {"findings": [ok_hit]}

        with tempfile.TemporaryDirectory() as tmpdir:
            config = _minimal_engine_config(tmpdir, gobuster_enabled=False, ffuf_enabled=True)
            with (
                patch("reconbot.core.engine.socket.getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 0))]),
                patch("reconbot.core.engine.run_httpx", return_value=[ok_base, bad_base]),
                patch("reconbot.core.engine.run_ffuf", side_effect=fake_ffuf),
            ):
                result = run(config)
            payload = json.loads((Path(tmpdir) / "run_result.json").read_text(encoding="utf-8"))

        self.assertEqual([ok_hit], result.checks_results["ffuf_findings"][ok_base])
        self.assertNotIn(bad_base, result.checks_results["ffuf_findings"])
        self.assertEqual([ok_hit], payload["ffuf"]["results"][ok_base])
        self.assertEqual(1, payload["ffuf"]["summary"]["total_hits"])
        self.assertEqual("partial", payload["stages"]["ffuf"]["status"])
        self.assertEqual(1, payload["stages"]["ffuf"]["failed_base_url_count"])
        self.assertEqual([bad_base], payload["stages"]["ffuf"]["failed_base_urls"])

    def test_active_candidate_validation_suppresses_generic_error_inventory(self) -> None:
        base = "https://zekagucu.example.test"
        auth_paths = [
            "/lms/Account/ForgotPassword",
            "/lms/Account/Login",
            "/lms/Account/Signup",
        ]
        noise_paths = [
            "/admin_interface",
            "/administrator-panel",
            "/administratoraccounts",
            "/.well-known/apple-app-site-association",
            "/.well-known/apple-developer-merchantid-domain-association",
            "/.well-known/nfv-oauth-server-configuration",
            "/.well-known/oauth-authorization-server",
            "/api/experiments",
            "/api/experiments/configurations",
            "/.git/HEAD",
        ]
        candidates = [
            {"source": "ffuf", "url": f"{base}{path}", "detail": "fixture"}
            for path in noise_paths + auth_paths
        ]
        baseline = {
            "base_url": base,
            "status_code": 400,
            "final_url": f"{base}/Error/400",
            "content_length": 620,
            "words": 9,
            "lines": 4,
            "title": "Error",
            "body_hash": "baseline",
            "error_markers": ["/error/400", "aspxerrorpath"],
        }

        def fake_probe(url: str, **_kwargs: object) -> dict:
            path = urlsplit(url).path
            if path in auth_paths:
                body = (
                    '<html><head><title>Account Login</title></head><body>'
                    '<form action="/lms/Account/Login" method="post">'
                    '<input name="__RequestVerificationToken">'
                    '<input type="password" name="Password">'
                    "</form></body></html>"
                )
                return {
                    "url": url,
                    "status_code": 200,
                    "final_url": url,
                    "content_type": "text/html; charset=utf-8",
                    "content_length": len(body),
                    "words": 10,
                    "lines": 1,
                    "title": "Account Login",
                    "body_hash": f"auth-{path}",
                    "error_markers": [],
                    "redirect_chain": [],
                    "_body_preview": body,
                    "_body_bytes_prefix": body.encode("utf-8")[:64],
                }
            body = "<html><head><title>Error</title></head><body>Bad request file not found</body></html>"
            return {
                "url": url,
                "status_code": 400,
                "final_url": f"{base}/Error/400?aspxerrorpath={path}",
                "content_type": "text/html; charset=utf-8",
                "content_length": 620,
                "words": 9,
                "lines": 4,
                "title": "Error",
                "body_hash": "baseline",
                "error_markers": ["/error/400", "aspxerrorpath", "file not found"],
                "redirect_chain": [f"{base}/Error/400?aspxerrorpath={path}"],
                "_body_preview": body,
                "_body_bytes_prefix": body.encode("utf-8")[:64],
            }

        with (
            patch("reconbot.core.engine._build_soft_error_baseline", return_value=baseline),
            patch("reconbot.core.engine._probe_soft_error_response", side_effect=fake_probe),
        ):
            validation = _active_validate_endpoint_candidates(
                candidate_records=candidates,
                base_urls=[base],
                existing_baselines={base: baseline},
                timeout=3,
            )

        confirmed_urls = sorted(f"{base}{path}" for path in auth_paths)
        self.assertEqual(confirmed_urls, validation["confirmed_urls"])
        self.assertEqual(len(noise_paths), validation["suppressed_count"])
        self.assertEqual({"confirmed": 3, "suppressed_generic_redirect": len(noise_paths)}, validation["by_status"])
        for path in noise_paths:
            status = validation["by_url"][f"{base}{path}"]["classification_status"]
            self.assertEqual("suppressed_generic_redirect", status)

        classified = _classify_endpoints(validation["confirmed_urls"])
        self.assertEqual(confirmed_urls, sorted(classified["auth_like"]))
        self.assertEqual([], classified["admin_like"])
        self.assertEqual([], classified["api_like"])
        self.assertEqual([], classified["source_control_like"])

        chains = _build_attack_chains(classified, [])
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": classified,
            "attack_chains": chains,
            "attack_graph": _build_attack_graph(classified, [], chains),
            "exploit_suggestions": [],
            "candidate_validation": validation,
            "ffuf_findings": {},
            "ffuf_summary": {"base_url_count": 0, "total_hits": 0, "status_counts": {}},
            "soft_error_filter": {"suppressed_count": 0, "baselines": {base: baseline}},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, validation["confirmed_urls"], gobuster_results={}, nuclei_results={"Status": "Success", "findings": []})
            generate_report({}, validation["confirmed_urls"], checks, {"Status": "Success", "findings": []}, base, "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertLess(_risk_score(html), 55)
        self.assertIn("/lms/Account/Login", html)
        self.assertIn("/lms/Account/Signup", html)
        self.assertIn("/lms/Account/ForgotPassword", html)
        self.assertIn("Suppressed / Noise", html)
        self.assertIn("10 candidate endpoints suppressed as generic error/redirect/noise.", html)
        self.assertNotIn("Source Control Exposure", html)
        self.assertNotIn("Code/Secret Leakage", html)

    def test_active_candidate_validation_json_sanitizes_bytes(self) -> None:
        base = "https://bytes.example.test"
        url = f"{base}/api/config"
        baseline = {
            "base_url": base,
            "status_code": 404,
            "final_url": f"{base}/missing",
            "content_length": 120,
            "words": 4,
            "lines": 2,
            "samples": [{"initial": {"_body_bytes_prefix": b"\xff\xfe"}}],
        }

        def fake_probe(_url: str, **_kwargs: object) -> dict:
            return {
                "url": url,
                "status_code": 200,
                "final_url": url,
                "content_type": "application/json",
                "content_length": 18,
                "words": 1,
                "lines": 1,
                "title": "",
                "body_hash": "api-json",
                "error_markers": [],
                "redirect_chain": [],
                "raw_body": b'{"status":"ok"}',
                "_body_preview": '{"status":"ok"}',
                "_body_bytes_prefix": b'{"status',
            }

        with (
            patch("reconbot.core.engine._build_soft_error_baseline", return_value=baseline),
            patch("reconbot.core.engine._probe_soft_error_response", side_effect=fake_probe),
        ):
            validation = _active_validate_endpoint_candidates(
                candidate_records=[{"source": "ffuf", "url": url, "detail": "bytes-fixture"}],
                base_urls=[base],
                existing_baselines={base: baseline},
                timeout=3,
            )

        json.dumps(validation)
        self.assertFalse(_contains_bytes(validation))
        self.assertEqual([url], validation["confirmed_urls"])
        raw_body = validation["by_url"][url]["validation"]["raw_body"]
        self.assertEqual(len(b'{"status":"ok"}'), raw_body["bytes_length"])
        self.assertIn("sha256", raw_body)

    def test_active_candidate_validation_confirms_real_git_evidence(self) -> None:
        base = "https://repo.example.test"
        paths = ["/.git/HEAD", "/.git/config", "/.git/index"]
        candidates = [{"source": "ffuf", "url": f"{base}{path}", "detail": "git-fixture"} for path in paths]
        baseline = {
            "base_url": base,
            "status_code": 404,
            "final_url": f"{base}/missing",
            "content_length": 120,
            "words": 4,
            "lines": 2,
            "error_markers": ["not found"],
        }

        def fake_probe(url: str, **_kwargs: object) -> dict:
            path = urlsplit(url).path
            if path.endswith("/HEAD"):
                body = "ref: refs/heads/main\n"
                prefix = body.encode("utf-8")[:8]
            elif path.endswith("/config"):
                body = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@example/repo.git\n"
                prefix = body.encode("utf-8")[:8]
            else:
                body = "DIRC\x00\x00\x00\x02"
                prefix = b"DIRC"
            return {
                "url": url,
                "status_code": 200,
                "final_url": url,
                "content_type": "application/octet-stream" if path.endswith("/index") else "text/plain",
                "content_length": len(body),
                "words": 2,
                "lines": 1,
                "title": "",
                "body_hash": f"git-{path}",
                "error_markers": [],
                "redirect_chain": [],
                "_body_preview": body,
                "_body_bytes_prefix": prefix,
            }

        with (
            patch("reconbot.core.engine._build_soft_error_baseline", return_value=baseline),
            patch("reconbot.core.engine._probe_soft_error_response", side_effect=fake_probe),
        ):
            validation = _active_validate_endpoint_candidates(
                candidate_records=candidates,
                base_urls=[base],
                existing_baselines={base: baseline},
                timeout=3,
            )

        confirmed = sorted(f"{base}{path}" for path in paths)
        self.assertEqual(confirmed, validation["confirmed_urls"])
        self.assertEqual({"confirmed": 3}, validation["by_status"])
        json.dumps(validation)
        classified = _classify_endpoints(validation["confirmed_urls"])
        self.assertEqual(confirmed, sorted(classified["source_control_like"]))

    def test_ffuf_soft_error_redirect_cluster_is_suppressed_before_report_scoring(self) -> None:
        base = "https://noise.example.test"
        sensitive_paths = [
            "/.git/HEAD",
            "/.git/config",
            "/.git/index",
            "/.well-known/openid-configuration",
            "/admin",
            "/backup",
        ]
        filler_paths = [f"/random-soft-error-{idx}" for idx in range(60)]
        ffuf_hits = [
            {
                "url": f"{base}{path}",
                "status": 302,
                "content_length": 620 + (idx % 3),
                "words": 9,
                "lines": 4,
                "redirect_location": "/Error/400",
                "source_tool": "ffuf",
            }
            for idx, path in enumerate(sensitive_paths + filler_paths)
        ]
        baseline = {
            "base_url": base,
            "status_code": 302,
            "final_url": f"{base}/Error/400",
            "content_length": 620,
            "words": 9,
            "lines": 4,
            "title": "Error",
            "body_hash": "baseline",
            "error_markers": ["/error/400"],
            "samples": [{"initial": {"_body_bytes_prefix": b"\x00\x01raw"}}],
        }

        with patch("reconbot.core.engine._build_soft_error_baseline", return_value=baseline):
            _gobuster, filtered_ffuf, metadata = _filter_soft_error_discovery(
                web_urls=[base],
                gobuster_results={},
                ffuf_results={base: ffuf_hits},
                timeout=3,
            )

        self.assertEqual({}, filtered_ffuf)
        self.assertEqual(len(ffuf_hits), metadata["suppressed_count"])
        json.dumps(metadata)
        self.assertFalse(_contains_bytes(metadata))

        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": _classify_endpoints([]),
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [],
            "ffuf_findings": filtered_ffuf,
            "ffuf_summary": {"base_url_count": 0, "total_hits": 0, "status_counts": {}},
            "soft_error_filter": metadata,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, [], gobuster_results={}, nuclei_results={"Status": "Success", "findings": []})
            generate_report({}, [], checks, {"Status": "Success", "findings": []}, "noise.example.test", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertLess(_risk_score(html), 75)
        self.assertNotIn("Source Control Exposure", html)
        self.assertNotIn("Code/Secret Leakage", html)
        self.assertIn(f"{len(ffuf_hits)} candidates suppressed as soft-error / generic redirect.", html)

    def test_real_git_head_body_survives_soft_error_filter(self) -> None:
        base = "https://repo.example.test"
        git_head_url = f"{base}/.git/HEAD"
        ffuf_hit = {
            "url": git_head_url,
            "status": 200,
            "content_length": 21,
            "words": 2,
            "lines": 1,
            "source_tool": "ffuf",
        }
        baseline = {
            "base_url": base,
            "status_code": 404,
            "final_url": f"{base}/missing",
            "content_length": 120,
            "words": 4,
            "lines": 2,
            "error_markers": ["not found"],
        }
        probe = {
            "url": git_head_url,
            "status_code": 200,
            "final_url": git_head_url,
            "content_length": 21,
            "words": 2,
            "lines": 1,
            "title": "",
            "body_hash": "git-head",
            "error_markers": [],
            "_body_preview": "ref: refs/heads/main\n",
            "_body_bytes_prefix": b"ref: ref",
        }

        with (
            patch("reconbot.core.engine._build_soft_error_baseline", return_value=baseline),
            patch("reconbot.core.engine._probe_soft_error_response", return_value=probe),
        ):
            _gobuster, filtered_ffuf, metadata = _filter_soft_error_discovery(
                web_urls=[base],
                gobuster_results={},
                ffuf_results={base: [ffuf_hit]},
                timeout=3,
            )

        self.assertEqual(0, metadata["suppressed_count"])
        self.assertEqual(1, len(filtered_ffuf[base]))
        self.assertEqual("confirmed_body", filtered_ffuf[base][0]["evidence_status"])
        classified = _classify_endpoints([filtered_ffuf[base][0]["url"]])
        self.assertIn(git_head_url, classified["source_control_like"])

    def test_engine_status_aware_classification_downgrades_forbidden_server_status(self) -> None:
        url = "https://example.com/server-status"
        classified, blocked = _classify_endpoints_with_status([url], readable_urls=[], forbidden_urls=[url])
        chains = _build_attack_chains(classified, [])
        graph = _build_attack_graph(classified, [], chains)

        self.assertEqual([url], blocked)
        self.assertNotIn(url, classified["debug_like"])
        self.assertNotIn("Runtime Disclosure → Manual Validation", [str(item.get("name") or "") for item in chains])
        self.assertFalse(any(str(node.get("label") or "") == "Runtime Disclosure" for node in graph.get("nodes", [])))

    def test_phpinfo_200_remains_high_confidence_runtime_disclosure(self) -> None:
        url = "https://example.com/phpinfo.php"
        classified, blocked = _classify_endpoints_with_status([url], readable_urls=[url], forbidden_urls=[])
        chains = _build_attack_chains(classified, [])
        graph = _build_attack_graph(classified, [], chains)

        self.assertEqual([], blocked)
        self.assertIn(url, classified["debug_like"])
        self.assertIn("Runtime Disclosure → Manual Validation", [str(item.get("name") or "") for item in chains])
        self.assertTrue(any(str(node.get("label") or "") == "Runtime Disclosure" for node in graph.get("nodes", [])))

    def test_readable_structural_exposures_remain_high_risk_candidates(self) -> None:
        urls = [
            "https://example.com/.git/config",
            "https://example.com/config/env.html",
            "https://example.com/backup/db-dump-preview.sql",
            "https://example.com/logs/app-error.log",
            "https://example.com/debug/console.html",
        ]
        classified, blocked = _classify_endpoints_with_status(urls, readable_urls=urls, forbidden_urls=[])
        chains = _build_attack_chains(classified, [])
        chain_names = [str(item.get("name") or "") for item in chains]

        self.assertEqual([], blocked)
        self.assertIn("https://example.com/.git/config", classified["source_control_like"])
        self.assertIn("https://example.com/debug/console.html", classified["debug_like"])
        self.assertIn("Source Control Exposure → Code/Secret Leakage → Manual Validation", chain_names)
        self.assertIn("Config Mirror → Secret/Config Exposure", chain_names)
        self.assertIn("Backup Area → Sensitive Data Exposure", chain_names)
        self.assertIn("Logs Exposure → Internal Info Disclosure", chain_names)
        self.assertIn("Debug Console → Internal Routes/Config Exposure", chain_names)

    def test_backup_redirect_alone_is_not_debug_or_high_confidence_backup_exposure(self) -> None:
        url = "https://example.com/backup"
        classified, blocked = _classify_endpoints_with_status([url], readable_urls=[], forbidden_urls=[])
        chains = _build_attack_chains(classified, [])
        graph = _build_attack_graph(classified, [], chains)
        names = [str(item.get("name") or "") for item in chains]

        self.assertEqual([], blocked)
        self.assertNotIn(url, classified["debug_like"])
        self.assertNotIn("Backup Area → Sensitive Data Exposure", names)
        self.assertNotIn("Debug/Test → Config Leak", names)
        self.assertFalse(any(str(node.get("label") or "") == "Sensitive Data Exposure" for node in graph.get("nodes", [])))

    def test_readable_backup_dump_or_config_stays_strong(self) -> None:
        urls = [
            "https://example.com/backup/db-dump-preview.sql",
            "https://example.com/backup/app-config.bak",
        ]
        classified, blocked = _classify_endpoints_with_status(urls, readable_urls=urls, forbidden_urls=[])
        chains = _build_attack_chains(classified, [])
        graph = _build_attack_graph(classified, [], chains)
        names = [str(item.get("name") or "") for item in chains]

        self.assertEqual([], blocked)
        self.assertIn("Backup Area → Sensitive Data Exposure", names)
        self.assertTrue(any(str(node.get("label") or "") == "Backup Area" for node in graph.get("nodes", [])))
        self.assertTrue(any(str(node.get("label") or "") == "Sensitive Data Exposure" for node in graph.get("nodes", [])))

    def test_weak_debug_redirect_or_status_page_does_not_create_config_leak_path(self) -> None:
        urls = ["https://example.com/debug", "https://example.com/debug/status.html"]
        classified, blocked = _classify_endpoints_with_status(urls, readable_urls=[], forbidden_urls=[])
        chains = _build_attack_chains(classified, [])
        graph = _build_attack_graph(classified, [], chains)

        self.assertEqual([], blocked)
        self.assertEqual([], classified["debug_like"])
        self.assertNotIn("Debug/Test → Config Leak", [str(item.get("name") or "") for item in chains])
        self.assertNotIn("Debug/Test → Config Leak", [str(item.get("name") or "") for item in graph.get("paths", [])])

    def test_readable_debug_console_stays_debug_exposure(self) -> None:
        url = "https://example.com/debug/console.html"
        classified, blocked = _classify_endpoints_with_status([url], readable_urls=[url], forbidden_urls=[])
        chains = _build_attack_chains(classified, [])

        self.assertEqual([], blocked)
        self.assertIn(url, classified["debug_like"])
        self.assertIn("Debug Console → Internal Routes/Config Exposure", [str(item.get("name") or "") for item in chains])

    def test_engine_and_report_graph_agree_for_forbidden_server_status(self) -> None:
        url = "https://example.com/server-status"
        classified, blocked = _classify_endpoints_with_status([url], readable_urls=[], forbidden_urls=[url])
        chains = _build_attack_chains(classified, [])
        graph = _build_attack_graph(classified, [], chains)
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": classified,
            "blocked_structural_candidates": blocked,
            "attack_chains": chains,
            "attack_graph": graph,
            "exploit_suggestions": [],
        }
        gobuster = {"example.com": [{"url": url, "status": 403}]}
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, [url], gobuster_results=gobuster)
            generate_report(gobuster, [url], checks, {"Status": "Success", "findings": []}, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertEqual([url], blocked)
        self.assertFalse(any(str(node.get("label") or "") == "Runtime Disclosure" for node in graph.get("nodes", [])))
        self.assertNotIn("Runtime Disclosure Signal", html)
        self.assertNotIn("Debug/Test → Config Leak", html)

    def test_unrelated_vendor_cve_keyword_overlap_stays_low_relevance(self) -> None:
        classified = _classify_endpoints(["https://example.com/index.php?page=upload-file.php"])
        scored = _score_cve_relevance(
            {
                "cve_id": "CVE-2014-125113",
                "description": "Dell KACE Systems Management Appliance allows PHP file upload abuse.",
                "query_product": "PHP",
            },
            classified,
            [{"technologies": ["PHP", "Apache HTTPD"]}],
        )

        self.assertLess(scored["relevance_score"], 30)
        self.assertIn("product/vendor mismatch; manual review only", scored["relevance_reasons"])

    def test_clean_single_login_suggestion_is_low_priority_hardening_not_attack(self) -> None:
        suggestions = build_context_aware_suggestions(
            [
                {
                    "title": "Auth / Admin Abuse Suggestions",
                    "priority": 74,
                    "surface": "Auth/Admin",
                    "why": "1 auth endpoint bulundu. Bu yüzden access control testleri öne çıktı.",
                    "tests": ["default credential checks", "forced browsing"],
                    "evidence": ["auth endpoints=1"],
                    "matched_endpoints": ["https://example.com/login.html"],
                }
            ],
            risk_score=3,
            discovery_reliability="HIGH",
            decision_confidence="High",
            failed_tier_1=[],
            failed_tier_2=[],
            failed_tier_3=[],
        )

        self.assertEqual(1, len(suggestions))
        self.assertEqual("HARDENING", suggestions[0]["category"])
        self.assertLessEqual(suggestions[0]["adjusted_confidence"], 55)
        self.assertNotEqual(74, suggestions[0]["adjusted_confidence"])
        self.assertIn("Normal login", suggestions[0]["title"])
        self.assertIn("hardening", suggestions[0]["title"])
        self.assertNotIn("ATTACK", suggestions[0]["category"])

    def test_real_admin_login_suggestion_still_emits_auth_admin_review(self) -> None:
        suggestions = build_context_aware_suggestions(
            [
                {
                    "title": "Auth / Admin Abuse Suggestions",
                    "priority": 82,
                    "surface": "Auth/Admin",
                    "why": "1 auth endpoint ve 1 admin panel bulundu.",
                    "tests": ["default credential checks", "forced browsing", "role / access control matrix testing"],
                    "evidence": ["auth endpoints=1", "admin panels=1"],
                    "matched_endpoints": ["https://example.com/login", "https://example.com/admin/dashboard.html"],
                }
            ],
            risk_score=35,
            discovery_reliability="HIGH",
            decision_confidence="High",
            failed_tier_1=[],
            failed_tier_2=[],
            failed_tier_3=[],
        )

        self.assertEqual(1, len(suggestions))
        self.assertEqual("ATTACK", suggestions[0]["category"])
        self.assertGreaterEqual(suggestions[0]["adjusted_confidence"], 70)
        self.assertIn("Auth / admin", suggestions[0]["title"])

    def test_recommendation_engine_preserves_url_evidence_fields(self) -> None:
        suggestions = build_context_aware_suggestions(
            [
                {
                    "title": "Auth / Admin Abuse Suggestions",
                    "priority": 82,
                    "surface": "Auth/Admin",
                    "why": "1 auth endpoint ve 1 admin panel bulundu.",
                    "tests": ["role / access control matrix testing"],
                    "evidence": ["auth endpoints=1", "admin panels=1"],
                    "matched_endpoints": [
                        "https://example.com/lms/Account/Login",
                        "https://example.com/admin/dashboard",
                    ],
                    "contributing_signals": ["auth_endpoints=1", "admin_panels=1"],
                }
            ],
            risk_score=35,
            discovery_reliability="HIGH",
            decision_confidence="High",
            failed_tier_1=[],
            failed_tier_2=[],
            failed_tier_3=[],
        )

        self.assertEqual(
            ["https://example.com/lms/Account/Login", "https://example.com/admin/dashboard"],
            suggestions[0]["recommended_urls"],
        )
        self.assertEqual("confirmed", suggestions[0]["validation_state"])
        self.assertIn("evidence_refs", suggestions[0])
        json.dumps(suggestions)

    def test_report_recommendation_details_include_confirmed_urls_and_hide_suppressed(self) -> None:
        login_url = "https://example.com/lms/Account/Login"
        suppressed_url = "https://example.com/admin_interface"
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": {
                "admin_like": [],
                "auth_like": [login_url],
                "api_like": [],
                "upload_like": [],
                "debug_like": [],
                "docs_like": [],
                "source_control_like": [],
            },
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [
                {
                    "title": "Auth / Admin Abuse Suggestions",
                    "priority": 78,
                    "surface": "Auth/Admin",
                    "why": "Auth endpoint bulundu.",
                    "tests": ["role / access control matrix testing"],
                    "evidence": ["auth endpoints=1"],
                    "matched_endpoints": [login_url, suppressed_url],
                }
            ],
            "candidate_validation": {
                "by_url": {
                    login_url: {
                        "url": login_url,
                        "source": "katana",
                        "categories": ["auth"],
                        "classification_status": "confirmed",
                        "validation": {"status_code": 200},
                    },
                    suppressed_url: {
                        "url": suppressed_url,
                        "source": "ffuf",
                        "categories": ["admin"],
                        "classification_status": "suppressed_generic_redirect",
                        "validation": {"status_code": 400, "final_url": "https://example.com/Error/400"},
                    },
                }
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, [login_url], nuclei_results={"Status": "Success", "findings": []})
            generate_report({}, [login_url], checks, {"Status": "Success", "findings": []}, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("İlgili URL’ler", html)
        self.assertIn(login_url, html)
        self.assertIn("kaynak=katana", html)
        self.assertIn("suppressed_generic_redirect", html)
        self.assertNotIn(f'href="{suppressed_url}"', html)

    def test_source_control_recommendation_lists_confirmed_git_urls(self) -> None:
        git_urls = [
            "https://example.com/.git/HEAD",
            "https://example.com/.git/config",
            "https://example.com/.git/index",
        ]
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": {
                "admin_like": [],
                "auth_like": [],
                "api_like": [],
                "upload_like": [],
                "debug_like": [],
                "docs_like": [],
                "source_control_like": git_urls,
            },
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [
                {
                    "title": "Source Control Exposure Manual Validation",
                    "priority": 94,
                    "surface": "Source Control",
                    "why": "Repository metadata exposure signal detected.",
                    "tests": ["confirm leaked remotes/config/history"],
                    "evidence": ["source_control endpoints=3"],
                    "matched_endpoints": git_urls,
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, git_urls, nuclei_results={"Status": "Success", "findings": []})
            generate_report({}, git_urls, checks, {"Status": "Success", "findings": []}, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("İlgili URL’ler", html)
        for url in git_urls:
            self.assertIn(url, html)

    def test_nuclei_passwd_like_evidence_uses_observed_behavior_wording(self) -> None:
        nuclei = {
            "Status": "Success",
            "findings": [
                {
                    "template-id": "fanwei-ecology-rce",
                    "matched-at": "https://example.com/download?file=../../../../etc/passwd",
                    "info": {
                        "name": "Fanwei e-cology RCE",
                        "severity": "high",
                        "description": "Product-specific template matched a response pattern.",
                    },
                    "extracted-results": ["root:x:0:0:root:/root:/bin/bash"],
                    "matcher-name": "passwd",
                }
            ],
        }
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": {
                "admin_like": [],
                "auth_like": [],
                "api_like": [],
                "upload_like": [],
                "debug_like": [],
                "docs_like": [],
                "source_control_like": [],
            },
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, [], nuclei_results=nuclei)
            generate_report({}, [], checks, nuclei, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("Observed evidence: file disclosure / passwd-like content", html)
        self.assertIn("Fanwei e-cology RCE", html)
        self.assertIn("Template name is not proof", html)
        self.assertIn("nuclei_template:fanwei-ecology-rce", html)

    def test_cve_rows_include_nvd_link_and_local_evidence(self) -> None:
        server_status = "https://example.com/server-status"
        checks = {
            "technology_fingerprint": [{"site": "https://example.com", "technologies": ["Apache HTTP Server 2.4.7"]}],
            "classified_endpoints": {
                "admin_like": [],
                "auth_like": [],
                "api_like": [],
                "upload_like": [],
                "debug_like": [server_status],
                "docs_like": [],
                "source_control_like": [],
            },
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [],
            "cve_enrichment": {
                "query_count": 1,
                "matches": [
                    {
                        "product": "Apache HTTP Server",
                        "version": "2.4.7",
                        "keyword": "Apache HTTP Server 2.4.7",
                        "evidence": "WhatWeb detected Apache HTTP Server 2.4.7",
                        "cves": [
                            {
                                "cve_id": "CVE-2014-0226",
                                "relevance_score": 82,
                                "description": "Apache HTTP Server vulnerability candidate.",
                                "relevance_reasons": ["apache stack"],
                            }
                        ],
                    }
                ],
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, [server_status], nuclei_results={"Status": "Success", "findings": []})
            generate_report({}, [server_status], checks, {"Status": "Success", "findings": []}, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2014-0226", html)
        self.assertIn("İlgili yerel kanıt", html)
        self.assertIn("cve-detail-row", html)
        self.assertIn("cve-detail-block", html)
        self.assertIn(server_status, html)
        self.assertIn("CVE korelasyonu kesin zafiyet kanıtı değildir", html)

    def test_attack_chain_and_priority_rows_include_relevant_urls(self) -> None:
        git_urls = [
            "https://example.com/.git/HEAD",
            "https://example.com/.git/config",
        ]
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": {
                "admin_like": [],
                "auth_like": [],
                "api_like": [],
                "upload_like": [],
                "debug_like": [],
                "docs_like": [],
                "source_control_like": git_urls,
            },
            "attack_chains": [
                {
                    "name": "Source Control Exposure → Code/Secret Leakage → Manual Validation",
                    "confidence": 92,
                    "signals": ["source_control endpoints=2"],
                    "why": "Repository metadata exposure signal detected.",
                    "next_tests": ["Confirm repository metadata exposure"],
                }
            ],
            "attack_graph": {},
            "exploit_suggestions": [],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, git_urls, nuclei_results={"Status": "Success", "findings": []})
            generate_report({}, git_urls, checks, {"Status": "Success", "findings": []}, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("Referansları göster", html)
        self.assertIn("Source Control Exposure Signal", html)
        self.assertIn("Validation state", html)
        for url in git_urls:
            self.assertIn(url, html)

    def test_attack_priority_nuclei_row_includes_url_and_template_id(self) -> None:
        affected_url = "https://example.com/admin/download?file=../../../../etc/passwd"
        nuclei = {
            "Status": "Success",
            "findings": [
                {
                    "template-id": "generic-passwd-disclosure",
                    "matched-at": affected_url,
                    "info": {"name": "Generic File Disclosure", "severity": "high"},
                    "extracted-results": ["root:x:0:0:root:/root:/bin/bash"],
                }
            ],
        }
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": {
                "admin_like": ["https://example.com/admin"],
                "auth_like": [],
                "api_like": [],
                "upload_like": [],
                "debug_like": [],
                "docs_like": [],
                "source_control_like": [],
            },
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, [affected_url], nuclei_results=nuclei)
            generate_report({}, [affected_url], checks, nuclei, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("Nuclei Bulguları", html)
        self.assertIn(affected_url, html)
        self.assertIn("nuclei_template:generic-passwd-disclosure", html)
        self.assertIn("Observed evidence: file disclosure / passwd-like content", html)

    def test_upload_priority_language_is_manual_validation_not_confirmed_exploit(self) -> None:
        upload_url = "https://example.com/upload"
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": {
                "admin_like": [],
                "auth_like": [],
                "api_like": [],
                "upload_like": [upload_url],
                "debug_like": [],
                "docs_like": [],
                "source_control_like": [],
            },
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, [upload_url], nuclei_results={"Status": "Success", "findings": []})
            generate_report({}, [upload_url], checks, {"Status": "Success", "findings": []}, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("Upload yüzeyi bulundu; zafiyet kanıtı değildir, manuel doğrulama gerektirir.", html)
        self.assertIn(upload_url, html)
        self.assertIn("server-side execution", html)
        self.assertNotIn("confirmed vulnerability veya RCE kanıtı değildir", html)
        self.assertNotIn("Upload → Possible RCE", html)

    def test_ip_enrichment_available_skipped_renders_section_and_nav_without_raising_risk(self) -> None:
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": {
                "admin_like": [],
                "auth_like": [],
                "api_like": [],
                "upload_like": [],
                "debug_like": [],
                "docs_like": [],
                "source_control_like": [],
            },
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [],
        }
        ip_enrichment = {
            "status": "available_skipped",
            "original_target": "https://example.com",
            "resolved_ip": "192.0.2.10",
            "hostname": "example.com",
            "scan_mode": "skipped",
            "detailed_nmap_enabled": False,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, [], ip_enrichment=ip_enrichment)
            generate_report({}, [], checks, {"Status": "Success", "findings": []}, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn('href="#ip-enrichment"', html)
        self.assertIn('id="ip-enrichment"', html)
        self.assertIn("IP Zenginleştirme", html)
        self.assertIn("192.0.2.10", html)
        self.assertNotIn("IP Enrichment / IP Zenginleştirme", html)
        self.assertLess(_risk_score(html), 40)

    def test_ip_enrichment_detailed_mode_is_reported_separately(self) -> None:
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": {
                "admin_like": [],
                "auth_like": [],
                "api_like": [],
                "upload_like": [],
                "debug_like": [],
                "docs_like": [],
                "source_control_like": [],
            },
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [],
        }
        ip_enrichment = {
            "status": "done",
            "request_status": "detailed_nmap_requested",
            "original_target": "https://example.com",
            "resolved_ip": "192.0.2.10",
            "hostname": "example.com",
            "scan_mode": "detailed_nmap",
            "detailed_nmap_enabled": True,
            "tools_used": ["detailed_nmap"],
            "results": {
                "open_ports": [
                    {"port": "80", "protocol": "tcp", "service": "http", "detail": "Apache httpd", "raw": "80/tcp open http Apache httpd"},
                    {"port": "443", "protocol": "tcp", "service": "https", "detail": "nginx", "raw": "443/tcp open https nginx"},
                ],
                "artifacts": {"nmap_text": "ip_enrichment_nmap.txt"},
                "validation_state": "informational",
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, [], ip_enrichment=ip_enrichment, target="https://example.com")
            generate_report({}, [], checks, {"Status": "Success", "findings": []}, "https://example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")
            run_payload = json.loads((run_dir / "run_result.json").read_text(encoding="utf-8"))

        self.assertIn("IP Zenginleştirme", html)
        self.assertNotIn("IP Enrichment / IP Zenginleştirme", html)
        self.assertIn("detailed_nmap / detailed_nmap=yes", html)
        self.assertIn("80/tcp open http Apache httpd", html)
        self.assertIn("Auxiliary context only; does not increase risk without behavioral proof.", html)
        self.assertEqual("https://example.com", run_payload["meta"]["target"])

    def test_limited_empty_report_uses_turkish_coverage_and_action_labels(self) -> None:
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": {
                "admin_like": [],
                "auth_like": [],
                "api_like": [],
                "upload_like": [],
                "debug_like": [],
                "docs_like": [],
                "source_control_like": [],
            },
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [],
        }
        skipped_tools = [
            "checks",
            "ffuf",
            "gobuster",
            "historical_urls",
            "katana",
            "nuclei",
            "screenshots",
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, [], target="https://example.com")
            generate_report(
                {},
                [],
                checks,
                {"Status": "Success", "findings": []},
                "https://example.com",
                "",
                skipped_tools=skipped_tools,
                output_dir=run_dir,
                open_browser=False,
                quiet=True,
            )
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("Karar güveni: düşük", html)
        self.assertIn("Kapsama: seçilen kapsam", html)
        self.assertIn("Kapalı veya hedefe uygulanmayan araçlar hata değildir", html)
        self.assertNotIn("Decision confidence: Low", html)
        self.assertNotIn("Kapsama: Normal", html)
        self.assertNotIn('href="#ip-enrichment"', html)
        self.assertIn("Doğrulanmış aksiyon oluşmadı", html)
        self.assertIn(
            "Bu sınırlı run’da aksiyon üretilecek doğrulanmış yüzey oluşmadı. "
            "Kapsam izin veriyorsa kapalı keşif araçlarıyla yeniden çalıştır.",
            html,
        )
        self.assertNotIn("İlk önerilen doğrulamayı uygula", html)
        self.assertLess(_risk_score(html), 40)

    def test_interrupted_limited_report_uses_cautious_confidence_display(self) -> None:
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": {
                "admin_like": [],
                "auth_like": [],
                "api_like": [],
                "upload_like": [],
                "debug_like": [],
                "docs_like": [],
                "source_control_like": [],
            },
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [
                {
                    "title": "API / Docs Enumeration Suggestions",
                    "surface": "API Surface",
                    "why": "Review API documentation exposure.",
                    "tests": ["review documented endpoints manually"],
                    "evidence": ["docs surface"],
                    "priority": 60,
                    "resolved_nuclei": {
                        "all_tags": ["exposure", "api"],
                        "suggested_cli": "nuclei -u http://127.0.0.1:8002 -tags exposure,api",
                    },
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(
                run_dir,
                checks,
                [],
                run_state="interrupted",
                stages={"nuclei": {"status": "interrupted", "findings_count": 0}},
                target="http://127.0.0.1:8002",
            )
            generate_report(
                {},
                [],
                checks,
                {"Status": "Interrupted", "findings": []},
                "http://127.0.0.1:8002",
                "",
                output_dir=run_dir,
                open_browser=False,
                quiet=True,
            )
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("sınırlı kapsam nedeniyle temkinli", html)
        self.assertIn("karar güveni kapsam sınırlı olduğu için temkinli", html)
        self.assertIn("tamamlanmış temiz scan değildir", html)
        self.assertIn("Kesilmiş çalışma", html)
        self.assertIn("Önerilen sonraki manuel Nuclei koşusu", html)
        self.assertIn("nuclei -u http://127.0.0.1:8002 -tags exposure,api", html)
        self.assertIn("decision_confidence=sınırlı kapsam nedeniyle temkinli", html)
        self.assertNotIn("decision_confidence=High", html)

    def test_attached_ip_enrichment_report_keeps_primary_target_identity(self) -> None:
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": {
                "admin_like": [],
                "auth_like": [],
                "api_like": [],
                "upload_like": [],
                "debug_like": [],
                "docs_like": [],
                "source_control_like": [],
            },
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [],
        }
        ip_enrichment = {
            "status": "done",
            "original_target": "https://example.com/login",
            "resolved_ip": "192.0.2.10",
            "hostname": "example.com",
            "scan_mode": "lightweight",
            "detailed_nmap_enabled": False,
            "results": {
                "open_ports": [
                    {"port": "80", "protocol": "tcp", "service": "http", "raw": "80/tcp open http Apache httpd"},
                ],
                "open_ports_count": 1,
                "validation_state": "informational",
                "risk_note": "Resolved IP and open ports are auxiliary context and do not raise risk by themselves.",
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, [], ip_enrichment=ip_enrichment, target="https://example.com/login")
            generate_report({}, [], checks, {"Status": "Success", "findings": []}, "https://example.com/login", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")
            run_payload = json.loads((run_dir / "run_result.json").read_text(encoding="utf-8"))

        self.assertEqual("https://example.com/login", run_payload["meta"]["target"])
        self.assertIn("https://example.com/login", html)
        self.assertIn("192.0.2.10", html)
        self.assertIn("80/tcp open http Apache httpd", html)
        self.assertIn("IP Zenginleştirme", html)
        self.assertLess(_risk_score(html), 40)

    def test_ip_enrichment_runner_updates_existing_primary_run(self) -> None:
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": {
                "admin_like": [],
                "auth_like": [],
                "api_like": [],
                "upload_like": [],
                "debug_like": [],
                "docs_like": [],
                "source_control_like": [],
            },
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, [], target="https://example.com/login")
            with (
                patch("reconbot.orchestration.ip_enrichment._reverse_dns_probe", return_value={"type": "ptr", "target": "192.0.2.10", "status": "ok", "ptr": "edge.example.test", "validation_state": "informational"}),
                patch(
                    "reconbot.orchestration.ip_enrichment._http_probe",
                    side_effect=[
                        {"type": "direct_http", "target": "http://192.0.2.10/", "status": "responded", "status_code": 200, "validation_state": "informational"},
                        None,
                        {"type": "host_header_http", "target": "http://192.0.2.10/", "status": "responded", "status_code": 200, "validation_state": "informational"},
                        None,
                    ],
                ),
                patch("reconbot.orchestration.ip_enrichment._tls_probe", return_value={"type": "tls", "target": "example.com:443 via 192.0.2.10:443", "status": "ok", "validation_state": "informational"}),
            ):
                result = run_ip_enrichment(
                    {
                        "run_dir": str(run_dir),
                        "original_target": "https://example.com/login",
                        "resolved_ip": "192.0.2.10",
                        "hostname": "example.com",
                        "scan_mode": "quick",
                    }
                )
            run_payload = json.loads((run_dir / "run_result.json").read_text(encoding="utf-8"))
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertEqual("done", result["status"])
        self.assertEqual("https://example.com/login", run_payload["meta"]["target"])
        self.assertEqual("192.0.2.10", run_payload["ip_enrichment"]["resolved_ip"])
        self.assertEqual("lightweight", run_payload["ip_enrichment"]["scan_mode"])
        self.assertIn("ptr_lookup", run_payload["ip_enrichment"]["tools_used"])
        self.assertEqual(0, run_payload["ip_enrichment"]["results"]["open_ports_count"])
        self.assertEqual(4, run_payload["ip_enrichment"]["results"]["probes_count"])
        self.assertIn("host_header_http", html)
        self.assertLess(_risk_score(html), 40)

    def test_ip_enrichment_reuses_primary_url_nmap_when_already_covered(self) -> None:
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": {
                "admin_like": [],
                "auth_like": [],
                "api_like": [],
                "upload_like": [],
                "debug_like": [],
                "docs_like": [],
                "source_control_like": [],
            },
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [],
        }
        nmap_output = "Nmap scan report for 192.0.2.10\n80/tcp open http Apache httpd\n443/tcp open https nginx\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, [], target="https://example.com/login", nmap_output=nmap_output)
            with patch(
                "reconbot.orchestration.ip_enrichment._run_lightweight_probes",
                return_value=(
                    [{"type": "ptr", "target": "192.0.2.10", "status": "ok", "ptr": "edge.example.test", "validation_state": "informational"}],
                    ["ptr_lookup"],
                ),
            ) as mocked_probes:
                result = run_ip_enrichment(
                    {
                        "run_dir": str(run_dir),
                        "original_target": "https://example.com/login",
                        "resolved_ip": "192.0.2.10",
                        "hostname": "example.com",
                        "scan_mode": "quick",
                    }
                )
            run_payload = json.loads((run_dir / "run_result.json").read_text(encoding="utf-8"))
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        mocked_probes.assert_called_once_with("192.0.2.10", "example.com")
        self.assertEqual("done", result["status"])
        self.assertEqual("already_covered", run_payload["ip_enrichment"]["scan_mode"])
        self.assertTrue(run_payload["ip_enrichment"]["already_covered_by_primary_nmap"])
        self.assertEqual(["primary_nmap_reuse", "ptr_lookup"], run_payload["ip_enrichment"]["tools_used"])
        self.assertEqual(2, run_payload["ip_enrichment"]["results"]["open_ports_count"])
        self.assertEqual(2, run_payload["ip_enrichment"]["results"]["services_count"])
        self.assertEqual(1, run_payload["ip_enrichment"]["results"]["probes_count"])
        self.assertIn("Primary nmap already scanned the resolved IP. ReconBot reused that output as auxiliary IP context.", html)
        self.assertLess(html.index('id="ip-enrichment"'), html.index('id="cve-enrichment"'))
        self.assertEqual("https://example.com/login", run_payload["meta"]["target"])
        self.assertLess(_risk_score(html), 40)

    def test_detailed_ip_enrichment_writes_attached_nmap_artifact(self) -> None:
        checks = {
            "technology_fingerprint": [],
            "classified_endpoints": {
                "admin_like": [],
                "auth_like": [],
                "api_like": [],
                "upload_like": [],
                "debug_like": [],
                "docs_like": [],
                "source_control_like": [],
            },
            "attack_chains": [],
            "attack_graph": {},
            "exploit_suggestions": [],
        }
        nmap_output = "Nmap scan report for 192.0.2.10\n8443/tcp open https nginx\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, [], target="https://example.com/login")
            with patch("reconbot.orchestration.ip_enrichment.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=nmap_output, stderr="")):
                result = run_ip_enrichment(
                    {
                        "run_dir": str(run_dir),
                        "original_target": "https://example.com/login",
                        "resolved_ip": "192.0.2.10",
                        "hostname": "example.com",
                        "scan_mode": "detailed",
                    }
                )
            run_payload = json.loads((run_dir / "run_result.json").read_text(encoding="utf-8"))
            detailed_artifact_exists = (run_dir / "ip_enrichment_detailed_nmap.txt").exists()

        self.assertEqual("done", result["status"])
        self.assertEqual("https://example.com/login", run_payload["meta"]["target"])
        self.assertEqual("detailed_nmap", run_payload["ip_enrichment"]["scan_mode"])
        self.assertEqual(["detailed_nmap"], run_payload["ip_enrichment"]["tools_used"])
        self.assertEqual("ip_enrichment_detailed_nmap.txt", run_payload["ip_enrichment"]["artifacts"]["detailed_nmap_text"])
        self.assertTrue(detailed_artifact_exists)
        self.assertEqual(1, run_payload["ip_enrichment"]["results"]["open_ports_count"])

    def test_quick_ip_scan_config_disables_detailed_nmap(self) -> None:
        config = RunConfig(
            target="192.0.2.10",
            wordlist="",
            nmap_enabled=False,
            detailed_nmap_enabled=False,
            ip_enrichment={
                "status": "quick_ip_scan_requested",
                "original_target": "https://example.com",
                "resolved_ip": "192.0.2.10",
                "scan_mode": "quick",
            },
        )

        self.assertFalse(config.detailed_nmap_enabled)
        self.assertEqual("quick_ip_scan_requested", config.ip_enrichment["status"])


if __name__ == "__main__":
    unittest.main()
