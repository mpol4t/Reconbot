from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from reconbot.core.engine import RunConfig
from reconbot.orchestration.cli_parser import build_parser
from reconbot.runtime.config import _apply_config_defaults, _load_yaml_config
from reconbot.report.builder import generate_report
from reconbot.report.depth import resolve_report_depth
from reconbot.report.sections.correlation import render_correlation_insights_section


def _write_run_result(
    run_dir: Path,
    checks_results: dict,
    nuclei_results: dict | None = None,
    *,
    run_state: str = "completed",
) -> None:
    (run_dir / "run_result.json").write_text(
        json.dumps(
            {
                "meta": {"target": "example.com", "mode": "domain", "skipped_tools": []},
                "run_state": run_state,
                "data": {
                    "nmap_output": "",
                    "katana_urls": ["http://example.com/"],
                    "gobuster_results": {},
                    "checks_results": checks_results,
                    "nuclei_results": nuclei_results or {},
                },
                "stages": {},
            }
        ),
        encoding="utf-8",
    )


def _sample_checks() -> dict:
    return {
        "technology_fingerprint": [{"site": "http://example.com/", "tech": ["nginx"]}],
        "classified_endpoints": {
            "admin_like": [f"http://example.com/admin-{idx}" for idx in range(5)],
            "auth_like": ["http://example.com/login"],
        },
        "exploit_suggestions": [
            {
                "title": f"Suggestion {idx}",
                "surface": "Admin",
                "why": "Operator validation lead.",
                "tests": [f"Validate {idx}"],
                "evidence": [f"http://example.com/admin-{idx}"],
                "priority": 90 - idx,
            }
            for idx in range(6)
        ],
        "screenshots": {
            "status": "done",
            "received": 6,
            "selected_count": 6,
            "max": 20,
            "entries": [
                {
                    "url": f"http://example.com/page-{idx}",
                    "screenshot_path": f"screenshots/files/page-{idx}.jpeg",
                    "status": "captured",
                    "source": "httpx",
                    "capture_error": "",
                }
                for idx in range(6)
            ],
        },
    }


def _sample_nuclei() -> dict:
    return {
        "Status": "Success",
        "findings": [
            {
                "template-id": f"test-template-{idx}",
                "matched-at": f"http://example.com/admin-{idx}",
                "info": {"name": f"Finding {idx}", "severity": "high"},
            }
            for idx in range(8)
        ],
    }


class ReportDepthTests(unittest.TestCase):
    def test_default_report_depth_is_balanced(self) -> None:
        self.assertEqual(resolve_report_depth(None).name, "balanced")
        self.assertEqual(RunConfig(target="example.com", wordlist="unused.txt").report_depth, "balanced")

    def test_cli_report_depth_overrides_yaml_config(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "example.com",
                "--report-depth",
                "summary",
            ]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.yaml"
            cfg_path.write_text("reconbot:\n  report:\n    depth: deep\n", encoding="utf-8")
            args = _apply_config_defaults(args, _load_yaml_config(str(cfg_path)))

        self.assertEqual(args.report_depth, "summary")

    def test_yaml_report_depth_overrides_hardcoded_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.yaml"
            cfg_path.write_text("reconbot:\n  report:\n    depth: deep\n", encoding="utf-8")
            args = _apply_config_defaults(args, _load_yaml_config(str(cfg_path)))

        self.assertEqual(args.report_depth, "deep")

    def test_invalid_report_depth_fails_cleanly(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["example.com", "--report-depth", "verbose"])
        with self.assertRaises(ValueError):
            resolve_report_depth("verbose")

    def test_summary_mode_caps_suggestions_correlation_and_screenshots(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            checks = _sample_checks()
            nuclei = _sample_nuclei()
            _write_run_result(run_dir, checks, nuclei)

            generate_report({}, ["http://example.com/"], checks, nuclei, "example.com", "", output_dir=run_dir, report_depth="summary", open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn('reconbot-report-depth" content="summary"', html)
        self.assertIn('body class="report-depth-summary"', html)
        self.assertIn("data-report-depth-current", html)
        self.assertIn('data-report-depth-button="summary"', html)
        self.assertIn('data-report-depth-button="balanced"', html)
        self.assertIn('data-report-depth-button="deep"', html)
        self.assertIn("Rapor modu:", html)
        self.assertIn("karar odaklı görünüm", html)
        self.assertIn('data-depth-nav="summary balanced deep">İlk 15 Dakika Planı</a>', html)
        self.assertIn('data-depth-nav="summary balanced deep">Rapor Güvenilirliği</a>', html)
        self.assertIn('id="operator-plan"', html)
        self.assertIn('id="run-quality"', html)
        self.assertIn("İlk 15 Dakika Operatör Planı", html)
        self.assertIn("Rapor Güvenilirliği ve Araç Kapsamı", html)
        self.assertIn("Öne çıkan araç uyarıları", html)
        self.assertIn("Araç Kapsam Matrisi", html)
        self.assertIn("Ne yapmalıyım?", html)
        self.assertIn("operator-plan-card", html)
        self.assertIn('data-depth-nav="balanced deep" hidden tabindex="-1" aria-hidden="true">Keşif</a>', html)
        self.assertIn('data-depth-nav="deep" hidden tabindex="-1" aria-hidden="true">Ham Kanıt / Araç Çıktıları</a>', html)
        self.assertIn("Suggestion 0", html)
        self.assertIn("Suggestion 2", html)
        self.assertIn("Suggestion 3", html)
        self.assertIn('class="report-depth-summary-extra"', html)
        self.assertIn("Korelasyon İçgörüleri", html)
        self.assertIn("page-3.jpeg", html)
        self.assertIn("page-4.jpeg", html)
        self.assertIn("body.report-depth-summary .report-depth-raw-detail", html)
        self.assertIn("body.report-depth-summary .report-depth-body-balanced-deep", html)
        self.assertIn("body.report-depth-summary .report-depth-body-deep-only", html)
        self.assertIn("body.report-depth-summary .report-depth-operator-detail", html)
        self.assertIn("body.report-depth-summary .report-depth-audit-section", html)
        self.assertIn("body.report-depth-summary .report-depth-graph-section", html)
        self.assertIn("body.report-depth-summary .report-depth-evidence-detail", html)
        self.assertIn("body.report-depth-summary .report-depth-explainer", html)
        self.assertIn('class="section compact report-depth-operator-detail report-depth-body-balanced-deep" data-depth-body="balanced deep" id="discovery"', html)
        self.assertIn('class="section report-depth-operator-detail report-depth-body-balanced-deep" data-depth-body="balanced deep" id="screenshots"', html)
        self.assertIn('class="section report-depth-operator-detail report-depth-body-balanced-deep" data-depth-body="balanced deep">\n        <h2 id="graph-relationships"', html)
        self.assertIn('id="correlation-insights"', html)
        self.assertNotIn("Ham Grafik Verisi", html)
        self.assertIn("CVE Zenginleştirme", html)

    def test_summary_mode_caps_correlation_insights(self) -> None:
        insights = [
            {
                "title": f"Insight {idx}",
                "affected_asset": f"http://example.com/{idx}",
                "severity": "medium",
                "confidence": 50,
                "evidence_sources": ["test"],
                "related_findings": [],
                "manual_validation_steps": ["review"],
                "tags": [],
            }
            for idx in range(5)
        ]

        html = render_correlation_insights_section(
            {
                "correlation_insights": insights,
                "checks_results": {},
                "run_context": {},
                "report_base_url": "http://example.com",
                "report_depth_config": SimpleNamespace(name="summary", max_correlation_preview=3),
                "_html_escape": lambda value: str(value or ""),
                "_render_detail_value": lambda value, _base: str(value or ""),
                "_render_score_pill": lambda value: f"{value}/100",
            }
        )

        self.assertIn("Insight 0", html)
        self.assertIn("Insight 2", html)
        self.assertIn("Insight 3", html)
        self.assertIn("report-depth-summary-extra", html)
        self.assertIn("5 içgörüden ilk 3", html)

    def test_report_depth_switcher_js_switches_body_class_and_uses_scoped_storage(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            checks = _sample_checks()
            nuclei = _sample_nuclei()
            _write_run_result(run_dir, checks, nuclei)

            generate_report({}, ["http://example.com/"], checks, nuclei, "example.com", "", output_dir=run_dir, report_depth="balanced", open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("window.__reconbotSetReportDepth = setReportDepth", html)
        self.assertIn('document.body.classList.remove("report-depth-" + item)', html)
        self.assertIn('document.body.classList.add("report-depth-" + normalized)', html)
        self.assertIn("function syncSidebarNavForDepth(depth, options)", html)
        self.assertIn('link.hidden = !allowed', html)
        self.assertIn('window.location.hash = "overview"', html)
        self.assertIn('"reconbot.report.depth." + hashString(scope)', html)
        self.assertIn('meta[name="reconbot-report-scope"]', html)
        self.assertIn("localStorage.setItem(reportDepthStorageKey(), normalized)", html)
        self.assertIn("sessionStorage.setItem(reportDepthStorageKey(), normalized)", html)

    def test_graph_runtime_guard_exists_for_depth_switching(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            checks = _sample_checks()
            nuclei = _sample_nuclei()
            _write_run_result(run_dir, checks, nuclei)

            generate_report({}, ["http://example.com/"], checks, nuclei, "example.com", "", output_dir=run_dir, report_depth="balanced", open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("window.__reconbotGraphRuntime", html)
        self.assertIn("cy.resize()", html)
        self.assertIn("cy.fit(visible, 56)", html)

    def test_premium_dashboard_shell_keeps_nav_switcher_graph_and_single_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            checks = _sample_checks()
            nuclei = _sample_nuclei()
            _write_run_result(run_dir, checks, nuclei)

            generate_report({}, ["http://example.com/"], checks, nuclei, "example.com", "", output_dir=run_dir, report_depth="balanced", open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn('class="app-shell"', html)
        self.assertIn('class="report-sidebar"', html)
        self.assertIn('aria-label="Rapor navigasyonu"', html)
        self.assertIn("function initSidebarNavState()", html)
        self.assertIn('link.classList.toggle("is-active"', html)
        expected_order = (
            "#overview",
            "#operator-plan",
            "#run-quality",
            "#traffic-profile",
            "#discovery",
            "#cve-enrichment",
            "#priority-suggestions",
            "#screenshots",
            "#correlation-insights",
            "#attack-graph",
            "#raw",
        )
        for anchor in expected_order:
            self.assertIn(f'href="{anchor}"', html)
            self.assertIn(f'id="{anchor[1:]}"', html)
        nav_positions = [html.index(f'href="{anchor}"') for anchor in expected_order]
        self.assertEqual(nav_positions, sorted(nav_positions))
        body_positions = [html.index(f'id="{anchor[1:]}"') for anchor in expected_order]
        self.assertEqual(body_positions, sorted(body_positions))
        self.assertEqual(html.count('data-report-depth-button="summary"'), 1)
        self.assertEqual(html.count('data-report-depth-button="balanced"'), 1)
        self.assertEqual(html.count('data-report-depth-button="deep"'), 1)
        self.assertIn('id="attack-graph-canvas"', html)
        self.assertIn('id="attack-graph-inspector"', html)
        self.assertIn('src="screenshots/files/page-0.jpeg"', html)
        self.assertNotIn('src="/private/', html)
        self.assertIn("Yönetici Özeti", html)
        self.assertIn("Trafik Profili", html)
        self.assertIn("CVE Zenginleştirme", html)
        self.assertIn("Görsel Kanıt", html)
        self.assertIn("Korelasyon İçgörüleri", html)
        self.assertIn("Saldırı Grafiği", html)
        self.assertIn("Ham Kanıt", html)
        self.assertIn("ReconBot", html)
        self.assertIn("Nuclei", html)
        self.assertIn("Katana", html)
        self.assertIn("Gobuster", html)
        self.assertIn("http://example.com/admin-0", html)
        self.assertIn('data-report-depth-button="summary"', html)
        self.assertIn('data-report-depth-button="balanced"', html)
        self.assertIn('data-report-depth-button="deep"', html)
        self.assertIn("--bg: #11161c", html)
        self.assertIn("scroll-margin-top: 92px", html)
        self.assertEqual(html.count("<html>"), 1)
        self.assertEqual(html.count('meta name="reconbot-report-depth"'), 1)

    def test_balanced_mode_preserves_default_report_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            checks = _sample_checks()
            nuclei = _sample_nuclei()
            _write_run_result(run_dir, checks, nuclei)

            generate_report({}, ["http://example.com/"], checks, nuclei, "example.com", "", output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn('reconbot-report-depth" content="balanced"', html)
        self.assertIn('body class="report-depth-balanced"', html)
        self.assertIn("data-report-depth-current", html)
        self.assertIn("Rapor modu:", html)
        self.assertIn("operatör inceleme görünümü", html)
        self.assertIn("İlk 15 Dakika Operatör Planı", html)
        self.assertIn("Rapor Güvenilirliği ve Araç Kapsamı", html)
        self.assertIn("<th>Araç</th><th>Durum</th><th>Üretilen Kanıt / Çıktı</th><th>Karara Etkisi</th>", html)
        self.assertIn("<strong>Nuclei</strong>", html)
        self.assertIn("<strong>Katana</strong>", html)
        self.assertIn("body.report-depth-balanced .report-depth-balanced-extra", html)
        self.assertIn('class="section compact report-depth-body-all operator-plan-section" data-depth-body="summary balanced deep" id="operator-plan"', html)
        self.assertIn("Suggestion 5", html)
        self.assertNotIn("Grafik path önizlemesi", html)
        self.assertIn("Ham / Detaylı Veri", html)
        self.assertIn("body.report-depth-balanced .report-depth-raw-detail", html)
        self.assertIn("body.report-depth-balanced .report-depth-raw-anchor", html)
        self.assertIn("body.report-depth-balanced .report-depth-body-deep-only", html)
        self.assertIn("body.report-depth-balanced .report-depth-audit-section", html)
        self.assertIn("body.report-depth-balanced .report-depth-deep-only", html)
        self.assertIn("CVE zenginleştirme bir triyaj ipucudur, kanıt değildir", html)
        self.assertIn("Korelasyon içgörüleri, birden fazla araçtan gelen sinyalleri birleştirir", html)
        self.assertIn("Screenshot bağlam sağlar; tek başına zafiyet kanıtı değildir", html)
        self.assertIn("Doğrulama sırasını seçmek için kullan", html)
        self.assertIn('<details class="show-more"><summary>CVE zenginleştirme önizlemesi</summary>', html)
        self.assertIn('<details class="show-more report-depth-balanced-preview"><summary>Fingerprint önizlemesi</summary>', html)
        self.assertIn('<details class="show-more report-depth-balanced-preview"><summary>Node ilişkileri önizlemesi</summary>', html)
        self.assertIn('class="section report-depth-operator-detail report-depth-body-deep-only" data-depth-body="deep"', html)
        self.assertIn('class="section report-depth-body-deep-only" data-depth-body="deep"', html)
        self.assertNotIn('<summary>Grafik path önizlemesi</summary>', html)
        self.assertNotIn("Derin kanıt detayı", html)
        self.assertIn("body.report-depth-balanced .report-depth-audit-only", html)
        self.assertIn('data-depth-nav="deep" hidden tabindex="-1" aria-hidden="true">Ham Kanıt / Araç Çıktıları</a>', html)
        self.assertIn('data-depth-nav="balanced deep">Görsel Kanıt</a>', html)

    def test_deep_mode_expands_full_evidence_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            checks = _sample_checks()
            nuclei = _sample_nuclei()
            _write_run_result(run_dir, checks, nuclei)

            generate_report({}, ["http://example.com/"], checks, nuclei, "example.com", "", output_dir=run_dir, report_depth="deep", open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn('reconbot-report-depth" content="deep"', html)
        self.assertIn('body class="report-depth-deep"', html)
        self.assertIn("data-report-depth-current", html)
        self.assertIn("tam kanıt/audit görünümü", html)
        self.assertIn("İlk 15 Dakika Operatör Planı", html)
        self.assertIn("Rapor Güvenilirliği ve Araç Kapsamı", html)
        self.assertIn('data-depth-body="balanced deep"', html)
        self.assertIn("operator-plan-source-detail report-depth-body-deep-only", html)
        self.assertIn("page-5.jpeg", html)
        self.assertIn("report-depth-deep-only", html)
        self.assertIn("Derin mod audit incelemesi için kaynak adlarını", html)
        self.assertIn("Teknik inceleme için ham template çıktısı", html)
        self.assertIn('<details class="show-more" open><summary>CVE zenginleştirme önizlemesi</summary>', html)
        self.assertIn('<details class="show-more" open><summary>Grafik path önizlemesi</summary>', html)
        self.assertIn('<details class="show-more report-depth-balanced-preview" open><summary>Fingerprint önizlemesi</summary>', html)
        self.assertIn('<details class="show-more report-depth-balanced-preview" open><summary>Node ilişkileri önizlemesi</summary>', html)
        self.assertIn("<details class=\"show-more\" open>", html)
        self.assertIn("Derin kanıt detayı", html)
        self.assertIn("Ham Grafik Verisi", html)
        self.assertIn('data-depth-nav="deep">Ham Kanıt / Araç Çıktıları</a>', html)

    def test_screenshot_display_labels_are_turkish_without_changing_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            checks = _sample_checks()
            checks["screenshots"] = {
                "status": "done",
                "received": 2,
                "selected_count": 2,
                "max": 20,
                "entries": [
                    {
                        "url": "http://example.com/ok",
                        "screenshot_path": "screenshots/files/ok.jpeg",
                        "status": "captured",
                        "source": "httpx",
                        "capture_error": "",
                    },
                    {
                        "url": "http://example.com/missing",
                        "screenshot_path": "",
                        "status": "missing_file",
                        "source": "selected",
                        "capture_error": "screenshot file not found for selected URL",
                    },
                ],
            }
            _write_run_result(run_dir, checks, _sample_nuclei())

            generate_report({}, ["http://example.com/"], checks, _sample_nuclei(), "example.com", "", output_dir=run_dir, report_depth="balanced", open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("alınan", html)
        self.assertIn("seçilen", html)
        self.assertIn("yakalandı", html)
        self.assertIn("dosya eksik", html)
        self.assertIn("seçilen URL için screenshot dosyası bulunamadı", html)
        self.assertIn('src="screenshots/files/ok.jpeg"', html)
        self.assertNotIn(">captured<", html)
        self.assertNotIn(">missing_file<", html)
        self.assertNotIn("screenshot file not found for selected URL", html)

    def test_interrupted_run_uses_careful_display_caveat_without_mutating_data(self) -> None:
        checks = _sample_checks()
        nuclei = {"Status": "Clean", "findings": []}
        before_checks = json.dumps(checks, sort_keys=True)
        before_nuclei = json.dumps(nuclei, sort_keys=True)
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, checks, nuclei, run_state="interrupted")

            generate_report({}, ["http://example.com/"], checks, nuclei, "example.com", "", output_dir=run_dir, report_depth="balanced", open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("Doğrulanmış bulgu yok; çalışma kesildiyse bu temiz scan anlamına gelmez.", html)
        self.assertIn("Çalıştırma kesildiği için kapsama eksik", html)
        self.assertNotIn("No findings, high confidence", html)
        self.assertEqual(json.dumps(checks, sort_keys=True), before_checks)
        self.assertEqual(json.dumps(nuclei, sort_keys=True), before_nuclei)

    def test_screenshots_and_correlation_render_in_all_modes(self) -> None:
        for depth in ("summary", "balanced", "deep"):
            with self.subTest(depth=depth):
                with tempfile.TemporaryDirectory() as tmpdir:
                    run_dir = Path(tmpdir)
                    checks = _sample_checks()
                    nuclei = _sample_nuclei()
                    _write_run_result(run_dir, checks, nuclei)

                    generate_report({}, ["http://example.com/"], checks, nuclei, "example.com", "", output_dir=run_dir, report_depth=depth, open_browser=False, quiet=True)
                    html = (run_dir / "report.html").read_text(encoding="utf-8")

                self.assertIn("Görsel Yüzey Kanıtı", html)
                self.assertIn("Korelasyon İçgörüleri", html)
                self.assertIn(f"reconbot-report-depth\" content=\"{depth}\"", html)

    def test_old_run_without_optional_data_generates_with_depth(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            _write_run_result(run_dir, {}, {})

            generate_report({}, [], {}, {}, "example.com", "", output_dir=run_dir, report_depth="summary", open_browser=False, quiet=True)

            self.assertTrue((run_dir / "report.html").exists())

    def test_report_depth_changes_presentation_only(self) -> None:
        checks = _sample_checks()
        before = json.dumps(checks, sort_keys=True)
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            nuclei = _sample_nuclei()
            _write_run_result(run_dir, checks, nuclei)

            generate_report({}, ["http://example.com/"], checks, nuclei, "example.com", "", output_dir=run_dir, report_depth="summary", open_browser=False, quiet=True)
            generate_report({}, ["http://example.com/"], checks, nuclei, "example.com", "", output_dir=run_dir, report_depth="deep", open_browser=False, quiet=True)

        self.assertEqual(json.dumps(checks, sort_keys=True), before)

    def test_generate_report_parser_accepts_report_depth(self) -> None:
        parser = build_parser()
        for depth in ("summary", "balanced", "deep"):
            with self.subTest(depth=depth):
                args = parser.parse_args(["generate-report", "--run-dir", "/tmp/run", "--report-depth", depth])

                self.assertEqual(args.report_depth, depth)

    def test_normal_scan_config_accepts_report_depth(self) -> None:
        config = RunConfig(target="example.com", wordlist="unused.txt", report_depth="summary")

        self.assertEqual(config.report_depth, "summary")


if __name__ == "__main__":
    unittest.main()
