from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from reconbot.core.engine import RunConfig
from reconbot.core.screenshots import (
    _find_screenshot_file,
    _gowitness_filename_stem,
    capture_screenshots,
    repair_screenshot_metadata,
    select_screenshot_urls,
)
from reconbot.report.builder import generate_report
from reconbot.report.correlation import build_correlation_insights


class ScreenshotSelectionTests(unittest.TestCase):
    def test_screenshots_disabled_by_default(self) -> None:
        config = RunConfig(target="example.com", wordlist="unused.txt")

        self.assertFalse(config.screenshots_enable)

    def test_default_scan_does_not_invoke_gowitness_or_create_artifacts(self) -> None:
        from reconbot.core.engine import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config = RunConfig(
                target="https://app.example.com",
                wordlist="unused.txt",
                output_dir=tmpdir,
                nmap_enabled=False,
                katana_enabled=False,
                gobuster_enabled=False,
                ffuf_enabled=False,
                historical_urls_enabled=False,
                wafw00f_enabled=False,
                whatweb_enabled=False,
                checks_enabled=False,
                nuclei_enabled=False,
                screenshots_enable=False,
                verbose=False,
            )
            with patch("reconbot.core.engine.capture_screenshots") as mocked_capture:
                run(config)

            mocked_capture.assert_not_called()
            self.assertFalse((Path(tmpdir) / "screenshots").exists())
            self.assertFalse((Path(tmpdir) / "screenshots.json").exists())

    def test_gowitness_missing_warns_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("reconbot.core.screenshots.shutil.which", return_value=None):
                result = capture_screenshots(
                    target="example.com",
                    run_dir=Path(tmpdir),
                    httpx_live_urls=["https://app.example.com"],
                    checks_results={},
                    historical_results={},
                    limit=20,
                    timeout_sec=5,
                )

        self.assertEqual(result["status"], "missing_tool")
        self.assertIn("gowitness not installed", result["warnings"][0])
        self.assertEqual(result["selected_count"], 1)

    def test_enabled_three_live_urls_selects_three(self) -> None:
        selected = select_screenshot_urls(
            target="example.com",
            httpx_live_urls=[
                "https://a.example.com",
                "https://b.example.com",
                "https://c.example.com",
            ],
            limit=20,
        )

        self.assertEqual(selected["received"], 3)
        self.assertEqual(selected["selected_count"], 3)

    def test_limit_caps_large_live_url_set(self) -> None:
        selected = select_screenshot_urls(
            target="example.com",
            httpx_live_urls=[f"https://host-{idx}.example.com" for idx in range(100)],
            limit=20,
        )

        self.assertEqual(selected["received"], 100)
        self.assertEqual(selected["selected_count"], 20)
        self.assertEqual(selected["max"], 20)

    def test_out_of_scope_url_is_dropped(self) -> None:
        selected = select_screenshot_urls(
            target="example.com",
            httpx_live_urls=["https://app.example.com", "https://evil.test"],
            limit=20,
        )

        self.assertEqual([item["url"] for item in selected["selected"]], ["https://app.example.com/"])
        self.assertEqual(selected["dropped_out_of_scope"], 1)

    def test_duplicate_urls_are_deduplicated(self) -> None:
        selected = select_screenshot_urls(
            target="example.com",
            httpx_live_urls=["https://app.example.com", "https://app.example.com/"],
            limit=20,
        )

        self.assertEqual(selected["selected_count"], 1)
        self.assertEqual(selected["dropped_duplicate"], 1)

    def test_http_and_https_same_host_are_preserved(self) -> None:
        selected = select_screenshot_urls(
            target="example.com",
            httpx_live_urls=["http://app.example.com", "https://app.example.com"],
            limit=20,
        )

        self.assertEqual(
            [item["url"] for item in selected["selected"]],
            ["http://app.example.com/", "https://app.example.com/"],
        )

    def test_same_host_different_ports_are_preserved(self) -> None:
        selected = select_screenshot_urls(
            target="example.com",
            httpx_live_urls=["https://app.example.com:8443", "https://app.example.com:9443"],
            limit=20,
        )

        self.assertEqual(
            [item["url"] for item in selected["selected"]],
            ["https://app.example.com:8443/", "https://app.example.com:9443/"],
        )

    def test_raw_historical_urls_without_live_marker_are_not_selected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = capture_screenshots(
                target="example.com",
                run_dir=Path(tmpdir),
                httpx_live_urls=[],
                checks_results={},
                historical_results={
                    "enabled": True,
                    "records": [
                        {
                            "url": "https://app.example.com/admin",
                            "sources": ["waybackurls"],
                            "live": False,
                        }
                    ],
                    "normalized_urls": ["https://app.example.com/admin"],
                },
                limit=20,
                timeout_sec=5,
            )

        self.assertEqual(result["status"], "empty")
        self.assertEqual(result["selected_count"], 0)

    def test_gowitness_filename_stem_matches_observed_files(self) -> None:
        cases = {
            "http://localhost:8082/.git/": "http---localhost-8082-.git-",
            "http://localhost:8082/.git/config": "http---localhost-8082-.git-config",
            "http://localhost:8082/.git/HEAD": "http---localhost-8082-.git-HEAD",
            "http://localhost:8082/documentation/": "http---localhost-8082-documentation-",
        }

        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(_gowitness_filename_stem(url), expected)

    def test_gowitness_deterministic_mapper_finds_observed_jpeg_files(self) -> None:
        cases = {
            "http://localhost:8082/.git/": "http---localhost-8082-.git-.jpeg",
            "http://localhost:8082/.git/config": "http---localhost-8082-.git-config.jpeg",
            "http://localhost:8082/.git/HEAD": "http---localhost-8082-.git-HEAD.jpeg",
            "http://localhost:8082/documentation/": "http---localhost-8082-documentation-.jpeg",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            files_dir = run_dir / "screenshots" / "files"
            files_dir.mkdir(parents=True)
            for filename in cases.values():
                (files_dir / filename).write_bytes(b"fake image")

            for url, filename in cases.items():
                with self.subTest(url=url):
                    self.assertEqual(
                        _find_screenshot_file(
                            url=url,
                            output_dir=files_dir,
                            json_item=None,
                            run_dir=run_dir,
                        ),
                        f"screenshots/files/{filename}",
                    )

    def test_gowitness_mapper_supports_png_and_uses_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            files_dir = run_dir / "screenshots" / "files"
            files_dir.mkdir(parents=True)
            (files_dir / "http---localhost-8082-documentation-.png").write_bytes(b"fake image")

            self.assertEqual(
                _find_screenshot_file(
                    url="http://localhost:8082/documentation/",
                    output_dir=files_dir,
                    json_item=None,
                    run_dir=run_dir,
                ),
                "screenshots/files/http---localhost-8082-documentation-.png",
            )

    def test_repair_metadata_only_leaves_truly_missing_entries_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            files_dir = run_dir / "screenshots" / "files"
            files_dir.mkdir(parents=True)
            (files_dir / "http---localhost-8082-.git-.jpeg").write_bytes(b"fake image")
            payload = {
                "status": "done",
                "entries": [
                    {
                        "url": "http://localhost:8082/.git/",
                        "screenshot_path": "",
                        "status": "missing_file",
                        "capture_error": "old error",
                    },
                    {
                        "url": "http://localhost:8082/not-found/",
                        "screenshot_path": "",
                        "status": "missing_file",
                        "capture_error": "old error",
                    },
                ],
            }
            (run_dir / "screenshots.json").write_text(json.dumps(payload), encoding="utf-8")

            repaired, repaired_count = repair_screenshot_metadata(run_dir)

            self.assertEqual(repaired_count, 1)
            self.assertEqual(
                repaired["entries"][0]["screenshot_path"],
                "screenshots/files/http---localhost-8082-.git-.jpeg",
            )
            self.assertEqual(repaired["entries"][0]["status"], "captured")
            self.assertEqual(repaired["entries"][0]["capture_error"], "")
            self.assertEqual(repaired["entries"][1]["status"], "missing_file")
            self.assertEqual(repaired["entries"][1]["screenshot_path"], "")
            self.assertEqual(
                repaired["entries"][1]["capture_error"],
                "screenshot file not found for selected URL",
            )

    def test_repair_uses_index_json_mapping_before_filename_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            screenshots_dir = run_dir / "screenshots"
            files_dir = screenshots_dir / "files"
            files_dir.mkdir(parents=True)
            (files_dir / "custom-index-name.jpeg").write_bytes(b"fake image")
            (screenshots_dir / "index.json").write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "url": "http://localhost:8082/.git/",
                                "screenshot_path": "screenshots/files/custom-index-name.jpeg",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "screenshots.json").write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "url": "http://localhost:8082/.git/",
                                "screenshot_path": "",
                                "status": "missing_file",
                                "capture_error": "old error",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            repaired, repaired_count = repair_screenshot_metadata(run_dir)

            self.assertEqual(repaired_count, 1)
            self.assertEqual(
                repaired["entries"][0]["screenshot_path"],
                "screenshots/files/custom-index-name.jpeg",
            )

    def test_old_run_without_screenshots_generates_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            (run_dir / "run_result.json").write_text(
                json.dumps(
                    {
                        "meta": {"target": "https://app.example.com", "mode": "url", "skipped_tools": []},
                        "data": {
                            "nmap_output": "",
                            "katana_urls": [],
                            "gobuster_results": {},
                            "checks_results": {},
                            "nuclei_results": {},
                        },
                        "stages": {},
                    }
                ),
                encoding="utf-8",
            )
            generate_report(
                {},
                [],
                {},
                {},
                "https://app.example.com",
                "",
                output_dir=run_dir,
                open_browser=False,
                quiet=True,
            )

            self.assertTrue((run_dir / "report.html").exists())

    def test_failed_capture_does_not_break_report_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)

            def fake_run(*args: object, **kwargs: object) -> SimpleNamespace:
                return SimpleNamespace(returncode=1, stdout="", stderr="chrome failed")

            with (
                patch("reconbot.core.screenshots.shutil.which", return_value="/usr/local/bin/gowitness"),
                patch("reconbot.core.screenshots.subprocess.run", side_effect=fake_run),
            ):
                screenshots = capture_screenshots(
                    target="example.com",
                    run_dir=run_dir,
                    httpx_live_urls=["https://app.example.com"],
                    checks_results={},
                    historical_results={},
                    limit=20,
                    timeout_sec=5,
                )

            checks_results = {"screenshots": screenshots}
            (run_dir / "run_result.json").write_text(
                json.dumps(
                    {
                        "meta": {"target": "example.com", "mode": "domain", "skipped_tools": []},
                        "data": {
                            "nmap_output": "",
                            "katana_urls": [],
                            "gobuster_results": {},
                            "checks_results": checks_results,
                            "screenshots": screenshots,
                            "nuclei_results": {},
                        },
                        "stages": {"screenshots": {"status": "error", "artifacts": {}}},
                    }
                ),
                encoding="utf-8",
            )

            generate_report(
                {},
                [],
                checks_results,
                {},
                "example.com",
                "",
                output_dir=run_dir,
                open_browser=False,
                quiet=True,
            )

            report_html = (run_dir / "report.html").read_text(encoding="utf-8")
            self.assertIn("Görsel Yüzey Kanıtı", report_html)
            self.assertIn("chrome failed", report_html)

    def test_successful_gowitness_with_no_files_is_failed_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)

            def fake_run(*args: object, **kwargs: object) -> SimpleNamespace:
                return SimpleNamespace(returncode=0, stdout="completed", stderr="")

            with (
                patch("reconbot.core.screenshots.shutil.which", return_value="/usr/local/bin/gowitness"),
                patch("reconbot.core.screenshots.subprocess.run", side_effect=fake_run),
            ):
                screenshots = capture_screenshots(
                    target="example.com",
                    run_dir=run_dir,
                    httpx_live_urls=["https://app.example.com"],
                    checks_results={},
                    historical_results={},
                    limit=20,
                    timeout_sec=5,
                )

            self.assertEqual(screenshots["status"], "failed")
            self.assertEqual(screenshots["exit_code"], 0)
            self.assertEqual(screenshots["produced_file_count"], 0)
            self.assertEqual(screenshots["captured_count"], 0)
            self.assertEqual(screenshots["missing_url_count"], 1)
            self.assertIn("Screenshot capture ran but produced no image files.", screenshots["warnings"])
            self.assertEqual(screenshots["entries"][0]["status"], "missing_file")

            checks_results = {"screenshots": screenshots}
            (run_dir / "run_result.json").write_text(
                json.dumps(
                    {
                        "meta": {"target": "example.com", "mode": "domain", "skipped_tools": []},
                        "data": {
                            "nmap_output": "",
                            "katana_urls": [],
                            "gobuster_results": {},
                            "checks_results": checks_results,
                            "screenshots": screenshots,
                            "nuclei_results": {},
                        },
                        "stages": {"screenshots": {"status": "error", "artifacts": {}}},
                    }
                ),
                encoding="utf-8",
            )
            generate_report(
                {},
                [],
                checks_results,
                {},
                "example.com",
                "",
                output_dir=run_dir,
                open_browser=False,
                quiet=True,
            )
            report_html = (run_dir / "report.html").read_text(encoding="utf-8")
            self.assertIn("Screenshot capture ran but produced no image files.", report_html)
            self.assertIn("produced_file_count", report_html)
            self.assertIn("gowitness_exit_code", report_html)

    def test_gowitness_mapper_discovers_nested_output_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            nested_dir = run_dir / "screenshots" / "files" / "nested"
            nested_dir.mkdir(parents=True)
            (nested_dir / "https---app.example.com-.jpeg").write_bytes(b"fake image")

            self.assertEqual(
                _find_screenshot_file(
                    url="https://app.example.com/",
                    output_dir=run_dir / "screenshots" / "files",
                    json_item=None,
                    run_dir=run_dir,
                ),
                "screenshots/files/nested/https---app.example.com-.jpeg",
            )

    def test_historical_enabled_screenshots_disabled_does_not_capture(self) -> None:
        from reconbot.core.engine import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config = RunConfig(
                target="https://app.example.com",
                wordlist="unused.txt",
                output_dir=tmpdir,
                nmap_enabled=False,
                katana_enabled=False,
                gobuster_enabled=False,
                ffuf_enabled=False,
                historical_urls_enabled=True,
                historical_urls_live_check_limit=10,
                wafw00f_enabled=False,
                whatweb_enabled=False,
                checks_enabled=False,
                nuclei_enabled=False,
                screenshots_enable=False,
                verbose=False,
            )
            historical_payload = {
                "enabled": True,
                "domains": ["app.example.com"],
                "records": [
                    {
                        "url": "https://app.example.com/admin",
                        "sources": ["waybackurls"],
                        "categories": ["auth_surface"],
                    }
                ],
                "normalized_urls": ["https://app.example.com/admin"],
                "warnings": [],
            }
            with (
                patch("reconbot.core.engine.collect_historical_urls", return_value=historical_payload),
                patch("reconbot.core.engine.run_httpx", return_value=["https://app.example.com/admin"]),
                patch("reconbot.core.engine.capture_screenshots") as mocked_capture,
            ):
                run(config)

            mocked_capture.assert_not_called()
            self.assertFalse((Path(tmpdir) / "screenshots").exists())

    def test_screenshot_evidence_does_not_raise_login_admin_severity_to_high(self) -> None:
        insights = build_correlation_insights(
            target="example.com",
            checks_results={
                "classified_endpoints": {
                    "admin_like": ["https://app.example.com/admin"],
                    "auth_like": ["https://app.example.com/login"],
                },
                "screenshots": {
                    "entries": [
                        {
                            "url": "https://app.example.com/admin",
                            "screenshot_path": "screenshots/files/app-example-com.png",
                            "status": "captured",
                            "source": "httpx",
                        }
                    ]
                },
            },
            run_context={},
        )

        auth_insights = [
            item.to_dict()
            for item in insights
            if item.finding_type == "login_admin_surface"
        ]
        self.assertTrue(auth_insights)
        self.assertNotIn(auth_insights[0]["severity"], {"high", "critical"})
        self.assertIn("screenshot/gowitness", auth_insights[0]["evidence_sources"])


if __name__ == "__main__":
    unittest.main()
