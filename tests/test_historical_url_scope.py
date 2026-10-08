from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from reconbot.core import historical_urls
from reconbot.core.engine import RunConfig, run


class HistoricalUrlScopeTests(unittest.TestCase):
    def test_large_candidates_use_only_resolved_hosts(self) -> None:
        candidates = [f"host-{idx}.example.com" for idx in range(37_000)]
        selected = historical_urls.select_historical_domains(
            root_domain="example.com",
            received_candidates=candidates,
            resolved_hosts=["app.example.com", "api.example.com"],
            live_urls=[],
            max_domains=25,
        )

        self.assertEqual(selected["received_count"], 37_000)
        self.assertEqual(selected["domains"], ["app.example.com", "api.example.com"])
        self.assertEqual(selected["selected_count"], 2)
        self.assertEqual(selected["selection_reason"], "resolved_hosts")

    def test_no_resolved_hosts_falls_back_to_root_domain(self) -> None:
        selected = historical_urls.select_historical_domains(
            root_domain="example.com",
            received_candidates=["candidate.example.com"],
            resolved_hosts=[],
            live_urls=[],
            max_domains=25,
            allow_root_fallback=True,
        )

        self.assertEqual(selected["domains"], ["example.com"])
        self.assertEqual(selected["selection_reason"], "root_domain_fallback")

    def test_max_domain_cap_is_respected_before_tools(self) -> None:
        invoked_domains: list[str] = []

        def fake_archive_tool(tool_name: str, domain: str, *, timeout_sec: int) -> tuple[list[str], str | None]:
            invoked_domains.append(domain)
            return [f"https://{domain}/login"], None

        with patch.object(historical_urls, "_run_archive_tool", side_effect=fake_archive_tool):
            result = historical_urls.collect_historical_urls(
                [f"host-{idx}.example.com" for idx in range(10)],
                max_domains=3,
                max_urls=100,
                tools=("gau",),
            )

        self.assertEqual(invoked_domains, ["host-0.example.com", "host-1.example.com", "host-2.example.com"])
        self.assertEqual(result["domains"], invoked_domains)
        self.assertEqual(result["max_domains"], 3)

    def test_out_of_scope_and_malformed_domains_are_dropped(self) -> None:
        selected = historical_urls.select_historical_domains(
            root_domain="example.com",
            received_candidates=[
                "app.example.com",
                "evil.com",
                "badexample.com",
                "https://app.example.com/path",
                "bad host.example.com",
            ],
            resolved_hosts=[
                "app.example.com",
                "evil.com",
                "badexample.com",
                "https://api.example.com",
                "api.example.com",
            ],
            live_urls=[],
            max_domains=25,
        )

        self.assertEqual(selected["domains"], ["app.example.com", "api.example.com"])
        self.assertEqual(selected["dropped_out_of_scope"], 4)

    def test_historical_disabled_does_not_invoke_collection(self) -> None:
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
                verbose=False,
            )
            with (
                patch("reconbot.core.engine.collect_historical_urls") as mocked_collect,
                patch("reconbot.core.engine.run_wafw00f") as mocked_wafw00f,
                patch("reconbot.core.engine.run_whatweb") as mocked_whatweb,
            ):
                run(config)

        mocked_collect.assert_not_called()
        mocked_wafw00f.assert_not_called()
        mocked_whatweb.assert_not_called()


if __name__ == "__main__":
    unittest.main()
