from __future__ import annotations

import builtins
import json
import importlib
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError

from reconbot.orchestration.osint_core.darkweb.collector import build_darkweb_intelligence
from reconbot.orchestration.osint_core.darkweb.manual_import import collect_manual_metadata_import
from reconbot.orchestration.osint_core.darkweb.provider_registry import (
    CUSTOM_HTTPS_DARKWEB_METADATA_PROVIDER,
    TOR_ONION_CRAWL_UNSUPPORTED,
    provider_profiles as darkweb_provider_profiles,
    validate_custom_https_provider,
)
from reconbot.orchestration.osint_core.leak_sources.collector_contract import (
    DISABLED_PLACEHOLDER_NOTE,
    build_disabled_result,
    build_manual_review_health_row,
)
from reconbot.orchestration.osint_core.leak_sources.aggregator import build_leak_intelligence
from reconbot.orchestration.osint_core.leak_sources.models import LeakSourceReference, LeakSourceResult
from reconbot.orchestration.osint_core.leak_sources.metadata_feed import result_from_metadata_feed
from reconbot.orchestration.osint_core.leak_sources.policy import (
    LEAK_SOURCE_CLASSIFICATIONS,
    sanitize_reference_payload,
)
from reconbot.orchestration.osint_core.leak_sources.provider_registry import (
    CUSTOM_HTTPS_METADATA_FEED,
    FUTURE_TRUSTED_PROVIDER_PROFILE,
    LOCAL_DEMO_FEED,
    provider_profiles,
    validate_metadata_feed_provider,
)
from reconbot.orchestration.osint_core.leak_sources.public_breach_catalog import result_from_known_breach_metadata
from reconbot.orchestration.osint_core.leak_sources.redaction import redact_email, redact_phone, redact_text
from reconbot.orchestration.osint_core.organization import mail_dns
from reconbot.orchestration.osint_core.source_health import source_health_diagnostic_summary
from reconbot.orchestration.osint import (
    _classify_wayback_url,
    _extract_ct_subdomains,
    _mail_infrastructure_intelligence,
    _source_health_summary,
    _target_context,
    build_osint_enrichment,
)
from reconbot.report.builder import generate_report
from reconbot.report.sections.osint import _display_text, render_osint_section
from reconbot.runtime.config import _load_yaml_config
from reconbot.runtime.dependencies import (
    INSTALL_COMMAND,
    REQUIRED_RUNTIME_DEPENDENCIES,
    format_runtime_check,
    runtime_preflight_error,
)


class LeakSourceContractTests(unittest.TestCase):
    def test_leak_source_model_defaults_are_safe(self) -> None:
        reference = LeakSourceReference(title="Public breach reference")
        result = LeakSourceResult(
            source_name="future_catalog",
            source_type="public_breach_catalog",
            status="completed",
            observed_references=[reference],
        )
        serialized = result.to_dict()
        self.assertEqual(serialized["risk_score_impact"], 0)
        self.assertIn("source_name", serialized)
        self.assertIn("source_type", serialized)
        self.assertIn("observed_references", serialized)
        observed = serialized["observed_references"][0]
        for field in (
            "title",
            "reference_url",
            "browser_safe",
            "render_as_clickable",
            "source_provider",
            "observed_at",
            "matched_entities",
            "match_type",
            "confidence",
            "confidence_reason",
            "scope_origin",
            "applies_to_target",
            "applies_to_parent_org",
            "evidence_type",
            "breach_date",
            "affected_accounts",
            "compromised_data_classes",
            "redacted_snippet",
            "raw_secret_collected",
            "credential_material_collected",
            "account_validated",
            "risk_score_impact",
            "recommended_action",
        ):
            self.assertIn(field, observed)
        self.assertFalse(observed["raw_secret_collected"])
        self.assertFalse(observed["credential_material_collected"])
        self.assertFalse(observed["account_validated"])
        self.assertEqual(observed["risk_score_impact"], 0)

    def test_darkweb_top_level_object_defaults_are_metadata_only(self) -> None:
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "include_certificate_transparency": False,
                    "include_historical_urls": False,
                    "include_public_code_references": False,
                    "include_known_breach_catalog": False,
                    "include_search_dork_suggestions": False,
                    "include_infrastructure_intelligence": False,
                    "include_organization_intelligence": False,
                }
            },
        )
        darkweb = payload["darkweb_intelligence"]
        self.assertEqual(darkweb["mode"], "metadata_only")
        self.assertFalse(darkweb["tor_onion_crawling"]["enabled"])
        self.assertFalse(darkweb["tor_onion_crawling"]["supported"])
        self.assertEqual(darkweb["tor_onion_crawling"]["status"], "not_supported")
        summary = darkweb["summary"]
        self.assertFalse(summary["credential_material_collected"])
        self.assertFalse(summary["raw_secret_collected"])
        self.assertFalse(summary["raw_dump_collected"])
        self.assertFalse(summary["raw_leaked_records_collected"])
        self.assertFalse(summary["credential_validation_performed"])

    def test_darkweb_existing_hibp_mapping_is_metadata_only_and_clickable(self) -> None:
        leak = build_leak_intelligence(
            enabled=True,
            known_breach_enabled=True,
            signals=[
                {
                    "category": "known_breach_reference",
                    "title": "7-Eleven breach",
                    "breach_name": "7-Eleven",
                    "source_provider": "haveibeenpwned",
                    "source_url": "https://haveibeenpwned.com/PwnedWebsites#7Eleven",
                    "match_type": "brand_alias",
                    "confidence": "medium",
                    "compromised_data_classes": ["Email addresses"],
                }
            ],
            sources=[{"name": "known_breach_catalog", "status": "completed_matched", "duration_ms": 4}],
            requested_target_host="7-eleven.com",
            requested_registered_domain="7-eleven.com",
        )
        darkweb = build_darkweb_intelligence(
            enabled=True,
            target_context={"target_host": "7-eleven.com", "target_registered_domain": "7-eleven.com"},
            leak_intelligence=leak,
            settings={},
        )
        self.assertEqual(darkweb["summary"]["observed_references"], 1)
        reference = darkweb["observed_references"][0]
        self.assertEqual(reference["source_channel"], "public_breach_catalog")
        self.assertTrue(reference["browser_safe"])
        self.assertTrue(reference["render_as_clickable"])
        self.assertEqual(reference["risk_score_impact"], 0)
        self.assertIn("aktif zafiyet", reference["scope_caveat_tr"])
        html = render_osint_section({"osint": {"enabled": True, "summary": {}, "sources": [], "darkweb_intelligence": darkweb, "leak_intelligence": leak}})
        self.assertIn("Bu aktif bir zafiyet bulgusu değildir", html)
        self.assertIn("haveibeenpwned.com/PwnedWebsites#7Eleven", html)

    def test_manual_darkweb_metadata_import_success_matches_example(self) -> None:
        fixture = Path("docs/examples/darkweb_metadata_references.sample.json")
        result = collect_manual_metadata_import(
            config={"enabled": True, "filePath": str(fixture), "sourceName": "local_darkweb_metadata_demo"},
            requested_target_host="example.com",
            requested_registered_domain="example.com",
            organization_aliases=["Example Corp"],
        )
        self.assertEqual(result["source"]["status"], "completed")
        self.assertEqual(result["source"]["items_matched_count"], 1)
        reference = result["observed_references"][0]
        self.assertEqual(reference["source_channel"], "darkweb_metadata_index")
        self.assertTrue(reference["browser_safe"])
        self.assertTrue(reference["render_as_clickable"])
        self.assertFalse(reference["credential_material_collected"])
        self.assertFalse(reference["raw_dump_collected"])
        self.assertNotIn(".onion", json.dumps(result))

    def test_manual_darkweb_metadata_import_suppresses_sensitive_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            feed_path = Path(tmpdir) / "unsafe_darkweb_metadata.json"
            secret = "alice@example.com:CorrectHorseBatteryStaple token=sk_live_secret sessionid=abcdef123456"
            feed_path.write_text(
                json.dumps(
                    {
                        "source_name": "unsafe_demo",
                        "items": [
                            {
                                "title": "unsafe",
                                "reference_url": "https://example.com/ref",
                                "matched_domains": ["example.com"],
                                "summary": secret,
                                "raw": "email,password\nalice@example.com,CorrectHorseBatteryStaple\nbob@example.com,hunter2",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = collect_manual_metadata_import(
                config={"enabled": True, "filePath": str(feed_path)},
                requested_target_host="example.com",
                requested_registered_domain="example.com",
                organization_aliases=[],
            )
        serialized = json.dumps(result)
        self.assertEqual(result["source"]["items_suppressed_count"], len(result["suppressed_sensitive_items"]))
        self.assertGreater(result["source"]["items_suppressed_count"], 0)
        self.assertEqual(result["observed_references"], [])
        self.assertNotIn("CorrectHorseBatteryStaple", serialized)
        self.assertNotIn("sk_live_secret", serialized)
        self.assertNotIn("hunter2", serialized)

    def test_darkweb_unsupported_tor_and_provider_validation(self) -> None:
        profiles = darkweb_provider_profiles()
        self.assertIn(TOR_ONION_CRAWL_UNSUPPORTED, profiles)
        self.assertEqual(profiles[TOR_ONION_CRAWL_UNSUPPORTED].status, "not_supported")
        self.assertEqual(validate_custom_https_provider({"enabled": True, "providerUrl": "https://metadata.example.com/feed.json"})[0], "not_supported")
        for url in ("http://metadata.example.com/feed.json", "file:///tmp/feed.json", "https://abc123.onion/feed.json"):
            self.assertEqual(validate_custom_https_provider({"enabled": True, "providerUrl": url})[0], "invalid_config")
        with mock.patch.dict("os.environ", {"DARKWEB_METADATA_TOKEN": "fake-token-value"}):
            darkweb = build_darkweb_intelligence(
                enabled=True,
                target_context={"target_host": "example.com", "target_registered_domain": "example.com"},
                leak_intelligence={},
                settings={"customHttpsProvider": {"enabled": True, "providerUrl": "https://metadata.example.com/feed.json", "apiKeyEnv": "DARKWEB_METADATA_TOKEN"}},
            )
        serialized = json.dumps(darkweb)
        provider_source = next(item for item in darkweb["sources"] if item["source_id"] == CUSTOM_HTTPS_DARKWEB_METADATA_PROVIDER)
        tor_source = next(item for item in darkweb["sources"] if item["source_id"] == TOR_ONION_CRAWL_UNSUPPORTED)
        self.assertEqual(tor_source["status"], "not_supported")
        self.assertEqual(provider_source["api_key_env"], "DARKWEB_METADATA_TOKEN")
        self.assertTrue(provider_source["api_key_configured"])
        self.assertFalse(provider_source["api_key_value_serialized"])
        self.assertNotIn("fake-token-value", serialized)

    def test_darkweb_report_wording_and_no_secret_visibility(self) -> None:
        darkweb = build_darkweb_intelligence(
            enabled=True,
            target_context={"target_host": "example.com", "target_registered_domain": "example.com"},
            leak_intelligence={},
            settings={},
        )
        html = render_osint_section({"osint": {"enabled": True, "summary": {}, "sources": [], "darkweb_intelligence": darkweb, "leak_intelligence": {}}})
        self.assertIn("Darkweb / Sızıntı / İhlal İstihbaratı", html)
        self.assertIn("Tor/onion crawling yapılmadı", html)
        self.assertIn("Kimlik bilgisi veya dump toplanmadı", html)
        self.assertIn("Bu aktif bir zafiyet bulgusu değildir", html)

    def test_leak_source_redaction_helpers_remove_sensitive_material(self) -> None:
        self.assertEqual(redact_email("user@example.com"), "u***@example.com")
        self.assertEqual(redact_email("user@example.com", public_contact_context=True), "user@example.com")
        self.assertEqual(redact_phone("+90 532 123 4567"), "+90 5** *** **67")
        self.assertEqual(redact_text("api_key=abcd1234SECRET"), "api_key=[redacted]")
        self.assertEqual(redact_text("password=swordfish"), "password=[redacted_password]")
        self.assertEqual(redact_text("password_hash=0123456789abcdef0123456789abcdef"), "password_hash=[redacted_hash]")
        self.assertEqual(redact_text("deadbeefdeadbeefdeadbeefdeadbeef"), "[redacted_hash]")
        self.assertEqual(redact_text("sessionid=abcdef1234567890"), "sessionid=[redacted_session]")
        private_key = "-----BEGIN PRIVATE KEY-----\nabcdef123456\n-----END PRIVATE KEY-----"
        self.assertEqual(redact_text(private_key), "[redacted_private_key]")

    def test_leak_source_safety_policy_suppresses_forbidden_raw_material(self) -> None:
        safe, suppressed = sanitize_reference_payload(
            {
                "title": "Example leak metadata",
                "redacted_snippet": "email user@example.com api_key=abcd1234SECRET",
                "raw_dump": "password=swordfish",
                "password_hash": "0123456789abcdef0123456789abcdef",
            },
            source_provider="future_provider",
        )
        serialized = json.dumps({"safe": safe, "suppressed": [item.to_dict() for item in suppressed]})
        self.assertGreaterEqual(len(suppressed), 3)
        self.assertFalse(safe["raw_secret_collected"])
        self.assertFalse(safe["credential_material_collected"])
        self.assertFalse(safe["account_validated"])
        self.assertEqual(safe["risk_score_impact"], 0)
        self.assertIn("api_key=[redacted]", safe["redacted_snippet"])
        self.assertIn("u***@example.com", safe["redacted_snippet"])
        self.assertNotIn("abcd1234SECRET", serialized)
        self.assertNotIn("swordfish", serialized)
        self.assertNotIn("0123456789abcdef0123456789abcdef", serialized)

    def test_leak_source_scope_defaults_and_exact_domain_override(self) -> None:
        external = LeakSourceReference(
            title="Public third-party breach reference",
            reference_url="https://example.test/report",
            browser_safe=True,
            source_provider="example_provider",
            requested_target_host="app.example.com",
            requested_registered_domain="example.com",
        ).to_dict()
        self.assertEqual(external["scope_origin"], "external_verified_source")
        self.assertEqual(external["applies_to_target"], "unknown")
        self.assertEqual(external["risk_score_impact"], 0)
        self.assertEqual(external["recommended_action"], "manual relevance review")

        exact = LeakSourceReference(
            title="Exact-domain metadata reference",
            scope_origin="exact_target_host",
            applies_to_target=True,
            observed_on_host="app.example.com",
            observed_on_registered_domain="example.com",
            requested_target_host="app.example.com",
            requested_registered_domain="example.com",
            confidence_reason="Exact domain evidence was present in metadata.",
        ).to_dict()
        self.assertEqual(exact["scope_origin"], "exact_target_host")
        self.assertIs(exact["applies_to_target"], True)
        self.assertEqual(exact["observed_on_host"], "app.example.com")

    def test_leak_source_classifications_and_disabled_helpers_are_non_live(self) -> None:
        self.assertEqual(LEAK_SOURCE_CLASSIFICATIONS["public_breach_catalog"].source_type, "public_breach_catalog")
        self.assertFalse(LEAK_SOURCE_CLASSIFICATIONS["darkweb_index"].enabled_by_default)
        self.assertFalse(LEAK_SOURCE_CLASSIFICATIONS["darkweb_index"].raw_content_allowed)
        result = build_disabled_result(source_name="darkweb_index_placeholder", source_type="darkweb_index")
        self.assertEqual(result.status, "disabled")
        self.assertEqual(result.risk_score_impact, 0)
        self.assertEqual(result.observed_references, [])
        self.assertIn(DISABLED_PLACEHOLDER_NOTE, result.operator_notes)
        self.assertFalse(result.source_health_row["render_as_clickable"])
        manual = build_manual_review_health_row(source_name="manual_leak_review")
        self.assertEqual(manual["status"], "suggestion_only")
        self.assertEqual(manual["source_status"], "suggestions_generated")
        self.assertFalse(manual["render_as_clickable"])
        self.assertEqual(manual["risk_score_impact"], 0)

    def test_metadata_feed_provider_registry_profiles_are_safe(self) -> None:
        profiles = provider_profiles()
        self.assertIn(LOCAL_DEMO_FEED, profiles)
        self.assertIn(CUSTOM_HTTPS_METADATA_FEED, profiles)
        self.assertIn(FUTURE_TRUSTED_PROVIDER_PROFILE, profiles)
        serialized = json.dumps({key: profile.__dict__ for key, profile in profiles.items()})
        self.assertNotIn("haveibeenpwned.com", serialized)
        self.assertNotIn("dehashed", serialized.lower())
        self.assertNotIn("intelx", serialized.lower())
        for profile in profiles.values():
            self.assertTrue(profile.metadata_only)
            self.assertTrue(profile.forbids_credentials)
            self.assertTrue(profile.forbids_dumps)
            self.assertTrue(profile.forbids_raw_content)
            self.assertEqual(profile.risk_score_impact, 0)

    def test_metadata_feed_provider_validation_rules(self) -> None:
        cases = [
            ({"enabled": True, "providerId": "unknown_provider", "feedUrl": "https://example.test/feed.json"}, "invalid_config"),
            ({"enabled": True, "providerId": LOCAL_DEMO_FEED, "sourceType": "local_file", "feedPath": "feed.json"}, "valid"),
            ({"enabled": True, "providerId": LOCAL_DEMO_FEED, "sourceType": "https_json", "feedUrl": "https://example.test/feed.json"}, "invalid_config"),
            ({"enabled": True, "providerId": CUSTOM_HTTPS_METADATA_FEED, "sourceType": "https_json", "feedUrl": "https://example.test/feed.json"}, "valid"),
            ({"enabled": True, "providerId": CUSTOM_HTTPS_METADATA_FEED, "sourceType": "https_json", "feedUrl": "http://example.test/feed.json"}, "invalid_config"),
            ({"enabled": True, "providerId": CUSTOM_HTTPS_METADATA_FEED, "sourceType": "https_json", "feedUrl": "file:///tmp/feed.json"}, "invalid_config"),
            ({"enabled": True, "providerId": FUTURE_TRUSTED_PROVIDER_PROFILE}, "not_implemented"),
        ]
        for config, expected_status in cases:
            with self.subTest(config=config):
                self.assertEqual(validate_metadata_feed_provider(config).status, expected_status)

    def test_public_breach_catalog_adapter_converts_known_breach_signal(self) -> None:
        result = result_from_known_breach_metadata(
            signals=[
                {
                    "category": "known_breach_reference",
                    "title": "Public breach catalog reference",
                    "source_name": "known_breach_catalog",
                    "source_provider": "haveibeenpwned",
                    "source_url": "https://haveibeenpwned.com/Breach/7-Eleven",
                    "browser_safe": True,
                    "render_as_clickable": True,
                    "confidence": "medium",
                    "confidence_reason": "Breach catalog name closely matches generated organization alias.",
                    "matched_entities": {"domains": ["www.7-eleven.com"], "keywords": ["7-Eleven"]},
                    "breach_name": "7-Eleven Data Breach",
                    "breach_date": "2024-08-08",
                    "affected_accounts": 164000,
                    "compromised_data_classes": ["Email addresses", "Names"],
                    "matched_alias": "7-Eleven",
                    "match_type": "brand_alias",
                    "evidence": {"snippet": "Public breach catalog reference found: 7-Eleven Data Breach"},
                }
            ],
            source={"name": "known_breach_catalog", "status": "completed_matched", "duration_ms": 12},
            requested_target_host="www.7-eleven.com",
            requested_registered_domain="7-eleven.com",
        )
        serialized = result.to_dict()
        self.assertEqual(serialized["source_name"], "known_breach_catalog")
        self.assertEqual(serialized["source_type"], "public_breach_catalog")
        self.assertEqual(serialized["status"], "completed")
        self.assertEqual(serialized["risk_score_impact"], 0)
        reference = serialized["observed_references"][0]
        self.assertEqual(reference["scope_origin"], "external_verified_source")
        self.assertEqual(reference["applies_to_target"], "unknown")
        self.assertFalse(reference["applies_to_parent_org"])
        self.assertEqual(reference["observed_on_host"], "haveibeenpwned.com")
        self.assertEqual(reference["observed_on_registered_domain"], "haveibeenpwned.com")
        self.assertEqual(reference["evidence_type"], "public_breach_metadata")
        self.assertEqual(reference["risk_score_impact"], 0)
        self.assertFalse(reference["credential_material_collected"])
        self.assertFalse(reference["raw_secret_collected"])
        self.assertFalse(reference["account_validated"])
        self.assertEqual(reference["recommended_action"], "Manually validate organization relevance; do not collect credentials.")
        self.assertEqual(reference["affected_accounts"], 164000)
        self.assertEqual(reference["breach_date"], "2024-08-08")

    def test_public_breach_catalog_no_match_has_empty_observed_references(self) -> None:
        leak = build_leak_intelligence(
            enabled=True,
            signals=[],
            sources=[{"name": "known_breach_catalog", "status": "completed_no_match", "duration_ms": 3}],
            requested_target_host="example.com",
            requested_registered_domain="example.com",
        )
        self.assertEqual(leak["status"], "no_match")
        self.assertEqual(leak["summary"]["observed_references"], 0)
        self.assertEqual(leak["results"][0]["status"], "no_match")
        self.assertEqual(leak["results"][0]["observed_references"], [])
        self.assertEqual(leak["source_health"][0]["source"], "known_breach_catalog")

    def test_leak_intelligence_final_serialization_redacts_secret_like_snippets(self) -> None:
        leak = build_leak_intelligence(
            enabled=True,
            signals=[
                {
                    "category": "known_breach_reference",
                    "source_url": "https://haveibeenpwned.com/Breach/Example",
                    "browser_safe": True,
                    "render_as_clickable": True,
                    "source_provider": "haveibeenpwned",
                    "breach_name": "Example Breach",
                    "evidence": {
                        "snippet": "metadata note password=swordfish api_key=abcd1234SECRET access_token=abcdef1234567890"
                    },
                }
            ],
            sources=[{"name": "known_breach_catalog", "status": "completed_matched", "duration_ms": 4}],
            requested_target_host="example.com",
            requested_registered_domain="example.com",
        )
        serialized = json.dumps(leak)
        self.assertIn("[redacted_password]", serialized)
        self.assertIn("api_key=[redacted]", serialized)
        self.assertIn("access_token=[redacted]", serialized)
        self.assertNotIn("swordfish", serialized)
        self.assertNotIn("abcd1234SECRET", serialized)
        self.assertNotIn("abcdef1234567890", serialized)
        self.assertGreaterEqual(leak["summary"]["suppressed_sensitive_items"], 2)
        self.assertFalse(leak["summary"]["credential_material_collected"])
        self.assertFalse(leak["summary"]["raw_secret_collected"])

    def test_metadata_feed_disabled_emits_coverage_only(self) -> None:
        result = result_from_metadata_feed(
            config={"enabled": False},
            requested_target_host="example.com",
            requested_registered_domain="example.com",
            organization_aliases=["Example"],
        ).to_dict()
        self.assertEqual(result["source_name"], "leak_metadata_feed")
        self.assertEqual(result["source_type"], "leak_metadata_api")
        self.assertEqual(result["status"], "disabled")
        self.assertEqual(result["observed_references"], [])
        self.assertEqual(result["source_health_row"]["source"], "leak_metadata_feed")
        self.assertEqual(result["source_health_row"]["collector_name"], "leak_metadata_feed")
        self.assertEqual(result["source_health_row"]["provider_id"], "custom_https_metadata_feed")
        self.assertEqual(result["source_health_row"]["provider_validation_status"], "valid")
        self.assertTrue(result["source_health_row"]["metadata_only"])
        self.assertIn("metadataFeed.enabled=false", result["source_health_row"]["user_message"])
        self.assertEqual(result["source_health_row"]["disabled_reason"], "metadataFeed.enabled=false")
        self.assertEqual(result["source_health_row"]["items_loaded_count"], 0)

    def test_metadata_feed_enabled_without_path_or_url_is_not_configured(self) -> None:
        result = result_from_metadata_feed(
            config={"enabled": True},
            requested_target_host="example.com",
            requested_registered_domain="example.com",
            organization_aliases=["Example"],
        ).to_dict()
        self.assertEqual(result["status"], "not_configured")
        self.assertEqual(result["observed_references"], [])
        self.assertIn("enabled=true but no feedPath/feedUrl", result["source_health_row"]["user_message"])
        self.assertEqual(result["source_health_row"]["not_configured_reason"], "enabled=true but no feedPath/feedUrl")

    def test_metadata_feed_rejects_non_https_feed_urls(self) -> None:
        for feed_url in ("http://example.com/feed.json", "file:///tmp/feed.json", "ftp://example.com/feed.json", "https:///missing-host"):
            with self.subTest(feed_url=feed_url):
                with mock.patch("reconbot.orchestration.osint_core.leak_sources.metadata_feed.urlopen") as urlopen_mock:
                    result = result_from_metadata_feed(
                        config={"enabled": True, "feedUrl": feed_url},
                        requested_target_host="example.com",
                        requested_registered_domain="example.com",
                        organization_aliases=["Example"],
                    ).to_dict()
                urlopen_mock.assert_not_called()
                self.assertEqual(result["status"], "invalid_config")
                self.assertEqual(result["observed_references"], [])
                self.assertEqual(result["source_health_row"]["provider_validation_status"], "invalid_config")
                self.assertIn("https://", result["source_health_row"]["provider_validation_message"])

    def test_metadata_feed_unknown_provider_and_future_provider_do_not_access_runtime_sources(self) -> None:
        configs = [
            ({"enabled": True, "providerId": "unknown_provider", "feedUrl": "https://metadata-feed.test/feed.json"}, "invalid_config"),
            ({"enabled": True, "providerId": FUTURE_TRUSTED_PROVIDER_PROFILE, "feedUrl": "https://metadata-feed.test/feed.json"}, "not_implemented"),
        ]
        for config, expected_status in configs:
            with self.subTest(config=config):
                with mock.patch("reconbot.orchestration.osint_core.leak_sources.metadata_feed.urlopen") as urlopen_mock:
                    with mock.patch.object(builtins, "open", wraps=builtins.open) as open_mock:
                        result = result_from_metadata_feed(
                            config=config,
                            requested_target_host="example.com",
                            requested_registered_domain="example.com",
                            organization_aliases=["Example"],
                        ).to_dict()
                urlopen_mock.assert_not_called()
                open_mock.assert_not_called()
                self.assertEqual(result["status"], expected_status)
                self.assertEqual(result["observed_references"], [])
                self.assertEqual(result["source_health_row"]["provider_validation_status"], expected_status)

    def test_metadata_feed_https_json_success_uses_safe_endpoint_and_matches(self) -> None:
        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *_args: object) -> bool:
                return False

            def read(self, _limit: int) -> bytes:
                return json.dumps(
                    {
                        "source_name": "example_https_metadata_feed",
                        "items": [
                            {
                                "title": "Example HTTPS breach reference",
                                "reference_url": "https://example.com/report/example",
                                "matched_domains": ["example.com"],
                                "snippet": "Metadata-only public report mention.",
                                "source_provider": "example_https_provider",
                            }
                        ],
                    }
                ).encode("utf-8")

        with mock.patch("reconbot.orchestration.osint_core.leak_sources.metadata_feed.urlopen", return_value=FakeResponse()) as urlopen_mock:
            result = result_from_metadata_feed(
                config={
                    "enabled": True,
                    "feedUrl": "https://metadata-feed.test/feed.json?api_key=never-serialize",
                    "sourceName": "local_test_metadata_feed",
                    "timeout": 3,
                },
                requested_target_host="www.example.com",
                requested_registered_domain="example.com",
                organization_aliases=["Example"],
            ).to_dict()

        request = urlopen_mock.call_args.args[0]
        self.assertEqual(request.full_url, "https://metadata-feed.test/feed.json?api_key=never-serialize")
        self.assertEqual(urlopen_mock.call_args.kwargs["timeout"], 3)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["source_name"], "local_test_metadata_feed")
        self.assertEqual(result["source_type"], "leak_metadata_api")
        self.assertEqual(len(result["observed_references"]), 1)
        reference = result["observed_references"][0]
        self.assertEqual(reference["title"], "Example HTTPS breach reference")
        self.assertIn(reference["match_type"], {"registered_domain", "exact_domain"})
        self.assertEqual(reference["confidence"], "high")
        self.assertEqual(reference["scope_origin"], "external_verified_source")
        self.assertFalse(reference["credential_material_collected"])
        self.assertFalse(reference["raw_secret_collected"])
        self.assertFalse(reference["account_validated"])
        self.assertEqual(reference["risk_score_impact"], 0)
        health = result["source_health_row"]
        self.assertEqual(health["provider_id"], "custom_https_metadata_feed")
        self.assertEqual(health["provider_display_name"], "Custom HTTPS metadata feed")
        self.assertEqual(health["source_mode"], "https_json")
        self.assertEqual(health["provider_validation_status"], "valid")
        self.assertFalse(health["api_key_value_serialized"])
        self.assertEqual(health["feed_source_type"], "https_json")
        self.assertEqual(health["endpoint"], "https://metadata-feed.test/feed.json")
        self.assertEqual(health["items_loaded_count"], 1)
        self.assertEqual(health["items_matched_count"], 1)
        serialized = json.dumps(result)
        self.assertNotIn("never-serialize", serialized)

    def test_metadata_feed_https_missing_api_key_env_is_auth_required_without_request(self) -> None:
        with mock.patch.dict("os.environ", {"RECONBOT_TEST_MISSING_KEY": ""}, clear=False):
            with mock.patch("reconbot.orchestration.osint_core.leak_sources.metadata_feed.urlopen") as urlopen_mock:
                result = result_from_metadata_feed(
                    config={
                        "enabled": True,
                        "feedUrl": "https://metadata-feed.test/feed.json",
                        "apiKeyEnv": "RECONBOT_TEST_MISSING_KEY",
                    },
                    requested_target_host="www.example.com",
                    requested_registered_domain="example.com",
                    organization_aliases=["Example"],
                ).to_dict()
        urlopen_mock.assert_not_called()
        self.assertEqual(result["status"], "auth_required")
        self.assertIn("API key environment variable is missing", result["source_health_row"]["user_message"])
        serialized = json.dumps(result)
        self.assertNotIn("RECONBOT_TEST_MISSING_KEY", serialized)

    def test_metadata_feed_https_api_key_header_is_never_serialized(self) -> None:
        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *_args: object) -> bool:
                return False

            def read(self, _limit: int) -> bytes:
                return json.dumps(
                    {
                        "source_name": "example_https_metadata_feed",
                        "items": [
                            {
                                "title": "Example HTTPS breach reference",
                                "reference_url": "https://example.com/report/example",
                                "matched_domains": ["example.com"],
                                "source_provider": "example_https_provider",
                            }
                        ],
                    }
                ).encode("utf-8")

        api_key = "reconbot-test-api-key-secret"
        with mock.patch.dict("os.environ", {"RECONBOT_TEST_FEED_KEY": api_key}, clear=False):
            with mock.patch("reconbot.orchestration.osint_core.leak_sources.metadata_feed.urlopen", return_value=FakeResponse()) as urlopen_mock:
                result = result_from_metadata_feed(
                    config={
                        "enabled": True,
                        "feedUrl": "https://metadata-feed.test/feed.json",
                        "apiKeyEnv": "RECONBOT_TEST_FEED_KEY",
                    },
                    requested_target_host="www.example.com",
                    requested_registered_domain="example.com",
                    organization_aliases=["Example"],
                ).to_dict()
        request = urlopen_mock.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), f"Bearer {api_key}")
        self.assertEqual(result["status"], "completed")
        serialized = json.dumps(result)
        self.assertNotIn(api_key, serialized)
        self.assertNotIn("RECONBOT_TEST_FEED_KEY", serialized)

    def test_metadata_feed_local_json_exact_domain_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feed_path = Path(tmp) / "feed.json"
            feed_path.write_text(
                json.dumps(
                    {
                        "source_name": "example_metadata_feed",
                        "generated_at": "2026-06-23T00:00:00Z",
                        "items": [
                            {
                                "title": "Example breach reference",
                                "reference_url": "https://example.com/report/example",
                                "published_at": "2026-05-01",
                                "breach_date": "2026-04-01",
                                "affected_accounts": 12345,
                                "data_classes": ["Email addresses", "Names"],
                                "matched_domains": ["example.com"],
                                "matched_brands": ["Example"],
                                "snippet": "Metadata-only public report mention.",
                                "source_provider": "example_provider",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = result_from_metadata_feed(
                config={"enabled": True, "feedPath": str(feed_path), "sourceName": "local_test_feed"},
                requested_target_host="example.com",
                requested_registered_domain="example.com",
                organization_aliases=["Example"],
            ).to_dict()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["observed_references"]), 1)
        reference = result["observed_references"][0]
        self.assertEqual(reference["evidence_type"], "public_leak_metadata")
        self.assertEqual(reference["provider_id"], "local_demo_feed")
        self.assertEqual(reference["provider_display_name"], "Local demo metadata feed")
        self.assertEqual(reference["scope_origin"], "external_verified_source")
        self.assertEqual(reference["match_type"], "exact_domain")
        self.assertEqual(reference["confidence"], "high")
        self.assertEqual(reference["observed_on_host"], "example.com")
        self.assertEqual(reference["observed_on_registered_domain"], "example.com")
        self.assertIs(reference["applies_to_target"], True)
        self.assertEqual(reference["risk_score_impact"], 0)
        self.assertFalse(reference["credential_material_collected"])
        self.assertFalse(reference["raw_secret_collected"])
        self.assertEqual(result["source_health_row"]["feed_source_type"], "local_file")
        self.assertEqual(result["source_health_row"]["provider_id"], "local_demo_feed")
        self.assertEqual(result["source_health_row"]["provider_display_name"], "Local demo metadata feed")
        self.assertEqual(result["source_health_row"]["source_mode"], "local_file")
        self.assertEqual(result["source_health_row"]["provider_validation_status"], "valid")
        self.assertEqual(result["source_health_row"]["feed_path_basename"], "feed.json")
        self.assertEqual(result["source_health_row"]["items_loaded_count"], 1)
        self.assertEqual(result["source_health_row"]["items_matched_count"], 1)
        self.assertEqual(result["source_health_row"]["items_suppressed_count"], 0)

    def test_metadata_feed_local_json_registered_domain_match_from_www_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feed_path = Path(tmp) / "feed.json"
            feed_path.write_text(
                json.dumps(
                    {
                        "source_name": "example_metadata_feed",
                        "items": [
                            {
                                "title": "Example breach reference",
                                "reference_url": "https://reports.example.org/report/example",
                                "published_at": "2026-05-01",
                                "breach_date": "2026-04-01",
                                "affected_accounts": 12345,
                                "data_classes": ["Email addresses", "Names"],
                                "matched_domains": ["example.com"],
                                "matched_brands": ["Example"],
                                "snippet": "Metadata-only public report mention.",
                                "source_provider": "example_provider",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = result_from_metadata_feed(
                config={"enabled": True, "feedPath": str(feed_path), "sourceName": "local_test_metadata_feed"},
                requested_target_host="www.example.com",
                requested_registered_domain="example.com",
                organization_aliases=["Example"],
            ).to_dict()
        self.assertEqual(result["source_name"], "local_test_metadata_feed")
        self.assertEqual(result["source_type"], "leak_metadata_api")
        self.assertEqual(result["status"], "completed")
        reference = result["observed_references"][0]
        self.assertEqual(reference["match_type"], "registered_domain")
        self.assertEqual(reference["confidence"], "high")
        self.assertEqual(reference["scope_origin"], "external_verified_source")
        self.assertEqual(reference["observed_on_host"], "reports.example.org")
        self.assertEqual(reference["observed_on_registered_domain"], "example.org")
        self.assertEqual(reference["applies_to_target"], "unknown")
        self.assertFalse(reference["credential_material_collected"])
        self.assertFalse(reference["raw_secret_collected"])
        self.assertFalse(reference["account_validated"])
        self.assertEqual(reference["risk_score_impact"], 0)

    def test_metadata_feed_local_json_no_match_has_no_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feed_path = Path(tmp) / "feed.json"
            feed_path.write_text(
                json.dumps(
                    {
                        "source_name": "example_metadata_feed",
                        "items": [
                            {
                                "title": "Unrelated breach reference",
                                "reference_url": "https://example.net/report",
                                "matched_domains": ["unrelated.example.net"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = result_from_metadata_feed(
                config={"enabled": True, "feedPath": str(feed_path)},
                requested_target_host="example.com",
                requested_registered_domain="example.com",
                organization_aliases=["Example"],
            ).to_dict()
        self.assertEqual(result["status"], "no_match")
        self.assertEqual(result["observed_references"], [])

    def test_metadata_feed_rejects_weak_alias_and_substring_only_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feed_path = Path(tmp) / "feed.json"
            feed_path.write_text(
                json.dumps(
                    {
                        "source_name": "example_metadata_feed",
                        "items": [
                            {
                                "title": "A complex service outage report",
                                "reference_url": "https://reports.example.org/report/a",
                                "matched_brands": ["www", "com", "exa"],
                                "snippet": "The word samplecorpse appears only as a larger unrelated token.",
                                "source_provider": "example_provider",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = result_from_metadata_feed(
                config={"enabled": True, "feedPath": str(feed_path)},
                requested_target_host="www.samplecorp.com",
                requested_registered_domain="samplecorp.com",
                organization_aliases=["sam", "com", "www", "samplecorp"],
            ).to_dict()
        self.assertEqual(result["status"], "no_match")
        self.assertEqual(result["observed_references"], [])

    def test_metadata_feed_suppresses_secret_like_snippets_without_serializing_raw_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feed_path = Path(tmp) / "feed.json"
            feed_path.write_text(
                json.dumps(
                    {
                        "source_name": "example_metadata_feed",
                        "items": [
                            {
                                "title": "Example breach reference",
                                "reference_url": "https://example.com/report/example",
                                "matched_domains": ["example.com"],
                                "snippet": (
                                    "password=swordfish api_key=abcd1234SECRET access_token=abcdef1234567890 "
                                    "user@example.com:swordfish sessionid=SESSIONSECRET12345 blob="
                                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                                ),
                                "private_key": "-----BEGIN PRIVATE KEY-----\nabcdef123456\n-----END PRIVATE KEY-----",
                                "hash": "0123456789abcdef0123456789abcdef",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            leak = build_leak_intelligence(
                enabled=True,
                known_breach_enabled=False,
                signals=[],
                sources=[],
                requested_target_host="example.com",
                requested_registered_domain="example.com",
                organization_aliases=["Example"],
                metadata_feed_config={"enabled": True, "feedPath": str(feed_path)},
            )
        serialized = json.dumps(leak)
        self.assertIn("[redacted_password]", serialized)
        self.assertIn("api_key=[redacted]", serialized)
        self.assertIn("[redacted_credential_pair]", serialized)
        self.assertIn("[redacted_private_key]", serialized)
        self.assertNotIn("swordfish", serialized)
        self.assertNotIn("abcd1234SECRET", serialized)
        self.assertNotIn("abcdef1234567890", serialized)
        self.assertNotIn("SESSIONSECRET12345", serialized)
        self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", serialized)
        self.assertNotIn("0123456789abcdef0123456789abcdef", serialized)
        self.assertGreaterEqual(leak["summary"]["suppressed_sensitive_items"], 4)
        metadata_health = next(row for row in leak["source_health"] if row["source"] == "leak_metadata_feed")
        self.assertGreaterEqual(metadata_health["items_suppressed_count"], 4)
        self.assertFalse(leak["summary"]["credential_material_collected"])
        self.assertFalse(leak["summary"]["raw_secret_collected"])

    def test_leak_intelligence_aggregates_known_catalog_and_metadata_feed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feed_path = Path(tmp) / "feed.json"
            feed_path.write_text(
                json.dumps(
                    {
                        "source_name": "example_metadata_feed",
                        "items": [
                            {
                                "title": "Example feed reference",
                                "reference_url": "https://example.com/report/example",
                                "matched_domains": ["example.com"],
                                "source_provider": "example_provider",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            leak = build_leak_intelligence(
                enabled=True,
                known_breach_enabled=True,
                signals=[
                    {
                        "category": "known_breach_reference",
                        "source_url": "https://haveibeenpwned.com/Breach/Example",
                        "browser_safe": True,
                        "render_as_clickable": True,
                        "source_provider": "haveibeenpwned",
                        "breach_name": "Example Breach",
                    }
                ],
                sources=[{"name": "known_breach_catalog", "status": "completed_matched", "duration_ms": 4}],
                requested_target_host="example.com",
                requested_registered_domain="example.com",
                organization_aliases=["Example"],
                metadata_feed_config={"enabled": True, "feedPath": str(feed_path), "sourceName": "local_test_feed"},
            )
        self.assertEqual(leak["status"], "completed")
        self.assertEqual(leak["summary"]["observed_references"], 2)
        self.assertEqual({row["source"] for row in leak["source_health"]}, {"known_breach_catalog", "local_test_feed"})

    def test_yaml_osint_metadata_feed_config_reaches_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            feed_path = tmp_path / "feed.json"
            feed_path.write_text(
                json.dumps(
                    {
                        "source_name": "local_example_metadata_feed",
                        "items": [
                            {
                                "title": "Example Corp public breach metadata reference",
                                "reference_url": "https://example.com/security/example-breach-report",
                                "published_at": "2026-05-01",
                                "breach_date": "2026-04-01",
                                "affected_accounts": 12345,
                                "data_classes": ["Email addresses", "Names"],
                                "matched_domains": ["example.com"],
                                "matched_brands": ["Example Corp"],
                                "snippet": "Metadata-only public report mention.",
                                "source_provider": "local_example_provider",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            config_path = tmp_path / "osint-feed.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "reconbot:",
                        "  osint:",
                        "    enabled: true",
                        "    passiveOnly: true",
                        "    includeCertificateTransparency: false",
                        "    includeHistoricalUrls: false",
                        "    includePublicCodeReferences: false",
                        "    includeKnownBreachCatalog: true",
                        "    includeSearchDorkSuggestions: false",
                        "    includeInfrastructureIntelligence: false",
                        "    includeOrganizationIntelligence: false",
                        "    leakSources:",
                        "      metadataFeed:",
                        "        enabled: true",
                        "        sourceName: local_test_metadata_feed",
                        f"        feedPath: {feed_path}",
                        "        feedUrl: \"\"",
                        "        apiKeyEnv: \"\"",
                        "        timeout: 10",
                        "        maxResults: 25",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            cfg = _load_yaml_config(str(config_path))
            with mock.patch(
                "reconbot.orchestration.osint_core.pipeline._run_known_breach_catalog",
                return_value={
                    "name": "known_breach_catalog",
                    "status": "completed_no_match",
                    "duration_ms": 1,
                    "user_message": "No matching public breach metadata reference found.",
                    "errors": [],
                },
            ):
                payload = build_osint_enrichment(
                    target="https://www.example.com",
                    enabled=True,
                    tool_settings=cfg["tool_settings"],
                )
        self.assertEqual(payload["settings"]["leak_sources"]["metadata_feed"]["sourceName"], "local_test_metadata_feed")
        sanitized_feed_settings = payload["settings"]["leak_sources"]["metadata_feed"]
        self.assertNotIn("apiKeyEnv", sanitized_feed_settings)
        self.assertNotIn("api_key_env", sanitized_feed_settings)
        self.assertFalse(sanitized_feed_settings["apiKeyEnvConfigured"])
        self.assertEqual(sanitized_feed_settings["feedPath"], "feed.json")
        self.assertNotIn(str(tmp_path), json.dumps(payload))
        leak = payload["leak_intelligence"]
        self.assertEqual(leak["status"], "completed")
        self.assertTrue(leak["enabled"])
        self.assertGreaterEqual(leak["enabled_collectors_count"], 2)
        self.assertEqual(leak["summary"]["observed_references"], 1)
        metadata_result = next(result for result in leak["results"] if result["source_type"] == "leak_metadata_api")
        self.assertEqual(metadata_result["source_name"], "local_test_metadata_feed")
        self.assertEqual(metadata_result["source_type"], "leak_metadata_api")
        self.assertEqual(metadata_result["status"], "completed")
        self.assertEqual(len(metadata_result["observed_references"]), 1)
        reference = metadata_result["observed_references"][0]
        self.assertEqual(reference["title"], "Example Corp public breach metadata reference")
        self.assertIn(metadata_result["source_name"], {"local_test_metadata_feed", "local_example_metadata_feed"})
        self.assertIn(reference["match_type"], {"registered_domain", "exact_domain"})
        self.assertEqual(reference["confidence"], "high")
        self.assertEqual(reference["scope_origin"], "external_verified_source")
        self.assertEqual(reference["observed_on_host"], "example.com")
        self.assertEqual(reference["observed_on_registered_domain"], "example.com")
        self.assertFalse(reference["credential_material_collected"])
        self.assertFalse(reference["raw_secret_collected"])
        self.assertFalse(reference["account_validated"])
        self.assertEqual(reference["risk_score_impact"], 0)
        metadata_health = next(row for row in leak["source_health"] if row["source"] == "local_test_metadata_feed")
        self.assertEqual(metadata_health["collector_name"], "leak_metadata_feed")
        self.assertEqual(metadata_health["status"], "completed")
        self.assertEqual(metadata_health["feed_source_type"], "local_file")
        self.assertEqual(metadata_health["feed_path_basename"], "feed.json")
        self.assertEqual(metadata_health["items_loaded_count"], 1)
        self.assertEqual(metadata_health["items_matched_count"], 1)

    def test_committed_metadata_feed_demo_config_generates_example_reference(self) -> None:
        config_path = Path("docs/examples/osint_metadata_feed_demo_config.json")
        self.assertTrue(config_path.exists())
        cfg = _load_yaml_config(str(config_path))
        self.assertEqual(cfg["run_mode"], "osint_only")
        feed_settings = cfg["tool_settings"]["osint"]["leakSources"]["metadataFeed"]
        self.assertTrue(feed_settings["enabled"])
        self.assertEqual(feed_settings["providerId"], "local_demo_feed")
        self.assertEqual(feed_settings["sourceName"], "local_test_metadata_feed")
        self.assertEqual(feed_settings["sourceType"], "local_file")
        self.assertEqual(feed_settings["feedPath"], "docs/examples/leak_metadata_feed.sample.json")

        payload = build_osint_enrichment(
            target="https://www.example.com",
            enabled=True,
            tool_settings=cfg["tool_settings"],
        )
        self.assertTrue(payload["normalization"]["generic_or_reserved_domain"])
        leak = payload["leak_intelligence"]
        self.assertTrue(leak["enabled"])
        self.assertGreaterEqual(leak["enabled_collectors_count"], 2)
        metadata_result = next(result for result in leak["results"] if result["source_type"] == "leak_metadata_api")
        self.assertEqual(metadata_result["status"], "completed")
        self.assertEqual(metadata_result["source_name"], "local_test_metadata_feed")
        self.assertEqual(len(metadata_result["observed_references"]), 1)
        reference = metadata_result["observed_references"][0]
        self.assertEqual(reference["title"], "Example Corp public breach metadata reference")
        self.assertEqual(reference["reference_url"], "https://example.com/security/example-breach-report")
        self.assertEqual(reference["source_provider"], "local_example_provider")
        self.assertEqual(reference["provider_id"], "local_demo_feed")
        self.assertEqual(reference["provider_display_name"], "Local demo metadata feed")
        self.assertIn(reference["match_type"], {"registered_domain", "exact_domain"})
        self.assertEqual(reference["confidence"], "high")
        self.assertEqual(reference["scope_origin"], "external_verified_source")
        self.assertEqual(reference["observed_on_host"], "example.com")
        self.assertEqual(reference["observed_on_registered_domain"], "example.com")
        self.assertEqual(reference["requested_target_host"], "www.example.com")
        self.assertEqual(reference["requested_registered_domain"], "example.com")
        self.assertEqual(reference["applies_to_target"], "unknown")
        self.assertFalse(reference["credential_material_collected"])
        self.assertFalse(reference["raw_secret_collected"])
        self.assertFalse(reference["account_validated"])
        self.assertEqual(reference["risk_score_impact"], 0)
        metadata_health = next(row for row in leak["source_health"] if row.get("collector_name") == "leak_metadata_feed")
        self.assertEqual(metadata_health["status"], "completed")
        self.assertEqual(metadata_health["provider_id"], "local_demo_feed")
        self.assertEqual(metadata_health["provider_display_name"], "Local demo metadata feed")
        self.assertEqual(metadata_health["provider_validation_status"], "valid")
        self.assertEqual(metadata_health["source_mode"], "local_file")
        self.assertEqual(metadata_health["feed_source_type"], "local_file")
        self.assertEqual(metadata_health["feed_path_basename"], "leak_metadata_feed.sample.json")
        self.assertEqual(metadata_health["items_loaded_count"], 1)
        self.assertEqual(metadata_health["items_matched_count"], 1)
        self.assertEqual(metadata_health["items_suppressed_count"], 0)

        html = render_osint_section({"osint": payload})
        leak_section = html.split('id="osint-leak-breach-intelligence"', 1)[1].split('id="osint-overview"', 1)[0]
        self.assertIn("<code>known_breach_catalog</code>", leak_section)
        self.assertIn("collector: <code>leak_metadata_feed</code>", leak_section)
        self.assertIn("Example Corp public breach metadata reference", leak_section)
        self.assertIn("local_example_provider / local_test_metadata_feed", leak_section)
        self.assertIn('href="https://example.com/security/example-breach-report"', leak_section)
        self.assertIn("Metadata feed sonucu. Bu aktif bir zafiyet bulgusu değildir.", leak_section)
        self.assertIn("12345", leak_section)
        self.assertIn("E-posta adresleri, İsimler", leak_section)

    def test_osint_report_renders_configured_metadata_feed_result_without_duplicate_safety_cards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feed_path = Path(tmp) / "feed.json"
            feed_path.write_text(
                json.dumps(
                    {
                        "source_name": "local_example_metadata_feed",
                        "items": [
                            {
                                "title": "Example Corp public breach metadata reference",
                                "reference_url": "https://example.com/security/example-breach-report",
                                "published_at": "2026-05-01",
                                "breach_date": "2026-04-01",
                                "affected_accounts": 12345,
                                "data_classes": ["Email addresses", "Names"],
                                "matched_domains": ["example.com"],
                                "matched_brands": ["Example Corp"],
                                "snippet": "Metadata-only public report mention.",
                                "source_provider": "local_example_provider",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch(
                "reconbot.orchestration.osint_core.pipeline._run_known_breach_catalog",
                return_value={
                    "name": "known_breach_catalog",
                    "status": "completed_no_match",
                    "duration_ms": 1,
                    "user_message": "No matching public breach metadata reference found.",
                    "errors": [],
                },
            ):
                payload = build_osint_enrichment(
                    target="https://www.example.com",
                    enabled=True,
                    tool_settings={
                        "osint": {
                            "passiveOnly": True,
                            "includeCertificateTransparency": False,
                            "includeHistoricalUrls": False,
                            "includePublicCodeReferences": False,
                            "includeKnownBreachCatalog": True,
                            "includeSearchDorkSuggestions": False,
                            "includeInfrastructureIntelligence": False,
                            "includeOrganizationIntelligence": False,
                            "leakSources": {
                                "metadataFeed": {
                                    "enabled": True,
                                    "sourceName": "local_test_metadata_feed",
                                    "feedPath": str(feed_path),
                                    "feedUrl": "",
                                    "apiKeyEnv": "",
                                    "timeout": 10,
                                    "maxResults": 25,
                                }
                            },
                        }
                    },
                )
        html = render_osint_section({"osint": payload})
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["leak_intelligence"]["summary"]["observed_references"], 1)
        self.assertIn("Metadata feed bu çalıştırmada açık ve başarıyla kontrol edildi.", html)
        self.assertIn("Bu Rapor Kısaca Ne Diyor?", html)
        self.assertIn("OSINT Yönetici Özeti", html)
        self.assertIn("Kanıt / Bağlam / Manuel Öneri Ayrımı", html)
        self.assertIn("Kaynak Kapsamı", html)
        self.assertIn("Darkweb / Sızıntı / İhlal İstihbaratı", html)
        self.assertIn("Konum İstihbaratı", html)
        self.assertIn("Gözlemlenmiş aktif OSINT kanıtı", html)
        self.assertIn("Sadece-metadata sızıntı/ihlal referansı", html)
        self.assertIn("Aktif maruziyet kanıtı: 0 | Sadece-metadata sızıntı/ihlal referansı: 1", html)
        self.assertIn("Aktif OSINT maruziyet kanıtı bulunmadı.", html)
        self.assertIn("Ancak 1 adet sadece-metadata sızıntı/ihlal referansı görüldü.", html)
        self.assertIn("Bu aktif bir zafiyet bulgusu değildir ve risk skorunu artırmaz.", html)
        self.assertIn("Kuruma gerçekten ait olup olmadığı manuel olarak doğrulanmalıdır.", html)
        self.assertNotIn("Metadata feed sağlayıcısı kurulu ama kapalı.", html)
        leak_section = html.split('id="osint-leak-breach-intelligence"', 1)[1].split('id="osint-overview"', 1)[0]
        self.assertIn("Example Corp public breach metadata reference", leak_section)
        self.assertIn("local_example_provider / local_test_metadata_feed", leak_section)
        self.assertIn('href="https://example.com/security/example-breach-report"', leak_section)
        self.assertIn("Metadata feed sonucu. Bu aktif bir zafiyet bulgusu değildir.", leak_section)
        self.assertIn("<code>known_breach_catalog</code>", leak_section)
        self.assertIn("<code>local_test_metadata_feed</code>", leak_section)
        self.assertIn("collector: <code>leak_metadata_feed</code>", leak_section)
        self.assertIn("completed", leak_section)
        self.assertIn("İhlal / yayın tarihi", leak_section)
        self.assertIn("12345", leak_section)
        self.assertIn("E-posta adresleri, İsimler", leak_section)
        self.assertIn("Toplanan kimlik bilgisi", leak_section)
        self.assertIn("Toplanan dump", leak_section)
        self.assertIn("Kurumla gerçekten ilişkili olup olmadığını manuel doğrula; kimlik bilgisi toplama.", html)
        self.assertNotIn("Raw credential collection", leak_section)
        self.assertNotIn("Raw dump collection", leak_section)

    def test_electron_metadata_feed_ui_defaults_validation_and_serialization_contract(self) -> None:
        shared_model = Path("desktop/src/shared/metadataFeed.ts").read_text(encoding="utf-8")
        settings_model = Path("desktop/src/renderer/lib/settingsModel.ts").read_text(encoding="utf-8")
        process_model = Path("desktop/src/main/reconbotProcess.ts").read_text(encoding="utf-8")
        app_model = Path("desktop/src/renderer/App.tsx").read_text(encoding="utf-8")
        settings_pane = Path("desktop/src/renderer/components/SettingsPane.tsx").read_text(encoding="utf-8")

        self.assertIn("enabled: false", shared_model)
        self.assertIn('providerId: "custom_https_metadata_feed"', shared_model)
        self.assertIn('sourceName: ""', shared_model)
        self.assertIn('sourceType: "https_json"', shared_model)
        self.assertIn('feedPath: ""', shared_model)
        self.assertIn('feedUrl: ""', shared_model)
        self.assertIn('apiKeyEnv: ""', shared_model)
        self.assertIn("timeout: 10", shared_model)
        self.assertIn("maxResults: 25", shared_model)
        self.assertIn("metadataFeedBackendConfig", shared_model)
        backend_function = shared_model.split("export function metadataFeedBackendConfig", 1)[1].split("export function validateMetadataFeedUiConfig", 1)[0]
        for key in ("enabled", "providerId", "sourceName", "sourceType", "feedPath", "feedUrl", "apiKeyEnv", "timeout", "maxResults"):
            self.assertIn(f"{key}:", backend_function)
        self.assertIn('feedPath: normalized.providerId === "local_demo_feed" && sourceType === "local_file" ? normalized.feedPath : ""', backend_function)
        self.assertIn('feedUrl: normalized.providerId === "custom_https_metadata_feed" && sourceType === "https_json" ? normalized.feedUrl : ""', backend_function)
        self.assertIn("LOCAL_EXAMPLE_METADATA_FEED", shared_model)
        self.assertIn('providerId: "local_demo_feed"', shared_model)
        self.assertIn('sourceName: "local_test_metadata_feed"', shared_model)
        self.assertIn('feedPath: "docs/examples/leak_metadata_feed.sample.json"', shared_model)
        self.assertIn('sourceType: "local_file"', shared_model)
        self.assertIn("future_trusted_provider_profile", shared_model)

        self.assertIn("Yalnızca https:// endpoint kabul edilir.", shared_model)
        self.assertIn("file:// URL kabul edilmez. Local JSON dosya yolu modunu kullan.", shared_model)
        self.assertIn("Custom HTTPS metadata feed açık ama HTTPS JSON endpoint yapılandırılmamış.", shared_model)
        self.assertIn("Local demo metadata feed açık ama local JSON dosya yolu yapılandırılmamış.", shared_model)
        self.assertIn("Future trusted provider profile yakında; etkin durumdayken scan başlatılamaz.", shared_model)
        self.assertIn('sourceType === "https_json" && feedUrl && !feedUrl.toLowerCase().startsWith("https://")', shared_model)
        self.assertIn("Metadata feed sağlayıcısı kurulu ama kapalı. Yalnızca kapalı kaynak kapsamı olarak görünür.", shared_model)
        self.assertIn("Provider registry runtime öncesinde metadata-only feed kurallarını uygular.", shared_model)
        self.assertIn("Metadata feed local JSON dosyasından okunacak:", shared_model)
        self.assertIn("Metadata feed güvenilir HTTPS JSON metadata endpoint'ini isteyecek.", shared_model)
        self.assertIn("Açık ama yapılandırılmamış. Collector not_configured döndürür.", shared_model)
        self.assertIn("Key değeri raporlarda veya run_result.json içinde saklanmaz.", shared_model)
        self.assertIn("validateMetadataFeedUiConfig", app_model)
        self.assertIn("validateMetadataFeedUiConfig", process_model)
        self.assertIn("metadataFeedBackendConfig(scanConfig.toolSettings.osint.leakSources?.metadataFeed)", process_model)

        self.assertIn("Darkweb / Sızıntı / İhlal Metadata Feed’i", settings_pane)
        self.assertIn("Sadece metadata. Tor/onion yok. Credential, dump veya ham sızıntı kaydı toplanmaz.", settings_pane)
        self.assertIn("Provider registry runtime öncesinde metadata-only feed kurallarını uygular.", settings_pane)
        self.assertIn("ReconBot credential, password, hash, token, private key, session cookie, raw dump, paste raw content, personal record veya ham sızıntı kaydı toplamaz.", settings_pane)
        self.assertIn("Bu collector yalnızca normalize edilmiş breach/leak metadata tüketir.", settings_pane)
        self.assertIn("Credential, dump, raw paste content veya personal record içeren feed yapılandırma.", settings_pane)
        self.assertIn("API key değeri buraya yazılmaz. Sadece ortam değişkeni adı girilir.", settings_pane)
        self.assertIn("ReconBot API key değerini run_result.json veya raporlara yazmaz.", settings_pane)
        self.assertIn("Metadata referansları aktif zafiyet bulgusu değildir ve risk skorunu etkilemez.", settings_pane)
        self.assertIn("Local örnek metadata feed’i yükle", settings_pane)
        self.assertIn("Demo fixture sadece yerel test içindir.", settings_pane)
        self.assertIn("metadataFeedStatusPreview", settings_pane)
        self.assertIn("Metadata feed’i etkinleştir", settings_pane)
        self.assertIn("Provider", settings_pane)
        self.assertIn("Future trusted provider profile / yakında", shared_model)
        self.assertIn("Kaynak adı", settings_pane)
        self.assertIn("Kaynak tipi", settings_pane)
        self.assertIn("Local JSON dosya yolu", settings_pane)
        self.assertIn("HTTPS JSON endpoint", settings_pane)
        self.assertIn("API key ortam değişkeni adı", settings_pane)
        self.assertIn("Zaman aşımı", settings_pane)
        self.assertIn("Maksimum sonuç", settings_pane)

        self.assertIn("includeKnownBreachCatalog: true", settings_model)
        self.assertIn("includeCertificateTransparency: true", settings_model)
        self.assertIn("includeHistoricalUrls: true", settings_model)
        self.assertIn("includePublicCodeReferences: true", settings_model)
        self.assertIn("includeSearchDorkSuggestions: true", settings_model)
        self.assertIn("includeInfrastructureIntelligence: true", settings_model)
        self.assertIn("includeOrganizationIntelligence: true", settings_model)
        self.assertIn("metadataFeed: { ...DEFAULT_METADATA_FEED }", settings_model)

    def test_electron_metadata_feed_docs_include_ui_smoke_values(self) -> None:
        desktop_readme = Path("desktop/README.md").read_text(encoding="utf-8")
        leak_readme = Path("reconbot/orchestration/osint_core/leak_sources/README.md").read_text(encoding="utf-8")
        for doc in (desktop_readme, leak_readme):
            self.assertIn("Settings", doc)
            self.assertIn("Darkweb / Sızıntı / İhlal Metadata Feed’i", doc)
            self.assertIn("www.example.com", doc)
            self.assertIn('"enabled": true', doc)
            self.assertIn('"providerId": "local_demo_feed"', doc)
            self.assertIn('"sourceName": "local_test_metadata_feed"', doc)
            self.assertIn('"sourceType": "local_file"', doc)
            self.assertIn('"feedPath": "docs/examples/leak_metadata_feed.sample.json"', doc)
            self.assertIn('"feedUrl": ""', doc)
            self.assertIn('"apiKeyEnv": ""', doc)
            self.assertIn('"timeout": 10', doc)
            self.assertIn('"maxResults": 25', doc)
            self.assertIn("No Tor", doc)
            self.assertIn("No credentials", doc)
            self.assertIn("credential validation", doc)

    def test_electron_ui_generated_local_metadata_feed_config_reaches_osint_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feed_path = Path(tmp) / "feed.json"
            feed_path.write_text(
                json.dumps(
                    {
                        "source_name": "ui_local_metadata_feed",
                        "items": [
                            {
                                "title": "UI configured metadata reference",
                                "reference_url": "https://example.com/security/ui-feed-reference",
                                "matched_domains": ["example.com"],
                                "matched_brands": ["Example"],
                                "source_provider": "ui_fixture_provider",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            ui_tool_settings = {
                "osint": {
                    "enabled": True,
                    "mode": "safe_mvp",
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": False,
                    "maxSignals": 25,
                    "timeout": 10,
                    "passiveOnly": True,
                    "leakSources": {
                        "metadataFeed": {
                            "enabled": True,
                            "providerId": "local_demo_feed",
                            "sourceName": "ui_local_metadata_feed",
                            "sourceType": "local_file",
                            "feedPath": str(feed_path),
                            "feedUrl": "",
                            "apiKeyEnv": "",
                            "timeout": 10,
                            "maxResults": 25,
                        }
                    },
                }
            }
            payload = build_osint_enrichment(
                target="https://www.example.com",
                enabled=True,
                tool_settings=ui_tool_settings,
            )

        self.assertFalse(payload["settings"]["leak_sources"]["metadata_feed"]["apiKeyEnvConfigured"])
        self.assertEqual(payload["settings"]["leak_sources"]["metadata_feed"]["providerId"], "local_demo_feed")
        self.assertEqual(payload["settings"]["leak_sources"]["metadata_feed"]["sourceType"], "local_file")
        leak = payload["leak_intelligence"]
        self.assertTrue(leak["enabled"])
        metadata_result = next(result for result in leak["results"] if result["source_type"] == "leak_metadata_api")
        self.assertEqual(metadata_result["source_name"], "ui_local_metadata_feed")
        self.assertEqual(metadata_result["status"], "completed")
        self.assertEqual(len(metadata_result["observed_references"]), 1)
        reference = metadata_result["observed_references"][0]
        self.assertEqual(reference["title"], "UI configured metadata reference")
        self.assertFalse(reference["credential_material_collected"])
        self.assertFalse(reference["raw_secret_collected"])
        self.assertFalse(reference["account_validated"])
        self.assertEqual(reference["risk_score_impact"], 0)
        metadata_health = next(row for row in leak["source_health"] if row.get("collector_name") == "leak_metadata_feed")
        self.assertEqual(metadata_health["status"], "completed")
        self.assertEqual(metadata_health["provider_id"], "local_demo_feed")
        self.assertEqual(metadata_health["source_mode"], "local_file")
        self.assertEqual(metadata_health["items_loaded_count"], 1)
        self.assertEqual(metadata_health["items_matched_count"], 1)
        html = render_osint_section({"osint": payload})
        self.assertIn("Metadata feed bu çalıştırmada açık ve başarıyla kontrol edildi.", html)
        self.assertIn("UI configured metadata reference", html)
        self.assertIn("Metadata feed sonucu. Bu aktif bir zafiyet bulgusu değildir.", html)

    def test_electron_ui_generated_custom_https_metadata_feed_config_is_safe(self) -> None:
        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *_args: object) -> bool:
                return False

            def read(self, _limit: int) -> bytes:
                return json.dumps(
                    {
                        "source_name": "ui_https_metadata_feed",
                        "items": [
                            {
                                "title": "UI HTTPS configured metadata reference",
                                "reference_url": "https://example.com/security/ui-https-feed-reference",
                                "matched_domains": ["example.com"],
                                "source_provider": "ui_https_fixture_provider",
                            }
                        ],
                    }
                ).encode("utf-8")

        with mock.patch.dict("os.environ", {"RECONBOT_UI_TEST_FEED_KEY": "do-not-serialize"}, clear=False):
            with mock.patch("reconbot.orchestration.osint_core.leak_sources.metadata_feed.urlopen", return_value=FakeResponse()) as urlopen_mock:
                payload = build_osint_enrichment(
                    target="https://www.example.com",
                    enabled=True,
                    tool_settings={
                        "osint": {
                            "includeCertificateTransparency": False,
                            "includeHistoricalUrls": False,
                            "includePublicCodeReferences": False,
                            "includeKnownBreachCatalog": False,
                            "includeSearchDorkSuggestions": False,
                            "includeInfrastructureIntelligence": False,
                            "includeOrganizationIntelligence": False,
                            "leakSources": {
                                "metadataFeed": {
                                    "enabled": True,
                                    "providerId": "custom_https_metadata_feed",
                                    "sourceName": "ui_https_metadata_feed",
                                    "sourceType": "https_json",
                                    "feedPath": "",
                                    "feedUrl": "https://metadata-feed.test/feed.json",
                                    "apiKeyEnv": "RECONBOT_UI_TEST_FEED_KEY",
                                    "timeout": 10,
                                    "maxResults": 25,
                                }
                            },
                        }
                    },
                )
        self.assertEqual(urlopen_mock.call_args.args[0].full_url, "https://metadata-feed.test/feed.json")
        serialized = json.dumps(payload)
        self.assertNotIn("do-not-serialize", serialized)
        self.assertNotIn("RECONBOT_UI_TEST_FEED_KEY", serialized)
        settings = payload["settings"]["leak_sources"]["metadata_feed"]
        self.assertEqual(settings["providerId"], "custom_https_metadata_feed")
        self.assertEqual(settings["sourceType"], "https_json")
        self.assertTrue(settings["apiKeyEnvConfigured"])
        leak = payload["leak_intelligence"]
        metadata_health = next(row for row in leak["source_health"] if row.get("collector_name") == "leak_metadata_feed")
        self.assertEqual(metadata_health["provider_id"], "custom_https_metadata_feed")
        self.assertEqual(metadata_health["source_mode"], "https_json")
        self.assertTrue(metadata_health["api_key_env_configured"])
        self.assertFalse(metadata_health["api_key_value_serialized"])
        self.assertEqual(metadata_health["items_loaded_count"], 1)
        self.assertEqual(metadata_health["items_matched_count"], 1)

    def test_electron_ui_generated_missing_metadata_feed_config_reports_not_configured(self) -> None:
        payload = build_osint_enrichment(
            target="https://www.example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": False,
                    "leakSources": {
                        "metadataFeed": {
                            "enabled": True,
                            "sourceName": "",
                            "feedPath": "",
                            "feedUrl": "",
                            "apiKeyEnv": "",
                            "timeout": 10,
                            "maxResults": 25,
                        }
                    },
                }
            },
        )
        leak = payload["leak_intelligence"]
        metadata_result = next(result for result in leak["results"] if result["source_type"] == "leak_metadata_api")
        self.assertEqual(metadata_result["status"], "not_configured")
        self.assertEqual(metadata_result["observed_references"], [])
        metadata_health = next(row for row in leak["source_health"] if row.get("collector_name") == "leak_metadata_feed")
        self.assertEqual(metadata_health["status"], "not_configured")
        self.assertIn("enabled=true but no feedPath/feedUrl", metadata_health["user_message"])
        html = render_osint_section({"osint": payload})
        self.assertIn("Metadata feed açık ama feedPath/feedUrl yapılandırılmamış.", html)
        self.assertNotIn("Metadata feed sağlayıcısı kurulu ama kapalı.", html)
        self.assertNotIn("Metadata feed bu çalıştırmada açık ve başarıyla kontrol edildi.", html)

    def test_metadata_feed_invalid_and_future_provider_render_source_coverage_only(self) -> None:
        configs = [
            (
                {
                    "enabled": True,
                    "providerId": "custom_https_metadata_feed",
                    "sourceName": "bad_http_feed",
                    "sourceType": "https_json",
                    "feedUrl": "http://metadata-feed.test/feed.json",
                },
                "invalid_config",
                "custom_https_metadata_feed accepts only complete https:// feedUrl values.",
            ),
            (
                {
                    "enabled": True,
                    "providerId": "future_trusted_provider_profile",
                    "sourceName": "future_feed",
                },
                "not_implemented",
                "Provider profile is a placeholder; no live provider integration is implemented.",
            ),
        ]
        for config, expected_status, expected_message in configs:
            with self.subTest(config=config):
                with mock.patch("reconbot.orchestration.osint_core.leak_sources.metadata_feed.urlopen") as urlopen_mock:
                    payload = build_osint_enrichment(
                        target="https://www.example.com",
                        enabled=True,
                        tool_settings={
                            "osint": {
                                "includeCertificateTransparency": False,
                                "includeHistoricalUrls": False,
                                "includePublicCodeReferences": False,
                                "includeKnownBreachCatalog": False,
                                "includeSearchDorkSuggestions": False,
                                "includeInfrastructureIntelligence": False,
                                "includeOrganizationIntelligence": False,
                                "leakSources": {"metadataFeed": config},
                            }
                        },
                    )
                urlopen_mock.assert_not_called()
                leak = payload["leak_intelligence"]
                metadata_result = next(result for result in leak["results"] if result["source_type"] == "leak_metadata_api")
                self.assertEqual(metadata_result["status"], expected_status)
                self.assertEqual(metadata_result["observed_references"], [])
                self.assertEqual(leak["summary"]["observed_references"], 0)
                metadata_health = next(row for row in leak["source_health"] if row.get("collector_name") == "leak_metadata_feed")
                self.assertEqual(metadata_health["status"], expected_status)
                self.assertEqual(metadata_health["provider_validation_status"], expected_status)
                self.assertEqual(metadata_health["provider_validation_message"], expected_message)
                html = render_osint_section({"osint": payload})
                self.assertIn(expected_status, html)
                self.assertIn(_display_text(expected_message), html)
                self.assertNotIn("Metadata feed result. This is not an active vulnerability finding.", html)


class OsintMvpTests(unittest.TestCase):
    def setUp(self) -> None:
        self._osint_validate_patcher = mock.patch(
            "reconbot.orchestration.osint._validate_osint_url",
            side_effect=self._default_osint_url_validation,
        )
        self.osint_validate_mock = self._osint_validate_patcher.start()
        self._dns_query_patcher = mock.patch(
            "reconbot.orchestration.osint._query_dns_records",
            side_effect=self._default_dns_query,
        )
        self.dns_query_mock = self._dns_query_patcher.start()

    def tearDown(self) -> None:
        self._dns_query_patcher.stop()
        self._osint_validate_patcher.stop()

    def _default_dns_query(self, name: str, record_type: str, timeout: int) -> dict[str, object]:
        rrtype = str(record_type or "").upper()
        if rrtype == "MX":
            return {"status": "present", "records": [f"10 mail.{name}"], "validation_error": ""}
        if rrtype == "TXT" and str(name).startswith("_dmarc."):
            return {"status": "present", "records": ["v=DMARC1; p=none"], "validation_error": ""}
        if rrtype == "TXT":
            return {"status": "present", "records": ["v=spf1 include:_spf.example.net -all"], "validation_error": ""}
        return {"status": "absent", "records": [], "validation_error": "no_answer"}

    def _default_osint_url_validation(self, url: str, **kwargs: object) -> dict[str, object]:
        return {
            "check_policy": "auto_check_allowed",
            "validation_method": str(kwargs.get("validation_method") or "head_get"),
            "check_status": "checked",
            "url_status": "checked_not_found",
            "http_status": 404,
            "final_url": url,
            "content_type": "text/html",
            "title": "",
            "validation_error": "",
            "body": "",
        }

    def _official_fixture(self, name: str) -> str:
        return (Path(__file__).parent / "fixtures" / "osint" / "official_pages" / name).read_text(encoding="utf-8")

    def _minimal_org_osint_settings(self) -> dict[str, object]:
        return {
            "osint": {
                "includeCertificateTransparency": False,
                "includeHistoricalUrls": False,
                "includePublicCodeReferences": False,
                "includeKnownBreachCatalog": False,
                "includeSearchDorkSuggestions": False,
                "includeInfrastructureIntelligence": False,
                "includeOrganizationIntelligence": True,
                "checkOrganizationPages": True,
                "timeout": 2,
            }
        }

    def _fake_dns_modules(self, resolver_class: object, **exception_types: type[Exception]) -> dict[str, types.ModuleType]:
        dns_package = types.ModuleType("dns")
        resolver_module = types.ModuleType("dns.resolver")
        resolver_module.Resolver = resolver_class
        for exception_name in ("NXDOMAIN", "NoAnswer", "LifetimeTimeout", "Timeout"):
            setattr(
                resolver_module,
                exception_name,
                exception_types.get(exception_name) or type(exception_name, (Exception,), {}),
            )
        dns_package.resolver = resolver_module
        return {"dns": dns_package, "dns.resolver": resolver_module}

    def test_fixture_jsonld_postal_address_extraction_v2_shape(self) -> None:
        body = self._official_fixture("entity_with_jsonld.html")

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://example.com/":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Example Entity",
                    "validation_error": "",
                    "body": body,
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(target="example.com", enabled=True, tool_settings=self._minimal_org_osint_settings())
        location = payload["organization_intelligence"]["location_intelligence"]["observed_locations"][0]
        self.assertEqual(location["location_text"], "500 Market Street, San Francisco, CA, 94105, US")
        self.assertEqual(location["address_text"], location["location_text"])
        self.assertEqual(location["source_page_type"], "json_ld")
        self.assertEqual(location["confidence"], "high")
        self.assertIn("PostalAddress", location["confidence_reason"])
        self.assertEqual(location["scope_origin"], "exact_target_host")
        self.assertIs(location["applies_to_target"], True)
        self.assertEqual(location["risk_score_impact"], 0)
        self.assertTrue(location["browser_safe"])
        self.assertTrue(location["render_as_clickable"])
        self.assertEqual(payload["summary"]["target_observed_locations"], 1)
        self.assertEqual(payload["summary"]["affiliate_observed_locations"], 0)

    def test_fixture_footer_contacts_extracts_public_contacts_and_rejects_noise(self) -> None:
        contact_body = self._official_fixture("entity_footer_contacts.html")
        noise_body = self._official_fixture("entity_noise_tracking.html")

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://example.com/contact":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Contact Example",
                    "validation_error": "",
                    "body": contact_body,
                }
            if url == "https://example.com/about":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Noise Example",
                    "validation_error": "",
                    "body": noise_body,
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(target="example.com", enabled=True, tool_settings=self._minimal_org_osint_settings())
        contacts = payload["organization_intelligence"]["contact_intelligence"]
        self.assertEqual([item["contact_endpoint"] for item in contacts["observed_email_addresses"]], ["abuse@example.com"])
        self.assertEqual([item["contact_endpoint"] for item in contacts["observed_phone_numbers"]], ["+15551234567"])
        self.assertIn("https://example.com/contact-us", [item["contact_endpoint"] for item in contacts["observed_contact_forms"]])
        serialized_contacts = json.dumps(contacts)
        self.assertNotIn("444444444444444", serialized_contacts)
        self.assertNotIn("999999999999", serialized_contacts)
        self.assertEqual(payload["summary"]["target_observed_public_contacts"], 3)
        self.assertEqual(payload["summary"]["observed_phone_numbers"], 1)

    def test_fixture_contact_social_document_quality_filters_and_dedupes(self) -> None:
        body = self._official_fixture("entity_contact_quality.html")

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://example.com/":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Entity Contact Quality",
                    "validation_error": "",
                    "body": body,
                }
            if url == "https://example.com/security.pdf":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": "head_get",
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "application/pdf",
                    "title": "",
                    "validation_error": "",
                    "body": "",
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(target="example.com", enabled=True, tool_settings=self._minimal_org_osint_settings())
        org = payload["organization_intelligence"]
        contacts = org["contact_intelligence"]
        form_urls = [item["contact_endpoint"] for item in contacts["observed_contact_forms"]]
        self.assertEqual(
            sorted(form_urls),
            sorted(
                [
                    "https://example.com/contact",
                    "https://example.com/contact-us",
                    "https://example.com/support/contact",
                    "https://example.com/help/contact",
                ]
            ),
        )
        self.assertEqual([item["contact_endpoint"] for item in contacts["observed_email_addresses"]], ["support@example.com"])
        self.assertEqual([item["contact_endpoint"] for item in contacts["observed_phone_numbers"]], ["+15552223333"])
        rejected_values = json.dumps(contacts["rejected_contact_candidates"])
        for rejected in ("/login", "/signup", "/newsletter", "/store-locator", "/careers", "/cart", "/app", "/rewards", "/privacy", "intent/tweet"):
            self.assertIn(rejected, rejected_values)
        self.assertTrue(all(item["contact_type"] == "contact_form" for item in contacts["observed_contact_forms"]))
        self.assertEqual(payload["summary"]["target_observed_public_contacts"], 6)
        self.assertEqual(payload["summary"]["parent_org_observed_public_contacts"], 0)
        self.assertEqual(payload["summary"]["affiliate_observed_public_contacts"], 0)

        profiles = org["people_organization_presence"]["observed_official_social_profiles"]
        profile_urls = {item["profile_url"] for item in profiles}
        self.assertEqual(
            profile_urls,
            {
                "https://www.linkedin.com/company/example-quality",
                "https://www.facebook.com/examplequality",
                "https://github.com/example-quality",
                "https://www.youtube.com/@examplequality",
            },
        )
        rejected_social = json.dumps(org["people_organization_presence"]["rejected_social_candidates"])
        self.assertIn("twitter.com/share", rejected_social)
        self.assertIn("linkedin.com/in/random-person", rejected_social)
        self.assertEqual(payload["summary"]["target_observed_social_profiles"], 4)

        docs = org["public_document_intelligence"]
        self.assertEqual([item["url"] for item in docs["validated_public_documents"]], ["https://example.com/security.pdf"])
        self.assertTrue(any("duplicate_final_url" in item.get("rejection_reason", []) for item in docs["rejected_document_candidates"]))
        self.assertEqual(payload["summary"]["target_validated_public_documents"], 1)

        html = render_osint_section({"osint": payload})
        for label in (
            "Tam hedef iletişim bilgileri",
            "Üst kurum iletişim bilgileri",
            "Bağlı/harici resmî iletişim bilgileri",
            "Üretilmiş rol tahminleri",
            "Tür",
            "Değer / Link",
            "Kaynak sayfa",
            "Nasıl çıkarıldı?",
            "Güven",
            "Kapsam",
            "Target'a uygulanır mı?",
            "Not",
            "Share/intent linkleri ve rastgele kullanıcı profilleri resmî sosyal profil sayılmaz.",
            "Doküman tipi",
            "Content-Type / HTTP",
            "Reddedilen / Bastırılan Adaylar",
            "Bunlar gözlemlenmiş public contact değildir; sadece manuel deneme/tahmin listesidir.",
        ):
            self.assertIn(label, html)
        self.assertIn("Manuel Öneri", html)
        self.assertIn("Manuel/API-gerekli arama kısayolu; gözlemlenmiş bulgu değil", html)

    def test_fixture_social_sameas_extracts_official_profiles_and_rejects_share_links(self) -> None:
        body = self._official_fixture("entity_social_sameas.html")

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://example.com/":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Social Example",
                    "validation_error": "",
                    "body": body,
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(target="example.com", enabled=True, tool_settings=self._minimal_org_osint_settings())
        profiles = payload["organization_intelligence"]["people_organization_presence"]["observed_official_social_profiles"]
        profile_urls = {item["url"] for item in profiles}
        self.assertIn("https://www.linkedin.com/company/example-entity", profile_urls)
        self.assertIn("https://twitter.com/example", profile_urls)
        self.assertIn("https://www.facebook.com/example", profile_urls)
        self.assertIn("https://www.instagram.com/example", profile_urls)
        self.assertIn("https://www.youtube.com/@example", profile_urls)
        self.assertIn("https://github.com/example", profile_urls)
        self.assertIn("https://www.tiktok.com/@example", profile_urls)
        self.assertIn("https://medium.com/example", profile_urls)
        self.assertFalse(any("share" in url.lower() or "intent" in url.lower() or "/in/random-person" in url.lower() for url in profile_urls))
        self.assertTrue(all(item["url_role"] == "observed_official_social_profile" for item in profiles))
        self.assertEqual(payload["summary"]["target_observed_social_profiles"], len(profiles))
        html = render_osint_section({"osint": payload})
        self.assertIn("Resmî Sosyal Profiller", html)

    def test_fixture_public_documents_validated_and_counted_by_scope(self) -> None:
        body = self._official_fixture("entity_footer_contacts.html")
        sitemap = """<?xml version="1.0"?><urlset>
          <url><loc>https://example.com/files/security-whitepaper.pdf</loc></url>
          <url><loc>https://example.com/robots.txt</loc></url>
          <url><loc>https://example.com/missing.pdf</loc></url>
        </urlset>"""

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://example.com/contact":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Contact Example",
                    "validation_error": "",
                    "body": body,
                }
            if url == "https://example.com/.well-known/security.txt":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "get_only"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/plain",
                    "title": "",
                    "validation_error": "",
                    "body": "Contact: mailto:security@example.com",
                }
            if url == "https://example.com/robots.txt":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "get_only"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/plain",
                    "title": "",
                    "validation_error": "",
                    "body": "Sitemap: https://example.com/sitemap.xml",
                }
            if url == "https://example.com/sitemap.xml":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "get_only"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "application/xml",
                    "title": "",
                    "validation_error": "",
                    "body": sitemap,
                }
            if url == "https://example.com/files/security-whitepaper.pdf":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": "head_get",
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "application/pdf",
                    "title": "",
                    "validation_error": "",
                    "body": "",
                }
            if url == "https://example.com/.well-known/security-metadata.json":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": "head_get",
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "application/json",
                    "title": "",
                    "validation_error": "",
                    "body": "",
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(target="example.com", enabled=True, tool_settings=self._minimal_org_osint_settings())
        docs = payload["organization_intelligence"]["public_document_intelligence"]
        validated_urls = {item["url"] for item in docs["validated_public_documents"]}
        self.assertIn("https://example.com/.well-known/security.txt", validated_urls)
        self.assertIn("https://example.com/robots.txt", validated_urls)
        self.assertIn("https://example.com/sitemap.xml", validated_urls)
        self.assertIn("https://example.com/files/security-whitepaper.pdf", validated_urls)
        self.assertIn("https://example.com/.well-known/security-metadata.json", validated_urls)
        self.assertNotIn("https://example.com/missing.pdf", validated_urls)
        self.assertEqual(payload["summary"]["target_validated_public_documents"], len(validated_urls))
        self.assertEqual(payload["summary"]["validated_public_documents"], len(validated_urls))
        self.assertTrue(all(item["browser_safe"] and item["render_as_clickable"] for item in docs["validated_public_documents"]))
        self.assertTrue(any(item["url"] == "https://example.com/missing.pdf" for item in docs["rejected_document_candidates"]))
        html = render_osint_section({"osint": payload})
        self.assertIn("Herkese Açık Dokümanlar", html)
        self.assertIn("Tam hedef herkese açık dokümanları", html)
        self.assertIn("Üst kurum herkese açık dokümanları", html)
        self.assertIn("Bağlı/harici resmî herkese açık dokümanlar", html)

    def test_fixture_soft_error_page_rejects_contacts_locations_and_documents(self) -> None:
        body = self._official_fixture("entity_soft_error.html")

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://example.com/contact":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_redirect",
                    "http_status": 200,
                    "final_url": "https://example.com/Error/400?aspxerrorpath=/contact",
                    "content_type": "text/html",
                    "title": "Error 400",
                    "validation_error": "",
                    "body": body,
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(target="example.com", enabled=True, tool_settings=self._minimal_org_osint_settings())
        org = payload["organization_intelligence"]
        self.assertEqual(payload["summary"]["observed_public_contacts"], 0)
        self.assertEqual(payload["summary"]["observed_phone_numbers"], 0)
        self.assertEqual(payload["summary"]["observed_locations"], 0)
        self.assertEqual(payload["summary"]["validated_public_documents"], 0)
        self.assertEqual(org["contact_intelligence"]["observed_phone_numbers"], [])
        self.assertEqual(org["location_intelligence"]["observed_locations"], [])
        self.assertEqual(org["public_document_intelligence"]["validated_public_documents"], [])

    def _assert_no_broken_internal_hrefs(self, html: str) -> None:
        ids = set(re.findall(r'\bid=["\']([^"\']+)["\']', html))
        anchors = set(re.findall(r'href=["\']#([^"\']+)["\']', html))
        self.assertFalse(anchors - ids, f"Broken internal hrefs: {sorted(anchors - ids)}")

    def _assert_external_osint_links_are_browser_safe(self, html: str) -> None:
        for attrs, href in re.findall(r'<a\s+([^>]*href="([^"]+)"[^>]*)>', html):
            if href.startswith("#"):
                continue
            self.assertRegex(href, r"^https?://")
            self.assertIn('data-browser-safe="true"', attrs, f"External OSINT link lacks browser-safe marker: {href}")

    def _render_osint_report(self, target: str, payload: dict[str, object], *, log_target: str | None = None) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            run_payload = {
                "timestamp": "20260607-120000",
                "started_at": "2026-06-07T12:00:00Z",
                "run_state": "completed",
                "meta": {"target": target, "mode": "domain_or_ip"},
                "run_config": {"run_mode": "osint_only"},
                "osint": payload,
            }
            (run_dir / "run_result.json").write_text(json.dumps(run_payload), encoding="utf-8")
            if log_target is not None:
                (run_dir / "reconbot.log").write_text(
                    f"2026-06-07 12:00:00 [+] Run initialized: target={log_target} output={run_dir}\n",
                    encoding="utf-8",
                )
            generate_report({}, [], {}, {}, target, "", skipped_tools=[], output_dir=run_dir, open_browser=False, quiet=True)
            return (run_dir / "report.html").read_text(encoding="utf-8")

    def test_osint_facade_imports_core_modules_and_keeps_payload_shape(self) -> None:
        osint_module = importlib.import_module("reconbot.orchestration.osint")
        pipeline_module = importlib.import_module("reconbot.orchestration.osint_core.pipeline")
        self.assertIs(osint_module, pipeline_module)
        for module_name in (
            "reconbot.orchestration.osint_core.source_health",
            "reconbot.orchestration.osint_core.organization.mail_dns",
            "reconbot.orchestration.osint_core.models",
            "reconbot.orchestration.osint_core.collectors.hibp",
            "reconbot.orchestration.osint_core.organization.contacts",
        ):
            self.assertIsNotNone(importlib.import_module(module_name))

        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        self.assertTrue(
            {
                "enabled",
                "status",
                "summary",
                "signals",
                "sources",
                "source_health",
                "diagnostics",
                "organization_intelligence",
                "infrastructure",
                "policy",
                "normalization",
                "settings",
            }
            <= set(payload)
        )
        self.assertEqual(payload["policy"]["risk_score_impact"], "none")

    def test_osint_only_sidebar_uses_osint_specific_anchors(self) -> None:
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        html = self._render_osint_report("example.com", payload)
        sidebar = re.search(r'<aside class="report-sidebar".*?</aside>', html, re.S)
        self.assertIsNotNone(sidebar)
        sidebar_html = sidebar.group(0)
        for label in (
            "Rapor Kısaca",
            "ReconBot Ne Öğrendi?",
            "Kanıt / Bağlam / Manuel Öneri",
            "Darkweb / Sızıntı / İhlal",
            "Herkese Açık İletişim",
            "Konum İstihbaratı",
            "Herkese Açık Dokümanlar",
            "Organizasyon / Profil Bağlamı",
            "Altyapı Bağlamı",
            "Kaynak Kapsamı",
            "Manuel Arama Önerileri",
            "Gelişmiş Teşhisler",
        ):
            self.assertIn(label, sidebar_html)
        for normal_anchor in (
            "#discovery",
            "#cve-enrichment",
            "#priority-suggestions",
            "#correlation-insights",
            "#attack-graph",
            "#screenshots",
            "#raw",
        ):
            self.assertNotIn(f'href="{normal_anchor}"', sidebar_html)
        self.assertNotIn("OSINT Enrichment", sidebar_html)
        self.assertGreaterEqual(sidebar_html.count('href="#osint-'), 9)
        ids = set(re.findall(r'\bid=["\']([^"\']+)["\']', html))
        sidebar_anchors = set(re.findall(r'href=["\']#([^"\']+)["\']', sidebar_html))
        self.assertFalse(sidebar_anchors - ids)
        self._assert_no_broken_internal_hrefs(html)

    def test_osint_report_leads_with_turkish_summary_legend_coverage_and_darkweb_sections(self) -> None:
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        html = render_osint_section({"osint": payload})
        expected_order = [
            'id="osint-operator-brief">Bu Rapor Kısaca Ne Diyor?',
            'id="osint-intelligence-board">ReconBot Ne Öğrendi?',
            'id="osint-evidence-context-fallback">Kanıt / Bağlam / Manuel Öneri Ayrımı',
            'id="osint-source-health">Kaynak Kapsamı',
            'id="osint-leak-breach-intelligence">Darkweb / Sızıntı / İhlal İstihbaratı',
            'id="osint-email-intelligence">Herkese Açık İletişim Bilgileri',
            'id="osint-location-intelligence">Konum İstihbaratı',
        ]
        offsets = [html.index(marker) for marker in expected_order]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn("Bu Rapor Kısaca Ne Diyor?", html)
        self.assertIn("Herkese açık ihlal/sızıntı referansları", html)
        self.assertIn("Darkweb / sızıntı metadata kaynakları", html)
        self.assertIn("Kanıt", html)
        self.assertIn("Bağlam", html)
        self.assertIn("Manuel Öneri", html)
        self.assertIn("Kapalı", html)
        self.assertIn("Kısmi kaynak kapsamı ReconBot'un her pasif kaynağı tam kontrol edemediği anlamına gelir.", html)
        self.assertIn("Sadece metadata. Tor/onion taraması yok. Kimlik bilgisi veya dump toplanmadı.", html)
        self.assertIn("Tor/onion taraması yok", html)
        self.assertIn("Metadata feed sağlayıcısı kurulu ama kapalı.", html)
        self.assertIn("Açık kaynaklardan herkese açık ihlal/sızıntı metadata referansı gözlemlenmedi.", html)
        self.assertIn("Bu, sızıntı olmadığı anlamına kesin olarak gelmez.", html)
        self.assertIn("kimlik bilgisi, parola, hash, token, private key, session cookie, raw dump veya ham sızıntı kaydı toplamadı", html)

    def test_location_report_shows_evidence_context_fallback_counts_and_zero_exact_explanation(self) -> None:
        payload = build_osint_enrichment(
            target="https://www.7-eleven.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        html = render_osint_section({"osint": payload})
        for label in (
            "Tam hedef konumları",
            "Üst kurum konumları",
            "Bağlı/harici resmî kaynak konumları",
            "Manuel öneri konum aramaları",
            "Reddedilen/noisy konum adayları",
        ):
            self.assertIn(label, html)
        self.assertIn("Tam hedef üzerinde doğrulanmış adres/konum çıkarılamadı.", html)
        self.assertIn("Neden konum bulunamadı?", html)
        self.assertIn("ReconBot yalnızca doğrulanmış resmî kaynaklarda görülen adresleri kanıt sayar.", html)
        self.assertIn("Manuel fallback konum aramaları", html)
        fallback_location = html.split("Manuel fallback konum aramaları", 1)[1]
        self.assertIn("Bu linkler doğrulanmış kanıt değildir. Yerel mağaza veya alakasız işletme döndürebilir.", fallback_location)
        self.assertIn("Risk etkisi", fallback_location)
        self.assertIn(">0<", fallback_location)

    def test_email_intelligence_dependency_missing_is_visible_not_zero_mx(self) -> None:
        self.dns_query_mock.side_effect = lambda name, record_type, timeout: {
            "status": "dependency_missing",
            "records": [],
            "validation_error": "dependency_missing",
        }
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        email = payload["organization_intelligence"]["email_intelligence"]
        self.assertEqual(email["mx_status"], "dependency_missing")
        self.assertEqual(email["mx_records"], [])
        self.assertEqual(email["resolver_method"], "dnspython")
        html = render_osint_section({"osint": payload})
        self.assertIn('id="osint-email-intelligence"', html)
        self.assertIn("Mail Altyapı Özeti", html)
        self.assertIn("Kontrol edilmedi - DNS resolver bağımlılığı yok.", html)
        self.assertNotIn("0 MX records", html)
        self.assertIn("<tr><th>MX record / bastırılan contact</th><td>Kontrol edilmedi / 0</td></tr>", html)
        self.assertIn("Üretilen role e-posta tahmini", html)
        self.assertIn("Üretilen role e-posta tahminleri geçerli inbox değildir", html)
        generated_section = html.split("Üretilen role e-posta tahminlerini göster", 1)[1]
        for column in ("Tür", "Değer / Link", "Nasıl çıkarıldı?", "Güven", "Kapsam", "Target'a uygulanır mı?", "Not"):
            self.assertIn(column, generated_section)
        self.assertIn("<details", generated_section)

    def test_mail_dns_present_uses_dnspython_records_and_dependency_file_declares_runtime(self) -> None:
        email = _mail_infrastructure_intelligence("example.com", 2)
        self.assertEqual(email["mx_status"], "present")
        self.assertEqual(email["spf_status"], "present")
        self.assertEqual(email["dmarc_status"], "present")
        self.assertEqual(email["resolver_method"], "dnspython")
        self.assertTrue(email["mx_records"])
        project_metadata = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
        self.assertRegex(project_metadata, r'"dnspython"')
        self.assertRegex(project_metadata, r'"requests"')
        runtime_requirements = (Path(__file__).resolve().parents[1] / "requirements.txt").read_text(encoding="utf-8")
        self.assertRegex(runtime_requirements, r"(?m)^dnspython$")
        self.assertRegex(runtime_requirements, r"(?m)^requests$")
        electron_package = json.loads((Path(__file__).resolve().parents[1] / "desktop" / "package.json").read_text(encoding="utf-8"))
        self.assertIn("python3 -m venv ../.venv", electron_package["scripts"]["ensure:python-deps"])
        self.assertIn("../.venv/bin/python -m pip install -r ../requirements.txt", electron_package["scripts"]["ensure:python-deps"])
        self.assertEqual(electron_package["scripts"]["predev"], "npm run ensure:python-deps")
        self.assertEqual(electron_package["scripts"]["prebuild"], "npm run ensure:python-deps")

    def test_runtime_dependency_inventory_and_preflight_messages(self) -> None:
        dependency_names = {item.name for item in REQUIRED_RUNTIME_DEPENDENCIES}
        import_names = {item.import_name for item in REQUIRED_RUNTIME_DEPENDENCIES}
        self.assertIn("requests", dependency_names)
        self.assertIn("dnspython", dependency_names)
        self.assertIn("dns.resolver", import_names)

        ok, output = format_runtime_check(import_func=lambda name: object())
        self.assertTrue(ok)
        self.assertIn("requests (requests): OK", output)
        self.assertIn("dnspython (dns.resolver): OK", output)

        def missing_requests(name: str) -> object:
            if name == "requests":
                raise ModuleNotFoundError("No module named 'requests'")
            return object()

        requests_error = runtime_preflight_error(import_func=missing_requests)
        self.assertIn(f"Missing Python dependency: requests. Run: {INSTALL_COMMAND}", requests_error)
        ok, output = format_runtime_check(import_func=missing_requests)
        self.assertFalse(ok)
        self.assertIn("requests (requests): FAIL", output)
        self.assertNotIn("Traceback", output)

        def missing_dns(name: str) -> object:
            if name == "dns.resolver":
                raise ModuleNotFoundError("No module named 'dns'")
            return object()

        dns_error = runtime_preflight_error(import_func=missing_dns)
        self.assertIn(f"Missing Python dependency: dnspython. Run: {INSTALL_COMMAND}", dns_error)
        ok, output = format_runtime_check(import_func=missing_dns)
        self.assertFalse(ok)
        self.assertIn("dnspython (dns.resolver): FAIL", output)
        self.assertNotIn("Traceback", output)

    def test_electron_scan_startup_runs_runtime_preflight_before_child_scan(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "desktop" / "src" / "main" / "reconbotProcess.ts").read_text(encoding="utf-8")
        self.assertIn("runPythonDependencyPreflight", source)
        self.assertIn('"--check-runtime"', source)
        self.assertIn("if (!preflight.ok) return preflight;", source)
        start_body = source[source.index("  async startScan("):source.index("  startIpEnrichment(")]
        self.assertLess(start_body.index("runPythonDependencyPreflight"), start_body.index("this.launchJob"))
        self.assertNotIn("Traceback", source)

    def test_mail_dns_resolver_module_present_absent_timeout_and_error_semantics(self) -> None:
        class FakeMX:
            preference = 10
            exchange = "mail.example.com."

        class FakeTXT:
            def __init__(self, text: str) -> None:
                self.strings = [text.encode("utf-8")]

        class PresentResolver:
            def __init__(self) -> None:
                self.timeout = 0
                self.lifetime = 0

            def resolve(self, name: str, record_type: str) -> list[object]:
                if record_type == "MX":
                    return [FakeMX()]
                if str(name).startswith("_dmarc."):
                    return [FakeTXT("v=DMARC1; p=none")]
                return [FakeTXT("v=spf1 include:_spf.example.net -all")]

        with mock.patch.dict(sys.modules, self._fake_dns_modules(PresentResolver)):
            email = mail_dns.mail_infrastructure_intelligence(
                "example.com",
                2,
                query_func=mail_dns.query_dns_records,
                now_func=lambda: "2026-06-21T00:00:00Z",
            )
            direct = mail_dns.query_dns_records("example.com", "MX", 2)
        self.assertEqual(email["mx_status"], "present")
        self.assertEqual(email["spf_status"], "present")
        self.assertEqual(email["dmarc_status"], "present")
        self.assertNotIn("dependency_missing", str(direct))
        self.assertEqual(email["mx_records"], ["10 mail.example.com"])
        self.assertEqual(email["checked_at"], "2026-06-21T00:00:00Z")

        no_answer = type("NoAnswer", (Exception,), {})

        class AbsentResolver:
            def __init__(self) -> None:
                self.timeout = 0
                self.lifetime = 0

            def resolve(self, name: str, record_type: str) -> list[object]:
                raise no_answer()

        with mock.patch.dict(sys.modules, self._fake_dns_modules(AbsentResolver, NoAnswer=no_answer)):
            absent = mail_dns.mail_infrastructure_intelligence("example.com", 2, query_func=mail_dns.query_dns_records)
        self.assertEqual(absent["mx_status"], "absent")
        self.assertEqual(absent["spf_status"], "absent")
        self.assertEqual(absent["dmarc_status"], "absent")
        self.assertEqual(absent["mx_validation_error"], "no_answer")

        nxdomain = type("NXDOMAIN", (Exception,), {})

        class NxdomainResolver:
            def __init__(self) -> None:
                self.timeout = 0
                self.lifetime = 0

            def resolve(self, name: str, record_type: str) -> list[object]:
                raise nxdomain()

        with mock.patch.dict(sys.modules, self._fake_dns_modules(NxdomainResolver, NXDOMAIN=nxdomain)):
            nxdomain_absent = mail_dns.mail_infrastructure_intelligence("example.com", 2, query_func=mail_dns.query_dns_records)
        self.assertEqual(nxdomain_absent["mx_status"], "absent")
        self.assertEqual(nxdomain_absent["spf_status"], "absent")
        self.assertEqual(nxdomain_absent["dmarc_status"], "absent")
        self.assertEqual(nxdomain_absent["mx_validation_error"], "nxdomain")

        lifetime_timeout = type("LifetimeTimeout", (Exception,), {})

        class TimeoutResolver:
            def __init__(self) -> None:
                self.timeout = 0
                self.lifetime = 0

            def resolve(self, name: str, record_type: str) -> list[object]:
                raise lifetime_timeout()

        with mock.patch.dict(sys.modules, self._fake_dns_modules(TimeoutResolver, LifetimeTimeout=lifetime_timeout)):
            timeout = mail_dns.mail_infrastructure_intelligence("example.com", 2, query_func=mail_dns.query_dns_records)
        self.assertEqual(timeout["mx_status"], "timeout")
        self.assertEqual(timeout["spf_status"], "timeout")
        self.assertEqual(timeout["dmarc_status"], "timeout")

        class ErrorResolver:
            def __init__(self) -> None:
                self.timeout = 0
                self.lifetime = 0

            def resolve(self, name: str, record_type: str) -> list[object]:
                raise RuntimeError("resolver boom")

        with mock.patch.dict(sys.modules, self._fake_dns_modules(ErrorResolver)):
            error = mail_dns.mail_infrastructure_intelligence("example.com", 2, query_func=mail_dns.query_dns_records)
        self.assertEqual(error["mx_status"], "resolver_error")
        self.assertIn("resolver_error: RuntimeError: resolver boom", error["mx_validation_error"])

    def test_mail_dns_resolver_module_dependency_missing_and_no_smtp_usage(self) -> None:
        original_import = builtins.__import__

        def import_blocker(name: str, *args: object, **kwargs: object) -> object:
            if name == "dns.resolver":
                raise ImportError("dns resolver deliberately missing")
            return original_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=import_blocker):
            result = mail_dns.query_dns_records("example.com", "MX", 2)
        self.assertEqual(result["status"], "dependency_missing")
        self.assertEqual(result["records"], [])
        self.assertIn("dependency_missing: ImportError: dns resolver deliberately missing", result["validation_error"])
        self.assertEqual(result["dns_resolver_import_error"], "ImportError: dns resolver deliberately missing")

        for path in (
            Path(mail_dns.__file__),
            Path(importlib.import_module("reconbot.orchestration.osint").__file__ or ""),
        ):
            source_text = path.read_text(encoding="utf-8")
            for forbidden in ("smtplib", "VRFY", "EXPN", "RCPT TO"):
                self.assertNotIn(forbidden, source_text)

    def test_checked_not_found_soft_error_and_duplicate_rows_are_diagnostics_only(self) -> None:
        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://cloudflare.com/" or url.endswith("/security"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Cloudflare",
                    "validation_error": "",
                    "body": "<html><head><title>Cloudflare</title></head><body>Cloudflare security</body></html>",
                }
            if url.endswith("/about"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": "https://www.cloudflare.com/about/",
                    "content_type": "text/html",
                    "title": "Cloudflare About",
                    "validation_error": "",
                    "body": "<html><head><title>Cloudflare About</title></head><body>Cloudflare about</body></html>",
                }
            if url.endswith("/legal"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_redirect",
                    "http_status": 200,
                    "final_url": "https://cloudflare.com/Error/400?aspxerrorpath=/legal",
                    "content_type": "text/html",
                    "title": "Error 400",
                    "validation_error": "",
                    "body": "<html><head><title>Error 400</title></head><body>400 error</body></html>",
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="https://www.cloudflare.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        pages = payload["organization_intelligence"]["official_pages"]
        for status in ("checked_not_found", "checked_soft_error", "checked_duplicate"):
            rows = [item for item in pages if item["url_status"] == status]
            self.assertTrue(rows, status)
            self.assertTrue(all(item["page_found"] is False and item["render_as_clickable"] is False for item in rows))
        valid_rows = [item for item in pages if item["page_found"] and item["url_status"] in {"checked_ok", "checked_redirect_valid"}]
        self.assertTrue(valid_rows)
        self.assertTrue(all(item["render_as_clickable"] for item in valid_rows))
        html = render_osint_section({"osint": payload})
        valid_section = html.split("<h4>Geçerli Kontrol Edilmiş Sayfalar</h4>", 1)[1].split("<h4>Security.txt / Robots / Sitemap</h4>", 1)[0]
        diagnostics_section = html.split("Filtrelenen / Reddedilen / Tekrarlı Path'ler", 1)[1]
        self.assertNotIn("checked_not_found", valid_section)
        self.assertNotIn("checked_soft_error", valid_section)
        self.assertNotIn("checked_duplicate", valid_section)
        self.assertIn("Bulunamadı", diagnostics_section)
        self.assertIn("Soft-error sayfası reddedildi", diagnostics_section)
        self.assertIn("Tekrarlı canonical URL", diagnostics_section)

    def test_source_health_lists_distinct_provider_issues(self) -> None:
        payload = {
            "enabled": True,
            "status": "partial",
            "mode": "safe_mvp",
            "verdict": "source_failures",
            "verdict_reason": "OSINT coverage is partial: crt.sh unavailable, Wayback timed out, and GitHub code search requires authentication. Absence of evidence is not conclusive.",
            "summary": {
                "observed_signals": 0,
                "generated_search_tasks": 1,
                "total_signals": 0,
                "confirmed": 0,
                "unconfirmed": 0,
                "needs_manual_review": 0,
                "suppressed": 0,
                "highest_confidence": "none",
                "risk_score_impact": "none",
            },
            "signals": [],
            "operator_search_tasks": [
                {
                    "source_name": "public_code_search",
                    "status": "suggestion_only",
                    "query": '"example.com"',
                    "link": "https://github.com/search?q=%22example.com%22&type=code",
                    "category": "code_search",
                    "purpose": "Manual fallback",
                    "safety_note": "Suggestion only.",
                    "render_as_clickable": True,
                    "url_status": "manual_only",
                }
            ],
            "sources": [
                {
                    "name": "certificate_transparency",
                    "status": "partial",
                    "provider_results": [{"provider": "crt.sh", "status": "unavailable", "http_status": 502, "user_message": "crt.sh unavailable"}],
                    "errors": ["crt.sh HTTP 502"],
                },
                {"name": "historical_urls", "status": "timeout", "errors": ["Wayback timeout"]},
                {"name": "public_code_search", "status": "auth_required_fallback", "error_class": "auth_required", "user_message": "manual search suggestions generated"},
                {"name": "known_breach_catalog", "status": "completed_no_match"},
                {"name": "safe_search_dorks", "status": "suggestions_generated"},
            ],
            "policy": {"passive_only": True, "risk_score_impact": "none"},
        }
        html = render_osint_section({"osint": payload})
        for source_name in ("crt.sh", "Wayback CDX", "GitHub code search", "HIBP", "safe_search_dorks"):
            self.assertIn(source_name, html)
        self.assertIn("crt.sh: Kaynağa erişilemedi / HTTP 502 / CT kapsamı kısmi", html)
        self.assertIn("Wayback CDX zaman aşımına uğradı; geçmiş URL kapsamı kısmi", html)
        self.assertIn("GitHub code search kimlik doğrulama gerektiriyor; manuel öneri üretildi", html)
        for count_label in (
            "Erişilemeyen sağlayıcı",
            "Zaman aşımı",
            "Kimlik doğrulama gereken kaynak",
            "Eşleşme yok",
            "Üretilen manuel öneri",
        ):
            self.assertIn(count_label, html)
        self.assertIn("OSINT kapsamı kısmi: crt.sh erişilemedi, Wayback zaman aşımına uğradı ve GitHub code search kimlik doğrulama gerektiriyor. Kanıt yokluğu kesin sonuç değildir.", html)
        self.assertNotIn("1 live passive source(s) failed", html)

    def test_source_health_summary_counts_final_rows_and_excludes_manual_dorks_from_attempts(self) -> None:
        health = _source_health_summary(
            [
                {"name": "certificate_transparency", "status": "timeout"},
                {"name": "historical_urls", "status": "timeout"},
                {"name": "public_code_search", "status": "auth_required_fallback"},
                {"name": "known_breach_catalog", "status": "completed_no_match"},
                {"name": "safe_search_dorks", "status": "suggestions_generated"},
            ]
        )
        self.assertEqual(health["timeout_count"], 2)
        self.assertEqual(health["timeout"], 2)
        self.assertEqual(health["auth_required_fallback_count"], 1)
        self.assertEqual(health["no_match_count"], 1)
        self.assertEqual(health["attempted_live_sources"], 4)
        self.assertEqual(health["suggestions_generated_count"], 1)

        mixed_health = _source_health_summary(
            [
                {"name": "certificate_transparency", "status": "unavailable"},
                {"name": "historical_urls", "status": "error"},
                {"name": "public_code_search", "status": "auth_required_fallback"},
                {"name": "safe_search_dorks", "status": "suggestions_generated"},
            ]
        )
        self.assertEqual(mixed_health["provider_unavailable_count"], 1)
        self.assertEqual(mixed_health["provider_unavailable"], 1)
        self.assertEqual(mixed_health["error"], 1)
        self.assertEqual(mixed_health["auth_required_fallback_count"], 1)
        self.assertEqual(mixed_health["attempted_live_sources"], 3)
        self.assertEqual(mixed_health["suggestions_generated_count"], 1)

    def test_source_health_diagnostic_summary_zero_live_sources_is_not_high_confidence(self) -> None:
        summary = source_health_diagnostic_summary(
            [
                {
                    "source": "safe_search_dorks",
                    "status": "suggestions_only",
                    "coverage_impact": "low",
                }
            ]
        )

        self.assertEqual(summary["live_sources_total"], 0)
        self.assertEqual(summary["coverage_confidence"], "low")
        self.assertIn("Canlı ana OSINT kaynağı çalıştırılmadı", summary["coverage_note"])

    def test_target_normalization_url_and_wildcard_to_domain(self) -> None:
        expected = {
            "target_domain": "zekagucu.turkcell.com.tr",
            "target_host": "zekagucu.turkcell.com.tr",
            "target_registered_domain": "turkcell.com.tr",
            "scope_mode": "exact_host",
            "parent_domain_expansion": False,
            "generic_or_reserved_domain": False,
            "organization_aliases": ["zekagucu.turkcell.com.tr", "turkcell.com.tr", "Turkcell"],
        }
        for target in (
            "https://zekagucu.turkcell.com.tr/",
            "http://zekagucu.turkcell.com.tr/path?q=1",
            "zekagucu.turkcell.com.tr",
            "*.zekagucu.turkcell.com.tr",
        ):
            with self.subTest(target=target):
                self.assertEqual(_target_context(target), expected)

    def test_target_alias_generation_includes_7_eleven_brand_forms(self) -> None:
        aliases = _target_context("https://www.7-eleven.com/")["organization_aliases"]
        self.assertEqual(aliases[:4], ["www.7-eleven.com", "7-eleven.com", "7-Eleven", "7 Eleven"])

    def test_example_subdomain_inherits_generic_reserved_domain_classification(self) -> None:
        context = _target_context("https://www.example.com/")
        self.assertEqual(context["target_host"], "www.example.com")
        self.assertEqual(context["target_registered_domain"], "example.com")
        self.assertTrue(context["generic_or_reserved_domain"])

    def test_email_dorks_use_registered_domain_scope(self) -> None:
        cases = [
            ("https://www.microsoft.com", '"@microsoft.com"', "@www.microsoft.com"),
            ("https://www.7-eleven.com", '"@7-eleven.com"', "@www.7-eleven.com"),
            ("https://zekagucu.turkcell.com.tr", '"@turkcell.com.tr"', "@zekagucu.turkcell.com.tr"),
        ]
        settings = {
            "osint": {
                "includeCertificateTransparency": False,
                "includeHistoricalUrls": False,
                "includePublicCodeReferences": False,
                "includeKnownBreachCatalog": False,
                "includeSearchDorkSuggestions": True,
                "timeout": 2,
            }
        }
        for target, expected_query, rejected_fragment in cases:
            with self.subTest(target=target):
                payload = build_osint_enrichment(target=target, enabled=True, tool_settings=settings)
                email_task = next(item for item in payload["operator_search_tasks"] if item["category"] == "emails")
                self.assertEqual(email_task["query"], expected_query)
                self.assertEqual(email_task["query_scope"], "registered_domain")
                self.assertNotIn(rejected_fragment, email_task["query"])

    def test_generated_dorks_do_not_increment_observed_signals(self) -> None:
        settings = {
            "osint": {
                "includeCertificateTransparency": True,
                "includeHistoricalUrls": True,
                "includePublicCodeReferences": False,
                "includeSearchDorkSuggestions": True,
                "maxSignals": 20,
                "timeout": 2,
                "passiveOnly": True,
            }
        }
        with mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=OSError("network blocked")):
            payload = build_osint_enrichment(
                target="https://example.com",
                enabled=True,
                tool_settings=settings,
            )

        self.assertTrue(payload["enabled"])
        self.assertEqual(payload["status"], "partial")
        source_statuses = {item["name"]: item["status"] for item in payload["sources"]}
        self.assertEqual(source_statuses["certificate_transparency"], "error")
        self.assertEqual(source_statuses["historical_urls"], "error")
        self.assertEqual(source_statuses["safe_search_dorks"], "suggestions_generated")
        self.assertFalse(any(item["category"] == "search_dork" for item in payload["signals"]))
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["total_signals"], 0)
        self.assertEqual(payload["summary"]["generated_search_tasks"], 19)
        self.assertEqual(payload["summary"]["needs_manual_review"], 0)
        self.assertEqual(payload["summary"]["highest_confidence"], "none")
        self.assertEqual(len(payload["operator_search_tasks"]), 19)
        self.assertTrue(all(task["status"] == "suggestion_only" for task in payload["operator_search_tasks"]))
        self.assertEqual(payload["summary"]["risk_score_impact"], "none")
        self.assertEqual(payload["verdict"], "source_failures")
        self.assertIn("Manual search tasks are not findings", payload["verdict_reason"])

    def test_github_api_403_falls_back_to_manual_tasks_without_signals(self) -> None:
        error = HTTPError("https://api.github.com/search/code", 403, "Forbidden", {}, None)
        with mock.patch.dict("os.environ", {"GITHUB_TOKEN": "fake-token-value"}), mock.patch("reconbot.orchestration.osint.time.sleep"), mock.patch(
            "reconbot.orchestration.osint._fetch_json",
            side_effect=error,
        ) as fetch:
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": True,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                        "passiveOnly": True,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "public_code_search")
        self.assertEqual(source["status"], "rate_limited_fallback")
        self.assertEqual(source["signal_count"], 0)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(payload["signals"], [])
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["generated_search_tasks"], 5)
        self.assertTrue(all(item["source_name"] == "public_code_search" for item in payload["operator_search_tasks"]))

    def test_github_api_401_auth_required_fallback_is_single_clean_error(self) -> None:
        error = HTTPError("https://api.github.com/search/code", 401, "Unauthorized", {}, None)
        with mock.patch.dict("os.environ", {"GITHUB_TOKEN": "fake-token-value"}), mock.patch("reconbot.orchestration.osint.time.sleep"), mock.patch(
            "reconbot.orchestration.osint._fetch_json",
            side_effect=error,
        ) as fetch:
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": True,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                        "passiveOnly": True,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "public_code_search")
        self.assertEqual(source["status"], "auth_required_fallback")
        self.assertEqual(source["signal_count"], 0)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(len(source["errors"]), 1)
        self.assertIn("auth_required", source["errors"][0])
        self.assertIn("requires authentication", source["notes"])
        self.assertEqual(source["error_class"], "auth_required")
        self.assertIn("manual search suggestions generated", source["user_message"])
        self.assertEqual(payload["signals"], [])
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["generated_search_tasks"], 5)

    def test_github_missing_token_records_auth_required_without_live_api_call(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch(
            "reconbot.orchestration.osint._fetch_json",
            return_value={"total_count": 0, "items": []},
        ) as fetch:
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": True,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                        "passiveOnly": True,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "public_code_search")
        self.assertEqual(source["status"], "auth_required_fallback")
        self.assertEqual(source["requires_api_key"], True)
        self.assertEqual(source["api_key_env"], "GITHUB_TOKEN")
        self.assertEqual(source["api_key_configured"], False)
        self.assertEqual(fetch.call_count, 0)
        diagnostic = next(item for item in payload["diagnostics"]["source_health"] if item["source"] == "public_code_search")
        self.assertEqual(diagnostic["status"], "auth_required")
        self.assertEqual(diagnostic["requires_api_key"], True)
        self.assertEqual(diagnostic["api_key_env"], "GITHUB_TOKEN")
        self.assertEqual(diagnostic["api_key_configured"], False)

    def test_github_token_value_is_never_serialized(self) -> None:
        fake_token = "ghp_FAKE_SECRET_TOKEN_VALUE"
        with mock.patch.dict("os.environ", {"GITHUB_TOKEN": fake_token}), mock.patch(
            "reconbot.orchestration.osint._fetch_json",
            return_value={"total_count": 0, "items": []},
        ):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": True,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                        "passiveOnly": True,
                    }
                },
            )
        html = render_osint_section({"osint": payload})
        serialized = json.dumps(payload, ensure_ascii=False)
        logs = "\n".join(str(event.get("message") or "") for event in payload.get("events", []))
        self.assertNotIn(fake_token, serialized)
        self.assertNotIn(fake_token, html)
        self.assertNotIn(fake_token, logs)
        diagnostic = next(item for item in payload["diagnostics"]["source_health"] if item["source"] == "public_code_search")
        self.assertEqual(diagnostic["api_key_env"], "GITHUB_TOKEN")
        self.assertEqual(diagnostic["api_key_configured"], True)

    def test_github_api_200_zero_items_is_completed_zero(self) -> None:
        with mock.patch.dict("os.environ", {"GITHUB_TOKEN": "fake-token-value"}), mock.patch("reconbot.orchestration.osint._fetch_json", return_value={"total_count": 0, "items": []}):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": True,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                        "passiveOnly": True,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "public_code_search")
        self.assertEqual(source["status"], "completed")
        self.assertEqual(source["signal_count"], 0)
        self.assertEqual(source["raw_count"], 0)
        self.assertIn("No exact public code results found", source["notes"])
        self.assertEqual(payload["signals"], [])
        self.assertEqual(payload["summary"]["observed_signals"], 0)

    def test_github_api_items_create_metadata_only_signals(self) -> None:
        item = {
            "name": "application.yml",
            "path": "config/application.yml",
            "html_url": "https://github.com/acme/repo/blob/main/config/application.yml",
            "score": 12.5,
            "repository": {"full_name": "acme/repo", "html_url": "https://github.com/acme/repo"},
        }
        with mock.patch.dict("os.environ", {"GITHUB_TOKEN": "fake-token-value"}), mock.patch("reconbot.orchestration.osint._fetch_json", return_value={"total_count": 1, "items": [item]}):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": True,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                        "passiveOnly": True,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "public_code_search")
        self.assertEqual(source["status"], "completed")
        self.assertEqual(source["signal_count"], 1)
        self.assertEqual(payload["summary"]["observed_signals"], 1)
        signal = payload["signals"][0]
        self.assertEqual(signal["category"], "public_code_reference")
        self.assertIn("Metadata-only GitHub result", signal["evidence"]["snippet"])
        self.assertEqual(signal["risk_score_impact"], 0)

    def test_generated_github_search_urls_do_not_create_signals_when_live_fails(self) -> None:
        with mock.patch.dict("os.environ", {"GITHUB_TOKEN": "fake-token-value"}), mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=OSError("network blocked")):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": True,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                        "passiveOnly": True,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "public_code_search")
        self.assertEqual(source["status"], "error")
        self.assertEqual(source["signal_count"], 0)
        self.assertEqual(payload["signals"], [])
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["generated_search_tasks"], 5)

    def test_public_code_source_not_executed_when_disabled(self) -> None:
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeSearchDorkSuggestions": False,
                    "maxSignals": 20,
                    "timeout": 2,
                    "passiveOnly": True,
                }
            },
        )
        self.assertFalse(any(item["name"] == "public_code_search" for item in payload["sources"]))
        self.assertEqual(payload["signals"], [])
        self.assertEqual(payload["operator_search_tasks"], [])

    def test_mocked_hibp_7_eleven_page_creates_known_breach_reference_signal(self) -> None:
        fixture_html = """
        <html>
          <head><title>7-Eleven Data Breach</title></head>
          <body>
            <h1>7-Eleven Data Breach</h1>
            <dl>
              <dt>Breach date</dt><dd>2024-08-08</dd>
              <dt>Added date</dt><dd>2024-09-01</dd>
              <dt>Pwned accounts</dt><dd>164,000</dd>
              <dt>Compromised data</dt><dd>Email addresses, Names, Phone numbers</dd>
            </dl>
          </body>
        </html>
        """
        with mock.patch(
            "reconbot.orchestration.osint._fetch_text_response",
            return_value={"text": fixture_html, "status": 200, "final_url": "https://haveibeenpwned.com/Breach/7-Eleven"},
        ) as fetch_text, mock.patch(
            "reconbot.orchestration.osint._fetch_json",
            return_value=[],
        ):
            payload = build_osint_enrichment(
                target="https://www.7-eleven.com/",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": True,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                        "passiveOnly": True,
                    }
                },
            )

        self.assertEqual(fetch_text.call_count, 1)
        self.assertEqual(payload["normalization"]["organization_aliases"][:4], ["www.7-eleven.com", "7-eleven.com", "7-Eleven", "7 Eleven"])
        source = next(item for item in payload["sources"] if item["name"] == "known_breach_catalog")
        self.assertEqual(source["status"], "completed_matched")
        self.assertEqual(source["signal_count"], 1)
        self.assertEqual(source["endpoint_url"], "https://haveibeenpwned.com/api/v3/breaches")
        self.assertEqual(source["report_url"], "https://haveibeenpwned.com/Breach/7-Eleven")
        self.assertEqual(source["report_url_status"], "validated")
        self.assertEqual(payload["summary"]["observed_signals"], 1)
        signal = payload["signals"][0]
        self.assertEqual(signal["category"], "known_breach_reference")
        self.assertEqual(signal["title"], "Public breach catalog reference")
        self.assertEqual(signal["status"], "needs_manual_review")
        self.assertEqual(signal["source_name"], "known_breach_catalog")
        self.assertEqual(signal["source_provider"], "haveibeenpwned")
        self.assertEqual(signal["risk_score_impact"], 0)
        self.assertEqual(signal["breach_name"], "7-Eleven Data Breach")
        self.assertEqual(signal["breach_date"], "2024-08-08")
        self.assertEqual(signal["added_date"], "2024-09-01")
        self.assertEqual(signal["affected_accounts"], 164000)
        self.assertEqual(signal["compromised_data_classes"], ["Email addresses", "Names", "Phone numbers"])
        self.assertEqual(signal["matched_alias"], "7-Eleven")
        self.assertEqual(signal["match_type"], "brand_alias")
        self.assertEqual(signal["url_role"], "observed_evidence_link")
        self.assertTrue(signal["browser_safe"])
        self.assertTrue(signal["render_as_clickable"])
        self.assertIn("Public breach catalog reference only.", signal["validation_notes"])
        self.assertIn("No credential material was collected.", signal["validation_notes"])
        self.assertEqual(signal["matched_entities"]["emails"], [])
        self.assertNotIn("credential", json.dumps(signal.get("matched_entities", {})).lower())
        leak = payload["leak_intelligence"]
        self.assertTrue(leak["enabled"])
        self.assertEqual(leak["status"], "completed")
        self.assertTrue(leak["live_collection_performed"])
        self.assertEqual(leak["summary"]["observed_references"], 1)
        self.assertFalse(leak["summary"]["credential_material_collected"])
        self.assertFalse(leak["summary"]["raw_secret_collected"])
        self.assertEqual(leak["summary"]["risk_score_impact"], "none")
        leak_result = leak["results"][0]
        self.assertEqual(leak_result["source_name"], "known_breach_catalog")
        self.assertEqual(leak_result["source_type"], "public_breach_catalog")
        self.assertEqual(leak_result["risk_score_impact"], 0)
        leak_reference = leak_result["observed_references"][0]
        self.assertEqual(leak_reference["title"], "7-Eleven Data Breach")
        self.assertEqual(leak_reference["reference_url"], "https://haveibeenpwned.com/Breach/7-Eleven")
        self.assertTrue(leak_reference["browser_safe"])
        self.assertTrue(leak_reference["render_as_clickable"])
        self.assertEqual(leak_reference["scope_origin"], "external_verified_source")
        self.assertEqual(leak_reference["applies_to_target"], "unknown")
        self.assertEqual(leak_reference["observed_on_host"], "haveibeenpwned.com")
        self.assertEqual(leak_reference["observed_on_registered_domain"], "haveibeenpwned.com")
        self.assertFalse(leak_reference["applies_to_parent_org"])
        self.assertEqual(leak_reference["risk_score_impact"], 0)
        self.assertFalse(leak_reference["credential_material_collected"])
        self.assertFalse(leak_reference["raw_secret_collected"])
        self.assertEqual(leak_reference["recommended_action"], "Manually validate organization relevance; do not collect credentials.")

        html = render_osint_section({"osint": payload})
        self.assertIn("Darkweb / Sızıntı / İhlal İstihbaratı", html)
        self.assertIn("Toplanan kimlik bilgisi", html)
        self.assertIn("Toplanan dump", html)
        leak_status_cards = html.split('id="osint-leak-breach-intelligence"', 1)[1].split("<h4>Gözlemlenen dış referanslar", 1)[0]
        self.assertNotIn("Raw credential collection", leak_status_cards)
        self.assertNotIn("Raw dump collection", leak_status_cards)
        self.assertIn("kimlik bilgisi, parola, hash, token, private key, session cookie, raw dump veya ham sızıntı kaydı toplamadı", html)
        self.assertIn("7-Eleven Data Breach", html)
        primary_signals_html = html.split("<h3>Gözlemlenen OSINT Kanıtları</h3>", 1)[1].split("<h3>Gelişmiş / Eski Uyumluluk Teşhisleri</h3>", 1)[0]
        self.assertNotIn("known_breach_reference", primary_signals_html)
        self.assertNotIn("Public breach catalog reference found: 7-Eleven Data Breach", primary_signals_html)
        self.assertIn("Gelişmiş / Eski Uyumluluk Teşhisleri", html)
        self.assertIn("Sadece compatibility görünümü.", html)
        coverage_html = html.split("<h3>Teşhisler</h3>", 1)[0]
        source_rows = re.findall(r"<td><code>known_breach_catalog</code></td>.*?</tr>", coverage_html, re.S)
        source_row_html = next((row for row in source_rows if "Kanıt raporunu aç" in row), "")
        self.assertTrue(source_row_html)
        self.assertIn('href="https://haveibeenpwned.com/Breach/7-Eleven"', source_row_html)
        self.assertIn("Kanıt raporunu aç", source_row_html)
        self.assertIn('href="#osint-source-known-breach-catalog"', source_row_html)
        self.assertIn("Sağlayıcı teşhislerini görüntüle", source_row_html)
        self.assertNotIn("View details", source_row_html)
        self.assertIn('href="https://haveibeenpwned.com/Breach/7-Eleven"', html)
        self.assertNotIn('href="https://haveibeenpwned.com/Breaches"', html)
        self.assertNotIn("https://haveibeenpwned.com/Breaches", html)
        self.assertIn("https://haveibeenpwned.com/api/v3/breaches", html)
        self.assertNotIn('href="https://haveibeenpwned.com/api/v3/breaches"', html)
        provider_details = html.split('id="osint-source-known-breach-catalog"', 1)[1].split("</div>", 1)[0]
        self.assertIn("Doğrulanmış herkese açık ihlal raporu", provider_details)
        self.assertIn('href="https://haveibeenpwned.com/Breach/7-Eleven"', provider_details)
        self.assertIn("Üçüncü taraf herkese açık ihlal kataloğu referansı; aktif zafiyet kanıtı değildir.", provider_details)
        self.assertIn("Endpoint: <code>https://haveibeenpwned.com/api/v3/breaches</code>", provider_details)
        self.assertNotIn('href="https://haveibeenpwned.com/api/v3/breaches"', provider_details)

    def test_osint_only_7_eleven_report_keeps_hibp_link_and_registered_email_dork(self) -> None:
        fixture_html = """
        <html>
          <head><title>7-Eleven Data Breach</title></head>
          <body>
            <h1>7-Eleven Data Breach</h1>
            <dl>
              <dt>Breach date</dt><dd>2024-08-08</dd>
              <dt>Added date</dt><dd>2024-09-01</dd>
              <dt>Pwned accounts</dt><dd>164,000</dd>
              <dt>Compromised data</dt><dd>Email addresses, Names, Phone numbers</dd>
            </dl>
          </body>
        </html>
        """
        with mock.patch(
            "reconbot.orchestration.osint._fetch_text_response",
            return_value={"text": fixture_html, "status": 200, "final_url": "https://haveibeenpwned.com/Breach/7-Eleven"},
        ), mock.patch("reconbot.orchestration.osint._fetch_json", return_value=[]):
            payload = build_osint_enrichment(
                target="https://www.7-eleven.com/",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": True,
                        "includeSearchDorkSuggestions": True,
                        "maxSignals": 20,
                        "timeout": 2,
                    }
                },
            )

        email_task = next(item for item in payload["operator_search_tasks"] if item["category"] == "emails")
        self.assertEqual(email_task["query"], '"@7-eleven.com"')
        self.assertEqual(email_task["query_scope"], "registered_domain")
        self.assertNotIn("@www.7-eleven.com", email_task["query"])
        self.assertEqual(payload["summary"]["observed_signals"], 1)

        html = self._render_osint_report("https://www.7-eleven.com/", payload, log_target="https://www.7-eleven.com/")
        self._assert_no_broken_internal_hrefs(html)
        self.assertIn('href="https://haveibeenpwned.com/Breach/7-Eleven"', html)
        self.assertIn("Herkese açık ihlal kataloğunda 7-Eleven Data Breach için metadata referansı görüldü", html)
        fallback_html = html.split('id="osint-manual-search-suggestions"', 1)[1]
        self.assertIn("Google e-posta pattern aramasını aç", fallback_html)
        self.assertIn("%407-eleven.com", fallback_html)
        self.assertNotIn("%40www.7-eleven.com", fallback_html)
        self.assertIn("Normal scan sections hidden for OSINT-only run", html)
        self.assertNotIn('id="discovery"', html)
        self.assertNotIn('id="auth"', html)

    def test_hibp_catalog_rejects_000webhost_for_turkcell_domain(self) -> None:
        catalog = [
            {
                "Name": "000webhost",
                "Title": "000webhost",
                "Domain": "000webhost.com",
                "BreachDate": "2015-03-01",
                "AddedDate": "2015-10-26T23:35:45Z",
                "PwnCount": 13545468,
                "DataClasses": ["Email addresses", "IP addresses", "Names", "Passwords"],
            }
        ]

        def fake_json(url: str, *_args: object, **_kwargs: object) -> object:
            if url.endswith("/api/v3/breaches"):
                return catalog
            raise HTTPError(url, 404, "Not Found", {}, None)

        with mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=fake_json), mock.patch(
            "reconbot.orchestration.osint._fetch_text_response",
            side_effect=lambda url, *_args, **_kwargs: (_ for _ in ()).throw(HTTPError(url, 404, "Not Found", {}, None)),
        ):
            payload = build_osint_enrichment(
                target="https://zekagucu.turkcell.com.tr",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": True,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                        "passiveOnly": True,
                    }
                },
            )

        source = next(item for item in payload["sources"] if item["name"] == "known_breach_catalog")
        self.assertEqual(source["status"], "completed_no_match")
        self.assertEqual(source["signal_count"], 0)
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertFalse(any(item["category"] == "known_breach_reference" for item in payload["signals"]))
        self.assertEqual(payload["leak_intelligence"]["status"], "no_match")
        self.assertEqual(payload["leak_intelligence"]["summary"]["observed_references"], 0)
        self.assertEqual(payload["leak_intelligence"]["results"][0]["observed_references"], [])
        debug = source["candidate_match_debug"]
        self.assertTrue(any(item["breach_name"] == "000webhost" and item["reject_reason"] == "domain_mismatch" for item in debug))
        html = render_osint_section({"osint": payload})
        self.assertIn("Açık kaynaklardan herkese açık ihlal/sızıntı metadata referansı gözlemlenmedi.", html)
        self.assertIn("Kanıt yokluğu kesin sonuç değildir.", html)
        self.assertNotIn('href="https://haveibeenpwned.com/Breach/000webhost"', html)
        self.assertNotIn("Public breach catalog reference found: 000webhost", html)

    def test_hibp_404_7_eleven_page_does_not_create_known_breach_signal(self) -> None:
        not_found_html = """
        <html>
          <head><title>Have I Been Pwned: 404</title></head>
          <body>
            <h1>Page not found</h1>
            <section>Recommended Actions</section>
            <p>Sponsored</p>
            <p>Use a password manager</p>
            <p>Services Information Connect With Us</p>
          </body>
        </html>
        """

        def fake_json(url: str, *_args: object, **_kwargs: object) -> object:
            if url.endswith("/api/v3/breaches"):
                return []
            raise HTTPError(url, 404, "Not Found", {}, None)

        with mock.patch(
            "reconbot.orchestration.osint._fetch_text_response",
            return_value={"text": not_found_html, "status": 404, "final_url": "https://haveibeenpwned.com/404"},
        ), mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=fake_json):
            payload = build_osint_enrichment(
                target="https://www.7-eleven.com/",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": True,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                        "passiveOnly": True,
                    }
                },
            )

        source = next(item for item in payload["sources"] if item["name"] == "known_breach_catalog")
        self.assertEqual(source["status"], "completed_no_match")
        self.assertEqual(source["signal_count"], 0)
        self.assertEqual(source["outcome"], "alias_not_found")
        self.assertEqual(source["match_status"], "no_match")
        self.assertEqual(source["endpoint_url"], "https://haveibeenpwned.com/api/v3/breaches")
        self.assertEqual(source["endpoint_url_status"], "validated")
        self.assertEqual(source["report_url"], "")
        self.assertEqual(source["report_url_status"], "unavailable")
        diagnostic = next(item for item in payload["diagnostics"]["source_health"] if item["source"] == "known_breach_catalog")
        self.assertEqual(diagnostic["status"], "completed_no_match")
        self.assertEqual(diagnostic["url_status"], "validated")
        self.assertNotEqual(diagnostic["url_status"], "not_found")
        self.assertTrue(source["alias_attempts"])
        self.assertEqual(source["alias_attempts"][0]["page_status"], "not_found")
        self.assertFalse(any(item["category"] == "known_breach_reference" for item in payload["signals"]))
        self.assertNotEqual(payload["verdict"], "observed_evidence")
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["needs_manual_review"], 0)
        self.assertEqual(payload["summary"]["highest_confidence"], "none")
        self.assertEqual(payload["leak_intelligence"]["status"], "no_match")
        self.assertEqual(payload["leak_intelligence"]["summary"]["observed_references"], 0)
        self.assertEqual(payload["leak_intelligence"]["results"][0]["status"], "no_match")
        self.assertEqual(payload["leak_intelligence"]["results"][0]["observed_references"], [])
        self.assertTrue(all(task["status"] == "suggestion_only" for task in payload["operator_search_tasks"]))
        self.assertNotIn("Recommended Actions", json.dumps(payload["signals"]))
        self.assertNotIn("Use a password manager", json.dumps(payload["signals"]))

        html = render_osint_section({"osint": payload})
        observed_html = html.split("<h3>Gelişmiş / Eski Uyumluluk Teşhisleri</h3>", 1)[0]
        self.assertNotIn("https://haveibeenpwned.com/Breach/7-Eleven", observed_html)
        self.assertNotIn('href="https://haveibeenpwned.com/Breaches"', html)
        self.assertNotIn("https://haveibeenpwned.com/Breaches", html)
        self.assertNotIn('href="https://haveibeenpwned.com/api/v3/breaches"', html)
        self.assertIn("Üretilen alias değerleriyle güvenilir herkese açık ihlal kataloğu referansı eşleşmedi.", html)

    def test_cloudflare_known_breach_no_match_does_not_create_leak_finding(self) -> None:
        def not_found_json(url: str, *_args: object, **_kwargs: object) -> object:
            if url.endswith("/api/v3/breaches"):
                return []
            raise HTTPError(url, 404, "Not Found", {}, None)

        with mock.patch(
            "reconbot.orchestration.osint._fetch_text_response",
            side_effect=lambda url, *_args, **_kwargs: (_ for _ in ()).throw(HTTPError(url, 404, "Not Found", {}, None)),
        ), mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=not_found_json):
            payload = build_osint_enrichment(
                target="https://www.cloudflare.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": True,
                        "includeSearchDorkSuggestions": False,
                        "includeInfrastructureIntelligence": False,
                        "includeOrganizationIntelligence": False,
                        "maxSignals": 20,
                        "timeout": 2,
                        "passiveOnly": True,
                    }
                },
            )
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["leak_intelligence"]["status"], "no_match")
        self.assertEqual(payload["leak_intelligence"]["summary"]["observed_references"], 0)
        self.assertEqual(payload["leak_intelligence"]["results"][0]["observed_references"], [])
        self.assertFalse(any(item["category"] == "known_breach_reference" for item in payload["signals"]))
        html = render_osint_section({"osint": payload})
        self.assertIn("Darkweb / Sızıntı / İhlal İstihbaratı", html)
        self.assertIn("Açık kaynaklardan herkese açık ihlal/sızıntı metadata referansı gözlemlenmedi.", html)
        self.assertIn("Kanıt yokluğu kesin sonuç değildir.", html)
        self.assertNotIn("Public breach catalog reference found", html)

    def test_random_clean_domain_creates_no_known_breach_reference(self) -> None:
        def not_found_json(url: str, *_args: object, **_kwargs: object) -> object:
            if url.endswith("/api/v3/breaches"):
                return []
            raise HTTPError(url, 404, "Not Found", {}, None)

        with mock.patch(
            "reconbot.orchestration.osint._fetch_text_response",
            side_effect=lambda url, *_args, **_kwargs: (_ for _ in ()).throw(HTTPError(url, 404, "Not Found", {}, None)),
        ), mock.patch(
            "reconbot.orchestration.osint._fetch_json",
            side_effect=not_found_json,
        ):
            payload = build_osint_enrichment(
                target="clean-example.biz",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": True,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                        "passiveOnly": True,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "known_breach_catalog")
        self.assertEqual(source["status"], "completed_no_match")
        self.assertEqual(source["outcome"], "alias_not_found")
        self.assertEqual(source["errors"], [])
        self.assertEqual(source["report_url"], "")
        self.assertEqual(source["report_url_status"], "unavailable")
        self.assertEqual(source["endpoint_url_status"], "validated")
        diagnostic = next(item for item in payload["diagnostics"]["source_health"] if item["source"] == "known_breach_catalog")
        self.assertEqual(diagnostic["url_status"], "validated")
        self.assertNotEqual(diagnostic["url_status"], "not_found")
        self.assertTrue(source["alias_attempts"])
        self.assertIn("No reliable public breach catalog reference matched generated aliases.", source["notes"])
        self.assertEqual(source["signal_count"], 0)
        self.assertFalse(any(item["category"] == "known_breach_reference" for item in payload["signals"]))
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["leak_intelligence"]["status"], "no_match")
        self.assertEqual(payload["leak_intelligence"]["summary"]["observed_references"], 0)
        self.assertEqual(payload["leak_intelligence"]["results"][0]["observed_references"], [])
        self.assertEqual(payload["verdict"], "organization_context_only")
        self.assertTrue(payload["verdict_reason"])

    def test_ct_parser_deduplicates_subdomains(self) -> None:
        records = [
            {"name_value": "*.api.example.com\napi.example.com\nwww.example.com"},
            {"common_name": "api.example.com"},
            {"name_value": "outside.test\nEXAMPLE.com"},
        ]
        self.assertEqual(
            _extract_ct_subdomains(records, "example.com"),
            ["example.com", "api.example.com", "www.example.com"],
        )

    def test_ct_http_502_failure_records_error_and_no_signals(self) -> None:
        def fake_fetch(url: str, timeout: int) -> list[dict[str, object]]:
            if "crt.sh" in url:
                raise HTTPError(url, 502, "Bad Gateway", {}, None)
            return [{"dns_names": ["example.com"]}]

        with mock.patch("reconbot.orchestration.osint.time.sleep"), mock.patch(
            "reconbot.orchestration.osint._fetch_json",
            side_effect=fake_fetch,
        ):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": True,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "certificate_transparency")
        self.assertEqual(source["status"], "partial")
        self.assertEqual(source["signal_count"], 0)
        self.assertIn("HTTPError 502", " ".join(source["errors"]))
        provider = next(item for item in source["provider_results"] if item["provider"] == "crtsh")
        self.assertEqual(provider["status"], "unavailable")
        self.assertEqual(provider["error_class"], "http_502")
        self.assertIn("CT coverage is partial", provider["user_message"])
        diagnostic = next(item for item in payload["diagnostics"]["source_health"] if item["source"] == "certificate_transparency")
        self.assertEqual(diagnostic["status"], "provider_unavailable")
        self.assertEqual(diagnostic["error_class"], "http_502")
        self.assertIn("CT coverage is partial", diagnostic["user_message"])
        self.assertEqual(payload["source_health"]["partial"], 1)
        self.assertEqual(payload["source_health"]["provider_unavailable"], 1)
        self.assertEqual(payload["summary"]["observed_signals"], 0)

    def test_ct_200_empty_json_is_completed_zero_records(self) -> None:
        with mock.patch("reconbot.orchestration.osint._fetch_json", return_value=[]):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": True,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "certificate_transparency")
        self.assertEqual(source["status"], "completed")
        self.assertEqual(source["raw_count"], 0)
        self.assertEqual(source["signal_count"], 0)
        self.assertIn("No CT records returned", source["notes"])
        self.assertEqual(payload["summary"]["observed_signals"], 0)

    def test_ct_success_creates_asset_discovery_candidates_not_observed_signals(self) -> None:
        records = [
            {"name_value": "*.api.example.com\napi.example.com\noutside.test\nEXAMPLE.com."},
            {"common_name": "cdn.example.com"},
        ]
        with mock.patch("reconbot.orchestration.osint._fetch_json", return_value=records):
            payload = build_osint_enrichment(
                target="https://example.com/path",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": True,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "certificate_transparency")
        self.assertEqual(source["status"], "completed")
        subdomains = sorted(
            candidate["matched_entities"]["subdomains"][0]
            for candidate in payload["asset_discovery_candidates"]
        )
        self.assertEqual(subdomains, ["api.example.com", "cdn.example.com"])
        self.assertEqual(payload["signals"], [])
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["asset_discovery_candidates"], 2)
        self.assertEqual(payload["summary"]["asset_identity_observations"], 1)
        self.assertEqual(payload["asset_identity_observations"][0]["matched_entities"]["subdomains"], ["example.com"])
        self.assertEqual(payload["verdict"], "asset_discovery_only")

    def test_example_ct_root_and_www_are_asset_identity_not_observed_signals(self) -> None:
        records = [{"name_value": "example.com\nwww.example.com"}]
        with mock.patch("reconbot.orchestration.osint._fetch_json", return_value=records):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": True,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                    }
                },
            )
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["total_signals"], 0)
        self.assertEqual(payload["summary"]["asset_identity_observations"], 2)
        self.assertEqual(payload["signals"], [])
        observed_assets = sorted(item["matched_entities"]["subdomains"][0] for item in payload["asset_identity_observations"])
        self.assertEqual(observed_assets, ["example.com", "www.example.com"])

    def test_badssl_ct_root_is_asset_identity_and_subdomain_is_asset_discovery(self) -> None:
        records = [{"dns_names": ["badssl.com", "revoked.badssl.com"]}]
        with mock.patch("reconbot.orchestration.osint._fetch_json", return_value=records):
            payload = build_osint_enrichment(
                target="badssl.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": True,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                    }
                },
            )
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["asset_identity_observations"], 1)
        self.assertEqual(payload["summary"]["asset_discovery_candidates"], 1)
        self.assertEqual(payload["signals"], [])
        self.assertEqual(payload["asset_discovery_candidates"][0]["matched_entities"]["subdomains"], ["revoked.badssl.com"])
        self.assertEqual(payload["asset_discovery_candidates"][0]["ct_classification"], "subdomain_candidate")
        self.assertEqual(payload["asset_identity_observations"][0]["matched_entities"]["subdomains"], ["badssl.com"])

    def test_ct_provider_attribution_uses_successful_provider_for_asset_discovery(self) -> None:
        def fake_fetch(url: str, timeout: int) -> list[dict[str, object]]:
            if "crt.sh" in url:
                raise TimeoutError("crtsh slow")
            return [{"dns_names": ["badssl.com", "revoked.badssl.com"]}]

        with mock.patch("reconbot.orchestration.osint.time.sleep"), mock.patch(
            "reconbot.orchestration.osint._fetch_json",
            side_effect=fake_fetch,
        ):
            payload = build_osint_enrichment(
                target="badssl.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": True,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "certificate_transparency")
        self.assertEqual(source["status"], "partial")
        provider_status = {item["provider"]: item["status"] for item in source["provider_results"]}
        self.assertEqual(provider_status["crtsh"], "timeout")
        self.assertEqual(provider_status["certspotter"], "completed")
        self.assertEqual(payload["signals"], [])
        self.assertEqual(payload["asset_discovery_candidates"][0]["source_provider"], "certspotter")
        self.assertIn("api.certspotter.com", payload["asset_discovery_candidates"][0]["source_url"])

    def test_cloudflare_style_ct_candidates_do_not_create_observed_evidence(self) -> None:
        records = [
            {
                "dns_names": [
                    "www.cloudflare.com",
                    "api.www.cloudflare.com",
                    "dash.www.cloudflare.com",
                    "support.www.cloudflare.com",
                ]
            }
        ]

        def fake_fetch(url: str, timeout: int) -> list[dict[str, object]]:
            if "crt.sh" in url:
                return []
            return records

        with mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=fake_fetch):
            payload = build_osint_enrichment(
                target="https://www.cloudflare.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": True,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": True,
                        "maxSignals": 20,
                        "timeout": 2,
                    }
                },
            )
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertGreater(payload["summary"]["asset_discovery_candidates"], 0)
        self.assertEqual(payload["summary"]["asset_identity_observations"], 1)
        self.assertNotEqual(payload["verdict"], "observed_evidence")
        self.assertIn(payload["verdict"], {"asset_discovery_only", "source_failures"})
        self.assertEqual(payload["signals"], [])
        candidate = payload["asset_discovery_candidates"][0]
        self.assertNotEqual(candidate["url_role"], "observed_evidence_link")
        self.assertIn(candidate["url_role"], {"machine_endpoint", "passive_source_reference"})
        self.assertFalse(candidate["render_as_clickable"])
        self.assertIn("api.certspotter.com", candidate["provider_reference"])

        html = self._render_osint_report("https://www.cloudflare.com", payload, log_target="https://www.cloudflare.com")
        self._assert_no_broken_internal_hrefs(html)
        self.assertIn("Certificate Transparency Varlık Keşfi", html)
        self.assertIn("https://api.certspotter.com/v1/issuances?domain=www.cloudflare.com", html)
        self.assertNotIn('href="https://api.certspotter.com/v1/issuances?domain=www.cloudflare.com', html)
        self.assertIn("API kaynağı; browser kanıt linki değil", html)

    def test_source_coverage_certificate_transparency_actions_are_internal_or_browser_safe(self) -> None:
        with mock.patch("reconbot.orchestration.osint._fetch_json", return_value=[]), mock.patch(
            "reconbot.orchestration.osint._resolve_dns_records",
            return_value={"resolved_ips": [], "ipv6_addresses": [], "cname_chain": [], "dns_status": "no_records", "resolver_error": ""},
        ):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": True,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "certificate_transparency")
        self.assertEqual(source["detail_id"], "osint-source-certificate-transparency")
        self.assertTrue(any(link["label"] == "Open crt.sh browser search" and link["browser_safe"] for link in source["browser_lookup_links"]))

        html = render_osint_section({"osint": payload})
        self._assert_no_broken_internal_hrefs(html)
        self._assert_external_osint_links_are_browser_safe(html)
        source_rows = re.findall(r"<td><code>certificate_transparency</code></td>.*?</tr>", html, re.S)
        source_row_html = next((row for row in source_rows if "Sağlayıcı teşhislerini görüntüle" in row), "")
        self.assertTrue(source_row_html)
        self.assertIn('href="#osint-source-certificate-transparency"', source_row_html)
        self.assertIn("Sağlayıcı teşhislerini görüntüle", source_row_html)
        self.assertNotIn("View details", source_row_html)
        self.assertNotIn("Open crt.sh browser search", source_row_html)
        self.assertIn("crt.sh tarayıcı aramasını aç", html)
        self.assertNotIn('href="https://crt.sh/?q=example.com&amp;output=json"', html)
        self.assertIn('id="osint-source-certificate-transparency"', html)

    def test_source_coverage_historical_urls_uses_wayback_browser_lookup_not_cdx_link(self) -> None:
        with mock.patch("reconbot.orchestration.osint._fetch_json", return_value=[]), mock.patch(
            "reconbot.orchestration.osint._resolve_dns_records",
            return_value={"resolved_ips": [], "ipv6_addresses": [], "cname_chain": [], "dns_status": "no_records", "resolver_error": ""},
        ):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                scan_profile="fast",
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": True,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "historical_urls")
        self.assertTrue(any("web.archive.org/web/*/example.com/*" in link["url"] and link["browser_safe"] for link in source["browser_lookup_links"]))

        html = render_osint_section({"osint": payload})
        self._assert_no_broken_internal_hrefs(html)
        self._assert_external_osint_links_are_browser_safe(html)
        self.assertIn('href="#osint-source-historical-urls"', html)
        self.assertIn('id="osint-source-historical-urls"', html)
        self.assertIn("Wayback tarayıcı aramasını aç", html)
        self.assertIn("https://web.archive.org/cdx", html)
        self.assertNotIn('href="https://web.archive.org/cdx', html)

    def test_source_coverage_public_code_search_uses_github_web_suggestions_not_api_link(self) -> None:
        error = HTTPError("https://api.github.com/search/code", 401, "Unauthorized", {}, None)
        with mock.patch("reconbot.orchestration.osint.time.sleep"), mock.patch(
            "reconbot.orchestration.osint._fetch_json",
            side_effect=error,
        ), mock.patch(
            "reconbot.orchestration.osint._resolve_dns_records",
            return_value={"resolved_ips": [], "ipv6_addresses": [], "cname_chain": [], "dns_status": "no_records", "resolver_error": ""},
        ):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": True,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "public_code_search")
        self.assertEqual(source["status"], "auth_required_fallback")

        html = render_osint_section({"osint": payload})
        self._assert_no_broken_internal_hrefs(html)
        self._assert_external_osint_links_are_browser_safe(html)
        self.assertIn("auth_required_fallback", html)
        source_rows = re.findall(r"<td><code>public_code_search</code></td>.*?</tr>", html, re.S)
        source_row_html = next((row for row in source_rows if "Manuel önerileri görüntüle" in row), "")
        self.assertTrue(source_row_html)
        self.assertIn("Manuel önerileri görüntüle", source_row_html)
        self.assertIn("Sağlayıcı teşhislerini görüntüle", source_row_html)
        self.assertIn("GitHub manuel arama önerilerini görüntüle", html)
        self.assertIn("GitHub .env aramasını aç", html)
        self.assertNotIn('href="https://api.github.com/search/code"', html)
        self.assertIn('id="osint-source-public-code-search"', html)

    def test_source_coverage_known_breach_api_plaintext_and_validated_detail_clickable_only_on_evidence(self) -> None:
        catalog = []
        with mock.patch("reconbot.orchestration.osint._fetch_json", return_value=catalog), mock.patch(
            "reconbot.orchestration.osint._fetch_text_response",
            side_effect=lambda url, *_args, **_kwargs: (_ for _ in ()).throw(HTTPError(url, 404, "Not Found", {}, None)),
        ), mock.patch(
            "reconbot.orchestration.osint._resolve_dns_records",
            return_value={"resolved_ips": [], "ipv6_addresses": [], "cname_chain": [], "dns_status": "no_records", "resolver_error": ""},
        ):
            no_match = build_osint_enrichment(
                target="clean-example.biz",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": True,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        no_match_html = render_osint_section({"osint": no_match})
        self.assertIn('href="#osint-source-known-breach-catalog"', no_match_html)
        self.assertIn("Katalog kontrol edildi; üretilen alias değerleriyle güvenilir herkese açık ihlal kataloğu referansı eşleşmedi.", no_match_html)
        self.assertIn("https://haveibeenpwned.com/api/v3/breaches", no_match_html)
        self.assertNotIn('href="https://haveibeenpwned.com/api/v3/breaches"', no_match_html)
        self.assertNotIn('href="https://haveibeenpwned.com/Breach/Clean-Example"', no_match_html)
        no_match_rows = re.findall(r"<td><code>known_breach_catalog</code></td>.*?</tr>", no_match_html, re.S)
        no_match_row_html = next((row for row in no_match_rows if "Sağlayıcı teşhislerini görüntüle" in row), "")
        self.assertTrue(no_match_row_html)
        self.assertIn("Sağlayıcı teşhislerini görüntüle", no_match_row_html)
        self.assertNotIn("Open evidence report", no_match_row_html)

        fixture_html = """
        <html><body><h1>7-Eleven Data Breach</h1><dl>
        <dt>Breach date</dt><dd>2024-08-08</dd>
        <dt>Added date</dt><dd>2024-09-01</dd>
        <dt>Pwned accounts</dt><dd>164,000</dd>
        <dt>Compromised data</dt><dd>Email addresses, Names</dd>
        </dl></body></html>
        """
        with mock.patch(
            "reconbot.orchestration.osint._fetch_text_response",
            return_value={"text": fixture_html, "status": 200, "final_url": "https://haveibeenpwned.com/Breach/7-Eleven"},
        ), mock.patch("reconbot.orchestration.osint._fetch_json", return_value=[]), mock.patch(
            "reconbot.orchestration.osint._resolve_dns_records",
            return_value={"resolved_ips": [], "ipv6_addresses": [], "cname_chain": [], "dns_status": "no_records", "resolver_error": ""},
        ):
            matched = build_osint_enrichment(
                target="https://www.7-eleven.com/",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": True,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        matched_html = render_osint_section({"osint": matched})
        matched_rows = re.findall(r"<td><code>known_breach_catalog</code></td>.*?</tr>", matched_html, re.S)
        matched_row_html = next((row for row in matched_rows if "Kanıt raporunu aç" in row), "")
        self.assertTrue(matched_row_html)
        self.assertIn("Kanıt raporunu aç", matched_row_html)
        self.assertIn("Sağlayıcı teşhislerini görüntüle", matched_row_html)
        self.assertIn('href="https://haveibeenpwned.com/Breach/7-Eleven"', matched_html)
        self.assertIn("Doğrulanmış herkese açık ihlal raporu", matched_html)
        self.assertIn('data-browser-safe="true"', matched_html)
        self.assertNotIn('href="https://haveibeenpwned.com/api/v3/breaches"', matched_html)

    def test_source_coverage_safe_search_dorks_suggestions_generated_and_manual_links_clickable(self) -> None:
        with mock.patch(
            "reconbot.orchestration.osint._resolve_dns_records",
            return_value={"resolved_ips": [], "ipv6_addresses": [], "cname_chain": [], "dns_status": "no_records", "resolver_error": ""},
        ):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": True,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "safe_search_dorks")
        self.assertEqual(source["status"], "suggestions_generated")
        diagnostic = next(item for item in payload["diagnostics"]["source_health"] if item["source"] == "safe_search_dorks")
        self.assertEqual(diagnostic["status"], "suggestions_only")

        html = render_osint_section({"osint": payload})
        self._assert_no_broken_internal_hrefs(html)
        self._assert_external_osint_links_are_browser_safe(html)
        self.assertIn("suggestions_generated", html)
        self.assertIn('href="#osint-source-safe-search-dorks"', html)
        self.assertIn("Manuel önerileri görüntüle", html)
        self.assertIn("Google Swagger aramasını aç", html)
        self.assertIn("Üretilen suggestion_only görev; dış arama toplanmadı veya doğrulanmadı.", html)
        self.assertIn("Endpoint: <code>manual</code>", html)
        self.assertNotIn('href="manual"', html)

    def test_osint_report_link_audit_internal_and_external_hrefs(self) -> None:
        with mock.patch("reconbot.orchestration.osint._fetch_json", return_value=[]), mock.patch(
            "reconbot.orchestration.osint._resolve_dns_records",
            return_value={"resolved_ips": ["104.16.1.1"], "ipv6_addresses": [], "cname_chain": [], "dns_status": "resolved", "resolver_error": ""},
        ), mock.patch("reconbot.orchestration.osint._reverse_dns_lookup", return_value=""):
            payload = build_osint_enrichment(
                target="https://www.cloudflare.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": True,
                        "includeHistoricalUrls": True,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": True,
                        "timeout": 2,
                    }
                },
            )
        html = render_osint_section({"osint": payload})
        self._assert_no_broken_internal_hrefs(html)
        self._assert_external_osint_links_are_browser_safe(html)

    def test_electron_embedded_report_opens_safe_external_links_only(self) -> None:
        main_ts = (Path(__file__).resolve().parents[1] / "desktop/src/main/main.ts").read_text(encoding="utf-8")
        self.assertIn("setWindowOpenHandler", main_ts)
        self.assertIn("will-navigate", main_ts)
        self.assertIn("will-frame-navigate", main_ts)
        self.assertIn("shell.openExternal(rawUrl)", main_ts)
        self.assertIn('protocolName === "http:" || protocolName === "https:" || protocolName === "mailto:"', main_ts)
        self.assertIn('rawUrl.startsWith("#")', main_ts)
        self.assertIn("event.isSameDocument", main_ts)
        self.assertIn("isInternalReportNavigation(event.url)", main_ts)
        self.assertIn("event.preventDefault()", main_ts)
        self.assertNotIn('protocolName === "file:"', main_ts)

    def test_organization_intelligence_payload_exists_without_observed_evidence(self) -> None:
        with mock.patch(
            "reconbot.orchestration.osint._resolve_dns_records",
            return_value={"resolved_ips": [], "ipv6_addresses": [], "cname_chain": [], "dns_status": "no_records", "resolver_error": ""},
        ):
            payload = build_osint_enrichment(
                target="https://www.7-eleven.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "includeInfrastructureIntelligence": False,
                        "includeOrganizationIntelligence": True,
                        "timeout": 2,
                    }
                },
            )
        org = payload["organization_intelligence"]
        self.assertIn("summary", org)
        for key in (
            "official_pages_checked",
            "official_pages_found",
            "official_pages_not_found",
            "official_pages_soft_error",
            "official_pages_unexpected_content",
            "official_pages_duplicates",
            "official_pages_forbidden",
            "security_txt_checked",
            "security_txt_found",
            "robots_found",
            "sitemap_found",
            "auto_checked_urls",
            "manual_only_urls",
            "api_required_urls",
            "generated_candidate_urls",
            "role_contact_candidates",
            "generated_contact_guesses",
            "observed_public_contacts",
            "mx_records_count",
            "suppressed_contacts_count",
            "organization_lookup_tasks",
            "public_document_search_tasks",
            "location_hints",
        ):
            self.assertIn(key, payload["summary"])
            self.assertIn(key, org["summary"])
        self.assertIn("historical_url_candidates", payload["summary"])
        self.assertIn("live_validated_historical_urls", payload["summary"])
        self.assertGreater(payload["summary"]["official_pages_checked"], 0)
        self.assertGreater(payload["summary"]["auto_checked_urls"], 0)
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["total_signals"], 0)
        self.assertEqual(payload["signals"], [])
        self.assertEqual(payload["verdict"], "organization_context_only")

    def test_cloudflare_organization_validation_checks_official_and_special_urls(self) -> None:
        security_txt = "Contact: mailto:security@cloudflare.com\nPolicy: https://www.cloudflare.com/disclosure/"

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            status = "checked_ok"
            http_status = 200
            content_type = "text/html"
            title = "Cloudflare"
            body = "<html><head><title>Cloudflare</title></head><body>Cloudflare offices</body></html>"
            final_url = url
            if url.endswith("/.well-known/security.txt") and url.startswith("https://cloudflare.com/"):
                content_type = "text/plain"
                title = ""
                body = security_txt
            elif url.endswith("/robots.txt"):
                content_type = "text/plain"
                title = ""
                body = "User-agent: *"
            elif url.endswith("/sitemap.xml"):
                status = "checked_redirect"
                final_url = url.replace("https://cloudflare.com", "https://www.cloudflare.com")
                content_type = "application/xml"
                title = ""
                body = "<urlset />"
            elif url.endswith("/about"):
                final_url = "https://www.cloudflare.com/about/"
            elif not (url == "https://cloudflare.com/" or url.endswith("/about") or url.endswith("/contact") or url.endswith("/security")):
                return self._default_osint_url_validation(url, **kwargs)
            return {
                "check_policy": "auto_check_allowed",
                "validation_method": str(kwargs.get("validation_method") or "head_get"),
                "check_status": "checked",
                "url_status": status,
                "http_status": http_status,
                "final_url": final_url,
                "content_type": content_type,
                "title": title,
                "validation_error": "",
                "body": body,
            }

        self.osint_validate_mock.side_effect = validate_url
        with mock.patch(
            "reconbot.orchestration.osint._resolve_dns_records",
            return_value={"resolved_ips": [], "ipv6_addresses": [], "cname_chain": [], "dns_status": "no_records", "resolver_error": ""},
        ):
            payload = build_osint_enrichment(
                target="https://www.cloudflare.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "includeInfrastructureIntelligence": False,
                        "includeOrganizationIntelligence": True,
                        "timeout": 2,
                    }
                },
            )
        org = payload["organization_intelligence"]
        self.assertGreater(payload["summary"]["official_pages_checked"], 0)
        self.assertGreater(payload["summary"]["official_pages_found"], 0)
        self.assertGreaterEqual(payload["summary"]["security_txt_checked"], 2)
        self.assertEqual(payload["summary"]["security_txt_found"], 1)
        self.assertGreaterEqual(payload["summary"]["robots_found"], 1)
        self.assertGreaterEqual(payload["summary"]["sitemap_found"], 1)
        self.assertTrue(any(item["page_type"] == "homepage" and item["check_status"] == "checked" for item in org["official_pages"]))
        self.assertTrue(any(item["page_type"] == "robots" and item["check_status"] == "checked" for item in org["official_pages"]))
        self.assertTrue(any(item["page_type"] == "sitemap" and item["url_status"] == "checked_redirect_valid" for item in org["official_pages"]))
        about_rows = [item for item in org["official_pages"] if item["page_type"] == "about"]
        about_found = [item for item in about_rows if item["page_found"]]
        about_duplicates = [item for item in about_rows if item["url_status"] == "checked_duplicate"]
        self.assertEqual(len(about_found), 1)
        self.assertEqual(len(about_duplicates), 1)
        self.assertEqual(about_duplicates[0]["suppressed_reason"], "duplicate_final_url")
        self.assertFalse(about_duplicates[0]["render_as_clickable"])
        self.assertGreaterEqual(payload["summary"]["official_pages_duplicates"], 1)
        generated = [item for item in org["role_contacts"] if item["source"] == "generated_candidate"]
        observed = [item for item in org["role_contacts"] if item["observed"]]
        self.assertTrue(generated)
        self.assertTrue(all(item["status"] == "generated_guess" for item in generated))
        self.assertTrue(all(item["url_status"] == "generated_candidate" for item in generated))
        self.assertTrue(all(item["verification_level"] == "not_observed_not_verified" for item in generated))
        self.assertEqual([item["contact_endpoint"] for item in observed], ["security@cloudflare.com"])
        self.assertTrue(all(item["contact_type"] == "email" for item in observed))
        self.assertTrue(all(item["status"] == "observed_public_contact" for item in observed))
        self.assertTrue(all(item["verification_level"] == "observed_on_public_source" for item in observed))
        self.assertTrue(all(item["account_validated"] is False for item in observed))
        self.assertEqual(payload["summary"]["observed_public_contacts"], 1)
        self.assertEqual(payload["summary"]["generated_contact_guesses"], len(generated))
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        html = render_osint_section({"osint": payload})
        self.assertIn("Geçerli Kontrol Edilmiş Sayfalar", html)
        self.assertIn("Security.txt / Robots / Sitemap", html)
        self.assertIn("Başarıyla kontrol edildi", html)
        self.assertIn("Başarıyla kontrol edildi", html)
        valid_section = html.split("<h4>Geçerli Kontrol Edilmiş Sayfalar</h4>", 1)[1].split("<h4>Security.txt / Robots / Sitemap</h4>", 1)[0]
        diagnostics_section = html.split("Filtrelenen / Reddedilen / Tekrarlı Path'ler", 1)[1]
        self.assertEqual(valid_section.count("https://www.cloudflare.com/about/"), 1)
        self.assertIn("duplicate_final_url", diagnostics_section)
        self.assertIn("Bunlar doğrulanmış inbox değildir", html)
        self.assertNotIn("url_status\">not_checked", html)
        self._assert_no_broken_internal_hrefs(html)
        self._assert_external_osint_links_are_browser_safe(html)

    def test_organization_security_txt_found_parses_public_contacts_without_validation(self) -> None:
        security_txt = "\n".join(
            [
                "Contact: mailto:security@example.com",
                "Contact: https://example.com/security-report-form",
                "Policy: https://example.com/security-policy",
                "Preferred-Languages: en, tr",
                "Expires: 2027-01-01T00:00:00Z",
            ]
        )

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://example.com/.well-known/security.txt":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "get_only"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/plain",
                    "title": "",
                    "validation_error": "",
                    "body": security_txt,
                }
            if url == "https://example.com/":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Example Home",
                    "validation_error": "",
                    "body": "<html><head><title>Example Home</title></head><body>Headquarters 123 Example Street</body></html>",
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        with mock.patch(
            "reconbot.orchestration.osint._resolve_dns_records",
            return_value={"resolved_ips": [], "ipv6_addresses": [], "cname_chain": [], "dns_status": "no_records", "resolver_error": ""},
        ):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "includeInfrastructureIntelligence": False,
                        "includeOrganizationIntelligence": True,
                        "checkOrganizationPages": True,
                        "timeout": 2,
                    }
                },
            )
        org = payload["organization_intelligence"]
        self.assertEqual(org["security_txt"]["status"], "found")
        self.assertEqual(org["security_txt"]["url_status"], "checked_ok")
        self.assertEqual(org["security_txt"]["fields"]["Contact"], ["mailto:security@example.com", "https://example.com/security-report-form"])
        self.assertEqual(org["security_txt"]["fields"]["Policy"], ["https://example.com/security-policy"])
        observed = [item for item in org["role_contacts"] if item["observed"]]
        self.assertEqual([item["contact_endpoint"] for item in observed], ["security@example.com", "https://example.com/security-report-form"])
        self.assertEqual([item["contact_type"] for item in observed], ["email", "contact_form"])
        self.assertTrue(all("email" not in item for item in observed))
        self.assertEqual(observed[0]["status"], "observed_public_contact")
        self.assertEqual(observed[0]["validation"], "not_verified_no_account_validation")
        self.assertEqual(payload["summary"]["observed_public_contacts"], 2)
        self.assertEqual(payload["summary"]["security_txt_checked"], 2)
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        html = render_osint_section({"osint": payload})
        board = html.split('id="osint-intelligence-board"', 1)[1].split('<h3 id="osint-overview"', 1)[0]
        self.assertIn("ReconBot Ne Öğrendi?", board)
        self.assertIn("Herkese açık iletişim bilgileri", board)
        self.assertIn("2", board)
        contact_section = html.split('id="osint-email-intelligence"', 1)[1].split('id="osint-location-intelligence"', 1)[0]
        self.assertIn("security@example.com", contact_section)
        self.assertIn("https://example.com/security-report-form", contact_section)
        self.assertIn("account_validated=false", contact_section)
        self.assertIn("Organizasyon İstihbaratı", html)
        self.assertIn("Security.txt", html)
        self.assertIn("security@example.com", html)
        self.assertIn("ReconBot inbox doğrulamaz", html)
        self._assert_no_broken_internal_hrefs(html)
        self._assert_external_osint_links_are_browser_safe(html)

    def test_scope_provenance_classifies_target_parent_affiliate_and_manual_rows(self) -> None:
        exact_page = """
        <html><body>
          <a href="mailto:security@app.example.com">Security</a>
        </body></html>
        """
        parent_page = """
        <html><body>
          <a href="tel:+15551234567">Phone</a>
          <a href="mailto:privacy@example-affiliate.test">Affiliate privacy</a>
        </body></html>
        """

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://app.example.com/contact":
                body = exact_page
            elif url == "https://example.com/contact":
                body = parent_page
            else:
                return self._default_osint_url_validation(url, **kwargs)
            return {
                "check_policy": "auto_check_allowed",
                "validation_method": str(kwargs.get("validation_method") or "head_get"),
                "check_status": "checked",
                "url_status": "checked_ok",
                "http_status": 200,
                "final_url": url,
                "content_type": "text/html",
                "title": "Contact",
                "validation_error": "",
                "body": body,
            }

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="app.example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "checkOrganizationPages": True,
                    "timeout": 2,
                }
            },
        )
        org = payload["organization_intelligence"]
        contacts = org["contact_intelligence"]
        exact = next(item for item in contacts["observed_email_addresses"] if item["contact_endpoint"] == "security@app.example.com")
        parent = contacts["observed_phone_numbers"][0]
        affiliate = next(item for item in contacts["observed_email_addresses"] if item["contact_endpoint"] == "privacy@example-affiliate.test")
        generated = org["email_intelligence"]["generated_role_contact_guesses"][0]

        self.assertEqual(exact["scope_origin"], "exact_target_host")
        self.assertEqual(exact["observed_on_host"], "app.example.com")
        self.assertIs(exact["applies_to_target"], True)
        self.assertEqual(parent["scope_origin"], "parent_organization")
        self.assertEqual(parent["observed_on_registered_domain"], "example.com")
        self.assertIs(parent["applies_to_target"], False)
        self.assertIs(parent["applies_to_parent_org"], True)
        self.assertEqual(affiliate["scope_origin"], "official_affiliate_domain")
        self.assertEqual(affiliate["domain_relationship"], "official_affiliate_domain")
        self.assertEqual(generated["scope_origin"], "manual_fallback")
        self.assertIs(generated["applies_to_target"], False)

        summary = org["summary"]
        self.assertEqual(summary["target_observed_public_contacts"], 1)
        self.assertEqual(summary["parent_org_observed_public_contacts"], 1)
        self.assertEqual(summary["affiliate_observed_public_contacts"], 1)
        self.assertTrue(
            any(
                item["scope_origin"] == "exact_target_host"
                for item in org["official_pages"]
                if item["url"] == "https://app.example.com/contact"
            )
        )

    def test_zekagucu_parent_turkcell_contacts_and_locations_are_not_exact_target_findings(self) -> None:
        parent_contact = """
        <html><head><script type="application/ld+json">
        {"@context":"https://schema.org","@type":"Organization","name":"Turkcell","address":{"@type":"PostalAddress","streetAddress":"Aydinevler Mahallesi Inonu Caddesi No 20","addressLocality":"Istanbul","addressCountry":"TR"}}
        </script></head><body>
          <a href="tel:+905321234567">Call</a>
          <a href="tel:+905327654321">Support</a>
        </body></html>
        """

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://turkcell.com.tr/contact" or url == "https://turkcell.com.tr/":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Turkcell",
                    "validation_error": "",
                    "body": parent_contact,
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="https://zekagucu.turkcell.com.tr",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "checkOrganizationPages": True,
                    "timeout": 2,
                }
            },
        )
        org = payload["organization_intelligence"]
        summary = org["summary"]
        self.assertEqual(summary["target_observed_public_contacts"], 0)
        self.assertEqual(summary["parent_org_observed_public_contacts"], 2)
        self.assertEqual(summary["target_observed_phone_numbers"], 0)
        self.assertEqual(summary["parent_org_observed_phone_numbers"], 2)
        self.assertEqual(summary["target_observed_locations"], 0)
        self.assertEqual(summary["parent_org_observed_locations"], 1)
        self.assertEqual(payload["summary"]["target_observed_public_contacts"], 0)
        self.assertEqual(payload["summary"]["parent_org_observed_public_contacts"], 2)
        self.assertTrue(
            all(
                item["scope_origin"] == "parent_organization" and item["applies_to_target"] is False
                for item in org["contact_intelligence"]["observed_phone_numbers"]
            )
        )
        self.assertTrue(
            all(
                item["scope_origin"] == "parent_organization" and item["applies_to_target"] is False
                for item in org["location_intelligence"]["observed_locations"]
            )
        )
        html = render_osint_section({"osint": payload})
        self.assertIn("Tam hedef host üzerinde herkese açık iletişim endpoint'i gözlemlenmedi.", html)
        self.assertIn("Üst kurum bağlamı", html)
        self.assertIn("Üst kurum konumları", html)
        contact_target = html.split("<h4>Tam hedef iletişim bilgileri</h4>", 1)[1].split("<h4>Üst kurum iletişim bilgileri</h4>", 1)[0]
        self.assertNotIn("+905321234567", contact_target)
        self.assertNotIn("+905327654321", contact_target)
        contact_parent = html.split("<h4>Üst kurum iletişim bilgileri</h4>", 1)[1].split("<h4>Bağlı/harici resmî iletişim bilgileri</h4>", 1)[0]
        self.assertIn("+905321234567", contact_parent)
        self.assertIn("+905327654321", contact_parent)

    def test_zekagucu_soft_error_pages_do_not_count_as_found_official_pages(self) -> None:
        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url.endswith("/legal"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_redirect",
                    "http_status": 200,
                    "final_url": "https://zekagucu.turkcell.com.tr/Error/400?aspxerrorpath=/legal",
                    "content_type": "text/html; charset=utf-8",
                    "title": "Hata - ZEKAGUCU",
                    "validation_error": "",
                    "body": "<html><head><title>Hata - ZEKAGUCU</title></head><body>400 Hata \x00\x01\x02\x03\x04\x05 address: 101 Garbage St. Istanbul 34000</body></html>",
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="https://zekagucu.turkcell.com.tr",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        legal = next(item for item in payload["organization_intelligence"]["official_pages"] if item["url"].endswith("/legal"))
        self.assertFalse(legal["page_found"])
        self.assertEqual(legal["url_status"], "checked_soft_error")
        self.assertEqual(legal["status"], "checked_soft_error")
        self.assertTrue({"soft_error_final_url", "soft_error_title"} & set(legal["rejection_reason"]))
        self.assertEqual(payload["summary"]["official_pages_found"], 0)
        self.assertGreaterEqual(payload["summary"]["official_pages_soft_error"], 1)
        contact_intel = payload["organization_intelligence"]["contact_intelligence"]
        self.assertEqual(contact_intel["observed_email_addresses"], [])
        self.assertEqual(contact_intel["observed_phone_numbers"], [])
        self.assertEqual(contact_intel["observed_contact_urls"], [])
        self.assertEqual(contact_intel["observed_contact_forms"], [])
        documents = payload["organization_intelligence"]["public_document_intelligence"]
        self.assertEqual(documents["validated_public_documents"], [])
        locations = payload["organization_intelligence"]["location_intelligence"]["observed_locations"]
        self.assertEqual(locations, [])
        rejected_locations = payload["organization_intelligence"]["location_intelligence"]["rejected_location_candidates"]
        self.assertFalse(any("Garbage" in str(item.get("text") or "") for item in rejected_locations))
        html = render_osint_section({"osint": payload})
        board = html.split('id="osint-intelligence-board"', 1)[1].split('<h3 id="osint-overview"', 1)[0]
        self.assertIn("ReconBot Ne Öğrendi?", board)
        self.assertIn("Bulunmadı", board)
        self.assertIn("Doğrulanmış konum çıkarılamadı", board)
        self.assertNotIn("İhlal raporunu aç", board)
        self.assertNotIn("Garbage", board)
        self.assertNotIn("linkedin.com", board)
        valid_section = html.split("<h4>Geçerli Kontrol Edilmiş Sayfalar</h4>", 1)[1].split("<h4>Security.txt / Robots / Sitemap</h4>", 1)[0]
        diagnostics_section = html.split("Filtrelenen / Reddedilen / Tekrarlı Path'ler", 1)[1]
        self.assertNotIn("/legal", valid_section)
        self.assertNotIn("official public page exists", valid_section)
        self.assertIn("/Error/400?aspxerrorpath=/legal", diagnostics_section)
        self.assertIn("Soft-error sayfası reddedildi", diagnostics_section)
        location_section = html.split('<h3 id="osint-location-intelligence">Konum İstihbaratı</h3>', 1)[1].split("<h4>Harici Konum Adayları</h4>", 1)[0]
        self.assertNotIn("Garbage", location_section)

    def test_body_keyword_alone_does_not_soft_error_valid_homepage(self) -> None:
        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://example.com/":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Example Corporate",
                    "validation_error": "",
                    "body": "<html><head><title>Example Corporate</title></head><body>Our legal policy explains how to report an error in billing records.</body></html>",
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        homepage = next(item for item in payload["organization_intelligence"]["official_pages"] if item["url"] == "https://example.com/")
        self.assertTrue(homepage["page_found"])
        self.assertEqual(homepage["url_status"], "checked_ok")
        self.assertNotEqual(homepage["status"], "checked_soft_error")

    def test_valid_corporate_affiliate_redirect_is_not_soft_error(self) -> None:
        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url.endswith("/about"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_redirect",
                    "http_status": 200,
                    "final_url": "https://corp.7-eleven.com/about-us",
                    "content_type": "text/html",
                    "title": "7-Eleven Corporate About",
                    "validation_error": "",
                    "body": "<html><head><title>7-Eleven Corporate About</title></head><body>Corporate headquarters and company information.</body></html>",
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="https://www.7-eleven.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        about = next(item for item in payload["organization_intelligence"]["official_pages"] if item["url"].endswith("/about"))
        self.assertTrue(about["page_found"])
        self.assertEqual(about["url_status"], "checked_redirect_valid")
        self.assertNotEqual(about["status"], "checked_soft_error")

    def test_valid_off_domain_affiliate_redirect_gets_explicit_status(self) -> None:
        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url.endswith("/legal"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_redirect",
                    "http_status": 200,
                    "final_url": "https://example-affiliate.org/legal",
                    "content_type": "text/html",
                    "title": "Example Affiliate Legal",
                    "validation_error": "",
                    "body": "<html><head><title>Example Affiliate Legal</title></head><body>Legal notices for the affiliate.</body></html>",
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        legal = next(item for item in payload["organization_intelligence"]["official_pages"] if item["url"].endswith("/legal"))
        self.assertTrue(legal["page_found"])
        self.assertEqual(legal["url_status"], "checked_official_affiliate_redirect")
        self.assertNotEqual(legal["status"], "checked_soft_error")

    def test_organization_404_rows_render_only_in_filtered_diagnostics(self) -> None:
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        html = render_osint_section({"osint": payload})
        valid_section = html.split("<h4>Geçerli Kontrol Edilmiş Sayfalar</h4>", 1)[1].split("<h4>Security.txt / Robots / Sitemap</h4>", 1)[0]
        diagnostics_section = html.split("Filtrelenen / Reddedilen / Tekrarlı Path'ler", 1)[1]
        self.assertNotIn("https://example.com/about", valid_section)
        self.assertIn("https://example.com/about", diagnostics_section)
        self.assertIn("Bulunamadı", diagnostics_section)

    def test_organization_security_txt_not_found_keeps_role_contacts_as_candidates(self) -> None:
        with mock.patch(
            "reconbot.orchestration.osint._resolve_dns_records",
            return_value={"resolved_ips": [], "ipv6_addresses": [], "cname_chain": [], "dns_status": "no_records", "resolver_error": ""},
        ):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "includeInfrastructureIntelligence": False,
                        "includeOrganizationIntelligence": True,
                        "checkOrganizationPages": True,
                        "timeout": 2,
                    }
                },
            )
        org = payload["organization_intelligence"]
        self.assertEqual(org["security_txt"]["status"], "checked_not_found")
        self.assertEqual(org["security_txt"]["url_status"], "checked_not_found")
        self.assertFalse(org["security_txt"]["found"])
        self.assertFalse(any(item["observed"] for item in org["role_contacts"]))
        self.assertTrue(all(item["status"] == "generated_guess" for item in org["role_contacts"]))
        self.assertTrue(all(item["url_status"] == "generated_candidate" for item in org["role_contacts"]))
        self.assertTrue(all(item["verification_level"] == "not_observed_not_verified" for item in org["role_contacts"]))
        self.assertTrue(all(item["account_validated"] is False for item in org["role_contacts"]))
        self.assertEqual(payload["summary"]["observed_signals"], 0)

    def test_email_intelligence_passive_mx_spf_dmarc_records(self) -> None:
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        email = payload["organization_intelligence"]["email_intelligence"]
        self.assertEqual(email["mx_status"], "present")
        self.assertEqual(email["spf_status"], "present")
        self.assertEqual(email["dmarc_status"], "present")
        self.assertEqual(email["dkim_status"], "not_checked")
        self.assertTrue(email["mx_records"])
        self.assertTrue(email["spf_records"])
        self.assertTrue(email["dmarc_records"])
        self.assertEqual(email["resolver_method"], "dnspython")
        self.assertGreater(email["email_summary"]["mx_records_count"], 0)
        queried_types = [call.args[1] for call in self.dns_query_mock.call_args_list]
        self.assertIn("MX", queried_types)
        self.assertIn("TXT", queried_types)
        self.assertNotIn("SMTP", queried_types)
        html = render_osint_section({"osint": payload})
        self.assertIn("Mail altyapısı tekil inbox varlığını kanıtlamaz", html)
        self.assertIn("10 mail.example.com", html)
        self.assertIn("v=spf1 include:_spf.example.net -all", html)
        self.assertIn("v=DMARC1; p=none", html)

    def test_no_mx_suppresses_generated_role_guesses(self) -> None:
        def no_mx(name: str, record_type: str, timeout: int) -> dict[str, object]:
            if str(record_type).upper() == "MX":
                return {"status": "absent", "records": [], "validation_error": "no_answer"}
            return {"status": "absent", "records": [], "validation_error": "no_answer"}

        self.dns_query_mock.side_effect = no_mx
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        email = payload["organization_intelligence"]["email_intelligence"]
        self.assertEqual(email["mx_status"], "absent")
        self.assertEqual(email["generated_role_contact_guesses"], [])
        self.assertGreater(email["email_summary"]["suppressed_contacts_count"], 0)
        self.assertFalse(any(item.get("source") == "generated_candidate" for item in payload["organization_intelligence"]["role_contacts"]))
        html = render_osint_section({"osint": payload})
        self.assertIn("Yok", html)
        generated_section = html.split("Üretilen role e-posta tahminlerini göster", 1)[1].split("<h4>Bastırılan Contact'lar</h4>", 1)[0]
        self.assertNotIn("security@example.com", generated_section)
        self.assertIn("suppressed_no_mx", html)

    def test_mail_dns_resolver_errors_are_explicit_not_generic_error(self) -> None:
        def resolver_error(name: str, record_type: str, timeout: int) -> dict[str, object]:
            return {"status": "resolver_error", "records": [], "validation_error": f"resolver_error: {record_type} boom"}

        self.dns_query_mock.side_effect = resolver_error
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        email = payload["organization_intelligence"]["email_intelligence"]
        self.assertEqual(email["mx_status"], "resolver_error")
        self.assertEqual(email["spf_status"], "resolver_error")
        self.assertEqual(email["dmarc_status"], "resolver_error")
        self.assertIn("resolver_error:", email["mx_validation_error"])
        self.assertNotIn("error", {email["mx_status"], email["spf_status"], email["dmarc_status"]})
        html = render_osint_section({"osint": payload})
        self.assertIn("Resolver hatası", html)

    def test_mail_dns_timeouts_are_explicit_not_absent(self) -> None:
        def timeout_dns(name: str, record_type: str, timeout: int) -> dict[str, object]:
            return {"status": "timeout", "records": [], "validation_error": "timeout"}

        self.dns_query_mock.side_effect = timeout_dns
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        email = payload["organization_intelligence"]["email_intelligence"]
        self.assertEqual(email["mx_status"], "timeout")
        self.assertEqual(email["spf_status"], "timeout")
        self.assertEqual(email["dmarc_status"], "timeout")
        self.assertEqual(email["mx_records"], [])
        html = render_osint_section({"osint": payload})
        self.assertIn("Zaman aşımı", html)
        self.assertNotIn("0 MX records", html)

    def test_mail_dns_dependency_missing_is_reported_without_mailbox_validation(self) -> None:
        self.dns_query_mock.return_value = {"status": "dependency_missing", "records": [], "validation_error": "dependency_missing"}
        self.dns_query_mock.side_effect = None
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        email = payload["organization_intelligence"]["email_intelligence"]
        self.assertEqual(email["mx_status"], "dependency_missing")
        self.assertEqual(email["spf_status"], "dependency_missing")
        self.assertEqual(email["dmarc_status"], "dependency_missing")
        html = render_osint_section({"osint": payload})
        self.assertIn("Kontrol edilmedi - DNS resolver bağımlılığı yok.", html)
        self.assertIn("<th>MX status</th><td>Kontrol edilmedi - DNS resolver bağımlılığı yok.</td>", html)
        self.assertNotIn("0 MX records", html)
        queried_types = [call.args[1] for call in self.dns_query_mock.call_args_list]
        self.assertNotIn("SMTP", queried_types)

    def test_organization_role_contacts_use_registered_domain_and_are_not_findings(self) -> None:
        settings = {
            "osint": {
                "includeCertificateTransparency": False,
                "includeHistoricalUrls": False,
                "includePublicCodeReferences": False,
                "includeKnownBreachCatalog": False,
                "includeSearchDorkSuggestions": False,
                "includeInfrastructureIntelligence": False,
                "includeOrganizationIntelligence": True,
                "timeout": 2,
            }
        }
        for target, expected in (
            ("https://www.7-eleven.com", "security@7-eleven.com"),
            ("https://zekagucu.turkcell.com.tr", "security@turkcell.com.tr"),
        ):
            with self.subTest(target=target), mock.patch(
                "reconbot.orchestration.osint._resolve_dns_records",
                return_value={"resolved_ips": [], "ipv6_addresses": [], "cname_chain": [], "dns_status": "no_records", "resolver_error": ""},
            ):
                payload = build_osint_enrichment(target=target, enabled=True, tool_settings=settings)
            contacts = payload["organization_intelligence"]["role_contacts"]
            self.assertIn(expected, [item["contact_endpoint"] for item in contacts])
            self.assertTrue(all(item["contact_type"] == "email" for item in contacts))
            self.assertTrue(all("email" not in item for item in contacts))
            self.assertTrue(all(item["source"] == "generated_candidate" for item in contacts))
            self.assertTrue(all(item["observed"] is False for item in contacts))
            self.assertTrue(all(item["status"] == "generated_guess" for item in contacts))
            self.assertTrue(all(item["verification_level"] == "not_observed_not_verified" for item in contacts))
            self.assertTrue(all(item["account_validated"] is False for item in contacts))
            self.assertTrue(all(item["check_policy"] == "generated_candidate" for item in contacts))
            self.assertTrue(all(item["url_status"] == "generated_candidate" for item in contacts))
            self.assertEqual(payload["signals"], [])
            self.assertEqual(payload["summary"]["observed_signals"], 0)

    def test_organization_official_lookup_location_and_document_links_are_shortcuts_not_findings(self) -> None:
        with mock.patch(
            "reconbot.orchestration.osint._resolve_dns_records",
            return_value={"resolved_ips": [], "ipv6_addresses": [], "cname_chain": [], "dns_status": "no_records", "resolver_error": ""},
        ):
            payload = build_osint_enrichment(
                target="https://www.7-eleven.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "includeInfrastructureIntelligence": False,
                        "includeOrganizationIntelligence": True,
                        "timeout": 2,
                    }
                },
            )
        org = payload["organization_intelligence"]
        official_urls = [item["url"] for item in org["official_pages"]]
        self.assertIn("https://7-eleven.com/about", official_urls)
        self.assertIn("https://www.7-eleven.com/contact", official_urls)
        self.assertTrue(all(item["browser_safe"] for item in org["official_pages"]))
        rejected_pages = [item for item in org["official_pages"] if item["url_status"] in {"checked_not_found", "checked_soft_error", "checked_duplicate"}]
        self.assertTrue(rejected_pages)
        self.assertTrue(all(item["page_found"] is False and item["render_as_clickable"] is False for item in rejected_pages))
        self.assertTrue(any(item["check_status"] == "checked" for item in org["official_pages"]))
        self.assertFalse(all(item["url_status"] == "not_checked" for item in org["official_pages"]))
        lookup_roles = {item["url_role"] for item in org["organization_lookup_links"]}
        self.assertEqual(lookup_roles, {"organization_lookup_shortcut"})
        self.assertTrue(any("linkedin.com" in item["url"] for item in org["organization_lookup_links"]))
        self.assertTrue(any("crunchbase.com" in item["url"] for item in org["organization_lookup_links"]))
        self.assertTrue(any("github.com/search" in item["url"] for item in org["organization_lookup_links"]))
        self.assertTrue(all(item["url_role"] == "location_lookup_shortcut" for item in org["location_lookup_links"]))
        maps_links = [item for item in org["location_lookup_links"] if "google.com/maps/search" in item["url"]]
        self.assertEqual(len(maps_links), 1)
        self.assertIn("Google Maps brand search", maps_links[0]["label"])
        self.assertIn("may return local stores or unrelated businesses", maps_links[0]["label"])
        self.assertEqual(maps_links[0]["confidence"], "low")
        self.assertEqual(maps_links[0]["status"], "suggestion_only")
        self.assertIs(maps_links[0]["observed"], False)
        self.assertEqual(maps_links[0]["url_status"], "manual_only")
        self.assertEqual(maps_links[0]["verification_level"], "not_verified_manual_lookup")
        self.assertEqual(maps_links[0]["source_type"], "manual_shortcut")
        self.assertEqual(maps_links[0]["risk_score_impact"], 0)
        self.assertIn("Retail/franchise map results", maps_links[0]["caveat"])
        self.assertTrue(all(item["url_status"] == "manual_only" for item in org["organization_lookup_links"] + org["location_lookup_links"]))
        self.assertTrue(all(item["check_policy"] == "manual_only" for item in org["organization_lookup_links"] + org["location_lookup_links"]))
        self.assertTrue(all(item["status"] == "suggestion_only" for item in org["organization_lookup_links"] + org["location_lookup_links"]))
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        html = render_osint_section({"osint": payload})
        self._assert_no_broken_internal_hrefs(html)
        self._assert_external_osint_links_are_browser_safe(html)
        self.assertIn("Manuel fallback konum aramaları", html)
        self.assertIn("Konum İstihbaratı Özeti", html)
        self.assertIn("Manuel öneri konum aramaları", html)
        self.assertIn("Yerel mağaza veya alakasız işletme döndürebilir", html)
        self.assertIn("Yalnızca Maps/search kısayolu; ReconBot bu konumu doğrulamadı.", html)
        self.assertIn("Tam hedef üzerinde doğrulanmış adres/konum çıkarılamadı.", html)
        observed_html = html.split("<h3>Gözlemlenen OSINT Kanıtları</h3>", 1)[1].split("<h3>Gelişmiş / Eski Uyumluluk Teşhisleri</h3>", 1)[0]
        self.assertNotIn("linkedin.com", observed_html)
        self.assertNotIn("crunchbase.com", observed_html)

    def test_location_hints_drop_promotional_noise_and_dedupe_pages(self) -> None:
        noisy_and_address = """
        <html><head><title>Example</title></head><body>
        Save 20 percent with office discount courses this week.
        Corporate headquarters address: 123 Main Street, New York, NY 10001.
        </body></html>
        """

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://example.com/" or url.endswith("/about"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Example",
                    "validation_error": "",
                    "body": noisy_and_address,
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        hints = payload["organization_intelligence"]["location_hints"]
        self.assertEqual(len(hints), 1)
        self.assertIn("123 Main Street", hints[0]["location_hint"])
        self.assertNotIn("discount", hints[0]["location_hint"].lower())
        self.assertNotIn("course", hints[0]["location_hint"].lower())

    def test_official_location_extraction_populates_location_intelligence(self) -> None:
        contact_page = """
        <html><head><title>Contact Example</title></head><body>
        Corporate headquarters address: 123 Main Street, New York, NY 10001.
        </body></html>
        """

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url.endswith("/contact"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Contact Example",
                    "validation_error": "",
                    "body": contact_page,
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        location = payload["organization_intelligence"]["location_intelligence"]
        self.assertEqual(location["location_summary"]["observed_locations_count"], 1)
        candidate = location["observed_locations"][0]
        self.assertTrue(candidate["observed"])
        self.assertEqual(candidate["source_type"], "official_page")
        self.assertEqual(candidate["verification_level"], "observed_on_official_source")
        self.assertEqual(candidate["risk_score_impact"], 0)
        self.assertIn("123 Main Street", candidate["address_text"])
        html = render_osint_section({"osint": payload})
        self.assertIn('id="osint-location-intelligence"', html)
        self.assertIn("Tam hedef konumları", html)
        self.assertIn("123 Main Street", html)

    def test_cloudflare_valid_address_text_becomes_observed_official_location(self) -> None:
        contact_page = """
        <html><head><title>Contact Cloudflare</title></head><body>
        <main>
          <h1>Contact</h1>
          <p>Corporate office address: 101 Townsend St. San Francisco, CA 94107.</p>
        </main>
        </body></html>
        """

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url.endswith("/contact"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Contact Cloudflare",
                    "validation_error": "",
                    "body": contact_page,
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="cloudflare.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        location = payload["organization_intelligence"]["location_intelligence"]
        self.assertEqual(location["location_summary"]["observed_locations_count"], 1)
        candidate = location["observed_locations"][0]
        self.assertIn("101 Townsend St. San Francisco, CA 94107", candidate["address_text"])
        self.assertTrue(candidate["observed"])
        self.assertEqual(candidate["status"], "official_observed_location")
        self.assertEqual(candidate["verification_level"], "observed_on_official_source")
        self.assertIn(candidate["confidence"], {"medium", "high"})
        self.assertEqual(candidate["risk_score_impact"], 0)

    def test_7eleven_noisy_location_text_is_rejected_not_observed(self) -> None:
        noisy_page = """
        <html><head><title>7-Eleven</title></head><body>
        <nav>Store Locator Menu Food, Drinks &amp; Fuel Rewards Franchise</nav>
        <main>
          <h1>Store Locator</h1>
          <p>Food, Drinks &amp; Fuel</p>
          <p>Store Chain by Newsweek</p>
          <p>Trust is a major factor for customers.</p>
          <footer>Footer generic links Franchise information</footer>
        </main>
        </body></html>
        """

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://7-eleven.com/" or url.endswith("/about") or url.endswith("/contact"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "7-Eleven",
                    "validation_error": "",
                    "body": noisy_page,
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="https://www.7-eleven.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        location = payload["organization_intelligence"]["location_intelligence"]
        observed_text = " ".join(item["address_text"] for item in location["observed_locations"])
        for snippet in ("Store Locator", "Food, Drinks & Fuel", "Store Chain by Newsweek", "Franchise"):
            self.assertNotIn(snippet, observed_text)
        self.assertEqual(location["location_summary"]["observed_locations_count"], 0)
        rejected = location["rejected_location_candidates"]
        rejected_text = " ".join(item["text"] for item in rejected)
        self.assertIn("Store Locator", rejected_text)
        self.assertIn("Food, Drinks & Fuel", rejected_text)
        self.assertIn("Store Chain by Newsweek", rejected_text)
        self.assertTrue(all(item["risk_score_impact"] == 0 for item in rejected))
        self.assertTrue(all(item["status"] == "rejected_location_candidate" for item in rejected))
        html = render_osint_section({"osint": payload})
        observed_table = html.split("<h4>Tam hedef konumları</h4>", 1)[1].split("<h4>Üst kurum konumları</h4>", 1)[0]
        self.assertNotIn("Store Locator", observed_table)
        self.assertNotIn("Food, Drinks &amp; Fuel", observed_table)
        diagnostics = html.split("Reddedilen Konum Adayları", 1)[1]
        self.assertIn("Store Locator", diagnostics)
        self.assertIn("Food, Drinks &amp; Fuel", diagnostics)

    def test_structured_data_location_ignores_soft_error_pages(self) -> None:
        json_ld = """
        <html><head><title>Example</title>
        <script type="application/ld+json">
        {"@context":"https://schema.org","@type":"Organization","name":"Example","address":{"@type":"PostalAddress","streetAddress":"500 Market Street","addressLocality":"San Francisco","addressRegion":"CA","postalCode":"94105","addressCountry":"US"}}
        </script></head><body>Example organization</body></html>
        """

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://example.com/":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Example",
                    "validation_error": "",
                    "body": json_ld,
                }
            if url.endswith("/about"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": "https://example.com/Error/400?aspxerrorpath=/about",
                    "content_type": "text/html",
                    "title": "Error 400",
                    "validation_error": "",
                    "body": json_ld,
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        locations = payload["organization_intelligence"]["location_intelligence"]["observed_locations"]
        self.assertEqual(len(locations), 1)
        self.assertEqual(locations[0]["source_type"], "structured_data")
        self.assertIn("500 Market Street", locations[0]["address_text"])

    def test_manual_location_shortcuts_are_fallback_only_when_no_location_observed(self) -> None:
        payload = build_osint_enrichment(
            target="zekagucu.turkcell.com.tr",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        location = payload["organization_intelligence"]["location_intelligence"]
        self.assertEqual(location["location_summary"]["observed_locations_count"], 0)
        self.assertTrue(location["location_lookup_shortcuts"])
        self.assertTrue(all(item["status"] == "suggestion_only" for item in location["location_lookup_shortcuts"]))
        self.assertTrue(all(item["risk_score_impact"] == 0 for item in location["location_lookup_shortcuts"]))
        html = render_osint_section({"osint": payload})
        self.assertIn("Konum İstihbaratı Özeti", html)
        self.assertIn("Manuel öneri konum aramaları", html)
        self.assertIn("Tam hedef üzerinde doğrulanmış adres/konum çıkarılamadı.", html)
        self.assertIn("Manuel fallback konum aramaları", html)
        self.assertIn("Tam hedef konumları", html)
        self.assertIn("Üst kurum konumları", html)
        self.assertIn("Bağlı/harici resmî kaynak konumları", html)
        main_location = html.split("<h4>Tam hedef konumları</h4>", 1)[1].split("Manuel fallback konum aramaları", 1)[0]
        self.assertNotIn("Google Maps", main_location)
        fallback_location = html.split("Manuel fallback konum aramaları", 1)[1]
        self.assertIn("Google Maps", fallback_location)
        self.assertIn("Yalnızca Maps/search kısayolu; ReconBot bu konumu doğrulamadı.", fallback_location)

    def test_email_contacts_from_official_pages_and_security_txt_are_observed(self) -> None:
        security_txt = "Contact: https://example.com/security-report-form\n"
        contact_page = """
        <html><head><script type="application/ld+json">
        {"@context":"https://schema.org","@type":"ContactPoint","contactType":"support","url":"https://example.com/support"}
        </script></head><body>
        <a href="mailto:abuse@example.com">abuse</a>
        <p>Phone +1 555 123 4567</p>
        </body></html>
        """

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://example.com/.well-known/security.txt":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "get_only"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/plain",
                    "title": "",
                    "validation_error": "",
                    "body": security_txt,
                }
            if url.endswith("/contact"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Contact",
                    "validation_error": "",
                    "body": contact_page,
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        email = payload["organization_intelligence"]["email_intelligence"]
        observed = email["observed_public_contacts"]
        self.assertIn(("abuse@example.com", "email"), [(item["contact_endpoint"], item["contact_type"]) for item in observed])
        self.assertNotIn(("https://example.com/security-report-form", "form"), [(item["contact_endpoint"], item["contact_type"]) for item in observed])
        contact_intel = payload["organization_intelligence"]["contact_intelligence"]
        self.assertIn(
            ("https://example.com/security-report-form", "contact_form"),
            [(item["contact_endpoint"], item["contact_type"]) for item in contact_intel["observed_contact_forms"]],
        )
        self.assertIn("+1 555 123 4567", [item["contact_endpoint"] for item in contact_intel["observed_phone_numbers"]])
        self.assertIn("https://example.com/support", [item["contact_endpoint"] for item in contact_intel["observed_contact_urls"]])
        self.assertTrue(all(item["contact_type"] == "email" for item in contact_intel["observed_email_addresses"]))
        email_endpoints = [item["contact_endpoint"] for item in contact_intel["observed_email_addresses"]]
        self.assertNotIn("+1 555 123 4567", email_endpoints)
        self.assertNotIn("https://example.com/support", email_endpoints)
        self.assertTrue(all(item["status"] == "observed_public_contact" for item in observed))
        generated = email["generated_role_contact_guesses"]
        self.assertTrue(generated)
        self.assertTrue(all(item["status"] == "generated_guess" and item["observed"] is False and item["risk_score_impact"] == 0 for item in generated))

    def test_strict_phone_extraction_rejects_coordinate_and_script_svg_text(self) -> None:
        coordinate_contact_page = """
        <html><body>
        <p>Contact support 6.51803 0 4.94714 0.476523 3.611 1.36931</p>
        <script>var phone = "+1 999 999 9999";</script>
        <style>.icon { d: "0 0 24 24"; }</style>
        <svg><text>Phone +1 888 888 8888</text><path d="0 0 24 24"/></svg>
        </body></html>
        """
        seven_eleven_contact_page = """
        <html><body>
        <p>Customer service: 1 (855) 711-5933</p>
        </body></html>
        """

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if "cloudflare.com" in url and url.endswith("/contact"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Contact",
                    "validation_error": "",
                    "body": coordinate_contact_page,
                }
            if "7-eleven.com" in url and url.endswith("/contact"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Contact",
                    "validation_error": "",
                    "body": seven_eleven_contact_page,
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        common_settings = {
            "osint": {
                "includeCertificateTransparency": False,
                "includeHistoricalUrls": False,
                "includePublicCodeReferences": False,
                "includeKnownBreachCatalog": False,
                "includeSearchDorkSuggestions": False,
                "includeInfrastructureIntelligence": False,
                "includeOrganizationIntelligence": True,
                "timeout": 2,
            }
        }
        cloudflare = build_osint_enrichment(target="https://www.cloudflare.com", enabled=True, tool_settings=common_settings)
        cloudflare_phones = [
            item["contact_endpoint"]
            for item in cloudflare["organization_intelligence"]["contact_intelligence"]["observed_phone_numbers"]
        ]
        self.assertNotIn("6.51803 0 4.94714 0.476523 3.611 1.36931", cloudflare_phones)
        self.assertFalse(any("999 999" in value or "888 888" in value or "0 0 24 24" in value for value in cloudflare_phones))

        seven_eleven = build_osint_enrichment(target="https://www.7-eleven.com", enabled=True, tool_settings=common_settings)
        seven_eleven_phones = [
            item["contact_endpoint"]
            for item in seven_eleven["organization_intelligence"]["contact_intelligence"]["observed_phone_numbers"]
        ]
        self.assertIn("1 (855) 711-5933", seven_eleven_phones)

    def test_cloudflare_structured_data_generic_urls_are_not_contact_urls(self) -> None:
        security_txt = "\n".join(
            [
                "Contact: https://hackerone.com/cloudflare",
                "Contact: https://www.cloudflare.com/abuse/",
            ]
        )
        homepage = """
        <html><head><script type="application/ld+json">
        {"@context":"https://schema.org","@type":"Organization","url":"https://www.cloudflare.com","sameAs":["https://www.cloudflare.com/about/"],"logo":"https://www.cloudflare.com/logo.png"}
        </script></head><body>Cloudflare homepage</body></html>
        """
        about = """
        <html><head><script type="application/ld+json">
        {"@context":"https://schema.org","@type":"Organization","url":"https://www.cloudflare.com/about/","mainEntityOfPage":"https://www.cloudflare.com/careers/jobs/"}
        </script></head><body>About Cloudflare</body></html>
        """

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url.endswith("/.well-known/security.txt") and url.startswith("https://cloudflare.com/"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "get_only"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/plain",
                    "title": "",
                    "validation_error": "",
                    "body": security_txt,
                }
            if url in {"https://cloudflare.com/", "https://www.cloudflare.com/"}:
                body = homepage
            elif url.endswith("/about"):
                body = about
            elif url.endswith("/careers"):
                body = '<html><body><script type="application/ld+json">{"@context":"https://schema.org","url":"https://www.cloudflare.com/careers/jobs/"}</script></body></html>'
            else:
                return self._default_osint_url_validation(url, **kwargs)
            return {
                "check_policy": "auto_check_allowed",
                "validation_method": str(kwargs.get("validation_method") or "head_get"),
                "check_status": "checked",
                "url_status": "checked_ok",
                "http_status": 200,
                "final_url": url,
                "content_type": "text/html",
                "title": "Cloudflare",
                "validation_error": "",
                "body": body,
            }

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="https://www.cloudflare.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        contact_urls = [
            item["contact_endpoint"]
            for item in payload["organization_intelligence"]["contact_intelligence"]["observed_contact_urls"]
        ]
        self.assertIn("https://hackerone.com/cloudflare", contact_urls)
        self.assertIn("https://www.cloudflare.com/abuse/", contact_urls)
        for generic_url in (
            "https://www.cloudflare.com",
            "https://www.cloudflare.com/",
            "https://www.cloudflare.com/about/",
            "https://www.cloudflare.com/careers/jobs/",
        ):
            self.assertNotIn(generic_url, contact_urls)
        summary = payload["organization_intelligence"]["contact_intelligence"]["contact_summary"]
        self.assertEqual(summary["observed_contact_urls_count"], 2)
        self.assertEqual(summary["observed_phone_numbers_count"], 0)
        self.assertEqual(payload["organization_intelligence"]["contact_intelligence"]["observed_phone_numbers"], [])

    def test_official_page_off_domain_email_is_affiliate_contact_not_validated_account(self) -> None:
        privacy_page = """
        <html><head><title>7-Eleven Privacy</title></head><body>
        <a href="mailto:privacypolicy@7-11.com">Privacy Policy</a>
        </body></html>
        """

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url.endswith("/privacy"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "7-Eleven Privacy",
                    "validation_error": "",
                    "body": privacy_page,
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="https://www.7-eleven.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        contact_intel = payload["organization_intelligence"]["contact_intelligence"]
        contact = next(item for item in contact_intel["observed_email_addresses"] if item["contact_endpoint"] == "privacypolicy@7-11.com")
        self.assertTrue(contact["observed"])
        self.assertFalse(contact["same_registered_domain"])
        self.assertEqual(contact["endpoint_registered_domain"], "7-11.com")
        self.assertEqual(contact["domain_relationship"], "official_affiliate_domain")
        self.assertFalse(contact["account_validated"])
        self.assertEqual(contact["risk_score_impact"], 0)

    def test_official_same_as_links_become_observed_social_profiles(self) -> None:
        homepage = """
        <html><head><script type="application/ld+json">
        {"@context":"https://schema.org","@type":"Organization","sameAs":["https://github.com/example","https://x.com/example","https://www.linkedin.com/company/example"]}
        </script></head><body><a href="https://www.youtube.com/@example">YouTube</a></body></html>
        """

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://example.com/":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Example",
                    "validation_error": "",
                    "body": homepage,
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        profiles = payload["organization_intelligence"]["people_organization_presence"]["observed_official_social_profiles"]
        profile_types = {item["profile_type"] for item in profiles}
        self.assertTrue({"github", "x", "linkedin", "youtube"} <= profile_types)
        self.assertTrue(all(item["status"] == "observed_official_social_profile" for item in profiles))
        self.assertTrue(all(item["verification_level"] == "linked_from_official_source" for item in profiles))
        html = render_osint_section({"osint": payload})
        board = html.split('id="osint-intelligence-board"', 1)[1].split('<h3 id="osint-overview"', 1)[0]
        self.assertIn("Resmî sayfalar", board)
        self.assertIn("4", board)
        profile_section = html.split("Gözlemlenen Resmî Sosyal Profiller", 1)[1].split("Resmî People / Organization Sayfaları", 1)[0]
        self.assertIn("github.com/example", profile_section)
        self.assertIn("linked_from_official_source", profile_section)
        self.assertNotIn("Crunchbase company search", board)
        self.assertIn("Gözlemlenen Resmî Sosyal Profiller", html)
        fallback_people = html.split("Manuel / API Gerektiren Arama Kısayolları", 1)[1]
        self.assertIn("Crunchbase şirket aramasını aç", fallback_people)

    def test_public_document_intelligence_validates_official_candidates(self) -> None:
        sitemap = """<?xml version="1.0"?><urlset>
        <url><loc>https://example.com/files/security-whitepaper.pdf</loc></url>
        <url><loc>https://example.com/files/missing.pdf</loc></url>
        </urlset>"""

        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://example.com/sitemap.xml":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "get_only"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "application/xml",
                    "title": "",
                    "validation_error": "",
                    "body": sitemap,
                }
            if url.endswith("security-whitepaper.pdf"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": "head_get",
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "application/pdf",
                    "title": "",
                    "validation_error": "",
                    "body": "",
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        docs = payload["organization_intelligence"]["public_document_intelligence"]
        self.assertEqual(docs["document_summary"]["validated_public_documents_count"], 2)
        self.assertEqual(docs["document_summary"]["rejected_document_candidates_count"], 1)
        validated = next(item for item in docs["validated_public_documents"] if item["url"].endswith("security-whitepaper.pdf"))
        self.assertEqual(validated["status"], "validated_public_document")
        self.assertTrue(validated["observed"])
        self.assertEqual(validated["verification_level"], "validated_public_official_link")
        self.assertEqual(validated["risk_score_impact"], 0)
        self.assertEqual(validated["url_role"], "validated_public_document")
        self.assertEqual(validated["check_policy"], "auto_check_allowed")
        self.assertEqual(validated["validation_method"], "head_get")
        self.assertEqual(validated["url_status"], "checked_ok")
        self.assertTrue(validated["browser_safe"])
        self.assertTrue(validated["render_as_clickable"])
        self.assertTrue(all(item["status"] == "suggestion_only" for item in docs["manual_document_search_shortcuts"]))
        html = render_osint_section({"osint": payload})
        validated_after_audit = next(
            item
            for item in payload["organization_intelligence"]["public_document_intelligence"]["validated_public_documents"]
            if item["url"].endswith("security-whitepaper.pdf")
        )
        self.assertEqual(validated_after_audit["url_audit"]["check_policy"], "auto_check_allowed")
        self.assertEqual(validated_after_audit["url_audit"]["validation_method"], "head_get")
        self.assertEqual(validated_after_audit["url_audit"]["url_status"], "checked_ok")
        self.assertEqual(validated_after_audit["url_audit"]["http_status"], 200)
        self.assertTrue(validated_after_audit["url_audit"]["browser_safe"])
        self.assertTrue(validated_after_audit["url_audit"]["render_as_clickable"])
        self.assertIn('id="osint-public-document-intelligence"', html)
        self.assertIn("security-whitepaper.pdf", html)
        self.assertIn("Manuel / API Gerektiren Arama Kısayolları", html)
        self.assertIn("Manuel doküman dork; doğrulanmış herkese açık doküman değil.", html)

    def test_validated_7eleven_pdf_and_cloudflare_llms_document_audits_are_consistent(self) -> None:
        cases = [
            (
                "https://www.7-eleven.com",
                "https://www.7-eleven.com/files/privacy-policy.pdf",
                "application/pdf",
            ),
            (
                "https://www.cloudflare.com",
                "https://www.cloudflare.com/llms.txt",
                "text/plain",
            ),
        ]
        for target, document_url, content_type in cases:
            with self.subTest(target=target):
                sitemap = f"<?xml version=\"1.0\"?><urlset><url><loc>{document_url}</loc></url></urlset>"

                def validate_url(url: str, **kwargs: object) -> dict[str, object]:
                    if url.endswith("/sitemap.xml"):
                        return {
                            "check_policy": "auto_check_allowed",
                            "validation_method": str(kwargs.get("validation_method") or "get_only"),
                            "check_status": "checked",
                            "url_status": "checked_ok",
                            "http_status": 200,
                            "final_url": url,
                            "content_type": "application/xml",
                            "title": "",
                            "validation_error": "",
                            "body": sitemap,
                        }
                    if url == document_url:
                        return {
                            "check_policy": "auto_check_allowed",
                            "validation_method": "head_get",
                            "check_status": "checked",
                            "url_status": "checked_ok",
                            "http_status": 200,
                            "final_url": url,
                            "content_type": content_type,
                            "title": "",
                            "validation_error": "",
                            "body": "",
                        }
                    return self._default_osint_url_validation(url, **kwargs)

                self.osint_validate_mock.side_effect = validate_url
                payload = build_osint_enrichment(
                    target=target,
                    enabled=True,
                    tool_settings={
                        "osint": {
                            "includeCertificateTransparency": False,
                            "includeHistoricalUrls": False,
                            "includePublicCodeReferences": False,
                            "includeKnownBreachCatalog": False,
                            "includeSearchDorkSuggestions": False,
                            "includeInfrastructureIntelligence": False,
                            "includeOrganizationIntelligence": True,
                            "timeout": 2,
                        }
                    },
                )
                documents = payload["organization_intelligence"]["public_document_intelligence"]["validated_public_documents"]
                self.assertGreaterEqual(len(documents), 1)
                document = next(item for item in documents if item["url"] == document_url)
                self.assertEqual(document["url"], document_url)
                self.assertEqual(document["url_role"], "validated_public_document")
                self.assertEqual(document["check_policy"], "auto_check_allowed")
                self.assertEqual(document["validation_method"], "head_get")
                self.assertEqual(document["url_status"], "checked_ok")
                self.assertEqual(document["http_status"], 200)
                self.assertTrue(document["browser_safe"])
                self.assertTrue(document["render_as_clickable"])
                audit = document["url_audit"]
                self.assertEqual(audit["url_role"], "validated_public_document")
                self.assertEqual(audit["check_policy"], "auto_check_allowed")
                self.assertEqual(audit["validation_method"], "head_get")
                self.assertEqual(audit["url_status"], "checked_ok")
                self.assertEqual(audit["http_status"], 200)
                self.assertTrue(audit["browser_safe"])
                self.assertTrue(audit["render_as_clickable"])

    def test_people_organization_presence_uses_official_pages_and_manual_shortcuts_only(self) -> None:
        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url.endswith("/about") or url.endswith("/team"):
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": str(kwargs.get("validation_method") or "head_get"),
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Example Team",
                    "validation_error": "",
                    "body": "<html><head><title>Example Team</title></head><body>Leadership team</body></html>",
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        presence = payload["organization_intelligence"]["people_organization_presence"]
        self.assertEqual(presence["status"], "observed_public_page")
        self.assertTrue(any(item["url"].endswith("/team") for item in presence["official_people_pages"]))
        shortcuts = presence["company_profile_lookup_shortcuts"]
        manual_shortcuts = [item for item in shortcuts if item.get("profile_candidate_type") != "github_org_landing"]
        github_candidate = next(item for item in shortcuts if item.get("profile_candidate_type") == "github_org_landing")
        self.assertTrue(all(item["status"] == "suggestion_only" for item in manual_shortcuts))
        self.assertTrue(all(item["url_status"] == "manual_only" for item in manual_shortcuts))
        self.assertEqual(github_candidate["check_policy"], "auto_check_allowed")
        self.assertEqual(github_candidate["validation_method"], "head_get")
        self.assertEqual(github_candidate["risk_score_impact"], 0)
        self.assertTrue(presence["policy"]["no_linkedin_employee_scraping"])
        self.assertTrue(presence["policy"]["no_employee_list_harvesting"])
        self.assertTrue(presence["policy"]["no_personal_email_generation"])
        self.assertNotIn("first.last@", json.dumps(payload).lower())
        html = render_osint_section({"osint": payload})
        self.assertIn("Herkese Açık Dokümanlar ve Sosyal Profiller", html)
        self.assertIn("Manuel arama kısayolları scrape edilmiş sonuç değildir", html)

    def test_github_direct_org_candidate_is_possible_profile_only(self) -> None:
        def validate_url(url: str, **kwargs: object) -> dict[str, object]:
            if url == "https://github.com/cloudflare":
                return {
                    "check_policy": "auto_check_allowed",
                    "validation_method": "head_get",
                    "check_status": "checked",
                    "url_status": "checked_ok",
                    "http_status": 200,
                    "final_url": url,
                    "content_type": "text/html",
                    "title": "Cloudflare · GitHub",
                    "validation_error": "",
                    "body": "<html><head><title>Cloudflare · GitHub</title></head><body>Cloudflare organization profile</body></html>",
                }
            return self._default_osint_url_validation(url, **kwargs)

        self.osint_validate_mock.side_effect = validate_url
        payload = build_osint_enrichment(
            target="cloudflare.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": False,
                    "includeInfrastructureIntelligence": False,
                    "includeOrganizationIntelligence": True,
                    "timeout": 2,
                }
            },
        )
        shortcuts = payload["organization_intelligence"]["people_organization_presence"]["company_profile_lookup_shortcuts"]
        github_candidate = next(item for item in shortcuts if item.get("profile_candidate_type") == "github_org_landing")
        github_search = next(item for item in shortcuts if item["label"] == "GitHub organization search")
        self.assertEqual(github_candidate["status"], "possible_official_org_profile")
        self.assertEqual(github_candidate["url_status"], "checked_ok")
        self.assertEqual(github_candidate["confidence"], "medium")
        self.assertEqual(github_candidate["risk_score_impact"], 0)
        self.assertIn("repositories and people are not scraped", github_candidate["note"])
        self.assertEqual(github_search["status"], "suggestion_only")
        self.assertEqual(github_search["check_policy"], "manual_only")
        self.assertNotIn("first.last@", json.dumps(payload).lower())

    def test_organization_public_document_searches_are_manual_suggestions_only(self) -> None:
        with mock.patch(
            "reconbot.orchestration.osint._resolve_dns_records",
            return_value={"resolved_ips": [], "ipv6_addresses": [], "cname_chain": [], "dns_status": "no_records", "resolver_error": ""},
        ):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "includeInfrastructureIntelligence": False,
                        "includeOrganizationIntelligence": True,
                        "timeout": 2,
                    }
                },
            )
        searches = payload["organization_intelligence"]["public_document_searches"]
        queries = [item["query"] for item in searches]
        self.assertIn("site:example.com filetype:pdf", queries)
        self.assertIn("site:example.com (filetype:doc OR filetype:docx)", queries)
        self.assertIn("site:example.com (filetype:xls OR filetype:xlsx)", queries)
        self.assertIn('site:example.com "confidential"', queries)
        self.assertIn('site:example.com "internal use only"', queries)
        self.assertTrue(all(item["url_role"] == "public_document_search" for item in searches))
        self.assertTrue(all(item["url_status"] == "manual_only" for item in searches))
        self.assertTrue(all(item["check_policy"] == "manual_only" for item in searches))
        self.assertTrue(all(item["status"] == "suggestion_only" for item in searches))
        self.assertEqual(payload["summary"]["public_document_search_tasks"], len(searches))
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        html = render_osint_section({"osint": payload})
        self.assertIn("Manuel / API Gerektiren Arama Kısayolları", html)
        self.assertIn("Manuel doküman dork; doğrulanmış herkese açık doküman değil.", html)
        self.assertIn("Herkese açık doküman aramasını aç: site:example.com filetype:pdf", html)
        self._assert_external_osint_links_are_browser_safe(html)

    def test_infrastructure_cloudflare_like_target_is_asset_discovery_only(self) -> None:
        dns_fixture = {
            "resolved_ips": ["104.16.1.1", "104.16.2.2"],
            "ipv6_addresses": [],
            "cname_chain": ["www.example-cdn.com.cdn.cloudflare.net"],
            "dns_status": "resolved",
            "resolver_error": "",
        }
        with mock.patch("reconbot.orchestration.osint._resolve_dns_records", return_value=dns_fixture), mock.patch(
            "reconbot.orchestration.osint._reverse_dns_lookup",
            return_value="edge.cloudflare.com",
        ):
            payload = build_osint_enrichment(
                target="https://www.example-cdn.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )

        infra = payload["infrastructure"]
        self.assertEqual(infra["resolved_ips"], ["104.16.1.1", "104.16.2.2"])
        self.assertTrue(infra["cdn_or_proxy_likely"])
        self.assertEqual(infra["cdn_provider_guess"], "Cloudflare")
        self.assertEqual(infra["origin_confidence"], "low")
        self.assertEqual(payload["summary"]["infrastructure_ips"], 2)
        self.assertEqual(payload["summary"]["cdn_or_proxy_likely_count"], 1)
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["total_signals"], 0)
        self.assertEqual(payload["signals"], [])
        self.assertEqual(payload["verdict"], "asset_discovery_only")

        html = self._render_osint_report("https://www.example-cdn.com", payload, log_target="https://www.example-cdn.com")
        self.assertIn("Altyapı Bağlamı", html)
        self.assertIn("Muhtemel CDN/proxy edge. Origin sunucu olduğu varsayılmamalıdır.", html)
        self.assertNotIn("Open Shodan host lookup", html)
        self.assertNotIn("Open Censys host lookup", html)
        self.assertNotIn("Open urlscan IP search", html)
        self.assertNotIn("Open SecurityTrails DNS lookup", html)
        self.assertIn("Shodan host aramasını aç", html)
        self.assertIn("Censys host aramasını aç", html)
        self.assertIn("urlscan IP aramasını aç", html)
        self.assertIn("SecurityTrails DNS aramasını aç", html)
        self.assertIn("Manuel pasif arama kısayolu; bulgu değildir.", html)
        observed_html = html.split("<h3>Gözlemlenen OSINT Kanıtları</h3>", 1)[1].split("<h3>Gelişmiş / Eski Uyumluluk Teşhisleri</h3>", 1)[0]
        self.assertNotIn("shodan.io/host", observed_html)
        self.assertNotIn("search.censys.io/hosts", observed_html)
        self.assertNotIn("urlscan.io/search", observed_html)

    def test_infrastructure_cloudflare_registered_domain_and_edge_range_detected_as_cdn(self) -> None:
        dns_fixture = {
            "resolved_ips": ["104.16.123.10"],
            "ipv6_addresses": [],
            "cname_chain": [],
            "dns_status": "resolved",
            "resolver_error": "",
        }
        with mock.patch("reconbot.orchestration.osint._resolve_dns_records", return_value=dns_fixture), mock.patch(
            "reconbot.orchestration.osint._reverse_dns_lookup",
            return_value="",
        ):
            payload = build_osint_enrichment(
                target="https://www.cloudflare.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        infra = payload["infrastructure"]
        self.assertTrue(infra["cdn_or_proxy_likely"])
        self.assertEqual(infra["cdn_provider_guess"], "Cloudflare")
        self.assertEqual(infra["origin_confidence"], "low")
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["signals"], [])
        self.assertTrue(all(link["status"] == "suggestion_only" for link in infra["passive_lookup_links"]))
        html = render_osint_section({"osint": payload})
        self.assertIn("Muhtemel CDN/proxy edge. Origin sunucu olduğu varsayılmamalıdır.", html)

    def test_infrastructure_normal_non_cdn_fixture_generates_passive_links_only(self) -> None:
        dns_fixture = {
            "resolved_ips": ["93.184.216.34"],
            "ipv6_addresses": [],
            "cname_chain": [],
            "dns_status": "resolved",
            "resolver_error": "",
        }
        with mock.patch("reconbot.orchestration.osint._resolve_dns_records", return_value=dns_fixture), mock.patch(
            "reconbot.orchestration.osint._reverse_dns_lookup",
            return_value="origin.example.org",
        ):
            payload = build_osint_enrichment(
                target="example.org",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )

        infra = payload["infrastructure"]
        self.assertEqual(infra["resolved_ips"], ["93.184.216.34"])
        self.assertFalse(infra["cdn_or_proxy_likely"])
        self.assertIn(infra["origin_confidence"], {"medium", "unknown"})
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["signals"], [])
        self.assertGreater(payload["summary"]["infrastructure_lookup_tasks"], 0)
        self.assertTrue(all(link["status"] == "suggestion_only" for link in infra["passive_lookup_links"]))

        html = render_osint_section({"osint": payload})
        self.assertIn("93.184.216.34", html)
        self.assertIn("Manuel pasif arama kısayolu; bulgu değildir.", html)
        self.assertNotIn("Muhtemel CDN/proxy edge. Origin sunucu olduğu varsayılmamalıdır.", html)

    def test_infrastructure_dns_failure_does_not_crash_or_imply_clean_target(self) -> None:
        dns_fixture = {
            "resolved_ips": [],
            "ipv6_addresses": [],
            "cname_chain": [],
            "dns_status": "error",
            "resolver_error": "resolver unavailable",
        }
        with mock.patch("reconbot.orchestration.osint._resolve_dns_records", return_value=dns_fixture):
            payload = build_osint_enrichment(
                target="dns-failure.example",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )

        self.assertEqual(payload["infrastructure"]["dns_status"], "error")
        self.assertEqual(payload["infrastructure"]["resolver_error"], "resolver unavailable")
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertNotEqual(payload["verdict"], "observed_evidence")
        self.assertEqual(payload["verdict"], "source_failures")
        self.assertIn("DNS infrastructure resolution failed", payload["verdict_reason"])

        html = render_osint_section({"osint": payload})
        self.assertIn("DNS çözümleme başarısız veya erişilemez", html)
        self.assertIn("temiz hedef", html.lower())
        self.assertNotIn("target is clean", html.lower())

    def test_infrastructure_link_audit_marks_passive_shortcuts_not_findings(self) -> None:
        dns_fixture = {
            "resolved_ips": ["203.0.113.10"],
            "ipv6_addresses": [],
            "cname_chain": [],
            "dns_status": "resolved",
            "resolver_error": "",
        }
        with mock.patch("reconbot.orchestration.osint._resolve_dns_records", return_value=dns_fixture), mock.patch(
            "reconbot.orchestration.osint._reverse_dns_lookup",
            return_value="",
        ):
            payload = build_osint_enrichment(
                target="audit.example",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        links = payload["infrastructure"]["passive_lookup_links"]
        self.assertTrue(links)
        for link in links:
            self.assertEqual(link["url_role"], "passive_infrastructure_lookup")
            self.assertEqual(link["check_policy"], "api_required")
            self.assertEqual(link["validation_method"], "api")
            self.assertEqual(link["url_status"], "api_key_missing")
            self.assertTrue(link["browser_safe"])
            self.assertTrue(link["render_as_clickable"])
            self.assertEqual(link["status"], "suggestion_only")
            self.assertEqual(link["risk_score_impact"], 0)
        infrastructure_audits = [item for item in payload["url_audit"] if item["url_role"] == "passive_infrastructure_lookup"]
        self.assertEqual(len(infrastructure_audits), len(links))
        html = render_osint_section({"osint": payload})
        observed_html = html.split("<h3>Gözlemlenen OSINT Kanıtları</h3>", 1)[1].split("<h3>Gelişmiş / Eski Uyumluluk Teşhisleri</h3>", 1)[0]
        self.assertNotIn("shodan.io/host", observed_html)
        self.assertNotIn("search.censys.io/hosts", observed_html)
        self.assertNotIn("urlscan.io/search", observed_html)

    def test_microsoft_style_ct_candidates_do_not_create_observed_evidence(self) -> None:
        records = [
            {
                "dns_names": [
                    "www.microsoft.com",
                    "login.www.microsoft.com",
                    "api.www.microsoft.com",
                    "portal.www.microsoft.com",
                    "cdn.www.microsoft.com",
                ]
            }
        ]

        def fake_fetch(url: str, timeout: int) -> list[dict[str, object]]:
            if "crt.sh" in url:
                return []
            return records

        with mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=fake_fetch):
            payload = build_osint_enrichment(
                target="https://www.microsoft.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": True,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                    }
                },
            )
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["signals"], [])
        self.assertGreater(payload["summary"]["asset_discovery_candidates"], 0)
        self.assertEqual(payload["verdict"], "asset_discovery_only")
        source = next(item for item in payload["sources"] if item["name"] == "certificate_transparency")
        self.assertEqual(source["signal_count"], 0)
        self.assertGreater(source["asset_discovery_count"], 0)
        self.assertFalse(source["render_as_clickable"])

    def test_osint_only_microsoft_report_has_valid_sidebar_and_registered_email_dork(self) -> None:
        records = [
            {
                "dns_names": [
                    "www.microsoft.com",
                    "login.www.microsoft.com",
                    "api.www.microsoft.com",
                ]
            }
        ]

        def fake_fetch(url: str, timeout: int) -> list[dict[str, object]]:
            if "crt.sh" in url:
                return []
            return records

        with mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=fake_fetch):
            payload = build_osint_enrichment(
                target="https://www.microsoft.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": True,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": True,
                        "maxSignals": 20,
                        "timeout": 2,
                    }
                },
            )

        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertGreater(payload["summary"]["asset_discovery_candidates"], 0)
        email_task = next(item for item in payload["operator_search_tasks"] if item["category"] == "emails")
        self.assertEqual(email_task["query"], '"@microsoft.com"')
        self.assertEqual(email_task["query_scope"], "registered_domain")
        self.assertNotIn("@www.microsoft.com", email_task["query"])

        html = self._render_osint_report("https://www.microsoft.com", payload, log_target="https://www.microsoft.com")
        self._assert_no_broken_internal_hrefs(html)
        self.assertNotIn('href="#screenshots"', html)
        self.assertNotIn('id="screenshots"', html)
        fallback_html = html.split('id="osint-manual-search-suggestions"', 1)[1]
        self.assertIn("Google e-posta pattern aramasını aç", fallback_html)
        self.assertIn("%40microsoft.com", fallback_html)
        self.assertNotIn("%40www.microsoft.com", fallback_html)
        self.assertIn("run_id / timestamp", html)
        self.assertIn("report file target", html)
        self.assertIn("log target", html)
        self.assertIn("reconbot-internal-link-audit: ok", html)

    def test_artifact_identity_warns_when_log_target_differs(self) -> None:
        payload = build_osint_enrichment(
            target="https://www.microsoft.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeKnownBreachCatalog": False,
                    "includeSearchDorkSuggestions": True,
                    "timeout": 2,
                }
            },
        )
        html = self._render_osint_report("https://www.microsoft.com", payload, log_target="https://example.org")
        self.assertIn("Artifact mismatch: this log appears to belong to a different target.", html)

    def test_ct_wildcard_404_does_not_create_fake_error_or_signal(self) -> None:
        def fake_fetch(url: str, timeout: int) -> list[dict[str, str]]:
            if "%25." in url:
                raise HTTPError(url, 404, "Not Found", {}, None)
            return []

        with mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=fake_fetch):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": True,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "certificate_transparency")
        self.assertEqual(source["status"], "completed")
        self.assertEqual(source["signal_count"], 0)
        self.assertEqual(source["errors"], [])
        self.assertIn("HTTP 404; classified as no records", source["notes"])
        self.assertEqual(payload["summary"]["observed_signals"], 0)

    def test_wayback_classifier_identifies_review_paths(self) -> None:
        samples = {
            "https://example.com/admin": "admin",
            "https://example.com/api/v1/users": "api",
            "https://example.com/backups/db.sql": "backup",
            "https://example.com/config/app.yaml": "config",
            "https://example.com/debug/trace": "debug",
            "https://example.com/swagger/index.html": "api",
            "https://example.com/upload/avatar": "upload",
            "https://example.com/register": "auth",
        }
        for url, expected_keyword in samples.items():
            with self.subTest(url=url):
                classified = _classify_wayback_url(url)
                self.assertTrue(classified["interesting"])
                self.assertIn(expected_keyword, classified["keywords"])

    def test_wayback_success_creates_historical_context_only_for_interesting_urls(self) -> None:
        records = [
            ["original", "timestamp", "statuscode", "mimetype"],
            ["https://example.com/", "20240101000000", "200", "text/html"],
            ["https://example.com/admin", "20240101000001", "200", "text/html"],
            ["https://example.com/assets/app.js", "20240101000002", "200", "application/javascript"],
            ["https://example.com/config/app.yaml", "20240101000003", "200", "text/plain"],
        ]
        with mock.patch("reconbot.orchestration.osint._fetch_json", return_value=records):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                scan_profile="balanced",
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": True,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": False,
                        "maxSignals": 20,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "historical_urls")
        self.assertEqual(source["status"], "completed")
        self.assertEqual(source["raw_count"], 4)
        self.assertEqual(source["signal_count"], 0)
        self.assertEqual(source["historical_url_candidates"], 2)
        urls = [item["url"] for item in payload["historical_url_context"]]
        self.assertEqual(urls, ["https://example.com/admin", "https://example.com/config/app.yaml"])
        self.assertTrue(all(item["observed_signal"] is False for item in payload["historical_url_context"]))
        self.assertTrue(all(item["url_status"] == "archived_not_live_checked" for item in payload["historical_url_context"]))
        self.assertEqual(payload["signals"], [])
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["total_signals"], 0)
        self.assertEqual(payload["summary"]["needs_manual_review"], 0)
        self.assertEqual(payload["summary"]["historical_url_candidates"], 2)
        self.assertEqual(payload["verdict"], "historical_context_only")
        html = render_osint_section({"osint": payload})
        self.assertIn("Geçmiş URL Bağlamı", html)
        self.assertIn("Arşiv URL adayı; mevcut maruziyet değildir", html)
        observed_section = html.split("<h3>Gözlemlenen OSINT Kanıtları</h3>", 1)[1].split("<h3>Gelişmiş / Eski Uyumluluk Teşhisleri</h3>", 1)[0]
        self.assertNotIn("https://example.com/admin", observed_section)

    def test_wayback_503_failure_records_error_and_no_signals(self) -> None:
        error = HTTPError("https://web.archive.org/cdx", 503, "Service Unavailable", {}, None)
        with mock.patch("reconbot.orchestration.osint.time.sleep"), mock.patch(
            "reconbot.orchestration.osint._fetch_json",
            side_effect=error,
        ):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": True,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "historical_urls")
        self.assertEqual(source["status"], "error")
        self.assertEqual(source["signal_count"], 0)
        self.assertIn("HTTPError 503", " ".join(source["errors"]))
        self.assertEqual(payload["summary"]["observed_signals"], 0)

    def test_wayback_200_empty_response_is_completed_zero_records(self) -> None:
        with mock.patch("reconbot.orchestration.osint._fetch_json", return_value=[]):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                scan_profile="balanced",
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": True,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "historical_urls")
        self.assertEqual(source["status"], "completed")
        self.assertEqual(source["raw_count"], 0)
        self.assertEqual(source["signal_count"], 0)
        self.assertIn("No records returned", source["notes"])
        self.assertEqual(payload["summary"]["observed_signals"], 0)

    def test_wayback_boring_urls_are_raw_not_signals(self) -> None:
        records = [
            ["original", "timestamp", "statuscode", "mimetype"],
            ["https://example.com/", "20240101000000", "200", "text/html"],
            ["https://example.com/assets/app.js", "20240101000002", "200", "application/javascript"],
        ]
        with mock.patch("reconbot.orchestration.osint._fetch_json", return_value=records):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": True,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "historical_urls")
        self.assertEqual(source["status"], "completed")
        self.assertGreater(source["raw_count"], 0)
        self.assertEqual(source["signal_count"], 0)
        self.assertEqual(payload["signals"], [])
        self.assertEqual(payload["summary"]["observed_signals"], 0)

    def test_wayback_uses_scheme_fallbacks_after_zero_records(self) -> None:
        calls: list[str] = []

        def fake_fetch(url: str, timeout: int) -> list[list[str]]:
            calls.append(url)
            if "https%3A%2F%2Fexample.com%2F%2A" in url:
                return [
                    ["original", "timestamp", "statuscode", "mimetype"],
                    ["https://example.com/api/v1", "20240101000000", "200", "text/html"],
                ]
            return []

        with mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=fake_fetch):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                scan_profile="balanced",
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": True,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "historical_urls")
        self.assertEqual(source["raw_count"], 1)
        self.assertEqual(source["signal_count"], 0)
        self.assertEqual(source["historical_url_candidates"], 1)
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["historical_url_candidates"], 1)
        self.assertEqual(payload["historical_url_context"][0]["url"], "https://example.com/api/v1")
        self.assertEqual(len(calls), 3)
        self.assertIn("limit=200", calls[0])

    def test_wayback_fast_profile_uses_only_exact_and_wildcard_variants(self) -> None:
        calls: list[str] = []

        def fake_fetch(url: str, timeout: int) -> list[list[str]]:
            calls.append(url)
            return []

        with mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=fake_fetch):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                scan_profile="fast",
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": True,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": False,
                        "timeout": 2,
                    }
                },
            )
        source = next(item for item in payload["sources"] if item["name"] == "historical_urls")
        self.assertEqual(source["status"], "completed")
        self.assertEqual(source["signal_count"], 0)
        self.assertEqual(len(calls), 2)
        self.assertIn("limit=50", calls[0])

    def test_generated_tasks_do_not_consume_max_signals_or_create_suppression(self) -> None:
        settings = {
            "osint": {
                "includeCertificateTransparency": False,
                "includeHistoricalUrls": False,
                "includePublicCodeReferences": True,
                "includeSearchDorkSuggestions": True,
                "maxSignals": 3,
                "timeout": 2,
                "passiveOnly": True,
            }
        }
        with mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=OSError("network blocked")):
            payload = build_osint_enrichment(target="example.com", enabled=True, tool_settings=settings)
        self.assertEqual(len(payload["signals"]), 0)
        self.assertEqual(len(payload["operator_search_tasks"]), 24)
        self.assertEqual(len(payload["suppressed_signals"]), 0)
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["total_signals"], 0)
        self.assertEqual(payload["summary"]["generated_search_tasks"], 24)
        self.assertEqual(payload["summary"]["suppressed"], 0)

    def test_osint_link_audit_marks_roles_and_clickability(self) -> None:
        with mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=OSError("network blocked")):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": True,
                        "includeSearchDorkSuggestions": True,
                        "maxSignals": 20,
                        "timeout": 2,
                        "passiveOnly": True,
                    }
                },
            )
        self.assertTrue(payload["url_audit"])
        self.assertTrue(all("url_role" in item and "browser_safe" in item and "render_as_clickable" in item for item in payload["url_audit"]))
        github_source = next(item for item in payload["sources"] if item["name"] == "public_code_search")
        self.assertEqual(github_source["url_role"], "machine_endpoint")
        self.assertFalse(github_source["render_as_clickable"])
        task = next(item for item in payload["operator_search_tasks"] if item.get("link"))
        self.assertEqual(task["url_role"], "manual_search_suggestion")
        self.assertTrue(task["browser_safe"])
        self.assertTrue(task["render_as_clickable"])
        html = render_osint_section({"osint": payload})
        self.assertNotIn('href="https://api.github.com/search/code"', html)
        self.assertIn("Üretilen suggestion_only görev; dış arama toplanmadı veya doğrulanmadı.", html)

    def test_manual_search_table_uses_descriptive_link_labels(self) -> None:
        with mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=OSError("network blocked")):
            payload = build_osint_enrichment(
                target="https://www.microsoft.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": True,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": True,
                        "maxSignals": 20,
                        "timeout": 2,
                    }
                },
            )
        html = render_osint_section({"osint": payload})
        self.assertNotIn(">Open query<", html)
        labels = set(re.findall(r'<a href="https://(?:www\.google\.com|github\.com)[^"]+"[^>]*>([^<]+)</a>', html))
        self.assertGreater(len(labels), 3)
        self.assertIn("GitHub .env aramasını aç", labels)
        self.assertIn("GitHub config aramasını aç", labels)
        self.assertIn("Google Swagger aramasını aç", labels)
        self.assertIn("Google API docs aramasını aç", labels)
        self.assertIn("Google PDF aramasını aç", labels)
        self.assertIn("Google e-posta pattern aramasını aç", labels)
        self.assertTrue(all(task["status"] == "suggestion_only" for task in payload["operator_search_tasks"]))
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["needs_manual_review"], 0)

    def test_dork_quality_classification_is_persisted(self) -> None:
        payload = build_osint_enrichment(
            target="acme.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeSearchDorkSuggestions": True,
                    "timeout": 2,
                    "passiveOnly": True,
                }
            },
        )
        qualities = {task["quality"] for task in payload["operator_search_tasks"]}
        categories = {task["category"] for task in payload["operator_search_tasks"]}
        self.assertIn("high_signal", qualities)
        self.assertIn("medium_signal", qualities)
        self.assertIn("noisy", qualities)
        self.assertIn("api_docs", categories)
        self.assertIn("documents", categories)
        self.assertEqual(payload["signals"], [])

    def test_generic_reserved_domain_dorks_are_downgraded_with_noise_note(self) -> None:
        payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeSearchDorkSuggestions": True,
                    "timeout": 2,
                    "passiveOnly": True,
                }
            },
        )
        qualities = {task["quality"] for task in payload["operator_search_tasks"]}
        self.assertNotIn("high_signal", qualities)
        self.assertIn("medium_signal", qualities)
        self.assertIn("noisy", qualities)
        self.assertTrue(payload["normalization"]["generic_or_reserved_domain"])
        self.assertTrue(
            all("Generic/example domains commonly produce documentation noise" in task["safety_note"] for task in payload["operator_search_tasks"])
        )

    def test_ct_asset_discovery_candidates_do_not_use_signal_cap(self) -> None:
        settings = {
            "osint": {
                "includeCertificateTransparency": True,
                "includeHistoricalUrls": False,
                "includePublicCodeReferences": False,
                "includeSearchDorkSuggestions": False,
                "maxSignals": 2,
                "timeout": 2,
                "passiveOnly": True,
            }
        }
        records = [
            {"name_value": "a.example.com\nb.example.com\nc.example.com"},
            {"name_value": "d.example.com"},
        ]
        with mock.patch("reconbot.orchestration.osint._fetch_json", return_value=records):
            payload = build_osint_enrichment(target="example.com", enabled=True, tool_settings=settings)
        self.assertEqual(payload["signals"], [])
        self.assertEqual(len(payload["asset_discovery_candidates"]), 4)
        self.assertEqual(payload["suppressed_signals"], [])
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["total_signals"], 0)
        self.assertEqual(payload["summary"]["asset_discovery_candidates"], 4)
        self.assertEqual(payload["verdict"], "asset_discovery_only")

    def test_report_generation_survives_osint_source_failures(self) -> None:
        with mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=OSError("network blocked")):
            payload = build_osint_enrichment(target="example.com", enabled=True)

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "run_result.json").write_text(
                json.dumps({"meta": {"target": "example.com", "mode": "domain_or_ip"}, "osint": payload}),
                encoding="utf-8",
            )
            generate_report({}, [], {}, {}, "example.com", "", skipped_tools=[], output_dir=run_dir, open_browser=False, quiet=True)
            html = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("OSINT Yönetici Özeti", html)
        self.assertIn("Manuel / API Gerektiren Arama Kısayolları", html)
        self.assertIn("Manuel arama önerileri bulgu değildir", html)
        self.assertIn("Gözlemlenmiş OSINT kanıtı toplanmadı", html)
        self.assertIn("Canlı pasif kaynaklar başarısız oldu veya kayıt döndürmedi", html)
        self.assertIn("Errors:", html)

    def test_diagnostics_source_health_records_failures(self) -> None:
        with mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=OSError("network blocked")):
            payload = build_osint_enrichment(target="example.com", enabled=True)
        diagnostics = payload["diagnostics"]
        self.assertEqual(diagnostics["http_connectivity"]["status"], "error")
        health_by_source = {item["source"]: item for item in diagnostics["source_health"]}
        self.assertEqual(health_by_source["certificate_transparency"]["status"], "error")
        self.assertEqual(health_by_source["historical_urls"]["status"], "error")
        self.assertEqual(health_by_source["public_code_search"]["status"], "auth_required")
        self.assertIn("OSError", str(payload["events"]) + str(payload["sources"]))

    def test_dns_runtime_self_check_is_recorded_and_only_rendered_on_failure(self) -> None:
        failure_diagnostic = {
            "python_executable": "/fake/python3",
            "python_version": "3.14.5",
            "sys_path_excerpt": ["/repo", "/site-packages"],
            "dns_resolver_import_ok": False,
            "dns_resolver_import_error": "ModuleNotFoundError: No module named 'dns'",
        }
        with mock.patch(
            "reconbot.orchestration.osint_core.organization.mail_dns.dns_runtime_diagnostic",
            return_value=failure_diagnostic,
        ):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": False,
                        "includePublicCodeReferences": False,
                        "includeKnownBreachCatalog": False,
                        "includeSearchDorkSuggestions": False,
                        "includeInfrastructureIntelligence": False,
                        "includeOrganizationIntelligence": False,
                    }
                },
            )
        self.assertEqual(payload["diagnostics"]["dns_runtime"], failure_diagnostic)
        failure_html = render_osint_section({"osint": payload})
        self.assertIn("DNS Runtime Self-Check", failure_html)
        self.assertIn("/fake/python3", failure_html)
        self.assertIn("ModuleNotFoundError: No module named &#x27;dns&#x27;", failure_html)

        success_diagnostic = {
            "python_executable": "/fake/python3",
            "python_version": "3.14.5",
            "sys_path_excerpt": ["/repo", "/site-packages"],
            "dns_resolver_import_ok": True,
        }
        payload["diagnostics"]["dns_runtime"] = success_diagnostic
        success_html = render_osint_section({"osint": payload})
        self.assertNotIn("DNS Runtime Self-Check", success_html)

    def test_source_health_report_surfaces_distinct_coverage_failures(self) -> None:
        html = render_osint_section(
            {
                "osint": {
                    "enabled": True,
                    "status": "partial",
                    "mode": "safe_mvp",
                    "summary": {
                        "observed_signals": 0,
                        "generated_search_tasks": 1,
                        "total_signals": 0,
                        "source_health": {
                            "attempted_live_sources": 3,
                            "completed": 0,
                            "partial": 1,
                            "error": 0,
                            "timeout": 1,
                            "unavailable": 0,
                            "auth_required_fallback": 1,
                            "rate_limited_fallback": 0,
                        },
                    },
                    "source_health": {
                        "attempted_live_sources": 3,
                        "completed": 0,
                        "partial": 1,
                        "error": 0,
                        "timeout": 1,
                        "unavailable": 0,
                        "auth_required_fallback": 1,
                        "rate_limited_fallback": 0,
                    },
                    "sources": [
                        {
                            "name": "certificate_transparency",
                            "status": "partial",
                            "provider_results": [
                                {
                                    "provider": "crt.sh",
                                    "status": "unavailable",
                                    "http_status": 502,
                                    "user_message": "crt.sh returned HTTP 502.",
                                }
                            ],
                        },
                        {"name": "historical_urls", "status": "timeout"},
                        {"name": "public_code_search", "status": "auth_required_fallback"},
                    ],
                    "operator_search_tasks": [{"source_name": "public_code_search", "status": "suggestion_only"}],
                    "diagnostics": {
                        "source_health": [
                            {"source": "certificate_transparency", "endpoint": "https://crt.sh/", "status": "provider_unavailable", "error": "", "error_class": "http_502"},
                            {"source": "historical_urls", "endpoint": "https://web.archive.org/cdx", "status": "timeout", "error": "timeout"},
                            {"source": "public_code_search", "endpoint": "https://api.github.com/search/code", "status": "auth_required", "error": "401"},
                        ]
                    },
                    "policy": {"passive_only": True, "risk_score_impact": "none"},
                }
            }
        )
        self.assertIn("<div class=\"value\">2</div>", html)
        self.assertIn("crt.sh: Kaynağa erişilemedi / HTTP 502 / CT kapsamı kısmi", html)
        self.assertIn("Wayback CDX zaman aşımına uğradı; geçmiş URL kapsamı kısmi", html)
        self.assertIn("GitHub: auth_required_fallback", html)
        self.assertIn("timeout 1", html)
        self.assertIn("auth_required 1", html)

    def test_partial_coverage_zero_evidence_summary_does_not_claim_clean(self) -> None:
        html = render_osint_section(
            {
                "osint": {
                    "enabled": True,
                    "status": "partial",
                    "mode": "safe_mvp",
                    "summary": {
                        "observed_signals": 0,
                        "generated_search_tasks": 1,
                        "total_signals": 0,
                        "source_health": {"attempted_live_sources": 2, "completed": 0, "timeout": 1, "auth_required_fallback": 1},
                    },
                    "source_health": {"attempted_live_sources": 2, "completed": 0, "timeout": 1, "auth_required_fallback": 1},
                    "sources": [
                        {"name": "historical_urls", "status": "timeout"},
                        {"name": "public_code_search", "status": "auth_required_fallback"},
                    ],
                    "operator_search_tasks": [{"source_name": "public_code_search", "status": "suggestion_only"}],
                    "policy": {"passive_only": True, "risk_score_impact": "none"},
                }
            }
        )
        self.assertIn("Bu rapor bazı OSINT kaynakları eksik kaldığı için kesin temiz sonucu değildir.", html)
        self.assertIn("Doğrulanmış bulgu görülmedi; ancak kaynak kapsamı kısmi kaldı.", html)
        self.assertIn("GitHub token olmadığı için canlı public code search yapılmadı; sadece manuel arama linkleri üretildi.", html)
        self.assertNotIn("Hiçbir şey yok", html)

    def test_osint_zero_counts_render_as_zero(self) -> None:
        html = render_osint_section(
            {
                "osint": {
                    "enabled": True,
                    "status": "completed",
                    "mode": "safe_mvp",
                    "summary": {
                        "observed_signals": 0,
                        "generated_search_tasks": 9,
                        "total_signals": 0,
                        "confirmed": 0,
                        "unconfirmed": 0,
                        "needs_manual_review": 0,
                        "suppressed": 0,
                        "highest_confidence": "none",
                        "risk_score_impact": "none",
                    },
                    "signals": [],
                    "operator_search_tasks": [{"source_name": "safe_search_dorks", "query": "site:example.com", "link": "https://example.test", "purpose": "Manual search task", "safety_note": "Suggestion only."}],
                    "suppressed_signals": [],
                    "sources": [],
                    "policy": {"passive_only": True, "risk_score_impact": "none"},
                }
            }
        )
        self.assertIn('<div class="value">0</div>', html)
        self.assertIn("Manuel / API Gerektiren Arama Kısayolları", html)
        self.assertIn("Manuel arama önerileri bulgu değildir", html)
        self.assertIn('<div class="value">9</div>', html)
        self.assertIn("Doğrulanmış: 0", html)
        self.assertIn("Bastırılan/gürültülü OSINT kanıt öğesi yok.", html)

    def test_report_renders_asset_identity_observations_separately(self) -> None:
        html = render_osint_section(
            {
                "osint": {
                    "enabled": True,
                    "status": "completed",
                    "mode": "safe_mvp",
                    "summary": {
                        "observed_signals": 0,
                        "asset_identity_observations": 2,
                        "generated_search_tasks": 19,
                        "total_signals": 0,
                        "confirmed": 0,
                        "unconfirmed": 0,
                        "needs_manual_review": 0,
                        "suppressed": 0,
                        "highest_confidence": "none",
                        "risk_score_impact": "none",
                    },
                    "signals": [],
                    "asset_identity_observations": [
                        {
                            "source_name": "certificate_transparency",
                            "source_provider": "certspotter",
                            "source_url": "https://api.certspotter.com/v1/issuances?domain=example.com",
                            "matched_entities": {"subdomains": ["example.com"]},
                            "evidence": {"snippet": "example.com observed in CT data via certspotter"},
                            "asset_identity_reason": "asset_identity_only",
                        }
                    ],
                    "operator_search_tasks": [],
                    "suppressed_signals": [],
                    "sources": [
                        {
                            "name": "certificate_transparency",
                            "status": "completed",
                            "signal_count": 0,
                            "asset_identity_count": 2,
                            "raw_count": 2,
                            "suppressed_count": 0,
                            "duration_ms": 10,
                            "notes": "Passive CT query completed.",
                            "provider_results": [
                                {
                                    "provider": "certspotter",
                                    "status": "completed",
                                    "raw_count": 2,
                                    "signal_count": 0,
                                    "asset_identity_count": 2,
                                    "errors": [],
                                }
                            ],
                        }
                    ],
                    "policy": {"passive_only": True, "risk_score_impact": "none"},
                    "normalization": {"generic_or_reserved_domain": True},
                }
            }
        )
        self.assertIn("Asset Identity Gözlemleri", html)
        self.assertIn("Root/www CT kayıtları", html)
        self.assertIn("asset_identity=2", html)
        self.assertIn("Generic/reserved domain notu", html)

    def test_report_renders_ct_provider_health_explicitly(self) -> None:
        html = render_osint_section(
            {
                "osint": {
                    "enabled": True,
                    "status": "partial",
                    "effective_status": "live_sources_partial",
                    "mode": "safe_mvp",
                    "summary": {
                        "observed_signals": 0,
                        "asset_identity_observations": 1,
                        "asset_discovery_candidates": 1,
                        "generated_search_tasks": 0,
                        "total_signals": 0,
                        "confirmed": 0,
                        "unconfirmed": 0,
                        "highest_confidence": "none",
                        "risk_score_impact": "none",
                    },
                    "signals": [],
                    "asset_discovery_candidates": [
                        {
                            "category": "asset_discovery_candidate",
                            "title": "CT subdomain candidate",
                            "source_name": "certificate_transparency",
                            "source_provider": "certspotter",
                            "source_url": "https://api.certspotter.com/v1/issuances?domain=badssl.com",
                            "provider_reference": "https://api.certspotter.com/v1/issuances?domain=badssl.com",
                            "matched_entities": {"subdomains": ["revoked.badssl.com"]},
                            "status": "asset_discovery_candidate",
                            "confidence": "medium",
                            "confidence_score": 55,
                            "exposure_priority": "medium",
                            "recommended_action": "Manual review.",
                            "url_role": "machine_endpoint",
                            "url_status": "not_checked",
                            "browser_safe": False,
                            "render_as_clickable": False,
                        }
                    ],
                    "asset_identity_observations": [
                        {
                            "source_name": "certificate_transparency",
                            "source_provider": "certspotter",
                            "matched_entities": {"subdomains": ["badssl.com"]},
                            "evidence": {"snippet": "badssl.com observed in CT data via certspotter"},
                        }
                    ],
                    "operator_search_tasks": [],
                    "suppressed_signals": [],
                    "sources": [
                        {
                            "name": "certificate_transparency",
                            "status": "partial",
                            "signal_count": 0,
                            "asset_identity_count": 1,
                            "asset_discovery_count": 1,
                            "raw_count": 2,
                            "suppressed_count": 0,
                            "duration_ms": 42,
                            "notes": "Passive CT query completed; candidates were not probed. Some CT provider queries failed.",
                            "errors": ["exact query failed: TimeoutError: crtsh slow"],
                            "provider_results": [
                                {
                                    "provider": "crtsh",
                                    "status": "error",
                                    "raw_count": 0,
                                    "signal_count": 0,
                                    "asset_identity_count": 0,
                                    "errors": ["exact query failed: TimeoutError: crtsh slow"],
                                    "queries_attempted": 2,
                                    "successful_queries": 0,
                                    "duration_ms": 20,
                                },
                                {
                                    "provider": "certspotter",
                                    "status": "completed",
                                    "raw_count": 2,
                                    "signal_count": 0,
                                    "asset_identity_count": 1,
                                    "asset_discovery_count": 1,
                                    "errors": [],
                                    "queries_attempted": 1,
                                    "successful_queries": 1,
                                    "duration_ms": 22,
                                },
                            ],
                        }
                    ],
                    "policy": {"passive_only": True, "risk_score_impact": "none"},
                }
            }
        )
        self.assertIn("Certificate Transparency Sağlayıcı Sağlığı", html)
        self.assertIn("Genel CT durumu", html)
        self.assertIn("partial", html)
        self.assertIn("crt.sh", html)
        self.assertIn("Hata / zaman aşımı", html)
        self.assertIn("certspotter", html)
        self.assertIn("Tamamlandı", html)
        self.assertIn("Gözlemlenen sinyaller", html)
        self.assertIn("Certificate Transparency Varlık Keşfi", html)
        self.assertIn("API kaynağı; browser kanıt linki değil", html)
        self.assertIn("https://api.certspotter.com/v1/issuances?domain=badssl.com", html)
        self.assertNotIn('href="https://api.certspotter.com/v1/issuances?domain=badssl.com"', html)
        self.assertIn("Asset Identity Gözlemleri", html)

    def test_report_shows_only_top_operator_tasks_before_collapsed_remainder(self) -> None:
        tasks = [
            {"source_name": "safe_search_dorks", "quality": "noisy", "category": "emails", "query": "noisy email", "purpose": "n", "safety_note": "n"},
            {"source_name": "safe_search_dorks", "quality": "medium_signal", "category": "documents", "query": "medium doc", "purpose": "m", "safety_note": "m"},
            {"source_name": "safe_search_dorks", "quality": "high_signal", "category": "api_docs", "query": "api swagger", "purpose": "a", "safety_note": "a"},
            {"source_name": "safe_search_dorks", "quality": "high_signal", "category": "config_terms", "query": "config env", "purpose": "c", "safety_note": "c"},
            {"source_name": "public_code_search", "quality": "high_signal", "category": "code_search", "query": "code env", "purpose": "c", "safety_note": "c"},
            {"source_name": "safe_search_dorks", "quality": "high_signal", "category": "general", "query": "admin login", "purpose": "g", "safety_note": "g"},
            {"source_name": "safe_search_dorks", "quality": "medium_signal", "category": "general", "query": "medium internal", "purpose": "m", "safety_note": "m"},
            {"source_name": "safe_search_dorks", "quality": "medium_signal", "category": "documents", "query": "medium xls", "purpose": "m", "safety_note": "m"},
            {"source_name": "safe_search_dorks", "quality": "noisy", "category": "general", "query": "noisy password", "purpose": "n", "safety_note": "n"},
            {"source_name": "safe_search_dorks", "quality": "noisy", "category": "general", "query": "noisy api_key", "purpose": "n", "safety_note": "n"},
        ]
        html = render_osint_section(
            {
                "osint": {
                    "enabled": True,
                    "status": "completed",
                    "mode": "safe_mvp",
                    "summary": {
                        "observed_signals": 0,
                        "generated_search_tasks": len(tasks),
                        "total_signals": 0,
                        "confirmed": 0,
                        "unconfirmed": 0,
                        "highest_confidence": "none",
                        "risk_score_impact": "none",
                    },
                    "signals": [],
                    "asset_identity_observations": [],
                    "operator_search_tasks": tasks,
                    "suppressed_signals": [],
                    "sources": [],
                    "policy": {"passive_only": True, "risk_score_impact": "none"},
                }
            }
        )
        self.assertIn("Manuel / API-gerekli arama kısayolları (10)", html)
        fallback_html = html.split('id="osint-manual-search-suggestions"', 1)[1]
        self.assertIn("safe_search_dorks", fallback_html)
        self.assertIn("public_code_search", fallback_html)
        self.assertIn("Üretilen suggestion_only görev; dış arama toplanmadı veya doğrulanmadı.", fallback_html)
        self.assertIn("<th>Kaynak</th><th>Amaç</th><th>Neden manuel?</th><th>Link</th><th>Risk etkisi</th>", fallback_html)

    def test_report_renders_github_auth_required_as_manual_fallback(self) -> None:
        html = render_osint_section(
            {
                "osint": {
                    "enabled": True,
                    "status": "partial",
                    "mode": "safe_mvp",
                    "summary": {"observed_signals": 0, "generated_search_tasks": 1, "total_signals": 0, "risk_score_impact": "none"},
                    "signals": [],
                    "asset_identity_observations": [],
                    "operator_search_tasks": [{"source_name": "public_code_search", "quality": "high_signal", "category": "code_search", "query": "github fallback", "purpose": "Manual.", "safety_note": "Suggestion only."}],
                    "suppressed_signals": [],
                    "sources": [
                        {
                            "name": "public_code_search",
                            "status": "auth_required_fallback",
                            "signal_count": 0,
                            "asset_identity_count": 0,
                            "raw_count": 0,
                            "suppressed_count": 0,
                            "duration_ms": 1,
                            "notes": "GitHub live code search requires authentication or was not authorized; manual search tasks generated.",
                            "errors": ["GitHub API auth_required: HTTPError 401"],
                        }
                    ],
                    "policy": {"passive_only": True, "risk_score_impact": "none"},
                }
            }
        )
        self.assertIn("GitHub canlı kod araması kimlik doğrulama gerektiriyor. Bu yüzden sadece manuel arama önerileri üretildi.", html)
        self.assertIn("auth_required_fallback", html)

    def test_report_translates_final_visible_source_messages_without_mutating_raw_payload(self) -> None:
        raw_verdict = "Passive public sources produced 1 observed evidence item(s). Manual search tasks are suggestions only and do not affect risk score."
        raw_safe_search = "Generated safe operator-run search suggestions only."
        raw_asn = "No local ASN database was available; passive lookup links were generated."
        raw_infra = "Infrastructure enrichment is passive DNS/metadata context only; it is not exposure evidence."
        raw_cdn = "This IP may represent CDN/proxy/edge infrastructure and may not be the target origin."
        raw_wayback = "Wayback CDX timed out; absence of historical URLs is not conclusive."
        raw_github = "GitHub live code search requires authentication; manual search suggestions generated."
        raw_crtsh = "crt.sh unavailable during this run; CT coverage is partial."
        payload = {
            "enabled": True,
            "status": "partial",
            "mode": "safe_mvp",
            "verdict_reason": raw_verdict,
            "summary": {"observed_signals": 1, "generated_search_tasks": 1, "total_signals": 1, "risk_score_impact": "none"},
            "signals": [
                {
                    "category": "public_code_reference",
                    "title": "Public code reference",
                    "source_name": "public_code_search",
                    "confidence": "medium",
                    "confidence_score": 50,
                    "exposure_priority": "medium",
                    "evidence": {"snippet": "metadata-only public reference"},
                    "recommended_action": "No action required.",
                }
            ],
            "asset_identity_observations": [],
            "operator_search_tasks": [
                {
                    "source_name": "safe_search_dorks",
                    "query": "site:example.com",
                    "link": "https://example.test",
                    "purpose": "Manual search task",
                    "safety_note": "Suggestion only.",
                }
            ],
            "suppressed_signals": [],
            "sources": [
                {"name": "safe_search_dorks", "status": "suggestions_generated", "notes": raw_safe_search, "signal_count": 0, "asset_identity_count": 0, "raw_count": 0, "suppressed_count": 0},
                {"name": "historical_urls", "status": "timeout", "notes": raw_wayback, "signal_count": 0, "asset_identity_count": 0, "raw_count": 0, "suppressed_count": 0},
                {"name": "public_code_search", "status": "auth_required_fallback", "notes": raw_github, "signal_count": 0, "asset_identity_count": 0, "raw_count": 0, "suppressed_count": 0},
                {
                    "name": "certificate_transparency",
                    "status": "partial",
                    "signal_count": 0,
                    "asset_identity_count": 0,
                    "raw_count": 0,
                    "suppressed_count": 0,
                    "provider_results": [{"provider": "crtsh", "status": "unavailable", "user_message": raw_crtsh, "http_status": 502}],
                },
            ],
            "infrastructure": {
                "target_host": "example.com",
                "target_registered_domain": "example.com",
                "resolved_ips": ["203.0.113.10"],
                "dns_status": "completed",
                "cdn_or_proxy_likely": True,
                "origin_confidence": "low",
                "caveat": raw_cdn,
                "ip_ownership": [{"ip": "203.0.113.10", "ip_version": 4, "enrichment_status": "unavailable", "confidence": "low"}],
                "passive_lookup_links": [],
            },
            "diagnostics": {
                "source_health": [
                    {"source": "infrastructure", "endpoint": "", "status": "partial", "error": "", "user_message": raw_asn},
                    {"source": "infrastructure", "endpoint": "", "status": "partial", "error": "", "user_message": raw_infra},
                ]
            },
            "policy": {"passive_only": True, "risk_score_impact": "none"},
        }
        html = render_osint_section({"osint": payload})
        for phrase in (
            raw_safe_search,
            "Passive public sources produced",
            "Manual search tasks are suggestions only",
            raw_asn,
            "Infrastructure enrichment is passive",
            "Wayback CDX timed out",
            "GitHub live code search requires authentication",
            "crt.sh unavailable during this run",
        ):
            self.assertNotIn(phrase, html)
        for phrase in (
            "Yalnızca operatörün manuel çalıştıracağı güvenli arama önerileri üretildi",
            "Manuel arama görevleri sadece öneridir ve risk skorunu etkilemez",
            "Yerel ASN veritabanı bulunamadı",
            "Altyapı zenginleştirmesi yalnızca pasif DNS/metadata bağlamıdır",
            "Wayback CDX zaman aşımına uğradı",
            "GitHub canlı kod araması kimlik doğrulama gerektiriyor",
            "Bu çalıştırmada crt.sh erişilemedi",
        ):
            self.assertIn(phrase, html)
        self.assertEqual(payload["verdict_reason"], raw_verdict)
        self.assertEqual(payload["sources"][0]["notes"], raw_safe_search)
        self.assertEqual(payload["diagnostics"]["source_health"][0]["user_message"], raw_asn)
        self.assertEqual(payload["infrastructure"]["caveat"], raw_cdn)

    def test_osint_overview_is_evidence_first_and_demotes_manual_shortcuts(self) -> None:
        html = render_osint_section(
            {
                "osint": {
                    "enabled": True,
                    "status": "completed",
                    "mode": "safe_mvp",
                    "summary": {"observed_signals": 1, "generated_search_tasks": 1, "total_signals": 1, "risk_score_impact": "none"},
                    "signals": [
                        {
                            "category": "known_breach_reference",
                            "title": "Public breach catalog reference",
                            "status": "needs_manual_review",
                            "source_name": "known_breach_catalog",
                            "source_url": "https://haveibeenpwned.com/Breach/7-Eleven",
                            "url_role": "observed_evidence_link",
                            "url_status": "validated",
                            "browser_safe": True,
                            "render_as_clickable": True,
                            "evidence": {"snippet": "Public breach catalog reference found: 7-Eleven Data Breach"},
                            "risk_score_impact": 0,
                        }
                    ],
                    "asset_identity_observations": [],
                    "operator_search_tasks": [
                        {
                            "source_name": "safe_search_dorks",
                            "category": "emails",
                            "query": '"@7-eleven.com"',
                            "link": "https://www.google.com/search?q=%22%407-eleven.com%22",
                            "status": "suggestion_only",
                            "url_role": "manual_search_suggestion",
                            "check_policy": "manual_only",
                        }
                    ],
                    "suppressed_signals": [],
                    "sources": [
                        {
                            "name": "known_breach_catalog",
                            "status": "completed_matched",
                            "signal_count": 1,
                            "raw_count": 1,
                            "report_url": "https://haveibeenpwned.com/Breach/7-Eleven",
                            "report_url_status": "validated",
                            "match_status": "matched",
                            "url_role": "source_report_link",
                            "browser_safe": True,
                            "render_as_clickable": True,
                        },
                        {
                            "name": "safe_search_dorks",
                            "status": "suggestions_generated",
                            "signal_count": 0,
                            "raw_count": 1,
                        },
                    ],
                    "organization_intelligence": {
                        "summary": {
                            "observed_public_contacts": 2,
                            "observed_locations": 0,
                            "validated_public_documents": 1,
                            "observed_official_social_profiles": 0,
                        },
                        "contact_intelligence": {
                            "observed_email_addresses": [{"email": "privacy@7-eleven.com"}],
                            "observed_phone_numbers": [{"phone": "+1-800-255-0711"}],
                            "observed_contact_urls": [],
                            "observed_contact_forms": [],
                            "generated_role_email_candidates": [{"email": "security@7-eleven.com", "status": "generated_guess"}],
                        },
                        "public_document_intelligence": {
                            "validated_public_documents": [{"url": "https://www.7-eleven.com/privacy", "title": "Privacy"}],
                        },
                    },
                    "infrastructure": {"dns_status": "resolved", "resolved_ips": ["203.0.113.10"], "ipv6_addresses": []},
                    "source_health": {"attempted_live_sources": 1, "completed": 1, "partial": 0, "error": 0, "timeout": 0, "unavailable": 0, "auth_required_fallback": 0, "rate_limited_fallback": 0},
                    "policy": {"passive_only": True, "risk_score_impact": "none"},
                }
            }
        )
        board = html.split('id="osint-intelligence-board"', 1)[1].split('<h3 id="osint-overview"', 1)[0]
        self.assertIn("ReconBot Ne Öğrendi?", board)
        self.assertIn("Herkese açık ihlal/sızıntı referansları", board)
        self.assertIn("Herkese açık ihlal/sızıntı metadata referansı görüldü.", board)
        leak_section = html.split('id="osint-leak-breach-intelligence"', 1)[1].split('id="osint-overview"', 1)[0]
        self.assertIn("Açık kaynaklardan herkese açık ihlal/sızıntı metadata referansı gözlemlenmedi.", leak_section)
        self.assertIn('href="https://haveibeenpwned.com/Breach/7-Eleven"', html)
        self.assertIn("Herkese açık iletişim bilgileri", board)
        self.assertIn("2", board)
        self.assertIn("Herkese açık dokümanlar", board)
        self.assertIn("1", board)
        self.assertNotIn("security@7-eleven.com", board)
        self.assertNotIn("google.com/search", board)
        summary_block = html.split("<strong>OSINT Bulgu Özeti</strong>", 1)[1].split('<div class="kpi-grid overview-core-grid">', 1)[0]
        self.assertIn("Gözlemlenmiş kanıt raporu: 1; gözlemlenmiş ihlal kataloğu referansı: 1.", summary_block)
        self.assertIn("Kanıt raporunu aç: HIBP /Breach/7-Eleven", summary_block)
        self.assertIn('href="https://haveibeenpwned.com/Breach/7-Eleven"', summary_block)
        self.assertIn("Tam hedef herkese açık iletişim bilgisi: toplam 2, telefon 1", summary_block)
        self.assertIn("Tam hedef herkese açık doküman: 1", summary_block)
        self.assertIn("Kullanılabilir manuel/API-gerekli arama kısayolu: 1. Bunlar bulgu değildir.", summary_block)
        self.assertNotIn("security@7-eleven.com", summary_block)
        self.assertNotIn("google.com/search", summary_block)

    def test_osint_report_shows_affiliate_public_documents_as_context(self) -> None:
        html = render_osint_section(
            {
                "osint": {
                    "enabled": True,
                    "status": "completed",
                    "mode": "safe_mvp",
                    "summary": {
                        "observed_signals": 0,
                        "generated_search_tasks": 0,
                        "total_signals": 0,
                        "risk_score_impact": "none",
                    },
                    "signals": [],
                    "asset_identity_observations": [],
                    "operator_search_tasks": [],
                    "suppressed_signals": [],
                    "sources": [],
                    "organization_intelligence": {
                        "summary": {
                            "target_validated_public_documents": 0,
                            "parent_org_validated_public_documents": 0,
                            "affiliate_validated_public_documents": 1,
                            "public_document_search_tasks": 2,
                        },
                        "public_document_intelligence": {
                            "validated_public_documents": [
                                {
                                    "url": "https://affiliate.example.com/privacy",
                                    "title": "Affiliate privacy notice",
                                    "label": "Affiliate privacy notice",
                                    "scope_origin": "official_affiliate_domain",
                                    "applies_to_target": False,
                                    "browser_safe": True,
                                    "render_as_clickable": True,
                                    "url_role": "validated_public_document",
                                    "url_status": "checked_ok",
                                }
                            ],
                            "manual_document_search_shortcuts": [
                                {"label": "PDF search", "url": "https://www.google.com/search?q=example+filetype%3Apdf"},
                                {"label": "Sitemap search", "url": "https://www.google.com/search?q=site%3Aexample.com+sitemap"},
                            ],
                        },
                    },
                    "policy": {"passive_only": True, "risk_score_impact": "none"},
                }
            }
        )
        board = html.split('id="osint-intelligence-board"', 1)[1].split('<h3 id="osint-overview"', 1)[0]
        self.assertIn("Herkese açık dokümanlar", board)
        self.assertIn("tam hedef 0; üst kurum 0; bağlı/harici 1; manuel öneri 2", board)
        self.assertIn("Bağlı/harici resmî kaynak herkese açık dokümanı bulundu; tam hedef kanıtı değildir.", board)
        self.assertNotIn("No validated public document was found", board)
        document_section = html.split('id="osint-public-document-intelligence"', 1)[1].split('id="osint-people-organization-presence"', 1)[0]
        self.assertIn("Tam hedef herkese açık dokümanları", document_section)
        self.assertIn("Üst kurum herkese açık dokümanları", document_section)
        self.assertIn("Bağlı/harici resmî herkese açık dokümanlar", document_section)
        self.assertIn("Manuel doküman arama kısayolları", document_section)
        self.assertIn("Resmî bağlı veya harici doğrulanmış kaynak bağlamı; tam hedef kanıtı değildir.", document_section)

    def test_report_renders_wayback_timeout_as_source_issue(self) -> None:
        html = render_osint_section(
            {
                "osint": {
                    "enabled": True,
                    "status": "partial",
                    "mode": "safe_mvp",
                    "summary": {"observed_signals": 0, "generated_search_tasks": 0, "total_signals": 0, "risk_score_impact": "none"},
                    "signals": [],
                    "asset_identity_observations": [],
                    "operator_search_tasks": [],
                    "suppressed_signals": [],
                    "sources": [
                        {
                            "name": "historical_urls",
                            "status": "error",
                            "signal_count": 0,
                            "asset_identity_count": 0,
                            "raw_count": 0,
                            "suppressed_count": 0,
                            "duration_ms": 1000,
                            "notes": "Wayback CDX source unavailable/slow from this environment. This does not prove absence of historical URLs.",
                            "errors": ["TimeoutError: slow"],
                        }
                    ],
                    "policy": {"passive_only": True, "risk_score_impact": "none"},
                }
            }
        )
        self.assertIn("Wayback CDX bu ortamda erişilemedi veya yavaş kaldı", html)
        self.assertNotIn('<span class="pill bad">error</span>', html)

    def test_report_renders_known_breach_section_separately(self) -> None:
        html = render_osint_section(
            {
                "osint": {
                    "enabled": True,
                    "status": "completed",
                    "mode": "safe_mvp",
                    "summary": {"observed_signals": 1, "generated_search_tasks": 0, "total_signals": 1, "risk_score_impact": "none"},
                    "signals": [
                        {
                            "category": "known_breach_reference",
                            "title": "Public breach catalog reference",
                            "status": "needs_manual_review",
                            "confidence": "high",
                            "confidence_score": 75,
                            "exposure_priority": "review",
                            "source_name": "known_breach_catalog",
                            "source_provider": "haveibeenpwned",
                            "source_url": "https://haveibeenpwned.com/Breach/7-Eleven",
                            "matched_entities": {"domains": ["www.7-eleven.com"], "urls": ["https://haveibeenpwned.com/Breach/7-Eleven"], "keywords": ["7-Eleven"]},
                            "evidence": {"snippet": "Public breach catalog reference found: 7-Eleven Data Breach"},
                            "recommended_action": "Review manually.",
                            "breach_name": "7-Eleven Data Breach",
                            "breach_date": "2024-08-08",
                            "added_date": "2024-09-01",
                            "affected_accounts": 164000,
                            "compromised_data_classes": ["Dates of birth", "Email addresses", "Names", "Phone numbers", "Physical addresses"],
                            "matched_alias": "7-Eleven",
                            "confidence_reason": "Breach catalog name closely matches generated organization alias.",
                        }
                    ],
                    "asset_identity_observations": [],
                    "operator_search_tasks": [],
                    "suppressed_signals": [],
                    "sources": [{"name": "known_breach_catalog", "status": "completed", "signal_count": 1, "raw_count": 1, "suppressed_count": 0, "duration_ms": 1}],
                    "leak_intelligence": {
                        "enabled": True,
                        "status": "completed",
                        "live_collection_performed": True,
                        "summary": {
                            "observed_references": 1,
                            "suppressed_sensitive_items": 0,
                            "credential_material_collected": False,
                            "raw_secret_collected": False,
                            "risk_score_impact": "none",
                        },
                        "results": [
                            {
                                "source_name": "known_breach_catalog",
                                "source_type": "public_breach_catalog",
                                "status": "completed",
                                "observed_references": [
                                    {
                                        "title": "7-Eleven Data Breach",
                                        "reference_url": "https://haveibeenpwned.com/Breach/7-Eleven",
                                        "browser_safe": True,
                                        "render_as_clickable": True,
                                        "source_provider": "haveibeenpwned",
                                        "matched_entities": {"domains": ["www.7-eleven.com"], "keywords": ["7-Eleven"], "matched_alias": "7-Eleven"},
                                        "match_type": "brand_alias",
                                        "confidence": "high",
                                        "confidence_reason": "Breach catalog name closely matches generated organization alias.",
                                        "scope_origin": "external_verified_source",
                                        "applies_to_target": "unknown",
                                        "applies_to_parent_org": False,
                                        "requested_target_host": "www.7-eleven.com",
                                        "requested_registered_domain": "7-eleven.com",
                                        "observed_on_host": "haveibeenpwned.com",
                                        "observed_on_registered_domain": "haveibeenpwned.com",
                                        "scope_caveat": "Public third-party breach metadata requires manual relevance validation.",
                                        "evidence_type": "public_breach_metadata",
                                        "breach_date": "2024-08-08",
                                        "affected_accounts": 164000,
                                        "compromised_data_classes": ["Dates of birth", "Email addresses", "Names", "Phone numbers", "Physical addresses"],
                                        "redacted_snippet": "Public breach catalog reference found: 7-Eleven Data Breach",
                                        "raw_secret_collected": False,
                                        "credential_material_collected": False,
                                        "account_validated": False,
                                        "risk_score_impact": 0,
                                        "recommended_action": "Manually validate organization relevance; do not collect credentials.",
                                    }
                                ],
                                "suppressed_sensitive_items": [],
                                "source_health_row": {"source": "known_breach_catalog", "status": "ok", "source_status": "completed", "latency_ms": 1},
                                "operator_notes": [],
                                "risk_score_impact": 0,
                            }
                        ],
                        "source_health": [{"source": "known_breach_catalog", "status": "ok", "source_status": "completed", "latency_ms": 1, "endpoint": "https://haveibeenpwned.com/api/v3/breaches"}],
                    },
                    "policy": {"passive_only": True, "risk_score_impact": "none"},
                }
            }
        )
        self.assertIn("Darkweb / Sızıntı / İhlal İstihbaratı", html)
        self.assertIn("Gelişmiş / Eski Uyumluluk Teşhisleri", html)
        self.assertIn("Bunlar üçüncü taraf herkese açık ihlal referanslarıdır; aktif scan bulgusu değildir.", html)
        self.assertIn("Herkese açık ihlal kataloğunda 7-Eleven Data Breach için metadata referansı görüldü", html)
        self.assertIn("İhlal kataloğundaki ad, ReconBot&#x27;un ürettiği kurum alias&#x27;ı ile yakın eşleşiyor.", html)
        self.assertIn("Doğum tarihleri, E-posta adresleri, İsimler, Telefon numaraları, Fiziksel adresler", html)
        self.assertIn("Üçüncü taraf herkese açık ihlal metadata&#x27;sı için kurum ilişkisi manuel doğrulanmalıdır.", html)
        self.assertIn("Kurumla gerçekten ilişkili olup olmadığını manuel doğrula; kimlik bilgisi toplama.", html)
        self.assertNotIn("Breach catalog name matches a generated organization alias.", html)
        self.assertNotIn("Breach catalog name closely matches generated organization alias.", html)
        self.assertNotIn("Public third-party breach metadata requires manual relevance validation.", html)
        self.assertNotIn("Dates of birth, Email addresses", html)
        primary_signals_html = html.split("<h3>Gözlemlenen OSINT Kanıtları</h3>", 1)[1].split("<h3>Gelişmiş / Eski Uyumluluk Teşhisleri</h3>", 1)[0]
        self.assertNotIn("known_breach_reference", primary_signals_html)
        self.assertNotIn("Public breach catalog reference found: 7-Eleven Data Breach", primary_signals_html)
        self.assertNotIn("ReconBot confirmed leak", html)
        self.assertNotIn("credentials found", html)

    def test_report_renders_known_breach_empty_state_as_no_match(self) -> None:
        html = render_osint_section(
            {
                "osint": {
                    "enabled": True,
                    "status": "completed",
                    "verdict": "no_observed_evidence",
                    "verdict_reason": "Live passive sources completed or returned no matching public records.",
                    "mode": "safe_mvp",
                    "summary": {"observed_signals": 0, "generated_search_tasks": 0, "total_signals": 0, "risk_score_impact": "none"},
                    "signals": [],
                    "asset_identity_observations": [],
                    "operator_search_tasks": [],
                    "suppressed_signals": [],
                    "sources": [
                        {
                            "name": "known_breach_catalog",
                            "status": "completed_no_match",
                            "outcome": "alias_not_found",
                            "signal_count": 0,
                            "asset_identity_count": 0,
                            "raw_count": 0,
                            "suppressed_count": 0,
                            "duration_ms": 1,
                            "notes": "No reliable public breach catalog reference matched generated aliases.",
                            "errors": [],
                            "alias_attempts": [
                                {
                                    "alias": "clean-example.biz",
                                    "slug": "Clean-Example",
                                    "page_status": "not_found",
                                    "api_status": "alias_not_found",
                                    "outcome": "no_match",
                                }
                            ],
                        }
                    ],
                    "source_health": {"attempted_live_sources": 1, "completed": 0, "partial": 0, "error": 0, "no_match": 1, "suggestions_only": 0},
                    "leak_intelligence": {
                        "enabled": True,
                        "status": "no_match",
                        "live_collection_performed": True,
                        "summary": {
                            "observed_references": 0,
                            "suppressed_sensitive_items": 0,
                            "credential_material_collected": False,
                            "raw_secret_collected": False,
                            "risk_score_impact": "none",
                        },
                        "results": [
                            {
                                "source_name": "known_breach_catalog",
                                "source_type": "public_breach_catalog",
                                "status": "no_match",
                                "observed_references": [],
                                "suppressed_sensitive_items": [],
                                "source_health_row": {
                                    "source": "known_breach_catalog",
                                    "status": "no_match",
                                    "source_status": "no_match",
                                    "latency_ms": 1,
                                    "endpoint": "https://haveibeenpwned.com/api/v3/breaches",
                                    "browser_safe": False,
                                    "render_as_clickable": False,
                                    "risk_score_impact": 0,
                                },
                                "operator_notes": [],
                                "risk_score_impact": 0,
                            }
                        ],
                        "source_health": [
                            {
                                "source": "known_breach_catalog",
                                "status": "no_match",
                                "source_status": "no_match",
                                "latency_ms": 1,
                                "endpoint": "https://haveibeenpwned.com/api/v3/breaches",
                                "user_message": "",
                            }
                        ],
                    },
                    "policy": {"passive_only": True, "risk_score_impact": "none"},
                }
            }
        )
        self.assertIn("Darkweb / Sızıntı / İhlal İstihbaratı", html)
        self.assertIn("Açık kaynaklardan herkese açık ihlal/sızıntı metadata referansı gözlemlenmedi.", html)
        self.assertIn("Kanıt yokluğu kesin sonuç değildir.", html)
        self.assertIn("Gelişmiş / Eski Uyumluluk Teşhisleri", html)
        self.assertIn("Üretilen alias değerleriyle güvenilir herkese açık ihlal kataloğu referansı eşleşmedi.", html)
        self.assertIn("Eşleşme yok", html)
        self.assertNotIn("Public breach catalog reference found", html)
        self.assertNotIn(">error<", html)

    def test_report_renders_metadata_feed_grouped_and_not_configured_as_coverage_only(self) -> None:
        html = render_osint_section(
            {
                "osint": {
                    "enabled": True,
                    "status": "completed",
                    "mode": "safe_mvp",
                    "summary": {"observed_signals": 0, "generated_search_tasks": 0, "total_signals": 0, "risk_score_impact": "none"},
                    "signals": [],
                    "asset_identity_observations": [],
                    "operator_search_tasks": [],
                    "suppressed_signals": [],
                    "sources": [],
                    "leak_intelligence": {
                        "enabled": True,
                        "status": "completed",
                        "live_collection_performed": True,
                        "enabled_collectors_count": 2,
                        "summary": {
                            "observed_references": 1,
                            "suppressed_sensitive_items": 0,
                            "credential_material_collected": False,
                            "raw_secret_collected": False,
                            "risk_score_impact": "none",
                        },
                        "results": [
                            {
                                "source_name": "local_test_feed",
                                "source_type": "leak_metadata_api",
                                "status": "completed",
                                "observed_references": [
                                    {
                                        "title": "Example feed reference",
                                        "reference_url": "https://example.com/report/example",
                                        "browser_safe": True,
                                        "render_as_clickable": True,
                                        "source_provider": "example_provider",
                                        "matched_entities": {"domains": ["example.com"], "brands": ["Example"], "matched": ["example.com"]},
                                        "match_type": "exact_domain",
                                        "confidence": "high",
                                        "confidence_reason": "Feed metadata explicitly matched the requested target host.",
                                        "scope_origin": "external_verified_source",
                                        "applies_to_target": True,
                                        "applies_to_parent_org": False,
                                        "requested_target_host": "example.com",
                                        "requested_registered_domain": "example.com",
                                        "observed_on_host": "example.com",
                                        "observed_on_registered_domain": "example.com",
                                        "scope_caveat": "Metadata-only external reference; relevance to the exact target must be reviewed manually.",
                                        "evidence_type": "public_leak_metadata",
                                        "affected_accounts": 12345,
                                        "breach_date": "2026-04-01",
                                        "compromised_data_classes": ["Email addresses"],
                                        "redacted_snippet": "Metadata-only public report mention.",
                                        "raw_secret_collected": False,
                                        "credential_material_collected": False,
                                        "account_validated": False,
                                        "risk_score_impact": 0,
                                        "recommended_action": "Manually validate organization relevance; do not collect credentials.",
                                    }
                                ],
                                "suppressed_sensitive_items": [],
                                "source_health_row": {"source": "local_test_feed", "status": "completed", "source_status": "completed", "latency_ms": 1},
                                "operator_notes": [],
                                "risk_score_impact": 0,
                            },
                            {
                                "source_name": "other_feed",
                                "source_type": "leak_metadata_api",
                                "status": "not_configured",
                                "observed_references": [],
                                "suppressed_sensitive_items": [],
                                "source_health_row": {"source": "other_feed", "status": "not_configured", "source_status": "not_configured", "latency_ms": 1},
                                "operator_notes": [],
                                "risk_score_impact": 0,
                            },
                        ],
                        "source_health": [
                            {"source": "local_test_feed", "status": "completed", "source_status": "completed", "latency_ms": 1, "endpoint": "local_json_feed"},
                            {"source": "other_feed", "status": "not_configured", "source_status": "not_configured", "latency_ms": 1, "endpoint": "", "user_message": "Metadata feed collector is enabled but no feedPath or feedUrl is configured."},
                        ],
                    },
                    "policy": {"passive_only": True, "risk_score_impact": "none"},
                }
            }
        )
        self.assertIn("Darkweb / Sızıntı / İhlal İstihbaratı", html)
        self.assertIn("Açık collector sayısı", html)
        self.assertIn("Example feed reference", html)
        self.assertIn("example_provider / local_test_feed", html)
        self.assertIn('href="https://example.com/report/example"', html)
        self.assertIn("<code>other_feed</code>", html)
        self.assertIn("not_configured", html)
        self.assertNotIn("ReconBot did not collect credentials", html)
        self.assertIn("ReconBot kimlik bilgisi, parola, hash, token", html)

    def test_wayback_timeout_keeps_observed_signals_zero(self) -> None:
        with mock.patch("reconbot.orchestration.osint._fetch_json", side_effect=TimeoutError("slow")):
            payload = build_osint_enrichment(
                target="example.com",
                enabled=True,
                tool_settings={
                    "osint": {
                        "includeCertificateTransparency": False,
                        "includeHistoricalUrls": True,
                        "includePublicCodeReferences": False,
                        "includeSearchDorkSuggestions": True,
                        "maxSignals": 20,
                        "timeout": 1,
                        "passiveOnly": True,
                    }
                },
            )
        wayback = next(item for item in payload["sources"] if item["name"] == "historical_urls")
        self.assertEqual(wayback["status"], "timeout")
        self.assertEqual(wayback["error_class"], "timeout")
        self.assertIn("absence of historical URLs is not conclusive", wayback["user_message"])
        self.assertIn("TimeoutError", wayback["notes"])
        self.assertEqual(payload["summary"]["observed_signals"], 0)
        self.assertEqual(payload["summary"]["generated_search_tasks"], 19)
        self.assertNotEqual(payload["verdict"], "no_observed_evidence")

    def test_osint_persists_normalization_and_events(self) -> None:
        payload = build_osint_enrichment(
            target="http://zekagucu.turkcell.com.tr/path?q=1",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeSearchDorkSuggestions": True,
                    "timeout": 2,
                }
            },
        )
        self.assertEqual(payload["normalization"]["target_host"], "zekagucu.turkcell.com.tr")
        self.assertEqual(payload["normalization"]["target_domain"], "zekagucu.turkcell.com.tr")
        self.assertEqual(payload["normalization"]["target_registered_domain"], "turkcell.com.tr")
        self.assertEqual(payload["normalization"]["scope_mode"], "exact_host")
        self.assertFalse(payload["normalization"]["parent_domain_expansion"])
        self.assertFalse(payload["normalization"]["generic_or_reserved_domain"])
        self.assertTrue(payload["events"])
        self.assertTrue(any("target normalized: zekagucu.turkcell.com.tr" in event["message"] for event in payload["events"]))

    def test_osint_does_not_change_report_risk_score(self) -> None:
        osint_payload = build_osint_enrichment(
            target="example.com",
            enabled=True,
            tool_settings={
                "osint": {
                    "includeCertificateTransparency": False,
                    "includeHistoricalUrls": False,
                    "includePublicCodeReferences": False,
                    "includeSearchDorkSuggestions": True,
                    "maxSignals": 5,
                    "timeout": 2,
                    "passiveOnly": True,
                }
            },
        )

        def render_score(with_osint: bool) -> int:
            with tempfile.TemporaryDirectory() as tmp:
                run_dir = Path(tmp)
                payload = {"meta": {"target": "example.com", "mode": "domain_or_ip"}}
                if with_osint:
                    payload["osint"] = osint_payload
                (run_dir / "run_result.json").write_text(json.dumps(payload), encoding="utf-8")
                generate_report({}, [], {}, {}, "example.com", "", skipped_tools=[], output_dir=run_dir, open_browser=False, quiet=True)
                html = (run_dir / "report.html").read_text(encoding="utf-8")
            match = re.search(r'<div class="label">\s*Risk Skoru\s*</div>\s*<div class="value">\s*(\d+)\s*/\s*100', html)
            self.assertIsNotNone(match)
            return int(match.group(1))

        self.assertEqual(render_score(with_osint=False), render_score(with_osint=True))

    def test_known_breach_reference_does_not_change_report_risk_score(self) -> None:
        osint_payload = {
            "enabled": True,
            "status": "completed",
            "mode": "safe_mvp",
            "summary": {
                "observed_signals": 1,
                "generated_search_tasks": 0,
                "total_signals": 1,
                "confirmed": 0,
                "unconfirmed": 0,
                "needs_manual_review": 1,
                "suppressed": 0,
                "highest_confidence": "high",
                "risk_score_impact": "none",
            },
            "signals": [
                {
                    "category": "known_breach_reference",
                    "title": "Public breach catalog reference",
                    "status": "needs_manual_review",
                    "confidence": "high",
                    "confidence_score": 75,
                    "source_name": "known_breach_catalog",
                    "source_provider": "haveibeenpwned",
                    "source_url": "https://haveibeenpwned.com/Breach/7-Eleven",
                    "matched_entities": {"domains": ["www.7-eleven.com"], "urls": ["https://haveibeenpwned.com/Breach/7-Eleven"], "keywords": ["7-Eleven"]},
                    "evidence": {"snippet": "Public breach catalog reference found: 7-Eleven Data Breach"},
                    "validation_notes": ["No credential material was collected."],
                    "recommended_action": "Review manually.",
                    "exposure_priority": "review",
                    "risk_score_impact": 0,
                    "breach_name": "7-Eleven Data Breach",
                    "matched_alias": "7-Eleven",
                    "confidence_reason": "Breach catalog name closely matches generated organization alias.",
                }
            ],
            "asset_identity_observations": [],
            "operator_search_tasks": [],
            "suppressed_signals": [],
            "sources": [{"name": "known_breach_catalog", "status": "completed", "signal_count": 1, "raw_count": 1, "suppressed_count": 0}],
            "policy": {"passive_only": True, "risk_score_impact": "none"},
        }

        def render_score(with_osint: bool) -> int:
            with tempfile.TemporaryDirectory() as tmp:
                run_dir = Path(tmp)
                payload = {"meta": {"target": "www.7-eleven.com", "mode": "domain_or_ip"}}
                if with_osint:
                    payload["osint"] = osint_payload
                (run_dir / "run_result.json").write_text(json.dumps(payload), encoding="utf-8")
                generate_report({}, [], {}, {}, "www.7-eleven.com", "", skipped_tools=[], output_dir=run_dir, open_browser=False, quiet=True)
                html = (run_dir / "report.html").read_text(encoding="utf-8")
            match = re.search(r'<div class="label">\s*Risk Skoru\s*</div>\s*<div class="value">\s*(\d+)\s*/\s*100', html)
            self.assertIsNotNone(match)
            return int(match.group(1))

        self.assertEqual(render_score(with_osint=False), render_score(with_osint=True))


if __name__ == "__main__":
    unittest.main()
