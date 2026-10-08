from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reconbot.ai.action_guard import validate_setting_change
from reconbot.ai.answer_validator import validate_answer_integrity
from reconbot.ai.assistant import (
    _answer_intent_for_request,
    _profile_for_request,
    _response_preferences,
    _selected_context_finding,
    chat,
)
from reconbot.ai.client import OpenAICompatibleClient
from reconbot.ai.config import ai_config_from_mapping
from reconbot.ai.context_builder import build_ai_context, context_as_prompt_text
from reconbot.ai.models import AIContext, ChatMessage
from reconbot.ai.prompt_builder import SYSTEM_PROMPT, SYSTEM_PROMPT_TR, build_messages
from reconbot.ai.request_planner import resolve_ai_request_plan


EXPECTED_SYSTEM_PROMPT = """You are ReconBot Operator Copilot.
Work as a practical cybersecurity analyst addressing security practitioners.
Answer the user's actual request directly.
Use the same language as the user unless they explicitly request another language.
Follow explicit user formatting instructions such as brevity, item count, headings/no headings, or requested style.
Treat exact-output constraints literally. If the user asks for only a specific word or phrase, output only that word or phrase.
Use supplied ReconBot run/finding context when it is relevant.
Current reference data takes precedence over earlier assistant claims. A partial scan limits coverage; it does not erase available evidence.
Previous assistant messages are conversation context only, never evidence; do not repeat their unsupported claims.
Do not invent artifact values, URLs, endpoints, versions, evidence, scan results, or findings that are not present in the supplied context.
If information is unavailable, say so naturally.
Do not force answers into a fixed report template."""


class RecordingClient(OpenAICompatibleClient):
    def __init__(self, config, responses: list[tuple[str, object, int]]) -> None:
        super().__init__(config)
        self.responses = list(responses)
        self.chat_payloads: list[dict] = []

    def _http_json(self, path, method="GET", payload=None, timeout_sec=None):
        if str(path).endswith("/api/v1/models"):
            return "ok", {
                "models": [{
                    "key": self.config.model,
                    "loaded_instances": [{"id": self.config.model, "config": {"context_length": 8192}}],
                    "max_context_length": 32768,
                    "capabilities": {"reasoning": False},
                }]
            }, 200
        if path == "/models":
            return "ok", {"data": [{"id": self.config.model}]}, 200
        if path == "/chat/completions":
            self.chat_payloads.append(payload)
            if not self.responses:
                raise AssertionError("Unexpected extra chat call")
            return self.responses.pop(0)
        raise AssertionError(f"Unexpected path: {path}")


def provider_ok(content: str, finish_reason: str = "stop") -> tuple[str, object, int]:
    return "ok", {
        "model": "mistralai/mistral-7b-instruct-v0.3",
        "choices": [{"message": {"content": content}, "finish_reason": finish_reason}],
    }, 200


class ThinModelFirstAssistantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run_dir = Path(self.temp.name)
        run_result = {
            "run_state": "completed",
            "target": "https://target.test",
            "meta": {"target": "https://target.test", "timestamp": "run-1"},
            "summary": {"nuclei_findings_count": 3, "risk_score": 82},
            "risk": {"score": 82, "verdict": "high"},
            "nuclei": {
                "findings": [
                    {
                        "title": "Fanwei e-cology Remote Code Execution",
                        "template_id": "fanwei-rce",
                        "severity": "critical",
                        "matched-at": "https://target.test/fanwei",
                    },
                    {
                        "title": "eYouMail Remote Code Execution",
                        "template_id": "eyoumail-rce",
                        "severity": "critical",
                        "matched-at": "https://target.test/eyoumail",
                    },
                    {
                        "title": "ShopXO Download File Read",
                        "template_id": "shopxo-read",
                        "severity": "high",
                        "matched-at": "https://target.test/shopxo",
                    },
                ]
            },
        }
        (self.run_dir / "run_result.json").write_text(json.dumps(run_result), encoding="utf-8")
        (self.run_dir / "stages_live.json").write_text(
            json.dumps({"nuclei": {"status": "done", "findings_count": 3}}),
            encoding="utf-8",
        )
        self.config = {
            "enabled": True,
            "baseUrl": "http://127.0.0.1:1234/v1",
            "model": "mistralai/mistral-7b-instruct-v0.3",
            "selectedModel": "mistralai/mistral-7b-instruct-v0.3",
            "temperature": 0.73,
            "timeout": 300,
            "maxContextChars": 7777,
            "maxOutputTokens": 24000,
            "disableReasoning": True,
            "responseMode": "adaptive",
        }

    def run_chat(
        self,
        user_message: str,
        answers: list[tuple[str, object, int]],
        *,
        history: list[dict[str, str]] | None = None,
        reference: dict | None = None,
        profile: str | None = None,
        mode: str = "chat",
    ) -> tuple[dict, RecordingClient]:
        created: list[RecordingClient] = []

        def factory(config):
            client = RecordingClient(config, answers)
            created.append(client)
            return client

        payload = {
            "mode": mode,
            "runDir": str(self.run_dir),
            "run_id": "run-1",
            "user_message": user_message,
            "conversation_history": history or [],
            "selected_finding_reference": reference or {},
            "aiConfig": self.config,
            "modelMetadata": {"loadedContextLength": 8192, "modelMaxContextLength": 32768},
        }
        if profile:
            payload["contextProfile"] = profile
        with patch("reconbot.ai.assistant.OpenAICompatibleClient", side_effect=factory):
            response = chat(payload)
        return response, created[0]

    def test_exact_minimal_system_prompt(self):
        self.assertEqual(SYSTEM_PROMPT, EXPECTED_SYSTEM_PROMPT)
        self.assertEqual(SYSTEM_PROMPT_TR, EXPECTED_SYSTEM_PROMPT)
        message = build_messages(AIContext(context={}), "Hello")[0]
        self.assertEqual(message.content, EXPECTED_SYSTEM_PROMPT)

    def test_domain_questions_receive_facts_without_replacing_the_user_or_model(self):
        cases = [
            ("CVE-2017-5638 neyi etkiler?", "do not guess a vendor from memory"),
            ("Authentication: Possible successful login gördüm, şifre kesin bulundu mu?", "A failed login does not confirm a password"),
            ("SQLmap Payload ne demek?", "does not imply that database contents were dumped"),
        ]
        for question, fact in cases:
            with self.subTest(question=question):
                messages = build_messages(AIContext(context={}), question)
                self.assertIn(fact, messages[0].content)
                self.assertEqual(messages[-1].content, question)
                self.assertEqual([message.role for message in messages], ["system", "user"])
        self.assertNotIn("CVE ID", build_messages(AIContext(context={}), "Hello")[0].content)

    def test_report_trust_and_next_steps_keep_coverage_after_a_selected_finding(self):
        path = self.run_dir / "run_result.json"
        run = json.loads(path.read_text())
        run.update(run_state="interrupted", interrupted_by_user=True)
        path.write_text(json.dumps(run))
        (self.run_dir / "report.html").write_text("<html>Partial report</html>")
        history = [{"role": "user", "content": "İlk bulgu Fanwei kaydını açıkla."},
                   {"role": "assistant", "content": "Fanwei eşleşmesi doğrulanmalı."}]
        for mode, profile, question in [
            ("trust", "trust", "Bu rapora güvenebilir miyim?"),
            ("next", "operational_question", "Sonraki güvenli operatör adımı ne olmalı?"),
        ]:
            with self.subTest(mode=mode):
                response, client = self.run_chat(question, [provider_ok("Mevcut kanıtları doğrula.")],
                                                 mode=mode, profile=profile, history=history)
                system = client.chat_payloads[0]["messages"][0]["content"]
                context = json.loads(re.search(r"<reconbot_context>(.*?)</reconbot_context>", system).group(1))["context"]
                current = context["current_run_context"]
                self.assertEqual(current["run_state"], "interrupted")
                self.assertTrue(current["partial_coverage_notes"])
                self.assertIn("source_health_summary", current)
                self.assertTrue(current["current_report_confidence"]["report_exists"])
                self.assertIn("fanwei-rce", system)
                self.assertIn("short spoken briefing", system)
                self.assertEqual(response["answer_source"], "model")

    def test_report_briefing_preserves_latest_question_and_current_evidence(self):
        question = "Bu raporu 30 saniyede açıkla"
        _, client = self.run_chat(question, [provider_ok("Üç Nuclei eşleşmesi var.")])
        messages = client.chat_payloads[0]["messages"]
        self.assertEqual(messages[-1]["content"], question)
        self.assertIn("not a deadline to access the report", messages[0]["content"])
        context = json.loads(re.search(r"<reconbot_context>(.*?)</reconbot_context>", messages[0]["content"]).group(1))["context"]
        self.assertEqual(context["current_run_context"]["nuclei_findings_count"], 3)
        self.assertEqual(_profile_for_request("chat", "Source health neden düşük?"), "trust")

    def test_english_report_trust_with_false_positive_keeps_run_context(self):
        question = "Is this result reliable? Explain partial coverage, source health and false-positive risk."
        response, client = self.run_chat(question, [provider_ok("Scanner matches should be verified manually.")], profile="trust")
        self.assertEqual(response["context_profile"], "trust")
        system = client.chat_payloads[0]["messages"][0]["content"]
        context = json.loads(re.search(r"<reconbot_context>(.*?)</reconbot_context>", system).group(1))["context"]
        self.assertEqual(context["current_run_context"]["nuclei_findings_count"], 3)
        self.assertEqual(context["current_run_context"]["target"], "https://target.test")
        self.assertEqual(client.chat_payloads[0]["messages"][-1]["content"], question)

    def test_turkish_latest_message_adds_only_a_language_hint(self):
        messages = build_messages(
            AIContext(context={"context_profile": "general_chat"}, truncated=True),
            "Sadece evet yaz.",
        )
        self.assertIn("latest message is in Turkish", messages[0].content)
        self.assertNotIn("reconbot_context", messages[0].content)
        self.assertEqual(messages[-1].content, "Sadece evet yaz.")

    def test_literal_latest_user_message_is_final_and_verbatim(self):
        question = "Sadece evet yaz."
        response, client = self.run_chat(question, [provider_ok("Evet")], profile="general_chat")
        sent = client.chat_payloads[0]["messages"]
        self.assertEqual(sent[-1], {"role": "user", "content": question})
        self.assertEqual(response["latest_user_message"], question)
        self.assertEqual(response["answer"], "Evet")
        self.assertEqual(response["answer_source"], "model")
        self.assertFalse(response["local_answer_generated"])
        self.assertEqual(response["answer_repair_attempt_count"], 0)
        self.assertEqual(response["request_plan"]["effectiveInjectedContextChars"], 0)

    def test_history_is_one_system_then_normal_chronology_then_latest(self):
        history = [
            {"role": "user", "content": "İkinci bulguyu konuşalım."},
            {"role": "assistant", "content": "eYouMail kaydını konuşuyoruz."},
        ]
        messages = build_messages(AIContext(context={"selected_finding": {"title": "eYouMail"}}), "Kısaca açıkla.", conversation_history=history)
        self.assertEqual([item.role for item in messages], ["system", "user", "assistant", "user"])
        self.assertEqual(messages[-1].content, "Kısaca açıkla.")
        self.assertEqual(sum(item.role == "system" for item in messages), 1)

    def test_general_chat_has_no_run_or_finding_dump(self):
        context = build_ai_context(self.run_dir, max_chars=7777, profile="general_chat")
        serialized = context_as_prompt_text(context)
        self.assertNotIn("Fanwei", serialized)
        self.assertNotIn("eYouMail", serialized)
        self.assertNotIn('"risk":', serialized)
        self.assertNotIn('"risk_score":82', serialized)

    def test_explicit_ordinal_resolves_then_only_selected_finding_is_sent(self):
        question = "Ben sadece ilk bulguyu açıklamanı istedim. Bir de Türkçe açıkla."
        response, client = self.run_chat(question, [provider_ok("İlk bulgu Fanwei kaydıdır.")], profile="finding_question")
        system = client.chat_payloads[0]["messages"][0]["content"]
        self.assertIn("Fanwei", system)
        self.assertNotIn("eYouMail", system)
        self.assertNotIn("ShopXO", system)
        self.assertEqual(response["selected_finding_reference"]["ordinal"], 1)

    def test_selected_finding_precedence(self):
        context = build_ai_context(self.run_dir, max_chars=7777, profile="finding_question").context
        findings = context["current_run_context"]["top_findings"]
        stale = {
            "template_id": "fanwei-rce",
            "title": "Fanwei e-cology Remote Code Execution",
            "source": "nuclei",
            "ordinal": 1,
            "run_id": "run-1",
        }
        context["conversation_reference"] = stale
        self.assertEqual(_selected_context_finding(context, "eYouMail hakkında konuşalım", [],)["template_id"], "eyoumail-rce")
        self.assertEqual(_selected_context_finding(context, "İkinci bulguyu açıkla", [],)["template_id"], "eyoumail-rce")
        self.assertEqual(
            _selected_context_finding(context, "Bunu açıkla", [{"role": "user", "content": "ShopXO seçilmişti"}])["template_id"],
            "fanwei-rce",
        )
        context.pop("conversation_reference")
        self.assertEqual(
            _selected_context_finding(context, "Bunu açıkla", [{"role": "user", "content": "eYouMail seçelim"}])["template_id"],
            "eyoumail-rce",
        )
        self.assertEqual(_selected_context_finding(context, "Bunu açıkla", []), {})
        self.assertEqual(len(findings), 3)

    def test_eyoumail_continuity_and_format_intent_separation(self):
        first, _ = self.run_chat(
            "İkinci bulgu olan eYouMail hakkında konuşalım. Kısaca açıkla.",
            [provider_ok("eYouMail kaydı henüz doğrulanmamış bir Nuclei eşleşmesidir.")],
            profile="finding_question",
        )
        reference = first["selected_finding_reference"]
        history = [
            {"role": "user", "content": "İkinci bulgu olan eYouMail hakkında konuşalım. Kısaca açıkla."},
            {"role": "assistant", "content": first["answer"]},
        ]
        identity, _ = self.run_chat(
            "Hangi bulgu hakkında konuşuyorduk?",
            [provider_ok("eYouMail Remote Code Execution bulgusu.")],
            history=history,
            reference=reference,
            profile="finding_question",
        )
        self.assertEqual(identity["selected_finding_reference"]["template_id"], "eyoumail-rce")
        four, client = self.run_chat(
            "Bunu tam 4 maddede anlat.",
            [provider_ok("1. Bir\n2. İki\n3. Üç\n4. Dört")],
            history=history,
            reference=reference,
            profile="continuation",
        )
        self.assertEqual(four["answer_intent"], "finding_question")
        self.assertEqual(four["response_preferences"]["requested_item_count"], 4)
        self.assertEqual(four["selected_finding_reference"]["template_id"], "eyoumail-rce")
        self.assertNotIn("action plan", client.chat_payloads[0]["messages"][0]["content"].lower())

    def test_detail_continuation_keeps_selected_finding(self):
        reference = {
            "template_id": "eyoumail-rce",
            "title": "eYouMail Remote Code Execution",
            "source": "nuclei",
            "ordinal": 2,
            "run_id": "run-1",
        }
        response, client = self.run_chat(
            "Biraz daha ayrıntılı anlat.",
            [provider_ok("eYouMail eşleşmesi için biraz daha ayrıntı.")],
            history=[{"role": "user", "content": "eYouMail"}, {"role": "assistant", "content": "Kısa açıklama"}],
            reference=reference,
            profile="general_chat",
        )
        self.assertEqual(response["context_profile"], "continuation")
        self.assertEqual(response["selected_finding_reference"]["template_id"], "eyoumail-rce")
        self.assertIn("eYouMail", client.chat_payloads[0]["messages"][0]["content"])

    def test_valid_provider_text_is_not_rejected_for_style_or_format(self):
        unconventional = "Raporun tam metnini inceleyiniz."
        response, client = self.run_chat(
            "False-positive olabilir mi? Kısa cevapla, başlık kullanma.",
            [provider_ok(unconventional)],
            profile="finding_question",
            reference={
                "template_id": "eyoumail-rce",
                "title": "eYouMail Remote Code Execution",
                "source": "nuclei",
                "ordinal": 2,
                "run_id": "run-1",
            },
        )
        self.assertEqual(response["answer"], unconventional)
        self.assertEqual(len(client.chat_payloads), 1)
        self.assertEqual(response["answer_repair_attempt_count"], 0)

    def test_exact_item_count_is_diagnostic_not_answer_validator(self):
        response, client = self.run_chat(
            "Bunu tam 4 maddede anlat.",
            [provider_ok("Tek doğal paragraf.")],
            profile="continuation",
            reference={
                "template_id": "eyoumail-rce",
                "title": "eYouMail Remote Code Execution",
                "source": "nuclei",
                "ordinal": 2,
                "run_id": "run-1",
            },
        )
        self.assertEqual(response["answer"], "Tek doğal paragraf.")
        self.assertEqual(len(client.chat_payloads), 1)
        self.assertEqual(response["response_preferences"]["requested_item_count"], 4)

    def test_unresolved_placeholder_gets_one_focused_repair(self):
        question = "İlk bulgunun gerçek adresini söyle."
        response, client = self.run_chat(
            question,
            [provider_ok("Adres: <URL>"), provider_ok("Adres: https://target.test/fanwei")],
            profile="finding_question",
        )
        self.assertEqual(len(client.chat_payloads), 2)
        self.assertEqual(client.chat_payloads[1]["messages"][-1]["content"], question)
        self.assertEqual(response["answer"], "Adres: https://target.test/fanwei")
        self.assertEqual(response["answer_source"], "repaired_model")
        self.assertEqual(response["answer_repair_attempt_count"], 1)
        self.assertFalse(response["local_answer_generated"])

    def test_failed_integrity_repair_returns_technical_error_not_fallback(self):
        response, client = self.run_chat(
            "İlk bulgunun gerçek adresini söyle.",
            [provider_ok("Adres: <URL>"), provider_ok("Adres: <ENDPOINT>")],
            profile="finding_question",
        )
        self.assertFalse(response["ok"])
        self.assertTrue(response["unavailable"])
        self.assertEqual(len(client.chat_payloads), 2)
        self.assertEqual(response["answer_source"], "technical_error")
        self.assertFalse(response["local_answer_generated"])
        self.assertIn("yerel bir metinle değiştirilmedi", response["answer"])

    def test_provider_failure_is_technical_and_never_fabricates_artifact_answer(self):
        response, client = self.run_chat(
            "Raporu açıkla.",
            [("transport_error", TimeoutError("timed out"), 0)],
            profile="report_summary",
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["status"], "model_timeout")
        self.assertFalse(response["local_answer_generated"])
        self.assertEqual(response["answer_source"], "technical_error")
        self.assertEqual(len(client.chat_payloads), 1)

    def test_raw_provider_content_equals_visible_answer(self):
        raw = "Doğrudan yanıt.\n\nİkinci paragraf."
        response, _ = self.run_chat("Doğrudan cevapla.", [provider_ok(raw)], profile="general_chat")
        self.assertEqual(response["endpoint_debug"]["rawProviderContent"], raw)
        self.assertFalse(response["endpoint_debug"]["providerContentRedacted"])
        self.assertEqual(response["answer"], raw)

    def test_final_provider_messages_and_answer_preserve_secret_values(self):
        secret = "abcdefghijklmnopqrstuvwxyz1234567890"
        question = f"Authorization: Bearer {secret}"
        response, client = self.run_chat(question, [provider_ok(question)], profile="general_chat")
        provider_question = client.chat_payloads[0]["messages"][-1]["content"]
        self.assertEqual(provider_question, question)
        diagnostics = json.dumps(response["endpoint_debug"]["providerMessages"])
        self.assertIn(secret, diagnostics)
        self.assertEqual(response["answer"], question)
        self.assertEqual(response["endpoint_debug"]["rawProviderContent"], question)
        self.assertFalse(response["endpoint_debug"]["providerContentRedacted"])

    def test_runtime_settings_control_provider_payload_and_diagnostics(self):
        response, client = self.run_chat("Merhaba", [provider_ok("Merhaba")], profile="general_chat")
        payload = client.chat_payloads[0]
        self.assertEqual(payload["model"], self.config["selectedModel"])
        self.assertEqual(payload["temperature"], 0.73)
        self.assertEqual(payload["max_tokens"], response["request_plan"]["effectiveMaxOutputTokens"])
        self.assertEqual(response["request_plan"]["configuredMaxOutputTokens"], 24000)
        self.assertLess(response["request_plan"]["effectiveMaxOutputTokens"], 24000)
        self.assertIn("loaded_context_window_and_request_input", response["request_plan"]["outputLimitReason"])
        self.assertEqual(response["request_plan"]["configuredTimeoutSec"], 300)
        self.assertEqual(response["request_plan"]["effectiveRequestTimeoutSec"], 300)
        self.assertEqual(response["request_plan"]["configuredMaxContextChars"], 7777)
        self.assertLessEqual(response["request_plan"]["effectiveInjectedContextChars"], 7777)

    def test_response_preferences_do_not_change_semantic_intent(self):
        preferences = _response_preferences("Bunu tam 4 maddede anlat.")
        self.assertEqual(preferences.requested_item_count, 4)
        self.assertEqual(preferences.requested_format, "list")
        self.assertEqual(
            _answer_intent_for_request(
                "chat",
                "Bunu tam 4 maddede anlat.",
                "continuation",
                {"title": "eYouMail"},
            ),
            "finding_question",
        )

    def test_profile_uses_continuation_for_detail_followup(self):
        self.assertEqual(
            _profile_for_request("chat", "Biraz daha ayrıntılı anlat.", "general_chat"),
            "continuation",
        )

    def test_integrity_validator_accepts_conditional_security_explanation(self):
        result = validate_answer_integrity(
            "RCE gerçekleşirse saldırgan kod çalıştırabilir; ancak bu eşleşme henüz doğrulanmadı.",
            findings=[{"title": "eYouMail Remote Code Execution", "verification_state": "unverified"}],
            enforce_artifact_grounding=True,
        )
        self.assertTrue(result.usable)

    def test_integrity_validator_rejects_direct_artifact_contradiction(self):
        result = validate_answer_integrity(
            "Bulgu doğrulandı. URL: https://invented.test/path",
            findings=[{
                "title": "eYouMail Remote Code Execution",
                "verification_state": "unverified",
                "matched_url": "https://target.test/eyoumail",
            }],
            enforce_artifact_grounding=True,
        )
        self.assertFalse(result.usable)
        self.assertIn("nuclei_match_treated_as_confirmed", result.categories)
        self.assertIn("invented_url", result.categories)

    def test_english_verification_guidance_does_not_claim_confirmation(self):
        finding = {"verification_state": "unverified", "matched_url": "https://target.test/path"}
        for answer in [
            "The findings are not verified. Verify them before reporting.",
            "The findings should be verified manually.",
            "The matches have not yet been confirmed.",
            "If verified, the finding could allow code execution.",
            "No confirmed vulnerabilities; these are scanner matches.",
            "The result cannot be confirmed from this evidence.",
            "Investigate the partially verified findings; they still require manual testing.",
        ]:
            with self.subTest(answer=answer):
                self.assertTrue(validate_answer_integrity(answer, findings=[finding], enforce_artifact_grounding=True).usable)

    def test_english_direct_confirmation_is_still_rejected(self):
        for answer in ["The vulnerability is confirmed.", "We verified this finding.", "Confirmed vulnerability: RCE.", "Verification: confirmed."]:
            with self.subTest(answer=answer):
                result = validate_answer_integrity(answer, findings=[{"verification_state": "unverified"}], enforce_artifact_grounding=True)
                self.assertIn("nuclei_match_treated_as_confirmed", result.categories)

    def test_report_target_is_valid_context_even_without_matching_endpoint(self):
        answer = "Target: https://target.test. The findings are not verified and should be verified manually."
        response, client = self.run_chat("Explain report", [provider_ok(answer)], profile="report_summary")
        self.assertTrue(response["ok"])
        self.assertEqual(response["answer"], answer)
        self.assertEqual(len(client.chat_payloads), 1)
        self.assertEqual(response["answer_repair_attempt_count"], 0)

    def test_known_target_root_slash_does_not_allow_other_paths_or_values(self):
        finding = {"verification_state": "unverified", "matched_url": "https://target.test/path?token=raw-value"}
        for answer, usable in [
            ("Target: https://target.test/", True),
            ("URL: https://target.test/path?token=raw-value", True),
            ("URL: https://target.test/not-recorded", False),
            ("URL: https://target.test/path?token=different", False),
            ("Not verified yet. However, the vulnerability is confirmed.", False),
        ]:
            with self.subTest(answer=answer):
                result = validate_answer_integrity(answer, findings=[finding], reference_urls=["https://target.test"], enforce_artifact_grounding=True)
                self.assertEqual(result.usable, usable)

    def test_settings_guard_still_protects_unrelated_runtime_state(self):
        self.assertTrue(validate_setting_change({
            "path": "tool_settings.nuclei.rateLimit",
            "current": 15,
            "proposed": 8,
            "reason_tr": "Daha düşük trafik",
        })[0])
        self.assertFalse(validate_setting_change({
            "path": "target",
            "current": "a",
            "proposed": "b",
            "reason_tr": "change",
        })[0])


class ProviderCompatibilityTests(unittest.TestCase):
    def test_mistral_system_role_retry_preserves_exact_latest_user(self):
        config = ai_config_from_mapping({
            "model": "mistralai/mistral-7b-instruct-v0.3",
            "selectedModel": "mistralai/mistral-7b-instruct-v0.3",
            "disableReasoning": True,
        })
        question = "Sadece evet yaz."
        client = RecordingClient(config, [
            ("http_error", '{"error":"Only user and assistant roles are supported"}', 400),
            provider_ok("Evet"),
        ])
        response = client.chat(
            [ChatMessage("system", EXPECTED_SYSTEM_PROMPT), ChatMessage("user", question)],
            max_tokens=100,
            max_attempts=2,
        )
        self.assertTrue(response.ok)
        self.assertEqual(response.answer, "Evet")
        self.assertEqual(client.chat_payloads[-1]["messages"][-1]["content"], question)
        self.assertNotIn("system", [item["role"] for item in client.chat_payloads[-1]["messages"]])
        self.assertIn("system_role_rejected", " ".join(response.compatibility_notes))

    def test_nonempty_http_200_is_one_model_answer(self):
        config = ai_config_from_mapping({})
        client = RecordingClient(config, [provider_ok("Kısa cevap")])
        response = client.chat(
            [ChatMessage("system", EXPECTED_SYSTEM_PROMPT), ChatMessage("user", "Kısa cevapla")],
            max_tokens=100,
        )
        self.assertTrue(response.ok)
        self.assertEqual(response.answer, "Kısa cevap")
        self.assertEqual(len(client.chat_payloads), 1)
        self.assertEqual(response.endpoint_debug["httpStatus"], 200)

    def test_planner_reports_configured_and_effective_values(self):
        config = ai_config_from_mapping({
            "maxOutputTokens": 24000,
            "maxContextChars": 7777,
            "timeout": 300,
            "temperature": 0.73,
        })
        plan = resolve_ai_request_plan(
            config,
            answer_intent="normal_question",
            context_profile="general_chat",
            user_message="Merhaba",
            injected_context={},
            model_metadata={"loadedContextLength": 8192, "modelMaxContextLength": 32768},
        )
        trace = plan.as_dict()
        self.assertEqual(trace["configuredMaxOutputTokens"], 24000)
        self.assertLess(trace["effectiveMaxOutputTokens"], 24000)
        self.assertEqual(trace["configuredMaxContextChars"], 7777)
        self.assertEqual(trace["configuredTimeoutSec"], 300)
        self.assertEqual(trace["providerTemperature"], 0.73)


if __name__ == "__main__":
    unittest.main()
