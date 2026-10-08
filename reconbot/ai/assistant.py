from __future__ import annotations

import json
import re
import sys
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .action_planner import extract_action_plan
from .answer_validator import AnswerValidationResult, validate_answer_integrity
from .client import OpenAICompatibleClient
from .config import ai_config_dict, ai_config_from_mapping, default_ai_config
from .context_builder import build_ai_context, context_as_prompt_text
from .models import AIContext, ChatResponse, ResponsePreferences
from .prompt_builder import build_messages, build_budgeted_repair_messages, model_context_text
from .redaction import REDACTION_MARK, contains_unresolved_placeholder_values, redact_obj, redact_for_ui, redact_text
from .request_planner import prepare_conversation_history, resolve_ai_request_plan, plan_serialized_messages
from .settings_actions import apply_settings_action


RAW_FIELD_REPLACEMENTS = {
    "summary.nuclei_findings_count": "Nuclei bulgu sayısı",
    "run_report_path": "rapor klasörü",
    "tool_stage_status.nuclei.status": "Nuclei aşaması",
    "run.current_run_dir": "run klasörü",
    "run.report_path": "rapor dosyası",
    "risk.score": "risk skoru",
    "risk.verdict": "risk kararı",
    "missing_evidence_fields": "eksik kanıtlar",
    "matched_url": "eşleşen adres",
    "validation_state": "doğrulama durumu",
    "verification_state": "doğrulama durumu",
    "explicit_validation_evidence": "açık doğrulama kanıtı",
    "product_fingerprint": "ürün izi",
    "status_or_redirect": "durum kodu veya yönlendirme",
}
JSON_BLOCK_PATTERN = re.compile(r"```(?:json)?\s*\{.*?\}\s*```", re.DOTALL)
RAW_CONTEXT_PATH_PATTERN = re.compile(
    r"\b(?:summary|run|run_config|run_report_path|tool_stage_status|osint|findings|important_findings|risk|log|source_boundaries)"
    r"(?:[.\[][A-Za-z0-9_\]-]+)+\b"
)
GENERIC_REDACTION_NOTE_PATTERN = re.compile(r"bazı hassas değerler.*gizlendi", re.IGNORECASE)
OPERATIONAL_CONTEXT_PATTERN = re.compile(
    r"(sald[ıi]r|exploit|bypass|gizlen|stealth|payload|shell|rce|evasion|kaçın|attack)",
    re.IGNORECASE,
)
REPORT_CONTEXT_PATTERN = re.compile(
    r"(rapor|bulgu|finding|risk|source\s*health|kaynak|nuclei|osint|darkweb|leak|log|tarama|scan|artifact|kanıt)",
    re.IGNORECASE,
)
FINDING_CONTEXT_PATTERN = re.compile(r"(bulgu|finding|nuclei|cve|zafiyet|eşleşme|kanıt)", re.IGNORECASE)
LOG_CONTEXT_PATTERN = re.compile(r"(log|hata|error|timeout|zaman aşımı|stage|aşama)", re.IGNORECASE)
AI_FAILURE_DIAGNOSTICS_PATTERN = re.compile(
    r"(zaman aşımı|timeout|http\s*400|neden hata verdi|model neden cevap vermedi)",
    re.IGNORECASE,
)
SETTINGS_CONTEXT_PATTERN = re.compile(r"(ayar|setting|config|profil|rate.?limit|timeout değeri)", re.IGNORECASE)
TRUST_CONTEXT_PATTERN = re.compile(r"(güvenilir|güvenebilir|doğru mu|gerçek mi|false.?positive|kapsam|kanıt|source\s*health|kaynak\s*sağlığ)", re.IGNORECASE)
DIRECT_FALSE_POSITIVE_PATTERN = re.compile(r"false.?positive", re.IGNORECASE)
FOLLOWUP_CONTEXT_PATTERN = re.compile(
    r"(?:\b(?:bu bulgu|bunlar|bunları|bunu|ikincisi|ikinciyi|önceki bulgu|konuştuğumuz bulgu|önceki cevap|devam et|devamını|daha kısa|kısalt|biraz aç|biraz açar|peki önce)\b|"
    r"\b(?:biraz daha|daha fazla|daha ayrıntılı|daha detaylı|ayrıntılandır|detaylandır)\b|"
    r"\b(?:ilk|birinci|ikinci|üçüncü|dördüncü|beşinci)\s+bulgu\b|"
    r"\b[1-9]\s*\.\s*(?:si(?:ni)?|sini|dediğini|maddeyi|bulguyu)?)",
    re.IGNORECASE,
)
ACTION_PLAN_PATTERN = re.compile(
    r"(?:\b\d{1,2}\s*ad[ıi]ml[ıi]k\b|\b(?:ilk\s+)?\d{1,2}\s+ad[ıi]m\w*\b[^?.!]{0,40}\b(?:öner|ver|yaz)|\bad[ıi]m\s+ad[ıi]m\b|"
    r"\bs[ıi]rayla\b[^?.!]{0,80}\bad[ıi]m|\bad[ıi]mlar[ıi]\b[^?.!]{0,60}\buygula|"
    r"\bplan\w*\b[^?.!]{0,40}\b(?:ver|haz[ıi]rla|olu[şs]tur|dönü[şs]tür|yaz)|"
    r"\b(?:ver|haz[ıi]rla|olu[şs]tur|yaz)\b[^?.!]{0,40}\bplan)",
    re.IGNORECASE,
)
OPERATIONAL_GUIDANCE_PATTERN = re.compile(
    r"(?:\bnas[ıi]l\b[^?.!]{0,70}\b(?:do[ğg]rula|kontrol|test|incele|teyit|kar[şs][ıi]la[şs]t[ıi]r)|"
    r"\b(?:do[ğg]rula|kontrol|test|incele|teyit|kar[şs][ıi]la[şs]t[ıi]r)[^?.!]{0,70}"
    r"\b(?:hangi\s+ad[ıi]m|ne\s+yap|nas[ıi]l)|\bhangi\s+ad[ıi]mlar[ıi]\s+izle|"
    r"\b(?:ilk\s+)?ne\s+yapmal[ıi]y[ıi]m|\bilk\s+ne\s+yapay[ıi]m)",
    re.IGNORECASE,
)
CAUSE_REQUEST_PATTERN = re.compile(r"(neden|niye|sebep)", re.IGNORECASE)
REQUESTED_COUNT_PATTERN = re.compile(
    r"\b(?:ilk\s+)?(\d{1,2})\s*(?:maddelik|maddede|madde|ad[ıi]ml[ıi]k|ad[ıi]m|öneri|yol|bulgu|neden|sebep)",
    re.IGNORECASE,
)
EXPLICIT_SINGLE_SENTENCE_PATTERN = re.compile(
    r"\b(?:tek|bir|1)\s+cümle(?:de|lik)?\b",
    re.IGNORECASE,
)
SHORT_ANSWER_PREFERENCE_PATTERN = re.compile(r"\b(?:k[ıi]sa\s+cevap|k[ıi]saca|özetle)\b", re.IGNORECASE)
NO_HEADING_PREFERENCE_PATTERN = re.compile(
    r"(?:ba[şs]l[ıi]k\s+(?:kullanma|olmas[ıi]n|istemi(?:yorum|yoruz))|ba[şs]l[ıi]ks[ıi]z)",
    re.IGNORECASE,
)
PARAGRAPH_PREFERENCE_PATTERN = re.compile(r"(?:tek\s+)?paragraf\s+(?:halinde|olarak|biçiminde)", re.IGNORECASE)
NUMBERED_LIST_PREFERENCE_PATTERN = re.compile(r"(?:numaral[ıi]|s[ıi]ral[ıi])\s+(?:liste|maddeler)", re.IGNORECASE)
GENERIC_REPORT_LINE_PATTERN = re.compile(
    r"(run durumu|risk(?: skoru)?|operatör doğrulamas[ıi]|template eşleşmesi|rapor (?:final|henüz)|tarama (?:interrupted|kesilmiş))",
    re.IGNORECASE,
)
SHORT_SUMMARY_PATTERN = re.compile(
    r"(5\s*sat[ıi]r|be[şs]\s*sat[ıi]r|30\s*saniye|k[ıi]sa\s+özet|k[ıi]saca\s+özet|özetle|durumu yorumla)",
    re.IGNORECASE,
)
DETAILED_PATTERN = re.compile(r"(detayl[ıi]|ayr[ıi]nt[ıi]l[ıi]|deep|uzun analiz|geni[şs] analiz)", re.IGNORECASE)
EVIDENCE_REQUEST_PATTERN = re.compile(
    r"(kan[ıi]t|hangi veriye g[öo]re|nereden biliyorsun|path|referans|proof|evidence)",
    re.IGNORECASE,
)
PROMPT_LEAK_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"Raw JSON field/path",
        r"secret,\s*token,\s*credential,\s*dump\s+veya\s+personal",
        r"Use only the CURRENT RUN CONTEXT",
        r"Do not invent",
        r"Evidence block",
        r"Prompt constraints",
        r"Refine for Polish",
        r"Answer in Turkish",
        r"Max 5 sentences",
        r"sunum kısıtıdır",
        r"Son kullanıcı açıkça\s+\d+\s+madde",
        r"Exploit mekanizmas[ıi] uydurma",
        r"Aç[ıi]k kan[ıi]t olmadan doğrulama durumunu yükseltme",
        r"tool_stage_status",
        r"summary\.nuclei_findings_count",
    )
]
LOW_QUALITY_OPERATOR_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ilk\s+a[şs]amaya\s+yapmak",
        r"operator\s+do[ğg]rulamas[ıi]na\s+tabidir",
        r"nuclei\s+bulgular[ıi]n[ıi]z[ıi]",
    )
]
FINDING_ORDINAL_PATTERNS = (
    (r"\b(?:ikinci(?:\s+bulgu(?:yu|nun|ya)?)?|ikincisi|ikinciyi)\b", 1),
    (r"\b(?:üçüncü(?:\s+bulgu(?:yu|nun|ya)?)?|üçüncüsü)\b", 2),
    (r"\b(?:dördüncü(?:\s+bulgu(?:yu|nun|ya)?)?|dördüncüsü)\b", 3),
    (r"\b(?:beşinci(?:\s+bulgu(?:yu|nun|ya)?)?|beşincisi)\b", 4),
    (r"\b(?:ilk\s+bulgu(?:yu|nun|ya)?|birinci(?:si)?)\b", 0),
)
NUMERIC_FINDING_ORDINAL_PATTERN = re.compile(
    r"\b(\d{1,2})\s*\.\s*(?:s[ıi](?:n[ıi])?|si(?:ni)?|sü(?:nü)?|bulgu(?:yu|nun|ya)?)\b",
    re.IGNORECASE,
)
ProgressCallback = Callable[[str, int], None]

FAILURE_REASON_TR = {
    "answer_not_relevant": "Yanıt soruyu ilgili ReconBot gerçekleriyle cevaplamadı",
    "evidence_integrity_failure": "Artifact kanıtıyla çelişen veya desteklenmeyen iddialar üretti",
    "nuclei_match_treated_as_confirmed": "Doğrulanmamış eşleşmeyi kesin bulgu gibi sundu",
    "unsupported_product_claim": "Artifactte desteklenmeyen ürün/sürüm iddiası üretti",
    "requested_items_missing": "İstenen adımları vermedi",
    "requested_items_are_repetitive": "İstenen maddeleri farklı ve anlamlı içerikle vermedi",
    "wrong_selected_finding": "Konuşmada seçilen bulguyu korumadı",
    "unrelated_scan_report_for_ai_diagnostics": "AI istek hatası yerine ilgisiz tarama bulgularını anlattı",
    "contradicts_latest_ai_request_status": "Son AI istek durumuyla çelişti",
    "unresolved_placeholder_values": "Gerçek olmayan alanlar kullandı",
    "invented_url": "Gerçek olmayan alanlar kullandı",
    "invented_endpoint": "Gerçek olmayan alanlar kullandı",
    "reasoning_without_final": "Yalnız reasoning üretip final cevap vermedi",
    "input_too_large": "Bağlam sınırı aşıldı",
    "context_length_exceeded": "Bağlam sınırı aşıldı",
    "model_timeout": "Zaman aşımı",
    "timeout": "Zaman aşımı",
}


def _as_record(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _present(value: Any) -> bool:
    return value not in (None, "", [], {})


def _run_is_active(state: Any) -> bool:
    return str(state or "").lower() in {"running", "in_progress", "active", "scanning", "started"}


def _run_is_interrupted(state: Any) -> bool:
    return str(state or "").lower() in {"interrupted", "stopped", "cancelled", "canceled", "failed", "error"}


def _findings_count(context: dict[str, Any]) -> int:
    current = _as_record(context.get("current_run_context"))
    value = current.get("nuclei_findings_count")
    if isinstance(value, int):
        return value
    summary = _as_record(context.get("summary"))
    for key in ("nuclei_findings_count", "findings_count", "total_findings"):
        value = summary.get(key)
        if isinstance(value, int):
            return value
    nuclei_stage = _as_record(_as_record(context.get("tool_stage_status")).get("nuclei"))
    value = nuclei_stage.get("findings_count")
    if isinstance(value, int):
        return value
    return len(_as_list(context.get("findings")))


def _severity_distribution(findings: list[Any]) -> str:
    counts = Counter(str(_as_record(item).get("severity") or "unknown").lower() for item in findings)
    ordered = ["critical", "high", "medium", "low", "info", "unknown"]
    parts = [f"{severity}: {counts[severity]}" for severity in ordered if counts.get(severity)]
    return ", ".join(parts)


def _natural_run_state(state: Any) -> str:
    normalized = str(state or "").lower()
    if _run_is_interrupted(normalized):
        return normalized
    if normalized in {"completed", "done", "finished", "historical_loaded"}:
        return "completed" if normalized != "historical_loaded" else "historical loaded"
    if _run_is_active(normalized):
        return "running"
    return normalized or "unknown"


def _coverage_line(context: dict[str, Any]) -> str:
    osint = _as_record(context.get("osint"))
    coverage = _as_record(osint.get("osint_source_health_summary")).get("coverage_confidence")
    if not coverage or str(coverage).lower() == "unknown":
        return "Kaynak kapsamı artifact içinde net değil; bu yüzden temiz sonucuna varılamaz."
    if str(coverage).lower() in {"low", "partial", "medium"}:
        return f"Kaynak kapsamı {coverage}; bazı kaynaklar eksik veya kısmi olabilir, temiz denemez."
    return f"Kaynak kapsamı {coverage}; otomatik sonuçlar yine de operatör doğrulaması ister."


def _darkweb_line(context: dict[str, Any]) -> str:
    darkweb = _as_record(_as_record(context.get("osint")).get("darkweb_intelligence"))
    mode = darkweb.get("mode")
    summary = _as_record(darkweb.get("summary"))
    if not mode:
        return "Darkweb/leak alanı için yorumlanacak ek kanıt görünmüyor."
    line = "Darkweb bölümü metadata-only; aktif zafiyet kanıtı değildir." if mode == "metadata_only" else f"Darkweb modu: {mode}."
    if summary.get("credential_material_collected") is False:
        line += " Hassas materyal veya ham kayıt toplanmadı."
    return line


def _sensitive_note_needed(*values: Any) -> bool:
    text = json.dumps(values, ensure_ascii=False, default=str)
    return REDACTION_MARK in text or "[REDACTED]" in text


def _status_sentence(context: dict[str, Any]) -> str:
    state = _as_record(context.get("current_run_context")).get("run_state") or _as_record(context.get("run")).get("state")
    if _run_is_active(state):
        return "Tarama hâlâ devam ediyor; bu özet final rapor değildir."
    if _run_is_interrupted(state):
        return "Tarama kesilmiş veya tamamlanmadan durmuş; bu özet final rapor değildir."
    if str(state or "").lower() in {"completed", "done", "finished", "historical_loaded"}:
        return "Tarama tamamlanmış görünüyor; sonuçlar mevcut run artifact'larına göre yorumlandı."
    return "Durum bilgisi artifact'lardan sınırlı okunabildi."


def compact_evidence(context: dict[str, Any]) -> list[str]:
    evidence: list[str] = []
    current = _as_record(context.get("current_run_context"))
    target = current.get("target") or context.get("target")
    if _present(target):
        evidence.append(f"Hedef: {target}")
    run = _as_record(context.get("run"))
    state = _natural_run_state(current.get("run_state") or run.get("state"))
    if state != "unknown":
        evidence.append(f"Run durumu: {state}")
    risk = _as_record(context.get("risk"))
    score = current.get("risk_score") if current.get("risk_score") is not None else risk.get("score")
    if _present(score):
        evidence.append(f"Risk: {score}/100")
    if _present(risk.get("verdict")):
        evidence.append(f"Risk kararı: {risk.get('verdict')}")
    findings_count = _findings_count(context)
    if findings_count:
        evidence.append(f"Nuclei bulguları: {findings_count}")
    nuclei_stage = _as_record(_as_record(context.get("tool_stage_status")).get("nuclei"))
    if _present(nuclei_stage.get("status")):
        evidence.append(f"Nuclei aşaması: {nuclei_stage.get('status')}")
    coverage = _as_record(_as_record(context.get("osint")).get("osint_source_health_summary")).get("coverage_confidence")
    if _present(coverage):
        evidence.append(f"Kaynak kapsamı: {coverage}")
    return evidence[:6]


def _grounding_fact_packet(
    context: dict[str, Any],
    *,
    answer_intent: str,
    context_profile: str,
    selected_finding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the smallest positive-grounding contract for the current intent."""
    current = _as_record(context.get("current_run_context"))
    run = _as_record(context.get("run"))
    risk = _as_record(context.get("risk"))
    target = current.get("target") or context.get("target")
    run_state = current.get("run_state") or run.get("state")
    risk_score = current.get("risk_score") if current.get("risk_score") is not None else risk.get("score")
    risk_band = current.get("risk_band") or risk.get("verdict")

    selected = _as_record(selected_finding)
    if selected and answer_intent in {
        "finding_question",
        "evidence_request",
        "operational_guidance",
        "numbered_action_plan",
    }:
        finding_facts = {
            key: selected.get(key)
            for key in (
                "title",
                "severity",
                "template_id",
                "status_code",
                "redirect",
                "fingerprint",
                "request_evidence",
                "response_evidence",
                "response_evidence_present",
                "validation_evidence",
                "verification_state",
                "missing_evidence_fields",
            )
            if selected.get(key) not in (None, "", [], {})
        }
        source = selected.get("source") or selected.get("tool")
        matched_url = selected.get("matched_url") or selected.get("url")
        if source not in (None, "", [], {}):
            finding_facts["source"] = source
        if matched_url not in (None, "", [], {}):
            finding_facts["matched_url"] = matched_url
        return redact_obj({
            "kind": "selected_finding",
            "selected_finding": finding_facts,
            "run": {
                key: value
                for key, value in {
                    "target": target,
                    "run_state": run_state,
                    "risk_score": risk_score,
                    "risk_band": risk_band,
                }.items()
                if value not in (None, "", [], {})
            },
        })

    if answer_intent == "short_summary" or context_profile in {"report_summary", "quick_report_summary"}:
        top_findings = []
        for finding in _top_context_findings(context, limit=5):
            top_findings.append({
                key: finding.get(key)
                for key in ("title", "severity", "source", "template_id", "verification_state")
                if finding.get(key) not in (None, "", [], {})
            })
        confidence = _as_record(current.get("current_report_confidence"))
        coverage = current.get("source_health_summary") or _as_record(_as_record(context.get("osint")).get("osint_source_health_summary"))
        return redact_obj({
            "kind": "report_summary",
            "target": target,
            "run_state": run_state,
            "risk_score": risk_score,
            "risk_band": risk_band,
            "findings_count": _findings_count(context),
            "findings_by_severity": current.get("findings_by_severity"),
            "top_findings": top_findings,
            "coverage": coverage,
            "partial_coverage_notes": _as_list(current.get("partial_coverage_notes"))[:5],
            "report_available": confidence.get("report_exists"),
        })
    return {}


def _operator_report_summary(context: dict[str, Any]) -> str:
    if not context.get("target") and not _as_record(context.get("risk")).get("score"):
        return "Bu yorumu yapmak için güncel run_result yüklenemedi."

    run = _as_record(context.get("run"))
    current = _as_record(context.get("current_run_context"))
    risk = _as_record(context.get("risk"))
    findings = _as_list(context.get("findings"))
    findings_count = _findings_count(context)
    state = _natural_run_state(current.get("run_state") or run.get("state"))
    target = current.get("target") or context.get("target") or "hedef bilgisi artifact içinde net değil"
    risk_score = current.get("risk_score") if current.get("risk_score") is not None else risk.get("score")
    risk_text = f"{risk_score}/100" if _present(risk_score) else "artifact içinde net değil"
    verdict_text = current.get("risk_band") or risk.get("verdict") or "belirsiz"

    if _run_is_active(current.get("run_state") or run.get("state")) or _run_is_interrupted(current.get("run_state") or run.get("state")):
        status_line = (
            f"Bu rapor henüz tamamlanmamış; bu özet ara durumdur. Hedef: {target} için risk "
            f"{risk_text} / {verdict_text} görünüyor."
        )
    else:
        status_line = f"Hedef: {target} için mevcut artifact risk durumunu {risk_text} / {verdict_text} olarak gösteriyor."

    if findings_count:
        severity = _severity_distribution(findings)
        severity_suffix = f" Dağılım: {severity}." if severity else ""
        findings_line = (
            f"Nuclei şu ana kadar {findings_count} bulgu üretmiş.{severity_suffix} "
            "Bunları kesin zafiyet gibi sunma; template eşleşmesi olarak ele al ve operatör doğrulaması yap."
        )
    else:
        findings_line = "Artifact içinde Nuclei kaynaklı bulgu görünmüyor; bu tek başına hedefin temiz olduğu anlamına gelmez."

    next_focus = "Findings sekmesindeki yüksek/kritik Nuclei kayıtları ve raw log ilk kontrol noktası olmalı."
    if not findings_count:
        next_focus = "İlk bakılacak yer source health, log hata/timeoutları ve kapsam eksikleri olmalı."

    return "\n\n".join([
        f"{status_line} {findings_line}",
        f"{_coverage_line(context)} {_darkweb_line(context)}",
        f"{next_focus} Tarama tamamlanmadan raporu kesin sonuç gibi sunma.",
    ])


def deterministic_brief(context: dict[str, Any]) -> str:
    if not context.get("target") and not _as_record(context.get("risk")).get("score"):
        return "Bu yorumu yapmak için güncel run_result yüklenemedi."
    current = _as_record(context.get("current_run_context"))
    target = current.get("target") or context.get("target") or "hedef bilgisi artifact içinde net değil"
    risk = _as_record(context.get("risk"))
    osint = _as_record(context.get("osint"))
    coverage = _as_record(osint.get("osint_source_health_summary")).get("coverage_confidence")
    findings = context.get("findings") if isinstance(context.get("findings"), list) else []
    darkweb = _as_record(osint.get("darkweb_intelligence"))
    darkweb_summary = _as_record(darkweb.get("summary"))
    critical_or_high = [
        item for item in findings
        if str(_as_record(item).get("severity") or "").lower() in {"critical", "high"}
    ]
    if critical_or_high:
        finding_line = f"İlk bakılacak yer: {len(critical_or_high)} yüksek/kritik bulgu kaydı."
    elif findings:
        finding_line = f"Artifact içinde {len(findings)} bulgu özeti var; yüksek/kritik görünen kayıt ayrıca doğrulanmalı."
    else:
        finding_line = "Bu raporda doğrulanmış kritik bulgu görünmüyor."
    if coverage and str(coverage).lower() != "unknown":
        coverage_line = f"Kaynak kapsamı: {coverage}. "
        inconclusive = "Kaynak kapsamı kısmi olduğu için temiz diyemeyiz." if coverage != "high" else "Yine de otomatik sonuçlar manuel doğrulama gerektirir."
    else:
        coverage_line = ""
        inconclusive = "Kaynak kapsamı artifact içinde net değil; kesin temiz yorumu yapılmamalı."
    darkweb_line = "Darkweb bölümü metadata-only; aktif zafiyet kanıtı değil."
    if darkweb_summary.get("credential_material_collected") is False:
        darkweb_line += " Hassas materyal veya ham kayıt toplanmadı."
    return " ".join(
        [
            f"{target} için risk skoru/kararı {current.get('risk_score') if current.get('risk_score') is not None else risk.get('score') or 'artifact içinde yok'} / {current.get('risk_band') or risk.get('verdict') or 'belirsiz'}.",
            f"{coverage_line}{finding_line}",
            darkweb_line,
            inconclusive,
        ]
    )


def _finding_title(item: Any) -> str:
    row = _as_record(item)
    title = str(row.get("title") or row.get("name") or row.get("template_id") or "Nuclei finding")
    return "Artifact bulgusu" if contains_unresolved_placeholder_values(title) else title


def _finding_severity(item: Any) -> str:
    return str(_as_record(item).get("severity") or "unknown").lower()


def _finding_url(item: Any) -> str:
    row = _as_record(item)
    value = str(row.get("matched_url") or row.get("url") or row.get("matched_at") or row.get("matched-at") or row.get("matchedAt") or "").strip()
    if not value or contains_unresolved_placeholder_values(value):
        return ""
    try:
        parsed = urlparse(value)
    except ValueError:
        return ""
    return value if parsed.scheme in {"http", "https"} and bool(parsed.netloc) else ""


def _top_context_findings(context: dict[str, Any], limit: int = 3) -> list[dict[str, Any]]:
    current = _as_record(context.get("current_run_context"))
    candidates = _as_list(current.get("top_findings")) or _as_list(context.get("important_findings")) or _as_list(context.get("findings"))
    return [_as_record(item) for item in candidates[:limit] if isinstance(item, dict)]


def _finding_reference(
    context: dict[str, Any],
    finding: dict[str, Any],
    *,
    run_id: str = "",
) -> dict[str, Any]:
    findings = _top_context_findings(context, limit=10)
    ordinal = next((index for index, item in enumerate(findings, 1) if item is finding or item == finding), 0)
    current = _as_record(context.get("current_run_context"))
    run = _as_record(context.get("run"))
    return {
        "finding_id": str(finding.get("id") or finding.get("finding_id") or finding.get("template_id") or ""),
        "template_id": str(finding.get("template_id") or finding.get("template-id") or ""),
        "title": _finding_title(finding),
        "source": str(finding.get("source") or finding.get("tool") or "nuclei"),
        "ordinal": ordinal,
        "run_id": str(current.get("run_id") or run_id or run.get("current_run_dir") or ""),
    }


def _reference_finding(context: dict[str, Any], reference: dict[str, Any]) -> dict[str, Any]:
    if not reference:
        return {}
    findings = _top_context_findings(context, limit=10)
    current = _as_record(context.get("current_run_context"))
    run = _as_record(context.get("run"))
    current_run_id = str(current.get("run_id") or run.get("current_run_dir") or "")
    reference_run_id = str(reference.get("run_id") or "")
    if (
        current_run_id
        and reference_run_id
        and current_run_id != reference_run_id
        and Path(current_run_id).name != Path(reference_run_id).name
    ):
        return {}
    reference_ids = {
        str(reference.get(key) or "").strip().lower()
        for key in ("finding_id", "template_id")
        if str(reference.get(key) or "").strip()
    }
    reference_title = _normalized_similarity_text(str(reference.get("title") or ""))
    reference_source = str(reference.get("source") or "").strip().lower()
    for finding in findings:
        finding_ids = {
            str(finding.get(key) or "").strip().lower()
            for key in ("id", "finding_id", "template_id", "template-id")
            if str(finding.get(key) or "").strip()
        }
        if reference_ids and reference_ids.intersection(finding_ids):
            return finding
        if reference_title and reference_title == _normalized_similarity_text(_finding_title(finding)):
            source = str(finding.get("source") or finding.get("tool") or "nuclei").strip().lower()
            if not reference_source or reference_source == source:
                return finding
    try:
        ordinal = int(reference.get("ordinal") or 0)
    except (TypeError, ValueError):
        ordinal = 0
    return findings[ordinal - 1] if 1 <= ordinal <= len(findings) else {}


_GENERIC_FINDING_IDENTITY_TOKENS = {
    "remote", "code", "execution", "rce", "file", "read", "exposure", "disclosure",
    "vulnerability", "zafiyet", "finding", "bulgu", "template", "match", "nuclei",
    "critical", "high", "medium", "low", "info", "panel", "gateway", "console",
}


def _matching_findings_in_text(findings: list[dict[str, Any]], text: str) -> list[dict[str, Any]]:
    normalized_text = _normalized_similarity_text(text)
    text_tokens = set(normalized_text.split())
    token_frequency: Counter[str] = Counter()
    finding_tokens: list[set[str]] = []
    for finding in findings:
        tokens = {
            token
            for token in _normalized_similarity_text(_finding_title(finding)).split()
            if len(token) >= 4 and token not in _GENERIC_FINDING_IDENTITY_TOKENS
        }
        finding_tokens.append(tokens)
        token_frequency.update(tokens)

    matches: list[dict[str, Any]] = []
    for finding, distinctive_tokens in zip(findings, finding_tokens):
        title = _normalized_similarity_text(_finding_title(finding))
        url = _finding_url(finding)
        identity_values = {
            _normalized_similarity_text(str(finding.get(key) or ""))
            for key in ("id", "finding_id", "template_id", "template-id")
            if str(finding.get(key) or "").strip()
        }
        full_identity_match = bool(
            (len(title) >= 6 and title in normalized_text)
            or any(len(value) >= 4 and value in normalized_text for value in identity_values)
        )
        unique_token_match = any(
            token_frequency[token] == 1 and token in text_tokens
            for token in distinctive_tokens
        )
        if (url and url.lower() in text.lower()) or full_identity_match or unique_token_match:
            matches.append(finding)
    return matches


def _ordinal_index(text: str) -> int | None:
    for pattern, index in FINDING_ORDINAL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return index
    numeric = NUMERIC_FINDING_ORDINAL_PATTERN.search(text)
    if numeric:
        return int(numeric.group(1)) - 1
    return None


def _ordinal_finding(findings: list[dict[str, Any]], text: str) -> dict[str, Any]:
    index = _ordinal_index(text)
    return findings[index] if index is not None and 0 <= index < len(findings) else {}


def _selected_context_finding(
    context: dict[str, Any],
    question: str,
    history: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    findings = _top_context_findings(context, limit=10)
    if not findings:
        return {}

    latest_matches = _matching_findings_in_text(findings, question)
    if len(latest_matches) == 1:
        return latest_matches[0]
    latest_ordinal = _ordinal_finding(findings, question)
    if latest_ordinal:
        return latest_ordinal

    # The renderer's structured selection is the current conversation state.
    # It outranks stale history but never an explicit reference in this turn.
    referenced = _reference_finding(context, _as_record(context.get("conversation_reference")))
    if referenced:
        return referenced

    valid_history = [
        item
        for item in reversed(history or [])
        if isinstance(item, dict) and str(item.get("content") or "").strip()
    ]
    # Recent explicit user selection is the next-best source.
    for item in valid_history:
        if str(item.get("role") or "") != "user":
            continue
        text = str(item.get("content") or "")
        matches = _matching_findings_in_text(findings, text)
        if len(matches) == 1:
            return matches[0]
        ordinal = _ordinal_finding(findings, text)
        if ordinal:
            return ordinal

    # Assistant text is only an unambiguous last-resort history reference.
    for item in valid_history:
        if str(item.get("role") or "") != "assistant":
            continue
        text = str(item.get("content") or "")
        matches = _matching_findings_in_text(findings, text)
        if len(matches) == 1:
            return matches[0]
        ordinal = _ordinal_finding(findings, text)
        if ordinal:
            return ordinal
    return {}


def _repair_artifact_evidence(
    context: dict[str, Any],
    question: str,
    history: list[dict[str, str]],
) -> list[str]:
    finding = _selected_context_finding(context, question, history)
    if not finding:
        return []
    lines = [
        f"Bulgu başlığı: {_finding_title(finding)}",
        f"Kaynak/tool: {finding.get('source') or finding.get('tool') or 'nuclei'}",
        f"Severity: {_finding_severity(finding)}",
        f"Verification state: {finding.get('verification_state') or 'unverified'}",
    ]
    template_id = str(finding.get("template_id") or "").strip()
    if template_id and not contains_unresolved_placeholder_values(template_id):
        lines.append(f"Template ID: {template_id}")
    url = _finding_url(finding)
    lines.append(f"Gerçek artifact URL: {url}" if url else "Gerçek URL: Bu bilgi artifact içinde mevcut değil")
    for label, key in (
        ("HTTP status", "status_code"),
        ("Redirect", "redirect"),
        ("Fingerprint", "fingerprint"),
        ("Explicit validation evidence", "validation_evidence"),
    ):
        value = finding.get(key)
        if value not in (None, "", [], {}) and not contains_unresolved_placeholder_values(str(value)):
            lines.append(f"{label}: {value}")
    missing = finding.get("missing_evidence_fields")
    if isinstance(missing, list) and missing:
        lines.append("Eksik kanıt alanları: " + ", ".join(str(item) for item in missing[:8]))
    return lines


def _finding_action_plan(finding: dict[str, Any], requested: int) -> str:
    title = _finding_title(finding) if finding else "Artifact bulgusu"
    severity = _finding_severity(finding) if finding else "unknown"
    url = _finding_url(finding) if finding else ""
    endpoint_step = (
        f"Artifact'taki gerçek eşleşen adres {url} için hedefe aitlik, yönlendirme, 404, login ve soft-error kontrollerini yap."
        if url
        else "Bu bulgu için artifact içinde gerçek adres bulunmadığından uç nokta uydurma; önce eksik eşleşen adres kanıtını tamamla."
    )
    steps = [
        f"{title} ({severity}) kaydını bir Nuclei template eşleşmesi olarak aç; doğrulama durumu henüz doğrulanmadıysa false-positive ihtimalini koru.",
        endpoint_step,
        "Artifactteki eşleşen istek/yanıt, HTTP durumu/yönlendirme ve gerçek ürün izi verilerini karşılaştır; eksik alanları tamamlanmış varsayma.",
        f"Kanıt doğrulanırsa {title} ile ilişkili bileşenin sürüm/config düzeltmesini ve sorumlu ekibi belirle.",
        f"Düzeltmeden sonra aynı template ve aynı artifact URL kanıtıyla yeniden test et; sonucu bulgu kaydına ekle.",
        "Run kısmi veya interrupted ise eksik aşamaları yetkili kapsamda tamamla.",
        "Aynı template ailesindeki bulguları severity, etki ve kanıt gücüne göre sırala.",
        "Source health ve kapsam eksiklerini doğrulama sonucuna ekle.",
        "False-positive ihtimali kapanmadan bulguyu kesin zafiyet olarak işaretleme.",
        "Kapanış kararını yalnız yeniden doğrulanmış artifact kanıtıyla ver.",
    ]
    return "\n".join(f"{index}. {step}" for index, step in enumerate(steps[:requested], 1))


def _finding_explanation_fallback(
    finding: dict[str, Any],
    requested: int,
    *,
    question: str = "",
) -> str:
    title = _finding_title(finding) if finding else "Artifact bulgusu"
    severity = _finding_severity(finding) if finding else "unknown"
    source = str(finding.get("source") or finding.get("tool") or "nuclei") if finding else "nuclei"
    url = _finding_url(finding) if finding else ""
    verification = str(finding.get("verification_state") or "unverified") if finding else "unverified"
    missing = {str(item) for item in _as_list(finding.get("missing_evidence_fields"))}
    if verification == "unverified":
        identity_sentence = f"{title}, {source} tarafından kaydedilmiş bir template eşleşmesidir ve henüz doğrulanmadı."
    elif verification == "partially_verified":
        identity_sentence = f"{title}, {source} kaydında yalnız mevcut yanıt kanıtı kadar kısmen doğrulanmıştır."
    elif verification == "verified":
        identity_sentence = f"{title}, {source} kaydındaki açık doğrulama kanıtının gösterdiği sınırda doğrulanmıştır."
    else:
        identity_sentence = f"{title}, {source} tarafından kaydedilmiş bir template eşleşmesidir; doğrulama durumu {verification}."
    items = [identity_sentence]
    if url:
        items.append(f"Eşleşme {url} adresinde kaydedilmiş; gerçek yanıtın hedefe aitliği ayrıca karşılaştırılmalıdır.")
    if finding.get("validation_evidence") not in (None, "", [], {}):
        items.append(f"Artifactteki açık doğrulama kanıtı şu sınırdadır: {finding.get('validation_evidence')}.")
    else:
        items.append("Mevcut artifact, başlıktaki ürünün varlığını veya iddia edilen etkiyi tek başına doğrulamıyor.")
    if finding.get("status_code") not in (None, "", [], {}):
        items.append(f"Kaydedilen HTTP durumu {finding.get('status_code')}; durum kodu tek başına zafiyet doğrulaması değildir.")
    if finding.get("redirect") not in (None, "", [], {}):
        items.append(f"Artifactte yönlendirme bilgisi bulunuyor: {finding.get('redirect')}; son içerikle birlikte değerlendirilmelidir.")
    if finding.get("fingerprint") not in (None, "", [], {}):
        items.append(f"Mevcut ürün izi {finding.get('fingerprint')} ile sınırlıdır; başlığın ötesinde ürün ayrıntısı çıkarılamaz.")
    elif "product_fingerprint" in missing:
        items.append("Ürün izi bulunmadığı için başlıkta geçen ürünün gerçekten kurulu olduğu sonucuna varılamaz.")
    if finding.get("response_evidence_present") is True:
        items.append("Artifactte istek veya yanıt kanıtı var; false-positive ayrımı bu kayıt ile negatif baseline yanıtının karşılaştırılmasına dayanmalıdır.")
    else:
        items.append("Kayıtlı istek/yanıt kanıtı olmadan eşleşmenin gerçek etkisi doğrulanmış sayılamaz.")
    if severity in {"critical", "high"}:
        natural_severity = "kritik" if severity == "critical" else "yüksek"
        items.append(f"Önem seviyesi {natural_severity} olarak işaretlenmiş; bu öncelik sağlar fakat doğrulanmış etki anlamına gelmez.")
    if missing:
        items.append("Eksik kanıtlar nedeniyle ortak hata sayfası, login yönlendirmesi veya soft-404 olasılığı dışlanmış değildir.")
    if re.search(r"false[- ]?positive|yanl[ıi]ş\s+pozitif", question, re.IGNORECASE):
        items.insert(1, "False-positive mümkündür; karar, eşleşen yanıt ile aynı hedefteki negatif kontrol yanıtının farkına dayanmalıdır.")
    count = min(10, max(1, requested))
    return "\n".join(f"{index}. {item}" for index, item in enumerate(items[:count], 1))


def _report_summary_fallback(context: dict[str, Any], question: str = "") -> str:
    packet = _grounding_fact_packet(
        context,
        answer_intent="short_summary",
        context_profile="report_summary",
    )
    target = packet.get("target") or "mevcut hedef"
    state = str(packet.get("run_state") or "unknown").lower()
    state_text = {
        "running": "tarama hâlâ sürüyor ve özet final değil",
        "interrupted": "tarama tamamlanmadan kesilmiş ve özet final değil",
        "stopped": "tarama tamamlanmadan durdurulmuş ve özet final değil",
        "completed": "tarama tamamlanmış",
    }.get(state, f"run durumu {state}" if state != "unknown" else "run durumu artifactte net değil")
    score = packet.get("risk_score")
    band = packet.get("risk_band")
    risk_text = f"risk {score}/100 ({band})" if _present(score) else f"risk seviyesi {band}" if band else "risk bilgisi sınırlı"
    sentences = [f"{target} için {state_text}; {risk_text} görünüyor."]
    count = packet.get("findings_count")
    top = [_as_record(item) for item in _as_list(packet.get("top_findings"))]
    titles = [str(item.get("title")) for item in top[:2] if item.get("title")]
    if isinstance(count, int) and count > 0:
        detail = f"; öne çıkanlar {', '.join(titles)}" if titles else ""
        sentences.append(f"Artifactte {count} Nuclei eşleşmesi bulunuyor{detail}; bunlar manuel doğrulama gerektiriyor.")
    elif isinstance(count, int):
        sentences.append("Artifactte Nuclei eşleşmesi görünmüyor; bu tek başına hedefin temiz olduğunu kanıtlamaz.")
    coverage = _as_record(packet.get("coverage"))
    coverage_confidence = coverage.get("coverage_confidence")
    if coverage_confidence and str(coverage_confidence).lower() != "high":
        sentences.append(f"Kaynak kapsamı {coverage_confidence}; eksik kapsam nedeniyle kesin temiz sonucu çıkarılamaz.")
    return " ".join(sentences[:2] if _is_short_summary_request(question) else sentences)


def _finding_operational_fallback(finding: dict[str, Any], question: str) -> str:
    """Answer common verification intents without inventing missing artifact fields."""
    title = _finding_title(finding) if finding else "Artifact içinde seçilebilir bulgu detayı yok"
    severity = _finding_severity(finding) if finding else "unknown"
    url = _finding_url(finding) if finding else ""
    verification = str(finding.get("verification_state") or "unverified") if finding else "unverified"
    identity = f"Seçilen kayıt {title} ({severity}); doğrulama durumu {verification}."
    url_fact = (
        f"Artifactteki gerçek eşleşen adres {url}."
        if url
        else "Bu kayıt için artifact içinde gerçek eşleşen adres yok; uç nokta değeri uydurulamaz."
    )
    normalized = str(question or "")
    if re.search(r"(?:endpoint.*(?:neden|niye|eşleş)|(?:neden|niye).*endpoint)", normalized, re.IGNORECASE):
        return "\n".join([
            identity,
            "Endpoint, Nuclei template'indeki yol/içerik/header koşullarından biri yanıtla eşleştiği için işaretlenmiş olabilir; bu tek başına zafiyetin doğrulandığı anlamına gelmez.",
            url_fact,
            "Matched response status, header/body izi, redirect zinciri ve aynı hedefte var olmayan bir yolun baseline yanıtını karşılaştır.",
            "Login sayfası, wildcard route, soft-404 veya ortak hata gövdesi aynı imzayı üretiyorsa false-positive olasılığı yüksektir.",
        ])
    if re.search(r"false[- ]?positive|yanl[ıi]ş\s+pozitif", normalized, re.IGNORECASE):
        return " ".join([
            identity,
            "Evet, false-positive olabilir.",
            url_fact,
            "Ortak hata sayfası, login yönlendirmesi, soft-404 veya ürün izinin bulunmaması bu ihtimali artırır; yalnız tekrarlanabilir ve hedefe ait kanıt varsa doğrulama durumunu yükselt.",
        ])
    if re.search(r"(?:request.*response|response.*request|istek.*yan[ıi]t|yan[ıi]t.*istek)", normalized, re.IGNORECASE):
        return "\n".join([
            identity,
            f"1. {url_fact}",
            "2. Artifactte gerçekten bulunan eşleşen istek için method, path, query, gerekli header ve redakte body alanlarını ayrı kaydet.",
            "3. Eşleşen yanıt için durum kodu, yönlendirme, header ve yalnız eşleşmeyi açıklayan body parçasını karşılaştır; artifactte olmayan içeriği ekleme.",
            "4. Aynı isteğin baseline/negatif kontrol yanıtını alarak ortak hata sayfası, login redirecti ve soft-404 olasılığını ele.",
            "5. Secret, token ve kişisel verileri kanıt kaydına koymadan önce redakte et; eksik request/response alanlarını 'mevcut değil' olarak işaretle.",
        ])
    return ""


def _natural_finding_fallback(finding: dict[str, Any], question: str) -> str:
    if not finding:
        return "Seçili bulguyu açıklamak için artifact içinde yeterli kayıt bulunamadı."
    if re.search(r"(?:hangi\s+(?:bulgu|finding)|hangisi|konuştuğumuz\s+(?:bulgu|finding)|önceki\s+(?:bulgu|finding))", question, re.IGNORECASE):
        return f"{_finding_title(finding)} bulgusu hakkında konuşuyorduk."
    operational = _finding_operational_fallback(finding, question)
    if operational:
        return operational
    numbered = _finding_explanation_fallback(finding, 2, question=question)
    sentences = [re.sub(r"^\d+[.)]\s+", "", line).strip() for line in numbered.splitlines() if line.strip()]
    return " ".join(sentences)


def deterministic_empty_lm_fallback(context: dict[str, Any], question: str = "") -> str:
    current = _as_record(context.get("current_run_context"))
    run = _as_record(context.get("run"))
    risk = _as_record(context.get("risk"))
    raw_target = str(current.get("target") or context.get("target") or "").strip()
    target = raw_target if raw_target and not contains_unresolved_placeholder_values(raw_target) else "hedef bilgisi artifact içinde net değil"
    run_state = _natural_run_state(current.get("run_state") or run.get("state"))
    risk_score = current.get("risk_score") if current.get("risk_score") is not None else risk.get("score")
    risk_band = current.get("risk_band") or risk.get("verdict") or "belirsiz"
    risk_text = f"{risk_score}/100" if _present(risk_score) else "n/a"
    findings_count = _findings_count(context)
    top_findings = _top_context_findings(context)
    interrupted = _run_is_interrupted(current.get("run_state") or run.get("state"))
    running = _run_is_active(current.get("run_state") or run.get("state"))

    if findings_count <= 0 and not top_findings:
        return "\n".join(
            [
                f"Hedef: {target}. Bu contextte güçlü Nuclei bulgu sinyali görünmüyor; bu yine de temiz hedef kanıtı değildir.",
                f"Run durumu: {run_state}; risk: {risk_text} {risk_band}.",
                "Kontrol sırası:",
                "1. reconbot.log içinde hata, timeout ve skipped tool kayıtlarını kontrol et.",
                "2. Source health düşük veya kısmi ise eksik kaynakları ayrıca not et.",
                "3. Settings içinde Nuclei, Katana/FFUF ve timeout limitleri hedef kapsamına göre kapalı mı kontrol et.",
                "4. Kapsam izin veriyorsa temiz bir Fast/Balanced doğrulama taraması çalıştır.",
            ]
        )

    finding_lines: list[str] = []
    for index, finding in enumerate(top_findings, 1):
        url = _finding_url(finding)
        suffix = f" - {url}" if url else ""
        finding_lines.append(f"{index}. {_finding_title(finding)} ({_finding_severity(finding)}){suffix}")

    status_note = f"Run durumu: {run_state}; risk: {risk_text} {risk_band}; Nuclei bulguları: {findings_count}."
    if interrupted or running:
        status_note += " Run final değil; false-positive riskini düşürmeden kesin sonuç çıkarma."

    if _is_short_summary_request(question):
        lines = [
            f"Hedef: {target}.",
            status_note,
            "En kritik kayıtlar:",
            *(finding_lines or ["1. Top finding artifact içinde net değil; Findings/Nuclei detayını aç."]),
            "İlk öneri: kritik/high Nuclei kanıtını doğrula; matched URL, request/response, redirect/404/soft-error ve hedefe aitlik kontrolünü bitirmeden sömürü varsayımı yapma.",
        ]
        return "\n".join(lines)

    lines = [
        "En kritik Nuclei bulgusu için kanıt doğrulama ve triage ile başla.",
        status_note,
        "Top bulgular:",
        *(finding_lines or ["1. Top finding artifact içinde net değil; Findings/Nuclei detayını aç."]),
        "Sırayla:",
        "1. Nuclei evidence kısmındaki matched URL, request ve response bilgisini aç.",
        "2. Endpoint gerçekten bu hedefe mi ait; redirect, 404, login sayfası veya soft-error mı kontrol et.",
        "3. RCE bulgularını file-read veya düşük etkili bulgulardan önce incele.",
        "4. Kanıt güvenilirse affected endpoint'i izole et veya servisi geçici kapat; sonra ilgili template/CVE bilgisine göre patch ve config kontrolü yap.",
        "5. Run interrupted/partial ise aynı hedefe temiz bir Fast/Balanced doğrulama taraması çalıştır.",
        "Bunu yetkili lab/defansif doğrulama çerçevesinde tut; payload, bypass veya yetkisiz sömürü adımı üretme.",
    ]
    return "\n".join(lines)


def _reference_paths(ai_context: Any) -> list[str]:
    return [ref.path for ref in ai_context.references]


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _request_metadata(payload: dict[str, Any], context: dict[str, Any], context_profile: str, question: str) -> dict[str, str]:
    run = _as_record(context.get("run"))
    request_id = str(payload.get("request_id") or payload.get("requestId") or f"ai-{datetime.now(UTC).timestamp():.6f}")
    return {
        "request_id": request_id,
        "created_at": str(payload.get("created_at") or payload.get("createdAt") or _now_iso()),
        "source": str(payload.get("source") or "chat_input"),
        "user_message": question,
        "context_profile": context_profile,
        "run_id": str(payload.get("run_id") or payload.get("runId") or run.get("current_run_dir") or ""),
        "target": str(payload.get("target") or context.get("target") or ""),
    }


def _metadata_response_fields(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "request_id": metadata["request_id"],
        "created_at": metadata["created_at"],
        "source": metadata["source"],
        "user_message": metadata["user_message"],
        "latest_user_message": metadata["user_message"],
        "context_profile": metadata["context_profile"],
        "run_id": metadata["run_id"],
        "target": metadata["target"],
    }


def _context_with_conversation_reference(ai_context: AIContext, reference: dict[str, Any]) -> AIContext:
    if not reference:
        return ai_context
    context = dict(ai_context.context)
    context["conversation_reference"] = redact_obj(reference)
    return AIContext(context=context, references=ai_context.references, truncated=ai_context.truncated)


def _context_with_selected_finding(ai_context: AIContext, finding: dict[str, Any]) -> AIContext:
    if not finding:
        return ai_context
    existing = dict(ai_context.context)
    profile = str(existing.get("context_profile") or "finding_question")
    if profile in {"finding_question", "continuation"}:
        context = {
            "context_profile": profile,
            "selected_finding": redact_obj(finding),
            "source_boundaries": redact_obj(_as_record(existing.get("source_boundaries"))),
        }
    else:
        context = existing
        # Report-wide review still needs coverage and lifecycle facts. Avoid
        # duplicating a full finding row at the expense of that run snapshot.
        selected = ({key: finding[key] for key in (
            "title", "template_id", "severity", "url", "verification_state",
            "validation", "response_evidence_present",
        ) if key in finding} if profile in {"trust", "operational_question"} else finding)
        context["selected_finding"] = redact_obj(selected)
    return AIContext(
        context=context,
        references=[] if profile in {"finding_question", "continuation"} else ai_context.references,
        truncated=ai_context.truncated,
    )


def _context_with_grounding_facts(ai_context: AIContext, grounding_facts: dict[str, Any]) -> AIContext:
    if not grounding_facts:
        return ai_context
    context = dict(ai_context.context)
    context["grounding_facts"] = redact_obj(grounding_facts)
    return AIContext(context=context, references=ai_context.references, truncated=ai_context.truncated)


def _serialized_context_chars(ai_context: AIContext) -> int:
    return len(context_as_prompt_text(ai_context))


def _fit_context_and_plan(
    *,
    initial_context: AIContext,
    config: Any,
    answer_intent: str,
    context_profile: str,
    question: str,
    conversation_history: Any,
    model_metadata: dict[str, Any],
    run_dir: Any,
    request_settings: dict[str, Any],
    provided_snapshot: dict[str, Any],
    conversation_reference: dict[str, Any],
    selected_finding: dict[str, Any],
    grounding_facts: dict[str, Any],
) -> tuple[AIContext, Any]:
    """Rebuild until the exact provider-facing context serialization fits."""
    def decorate(candidate: AIContext) -> AIContext:
        candidate = _context_with_selected_finding(candidate, selected_finding)
        candidate = _context_with_conversation_reference(candidate, conversation_reference)
        return _context_with_grounding_facts(candidate, grounding_facts)

    ai_context = decorate(initial_context)
    actual_chars = _serialized_context_chars(ai_context)
    initial_plan = resolve_ai_request_plan(
        config,
        answer_intent=answer_intent,
        context_profile=context_profile,
        user_message=question,
        injected_context=ai_context.context,
        conversation_history=conversation_history,
        model_metadata=model_metadata,
        serialized_context_chars=actual_chars,
    )
    compacted = bool(initial_plan.context_was_compacted or ai_context.truncated)
    if initial_plan.context_was_compacted:
        rebuild_budget = max(0, int(initial_plan.context_budget_chars))
        ai_context = (
            build_ai_context(
                run_dir,
                request_settings,
                rebuild_budget,
                profile=context_profile,
                provided_snapshot=provided_snapshot,
            )
            if rebuild_budget >= 600
            else AIContext(context={"context_profile": context_profile}, references=[], truncated=True)
        )
        ai_context = decorate(ai_context)

    configured_ceiling = max(0, int(config.maxContextChars))
    effective_ceiling = max(
        0,
        min(configured_ceiling, int(initial_plan.context_budget_chars or configured_ceiling)),
    )
    build_budget = effective_ceiling
    for _attempt in range(12):
        actual_chars = _serialized_context_chars(ai_context)
        if actual_chars <= effective_ceiling:
            break
        compacted = True
        if ai_context.references:
            ai_context = AIContext(context=ai_context.context, references=[], truncated=True)
            continue
        overshoot = actual_chars - effective_ceiling
        next_budget = max(0, min(build_budget - 1, build_budget - overshoot - 32))
        if next_budget >= 600 and next_budget < build_budget:
            build_budget = next_budget
            ai_context = build_ai_context(
                run_dir,
                request_settings,
                build_budget,
                profile=context_profile,
                provided_snapshot=provided_snapshot,
            )
            ai_context = decorate(ai_context)
            continue
        minimal_context: dict[str, Any] = {"context_profile": context_profile}
        if grounding_facts:
            minimal_context["grounding_facts"] = redact_obj(grounding_facts)
        if conversation_reference:
            minimal_context["conversation_reference"] = redact_obj(conversation_reference)
        ai_context = AIContext(context=minimal_context, references=[], truncated=True)
        if _serialized_context_chars(ai_context) > effective_ceiling and conversation_reference:
            minimal_context.pop("conversation_reference", None)
            ai_context = AIContext(context=minimal_context, references=[], truncated=True)
        if _serialized_context_chars(ai_context) > effective_ceiling:
            ai_context = AIContext(context={}, references=[], truncated=True)
        break

    actual_chars = _serialized_context_chars(ai_context)
    if actual_chars > effective_ceiling and ai_context.references:
        compacted = True
        ai_context = AIContext(context=ai_context.context, references=[], truncated=True)
        actual_chars = _serialized_context_chars(ai_context)
    if actual_chars > effective_ceiling:
        compacted = True
        minimal_context: dict[str, Any] = {"context_profile": context_profile}
        if grounding_facts:
            minimal_context["grounding_facts"] = redact_obj(grounding_facts)
        if conversation_reference:
            minimal_context["conversation_reference"] = redact_obj(conversation_reference)
        ai_context = AIContext(context=minimal_context, references=[], truncated=True)
        if _serialized_context_chars(ai_context) > effective_ceiling and conversation_reference:
            minimal_context.pop("conversation_reference", None)
            ai_context = AIContext(context=minimal_context, references=[], truncated=True)
        if _serialized_context_chars(ai_context) > effective_ceiling:
            ai_context = AIContext(context={}, references=[], truncated=True)

    actual_chars = _serialized_context_chars(ai_context)
    plan = resolve_ai_request_plan(
        config,
        answer_intent=answer_intent,
        context_profile=context_profile,
        user_message=question,
        injected_context=ai_context.context,
        conversation_history=conversation_history,
        model_metadata=model_metadata,
        serialized_context_chars=actual_chars,
    )
    return ai_context, replace(
        plan,
        effective_injected_context_chars=actual_chars,
        injected_context_chars=actual_chars,
        context_was_compacted=bool(compacted or plan.context_was_compacted),
    )


def _wants_evidence_paths(question: str) -> bool:
    normalized = question.lower()
    return any(
        marker in normalized
        for marker in (
            "kanıt path",
            "pathleri göster",
            "pathlerini göster",
            "field path",
            "json path",
            "raw path",
            "context path",
            "referans path",
        )
    )


def _remove_json_blocks(text: str) -> str:
    return JSON_BLOCK_PATTERN.sub("", text)


def _line_has_prompt_leak(line: str) -> bool:
    return any(pattern.search(line) for pattern in PROMPT_LEAK_PATTERNS)


def _normalized_block_key(value: str) -> str:
    return re.sub(r"[^a-z0-9çğıöşü]+", " ", value.lower()).strip()


def _collapse_duplicate_blocks(text: str) -> str:
    blocks = re.split(r"\n{2,}", text.strip())
    seen_blocks: set[str] = set()
    unique_blocks: list[str] = []
    for block in blocks:
        key = _normalized_block_key(block)
        if key and len(key) > 24 and key in seen_blocks:
            continue
        if key:
            seen_blocks.add(key)
        unique_blocks.append(block)
    lines: list[str] = []
    seen_lines: set[str] = set()
    seen_headings: set[str] = set()
    heading_names = {
        "durum",
        "önemli bulgular",
        "guvenilirlik eksik kapsam",
        "güvenilirlik eksik kapsam",
        "sonraki adım",
        "ilk bakılacak yer",
        "rapor özeti",
        "kanıt",
    }
    for line in "\n\n".join(unique_blocks).splitlines():
        key = _normalized_block_key(line)
        is_heading = key in heading_names
        if is_heading:
            if key in seen_headings:
                continue
            seen_headings.add(key)
        elif key and len(key) > 18:
            if key in seen_lines:
                continue
            seen_lines.add(key)
        lines.append(line)
    return "\n".join(lines).strip()


def _has_substantive_visible_content(text: str) -> bool:
    heading_names = {
        "durum",
        "önemli bulgular",
        "güvenilirlik eksik kapsam",
        "sonraki adım",
        "ilk bakılacak yer",
        "rapor özeti",
        "kanıt",
    }
    for line in text.splitlines():
        clean = re.sub(r"^\s*(?:#+|\d+[.)]|[-*•])\s*", "", line).strip()
        if not clean or _normalized_block_key(clean) in heading_names:
            continue
        if clean.endswith(":"):
            continue
        if len(_normalized_block_key(clean)) >= 3:
            return True
    return False


def _repair_unknown_claims(text: str, context: dict[str, Any] | None) -> str:
    if not context:
        return text
    current = _as_record(context.get("current_run_context"))
    risk_score = current.get("risk_score")
    nuclei_count = current.get("nuclei_findings_count")
    run_state = current.get("run_state")
    if _present(risk_score):
        text = re.sub(r"\b(risk(?: skoru)?\s*[:=-]?\s*)unknown\b", rf"\g<1>{risk_score}/100", text, flags=re.IGNORECASE)
        text = re.sub(r"\b(risk(?: skoru)?\s*[:=-]?\s*)bilinmiyor\b", rf"\g<1>{risk_score}/100", text, flags=re.IGNORECASE)
    if isinstance(nuclei_count, int):
        text = re.sub(r"\b(nuclei(?: bulgular[ıi])?\s*[:=-]?\s*)unknown\b", rf"\g<1>{nuclei_count}", text, flags=re.IGNORECASE)
        text = re.sub(r"\b(nuclei(?: bulgular[ıi])?\s*[:=-]?\s*)bilinmiyor\b", rf"\g<1>{nuclei_count}", text, flags=re.IGNORECASE)
    if _present(run_state):
        text = re.sub(r"\b(run durumu\s*[:=-]?\s*)unknown\b", rf"\g<1>{run_state}", text, flags=re.IGNORECASE)
        text = re.sub(r"\b(run durumu\s*[:=-]?\s*)bilinmiyor\b", rf"\g<1>{run_state}", text, flags=re.IGNORECASE)
    return text


def _repair_false_zero_claims(lines: list[str], context: dict[str, Any] | None) -> list[str]:
    if not context:
        return lines
    current = _as_record(context.get("current_run_context"))
    risk_score = current.get("risk_score")
    nuclei_count = current.get("nuclei_findings_count")
    has_findings = isinstance(nuclei_count, int) and nuclei_count > 0
    risk_is_positive = isinstance(risk_score, (int, float)) and risk_score > 0
    repaired: list[str] = []
    for line in lines:
        stripped = line.strip()
        lower = stripped.lower()
        if has_findings and re.search(r"nuclei.*[:=-]?\s*0\b", lower):
            repaired.append(f"Nuclei bulguları: {nuclei_count}")
            continue
        if has_findings and re.search(r"(önemli\s+bulgular|bulgular|finding).*[:=-]?\s*(yok|0\b)", lower):
            label = "Önemli bulgular" if "önemli" in lower else "Bulgular"
            repaired.append(f"{label}: {nuclei_count}")
            continue
        if risk_is_positive and re.search(r"risk(?: skoru)?\s*[:=-]?\s*0\s*/\s*100", lower):
            repaired.append(f"Risk: {risk_score}/100")
            continue
        repaired.append(line)
    return repaired


def _sanitize_visible_answer(
    answer: str,
    context: dict[str, Any] | None = None,
    *,
    strip_json: bool = False,
    allow_paths: bool = False,
) -> str:
    text = redact_text(answer or "", mode="ui_display_redaction")
    text = text.replace(REDACTION_MARK, "").replace("[REDACTED]", "")
    text = re.sub(r"\bdoğrulanmamış\s+değil(?:dir)?\b", "doğrulanmış değildir", text, flags=re.IGNORECASE)
    fallback_text = text.strip()
    if strip_json:
        text = _remove_json_blocks(text)
    for raw, friendly in RAW_FIELD_REPLACEMENTS.items():
        text = text.replace(raw.replace("_", "\\_"), friendly)
        text = text.replace(raw, friendly)
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped and (not lines or not lines[-1].strip()):
            continue
        if not stripped:
            lines.append(line)
            continue
        if stripped in {"-", ":", "•", "#", "##", "###"}:
            continue
        if GENERIC_REDACTION_NOTE_PATTERN.search(stripped):
            continue
        if _line_has_prompt_leak(stripped):
            continue
        if not allow_paths and RAW_CONTEXT_PATH_PATTERN.search(stripped):
            # Keep the meaning out of the main answer instead of leaking JSON paths.
            continue
        lines.append(line)
    lines = _repair_false_zero_claims(lines, context)
    text = "\n".join(lines).strip()
    text = _repair_unknown_claims(text, context)
    text = _collapse_duplicate_blocks(text)
    if text and not _has_substantive_visible_content(text):
        text = ""
    if text:
        return text
    if (
        fallback_text
        and not strip_json
        and not _line_has_prompt_leak(fallback_text)
        and not GENERIC_REDACTION_NOTE_PATTERN.search(fallback_text)
        and (allow_paths or not RAW_CONTEXT_PATH_PATTERN.search(fallback_text))
    ):
        return fallback_text
    return ""


def _visible_answer_for_mode(raw_answer: str, context: dict[str, Any], mode: str, question: str, *, action_plan: Any = None) -> str:
    return _sanitize_visible_answer(
        raw_answer,
        context,
        strip_json=action_plan is not None,
        allow_paths=_wants_evidence_paths(question),
    )


def _is_operational_question(question: str) -> bool:
    return bool(
        OPERATIONAL_CONTEXT_PATTERN.search(question or "")
        or _is_action_plan_request(question)
        or _is_operational_guidance_request(question)
    )


def _is_action_plan_request(question: str) -> bool:
    return bool(ACTION_PLAN_PATTERN.search(question or ""))


def _is_operational_guidance_request(question: str) -> bool:
    return bool(OPERATIONAL_GUIDANCE_PATTERN.search(question or ""))


def _response_preferences(question: str) -> ResponsePreferences:
    value = question or ""
    count_match = REQUESTED_COUNT_PATTERN.search(value)
    requested_count = min(10, max(1, int(count_match.group(1)))) if count_match else None
    requested_format = None
    if count_match:
        requested_format = "numbered_list" if re.search(r"ad[ıi]m", count_match.group(0), re.IGNORECASE) else "list"
    elif NUMBERED_LIST_PREFERENCE_PATTERN.search(value):
        requested_format = "numbered_list"
    elif re.search(r"\b(?:madde|liste)\s+(?:halinde|olarak|biçiminde)", value, re.IGNORECASE):
        requested_format = "list"
    elif PARAGRAPH_PREFERENCE_PATTERN.search(value):
        requested_format = "paragraph"
    return ResponsePreferences(
        requested_item_count=requested_count,
        requested_format=requested_format,
        single_sentence=bool(EXPLICIT_SINGLE_SENTENCE_PATTERN.search(value)),
        short_answer=bool(SHORT_ANSWER_PREFERENCE_PATTERN.search(value)),
        no_heading=bool(NO_HEADING_PREFERENCE_PATTERN.search(value)),
    )


def _is_report_context_question(question: str) -> bool:
    return bool(REPORT_CONTEXT_PATTERN.search(question or ""))


def _is_short_summary_request(question: str) -> bool:
    return bool(SHORT_SUMMARY_PATTERN.search(question or ""))


def _is_detailed_request(question: str) -> bool:
    return bool(DETAILED_PATTERN.search(question or ""))


def _is_evidence_request(question: str) -> bool:
    return bool(EVIDENCE_REQUEST_PATTERN.search(question or ""))


def _response_needs_empty_final_fallback(response: ChatResponse) -> bool:
    debug = _as_record(response.endpoint_debug)
    parser_reason = str(debug.get("parserReason") or response.error or response.status or "")
    return parser_reason in {
        "empty_message_content",
        "reasoning_without_final",
        "length_without_content",
    }


def _allows_deterministic_fallback(mode: str, question: str, context_profile: str) -> bool:
    if context_profile in {"report_summary", "quick_report_summary", "finding_question", "operational_question", "logs", "log_troubleshooting", "trust", "ai_failure_diagnostics"}:
        return True
    if context_profile == "continuation" and (
        _is_action_plan_request(question)
        or _is_operational_guidance_request(question)
        or FOLLOWUP_CONTEXT_PATTERN.search(question)
    ):
        return True
    return mode in {"report", "brief", "trust", "next", "finding", "logs"} and _is_report_context_question(question)


def _normalized_similarity_text(value: str) -> str:
    return re.sub(r"[^a-z0-9çğıöşü]+", " ", (value or "").lower()).strip()


def _action_item_count(answer: str) -> int:
    """Count explicit, meaningful list items without judging their vocabulary."""
    return len(_meaningful_list_items(answer))


def _meaningful_list_items(answer: str) -> list[tuple[int, str]]:
    items: list[tuple[int, str]] = []
    for index, line in enumerate(answer.splitlines()):
        match = re.match(r"^\s*(?:\*\*)?(?:\d+[.)]|[-*•])(?:\*\*)?\s+(.+?)\s*$", line)
        if not match:
            continue
        item = _normalized_similarity_text(match.group(1))
        if len(item) >= 6 and len(item.split()) >= 2:
            items.append((index, match.group(1).strip()))
    return items


def _requested_items_contract_failure(
    question: str,
    answer: str,
    preferences: ResponsePreferences,
) -> str:
    requested = preferences.requested_item_count
    if requested is None:
        return ""
    items = _meaningful_list_items(answer)
    if len(items) != requested:
        return "requested_items_missing"
    item_line_indexes = {index for index, _body in items}
    connective_entries = [
        (index, line.strip())
        for index, line in enumerate(answer.splitlines())
        if line.strip() and index not in item_line_indexes
    ]
    connective_lines = [line for _index, line in connective_entries]
    connective_text = " ".join(connective_lines)
    first_item_index = min(item_line_indexes) if item_line_indexes else 0
    concise_intro_only = bool(
        connective_entries
        and len(connective_entries) == 1
        and connective_entries[0][0] < first_item_index
        and len(connective_text) <= 160
        and len(re.findall(r"[.!?]+(?:\s+|$)", connective_text)) <= 1
    )
    if not concise_intro_only and (
        len(connective_lines) > 2
        or len(connective_text) > 80
        or len(re.findall(r"[.!?]+(?:\s+|$)", connective_text)) > 1
    ):
        return "requested_items_with_extra_body"
    if not re.search(r"(?:risk|run\s+durumu|bulgu\s+say[ıi]s[ıi]|kaç\s+bulgu|tarama\s+durumu)", question, re.IGNORECASE):
        metadata_fillers = sum(
            1
            for _index, body in items
            if re.search(
                r"(?:risk\s+skoru|run\s+durumu|bulgu\s+say[ıi]s[ıi]|tarama\s+durumu)",
                body,
                re.IGNORECASE,
            )
        )
        if metadata_fillers >= max(2, requested - 1):
            return "requested_items_are_metadata_filler"
    normalized_items = [_normalized_similarity_text(body) for _index, body in items]
    common_tokens = set.intersection(*(set(item.split()) for item in normalized_items)) if normalized_items else set()
    distinct_items = [
        " ".join(token for token in item.split() if token not in common_tokens)
        for item in normalized_items
    ]
    similar_pairs = sum(
        1
        for index, current in enumerate(distinct_items)
        for previous in distinct_items[:index]
        if SequenceMatcher(None, previous, current).ratio() >= 0.65
    )
    if requested >= 3 and similar_pairs >= max(2, requested - 2):
        return "requested_items_are_repetitive"
    return ""


def _sentence_count(answer: str) -> int:
    """Count natural-language sentences only for an explicit sentence-count request."""
    lines = [line.strip() for line in answer.splitlines() if line.strip()]
    if len(lines) > 1:
        return len(lines)
    text = lines[0] if lines else ""
    chunks = [
        chunk.strip()
        for chunk in re.split(r"[.!?]+(?:[\"')\]]+)?(?:\s+|$)", text)
        if chunk.strip()
    ]
    return max(1, len(chunks)) if text else 0


def _previous_assistant_answer(history: list[dict[str, str]]) -> str:
    for turn in reversed(history):
        if turn.get("role") == "assistant" and turn.get("content", "").strip():
            return turn["content"]
    return ""


def _contains_fact_value(answer: str, value: Any) -> bool:
    if value in (None, "", [], {}):
        return False
    normalized_answer = _normalized_similarity_text(answer)
    if isinstance(value, (int, float)):
        return bool(re.search(rf"(?<!\d){re.escape(str(value))}(?!\d)", answer))
    normalized_value = _normalized_similarity_text(str(value))
    if len(normalized_value) < 4:
        return False
    if normalized_value in normalized_answer:
        return True
    meaningful_tokens = [token for token in normalized_value.split() if len(token) >= 5]
    return bool(meaningful_tokens) and all(token in normalized_answer.split() for token in meaningful_tokens[:3])


def _report_relevance_anchors(answer: str, packet: dict[str, Any]) -> tuple[set[str], set[str]]:
    visible = answer or ""
    normalized = _normalized_similarity_text(visible)
    matched: set[str] = set()
    available: set[str] = set()
    target = packet.get("target")
    if _present(target):
        available.add("target")
        target_text = str(target)
        host = urlparse(target_text).netloc or target_text
        if _contains_fact_value(visible, target_text) or _contains_fact_value(visible, host):
            matched.add("target")
    state = str(packet.get("run_state") or "").lower()
    if state:
        available.add("run_state")
        state_patterns = {
            "running": r"\b(?:running|devam\s+ediyor|sürüyor|tamamlanmad[ıi]|final\s+değil)\b",
            "interrupted": r"\b(?:interrupted|kesil|durdur|yar[ıi]m|tamamlanmadan|final\s+değil)\w*\b",
            "stopped": r"\b(?:stopped|durdur|kesil|tamamlanmadan|final\s+değil)\w*\b",
            "completed": r"\b(?:completed|tamamland[ıi]|tamamlanm[ıi][şs]|final)\b",
        }
        pattern = next((pattern for key, pattern in state_patterns.items() if key in state), re.escape(state))
        if re.search(pattern, visible, re.IGNORECASE):
            matched.add("run_state")
    score = packet.get("risk_score")
    band = str(packet.get("risk_band") or "").lower()
    if _present(score) or band:
        available.add("risk")
        band_patterns = {
            "critical": r"\b(?:critical|kritik)\b",
            "high": r"\b(?:high|yüksek)\b",
            "elevated": r"\b(?:elevated|orta|yükselmiş)\b",
            "medium": r"\b(?:medium|orta)\b",
            "low": r"\b(?:low|düşük)\b",
        }
        band_match = bool(band and re.search(band_patterns.get(band, re.escape(band)), visible, re.IGNORECASE))
        if (_present(score) and _contains_fact_value(visible, score)) or band_match:
            matched.add("risk")
    count = packet.get("findings_count")
    if isinstance(count, int):
        available.add("finding_count")
        if re.search(
            rf"(?:\b{count}\b.{{0,24}}\b(?:bulgu|eşleşme|nuclei)|\b(?:bulgu|eşleşme|nuclei)\b.{{0,24}}\b{count}\b)",
            visible,
            re.IGNORECASE | re.DOTALL,
        ):
            matched.add("finding_count")
    top_findings = [_as_record(item) for item in _as_list(packet.get("top_findings")) if isinstance(item, dict)]
    if top_findings:
        available.add("top_finding")
        if _matching_findings_in_text(top_findings, normalized):
            matched.add("top_finding")
    coverage = _as_record(packet.get("coverage"))
    coverage_confidence = str(coverage.get("coverage_confidence") or "").lower()
    partial_notes = _as_list(packet.get("partial_coverage_notes"))
    if coverage_confidence or partial_notes:
        available.add("coverage")
        if re.search(r"\b(?:kapsam|coverage|k[ıi]smi|partial|eksik|s[ıi]n[ıi]rl[ıi])\w*\b", visible, re.IGNORECASE):
            matched.add("coverage")
    if packet.get("report_available") is not None:
        available.add("report_available")
        if re.search(r"\b(?:rapor|artifact)\b", visible, re.IGNORECASE):
            matched.add("report_available")
    return matched, available


def _finding_relevance_anchors(answer: str, packet: dict[str, Any]) -> tuple[bool, set[str], set[str]]:
    visible = answer or ""
    finding = _as_record(packet.get("selected_finding"))
    identity = bool(finding and _matching_findings_in_text([finding], visible))
    matched: set[str] = set()
    specific: set[str] = set()

    source = str(finding.get("source") or finding.get("tool") or "").strip()
    if source and _contains_fact_value(visible, source):
        matched.add("source")
    severity = str(finding.get("severity") or "").lower()
    severity_patterns = {
        "critical": r"\b(?:critical|kritik)\b",
        "high": r"\b(?:high|yüksek)\b",
        "medium": r"\b(?:medium|orta)\b",
        "low": r"\b(?:low|düşük)\b",
        "info": r"\b(?:info|bilgi)\b",
    }
    if severity and re.search(severity_patterns.get(severity, re.escape(severity)), visible, re.IGNORECASE):
        matched.add("severity")
    verification = str(finding.get("verification_state") or "").lower()
    verification_patterns = {
        "unverified": r"\b(?:unverified|doğrulanmam[ıi][şs]|henüz\s+doğrulanmad[ıi]|template\s+eşleşmesi)\b",
        "partially_verified": r"\b(?:partially[_ -]?verified|k[ıi]smen\s+doğrulan)\w*\b",
        "verified": r"\b(?:verified|doğrulanm[ıi][şs]|doğruland[ıi])\b",
    }
    if verification and re.search(verification_patterns.get(verification, re.escape(verification)), visible, re.IGNORECASE):
        matched.add("verification")

    for key in ("template_id", "matched_url", "url", "status_code", "redirect", "fingerprint", "validation_evidence"):
        value = finding.get(key)
        if _contains_fact_value(visible, value):
            matched.add(key)
            specific.add(key)
    if finding.get("response_evidence_present") is True and re.search(r"\b(?:request|response|istek|yan[ıi]t)\b", visible, re.IGNORECASE):
        matched.add("request_response")
        specific.add("request_response")
    missing = {str(item) for item in _as_list(finding.get("missing_evidence_fields"))}
    missing_patterns = {
        "matched_url": r"(?:eşleşen\s+(?:adres|url)|url|adres).{0,35}(?:yok|eksik|bulunmuyor|mevcut\s+değil)",
        "status_or_redirect": r"(?:durum\s+kodu|yönlendirme|redirect).{0,35}(?:yok|eksik|bulunmuyor|mevcut\s+değil)",
        "product_fingerprint": r"(?:ürün\s+izi|fingerprint).{0,35}(?:yok|eksik|bulunmuyor|doğrulanmam)",
        "explicit_validation_evidence": r"(?:doğrulama\s+kan[ıi]t[ıi]|aç[ıi]k\s+kan[ıi]t).{0,35}(?:yok|eksik|bulunmuyor|mevcut\s+değil)",
    }
    for field in missing:
        pattern = missing_patterns.get(field)
        if pattern and re.search(pattern, visible, re.IGNORECASE | re.DOTALL):
            matched.add(f"missing:{field}")
            specific.add(f"missing:{field}")
    return identity, matched, specific


def _answer_relevance_failure_reason(
    question: str,
    answer: str,
    *,
    answer_intent: str,
    context_profile: str,
    grounding_facts: dict[str, Any] | None = None,
) -> str:
    packet = _as_record(grounding_facts)
    kind = str(packet.get("kind") or "")
    if kind == "report_summary" and (answer_intent == "short_summary" or context_profile in {"report_summary", "quick_report_summary"}):
        matched, available = _report_relevance_anchors(answer, packet)
        required = min(2, len(available))
        return "answer_not_relevant" if required and len(matched) < required else ""
    if kind == "selected_finding" and answer_intent in {
        "finding_question",
        "evidence_request",
        "operational_guidance",
        "numbered_action_plan",
    }:
        identity, matched, specific = _finding_relevance_anchors(answer, packet)
        identity_question = bool(re.search(
            r"(?:hangi\s+(?:bulgu|finding)|hangisi|konuştuğumuz\s+(?:bulgu|finding)|önceki\s+(?:bulgu|finding))",
            question,
            re.IGNORECASE,
        ))
        if identity_question:
            return "" if identity else "answer_not_relevant"
        grounded = (identity and len(matched) >= 1) or (len(matched) >= 3) or (len(specific) >= 1 and len(matched) >= 2)
        return "" if grounded else "answer_not_relevant"
    return ""


def _answer_quality_failure_reason(
    question: str,
    answer: str,
    history: list[dict[str, str]],
    *,
    answer_intent: str,
    context_profile: str,
    expected_finding_title: str = "",
    known_findings: list[dict[str, Any]] | None = None,
    response_preferences: ResponsePreferences | None = None,
    grounding_facts: dict[str, Any] | None = None,
) -> str:
    visible = (answer or "").strip()
    if not visible:
        return "empty_visible_answer"
    if contains_unresolved_placeholder_values(visible):
        return "unresolved_placeholder_values"
    normalized_answer = _normalized_similarity_text(visible)
    normalized_question = _normalized_similarity_text(question)
    if len(normalized_answer) < 3:
        return "extremely_short_answer"
    if normalized_answer == normalized_question:
        return "question_repeated_without_answer"
    previous = _previous_assistant_answer(history)
    if previous:
        ratio = SequenceMatcher(None, _normalized_similarity_text(previous), normalized_answer).ratio()
        if ratio >= 0.93 and min(len(previous), len(visible)) >= 80:
            return "repeats_previous_assistant_answer"
    generic_markers = len(GENERIC_REPORT_LINE_PATTERN.findall(visible))
    action_items = _action_item_count(visible)
    effective_preferences = response_preferences or _response_preferences(question)
    requested_items_failure = _requested_items_contract_failure(question, visible, effective_preferences)
    if requested_items_failure:
        return requested_items_failure
    if effective_preferences.single_sentence and _sentence_count(visible) != 1:
        return "requested_single_sentence_missing"
    known = known_findings or []
    mentioned_findings = _matching_findings_in_text(known, visible) if known else []
    expected_normalized = _normalized_similarity_text(expected_finding_title)
    expected_mentioned = any(
        _normalized_similarity_text(_finding_title(finding)) == expected_normalized
        for finding in mentioned_findings
    ) if expected_normalized else False
    if expected_normalized and mentioned_findings and not expected_mentioned:
        return "wrong_selected_finding"
    if expected_finding_title and re.search(r"hangi\s+bulgu|hangisi|konuştuğumuz\s+bulgu|önceki\s+bulgu", question, re.IGNORECASE):
        if not expected_mentioned and expected_normalized not in normalized_answer:
            return "wrong_selected_finding"
    if FOLLOWUP_CONTEXT_PATTERN.search(question) and history and generic_markers >= 3 and action_items == 0:
        return "followup_reference_ignored"
    if context_profile == "general_chat" and answer_intent == "normal_question" and generic_markers >= 3:
        return "generic_run_summary_for_general_question"
    if context_profile == "ai_failure_diagnostics":
        scan_artifact_markers = len(re.findall(
            r"\b(?:artifact|matched\s+url|bulgu|nuclei|scanner|collector|soft-error|redirect\s+kanıtı)\b",
            visible,
            re.IGNORECASE,
        ))
        if scan_artifact_markers >= 2:
            return "unrelated_scan_report_for_ai_diagnostics"
    return ""


def _answer_integrity_validation(
    context: dict[str, Any],
    question: str,
    history: list[dict[str, str]],
    context_profile: str,
    answer: str,
) -> AnswerValidationResult:
    enforce = context_profile in {
        "report_summary",
        "quick_report_summary",
        "report_qa",
        "finding_question",
        "operational_question",
        "trust",
        "continuation",
    } or bool(REPORT_CONTEXT_PATTERN.search(question))
    findings = _top_context_findings(context, limit=10)
    if context_profile in {"report_summary", "quick_report_summary", "report_qa", "trust"}:
        current = _as_record(context.get("current_run_context"))
        artifact_target = str(current.get("target") or context.get("target") or "").strip()
        if artifact_target:
            findings.append({"matched_url": artifact_target, "verification_state": "unverified"})
    if context_profile in {"finding_question", "operational_question", "trust", "continuation"} and findings:
        selected = _selected_context_finding(context, question, history)
        findings = [selected] if selected else findings
    return validate_answer_integrity(
        answer,
        findings=findings,
        enforce_artifact_grounding=enforce,
    )


def _ai_diagnostics_integrity_failure(
    context_profile: str,
    context: dict[str, Any],
    answer: str,
) -> str:
    if context_profile != "ai_failure_diagnostics":
        return ""
    diagnostics = _as_record(context.get("ai_request_diagnostics"))
    latest_status = str(diagnostics.get("latest_request_status") or "").strip().lower()
    visible = str(answer or "")
    if latest_status == "cancelled":
        mentions_cancellation = bool(re.search(
            r"\b(?:iptal(?:\s+edil(?:di|miş))?|cancel(?:led)?|operatör\s+tarafından\s+durduruldu)\b",
            visible,
            re.IGNORECASE,
        ))
        denies_timeout = bool(re.search(
            r"(?:zaman\s+aşım(?:ı|ına)|timeout).{0,80}(?:olmad[ıi]|uğramad[ıi]|değil(?:di)?|gerçekleşmedi|kaydı\s+yok)",
            visible,
            re.IGNORECASE | re.DOTALL,
        ))
        if not mentions_cancellation or not denies_timeout:
            return "contradicts_latest_ai_request_status"
    return ""


def _failure_reason_tr(reason: str, status: str = "") -> str:
    normalized = str(reason or "").strip()
    state = str(status or "").strip()
    return FAILURE_REASON_TR.get(normalized) or FAILURE_REASON_TR.get(state) or (
        "Gerçek olmayan alanlar kullandı" if normalized.startswith("invented_") else "Model kullanılabilir cevap üretmedi"
    )


def _failure_answer(reason: str, status: str = "") -> str:
    return f"Model soruya uygun kullanılabilir final cevap üretmedi.\nNeden: {_failure_reason_tr(reason, status)}."


def _fallback_for_intent(
    context: dict[str, Any],
    question: str,
    context_profile: str,
    history: list[dict[str, str]] | None = None,
) -> str:
    if context_profile == "ai_failure_diagnostics":
        diagnostics = _as_record(context.get("ai_request_diagnostics"))
        status = str(diagnostics.get("latest_request_status") or "unknown")
        http_status = int(diagnostics.get("provider_http_status") or 0)
        provider_error = str(diagnostics.get("provider_error") or "").strip()
        configured_timeout = diagnostics.get("configured_timeout_sec")
        effective_timeout = diagnostics.get("effective_attempt_timeout_sec")
        if status == "cancelled":
            return (
                "Önceki istek zaman aşımına uğramadı; operatör tarafından iptal edildi. "
                f"Yapılandırılmış/effective attempt timeout {configured_timeout}/{effective_timeout} saniyeydi. "
                "İptal yalnız aktif AI child processini durdurdu; konuşma ve run artifactleri korundu."
            )
        if status in {"timeout", "model_timeout"}:
            return (
                f"Son AI isteği gerçekten timeout durumunda tamamlandı. Yapılandırılmış/effective attempt timeout "
                f"{configured_timeout}/{effective_timeout} saniyeydi. "
                + (f"Redakte provider mesajı: {provider_error}" if provider_error else "Provider ek bir hata mesajı döndürmedi.")
            )
        if status == "context_length_exceeded":
            return "Son istek, konuşma bağlamı modelin yüklü context sınırını aştığı için tamamlanamadı; geçmiş/context küçültülerek bir kez yeniden denenebilir."
        if http_status:
            return f"Son AI isteği HTTP {http_status} ile reddedildi. " + (provider_error or "Provider ayrıntılı bir hata mesajı döndürmedi.")
        return f"Son AI istek durumu {status}. Artifactlerde bunun timeout olduğunu doğrulayan provider veya HTTP kanıtı yok; kesin bir timeout nedeni uydurulamıyor."
    if context_profile in {"report_summary", "quick_report_summary"}:
        return _report_summary_fallback(context, question)
    if context_profile == "continuation":
        selected = _selected_context_finding(context, question, history)
        count_match = REQUESTED_COUNT_PATTERN.search(question)
        requested = min(10, max(1, int(count_match.group(1)))) if count_match else 1
        asks_for_steps = _is_action_plan_request(question) or _is_operational_guidance_request(question)
        if selected and count_match and not asks_for_steps:
            return _finding_explanation_fallback(selected, requested, question=question)
        if selected and asks_for_steps:
            return _finding_action_plan(selected, requested)
        if selected:
            return _natural_finding_fallback(selected, question)
    if context_profile in {"finding_question", "operational_question"}:
        selected = _selected_context_finding(context, question, history)
        selected_title = _finding_title(selected) if selected else "Artifact içinde seçilebilir bulgu detayı yok"
        selected_severity = _finding_severity(selected) if selected else "unknown"
        selected_url = _finding_url(selected) if selected else ""
        asks_for_steps = _is_action_plan_request(question) or _is_operational_guidance_request(question)
        count_match = REQUESTED_COUNT_PATTERN.search(question)
        requested = min(10, max(1, int(count_match.group(1)))) if count_match else 1
        if count_match and not asks_for_steps:
            return _finding_explanation_fallback(selected, requested, question=question)
        operational_fallback = _finding_operational_fallback(selected, question)
        if operational_fallback:
            return operational_fallback
        if asks_for_steps:
            return _finding_action_plan(selected, requested)
        return _natural_finding_fallback(selected, question)
    if context_profile in {"logs", "log_troubleshooting"}:
        errors = [
            item for item in _as_list(_as_record(context.get("log")).get("recent_errors"))
            if not contains_unresolved_placeholder_values(str(item))
        ]
        if errors:
            return "Son hata kayıtları:\n" + "\n".join(f"- {str(item)}" for item in errors[-5:]) + "\nBu kayıtları ilgili aşama durumu ve timeout ayarıyla birlikte doğrula."
        return "Log contextinde yorumlanabilir hata veya timeout satırı yok. İlgili aşama durumunu ve reconbot.log sonunu manuel kontrol et."
    if context_profile == "trust":
        return "\n".join([_status_sentence(context), _coverage_line(context), "Nuclei eşleşmeleri ve kapsam eksikleri manuel doğrulanmadan sonucu kesin kabul etme."])
    if context_profile == "continuation" and FOLLOWUP_CONTEXT_PATTERN.search(question):
        if _ordinal_finding(_top_context_findings(context, limit=10), question):
            return _fallback_for_intent(context, question, "finding_question", history)
        previous = _previous_assistant_answer(history or [])
        if not previous:
            return ""
        sentences = re.split(r"(?<=[.!?])\s+", previous.strip())
        concise = " ".join(sentence for sentence in sentences[:3] if sentence).strip()
        return concise[:700].rstrip()
    return ""


def _qwen_like_model(model: str) -> bool:
    return "qwen" in str(model or "").lower()


def _answer_intent_for_request(
    mode: str,
    question: str,
    context_profile: str,
    selected_finding_reference: dict[str, Any] | None = None,
) -> str:
    if _is_evidence_request(question) or mode == "trust":
        return "evidence_request"
    if mode == "settings" or context_profile in {"settings_advice", "settings"}:
        return "settings_advice"
    if mode == "logs" or context_profile in {"log_troubleshooting", "logs"}:
        return "log_troubleshooting"
    if _is_detailed_request(question):
        return "deep_analysis"
    if _is_action_plan_request(question):
        return "numbered_action_plan"
    if _is_operational_guidance_request(question):
        return "operational_guidance"
    if mode in {"report", "brief"} or context_profile in {"report_summary", "quick_report_summary"} or _is_short_summary_request(question):
        return "short_summary"
    if context_profile == "finding_question" or mode == "finding" or (
        context_profile == "continuation" and selected_finding_reference
    ):
        return "finding_question"
    if mode == "next" or context_profile == "operational_question":
        return "operational_guidance"
    if context_profile == "trust":
        return "finding_question"
    if _is_report_context_question(question) or context_profile in {"report_qa", "trust"}:
        return "normal_report_qa"
    return "normal_question"


def _profile_for_mode(mode: str) -> str:
    if mode in {"report", "brief", "trust", "next", "finding"}:
        return "quick_report_summary"
    if mode == "logs":
        return "log_troubleshooting"
    if mode == "settings":
        return "settings_advice"
    return "general_chat"


def _profile_for_request(mode: str, question: str, explicit_profile: Any = None, config: Any = None) -> str:
    explicit = str(explicit_profile or "")
    # Python is authoritative: a renderer hint must not downgrade an obvious
    # follow-up and strip the conversation context it needs.
    if AI_FAILURE_DIAGNOSTICS_PATTERN.search(question):
        return "ai_failure_diagnostics"
    if _ordinal_index(question) is not None:
        return "finding_question"
    if mode == "continuation" or FOLLOWUP_CONTEXT_PATTERN.search(question):
        return "continuation"
    if mode == "chat" and (_is_action_plan_request(question) or _is_operational_guidance_request(question)):
        return "operational_question"
    if explicit and explicit not in {"question_answer", "chat"}:
        return explicit
    if mode in {"report", "brief"}:
        return "report_summary"
    if mode == "trust":
        return "trust"
    if mode in {"next", "finding"}:
        return "finding_question" if mode == "finding" else "operational_question"
    if mode == "logs":
        return "logs"
    if mode == "settings":
        return "settings"
    if LOG_CONTEXT_PATTERN.search(question):
        return "logs"
    if SETTINGS_CONTEXT_PATTERN.search(question):
        return "settings"
    if TRUST_CONTEXT_PATTERN.search(question):
        return "trust"
    if _is_short_summary_request(question):
        return "report_summary"
    if FINDING_CONTEXT_PATTERN.search(question):
        return "finding_question"
    if _is_operational_question(question):
        return "operational_question"
    if _is_report_context_question(question):
        return "finding_question"
    return "general_chat"


def _prompt_mode(mode: str, context_profile: str) -> str:
    if context_profile in {"quick_report_summary", "report_summary"}:
        return "quick_report_summary"
    if context_profile in {"general_chat", "operational_question", "finding_question", "report_qa", "trust", "continuation"}:
        return context_profile
    if context_profile in {"settings_advice", "settings"}:
        return "settings"
    if context_profile in {"log_troubleshooting", "logs"}:
        return "logs"
    if context_profile == "ai_failure_diagnostics":
        return "ai_failure_diagnostics"
    return mode


def _include_evidence(mode: str, context_profile: str, question: str, include_paths: bool) -> bool:
    if include_paths:
        return True
    if mode == "trust":
        return True
    if _is_evidence_request(question):
        return True
    return False


def _legacy_shaped_chat_disabled(payload: dict[str, Any], progress_callback: ProgressCallback | None = None) -> dict[str, Any]:
    def emit(state: str, attempt: int = 0) -> None:
        if progress_callback is not None:
            progress_callback(state, attempt)

    emit("preparing_request", 1)
    config = ai_config_from_mapping(_as_record(payload.get("aiConfig") or payload.get("ai")))
    mode = str(payload.get("mode") or "chat")
    question = str(payload.get("user_message") or payload.get("userMessage") or payload.get("question") or "Bu raporu kısa özetle.")
    response_preferences = _response_preferences(question)
    raw_history = payload.get("conversation_history") or payload.get("conversationHistory") or []
    context_profile = _profile_for_request(mode, question, payload.get("contextProfile"), config)
    request_settings = _as_record(payload.get("settings"))
    provided_snapshot = _as_record(payload.get("aiRunContext") or payload.get("currentRunContext"))
    conversation_reference = _as_record(
        payload.get("selected_finding_reference") or payload.get("selectedFindingReference")
    )
    had_structured_finding_reference = bool(conversation_reference)
    if mode != "trust" and DIRECT_FALSE_POSITIVE_PATTERN.search(question):
        context_profile = "finding_question" if conversation_reference or raw_history else "general_chat"
    if isinstance(payload.get("aiDiagnostics"), dict):
        request_settings = {**request_settings, "ai_diagnostics": payload["aiDiagnostics"]}
    ai_context = build_ai_context(
        payload.get("runDir"),
        request_settings,
        config.maxContextChars,
        profile=context_profile,
        provided_snapshot=provided_snapshot,
    )
    reference_context = ai_context.context
    if conversation_reference:
        reference_context = {**reference_context, "conversation_reference": redact_obj(conversation_reference)}
    if context_profile == "continuation":
        reference_context = build_ai_context(
            payload.get("runDir"),
            request_settings,
            min(config.maxContextChars, 8000),
            profile="finding_question",
            provided_snapshot=provided_snapshot,
        ).context
        if conversation_reference:
            reference_context = {**reference_context, "conversation_reference": redact_obj(conversation_reference)}
    selected_finding: dict[str, Any] = {}
    if context_profile in {"finding_question", "operational_question", "trust", "continuation"}:
        selected_finding = _selected_context_finding(reference_context, question, raw_history)
        if selected_finding:
            conversation_reference = _finding_reference(
                reference_context,
                selected_finding,
                run_id=str(payload.get("run_id") or payload.get("runId") or ""),
            )
    answer_intent = _answer_intent_for_request(mode, question, context_profile, conversation_reference)
    selected_grounding_is_active = bool(
        selected_finding
        and (
            had_structured_finding_reference
            or len(_matching_findings_in_text(_top_context_findings(reference_context, limit=10), question)) == 1
            or _ordinal_index(question) is not None
            or context_profile in {"finding_question", "continuation", "trust"}
        )
    )
    grounding_facts = _grounding_fact_packet(
        reference_context,
        answer_intent=answer_intent,
        context_profile=context_profile,
        selected_finding=selected_finding if selected_grounding_is_active else None,
    )
    prompt_selected_finding = selected_finding
    if selected_finding and (
        response_preferences.short_answer
        or (
            response_preferences.requested_item_count is not None
            and answer_intent != "numbered_action_plan"
        )
    ):
        prompt_keys = ["title", "template_id", "source", "verification_state"]
        if response_preferences.requested_item_count is not None:
            prompt_keys.append("severity")
        prompt_selected_finding = {
            key: selected_finding.get(key)
            for key in prompt_keys
            if selected_finding.get(key) not in (None, "", [], {})
        }
    ai_context = _context_with_selected_finding(ai_context, prompt_selected_finding)
    grounding_ai_context = _context_with_conversation_reference(ai_context, conversation_reference)
    if conversation_reference:
        reference_context = {**reference_context, "conversation_reference": redact_obj(conversation_reference)}
    client = OpenAICompatibleClient(config)
    model_metadata = _as_record(payload.get("modelMetadata"))
    if payload.get("discoverRuntimeCapabilities"):
        discovered_metadata, _metadata_source = client.discover_runtime_model_metadata()
        if discovered_metadata:
            model_metadata = {**model_metadata, **discovered_metadata}
    client.set_model_metadata(model_metadata)
    ai_context, request_plan = _fit_context_and_plan(
        initial_context=ai_context,
        config=config,
        answer_intent=answer_intent,
        context_profile=context_profile,
        question=question,
        conversation_history=raw_history,
        model_metadata=model_metadata,
        run_dir=payload.get("runDir"),
        request_settings=request_settings,
        provided_snapshot=provided_snapshot,
        conversation_reference=conversation_reference,
        selected_finding=prompt_selected_finding,
        grounding_facts=grounding_facts,
    )
    effective_grounding_facts = _as_record(ai_context.context.get("grounding_facts"))
    request_plan = replace(request_plan, response_preferences=response_preferences.as_dict())
    request_meta = _request_metadata(payload, ai_context.context, context_profile, question)
    response_fields = _metadata_response_fields(request_meta)
    response_fields = {**response_fields, "response_preferences": response_preferences.as_dict()}
    if conversation_reference:
        response_fields = {**response_fields, "selected_finding_reference": redact_obj(conversation_reference)}
    if not request_plan.compatible:
        emit("unusable_answer", 1)
        return {
            **response_fields,
            "ok": False,
            "unavailable": True,
            "status": "model_incompatible",
            "answer": request_plan.incompatibility_reason,
            "error": "model_incompatible",
            "model": config.model,
            "lm_request_sent": False,
            "local_answer_generated": False,
            "request_plan": request_plan.as_dict(),
            "answer_intent": answer_intent,
            "model_profile": request_plan.model_profile,
            "failure_reason_category": "model_incompatible",
            "failure_reason_tr": "Seçili model sohbet için uygun değil",
        }
    if not request_plan.user_message_fits:
        emit("context_error", 1)
        return {
            **response_fields,
            "ok": False,
            "unavailable": True,
            "status": "input_too_large",
            "answer": (
                "Mesajın seçili modelin tahmini context penceresine tek başına sığmıyor. "
                "Taslak korunuyor; metni bölerek veya gereksiz ekleri kısaltarak yeniden deneyebilirsin."
            ),
            "error": "user_message_exceeds_model_window",
            "model": config.model,
            "lm_request_sent": False,
            "local_answer_generated": False,
            "request_plan": request_plan.as_dict(),
            "answer_intent": answer_intent,
            "model_profile": request_plan.model_profile,
            "preserve_user_message": True,
            "failure_reason_category": "input_too_large",
            "failure_reason_tr": _failure_reason_tr("input_too_large"),
        }
    conversation_history, history_compacted, _ = prepare_conversation_history(
        raw_history,
        question,
        max_chars=request_plan.history_budget_chars,
    )
    include_evidence_paths = _wants_evidence_paths(question)
    include_evidence = _include_evidence(mode, context_profile, question, include_evidence_paths)
    evidence = compact_evidence(reference_context)
    paths = _reference_paths(grounding_ai_context)
    compact_budget = min(request_plan.context_budget_chars, 1600)
    compact_context = (
        build_ai_context(
            payload.get("runDir"),
            request_settings,
            compact_budget,
            profile=context_profile,
            provided_snapshot=provided_snapshot,
        )
        if compact_budget >= 600
        else AIContext(context={"context_profile": context_profile}, references=[], truncated=True)
    )
    compact_context = _context_with_selected_finding(compact_context, prompt_selected_finding)
    compact_context = _context_with_conversation_reference(compact_context, conversation_reference)
    compact_context = _context_with_grounding_facts(compact_context, grounding_facts)
    if _serialized_context_chars(compact_context) > max(0, int(config.maxContextChars)):
        compact_minimal: dict[str, Any] = {"context_profile": context_profile}
        if conversation_reference:
            compact_minimal["conversation_reference"] = redact_obj(conversation_reference)
        if grounding_facts:
            compact_minimal["grounding_facts"] = redact_obj(grounding_facts)
        compact_context = AIContext(context=compact_minimal, references=[], truncated=True)
        if _serialized_context_chars(compact_context) > max(0, int(config.maxContextChars)):
            compact_minimal.pop("grounding_facts", None)
            compact_context = AIContext(context=compact_minimal, references=[], truncated=True)
    grounding_context = reference_context
    if context_profile == "continuation":
        grounding_context = build_ai_context(
            payload.get("runDir"),
            request_settings,
            min(config.maxContextChars, 8000),
            profile="finding_question",
            provided_snapshot=provided_snapshot,
        ).context
        if conversation_reference:
            grounding_context = {**grounding_context, "conversation_reference": redact_obj(conversation_reference)}
    provider_prompt_mode = (
        "operational_question"
        if answer_intent in {"operational_guidance", "numbered_action_plan"}
        else _prompt_mode(mode, context_profile)
    )
    messages = build_messages(
        ai_context,
        question,
        mode=provider_prompt_mode,
        config=config,
        request_metadata=request_meta,
        compact_system=request_plan.compact_system_prompt,
        conversation_history=conversation_history,
        response_preferences=response_preferences,
    )
    compact_messages = build_messages(
        compact_context,
        question,
        mode=provider_prompt_mode,
        config=config,
        request_metadata=request_meta,
        compact_system=True,
        conversation_history=conversation_history[-6:],
        response_preferences=response_preferences,
    )
    emit("waiting_for_model", 1)
    known_compatibility_notes = [
        str(note)
        for note in _as_list(payload.get("known_compatibility_notes") or payload.get("knownCompatibilityNotes"))
        if str(note).strip()
    ]
    response = client.chat(
        messages,
        max_tokens=request_plan.effective_max_output_tokens,
        compact_messages=compact_messages,
        request_timeout_sec=request_plan.effective_request_timeout_sec,
        max_attempts=int(request_plan.retry_policy.get("maxAttempts") or 4),
        known_compatibility_notes=known_compatibility_notes,
    )
    emit("validating_answer", max(1, int(response.attempt_count or 1)))
    action_plan = extract_action_plan(response.answer) if mode == "settings" and response.ok else None
    visible_answer = (
        _visible_answer_for_mode(response.answer, grounding_context, mode, question, action_plan=action_plan)
        if response.ok
        else _sanitize_visible_answer(response.answer, grounding_context)
    )
    answer_source = "model"
    repair_attempted = False
    repair_reason = ""
    relevance_validation_result = "not_applicable" if not effective_grounding_facts else "passed"
    relevance_validation_reason = ""
    repair_request_plan = None
    answer_repair_transport_attempt_count = 0
    transport_attempt_count = int(response.transport_attempt_count or response.attempt_count or 0)
    answer_repair_attempt_count = 0
    total_attempt_count = transport_attempt_count
    repair_failed_quality = False
    quality_reason = ""
    unsupported_claims: list[str] = []
    final_quality_failure_reason = ""
    if response.ok and effective_grounding_facts:
        initial_relevance_reason = _answer_relevance_failure_reason(
            question,
            visible_answer,
            answer_intent=answer_intent,
            context_profile=context_profile,
            grounding_facts=effective_grounding_facts,
        )
        if initial_relevance_reason:
            relevance_validation_result = "failed"
            relevance_validation_reason = initial_relevance_reason
    if response.ok and action_plan is None:
        if contains_unresolved_placeholder_values(visible_answer or response.answer):
            quality_reason = "unresolved_placeholder_values"
        elif context_profile == "ai_failure_diagnostics" or (
            not response.output_truncated and response.finish_reason != "length"
        ):
            quality_reason = _answer_quality_failure_reason(
                question,
                visible_answer,
                conversation_history,
                answer_intent=answer_intent,
                context_profile=context_profile,
                expected_finding_title=str(conversation_reference.get("title") or ""),
                known_findings=_top_context_findings(grounding_context, limit=10),
                response_preferences=response_preferences,
                grounding_facts=effective_grounding_facts,
            )
            if quality_reason == "answer_not_relevant":
                relevance_validation_result = "failed"
                relevance_validation_reason = quality_reason
            if not quality_reason:
                quality_reason = _ai_diagnostics_integrity_failure(
                    context_profile,
                    grounding_context,
                    visible_answer,
                )
            if not quality_reason:
                integrity_validation = _answer_integrity_validation(
                    grounding_context,
                    question,
                    conversation_history,
                    context_profile,
                    visible_answer,
                )
                if not integrity_validation.usable:
                    quality_reason = integrity_validation.reason
                    unsupported_claims = integrity_validation.unsupported_claims
            if not quality_reason:
                quality_reason = _answer_relevance_failure_reason(
                    question,
                    visible_answer,
                    answer_intent=answer_intent,
                    context_profile=context_profile,
                    grounding_facts=effective_grounding_facts,
                )
    if response.ok and quality_reason:
        repair_attempted = True
        answer_repair_attempt_count = 1
        repair_reason = quality_reason
        emit("repairing_answer", max(2, total_attempt_count + 1))
        repair_messages, repair_request_plan = build_budgeted_repair_messages(
            compact_context,
            question,
            mode=provider_prompt_mode,
            config=config,
            compact_system=True,
            conversation_history=conversation_history[-4:],
            request_plan=request_plan,
            repair_failed_answer=visible_answer or response.answer,
            repair_reason=quality_reason,
            repair_artifact_evidence=_repair_artifact_evidence(grounding_context, question, conversation_history),
            repair_unsupported_claims=unsupported_claims,
            response_preferences=response_preferences,
        )
        repair_response = client.chat(
            repair_messages,
            max_tokens=repair_request_plan.effective_max_output_tokens,
            request_timeout_sec=repair_request_plan.effective_request_timeout_sec,
            max_attempts=1,
            known_compatibility_notes=response.compatibility_notes,
        ) if repair_request_plan.user_message_fits else ChatResponse(ok=False, answer="Yanıt onarımı modelin context penceresine sığmadı.", model=config.model, status="input_too_large", error="repair_context_exceeds_model_window", lm_request_sent=True)
        answer_repair_transport_attempt_count = int(repair_response.transport_attempt_count or repair_response.attempt_count or 0)
        total_attempt_count = transport_attempt_count + answer_repair_transport_attempt_count
        emit("validating_answer", max(2, total_attempt_count))
        if repair_response.ok:
            repaired_visible = _visible_answer_for_mode(
                repair_response.answer,
                grounding_context,
                mode,
                question,
            )
            repaired_relevance_reason = _answer_relevance_failure_reason(
                question,
                repaired_visible,
                answer_intent=answer_intent,
                context_profile=context_profile,
                grounding_facts=effective_grounding_facts,
            )
            second_quality_reason = _answer_quality_failure_reason(
                question,
                repaired_visible,
                conversation_history,
                answer_intent=answer_intent,
                context_profile=context_profile,
                expected_finding_title=str(conversation_reference.get("title") or ""),
                known_findings=_top_context_findings(grounding_context, limit=10),
                response_preferences=response_preferences,
                grounding_facts=effective_grounding_facts,
            )
            if not second_quality_reason:
                second_quality_reason = _ai_diagnostics_integrity_failure(
                    context_profile,
                    grounding_context,
                    repaired_visible,
                )
            if not second_quality_reason:
                repaired_integrity_validation = _answer_integrity_validation(
                    grounding_context,
                    question,
                    conversation_history,
                    context_profile,
                    repaired_visible,
                )
                if not repaired_integrity_validation.usable:
                    second_quality_reason = repaired_integrity_validation.reason
            if not second_quality_reason:
                second_quality_reason = repaired_relevance_reason
            if repaired_visible and not second_quality_reason:
                response = repair_response
                visible_answer = repaired_visible
                answer_source = "repaired_model"
                if repair_reason == "answer_not_relevant":
                    relevance_validation_result = "passed_after_repair"
                elif not repaired_relevance_reason:
                    relevance_validation_result = "passed"
            else:
                final_quality_failure_reason = second_quality_reason or "empty_repair_answer"
                response = ChatResponse(
                    ok=False,
                    answer=_failure_answer(final_quality_failure_reason),
                    model=config.model,
                    unavailable=True,
                    error=second_quality_reason or "empty_repair_answer",
                    status="invalid_response",
                    lm_request_sent=True,
                    finish_reason=repair_response.finish_reason,
                    endpoint_debug=repair_response.endpoint_debug,
                    attempt_count=total_attempt_count,
                    transport_attempt_count=transport_attempt_count,
                    answer_repair_attempt_count=answer_repair_attempt_count,
                )
                visible_answer = ""
                repair_failed_quality = True
        else:
            response = repair_response
            final_quality_failure_reason = str(
                repair_response.endpoint_debug.get("parserReason")
                or repair_response.error
                or repair_response.status
                or "repair_request_failed"
            )
            visible_answer = ""
            repair_failed_quality = True

    empty_final_failure = response.lm_request_sent and _response_needs_empty_final_fallback(response)
    can_fallback = _allows_deterministic_fallback(mode, question, context_profile)
    if can_fallback and (empty_final_failure or repair_failed_quality):
        emit("generating_local_fallback", max(1, total_attempt_count))
        fallback_answer = _fallback_for_intent(grounding_context, question, context_profile, conversation_history)
        fallback_validation = _answer_integrity_validation(
            grounding_context,
            question,
            conversation_history,
            context_profile,
            fallback_answer,
        )
        fallback_quality_reason = _answer_quality_failure_reason(
            question,
            fallback_answer,
            conversation_history,
            answer_intent=answer_intent,
            context_profile=context_profile,
            expected_finding_title=str(conversation_reference.get("title") or ""),
            known_findings=_top_context_findings(grounding_context, limit=10),
            response_preferences=response_preferences,
            grounding_facts=grounding_facts,
        )
        if not fallback_quality_reason:
            fallback_quality_reason = _answer_relevance_failure_reason(
                question,
                fallback_answer,
                answer_intent=answer_intent,
                context_profile=context_profile,
                grounding_facts=grounding_facts,
            )
        if fallback_answer and fallback_validation.usable and not fallback_quality_reason and not contains_unresolved_placeholder_values(fallback_answer):
            fallback_reason = repair_reason if repair_failed_quality else str(response.endpoint_debug.get("parserReason") or response.error or "empty_final")
            if grounding_facts:
                relevance_validation_result = "fallback_grounded"
                relevance_validation_reason = relevance_validation_reason or fallback_reason
            emit("completed", max(1, total_attempt_count))
            return {
                **response.__dict__,
                **response_fields,
                "ok": True,
                "unavailable": False,
                "status": "ready",
                "answer": fallback_answer,
                "answer_source": "local_fallback",
                "fallback_reason": fallback_reason,
                "repair_attempted": repair_attempted,
                "repair_reason": repair_reason,
                "attempt_count": total_attempt_count,
                "transport_attempt_count": transport_attempt_count,
                "answer_repair_attempt_count": answer_repair_attempt_count,
                "answer_repair_transport_attempt_count": answer_repair_transport_attempt_count,
                "action_plan": None,
                "references": paths if include_evidence_paths else [],
                "evidence": evidence if include_evidence else [],
                "evidence_paths": paths if include_evidence_paths else [],
                "lm_request_sent": True,
                "local_answer_generated": True,
                "answer_intent": answer_intent,
                "effective_max_tokens": request_plan.effective_max_output_tokens,
                "model_profile": request_plan.model_profile,
                "history_turns_sent": len(conversation_history),
                "history_compacted": bool(history_compacted or request_plan.history_was_compacted),
                "context_compacted": bool(ai_context.truncated or request_plan.context_was_compacted),
                "request_plan": request_plan.as_dict(),
                "failure_reason_category": "",
                "failure_reason_tr": "",
                "relevance_validation_result": relevance_validation_result,
                "relevance_validation_reason": relevance_validation_reason,
            }

    if not response.ok and repair_attempted and not visible_answer:
        final_quality_failure_reason = final_quality_failure_reason or repair_reason or response.error or "invalid_response"
        visible_answer = _failure_answer(final_quality_failure_reason, response.status)
    elif not response.ok and empty_final_failure and not can_fallback:
        final_quality_failure_reason = str(response.endpoint_debug.get("parserReason") or response.error or response.status or "invalid_response")
        visible_answer = _failure_answer(final_quality_failure_reason, response.status)
    if contains_unresolved_placeholder_values(visible_answer):
        visible_answer = "Model kullanılabilir final cevap üretmedi."
        response = ChatResponse(
            ok=False,
            answer=visible_answer,
            model=config.model,
            unavailable=True,
            error="unresolved_placeholder_values",
            status="invalid_response",
            lm_request_sent=True,
            finish_reason=response.finish_reason,
            endpoint_debug=response.endpoint_debug,
            attempt_count=total_attempt_count,
            transport_attempt_count=transport_attempt_count,
            answer_repair_attempt_count=answer_repair_attempt_count,
        )
        final_quality_failure_reason = "unresolved_placeholder_values"
    failure_reason_category = final_quality_failure_reason or (str(response.error or response.status) if not response.ok else "")
    if response.ok:
        emit("completed", max(1, total_attempt_count))
    elif response.status in {"timeout", "model_timeout"}:
        emit("timeout", max(1, total_attempt_count))
    elif response.status in {"input_too_large", "context_length_exceeded"}:
        emit("context_error", max(1, total_attempt_count))
    else:
        emit("unusable_answer", max(1, total_attempt_count))
    return {
        **response.__dict__,
        **response_fields,
        "answer": visible_answer,
        "answer_source": answer_source,
        "fallback_reason": "",
        "repair_attempted": repair_attempted,
        "repair_reason": repair_reason,
        "attempt_count": total_attempt_count,
        "transport_attempt_count": transport_attempt_count,
        "answer_repair_attempt_count": answer_repair_attempt_count,
        "answer_repair_transport_attempt_count": answer_repair_transport_attempt_count,
        "action_plan": redact_obj(action_plan),
        "references": paths if include_evidence_paths else [],
        "evidence": evidence if include_evidence else [],
        "evidence_paths": paths if include_evidence_paths else [],
        "lm_request_sent": bool(response.lm_request_sent),
        "local_answer_generated": False,
        "answer_intent": answer_intent,
        "effective_max_tokens": request_plan.effective_max_output_tokens,
        "model_profile": request_plan.model_profile,
        "history_turns_sent": len(conversation_history),
        "history_compacted": bool(history_compacted or request_plan.history_was_compacted),
        "context_compacted": bool(ai_context.truncated or request_plan.context_was_compacted),
        "request_plan": request_plan.as_dict(),
        "answer_repair_request_plan": repair_request_plan.as_dict() if repair_request_plan else None,
        "failure_reason_category": failure_reason_category,
        "failure_reason_tr": _failure_reason_tr(failure_reason_category, response.status) if failure_reason_category else "",
        "relevance_validation_result": relevance_validation_result,
        "relevance_validation_reason": relevance_validation_reason,
    }


def _thin_integrity_defect(
    answer: str,
    *,
    question: str,
    selected_finding: dict[str, Any],
    known_findings: list[dict[str, Any]],
    ground_all_findings: bool = False,
    reference_urls: list[str] | None = None,
) -> AnswerValidationResult:
    """Check only concrete answer-integrity failures, never prose quality."""
    if contains_unresolved_placeholder_values(answer):
        return AnswerValidationResult(
            usable=False,
            reason="unresolved_placeholder_values",
            categories=["unresolved_placeholder_values"],
            unsupported_claims=["The response contains an unresolved placeholder value."],
        )
    if not selected_finding:
        if ground_all_findings and known_findings:
            return validate_answer_integrity(
                answer,
                findings=known_findings,
                enforce_artifact_grounding=True,
                reference_urls=reference_urls,
            )
        return AnswerValidationResult(usable=True)

    if not re.search(r"(?:karşılaştır|kıyasla|iki\s+bulgu|tüm\s+bulgu|başka\s+bulgu)", question, re.IGNORECASE):
        mentioned = _matching_findings_in_text(known_findings, answer)
        selected_title = _normalized_similarity_text(_finding_title(selected_finding))
        if mentioned and not any(
            _normalized_similarity_text(_finding_title(item)) == selected_title
            for item in mentioned
        ):
            return AnswerValidationResult(
                usable=False,
                reason="wrong_selected_finding",
                categories=["wrong_selected_finding"],
                unsupported_claims=["The response switched to another known finding."],
            )

    return validate_answer_integrity(
        answer,
        findings=[selected_finding],
        enforce_artifact_grounding=True,
        reference_urls=reference_urls,
    )


def _thin_technical_failure(reason: str) -> str:
    labels = {
        "unresolved_placeholder_values": "Model yanıtında çözümlenmemiş placeholder değerleri vardı.",
        "wrong_selected_finding": "Model konuşmada seçili bulgu yerine başka bir bulguya geçti.",
        "evidence_integrity_failure": "Model yanıtı bilinen artifact verileriyle çelişen değerler içeriyordu.",
        "nuclei_match_treated_as_confirmed": "Model doğrulanmamış eşleşmeyi doğrulanmış gibi sundu.",
        "unsupported_product_claim": "Model artifactte bulunmayan ürün ayrıntısını gerçek gibi sundu.",
        "invented_url": "Model artifactte bulunmayan bir URL'yi gerçek gibi sundu.",
        "invented_endpoint": "Model artifactte bulunmayan bir endpoint'i gerçek gibi sundu.",
        "invented_request_response": "Model artifactte bulunmayan istek/yanıt kanıtı sundu.",
    }
    detail = labels.get(reason, "Model yanıtı temel bütünlük kontrolünü geçemedi.")
    return f"{detail} Yanıt yerel bir metinle değiştirilmedi; yeniden deneyebilirsin."


# Thin model-first implementation. The legacy helper functions above remain
# import-compatible for older integrations, but the former shaping pipeline is
# explicitly named as disabled and is not reachable from the CLI/API entrypoint.
def chat(payload: dict[str, Any], progress_callback: ProgressCallback | None = None) -> dict[str, Any]:
    def emit(state: str, attempt: int = 0) -> None:
        if progress_callback is not None:
            progress_callback(state, attempt)

    emit("preparing_request", 1)
    config = ai_config_from_mapping(_as_record(payload.get("aiConfig") or payload.get("ai")))
    mode = str(payload.get("mode") or "chat")
    latest_value = payload.get("user_message")
    if latest_value is None:
        latest_value = payload.get("userMessage")
    if latest_value is None:
        latest_value = payload.get("question")
    question = str(latest_value or "")
    response_preferences = _response_preferences(question)
    raw_history = payload.get("conversation_history") or payload.get("conversationHistory") or []
    context_profile = _profile_for_request(mode, question, payload.get("contextProfile"), config)
    request_settings = _as_record(payload.get("settings"))
    provided_snapshot = _as_record(payload.get("aiRunContext") or payload.get("currentRunContext"))
    conversation_reference = _as_record(
        payload.get("selected_finding_reference") or payload.get("selectedFindingReference")
    )

    if not question.strip():
        metadata = _request_metadata(payload, {}, context_profile, question)
        emit("unusable_answer", 1)
        return {
            **_metadata_response_fields(metadata),
            "ok": False,
            "unavailable": True,
            "status": "invalid_response",
            "answer": "Gönderilecek kullanıcı mesajı boş.",
            "error": "empty_user_message",
            "model": config.model,
            "lm_request_sent": False,
            "local_answer_generated": False,
            "answer_source": "technical_error",
            "answer_repair_attempt_count": 0,
            "response_preferences": response_preferences.as_dict(),
        }

    # A report-wide reliability question must retain its run context even when
    # it mentions false positives. Only direct finding/general questions use
    # the narrower false-positive routing.
    if mode != "trust" and context_profile not in {"trust", "report_summary", "quick_report_summary", "report_qa", "operational_question"} and DIRECT_FALSE_POSITIVE_PATTERN.search(question):
        context_profile = "finding_question" if conversation_reference or raw_history else "general_chat"

    ai_context = build_ai_context(
        payload.get("runDir"),
        request_settings,
        config.maxContextChars,
        profile=context_profile,
        provided_snapshot=provided_snapshot,
    )

    # Continuations need the finding inventory only for reference resolution.
    # Once resolved, only the selected finding is attached to the provider call.
    reference_context = ai_context.context
    if context_profile == "continuation":
        reference_context = build_ai_context(
            payload.get("runDir"),
            request_settings,
            min(config.maxContextChars, 8000),
            profile="finding_question",
            provided_snapshot=provided_snapshot,
        ).context
    if conversation_reference:
        reference_context = {
            **reference_context,
            "conversation_reference": redact_obj(conversation_reference),
        }

    selection_profiles = {"finding_question", "operational_question", "trust", "continuation"}
    selected_finding: dict[str, Any] = {}
    if context_profile in selection_profiles:
        selected_finding = _selected_context_finding(reference_context, question, raw_history)
        if selected_finding:
            conversation_reference = _finding_reference(
                reference_context,
                selected_finding,
                run_id=str(payload.get("run_id") or payload.get("runId") or ""),
            )

    ai_context = _context_with_selected_finding(ai_context, selected_finding)
    ai_context = _context_with_conversation_reference(ai_context, conversation_reference)
    answer_intent = _answer_intent_for_request(mode, question, context_profile, conversation_reference)

    client = OpenAICompatibleClient(config)
    model_metadata = _as_record(payload.get("modelMetadata"))
    if payload.get("discoverRuntimeCapabilities"):
        discovered_metadata, _metadata_source = client.discover_runtime_model_metadata()
        if discovered_metadata:
            model_metadata = {**model_metadata, **discovered_metadata}
    client.set_model_metadata(model_metadata)

    ai_context, request_plan = _fit_context_and_plan(
        initial_context=ai_context,
        config=config,
        answer_intent=answer_intent,
        context_profile=context_profile,
        question=question,
        conversation_history=raw_history,
        model_metadata=model_metadata,
        run_dir=payload.get("runDir"),
        request_settings=request_settings,
        provided_snapshot=provided_snapshot,
        conversation_reference=conversation_reference,
        selected_finding=selected_finding,
        grounding_facts={},
    )
    request_plan = replace(request_plan, response_preferences=response_preferences.as_dict())
    request_meta = _request_metadata(payload, ai_context.context, context_profile, question)
    response_fields: dict[str, Any] = {
        **_metadata_response_fields(request_meta),
        "response_preferences": response_preferences.as_dict(),
    }
    if conversation_reference:
        response_fields["selected_finding_reference"] = redact_obj(conversation_reference)

    if not request_plan.compatible:
        emit("unusable_answer", 1)
        return {
            **response_fields,
            "ok": False,
            "unavailable": True,
            "status": "model_incompatible",
            "answer": request_plan.incompatibility_reason,
            "error": "model_incompatible",
            "model": config.model,
            "lm_request_sent": False,
            "local_answer_generated": False,
            "answer_source": "technical_error",
            "answer_intent": answer_intent,
            "request_plan": request_plan.as_dict(),
            "answer_repair_attempt_count": 0,
        }
    if not request_plan.user_message_fits:
        emit("context_error", 1)
        return {
            **response_fields,
            "ok": False,
            "unavailable": True,
            "status": "input_too_large",
            "answer": "Mesaj seçili modelin context penceresine sığmıyor; mesaj korunarak yeniden denenebilir.",
            "error": "user_message_exceeds_model_window",
            "model": config.model,
            "lm_request_sent": False,
            "local_answer_generated": False,
            "answer_source": "technical_error",
            "answer_intent": answer_intent,
            "request_plan": request_plan.as_dict(),
            "preserve_user_message": True,
            "answer_repair_attempt_count": 0,
        }

    conversation_history, history_compacted, _received = prepare_conversation_history(
        raw_history,
        question,
        max_chars=request_plan.history_budget_chars,
    )
    prompt_mode = _prompt_mode(mode, context_profile)
    messages = build_messages(
        ai_context,
        question,
        mode=prompt_mode,
        config=config,
        conversation_history=conversation_history,
        response_preferences=response_preferences,
    )
    request_plan = plan_serialized_messages(request_plan, messages)
    actual_injected_context_chars = len(model_context_text(ai_context))
    request_plan = replace(
        request_plan,
        injected_context_chars=actual_injected_context_chars,
        effective_injected_context_chars=actual_injected_context_chars,
    )

    compact_context = AIContext(
        context=ai_context.context,
        references=[],
        truncated=ai_context.truncated,
    )
    compact_messages = build_messages(
        compact_context,
        question,
        mode=prompt_mode,
        config=config,
        conversation_history=conversation_history[-6:],
        response_preferences=response_preferences,
    )
    known_notes = [
        str(note)
        for note in _as_list(payload.get("known_compatibility_notes") or payload.get("knownCompatibilityNotes"))
        if str(note).strip()
    ]

    if not request_plan.user_message_fits:
        return {**response_fields, "ok": False, "unavailable": True, "status": "input_too_large", "error": "serialized_request_exceeds_model_window", "answer": "Mesaj ve gerekli bağlam modelin context penceresine sığmıyor.", "model": config.model, "lm_request_sent": False, "local_answer_generated": False, "answer_source": "technical_error", "request_plan": request_plan.as_dict(), "answer_repair_attempt_count": 0}
    emit("waiting_for_model", 1)
    response = client.chat(
        messages,
        max_tokens=request_plan.effective_max_output_tokens,
        compact_messages=compact_messages,
        request_timeout_sec=request_plan.effective_request_timeout_sec,
        max_attempts=int(request_plan.retry_policy.get("maxAttempts") or 4),
        known_compatibility_notes=known_notes,
    )
    transport_attempt_count = int(response.transport_attempt_count or response.attempt_count or 0)
    answer_repair_attempt_count = 0
    repair_request_plan = None
    answer_repair_transport_attempt_count = 0
    repair_reason = ""
    answer_source = "model"
    initial_raw_answer = response.answer
    current_reference = _as_record(reference_context.get("current_run_context"))
    reference_urls = [str(value) for value in (reference_context.get("target"), current_reference.get("target"), current_reference.get("report_file_target")) if value]

    if response.ok:
        emit("validating_answer", max(1, transport_attempt_count))
        known_findings = _top_context_findings(reference_context, limit=10)
        integrity = _thin_integrity_defect(
            response.answer,
            question=question,
            selected_finding=selected_finding,
            known_findings=known_findings,
            ground_all_findings=context_profile in {"report_summary", "quick_report_summary", "report_qa", "trust", "operational_question"},
            reference_urls=reference_urls,
        )
        if not integrity.usable:
            repair_reason = integrity.reason
            answer_repair_attempt_count = 1
            emit("repairing_answer", transport_attempt_count + 1)
            repair_messages, repair_request_plan = build_budgeted_repair_messages(
                compact_context,
                question,
                mode=prompt_mode,
                config=config,
                conversation_history=conversation_history,
                request_plan=request_plan,
                repair_failed_answer=response.answer,
                repair_reason=repair_reason,
                repair_artifact_evidence=_repair_artifact_evidence(reference_context, question, conversation_history),
                repair_unsupported_claims=integrity.unsupported_claims,
                response_preferences=response_preferences,
            )
            repaired = client.chat(
                repair_messages,
                max_tokens=repair_request_plan.effective_max_output_tokens,
                request_timeout_sec=repair_request_plan.effective_request_timeout_sec,
                max_attempts=1,
                known_compatibility_notes=response.compatibility_notes,
            ) if repair_request_plan.user_message_fits else ChatResponse(ok=False, answer="Yanıt onarımı modelin context penceresine sığmadı.", model=config.model, status="input_too_large", error="repair_context_exceeds_model_window", lm_request_sent=True)
            answer_repair_transport_attempt_count = int(repaired.transport_attempt_count or repaired.attempt_count or 0)
            if repaired.ok:
                repaired_integrity = _thin_integrity_defect(
                    repaired.answer,
                    question=question,
                    selected_finding=selected_finding,
                    known_findings=known_findings,
                    ground_all_findings=context_profile in {"report_summary", "quick_report_summary", "report_qa", "trust", "operational_question"},
                    reference_urls=reference_urls,
                )
            else:
                repaired_integrity = AnswerValidationResult(usable=False, reason=repaired.error or repaired.status)
            if repaired.ok and repaired_integrity.usable:
                response = replace(
                    repaired,
                    endpoint_debug={
                        **repaired.endpoint_debug,
                        "initialRawProviderContent": initial_raw_answer,
                    },
                )
                answer_source = "repaired_model"
            else:
                failure_reason = repaired_integrity.reason or repair_reason
                response = ChatResponse(
                    ok=False,
                    answer=_thin_technical_failure(failure_reason),
                    model=config.model,
                    unavailable=True,
                    error=failure_reason,
                    status="invalid_response",
                    lm_request_sent=True,
                    finish_reason=repaired.finish_reason,
                    endpoint_debug={
                        **repaired.endpoint_debug,
                        "initialRawProviderContent": initial_raw_answer,
                    },
                    attempt_count=transport_attempt_count + answer_repair_transport_attempt_count,
                    transport_attempt_count=transport_attempt_count + answer_repair_transport_attempt_count,
                )
                answer_source = "technical_error"
    else:
        answer_source = "technical_error"

    action_plan = extract_action_plan(response.answer) if mode == "settings" and response.ok else None
    include_evidence_paths = _wants_evidence_paths(question)
    include_evidence = _include_evidence(mode, context_profile, question, include_evidence_paths)
    total_attempt_count = transport_attempt_count + answer_repair_transport_attempt_count
    if response.ok:
        emit("completed", max(1, total_attempt_count))
    elif response.status in {"timeout", "model_timeout"}:
        emit("timeout", max(1, total_attempt_count))
    elif response.status in {"input_too_large", "context_length_exceeded"}:
        emit("context_error", max(1, total_attempt_count))
    else:
        emit("unusable_answer", max(1, total_attempt_count))

    return {
        **response.__dict__,
        **response_fields,
        # For every successful usable provider response, this is provider-owned
        # text. No local translation, template, metadata appendix, or sanitizer
        # is applied here.
        "answer": response.answer,
        "answer_source": answer_source,
        "fallback_reason": "",
        "repair_attempted": bool(answer_repair_attempt_count),
        "repair_reason": repair_reason,
        "attempt_count": total_attempt_count,
        "transport_attempt_count": transport_attempt_count,
        "answer_repair_attempt_count": answer_repair_attempt_count,
        "answer_repair_transport_attempt_count": answer_repair_transport_attempt_count,
        "action_plan": redact_obj(action_plan),
        "references": _reference_paths(ai_context) if include_evidence_paths else [],
        "evidence": compact_evidence(reference_context) if include_evidence else [],
        "evidence_paths": _reference_paths(ai_context) if include_evidence_paths else [],
        "lm_request_sent": bool(response.lm_request_sent),
        "local_answer_generated": False,
        "answer_intent": answer_intent,
        "effective_max_tokens": request_plan.effective_max_output_tokens,
        "model_profile": request_plan.model_profile,
        "history_turns_sent": len(conversation_history),
        "history_compacted": bool(history_compacted or request_plan.history_was_compacted),
        "context_compacted": bool(ai_context.truncated or request_plan.context_was_compacted),
        "request_plan": request_plan.as_dict(),
        "answer_repair_request_plan": repair_request_plan.as_dict() if repair_request_plan else None,
        "failure_reason_category": "" if response.ok else str(response.error or response.status),
        "failure_reason_tr": "" if response.ok else _failure_reason_tr(str(response.error or response.status), response.status),
        "relevance_validation_result": "not_performed",
        "relevance_validation_reason": "",
    }


def context(payload: dict[str, Any]) -> dict[str, Any]:
    config = ai_config_from_mapping(_as_record(payload.get("aiConfig") or payload.get("ai")))
    profile = str(payload.get("contextProfile") or _profile_for_mode(str(payload.get("mode") or "chat")))
    ai_context = build_ai_context(
        payload.get("runDir"),
        _as_record(payload.get("settings")),
        config.maxContextChars,
        profile=profile,
        provided_snapshot=_as_record(payload.get("aiRunContext") or payload.get("currentRunContext")),
    )
    return {
        "ok": True,
        "context": redact_obj(ai_context.context),
        "references": [ref.__dict__ for ref in ai_context.references],
        "truncated": ai_context.truncated,
    }


def status(payload: dict[str, Any]) -> dict[str, Any]:
    config = ai_config_from_mapping(_as_record(payload.get("aiConfig") or payload.get("ai")))
    ai_status = OpenAICompatibleClient(config).status()
    return {
        "ok": ai_status.ready,
        "status": ai_status.connection,
        "ai": {"status": ai_status.__dict__},
        "aiStatus": ai_status.__dict__,
        "model": config.model,
        "error": "" if ai_status.ready else ai_status.user_message_tr,
        "config": ai_config_dict(config),
        "availableModels": ai_status.available_models,
    }


def apply_settings(payload: dict[str, Any]) -> dict[str, Any]:
    config = ai_config_from_mapping(_as_record(payload.get("aiConfig") or payload.get("ai")))
    if not config.allowApprovedSettingsChanges:
        return {"ok": False, "errors": ["Kullanıcı onaylı AI ayar değişiklikleri kapalı."], "settings": redact_for_ui(_as_record(payload.get("settings")))}
    return apply_settings_action(
        _as_record(payload.get("settings")),
        _as_record(payload.get("plan")),
        approved=payload.get("approved") is True,
    )


def dispatch(payload: dict[str, Any], progress_callback: ProgressCallback | None = None) -> dict[str, Any]:
    action = str(payload.get("action") or "chat")
    if action == "context":
        return context(payload)
    if action == "status":
        return status(payload)
    if action == "apply_settings":
        return apply_settings(payload)
    if action in {"chat", "brief", "settings"}:
        return chat(
            {**payload, "mode": action if action != "chat" else payload.get("mode", "chat")},
            progress_callback=progress_callback,
        )
    return {"ok": False, "error": f"Unknown AI action: {action}"}


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        if not isinstance(payload, dict):
            raise ValueError("payload must be a JSON object")
        request_id = str(payload.get("request_id") or "")

        def progress_callback(state: str, attempt: int) -> None:
            sys.stderr.write(
                json.dumps(
                    {
                        "type": "ai_progress",
                        "request_id": request_id,
                        "state": state,
                        "attempt": max(0, int(attempt)),
                        "timestamp": datetime.now(UTC).isoformat(),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            sys.stderr.flush()

        result = dispatch(payload, progress_callback=progress_callback)
        sys.stdout.write(json.dumps(redact_for_ui(result), ensure_ascii=False))
        return 0
    except Exception as error:  # pragma: no cover - last-resort IPC guard
        sys.stdout.write(json.dumps({"ok": False, "error": redact_text(str(error))}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
