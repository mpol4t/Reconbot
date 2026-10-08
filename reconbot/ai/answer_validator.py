from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .redaction import contains_unresolved_placeholder_values


URL_PATTERN = re.compile(r"https?://[^\s<>\]\[\"'`]+", re.IGNORECASE)
ENDPOINT_VALUE_PATTERN = re.compile(
    r"\b(?:matched\s+url|url|endpoint|uç\s*nokta|panel|adres|path)\s*(?:değeri|yolu)?\s*[:=\-]\s*`?(/[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]+)",
    re.IGNORECASE,
)
REQUEST_RESPONSE_VALUE_PATTERN = re.compile(
    r"\b(?:matched\s+)?(?:request(?:\s*/\s*response)?|response|istek|yanıt)\s*[:=\-]\s*"
    r"(`?(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+/[^\s`]+(?:\s+HTTP/\d(?:\.\d)?)?|`?HTTP/\d(?:\.\d)?\s+\d{3})",
    re.IGNORECASE,
)
NEGATION_PATTERN = re.compile(
    r"\b(?:kullanma(?:y[ıi]n(?:[ıi]z)?)?|deneme(?:y[ıi]n(?:[ıi]z)?)?|çalıştırma(?:y[ıi]n(?:[ıi]z)?)?|"
    r"yükleme(?:y[ıi]n(?:[ıi]z)?)?|yapma(?:y[ıi]n(?:[ıi]z)?)?|üretme(?:y[ıi]n(?:[ıi]z)?)?|"
    r"oluşturma(?:y[ıi]n(?:[ıi]z)?)?|uygulamay[ıi]n(?:[ıi]z)?|önerme(?:y[ıi]n(?:[ıi]z)?)?|"
    r"kaçın(?:ın)?|yasak|verme(?:y[ıi]n(?:[ıi]z)?)?|değil)\b",
    re.IGNORECASE,
)
UNVERIFIED_CAPABILITY_PATTERN = re.compile(
    r"\b(?:rce|remote\s+code\s+execution|uzaktan\s+kod\s+çalıştırma|file[- ]?read|dosya\s+okuma|auth(?:entication)?\s+bypass|"
    r"kimlik\s+doğrulama\s+atlatma|exploit|sömürü)\b.*"
    r"\b(?:başarılı|çalışıyor|çalışır|erişilebilir|doğrulandı|kanıtlandı|kesin|mevcut|etkileniyor|"
    r"istismar\s+edilebilir|mümkün|var|sağla\w*|olanak\s+tanır|izin\s+verir|"
    r"tespit\w*|saptan\w*|bulun\w*|göster\w*)\b",
    re.IGNORECASE,
)
UNVERIFIED_EXPLOIT_EFFECT_PATTERN = re.compile(
    r"(?:\b(?:kod|komut)\w*\b.{0,90}\b(?:yaz|çalıştır|yükle|yürüt)\w*\b|"
    r"\b(?:sunucu|işletim\s+sistemi|sistem)\w*\b.{0,90}\b(?:kontrol|ele\s+geçir)\w*\b|"
    r"\b(?:güvenlik\s+açığı|zafiyet)\w*\b.{0,70}\b(?:dır|dir|var|mevcut|bulun|tespit|saptan|yanıtı)\w*\b)",
    re.IGNORECASE,
)
GROUNDING_QUALIFIER_PATTERN = re.compile(
    r"\b(?:nuclei\s+template\s+eşleşmesi|template\s+eşleşmesi|henüz\s+doğrulanmadı|"
    r"doğrulanmış\s+değil|false[- ]?positive|artifact(?:te|taki)?\s+.*doğrulanmalı|başlığında\s+geçen)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class AnswerValidationResult:
    usable: bool
    reason: str = ""
    categories: list[str] = field(default_factory=list)
    unsupported_claims: list[str] = field(default_factory=list)


def _as_record(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _finding_url(finding: dict[str, Any]) -> str:
    value = str(finding.get("matched_url") or finding.get("url") or "").strip().rstrip(".,;:)")
    if not value or contains_unresolved_placeholder_values(value):
        return ""
    try:
        parsed = urlparse(value)
    except ValueError:
        return ""
    return value if parsed.scheme in {"http", "https"} and bool(parsed.netloc) else ""


def _url_path(value: str) -> str:
    try:
        return urlparse(value).path or "/"
    except ValueError:
        return ""


def _url_identity(value: str) -> tuple[str, str, str, str, str]:
    parsed = urlparse(value)
    # A host URL and its root slash represent the same address; query/path
    # bytes are retained so a different parameter value is not accepted.
    return (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, parsed.fragment)


def _clean_claim(line: str) -> str:
    return re.sub(r"\s+", " ", line).strip()[:360]


def validate_answer_integrity(
    answer: str,
    *,
    findings: list[dict[str, Any]] | None = None,
    enforce_artifact_grounding: bool = False,
    reference_urls: list[str] | None = None,
) -> AnswerValidationResult:
    """Validate concrete artifact integrity, never answer style or completeness."""
    visible = (answer or "").strip()
    if contains_unresolved_placeholder_values(visible):
        return AnswerValidationResult(
            usable=False,
            reason="unresolved_placeholder_values",
            categories=["unresolved_placeholder_values"],
            unsupported_claims=["Cevap çözülmemiş placeholder alanları içeriyor."],
        )
    categories: list[str] = []
    claims: list[str] = []

    def reject(category: str, claim: str) -> None:
        if category not in categories:
            categories.append(category)
        cleaned = _clean_claim(claim)
        if cleaned and cleaned not in claims:
            claims.append(cleaned)

    lines = [raw_line.strip() for raw_line in visible.splitlines() if raw_line.strip()]
    if not enforce_artifact_grounding:
        return AnswerValidationResult(usable=True)

    relevant_findings = [_as_record(item) for item in (findings or []) if isinstance(item, dict)]
    allowed_urls = {url for item in relevant_findings if (url := _finding_url(item))}
    allowed_urls.update(url for value in (reference_urls or []) if (url := _finding_url({"matched_url": value})))
    allowed_url_ids = {_url_identity(url) for url in allowed_urls}
    allowed_paths = {_url_path(url) for url in allowed_urls if _url_path(url)}
    verification_states = {str(item.get("verification_state") or "unverified").lower() for item in relevant_findings}
    all_verified = bool(verification_states) and verification_states == {"verified"}
    has_request_response_evidence = any(
        item.get(key) not in (None, "", [], {})
        for item in relevant_findings
        for key in ("request", "response", "matched_request", "matched_response")
    )

    # A direct claim that an unverified record was actually verified contradicts
    # the supplied artifact. Conditional impact explanations and ordinary
    # security terminology are intentionally not inspected.
    confirmed_pattern = re.compile(
        r"\b(?:doğruland[ıi]|kanıtland[ıi]|kesin\s+olarak\s+tespit\w*)\b|"
        r"\b(?:is|are|was|were|been|has\s+been|have\s+been)\s+(?:(?:fully|successfully|independently|manually)\s+){0,2}(?:confirmed|verified)\b|"
        r"\b(?:we|i|nuclei|scanner|scan|report|test)\s+(?:(?:successfully|manually|independently)\s+)?(?:confirmed|verified)\b|"
        r"\b(?:confirmed|verified)\s+(?:vulnerabilit(?:y|ies)|findings?|exploits?|rce)\b|"
        r"\b(?:verification|validation|status)\s*[:=]\s*(?:confirmed|verified)\b|"
        r"\b(?:confirmed|verified)\s*[:=]\s*(?:true|yes)\b",
        re.IGNORECASE,
    )
    for line in lines:
        # Assess separate clauses: a warning in one sentence must not license a
        # contradictory confirmation in the next. English negation/advice is
        # not a claim of verification.
        clauses = re.split(r"(?<=[.!?;])\s+|\b(?:but|however|ancak|fakat)\b", line, flags=re.IGNORECASE)
        for clause in clauses:
            negated = bool(NEGATION_PATTERN.search(clause) or re.search(r"\b(?:not|never|no|cannot|can't|isn't|aren't|wasn't|weren't|hasn't|haven't)\b", clause, re.IGNORECASE))
            qualified = bool(GROUNDING_QUALIFIER_PATTERN.search(clause) or re.search(r"\b(?:if|unless|until|should|must|need(?:s)?\s+to|require(?:s)?|may|might|could|would|partially\s+(?:verified|confirmed))\b", clause, re.IGNORECASE))
            if confirmed_pattern.search(clause) and not all_verified and not qualified and not negated:
                reject("nuclei_match_treated_as_confirmed", clause)

    for match in URL_PATTERN.finditer(visible):
        url = match.group(0).rstrip(".,;:)")
        if url not in allowed_urls:
            prefix = visible[max(0, match.start() - 3):match.start()]
            for marker in ("***", "**", "*", "___", "__", "_"):
                if prefix.endswith(marker) and url.endswith(marker):
                    url = url[:-len(marker)].rstrip(".,;:)")
                    break
            link_emphasis = re.search(r"(\*{1,3}|_{1,3})\[[^\]\r\n]*\]\($", visible[:match.start()])
            if link_emphasis and url.endswith(")" + link_emphasis.group(1)):
                url = url[:-len(link_emphasis.group(1))].rstrip(".,;:)")
        if _url_identity(url) not in allowed_url_ids:
            reject("invented_url", f"Artifact içinde bulunmayan URL: {url}")

    without_urls = URL_PATTERN.sub("", visible)
    for match in ENDPOINT_VALUE_PATTERN.finditer(without_urls):
        endpoint = match.group(1).rstrip(".,;:)")
        endpoint_path = _url_path(endpoint) if endpoint.startswith("http") else endpoint.split("?", 1)[0]
        if endpoint_path not in allowed_paths:
            reject("invented_endpoint", f"Artifact içinde bulunmayan endpoint: {endpoint}")

    if not has_request_response_evidence:
        for match in REQUEST_RESPONSE_VALUE_PATTERN.finditer(without_urls):
            reject("invented_request_response", f"Artifact içinde bulunmayan request/response kanıtı: {match.group(1).strip('`')}")

    if categories:
        return AnswerValidationResult(
            usable=False,
            reason=categories[0] if len(categories) == 1 else "evidence_integrity_failure",
            categories=categories,
            unsupported_claims=claims[:8],
        )
    return AnswerValidationResult(usable=True)
