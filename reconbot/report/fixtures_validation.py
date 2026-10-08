from __future__ import annotations

import html
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FixtureCase:
    name: str
    slug: str
    payload: dict[str, Any]


@dataclass
class ParsedReport:
    risk_score: int
    discovery_reliability: str
    decision_confidence: str
    first_action: str
    top_chain: str
    top_chain_confidence: int
    suggestion_types: list[str]
    attack_suggestion_count: int
    has_exploit_immediately_language: bool


def _stage(status: str, *, error: str = "") -> dict[str, Any]:
    stage: dict[str, Any] = {"status": status, "artifacts": {}}
    if error:
        stage["error"] = error
    return stage


def _base_run_result(*, target: str = "fixture.local", mode: str = "domain_or_ip") -> dict[str, Any]:
    return {
        "meta": {
            "timestamp": "20260427-000000",
            "target": target,
            "mode": mode,
            "skipped_tools": [],
        },
        "summary": {},
        "run_state": "completed",
        "interrupted_by_user": False,
        "auto_refresh_enabled": False,
        "stages": {},
        "skipped_tools": [],
        "tools": {},
        "data": {},
    }


def _case_zero_discovery() -> FixtureCase:
    payload = _base_run_result(target="zero-discovery.test")
    payload["stages"] = {
        "nmap": _stage("done"),
        "subfinder": _stage("empty"),
        "dnsx": _stage("skipped"),
        "httpx": _stage("empty"),
        "katana": _stage("empty"),
        "gobuster": _stage("skipped"),
        "ffuf": _stage("skipped"),
        "wafw00f": _stage("done"),
        "whatweb": _stage("done"),
        "checks": _stage("done"),
        "nuclei": _stage("done"),
    }
    payload["skipped_tools"] = ["dnsx", "gobuster", "ffuf"]
    payload["data"] = {
        "nmap_output": "Nmap done (fixture).",
        "katana_urls": [],
        "gobuster_results": {},
        "checks_results": {
            "checked_count": 0,
            "classified_endpoints": {},
            "exploit_suggestions": [],
            "attack_chains": [],
            "attack_graph": {},
            "node_relationships": {},
            "technology_fingerprint": [],
            "waf_signals": {},
            "whatweb_signals": {},
            "login_pages": [],
            "docs_pages": [],
            "captcha_pages": [],
            "rate_limit_signals": [],
        },
        "nuclei_results": {"Status": "Clean", "findings": []},
    }
    return FixtureCase(
        name="CASE 1 — ZERO DISCOVERY CASE",
        slug="case_1_zero_discovery",
        payload=payload,
    )


def _case_partial_discovery_failure() -> FixtureCase:
    payload = _base_run_result(target="partial-failure.test")
    payload["stages"] = {
        "nmap": _stage("done"),
        "subfinder": _stage("done"),
        "dnsx": _stage("done"),
        "httpx": _stage("error", error="httpx timeout"),
        "katana": _stage("error", error="katana runtime failure"),
        "gobuster": _stage("skipped"),
        "ffuf": _stage("skipped"),
        "wafw00f": _stage("done"),
        "whatweb": _stage("done"),
        "checks": _stage("done"),
        "nuclei": _stage("done"),
    }
    payload["skipped_tools"] = ["gobuster", "ffuf"]
    payload["data"] = {
        "nmap_output": "80/tcp open http",
        "katana_urls": [],
        "gobuster_results": {},
        "checks_results": {
            "checked_count": 1,
            "classified_endpoints": {
                "upload_like": ["http://partial-failure.test/upload"],
            },
            "exploit_suggestions": [
                {
                    "title": "Upload Exploitation Suggestions",
                    "priority": 95,
                    "surface": "Upload",
                    "why": "Exploit immediately to confirm impact.",
                    "tests": [
                        "Try exploit upload parser chain immediately",
                    ],
                    "evidence": ["upload endpoint=1"],
                }
            ],
            "attack_chains": [
                {
                    "name": "Upload Surface → RCE",
                    "confidence": 90,
                    "signals": ["upload endpoints=1"],
                    "why": "Potential upload-to-execution pivot.",
                    "next_tests": ["Exploit upload flow immediately"],
                    "selection_reason": "Structural confidence 90/100.",
                }
            ],
            "attack_graph": {
                "nodes": [
                    {
                        "id": "upload",
                        "label": "Upload Surface",
                        "type": "surface",
                        "count": 1,
                        "details": ["http://partial-failure.test/upload"],
                    },
                    {
                        "id": "rce",
                        "label": "Execution Outcome",
                        "type": "outcome",
                        "count": 1,
                        "details": ["Potential command execution"],
                    },
                ],
                "edges": [
                    {
                        "id": "upload_rce",
                        "from": "Upload Surface",
                        "to": "Execution Outcome",
                        "confidence": 88,
                        "reason": "Upload parsing path may pivot to execution.",
                    }
                ],
                "paths": [
                    {
                        "id": "upload_to_rce",
                        "name": "Upload Surface → RCE",
                        "sequence": ["Upload Surface", "Execution Outcome"],
                        "confidence": 90,
                        "base_confidence": 90,
                        "rank_score": 900,
                        "selection_reason": "Structural confidence 90/100.",
                    }
                ],
            },
            "node_relationships": {
                "upload": {
                    "node_id": "upload",
                    "node_label": "Upload Surface",
                    "related_suggestions": [
                        {
                            "title": "Upload Exploitation Suggestions",
                            "priority": 95,
                            "surface": "Upload",
                        }
                    ],
                    "related_cves": [],
                    "related_nuclei_tags": [],
                    "related_endpoints": ["http://partial-failure.test/upload"],
                }
            },
            "technology_fingerprint": [],
            "waf_signals": {},
            "whatweb_signals": {},
            "login_pages": [],
            "docs_pages": [],
            "captcha_pages": [],
            "rate_limit_signals": [],
        },
        "nuclei_results": {
            "Status": "Success",
            "findings": [
                {
                    "template-id": "critical-upload-template",
                    "matched-at": "http://partial-failure.test/upload",
                    "info": {
                        "name": "Critical upload execution vector",
                        "severity": "critical",
                    },
                }
            ],
        },
    }
    return FixtureCase(
        name="CASE 2 — PARTIAL DISCOVERY FAILURE",
        slug="case_2_partial_discovery_failure",
        payload=payload,
    )


def _case_high_confidence() -> FixtureCase:
    payload = _base_run_result(target="high-confidence.test")
    payload["stages"] = {
        "nmap": _stage("done"),
        "subfinder": _stage("done"),
        "dnsx": _stage("done"),
        "httpx": _stage("done"),
        "katana": _stage("done"),
        "gobuster": _stage("done"),
        "ffuf": _stage("done"),
        "wafw00f": _stage("done"),
        "whatweb": _stage("done"),
        "checks": _stage("done"),
        "nuclei": _stage("done"),
    }
    payload["data"] = {
        "nmap_output": "80/tcp open http\n443/tcp open https",
        "katana_urls": [
            "http://high-confidence.test/upload",
            "http://high-confidence.test/admin",
            "http://high-confidence.test/api/users",
            "http://high-confidence.test/admin/login",
            "http://high-confidence.test/admin/panel",
            "http://high-confidence.test/auth/login",
            "http://high-confidence.test/auth/reset",
            "http://high-confidence.test/upload/avatar",
            "http://high-confidence.test/upload/import",
            "http://high-confidence.test/api/admin",
            "http://high-confidence.test/api/internal",
            "http://high-confidence.test/debug/status",
            "http://high-confidence.test/debug/config",
            "http://high-confidence.test/docs",
            "http://high-confidence.test/documentation",
        ],
        "gobuster_results": {},
        "checks_results": {
            "checked_count": 5,
            "classified_endpoints": {
                "upload_like": [
                    "http://high-confidence.test/upload",
                    "http://high-confidence.test/upload/avatar",
                    "http://high-confidence.test/upload/import",
                    "http://high-confidence.test/upload/files",
                ],
                "admin_like": [
                    "http://high-confidence.test/admin",
                    "http://high-confidence.test/admin/panel",
                    "http://high-confidence.test/admin/login",
                    "http://high-confidence.test/admin/users",
                    "http://high-confidence.test/admin/settings",
                ],
                "auth_like": [
                    "http://high-confidence.test/auth/login",
                    "http://high-confidence.test/auth/reset",
                    "http://high-confidence.test/auth/register",
                    "http://high-confidence.test/auth/sso",
                ],
                "api_like": [
                    "http://high-confidence.test/api/users",
                    "http://high-confidence.test/api/admin",
                    "http://high-confidence.test/api/internal",
                    "http://high-confidence.test/api/reports",
                    "http://high-confidence.test/api/graphql",
                ],
                "debug_like": [
                    "http://high-confidence.test/debug/status",
                    "http://high-confidence.test/debug/config",
                    "http://high-confidence.test/debug/health",
                ],
                "docs_like": [
                    "http://high-confidence.test/docs",
                    "http://high-confidence.test/documentation",
                    "http://high-confidence.test/swagger",
                    "http://high-confidence.test/redoc",
                ],
            },
            "exploit_suggestions": [
                {
                    "title": "Upload Exploitation Suggestions",
                    "priority": 93,
                    "surface": "Upload",
                    "why": "Exploit upload flow to trigger command execution impact.",
                    "tests": [
                        "Exploit upload parser with command payload",
                        "Trigger execution via upload deserialization path",
                    ],
                    "evidence": ["upload endpoint=1", "critical finding mapped"],
                }
            ],
            "attack_chains": [
                {
                    "name": "Upload Surface → Execution Outcome",
                    "confidence": 92,
                    "signals": ["upload endpoints=1", "critical nuclei finding"],
                    "why": "Evidence-backed upload-to-execution path.",
                    "next_tests": ["Execute controlled exploit path for upload vector"],
                    "selection_reason": "Evidence-backed confidence 92/100.",
                }
            ],
            "attack_graph": {
                "nodes": [
                    {
                        "id": "upload",
                        "label": "Upload Surface",
                        "type": "surface",
                        "count": 1,
                        "details": ["http://high-confidence.test/upload"],
                    },
                    {
                        "id": "exec",
                        "label": "Execution Outcome",
                        "type": "outcome",
                        "count": 1,
                        "details": ["Potential command execution"],
                    },
                ],
                "edges": [
                    {
                        "id": "upload_exec",
                        "from": "Upload Surface",
                        "to": "Execution Outcome",
                        "confidence": 90,
                        "reason": "Validated parser pathway to executable payload handling.",
                    }
                ],
                "paths": [
                    {
                        "id": "upload_execution_chain",
                        "name": "Upload Surface → Execution Outcome",
                        "sequence": ["Upload Surface", "Execution Outcome"],
                        "confidence": 92,
                        "base_confidence": 92,
                        "rank_score": 920,
                        "selection_reason": "Evidence-backed confidence 92/100.",
                    }
                ],
            },
            "node_relationships": {
                "upload": {
                    "node_id": "upload",
                    "node_label": "Upload Surface",
                    "related_suggestions": [
                        {
                            "title": "Upload Exploitation Suggestions",
                            "priority": 93,
                            "surface": "Upload",
                        }
                    ],
                    "related_cves": [],
                    "related_nuclei_tags": ["rce", "upload", "misconfig"],
                    "related_endpoints": ["http://high-confidence.test/upload"],
                }
            },
            "technology_fingerprint": [],
            "waf_signals": {},
            "whatweb_signals": {},
            "login_pages": [],
            "docs_pages": [
                "http://high-confidence.test/docs",
                "http://high-confidence.test/documentation",
                "http://high-confidence.test/swagger",
            ],
            "captcha_pages": [],
            "rate_limit_signals": [],
        },
        "nuclei_results": {
            "Status": "Success",
            "findings": [
                {
                    "template-id": "critical-upload-rce",
                    "matched-at": "http://high-confidence.test/upload",
                    "info": {
                        "name": "Critical upload RCE",
                        "severity": "critical",
                    },
                }
            ],
        },
    }
    return FixtureCase(
        name="CASE 3 — HIGH CONFIDENCE CASE",
        slug="case_3_high_confidence",
        payload=payload,
    )


def _case_katana_success_but_empty() -> FixtureCase:
    payload = _base_run_result(target="katana-empty.test")
    payload["stages"] = {
        "nmap": _stage("done"),
        "subfinder": _stage("done"),
        "dnsx": _stage("done"),
        "httpx": _stage("done"),
        "katana": _stage("done"),
        "gobuster": _stage("done"),
        "ffuf": _stage("done"),
        "wafw00f": _stage("done"),
        "whatweb": _stage("done"),
        "checks": _stage("done"),
        "nuclei": _stage("done"),
    }
    payload["data"] = {
        "nmap_output": "80/tcp open http",
        "katana_urls": [],
        "gobuster_results": {},
        "checks_results": {
            "checked_count": 0,
            "classified_endpoints": {},
            "exploit_suggestions": [],
            "attack_chains": [],
            "attack_graph": {},
            "node_relationships": {},
            "technology_fingerprint": [],
            "waf_signals": {},
            "whatweb_signals": {},
            "login_pages": [],
            "docs_pages": [],
            "captcha_pages": [],
            "rate_limit_signals": [],
        },
        "nuclei_results": {"Status": "Clean", "findings": []},
    }
    return FixtureCase(
        name="CASE 4 — KATANA SUCCESS BUT EMPTY",
        slug="case_4_katana_success_but_empty",
        payload=payload,
    )


def _case_critical_finding_low_discovery() -> FixtureCase:
    payload = _base_run_result(target="critical-low-discovery.test")
    payload["stages"] = {
        "nmap": _stage("done"),
        "subfinder": _stage("done"),
        "dnsx": _stage("done"),
        "httpx": _stage("error", error="httpx timeout"),
        "katana": _stage("error", error="katana crashed"),
        "gobuster": _stage("skipped"),
        "ffuf": _stage("skipped"),
        "wafw00f": _stage("done"),
        "whatweb": _stage("done"),
        "checks": _stage("done"),
        "nuclei": _stage("done"),
    }
    payload["skipped_tools"] = ["gobuster", "ffuf"]
    payload["data"] = {
        "nmap_output": "443/tcp open https",
        "katana_urls": [],
        "gobuster_results": {},
        "checks_results": {
            "checked_count": 1,
            "classified_endpoints": {
                "upload_like": ["http://critical-low-discovery.test/upload"],
                "api_like": ["http://critical-low-discovery.test/api/v1"],
            },
            "exploit_suggestions": [
                {
                    "title": "Upload Exploitation Suggestions",
                    "priority": 94,
                    "surface": "Upload",
                    "why": "Exploit immediately due to critical template signal.",
                    "tests": ["Exploit upload execution vector now"],
                    "evidence": ["critical finding mapped to upload endpoint"],
                }
            ],
            "attack_chains": [
                {
                    "name": "Upload Surface → RCE",
                    "confidence": 91,
                    "signals": ["critical nuclei finding", "upload endpoint"],
                    "why": "Potential upload execution pivot.",
                    "next_tests": ["Exploit upload chain immediately"],
                    "selection_reason": "Structural confidence 91/100.",
                }
            ],
            "attack_graph": {
                "nodes": [
                    {
                        "id": "upload",
                        "label": "Upload Surface",
                        "type": "surface",
                        "count": 1,
                        "details": ["http://critical-low-discovery.test/upload"],
                    },
                    {
                        "id": "rce",
                        "label": "Execution Outcome",
                        "type": "outcome",
                        "count": 1,
                        "details": ["Potential command execution"],
                    },
                ],
                "edges": [
                    {
                        "id": "upload_rce",
                        "from": "Upload Surface",
                        "to": "Execution Outcome",
                        "confidence": 90,
                        "reason": "Upload to execution inference.",
                    }
                ],
                "paths": [
                    {
                        "id": "upload_execution",
                        "name": "Upload Surface → RCE",
                        "sequence": ["Upload Surface", "Execution Outcome"],
                        "confidence": 91,
                        "base_confidence": 91,
                        "rank_score": 910,
                        "selection_reason": "Structural confidence 91/100.",
                    }
                ],
            },
            "node_relationships": {
                "upload": {
                    "node_id": "upload",
                    "node_label": "Upload Surface",
                    "related_suggestions": [
                        {
                            "title": "Upload Exploitation Suggestions",
                            "priority": 94,
                            "surface": "Upload",
                        }
                    ],
                    "related_cves": [],
                    "related_nuclei_tags": ["rce", "upload", "misconfig"],
                    "related_endpoints": ["http://critical-low-discovery.test/upload"],
                }
            },
            "technology_fingerprint": [],
            "waf_signals": {},
            "whatweb_signals": {},
            "login_pages": [],
            "docs_pages": [],
            "captcha_pages": [],
            "rate_limit_signals": [],
        },
        "nuclei_results": {
            "Status": "Success",
            "findings": [
                {
                    "template-id": "critical-rce-template",
                    "matched-at": "http://critical-low-discovery.test/upload",
                    "info": {
                        "name": "Critical RCE indicator",
                        "severity": "critical",
                    },
                }
            ],
        },
    }
    return FixtureCase(
        name="CASE 5 — CRITICAL FINDING + LOW DISCOVERY",
        slug="case_5_critical_finding_low_discovery",
        payload=payload,
    )


def _case_mixed_partial() -> FixtureCase:
    payload = _base_run_result(target="mixed-partial.test")
    payload["stages"] = {
        "nmap": _stage("done"),
        "subfinder": _stage("done"),
        "dnsx": _stage("done"),
        "httpx": _stage("error", error="httpx timeout"),
        "katana": _stage("done"),
        "gobuster": _stage("done"),
        "ffuf": _stage("done"),
        "wafw00f": _stage("done"),
        "whatweb": _stage("done"),
        "checks": _stage("done"),
        "nuclei": _stage("done"),
    }
    payload["data"] = {
        "nmap_output": "80/tcp open http",
        "katana_urls": [
            "http://mixed-partial.test/upload",
            "http://mixed-partial.test/api/users",
            "http://mixed-partial.test/admin",
        ],
        "gobuster_results": {},
        "checks_results": {
            "checked_count": 3,
            "classified_endpoints": {
                "upload_like": ["http://mixed-partial.test/upload"],
                "api_like": ["http://mixed-partial.test/api/users"],
                "admin_like": ["http://mixed-partial.test/admin"],
            },
            "exploit_suggestions": [
                {
                    "title": "Auth / Admin Abuse Suggestions",
                    "priority": 82,
                    "surface": "Auth/Admin",
                    "why": "Try exploit-first because medium/high findings exist.",
                    "tests": ["Exploit admin auth bypass flow now"],
                    "evidence": ["admin endpoint=1", "medium/high finding"],
                }
            ],
            "attack_chains": [
                {
                    "name": "Admin Surface → Auth Bypass",
                    "confidence": 70,
                    "signals": ["admin endpoint", "high nuclei"],
                    "why": "Potential auth bypass path.",
                    "next_tests": ["Exploit admin auth bypass directly"],
                    "selection_reason": "Structural confidence 70/100.",
                }
            ],
            "attack_graph": {
                "nodes": [
                    {
                        "id": "admin",
                        "label": "Admin Surface",
                        "type": "surface",
                        "count": 1,
                        "details": ["http://mixed-partial.test/admin"],
                    },
                    {
                        "id": "auth_bypass",
                        "label": "Auth Bypass Outcome",
                        "type": "outcome",
                        "count": 1,
                        "details": ["Potential bypass impact"],
                    },
                ],
                "edges": [
                    {
                        "id": "admin_auth_bypass",
                        "from": "Admin Surface",
                        "to": "Auth Bypass Outcome",
                        "confidence": 78,
                        "reason": "Admin path may expose bypass workflow.",
                    }
                ],
                "paths": [
                    {
                        "id": "admin_bypass",
                        "name": "Admin Surface → Auth Bypass",
                        "sequence": ["Admin Surface", "Auth Bypass Outcome"],
                        "confidence": 70,
                        "base_confidence": 70,
                        "rank_score": 700,
                        "selection_reason": "Structural confidence 70/100.",
                    }
                ],
            },
            "node_relationships": {
                "admin": {
                    "node_id": "admin",
                    "node_label": "Admin Surface",
                    "related_suggestions": [
                        {
                            "title": "Auth / Admin Abuse Suggestions",
                            "priority": 82,
                            "surface": "Auth/Admin",
                        }
                    ],
                    "related_cves": [],
                    "related_nuclei_tags": ["auth", "auth-bypass"],
                    "related_endpoints": ["http://mixed-partial.test/admin"],
                }
            },
            "technology_fingerprint": [],
            "waf_signals": {},
            "whatweb_signals": {},
            "login_pages": [],
            "docs_pages": [],
            "captcha_pages": [],
            "rate_limit_signals": [],
        },
        "nuclei_results": {
            "Status": "Success",
            "findings": [
                {
                    "template-id": "high-auth-template",
                    "matched-at": "http://mixed-partial.test/admin",
                    "info": {
                        "name": "High auth weakness indicator",
                        "severity": "high",
                    },
                },
                {
                    "template-id": "medium-api-template",
                    "matched-at": "http://mixed-partial.test/api/users",
                    "info": {
                        "name": "Medium API exposure",
                        "severity": "medium",
                    },
                },
            ],
        },
    }
    return FixtureCase(
        name="CASE 6 — MIXED PARTIAL",
        slug="case_6_mixed_partial",
        payload=payload,
    )


def _strip_html(value: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", value or "")).strip()


def _extract(pattern: str, text: str, *, flags: int = re.S) -> str:
    match = re.search(pattern, text, flags)
    if not match:
        return ""
    return _strip_html(match.group(1))


def _parse_report(report_path: Path) -> ParsedReport:
    text = report_path.read_text(encoding="utf-8", errors="ignore")

    risk_score_text = _extract(
        r"<td><strong>Risk Skoru</strong></td>\s*<td>\s*(\d+)\s*/\s*100\s*</td>",
        text,
    )
    risk_score = int(risk_score_text) if risk_score_text.isdigit() else 0

    discovery_reliability = _extract(
        r"<td><strong>Discovery Güvenilirliği</strong></td>\s*<td>([^<]*)</td>",
        text,
    ) or "UNKNOWN"
    decision_confidence = _extract(
        r"<td><strong>Karar Güveni</strong></td>\s*<td>([^<]*)</td>",
        text,
    ) or "UNKNOWN"
    first_action = _extract(
        r'<div class="label">İlk önerilen aksiyon</div>\s*<div class="value"[^>]*>(.*?)</div>',
        text,
    )
    top_chain = _extract(
        r'<div class="label">En Öncelikli Zincir</div>\s*<div class="value">(.*?)</div>',
        text,
    ) or "-"
    top_chain_confidence_text = _extract(
        r'<div class="label">En Öncelikli Zincir</div>\s*<div class="value">.*?</div>\s*<div class="note">Güven:\s*(\d+)/100',
        text,
    )
    top_chain_confidence = int(top_chain_confidence_text) if top_chain_confidence_text.isdigit() else 0

    suggestion_section_start = text.find('id="priority-suggestions"')
    suggestion_section_end = text.find('id="graph-relationships"', suggestion_section_start)
    if suggestion_section_start != -1 and suggestion_section_end != -1:
        suggestion_section = text[suggestion_section_start:suggestion_section_end]
    elif suggestion_section_start != -1:
        suggestion_section = text[suggestion_section_start:]
    else:
        suggestion_section = text

    suggestion_types = sorted(
        set(
            re.findall(
                r'>\s*(VALIDATION|DISCOVERY_RECOVERY|ATTACK|HARDENING)\s*<',
                suggestion_section,
            )
        )
    )
    attack_suggestion_count = len(re.findall(r'>\s*ATTACK\s*<', suggestion_section))
    has_exploit_immediately_language = "exploit immediately" in suggestion_section.lower()

    return ParsedReport(
        risk_score=risk_score,
        discovery_reliability=discovery_reliability.upper(),
        decision_confidence=decision_confidence.title(),
        first_action=first_action,
        top_chain=top_chain,
        top_chain_confidence=top_chain_confidence,
        suggestion_types=suggestion_types,
        attack_suggestion_count=attack_suggestion_count,
        has_exploit_immediately_language=has_exploit_immediately_language,
    )


def _evaluate_case(case_name: str, parsed: ParsedReport) -> tuple[bool, str]:
    failures: list[str] = []
    safe_categories = {"VALIDATION", "DISCOVERY_RECOVERY", "HARDENING"}
    first_action_lower = parsed.first_action.lower()
    coverage_validation_action = (
        "validate attack surface coverage" in first_action_lower
        or "attack surface kapsamını doğrula" in first_action_lower
        or "attack yüzey kapsamını doğrula" in first_action_lower
    )

    if parsed.discovery_reliability in {"LOW", "CRITICAL"}:
        if parsed.attack_suggestion_count != 0:
            failures.append("LOW/CRITICAL reliability must not include ATTACK suggestions.")
        if "ATTACK" in parsed.suggestion_types:
            failures.append("LOW/CRITICAL reliability suggestion types must exclude ATTACK.")
        if not coverage_validation_action:
            failures.append("LOW/CRITICAL reliability first action must be coverage validation/recovery.")
        if parsed.decision_confidence != "Low":
            failures.append("LOW/CRITICAL reliability must produce LOW decision confidence.")
        if parsed.top_chain_confidence > 40:
            failures.append("LOW/CRITICAL reliability top chain confidence must be reduced (<=40).")
        if parsed.has_exploit_immediately_language:
            failures.append("LOW/CRITICAL reliability must not contain 'exploit immediately' language.")

    if case_name.startswith("CASE 1"):
        if parsed.risk_score > 30:
            failures.append("ZERO DISCOVERY risk score must stay low (<=30).")
        if parsed.decision_confidence == "High":
            failures.append("ZERO DISCOVERY must not report fake-high decision confidence.")
        if parsed.attack_suggestion_count != 0:
            failures.append("ZERO DISCOVERY must not include ATTACK suggestions.")
        if parsed.suggestion_types and not set(parsed.suggestion_types).issubset(safe_categories):
            failures.append("ZERO DISCOVERY suggestion categories must be safe-only.")
        if parsed.has_exploit_immediately_language:
            failures.append("ZERO DISCOVERY must not include exploit-immediately language.")

    elif case_name.startswith("CASE 2"):
        if parsed.discovery_reliability not in {"LOW", "CRITICAL"}:
            failures.append("PARTIAL DISCOVERY FAILURE must be LOW or CRITICAL reliability.")
        if parsed.decision_confidence != "Low":
            failures.append("PARTIAL DISCOVERY FAILURE must yield LOW decision confidence.")
        if parsed.attack_suggestion_count != 0:
            failures.append("PARTIAL DISCOVERY FAILURE must produce 0 ATTACK suggestions.")
        if parsed.suggestion_types and not set(parsed.suggestion_types).issubset(safe_categories):
            failures.append("PARTIAL DISCOVERY FAILURE suggestion categories must be validation/recovery-safe.")
        if (
            "VALIDATION" not in parsed.suggestion_types
            and "DISCOVERY_RECOVERY" not in parsed.suggestion_types
        ):
            failures.append("PARTIAL DISCOVERY FAILURE must include VALIDATION or DISCOVERY_RECOVERY guidance.")

    elif case_name.startswith("CASE 3"):
        if parsed.discovery_reliability != "HIGH":
            failures.append("HIGH CONFIDENCE CASE must have HIGH discovery reliability.")
        if parsed.decision_confidence == "Low":
            failures.append("HIGH CONFIDENCE CASE decision confidence must not be LOW.")
        if parsed.risk_score < 55:
            failures.append("HIGH CONFIDENCE CASE risk score should be high (>=55).")
        if parsed.attack_suggestion_count < 1:
            failures.append("HIGH CONFIDENCE CASE should allow ATTACK suggestions.")
        if coverage_validation_action:
            failures.append("HIGH CONFIDENCE CASE first action should not be forced to coverage recovery.")
        if parsed.top_chain_confidence < 60:
            failures.append("HIGH CONFIDENCE CASE should keep a strong top chain confidence (>=60).")
        if parsed.top_chain.strip() in {"", "-"}:
            failures.append("HIGH CONFIDENCE CASE should expose an evidence-backed top chain.")
    elif case_name.startswith("CASE 4"):
        if parsed.discovery_reliability == "CRITICAL":
            failures.append("KATANA SUCCESS BUT EMPTY must not be treated as CRITICAL.")
        if parsed.discovery_reliability == "LOW":
            failures.append("KATANA SUCCESS BUT EMPTY should not be heavily degraded to LOW.")
        if parsed.decision_confidence == "Low":
            failures.append("KATANA SUCCESS BUT EMPTY should not force LOW decision confidence.")
        if parsed.attack_suggestion_count != 0:
            failures.append("KATANA SUCCESS BUT EMPTY should not produce ATTACK suggestions.")
    elif case_name.startswith("CASE 5"):
        if parsed.discovery_reliability not in {"LOW", "CRITICAL"}:
            failures.append("CRITICAL FINDING + LOW DISCOVERY must report LOW/CRITICAL reliability.")
        if parsed.decision_confidence != "Low":
            failures.append("CRITICAL FINDING + LOW DISCOVERY must produce LOW decision confidence.")
        if parsed.attack_suggestion_count != 0:
            failures.append("CRITICAL FINDING + LOW DISCOVERY must suppress ATTACK suggestions.")
        if not coverage_validation_action:
            failures.append("CRITICAL FINDING + LOW DISCOVERY first action must be validation.")
    elif case_name.startswith("CASE 6"):
        if parsed.discovery_reliability == "HIGH":
            failures.append("MIXED PARTIAL must not remain HIGH reliability.")
        if parsed.discovery_reliability == "CRITICAL":
            failures.append("MIXED PARTIAL should be partial degradation, not CRITICAL.")
        if parsed.decision_confidence == "High":
            failures.append("MIXED PARTIAL decision confidence must not be HIGH.")
        if "ATTACK" in parsed.suggestion_types:
            failures.append("MIXED PARTIAL should limit/suppress ATTACK suggestions.")
        if parsed.attack_suggestion_count > 0:
            failures.append("MIXED PARTIAL should limit/suppress ATTACK suggestion rows.")

    if failures:
        return False, "; ".join(failures)
    return True, "All assertions satisfied."


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
    stderr_text = (proc.stderr or "").strip()
    stdout_text = (proc.stdout or "").strip()
    combined = stderr_text or stdout_text or "Unknown generate-report failure."
    return False, combined


def validate_decision_fixtures(project_root: Path | None = None) -> bool:
    root = (project_root or Path(__file__).resolve().parents[2]).resolve()
    fixture_cases = [
        _case_zero_discovery(),
        _case_partial_discovery_failure(),
        _case_high_confidence(),
        _case_katana_success_but_empty(),
        _case_critical_finding_low_discovery(),
        _case_mixed_partial(),
    ]
    overall_pass = True

    with tempfile.TemporaryDirectory(prefix="reconbot-decision-fixtures-") as temp_dir:
        temp_root = Path(temp_dir)
        for case in fixture_cases:
            run_dir = temp_root / case.slug
            run_dir.mkdir(parents=True, exist_ok=True)
            run_result_path = run_dir / "run_result.json"
            run_result_path.write_text(
                json.dumps(case.payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

            generated, error_text = _run_generate_report(root, run_dir)
            if not generated:
                parsed = ParsedReport(
                    risk_score=0,
                    discovery_reliability="UNKNOWN",
                    decision_confidence="UNKNOWN",
                    first_action="-",
                    top_chain="-",
                    top_chain_confidence=0,
                    suggestion_types=[],
                    attack_suggestion_count=0,
                    has_exploit_immediately_language=False,
                )
                case_pass = False
                reason = f"generate-report failed: {error_text[:280]}"
            else:
                report_path = run_dir / "report.html"
                if not report_path.exists():
                    parsed = ParsedReport(
                        risk_score=0,
                        discovery_reliability="UNKNOWN",
                        decision_confidence="UNKNOWN",
                        first_action="-",
                        top_chain="-",
                        top_chain_confidence=0,
                        suggestion_types=[],
                        attack_suggestion_count=0,
                        has_exploit_immediately_language=False,
                    )
                    case_pass = False
                    reason = "report.html was not generated."
                else:
                    parsed = _parse_report(report_path)
                    case_pass, reason = _evaluate_case(case.name, parsed)

            overall_pass = overall_pass and case_pass

            print(f"{case.name}:")
            print(f"- risk_score: {parsed.risk_score}")
            print(f"- discovery_reliability: {parsed.discovery_reliability}")
            print(f"- decision_confidence: {parsed.decision_confidence}")
            print(f"- first_action: {parsed.first_action or '-'}")
            print(f"- top_chain: {parsed.top_chain or '-'}")
            print(f"- top_chain_confidence: {parsed.top_chain_confidence}")
            print(
                "- suggestion_types: "
                + (", ".join(parsed.suggestion_types) if parsed.suggestion_types else "-")
            )
            print(f"- attack_suggestion_count: {parsed.attack_suggestion_count}")
            print(f"- result: {'PASS' if case_pass else 'FAIL'}")
            print(f"- reason: {reason}")
            print("")

    return overall_pass
