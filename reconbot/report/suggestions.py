from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from reconbot.report.texts import text as _txt


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


_PUBLIC_CONTENT_PATH_MARKERS = (
    "/blog/",
    "/blog/category/",
    "/blog/tags/",
    "/docs/",
    "/help/",
    "/resources/",
    "/resource/",
    "/category/",
    "/tags/",
    "/tag/",
    "/services/",
    "/products/",
    "/news/",
    "/events/",
    "/company/",
    "/careers/",
    "/legal/",
)


def _is_public_content_context_url(value: Any) -> bool:
    low = str(value or "").lower()
    path = urlparse(low).path or low
    if any(marker in path for marker in _PUBLIC_CONTENT_PATH_MARKERS):
        return True
    if path.endswith(".html") and not any(
        marker in path
        for marker in (
            "/admin",
            "/administrator",
            "/manage",
            "/management",
            "/console",
            "/cpanel",
            "/control-panel",
            "/login",
            "/signin",
            "/auth",
        )
    ):
        slug = path.rsplit("/", 1)[-1]
        return bool("-" in slug or "_" in slug)
    return False


def _is_public_content_debug_config_suggestion(raw: dict[str, Any]) -> bool:
    combined = " ".join(
        [
            str(raw.get("title") or ""),
            str(raw.get("surface") or ""),
            str(raw.get("why") or ""),
        ]
    ).lower()
    if "debug/test" not in combined and "debug / config" not in combined and "config leak" not in combined:
        return False
    endpoints = raw.get("matched_endpoints", [])
    if not isinstance(endpoints, list) or not endpoints:
        return False
    return all(_is_public_content_context_url(endpoint) for endpoint in endpoints)


def soften_suggestion_text(text: Any) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""
    softened = raw
    replacements = (
        ("Exploit", "Validate"),
        ("exploit", "validate"),
        ("abuse", "review"),
        ("Abuse", "Review"),
        ("attack", "investigate"),
        ("Attack", "Investigate"),
        ("immediately", "after coverage validation"),
    )
    for before, after in replacements:
        softened = softened.replace(before, after)
    return softened


def infer_suggestion_category(
    title: Any,
    surface: Any,
    why: Any,
    tests: list[Any],
) -> str:
    title_low = str(title or "").strip().lower()
    surface_low = str(surface or "").strip().lower()
    why_low = str(why or "").strip().lower()
    tests_joined = " ".join(str(test or "").strip().lower() for test in (tests or []))
    combined = " ".join([title_low, surface_low, why_low, tests_joined]).strip()

    hardening_tokens = ("hardening", "misconfiguration", "cookie flags", "csrf", "rate-limit", "lockout")
    validation_tokens = ("validate", "validation", "review", "confirm", "verification", "investigate")
    attack_tokens = ("exploit", "abuse", "rce", "bypass", "overwrite", "lfi", "sqli")

    if any(token in combined for token in hardening_tokens):
        return "HARDENING"
    if any(token in combined for token in validation_tokens):
        return "VALIDATION"
    if any(token in combined for token in attack_tokens):
        return "ATTACK"
    return "ATTACK"


def _context_aware_suggestion_sort_key(item: dict[str, Any], discovery_reliability: str) -> tuple[int, int, str]:
    category = str(item.get("category") or "VALIDATION").strip().upper()
    if discovery_reliability == "CRITICAL":
        category_rank = {"DISCOVERY_RECOVERY": 0, "VALIDATION": 1, "HARDENING": 2, "ATTACK": 3}.get(category, 4)
    elif discovery_reliability in {"LOW", "MEDIUM"}:
        category_rank = {"VALIDATION": 0, "DISCOVERY_RECOVERY": 1, "HARDENING": 2, "ATTACK": 3}.get(category, 4)
    else:
        category_rank = {"ATTACK": 0, "VALIDATION": 1, "HARDENING": 2, "DISCOVERY_RECOVERY": 3}.get(category, 4)
    confidence_sort = -_safe_int(item.get("adjusted_confidence"), 0)
    title_sort = str(item.get("title") or "").strip().lower()
    return (category_rank, confidence_sort, title_sort)


def operator_text_to_english(text: Any) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""
    normalized = raw.replace("Validateation", "Validation")
    replacements = (
        ("Therefore", "Bu yüzden"),
        ("observed", "görüldü"),
        ("detected", "tespit edildi"),
        ("identified", "bulundu"),
        ("signal", "sinyali"),
        ("signals", "sinyalleri"),
        ("not a confirmed vulnerability", "kesin zafiyet değil"),
        ("operational inference only", "yalnızca operasyonel çıkarım"),
        ("validation", "doğrulama"),
        ("is prioritized", "önceliklendirildi"),
        ("should be reviewed", "incelenmeli"),
        ("surface", "yüzey"),
        ("findings", "bulgular"),
        ("workakış", "workflow"),
        ("Upload Exploitation Suggestions", "Upload doğrulama önerileri"),
        ("Upload Validation Suggestions", "Upload doğrulama önerileri"),
        ("Upload Execution Validation Suggestions", "Upload execution doğrulama önerileri"),
        ("Auth / Admin Abuse Suggestions", "Auth / admin inceleme önerileri"),
        ("API / Docs Enumeration Suggestions", "API / docs enumeration önerileri"),
        ("Public Documentation Manual Review", "Public documentation manual review"),
        ("Debug / Config Leak Suggestions", "Debug / config leak önerileri"),
        ("Config Exposure Manual Validation", "Config exposure manual validation"),
        ("Backup/Dump Exposure Manual Validation", "Backup/dump exposure manual validation"),
        ("Logs Exposure Manual Validation", "Logs exposure manual validation"),
        ("Debug Console Manual Validation", "Debug console manual validation"),
        ("Runtime Disclosure Manual Validation", "Runtime disclosure manual validation"),
        ("Internal API Manual Validation", "Internal API manual validation"),
        ("Admin Export Manual Validation", "Admin export manual validation"),
        ("Source Control Exposure Manual Validation", "Source control exposure manual validation"),
        ("Attack Path Validation Suggestions", "Attack path doğrulama önerileri"),
        ("Attack Chains", "Saldırı Zincirleri"),
        ("Upload → Manual Validation", "Upload → Manuel doğrulama"),
        ("Upload → Possible RCE", "Upload → RCE Validation Candidate"),
        ("Upload → RCE Validation Candidate", "Upload → RCE Validation Candidate"),
        ("Auth → Admin Abuse", "Auth → Admin kötüye kullanım incelemesi"),
        ("Docs/API → Enumeration & Exposure", "Docs/API → Enumeration & Exposure İncelemesi"),
        ("Public documentation surface → manual review", "Public documentation surface → manual review"),
        ("Config Mirror → Secret/Config Exposure", "Config Mirror → Secret/Config Exposure"),
        ("Backup Area → Sensitive Data Exposure", "Backup Area → Sensitive Data Exposure"),
        ("Logs Exposure → Internal Info Disclosure", "Logs Exposure → Internal Info Disclosure"),
        ("Debug Console → Internal Routes/Config Exposure", "Debug Console → Internal Routes/Config Exposure"),
        ("Runtime Disclosure → Manual Validation", "Runtime Disclosure → Manual Validation"),
        ("Internal API → Users Preview/Data Exposure", "Internal API → Users Preview/Data Exposure"),
        ("Admin Export → Data Exposure Review", "Admin Export → Data Exposure Review"),
        ("Source Control Exposure → Code/Secret Leakage → Manual Validation", "Source Control Exposure → Code/Secret Leakage → Manual Validation"),
        ("Debug/Test → Config Leak", "Debug/Test → Config Leak İncelemesi"),
        ("Docs → API → Enumeration", "Docs → API → Enumeration İncelemesi"),
        ("Admin Surface", "Admin Yüzeyi"),
        ("Authentication Surface", "Authentication Yüzeyi"),
        ("API Surface", "API Yüzeyi"),
        ("Upload Surface", "Upload Yüzeyi"),
        ("Debug/Test Surface", "Debug/Test Yüzeyi"),
        ("Docs/Dev Surface", "Docs/Dev Yüzeyi"),
        ("Technology Stack", "Teknoloji Stack"),
        ("Public Upload/Listing Exposure", "Public Upload/Listing Exposure"),
        ("Possible RCE", "RCE Validation Candidate"),
        ("RCE Validation Candidate", "RCE Validation Candidate"),
        ("Admin Abuse", "Admin kötüye kullanım incelemesi"),
        ("Config Leak", "Config Leak"),
        ("Enumeration / Exposure", "Enumeration / Exposure"),
        ("Nuclei Findings", "Nuclei Bulguları"),
        ("Nuclei Critical Findings", "Nuclei Critical Bulguları"),
        ("Execution Outcome", "Execution Sonucu"),
        ("Auth Bypass Outcome", "Auth Bypass Sonucu"),
        ("Nuclei findings correlated with", "Nuclei bulguları korele:"),
        ("Nuclei bulgular correlated with", "Nuclei bulguları korele:"),
        ("Nuclei findings are concentrated on", "Nuclei bulguları şu yüzeyde yoğunlaşıyor:"),
        ("Nuclei bulgular are concentrated on", "Nuclei bulguları şu yüzeyde yoğunlaşıyor:"),
        ("with critical severity signal", "critical severity sinyaliyle"),
        ("with high severity signal", "high severity sinyaliyle"),
        ("default credential checks", "default credential kontrolleri"),
        ("role / access control matrix testing", "role / access control matrix testi"),
        ("password reset workflow analysis", "password reset workflow analizi"),
        ("excessive data exposure review", "excessive data exposure incelemesi"),
        ("mass assignment testing", "mass assignment testi"),
        ("object-level authorization checks", "object-level authorization kontrolleri"),
        ("swagger / docs enumeration", "swagger / docs enumeration"),
        ("verbose error triggering", "verbose error tetikleme"),
        ("env/config disclosure review", "env/config disclosure incelemesi"),
        ("hidden parameters and debug flags", "gizli parametreler ve debug flag’leri"),
        ("internal/test route abuse", "internal/test route abuse incelemesi"),
        ("hidden endpoint harvesting", "gizli endpoint harvesting"),
        ("chain-specific manual validation", "zincire özel doğrulama"),
        ("chain-specific manual doğrulama", "zincire özel doğrulama"),
        ("entrypoint-to-impact walkthrough", "entrypoint’ten etkiye akış kontrolü"),
        ("pivot dependency checks", "pivot dependency kontrolleri"),
        ("false-positive elimination", "false-positive eleme"),
        ("env/config leak review", "env/config leak incelemesi"),
        ("hidden parameters", "gizli parametreler"),
        ("test harness / internal route abuse", "test harness / internal route abuse incelemesi"),
        ("default credentials", "default credential kontrolleri"),
        ("role/access control testing", "role/access control testi"),
        ("password reset / session workflow analysis", "password reset / session workflow analizi"),
        ("Admin yüzey", "Admin Yüzeyi"),
        ("Authentication yüzey", "Authentication Yüzeyi"),
        ("API yüzey", "API Yüzeyi"),
        ("Upload yüzey", "Upload Yüzeyi"),
        ("Debug/Test yüzey", "Debug/Test Yüzeyi"),
        ("Docs/Dev yüzey", "Docs/Dev Yüzeyi"),
        ("Nuclei bulgular", "Nuclei Bulguları"),
        ("Critical Bulguları", "Critical Bulguları"),
        ("Discovery coverage degraded - validate surface before acting on findings.", "Discovery kapsamı zayıfladı - bulgularla aksiyon almadan önce yüzeyi doğrula."),
        ("High/critical findings are high-trust under healthy discovery coverage; exploit-oriented first action is acceptable.", "Discovery kapsamı sağlıklıyken high/critical bulgular yüksek güvenlidir; exploit odaklı ilk aksiyon kabul edilebilir."),
        ("High/critical findings exist but trust is not high enough for exploit-first prioritization. Validate the finding before exploitation.", "High/critical bulgular var ancak güven exploit-first önceliklendirme için yeterli değil. Exploit öncesinde bulguyu doğrula."),
        ("Validation-oriented first action selected due to limited high-trust exploit evidence.", "Yüksek güvenli exploit kanıtı sınırlı olduğu için doğrulama odaklı ilk aksiyon seçildi."),
        ("Execute controlled exploit path for upload vector", "Upload vektörü için exploit önkoşullarını doğrula"),
        ("public upload/listing exposure review", "public upload/listing exposure incelemesi"),
        ("manual validation for upload abuse", "upload abuse için manuel doğrulama"),
        ("check executable handling", "executable handling kontrolü"),
        ("manual validation required", "manuel doğrulama gerekli"),
        ("not confirmed vulnerability", "kesin zafiyet değil"),
        ("reproduce top-severity findings", "en yüksek severity bulguları yeniden üret"),
        ("validate exploit preconditions", "exploit önkoşullarını doğrula"),
        ("confirm impact and false-positive status", "impact ve false-positive durumunu teyit et"),
        ("Operator validation lead.", "Operatör doğrulama önceliği."),
        ("Structural confidence", "Yapısal confidence"),
        ("evidence boost", "kanıt artışı"),
        ("no direct nuclei evidence mapped", "bu path ile doğrudan Nuclei kanıtı eşleşmedi"),
        ("Nuclei evidence on", "Nuclei kanıtı şu yüzeyde"),
        ("Exploit-practical signal present.", "Exploit açısından pratik sinyal mevcut."),
        ("correlated surface(s).", "korele yüzey."),
        ("Evidence-adjusted:", "Kanıta göre ayarlandı:"),
        ("Nuclei Bulgularıı", "Nuclei Bulguları"),
        ("Yüzeyii", "Yüzeyi"),
        ("total nuclei bulgular", "toplam_nuclei_bulgusu"),
        ("top templates:", "öne çıkan template’ler:"),
        ("1 bulgular", "1 bulgu"),
        ("template:", "template:"),
        ("aligns with upload yüzey", "upload yüzeyiyle ilişkili"),
        ("aligns with API Yüzeyi", "API yüzeyiyle ilişkili"),
        ("aligns with api yüzey", "API yüzeyiyle ilişkili"),
        ("aligns with debug/test yüzey", "Debug/Test yüzeyiyle ilişkili"),
        ("aligns with auth/admin yüzey", "Auth/Admin yüzeyiyle ilişkili"),
        ("aligns with docs/dev yüzey", "Docs/Dev yüzeyiyle ilişkili"),
        ("aligns with upload surface", "upload yüzeyiyle ilişkili"),
        ("aligns with API surface", "API yüzeyiyle ilişkili"),
        ("aligns with api surface", "API yüzeyiyle ilişkili"),
        ("aligns with debug/test surface", "Debug/Test yüzeyiyle ilişkili"),
        ("aligns with auth/admin surface", "Auth/Admin yüzeyiyle ilişkili"),
        ("aligns with docs/dev surface", "Docs/Dev yüzeyiyle ilişkili"),
        ("matches PHP stack", "PHP stack ile eşleşiyor"),
        ("matches Apache stack", "Apache stack ile eşleşiyor"),
        ("matches Nginx stack", "Nginx stack ile eşleşiyor"),
        ("Admin Abuse İncelemesi İncelemesi", "Admin kötüye kullanım incelemesi"),
        ("Admin kötüye kullanım incelemesi İncelemesi", "Admin kötüye kullanım incelemesi"),
        ("Config Leak İncelemesi İncelemesi", "Config Leak İncelemesi"),
        ("Enumeration & Exposure İncelemesi İncelemesi", "Enumeration & Exposure İncelemesi"),
        ("internal/test route abuse incelemesi incelemesi", "internal/test route abuse incelemesi"),
        ("with critical severity sinyali", "critical severity sinyaliyle"),
        ("with high severity sinyali", "high severity sinyaliyle"),
    )
    for before, after in replacements:
        normalized = normalized.replace(before, after)
    return normalized


def normalize_related_suggestion_title(title: Any, *, low_visibility: bool) -> str:
    raw = str(title or "").strip() or "-"
    cleaned = raw.replace("Validateation", "Validation")
    lower = cleaned.lower()

    exact_map = {
        "upload exploitation suggestions": "Upload doğrulama önerileri",
        "auth / admin abuse suggestions": "Auth / admin inceleme önerileri",
        "attack path validation suggestions": "Attack path doğrulama önerileri",
    }
    if lower in exact_map:
        return exact_map[lower]

    if low_visibility:
        cleaned = cleaned.replace("Exploitation", "Validation")
        cleaned = cleaned.replace("exploit", "validate")
        cleaned = cleaned.replace("Exploit", "Validate")
        cleaned = cleaned.replace("Abuse", "Review")
        cleaned = cleaned.replace("abuse", "review")
    return cleaned


def normalize_node_relationships_for_report(
    node_relationships: dict[str, Any],
    *,
    discovery_reliability: str,
    decision_confidence: str,
    failed_tier_1: list[dict[str, str]],
) -> dict[str, Any]:
    if not isinstance(node_relationships, dict):
        return {}

    normalized_map: dict[str, Any] = {}
    low_visibility = bool(discovery_reliability == "CRITICAL" or decision_confidence == "Low")
    partial_visibility = bool(low_visibility or discovery_reliability in {"LOW", "MEDIUM"})
    tier1_failed_tools = [
        str(item.get("tool") or "").strip().lower()
        for item in (failed_tier_1 or [])
        if str(item.get("tool") or "").strip()
    ]
    key_tool_failure = bool(any(tool in {"katana", "httpx"} for tool in tier1_failed_tools))

    for rel_key, rel_value in node_relationships.items():
        if not isinstance(rel_value, dict):
            normalized_map[rel_key] = rel_value
            continue

        rel_copy = dict(rel_value)
        rel_suggestions = rel_copy.get("related_suggestions", [])
        normalized_suggestions: list[dict[str, Any]] = []
        if isinstance(rel_suggestions, list):
            for sug in rel_suggestions:
                if not isinstance(sug, dict):
                    continue
                sug_copy = dict(sug)
                title = normalize_related_suggestion_title(
                    sug_copy.get("title"),
                    low_visibility=low_visibility or key_tool_failure,
                )
                priority = max(0, min(100, _safe_int(sug_copy.get("priority"), 0)))
                if discovery_reliability == "CRITICAL":
                    priority = min(priority, 40)
                elif decision_confidence == "Low":
                    priority = min(int(round(priority * 0.70)), 60)
                elif partial_visibility or key_tool_failure:
                    priority = min(priority, 70)

                sug_copy["title"] = operator_text_to_english(title)
                sug_copy["priority"] = max(0, min(100, priority))
                sug_copy["surface"] = operator_text_to_english(sug_copy.get("surface") or "-")
                normalized_suggestions.append(sug_copy)

        if low_visibility and tier1_failed_tools:
            recovery_title = _txt("suggestion_recover_tier1_title")
            if not any(str(s.get("title") or "").strip().lower() == recovery_title.lower() for s in normalized_suggestions):
                normalized_suggestions.insert(
                    0,
                    {
                        "title": recovery_title,
                        "priority": 35 if discovery_reliability == "CRITICAL" else 50,
                        "surface": "Discovery",
                    },
                )

        normalized_suggestions = sorted(
            normalized_suggestions,
            key=lambda item: _safe_int(item.get("priority"), 0),
            reverse=True,
        )
        rel_copy["related_suggestions"] = normalized_suggestions[:8]
        normalized_map[rel_key] = rel_copy

    return normalized_map


def build_context_aware_suggestions(
    raw_suggestions: list[dict[str, Any]],
    *,
    risk_score: int,
    discovery_reliability: str,
    decision_confidence: str,
    failed_tier_1: list[dict[str, str]],
    failed_tier_2: list[dict[str, str]],
    failed_tier_3: list[dict[str, str]],
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []

    def _clean_url_list(values: Any, *, limit: int = 12) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        if not isinstance(values, list):
            return urls
        for value in values:
            text = str(value or "").strip()
            if not text or not text.startswith(("http://", "https://", "/")):
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            urls.append(text)
            if len(urls) >= limit:
                break
        return urls

    def _clean_artifacts(values: Any, *, limit: int = 12) -> list[str]:
        refs: list[str] = []
        seen: set[str] = set()
        if not isinstance(values, list):
            return refs
        for value in values:
            text = str(value or "").strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            refs.append(text)
            if len(refs) >= limit:
                break
        return refs

    def _clean_evidence_refs(raw: dict[str, Any], evidence_values: list[Any]) -> list[dict[str, Any]]:
        refs: list[dict[str, Any]] = []
        for item in evidence_values[:12]:
            text = str(item or "").strip()
            if text:
                refs.append({"source": "engine", "evidence": text})
        for item in raw.get("contributing_signals", []) if isinstance(raw.get("contributing_signals"), list) else []:
            text = str(item or "").strip()
            if text:
                refs.append({"source": "decision", "signal": text})
        return refs[:16]

    failed_tools = [
        str(item.get("tool") or "").strip().lower()
        for item in (failed_tier_1 + failed_tier_2 + failed_tier_3)
        if str(item.get("tool") or "").strip()
    ]
    key_visibility_failures = [tool for tool in ("katana", "httpx") if tool in failed_tools]
    key_tools_failed = bool(key_visibility_failures)

    for raw in raw_suggestions:
        if not isinstance(raw, dict):
            continue
        if _is_public_content_debug_config_suggestion(raw):
            continue

        title = str(raw.get("title") or "-").strip() or "-"
        surface = str(raw.get("surface") or "-").strip() or "-"
        why = str(raw.get("why") or "").strip()
        tests = raw.get("tests", []) if isinstance(raw.get("tests"), list) else []
        evidence = raw.get("evidence", []) if isinstance(raw.get("evidence"), list) else []

        base_confidence = max(0, min(100, _safe_int(raw.get("priority"), 0)))
        adjusted_confidence = int(base_confidence)
        category = infer_suggestion_category(title, surface, why, tests)
        original_category = category

        visibility_status = "FULL"
        if discovery_reliability == "CRITICAL":
            visibility_status = "LOW_VISIBILITY"
            adjusted_confidence = min(adjusted_confidence, 40)
            if category == "ATTACK":
                category = "VALIDATION"
        elif discovery_reliability in {"LOW", "MEDIUM"}:
            visibility_status = "PARTIAL"
            if category == "ATTACK":
                adjusted_confidence = min(adjusted_confidence, 70)

        if decision_confidence == "Low":
            adjusted_confidence = int(round(adjusted_confidence * 0.70))
            if category == "ATTACK":
                category = "VALIDATION"
            adjusted_confidence = min(adjusted_confidence, 60)

        if key_tools_failed:
            if discovery_reliability == "CRITICAL" and len(key_visibility_failures) >= 2:
                visibility_status = "LOW_VISIBILITY"
            else:
                visibility_status = "PARTIAL"
            if category == "ATTACK":
                category = "VALIDATION"
            adjusted_confidence = min(adjusted_confidence, 65)

        # Non-negotiable: no high-confidence exploitation under CRITICAL or LOW decision confidence.
        if discovery_reliability == "CRITICAL" or decision_confidence == "Low":
            if category == "ATTACK":
                category = "VALIDATION"
            adjusted_confidence = min(adjusted_confidence, 60)

        evidence_text = " ".join(str(item or "").strip().lower() for item in evidence)
        matched_endpoints = raw.get("matched_endpoints", []) if isinstance(raw.get("matched_endpoints"), list) else []
        recommended_urls = _clean_url_list(raw.get("recommended_urls") if isinstance(raw.get("recommended_urls"), list) else matched_endpoints)
        artifact_refs = _clean_artifacts(raw.get("artifact_refs", []))
        evidence_refs = raw.get("evidence_refs") if isinstance(raw.get("evidence_refs"), list) else _clean_evidence_refs(raw, evidence)
        validation_state = str(raw.get("validation_state") or "").strip() or ("confirmed" if recommended_urls else "needs_manual_validation")
        combined_auth_context = " ".join(
            [
                title.lower(),
                surface.lower(),
                why.lower(),
                evidence_text,
                " ".join(str(test or "").strip().lower() for test in tests),
            ]
        )
        clean_single_login_review = bool(
            risk_score < 10
            and "auth" in surface.lower()
            and "auth endpoints=1" in evidence_text
            and "admin panels=" not in evidence_text
            and len(matched_endpoints) <= 1
            and not any(
                token in combined_auth_context
                for token in (
                    "default-login",
                    "default credential evidence",
                    "auth-bypass",
                    "bypass evidence",
                    "rate-limit",
                    "captcha issue",
                    "lockout",
                    "nuclei evidence",
                    "phpmyadmin",
                    "wordpress",
                    "admin export",
                )
            )
        )
        if clean_single_login_review:
            category = "HARDENING"
            base_confidence = min(base_confidence, 55)
            adjusted_confidence = min(max(35, adjusted_confidence), 55)
            title = "Normal login surface hardening review"
            why = (
                "Single normal login surface detected in a low-risk report; treat as access-control "
                "hardening review, not an attack path."
            )
            tests = [
                "confirm expected access-control behavior",
                "review lockout/rate-limit policy only if evidence exists",
                "verify no default-login or bypass evidence is present",
            ]

        adjusted_confidence = max(0, min(100, int(adjusted_confidence)))

        transformed_title = title
        transformed_why = why
        transformed_tests = [str(test or "").strip() for test in tests if str(test or "").strip()]

        if category in {"VALIDATION", "DISCOVERY_RECOVERY"} and original_category == "ATTACK":
            transformed_title = f"Exploit öncesinde olası {surface.lower()} vektörünü doğrula"
            transformed_why = (
                f"Olası {surface.lower()} vektörü tespit edildi, ancak discovery/decision confidence "
                "exploit-first aksiyon için yeterince güçlü değil. Önce kapsamı ve önkoşulları doğrula."
            )
            transformed_tests = [
                soften_suggestion_text(test) for test in transformed_tests
            ]
        elif discovery_reliability in {"CRITICAL", "LOW"} or decision_confidence == "Low":
            transformed_title = soften_suggestion_text(transformed_title)
            transformed_why = soften_suggestion_text(transformed_why)
            transformed_tests = [soften_suggestion_text(test) for test in transformed_tests]

        transformed_title = operator_text_to_english(transformed_title)
        transformed_why = operator_text_to_english(transformed_why)
        transformed_tests = [operator_text_to_english(test) for test in transformed_tests]

        reasoning_parts = [
            f"Risk {max(0, min(100, int(risk_score)))} önceliklendirmeye katkı sağlar",
            f"discovery={discovery_reliability}",
            f"decision_confidence={decision_confidence}",
        ]
        if key_tools_failed:
            reasoning_parts.append(f"kritik araç hatası: {', '.join(key_visibility_failures)}")
        reasoning = "; ".join(reasoning_parts)

        uncertainty_note = ""
        if decision_confidence == "Low":
            uncertainty_note = _txt("suggestion_low_conf_uncertainty")

        normalized.append(
            {
                "title": transformed_title,
                "surface": surface,
                "category": category,
                "original_category": original_category,
                "base_confidence": base_confidence,
                "adjusted_confidence": adjusted_confidence,
                "visibility_status": visibility_status,
                "reasoning": reasoning,
                "why": transformed_why or why or "Gerekçe yok.",
                "tests": transformed_tests,
                "evidence": evidence,
                "uncertainty_note": uncertainty_note,
                "contributing_signals": raw.get("contributing_signals", []) if isinstance(raw.get("contributing_signals"), list) else [],
                "resolved_nuclei": raw.get("resolved_nuclei", {}) if isinstance(raw.get("resolved_nuclei"), dict) else {},
                "matched_endpoints": raw.get("matched_endpoints", []) if isinstance(raw.get("matched_endpoints"), list) else [],
                "recommended_urls": recommended_urls,
                "evidence_refs": evidence_refs,
                "artifact_refs": artifact_refs,
                "validation_state": validation_state,
                "matched_technologies": raw.get("matched_technologies", []) if isinstance(raw.get("matched_technologies"), list) else [],
                "matched_cves": raw.get("matched_cves", []) if isinstance(raw.get("matched_cves"), list) else [],
            }
        )

    if discovery_reliability in {"CRITICAL", "LOW", "MEDIUM"}:
        failed_tier_1_tools = [str(item.get("tool") or "").strip() for item in failed_tier_1 if str(item.get("tool") or "").strip()]
        if failed_tier_1_tools:
            normalized.insert(
                0,
                {
                    "title": _txt("suggestion_recover_tier1_title"),
                    "surface": "Discovery",
                    "category": "DISCOVERY_RECOVERY",
                    "original_category": "DISCOVERY_RECOVERY",
                    "base_confidence": 45,
                    "adjusted_confidence": 35 if discovery_reliability == "CRITICAL" else 50,
                    "visibility_status": "LOW_VISIBILITY" if discovery_reliability == "CRITICAL" else "PARTIAL",
                    "reasoning": _txt("suggestion_recover_tier1_reasoning", tools=", ".join(failed_tier_1_tools)),
                    "why": _txt("suggestion_recover_tier1_why"),
                    "tests": [
                        _txt("suggestion_recover_tier1_test_1"),
                        _txt("suggestion_recover_tier1_test_2"),
                        _txt("suggestion_recover_tier1_test_3"),
                    ],
                    "evidence": failed_tier_1_tools,
                    "uncertainty_note": _txt("suggestion_recover_tier1_uncertainty"),
                    "contributing_signals": [f"tier1_failed={','.join(failed_tier_1_tools)}"],
                    "resolved_nuclei": {},
                    "matched_endpoints": [],
                    "recommended_urls": [],
                    "evidence_refs": [{"source": "pipeline", "evidence": tool} for tool in failed_tier_1_tools],
                    "artifact_refs": [],
                    "validation_state": "needs_manual_validation",
                    "matched_technologies": [],
                    "matched_cves": [],
                },
            )

    if discovery_reliability == "CRITICAL":
        normalized = [
            item
            for item in normalized
            if str(item.get("category") or "").strip().upper() in {"VALIDATION", "DISCOVERY_RECOVERY"}
        ]

    normalized.sort(key=lambda item: _context_aware_suggestion_sort_key(item, discovery_reliability))
    return normalized
