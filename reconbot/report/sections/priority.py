from __future__ import annotations

from typing import Any

def render_priority_section(context: dict[str, Any]) -> str:
    _html_escape = context.get("_html_escape")
    _render_detail_value = context.get("_render_detail_value")
    _txt = context.get("_txt")
    report_base_url = str(context.get("report_base_url") or "")
    admin_like_for_score = context.get("admin_like_for_score")
    api_like_for_score = context.get("api_like_for_score")
    auth_scoring_summary = context.get("auth_scoring_summary")
    captcha_pages = context.get("captcha_pages")
    debug_like_for_score = context.get("debug_like_for_score")
    docs_like_for_score = context.get("docs_like_for_score")
    ffuf_diverse_response_clusters = context.get("ffuf_diverse_response_clusters")
    ffuf_effective_units = context.get("ffuf_effective_units")
    ffuf_high_value_clusters = context.get("ffuf_high_value_clusters")
    ffuf_overlap_ratio = context.get("ffuf_overlap_ratio")
    ffuf_priority_count = context.get("ffuf_priority_count")
    ffuf_security_relevant_clusters = context.get("ffuf_security_relevant_clusters")
    ffuf_sensitive_marker_clusters = context.get("ffuf_sensitive_marker_clusters")
    login_pages = context.get("login_pages")
    nuclei_findings_count = context.get("nuclei_findings_count")
    priority_items = context.get("priority_items")
    rate_signals = context.get("rate_signals")
    source_control_like_for_score = context.get("source_control_like_for_score") or []
    structural_exposure_groups = context.get("structural_exposure_groups") if isinstance(context.get("structural_exposure_groups"), dict) else {}
    tech_labels = context.get("tech_labels")
    tech_owasp_notes = context.get("tech_owasp_notes")
    upload_like_for_score = context.get("upload_like_for_score")
    waf_labels = context.get("waf_labels")
    section_html = ""

    def _urls(values: Any, *, limit: int = 8) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for value in values if isinstance(values, list) else []:
            text = str(value or "").strip()
            if not text or not text.startswith(("http://", "https://", "/")):
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(text)
            if len(out) >= limit:
                break
        return out

    def _render_url_list(urls: list[str]) -> str:
        if not urls:
            return "<span class='note'>Direct URL evidence yok; bu öncelik genel bağlamdan üretildi.</span>"
        return "<ul class='compact-list'>" + "".join(
            f"<li title=\"{_html_escape(url)}\">{_render_detail_value(url, report_base_url)}</li>"
            for url in urls[:8]
        ) + "</ul>"

    def _render_evidence_refs(item: dict[str, Any]) -> str:
        refs = item.get("evidence_refs") if isinstance(item.get("evidence_refs"), list) else []
        artifacts = item.get("artifact_refs") if isinstance(item.get("artifact_refs"), list) else []
        lines: list[str] = []
        for ref in refs[:8]:
            if isinstance(ref, dict):
                source = str(ref.get("source") or "-").strip()
                category = str(ref.get("category") or ref.get("template_id") or "-").strip()
                status = str(ref.get("status") or "").strip()
                parts = [f"source={source}", f"category={category}"]
                if status:
                    parts.append(f"status={status}")
                lines.append(" | ".join(parts))
        for artifact in artifacts[:8]:
            text = str(artifact or "").strip()
            if text:
                lines.append(f"artifact={text}")
        if not lines:
            return "-"
        return "<ul class='compact-list'>" + "".join(f"<li>{_html_escape(line)}</li>" for line in lines[:10]) + "</ul>"

    def _priority_details(item: dict[str, Any]) -> str:
        urls = _urls(item.get("urls", []))
        validation_state = str(item.get("validation_state") or ("confirmed" if urls else "needs_manual_validation"))
        return (
            f'<details><summary class="row-details-toggle">Referansları göster</summary>'
            f'<dl class="suggestion-detail">'
            f'<dt>İlgili URL’ler:</dt><dd>{_render_url_list(urls)}</dd>'
            f'<dt>Kanıt / kaynak:</dt><dd>{_render_evidence_refs(item)}</dd>'
            f'<dt>Validation state:</dt><dd>{_html_escape(validation_state)}</dd>'
            f'<dt>Next safe validation step:</dt><dd>{_html_escape(str(item.get("test_first") or "Manual validation required"))}</dd>'
            f'<dt>Not:</dt><dd>Bu öncelik not exploit proof; observed surface veya korelasyon sinyalidir.</dd>'
            f'</dl></details>'
        )
    # --- Attack Priority Engine ---
    section_html += f"""
    <div class="section report-depth-body-deep-only" data-depth-body="deep">
        <h2 id="priority">{_html_escape(_txt("priority_engine_title"))}</h2>
        <p class="note">
        {_html_escape(_txt("priority_engine_note"))}
        </p>
        <table>
            <tr>
                <th>#</th>
                <th>Yüzey</th>
                <th>Sayı</th>
                <th>Öncelik</th>
                <th>Neden önce?</th>
                <th>İlk test</th>
                <th>Referanslar</th>
            </tr>
    """

    if not priority_items:
        section_html += """
            <tr>
                <td colspan="7">""" + _html_escape(_txt("priority_engine_empty")) + """</td>
            </tr>
        """
    else:
        for idx, item in enumerate(priority_items[:8], start=1):
            section_html += f"""
            <tr>
                <td><strong>{idx}</strong></td>
                <td><strong>{_html_escape(item.get('label', 'Unknown'))}</strong></td>
                <td>{int(item.get('count', 0))}</td>
                <td>{int(item.get('priority_score', 0))} / 100</td>
                <td>{_html_escape(item.get('why', ''))}</td>
                <td>{_html_escape(item.get('test_first', ''))}</td>
                <td>{_priority_details(item)}</td>
            </tr>
            """

    section_html += """
        </table>
    </div>
    """

    # --- OWASP / Attack Surface Intelligence ---
    attack_surface_rows = [
        ("Admin panelleri", len(admin_like_for_score), "A01 Broken Access Control / yönetim paneli yüzeyi"),
        (
            "Authentication endpoint’leri",
            int(auth_scoring_summary.get("canonical_login_flows_count", 0) or 0)
            + int(auth_scoring_summary.get("canonical_admin_auth_flows_count", 0) or 0)
            + int(auth_scoring_summary.get("canonical_xmlrpc_count", 0) or 0)
            + int(auth_scoring_summary.get("canonical_oauth_sso_count", 0) or 0),
            "A07 Identification & Authentication Failures yüzeyi (kanonik auth flow aileleri)",
        ),
        ("API / GraphQL / Actuator", len(api_like_for_score), "API keşfi, mass assignment ve exposure yüzeyi"),
        ("Upload endpoint’leri", len(upload_like_for_score), "Upload yüzeyi bulundu; zafiyet kanıtı değildir, manuel doğrulama gerektirir."),
        ("Debug / test endpoint’leri", len(debug_like_for_score), "Debug / test / internal / dev exposure yüzeyi"),
        ("Source-control yüzeyi", len(source_control_like_for_score), "Confirmed repository metadata surface; leaked content/manual validation gerekir"),
        (
            "Config/debug structural evidence",
            sum(len(structural_exposure_groups.get(key, []) or []) for key in ("config", "debug_console", "runtime")),
            "Config/debug/runtime observed surface; response body ve auth gereksinimi manuel doğrulanmalıdır",
        ),
        ("Dokümantasyon / dev sayfaları", len(docs_like_for_score), "Swagger / docs / dev sayfaları / bilgi sızıntısı yüzeyi"),
        ("Login adayları", len(login_pages), "Login adayları / brute-force / auth analizi yüzeyi"),
        ("Captcha sayfaları", len(captcha_pages), "Captcha enforcement ve tutarlılık analizi yüzeyi"),
        ("Rate-limit sinyalleri", len(rate_signals), "429 / Retry-After / X-RateLimit-* sinyalleri"),
        ("Teknoloji sinyalleri", len(tech_labels), ", ".join(tech_labels) if tech_labels else "Framework/server sinyali yok"),
        ("WAF / CDN sinyalleri", len(waf_labels), ", ".join(waf_labels) if waf_labels else "WAF/CDN sinyali yok"),
        (
            "FFUF kalite aileleri",
            ffuf_priority_count,
            (
                "Kalite odaklı FFUF katkısı "
                f"(units={ffuf_effective_units}, overlap={ffuf_overlap_ratio:.2f}, high_value={ffuf_high_value_clusters}, sensitive={ffuf_sensitive_marker_clusters}, security_query={ffuf_security_relevant_clusters}, diversity={ffuf_diverse_response_clusters})"
            ),
        ),
        ("Nuclei bulguları", nuclei_findings_count, "Otomatik zafiyet bulguları"),
    ]

    tech_notes_html = "".join(f"<li>{_html_escape(note)}</li>" for note in tech_owasp_notes) or '<li>Teknoloji bazlı ek OWASP notu üretilmedi.</li>'
    section_html += f"""
    <div class="section report-depth-body-deep-only" data-depth-body="deep">
        <h2>🔥 OWASP / Attack Surface Intelligence</h2>
        <p class="note">
        Bu bölüm hedefin saldırı yüzeyini hızlı özetler. OWASP bakış açısıyla hangi alanların önce incelenmesi gerektiğini gösterir.
        </p>
        <p class="note">
        Not (içsel): Auth-related score, kanonik dedupe edilmiş auth flow ailelerini kullanır; ham auth profiler adayları detay için tutulur.
        </p>
        <p class="note"><strong>Teknolojiye duyarlı notlar:</strong></p>
        <ul>
            {tech_notes_html}
        </ul>
        <table>
            <tr>
                <th>Kategori</th>
                <th>Sayı</th>
                <th>OWASP / Anlam</th>
                <th>İlgili kanıt / URL</th>
            </tr>
    """

    for label, count, meaning in attack_surface_rows:
        label_low = label.lower()
        row_urls: list[str] = []
        if "admin" in label_low:
            row_urls = _urls(admin_like_for_score)
        elif "authentication" in label_low or "login" in label_low:
            row_urls = _urls(login_pages or auth_scoring_summary.get("login_urls", []))
        elif "api" in label_low:
            row_urls = _urls(api_like_for_score)
        elif "upload" in label_low:
            row_urls = _urls(upload_like_for_score)
        elif "debug" in label_low or "config" in label_low:
            row_urls = _urls(
                (debug_like_for_score or [])
                + (structural_exposure_groups.get("config", []) or [])
                + (structural_exposure_groups.get("debug_console", []) or [])
                + (structural_exposure_groups.get("runtime", []) or [])
            )
        elif "source-control" in label_low:
            row_urls = _urls(source_control_like_for_score)
        section_html += f"""
        <tr>
            <td><strong>{label}</strong></td>
            <td>{count}</td>
            <td>{meaning}</td>
            <td>{_render_url_list(row_urls)}</td>
        </tr>
        """

    section_html += """
        </table>
    </div>
    """
    return section_html
