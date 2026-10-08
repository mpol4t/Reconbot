from __future__ import annotations

from typing import Any

from reconbot.report.suggestions import operator_text_to_english as _localize_report_text

def render_cve_sections(context: dict[str, Any]) -> str:
    _html_escape = context.get("_html_escape")
    _render_progressive_table = context.get("_render_progressive_table")
    _render_score_pill = context.get("_render_score_pill")
    _render_summary_strip_counts = context.get("_render_summary_strip_counts")
    _render_detail_value = context.get("_render_detail_value")
    _truncate_text = context.get("_truncate_text")
    _txt = context.get("_txt")
    report_base_url = str(context.get("report_base_url") or "")
    depth_config = context.get("report_depth_config")
    cve_preview = int(getattr(depth_config, "max_cve_preview", 5))
    cve_details_open = " open" if str(getattr(depth_config, "name", "balanced")) == "deep" else ""
    cve_enrichment = context.get("cve_enrichment")
    section_html = ""
    empty_state = "Ürün/sürüm fingerprint’i yeterli olmadığı için CVE adayı üretilmedi."

    def _dedupe_urls(values: Any, *, limit: int = 8) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for value in values if isinstance(values, list) else []:
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

    surface_url_map = {
        "Upload": _dedupe_urls(context.get("upload_like_for_score", [])),
        "Auth/Admin": _dedupe_urls((context.get("auth_like_for_score", []) or []) + (context.get("admin_like_for_score", []) or [])),
        "API": _dedupe_urls(context.get("api_like_for_score", [])),
        "Docs/Dev": _dedupe_urls(context.get("docs_like_for_score", [])),
        "Debug/Test": _dedupe_urls(context.get("debug_like_for_score", [])),
        "PHP Stack": _dedupe_urls(context.get("upload_like_for_score", []) or []),
        "Apache Stack": _dedupe_urls(
            (context.get("debug_like_for_score", []) or [])
            + (context.get("docs_like_for_score", []) or [])
            + (context.get("admin_like_for_score", []) or [])
        ),
        "Nginx Stack": _dedupe_urls((context.get("api_like_for_score", []) or []) + (context.get("docs_like_for_score", []) or [])),
    }

    def _render_url_list(urls: list[str]) -> str:
        if not urls:
            return "<span class='note'>Direct URL evidence yok; bu korelasyon genel teknoloji/yüzey bağlamından üretildi.</span>"
        items = []
        for url in urls[:8]:
            items.append(
                f"<li title=\"{_html_escape(url)}\">{_render_detail_value(url, report_base_url)}</li>"
            )
        return f"<ul class='compact-list'>{''.join(items)}</ul>"

    def _nvd_link(cve_id: Any) -> str:
        cid = str(cve_id or "").strip().upper()
        if not cid.startswith("CVE-"):
            return "-"
        href = f"https://nvd.nist.gov/vuln/detail/{cid}"
        return f'<a class="report-link" href="{_html_escape(href)}" target="_blank">{_html_escape(cid)} / NVD</a>'

    def _local_evidence_html(product: Any, version: Any, evidence: Any, surfaces: list[str]) -> str:
        urls: list[str] = []
        for surface in surfaces:
            for url in surface_url_map.get(surface, []):
                if url not in urls:
                    urls.append(url)
        product_text = str(product or "-").strip() or "-"
        version_text = str(version or "-").strip() or "-"
        evidence_text = str(evidence or "").strip()
        parts = [
            f"<dt>Ürün/sürüm sinyali:</dt><dd>{_html_escape(product_text)} {_html_escape(version_text)}</dd>",
            f"<dt>Kaynak/kanıt:</dt><dd>{_html_escape(_truncate_text(evidence_text, 220) or '-')}</dd>",
            f"<dt>İlişkili yüzey:</dt><dd>{_html_escape(', '.join(surfaces) or '-')}</dd>",
            f"<dt>İlgili yerel kanıt:</dt><dd>{_render_url_list(urls)}</dd>",
            "<dt>Doğrulama notu:</dt><dd>CVE korelasyonu kesin zafiyet kanıtı değildir; ürün/sürüm ve etkilenen özellik manuel doğrulanmalıdır.</dd>",
        ]
        return "".join(parts)
    # --- CVE Enrichment ---
    cve_query_count = int(cve_enrichment.get("query_count", 0)) if isinstance(cve_enrichment, dict) else 0
    cve_matches = cve_enrichment.get("matches", []) if isinstance(cve_enrichment, dict) else []

    # --- CVE + Attack Surface Correlation (derived for reporting) ---
    cve_surface_correlations: list[dict[str, Any]] = []
    for item in cve_matches[:10]:
        for cve in (item.get("cves", []) or [])[:5]:
            reasons = [str(r or "") for r in (cve.get("relevance_reasons", []) or [])]
            correlated_surfaces: list[str] = []

            for reason in reasons:
                low = reason.lower()
                if "upload surface" in low and "Upload" not in correlated_surfaces:
                    correlated_surfaces.append("Upload")
                if "auth/admin surface" in low and "Auth/Admin" not in correlated_surfaces:
                    correlated_surfaces.append("Auth/Admin")
                if "api surface" in low and "API" not in correlated_surfaces:
                    correlated_surfaces.append("API")
                if "docs/dev surface" in low and "Docs/Dev" not in correlated_surfaces:
                    correlated_surfaces.append("Docs/Dev")
                if "debug/test surface" in low and "Debug/Test" not in correlated_surfaces:
                    correlated_surfaces.append("Debug/Test")
                if "php stack" in low and "PHP Stack" not in correlated_surfaces:
                    correlated_surfaces.append("PHP Stack")
                if "apache stack" in low and "Apache Stack" not in correlated_surfaces:
                    correlated_surfaces.append("Apache Stack")
                if "nginx stack" in low and "Nginx Stack" not in correlated_surfaces:
                    correlated_surfaces.append("Nginx Stack")

            cve_surface_correlations.append(
                {
                    "cve_id": cve.get("cve_id", "-"),
                    "relevance_score": int(cve.get("relevance_score", 0) or 0),
                    "surfaces": correlated_surfaces,
                    "reasons": reasons,
                    "product": item.get("product", "-"),
                    "version": item.get("version", "-"),
                    "description": cve.get("description", "") or "",
                }
            )

    cve_surface_correlations = sorted(
        cve_surface_correlations,
        key=lambda item: int(item.get("relevance_score", 0)),
        reverse=True,
    )

    cve_corr_surfaces_by_id: dict[str, set[str]] = {}
    for corr in cve_surface_correlations:
        cid = str(corr.get("cve_id") or "").strip()
        if not cid:
            continue
        bucket = cve_corr_surfaces_by_id.setdefault(cid, set())
        for surf in (corr.get("surfaces", []) or []):
            surf_text = str(surf or "").strip()
            if surf_text:
                bucket.add(surf_text)

    _cve_hdr = "<th>Ürün / Versiyon</th><th>En Yüksek Alaka</th><th>İlişkili Yüzey</th><th>Açıklama Önizlemesi</th><th>Detaylar</th>"
    _cve_row_weighted: list[tuple[int, str]] = []
    cve_total_entries = 0
    for _cve_item in (cve_matches or []):
        if not isinstance(_cve_item, dict):
            continue
        _cve_prod = _html_escape(_cve_item.get("product", "-") or "-")
        _cve_ver = _html_escape(_cve_item.get("version", "-") or "-")
        _cve_kw = _html_escape(_cve_item.get("keyword", "-") or "-")
        _cve_ev = _html_escape(_truncate_text(_cve_item.get("evidence", ""), 90))
        _cve_list = _cve_item.get("cves", []) if isinstance(_cve_item.get("cves"), list) else []
        cve_total_entries += len(_cve_list)
        _top_cve = _cve_list[0] if _cve_list else {}
        _top_cve_id = _html_escape(_top_cve.get("cve_id", "-") or "-")
        _top_rel = int(_top_cve.get("relevance_score", 0) or 0) if isinstance(_top_cve, dict) else 0
        _top_desc_raw = str(_top_cve.get("description", "") or "") if isinstance(_top_cve, dict) else ""
        _top_desc_short = _html_escape(_truncate_text(_top_desc_raw, 130) or "-")
        _top_surfaces_list = sorted(cve_corr_surfaces_by_id.get(str(_top_cve.get("cve_id") or ""), set()))
        if not _top_surfaces_list and isinstance(_top_cve, dict):
            _top_reasons = [str(r or "") for r in (_top_cve.get("relevance_reasons", []) or [])]
            if _top_reasons:
                _top_surfaces_list = [_truncate_text(", ".join(_top_reasons), 80)]
        _top_surfaces = _html_escape(", ".join(_top_surfaces_list) or "-")
        _top_surfaces_raw = [str(item) for item in _top_surfaces_list]

        _cve_list_details = ""
        if _cve_list:
            _cve_lis = []
            for c in _cve_list:
                if not isinstance(c, dict):
                    continue
                _cid = _html_escape(c.get("cve_id", "-") or "-")
                _crel = int(c.get("relevance_score", 0) or 0)
                _cdesc = _html_escape(_truncate_text(c.get("description", ""), 120))
                _cve_lis.append(
                    f"<li><strong>{_cid}</strong> {_render_score_pill(_crel)}<br>"
                    f"<span class='note'>{_cdesc}</span><br>"
                    f"<span class='note'>External reference: {_nvd_link(c.get('cve_id'))}</span></li>"
                )
            _cve_items_html = "".join(_cve_lis) or '<li class="note">CVE kaydı yok</li>'
            _cve_list_details = (
                f"<dt>Eşleşen CVE’ler:</dt><dd><ul class='compact-list'>{_cve_items_html}</ul></dd>"
            )
        _top_reason_preview = ""
        if isinstance(_top_cve, dict):
            _reasons = [str(r) for r in (_top_cve.get("relevance_reasons", []) or []) if str(r or "").strip()]
            if _reasons:
                _top_reason_preview = f"<dt>En önemli gerekçeler:</dt><dd>{_html_escape(_truncate_text(_localize_report_text('; '.join(_reasons)), 220))}</dd>"
        _cve_details_html = (
            f'<details class="cve-detail-card"><summary class="row-details-toggle">Detayları göster</summary>'
            f'<dl class="suggestion-detail cve-detail-block">'
            f'<dt>Keyword:</dt><dd>{_cve_kw}</dd>'
            f'<dt>Kanıt:</dt><dd>{_cve_ev or "-"}</dd>'
            f"<dt>En Öncelikli CVE:</dt><dd>{_top_cve_id}<br><span class='note'>External reference: {_nvd_link(_top_cve.get('cve_id') if isinstance(_top_cve, dict) else '')}</span></dd>"
            f"{_local_evidence_html(_cve_item.get('product'), _cve_item.get('version'), _cve_item.get('evidence'), _top_surfaces_raw)}"
            f"{_top_reason_preview}"
            f"{_cve_list_details}"
            f"</dl></details>"
        )

        _cve_row_weighted.append(
            (
                _top_rel,
                f"<tr><td><strong>{_cve_prod}</strong><br><span class=\"note\">{_cve_ver}</span></td>"
                f"<td>{_render_score_pill(_top_rel)}</td>"
                f"<td class=\"wrap-cell\">{_top_surfaces}</td>"
                f"<td class=\"wrap-cell\"><span class=\"note\">{_top_desc_short}</span></td>"
                f"<td>{_nvd_link(_top_cve.get('cve_id') if isinstance(_top_cve, dict) else '')}</td></tr>"
                f"<tr class=\"cve-detail-row\"><td colspan=\"5\">{_cve_details_html}</td></tr>",
            )
        )

    _cve_rows = [row for _rel, row in sorted(_cve_row_weighted, key=lambda item: item[0], reverse=True)]
    section_html += f"""
    <div class="report-depth-enrichment-detail report-depth-body-balanced-deep" data-depth-body="balanced deep">
    <div class="section" id="cve-enrichment">
        <h2>🧬 CVE Zenginleştirme</h2>
        <p class="report-depth-explainer"><strong>Bu ne anlama geliyor?</strong> CVE zenginleştirme bir triyaj ipucudur, kanıt değildir. ReconBot olası CVE adaylarını bulmak için gözlenen teknoloji string’lerini kullanır. Herhangi bir CVE’yi uygulanabilir kabul etmeden önce tam ürün/versiyon ve exploit önkoşullarını doğrula.</p>
        <p class="note">{_html_escape(_txt("cve_enrichment_note"))}</p>
        <p class="operator-view-note">Dengeli mod ürün/versiyon, alaka, etkilenen yüzey ve kısa doğrulama uyarısı gösterir. Derin mod tam eşleşen CVE detayını ve korelasyon gerekçelerini açar.</p>
    """
    section_html += _render_summary_strip_counts(
        [
            ("queries", cve_query_count),
            ("groups", len(cve_matches)),
            ("matched CVEs", cve_total_entries),
        ]
    )
    section_html += f'<details class="show-more"{cve_details_open}><summary>CVE zenginleştirme önizlemesi</summary>'
    section_html += _render_progressive_table(
        header_html=_cve_hdr,
        rows=_cve_rows,
        empty_row_html=f'<tr><td colspan="5">{_html_escape(empty_state)}</td></tr>',
        preview_rows=cve_preview,
        summary_label="Tüm CVE eşleşmelerini göster",
    )
    section_html += "</details>"
    section_html += "</div>"

    # --- CVE + Attack Surface Correlation ---
    _corr_hdr = "<th>CVE</th><th>Ürün / Versiyon</th><th>Alaka</th><th>İlişkili Yüzey</th><th>Açıklama önizlemesi</th><th>Detaylar</th>"
    _corr_rows: list[str] = []
    for _corr_item in cve_surface_correlations:
        _corr_cve_id = _html_escape(_corr_item.get("cve_id", "-") or "-")
        _corr_prod = _html_escape(_corr_item.get("product", "-") or "-")
        _corr_ver = _html_escape(_corr_item.get("version", "-") or "-")
        _corr_desc_raw = str(_corr_item.get("description", "") or "")
        _corr_desc_short = _html_escape(_truncate_text(_corr_desc_raw, 100))
        _corr_rel = int(_corr_item.get("relevance_score", 0) or 0)
        _corr_surfaces = _html_escape(", ".join(_corr_item.get("surfaces", []) or []) or "-")
        _corr_surface_raw = [str(item or "").strip() for item in (_corr_item.get("surfaces", []) or []) if str(item or "").strip()]
        _corr_reasons = [str(reason or "").strip() for reason in (_corr_item.get("reasons", []) or []) if str(reason or "").strip()]
        _corr_reason_html = (
            "<ul class='compact-list'>"
            + "".join(f"<li>{_html_escape(_truncate_text(_localize_report_text(reason), 120))}</li>" for reason in _corr_reasons[:10])
            + "</ul>"
        ) if _corr_reasons else "<p class='note'>Gerekçe detayı yok.</p>"
        _corr_details = (
            f'<details class="cve-detail-card"><summary class="row-details-toggle">Detayları göster</summary>'
            f"<dl class='suggestion-detail cve-detail-block'>"
            f"<dt>Açıklama (tam önizleme):</dt><dd>{_html_escape(_truncate_text(_corr_desc_raw, 400) or '-')}</dd>"
            f"<dt>CVE referansı:</dt><dd>{_nvd_link(_corr_item.get('cve_id'))}</dd>"
            f"{_local_evidence_html(_corr_item.get('product'), _corr_item.get('version'), '', _corr_surface_raw)}"
            f"<dt>Korelasyon gerekçeleri:</dt><dd>{_corr_reason_html}</dd>"
            f"</dl></details>"
        )
        _corr_rows.append(
            f"<tr><td><strong>{_corr_cve_id}</strong></td>"
            f"<td>{_corr_prod}<br><span class=\"note\">{_corr_ver}</span></td>"
            f"<td>{_render_score_pill(_corr_rel)}</td>"
            f"<td>{_corr_surfaces}</td>"
            f"<td class=\"wrap-cell\"><span class=\"note\">{_corr_desc_short}</span></td>"
            f"<td>{_nvd_link(_corr_item.get('cve_id'))}</td></tr>"
            f"<tr class=\"cve-detail-row\"><td colspan=\"6\">{_corr_details}</td></tr>"
        )
    section_html += """
    <div class="section">
        <h2>🔬 CVE + Saldırı Yüzeyi Korelasyonu</h2>
        <p class="report-depth-explainer"><strong>Neden önemli?</strong> Bu bölüm olası CVE adaylarını gözlenen yüzeylerle ilişkilendirir. Eşleşme doğrulama önceliğini artırır; ancak etkilenen ürün/versiyon ve erişilebilir koşul güvenli biçimde doğrulanana kadar exploitability kanıtlamaz.</p>
        <p class="note">""" + _html_escape(_txt("cve_correlation_note")) + """</p>
        <p class="operator-view-note">Dengeli mod korelasyon önizlemesini inceleme için kapalı tutar. Derin mod detaylı gerekçeleri, kanıt string’lerini ve satır seviyesinde eşlemeyi açar.</p>
    """
    section_html += _render_summary_strip_counts(
        [
            ("correlations", len(cve_surface_correlations)),
            ("high relevance (>=75)", len([i for i in cve_surface_correlations if int(i.get("relevance_score", 0) or 0) >= 75])),
        ]
    )
    section_html += f'<details class="show-more"{cve_details_open}><summary>CVE korelasyon önizlemesi</summary>'
    section_html += _render_progressive_table(
        header_html=_corr_hdr,
        rows=_corr_rows,
        empty_row_html=f'<tr><td colspan="6">{_html_escape(_txt("cve_correlation_empty"))}</td></tr>',
        preview_rows=cve_preview,
        summary_label="Tüm CVE korelasyonlarını göster",
    )
    section_html += "</details>"
    section_html += "</div>"
    section_html += "</div>"
    return section_html
