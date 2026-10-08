from __future__ import annotations

from typing import Any

def render_technology_section(context: dict[str, Any]) -> str:
    _html_escape = context.get("_html_escape")
    _render_progressive_table = context.get("_render_progressive_table")
    _render_report_link = context.get("_render_report_link")
    _render_summary_strip_counts = context.get("_render_summary_strip_counts")
    _sanitize_report_url = context.get("_sanitize_report_url")
    report_base_url = context.get("report_base_url")
    tech_labels = context.get("tech_labels")
    technology_fingerprint = context.get("technology_fingerprint")
    waf_detected_count = context.get("waf_detected_count")
    depth_config = context.get("report_depth_config")
    depth_name = str(getattr(depth_config, "name", "balanced"))
    section_html = ""
    # --- Technology Fingerprint ---
    _tf_hdr = "<th>Site</th><th>Server</th><th>Teknolojiler</th><th>WAF</th><th>OWASP İpucu</th>"
    _tf_rows: list[str] = []
    for _tf_item in (technology_fingerprint or []):
        _tf_safe = _sanitize_report_url(_tf_item.get("site", ""), report_base_url)
        if not _tf_safe:
            continue
        _tf_server = _html_escape(_tf_item.get("server", "") or "-")
        _tf_techs = ", ".join(_tf_item.get("technologies", []) or [])
        _tf_waf = ", ".join(_tf_item.get("waf_signals", []) or [])
        _tf_lower = [str(t or "").lower() for t in (_tf_item.get("technologies", []) or [])]
        _tf_owasp: list[str] = []
        if any(t in _tf_lower for t in ["php", "apache httpd"]):
            _tf_owasp.append("A05 patch hygiene")
        if any("graphql" in t for t in _tf_lower):
            _tf_owasp.append("API schema exposure")
        if any(t in _tf_lower for t in ["swagger", "redoc"]):
            _tf_owasp.append("Docs exposure")
        if any(t in _tf_lower for t in ["wordpress", "drupal", "joomla"]):
            _tf_owasp.append("CMS surface")
        if _tf_item.get("waf_signals"):
            _tf_owasp.append("WAF present")
        _tf_rows.append(
            f"<tr><td>{_render_report_link(_tf_safe, report_base_url)}</td>"
            f"<td>{_tf_server}</td>"
            f"<td class=\"wrap-cell\">{_html_escape(_tf_techs or '-')}</td>"
            f"<td>{_html_escape(_tf_waf or '-')}</td>"
            f"<td>{_html_escape('; '.join(_tf_owasp) or '-')}</td></tr>"
        )
    section_html += f"""
    <div class="section report-depth-operator-detail report-depth-body-deep-only" data-depth-body="deep">
        <h2>🧩 Technology Fingerprint</h2>
        <p class="note">Response header/body sinyallerinden çıkarılan teknoloji izi. Framework, server ve WAF/CDN ipuçları.</p>
        <p class="operator-view-note">Operatör triyajı için düzenlenmiş önizleme. Kapsamlı fingerprint detayı için genişletilmiş satırları kullan.</p>
    """
    section_html += _render_summary_strip_counts(
        [
            ("fingerprint’ler", len(_tf_rows)),
            ("unique tech etiketleri", len(tech_labels)),
            ("WAF-detected hosts", waf_detected_count),
        ]
    )
    fingerprint_open = " open" if depth_name == "deep" else ""
    section_html += f'<details class="show-more report-depth-balanced-preview"{fingerprint_open}><summary>Fingerprint önizlemesi</summary>'
    section_html += _render_progressive_table(
        header_html=_tf_hdr,
        rows=_tf_rows,
        empty_row_html='<tr><td colspan="5">Technology fingerprint verisi yok.</td></tr>',
        preview_rows=6,
        summary_label="Tüm fingerprint’leri göster",
    )
    section_html += "</details>"
    section_html += "</div>"
    return section_html
