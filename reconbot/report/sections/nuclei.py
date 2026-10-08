from __future__ import annotations

from typing import Any

def render_nuclei_findings_section(context: dict[str, Any]) -> str:
    _render_nuclei_summary_block = context.get("_render_nuclei_summary_block")
    nuclei_summary_data = context.get("nuclei_summary_data")
    _render_nuclei_severity_sections = context.get("_render_nuclei_severity_sections")
    nuclei_grouped_templates = context.get("nuclei_grouped_templates")
    report_base_url = context.get("report_base_url")
    nuclei_empty_message = context.get("nuclei_empty_message")
    _render_nuclei_raw_table = context.get("_render_nuclei_raw_table")
    nuclei_report_entries = context.get("nuclei_report_entries")
    _html_escape = context.get("_html_escape")
    _txt = context.get("_txt")
    nuclei_state_note_html = context.get("nuclei_state_note_html")
    _safe_int = context.get("_safe_int")
    depth_config = context.get("report_depth_config")
    nuclei_preview = int(getattr(depth_config, "max_nuclei_preview", 12))
    depth_name = str(getattr(depth_config, "name", "balanced"))
    section_html = ""
    nuclei_summary_html = _render_nuclei_summary_block(nuclei_summary_data)
    nuclei_grouped_html = _render_nuclei_severity_sections(
        nuclei_grouped_templates,
        base_url=report_base_url,
        endpoint_preview_count=2 if depth_name == "summary" else 3,
        preview_templates_per_group=2 if depth_name == "summary" else (0 if depth_name == "deep" else 4),
        empty_message=nuclei_empty_message,
    )
    nuclei_raw_table_html = _render_nuclei_raw_table(
        nuclei_report_entries,
        base_url=report_base_url,
        empty_message=nuclei_empty_message,
        preview_rows=nuclei_preview,
    )
    raw_open = " open" if bool(getattr(depth_config, "expand_raw_by_default", False)) else ""

    section_html += f"""
    <div class="section" id="findings">
        <h2>⚠ Potansiyel Zafiyetler (Doğrulama Gerekli)</h2>
        <p class="note">
        {_html_escape(_txt("nuclei_operator_note"))}
        </p>
        <p class="operator-view-note">Aşağıdaki gruplanmış triyaj kartları birincil operatör görünümüdür. Ham eşleşmeler kapsamlı template seviyesinde çıktı olarak erişilebilir kalır.</p>
        {nuclei_state_note_html}
        {nuclei_summary_html}
        <h3 class="nuclei-primary-heading">Gruplanmış ve Önceliklendirilmiş Triyaj (Birincil)</h3>
        <div class="nuclei-grouped-findings">
            {nuclei_grouped_html}
        </div>
        <details class="show-more report-depth-evidence-detail report-depth-audit-only"{raw_open}>
            <summary>Tüm ham eşleşmeler ({_safe_int(nuclei_summary_data.get("total_findings"), 0)})</summary>
            <p class="note">Teknik inceleme için ham template çıktısı. Dengeli mod yukarıdaki gruplanmış kartları önceliklendirir; Derin mod audit çalışması için bu kanıtı açar.</p>
            {nuclei_raw_table_html}
        </details>
    </div>
    """
    return section_html
