from __future__ import annotations

from typing import Any

def render_surface_section(context: dict[str, Any]) -> str:
    _html_escape = context.get("_html_escape")
    _render_representative_endpoint = context.get("_render_representative_endpoint")
    _render_summary_strip_counts = context.get("_render_summary_strip_counts")
    _sanitize_report_url = context.get("_sanitize_report_url")
    admin_like = context.get("admin_like")
    api_like = context.get("api_like")
    auth_like = context.get("auth_like")
    checks_results = context.get("checks_results")
    debug_like = context.get("debug_like")
    docs_like = context.get("docs_like")
    endpoint_analysis = context.get("endpoint_analysis")
    ffuf_effective_units = context.get("ffuf_effective_units")
    ffuf_overlap_ratio = context.get("ffuf_overlap_ratio")
    ffuf_priority_count = context.get("ffuf_priority_count")
    normalized_cluster_insights = context.get("normalized_cluster_insights")
    report_base_url = context.get("report_base_url")
    representative_cluster_map = context.get("representative_cluster_map")
    upload_like = context.get("upload_like")
    section_html = ""
    # --- Endpoint Analysis Summary ---
    analysis_raw_count = int(endpoint_analysis.get("raw_discovery_count", 0) or 0)
    analysis_clustered_count = int(endpoint_analysis.get("clustered_count", 0) or 0)
    analysis_suppressed_count = int(endpoint_analysis.get("suppressed_noise_count", 0) or 0)
    analysis_representatives = endpoint_analysis.get("representative_endpoints", []) if isinstance(endpoint_analysis.get("representative_endpoints"), list) else []
    analysis_suspicious = checks_results.get("suspicious_families", []) if isinstance(checks_results.get("suspicious_families"), list) else endpoint_analysis.get("suspicious_families", [])
    analysis_duplicate = checks_results.get("duplicate_families", []) if isinstance(checks_results.get("duplicate_families"), list) else endpoint_analysis.get("duplicate_families", [])
    analysis_note = (
        "Classified buckets source: checks_results.classified_endpoints (full canonical inventory). "
        "Endpoint-analysis reportworthy/representative data is overlay-only for cluster insights."
    )

    section_html += f"""
    <div class="section report-depth-body-deep-only" data-depth-body="deep" id="surface">
      <h2>📌 Endpoint Analysis Summary</h2>
      <p class="operator-view-note">Summary-first operator view. Expand the detail block for full metric coverage and tuning signals.</p>
      {_render_summary_strip_counts([
          ("clusters", analysis_clustered_count),
          ("suppressed", analysis_suppressed_count),
          ("representatives", len(analysis_representatives)),
          ("suspicious families", len(analysis_suspicious) if isinstance(analysis_suspicious, list) else 0),
      ])}
      <details class="show-more">
        <summary style="font-size:15px; font-weight:600; color:var(--accent2);">Show endpoint analysis metrics</summary>
        <p class="note" style="margin:8px 0;">{_html_escape(analysis_note)}</p>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Raw discovery count</td><td>{analysis_raw_count}</td></tr>
            <tr><td>Clustered (active) count</td><td>{analysis_clustered_count}</td></tr>
            <tr><td>Suppressed noise count</td><td>{analysis_suppressed_count}</td></tr>
            <tr><td>Representative endpoints</td><td>{len(analysis_representatives)}</td></tr>
            <tr><td>Suspicious families</td><td>{len(analysis_suspicious) if isinstance(analysis_suspicious, list) else 0}</td></tr>
            <tr><td>Duplicate families</td><td>{len(analysis_duplicate) if isinstance(analysis_duplicate, list) else 0}</td></tr>
            <tr><td>Cluster insights</td><td>{len(normalized_cluster_insights)}</td></tr>
            <tr><td>FFUF normalized families</td><td>{ffuf_priority_count}</td></tr>
            <tr><td>FFUF effective units</td><td>{ffuf_effective_units}</td></tr>
            <tr><td>FFUF overlap ratio</td><td>{ffuf_overlap_ratio:.2f}</td></tr>
        </table>
      </details>
    </div>
    """

    suspicious_insight_rows = ""
    for cluster in normalized_cluster_insights[:20]:
        risk_signals = ", ".join(cluster.get("risk_signals", [])[:4]) or "-"
        notes = "; ".join(cluster.get("explanatory_notes", [])[:2]) or "-"
        representative_url = str(cluster.get("representative_url") or "")
        suspicious_insight_rows += f"""
        <tr>
            <td>{_render_representative_endpoint(representative_url, report_base_url, cluster, preview_variants=5)}</td>
            <td>{_html_escape(cluster.get("family_type", "-"))}</td>
            <td>{int(cluster.get("variants_count", 0) or 0)}</td>
            <td>{_html_escape(risk_signals)}</td>
            <td>{_html_escape(notes)}</td>
        </tr>
        """

    if not suspicious_insight_rows:
        suspicious_insight_rows = """
        <tr>
            <td colspan="5">Cluster insight verisi bulunamadı.</td>
        </tr>
        """

    section_html += f"""
    <div class="section report-depth-body-deep-only" data-depth-body="deep">
      <h2>🧭 Representative Families / Variants</h2>
      <p class="operator-view-note">Family-level preview reduces URL wall noise. Expand for full representative and variant context.</p>
      {_render_summary_strip_counts([
          ("families", len(normalized_cluster_insights)),
          ("FFUF quality families", ffuf_priority_count),
      ])}
      <details class="show-more">
        <summary style="font-size:15px; font-weight:600; color:var(--accent2);">Show family detail table</summary>
        <table>
            <tr>
                <th>Representative</th>
                <th>Family</th>
                <th>Variants</th>
                <th>Risk Signals</th>
                <th>Notes</th>
            </tr>
            {suspicious_insight_rows}
        </table>
      </details>
    </div>
    """

    # --- Sensitive / Classified Endpoints (priority section) ---
    def _render_endpoint_list(items: list[str], empty_text: str = "-") -> str:
        rendered_items: list[str] = []
        for raw_url in items:
            safe_url = _sanitize_report_url(raw_url, report_base_url)
            if not safe_url:
                continue
            cluster = representative_cluster_map.get(safe_url)
            rendered_items.append(
                f'<li>{_render_representative_endpoint(safe_url, report_base_url, cluster)}</li>'
            )

        if not rendered_items:
            return f'<li class="note">{_html_escape(empty_text)}</li>'

        return "".join(rendered_items)

    def _render_endpoint_bucket(title: str, items: list[str], empty_text: str, preview: int = 3) -> str:
        rendered_items: list[str] = []
        for raw_url in items:
            safe_url = _sanitize_report_url(raw_url, report_base_url)
            if not safe_url:
                continue
            cluster = representative_cluster_map.get(safe_url)
            rendered_items.append(_render_representative_endpoint(safe_url, report_base_url, cluster))
        count = len(rendered_items)
        count_badge = f'<span class="stat-badge"><span class="val">{count}</span> found</span>'
        if not rendered_items:
            return f'<div style="margin-bottom:12px;"><h3>{_html_escape(title)} {count_badge}</h3><p class="note">{_html_escape(empty_text)}</p></div>'
        preview_items = rendered_items[:preview]
        rest_items = rendered_items[preview:]
        preview_html = "<ul class='compact-list'>" + "".join(f"<li>{x}</li>" for x in preview_items) + "</ul>"
        rest_html = ""
        if rest_items:
            rest_html = (
                f'<details class="show-more"><summary>Show {len(rest_items)} more</summary>'
                f"<ul class='compact-list'>{''.join(f'<li>{x}</li>' for x in rest_items)}</ul></details>"
            )
        return f'<div style="margin-bottom:16px;"><h3 style="margin-bottom:4px;">{_html_escape(title)} {count_badge}</h3>{preview_html}{rest_html}</div>'

    classified_empty_note = ""
    if not any((admin_like, auth_like, api_like, upload_like, debug_like, docs_like)):
        classified_empty_note = (
            "<p class=\"note\">"
            f"{_html_escape('Doğrulanmış admin/auth/api/upload/debug/docs endpoint’i oluşmadı.')}"
            "</p>"
        )

    section_html += f"""
    <div class="section report-depth-body-deep-only" data-depth-body="deep">
        <h2 id="surface-classified">🎯 Sensitive / Classified Endpoints</h2>
        <p class="operator-view-note">Curated operator view. Each bucket shows only top endpoints by default; expand for the rest.</p>
        {_render_summary_strip_counts([
            ("admin", len(admin_like)),
            ("auth", len(auth_like)),
            ("api", len(api_like)),
            ("upload", len(upload_like)),
            ("debug/test", len(debug_like)),
            ("docs/dev", len(docs_like)),
        ])}
        <p class="note">
        Tam sınıflandırılmış endpoint envanteri (canonical classified_endpoints). Her kategori ilk {3} endpoint'i gösterir, kalanlar açılır alanda.
        </p>
        {classified_empty_note}
        {_render_endpoint_bucket("Admin Panels", admin_like, "Bu kategori için doğrulanmış endpoint oluşmadı.")}
        {_render_endpoint_bucket("Authentication Endpoints", auth_like, "Bu kategori için doğrulanmış endpoint oluşmadı.")}
        {_render_endpoint_bucket("API Endpoints", api_like, "Bu kategori için doğrulanmış endpoint oluşmadı.")}
        {_render_endpoint_bucket("Upload Endpoints", upload_like, "Bu kategori için doğrulanmış endpoint oluşmadı.")}
        {_render_endpoint_bucket("Debug / Test Endpoints", debug_like, "Bu kategori için doğrulanmış endpoint oluşmadı.")}
        {_render_endpoint_bucket("Documentation / Dev Pages", docs_like, "Bu kategori için doğrulanmış endpoint oluşmadı.")}
    </div>
    """


    return section_html
