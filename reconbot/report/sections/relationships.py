from __future__ import annotations

from typing import Any

def render_relationships_section(context: dict[str, Any]) -> str:
    _html_escape = context.get("_html_escape")
    _is_url_like_text = context.get("_is_url_like_text")
    _render_progressive_list = context.get("_render_progressive_list")
    _render_progressive_table = context.get("_render_progressive_table")
    _render_representative_endpoint = context.get("_render_representative_endpoint")
    _render_summary_strip_counts = context.get("_render_summary_strip_counts")
    _sanitize_report_url = context.get("_sanitize_report_url")
    _operator_text_to_english = context.get("_operator_text_to_english")
    _soften_suggestion_text = context.get("_soften_suggestion_text")
    _truncate_text = context.get("_truncate_text")
    _txt = context.get("_txt")
    decision_confidence = context.get("decision_confidence")
    discovery_low_or_critical = context.get("discovery_low_or_critical")
    node_relationships = context.get("node_relationships")
    report_base_url = context.get("report_base_url")
    representative_cluster_map = context.get("representative_cluster_map")
    variant_to_representative = context.get("variant_to_representative")
    depth_config = context.get("report_depth_config")
    depth_name = str(getattr(depth_config, "name", "balanced"))
    section_html = ""
    # --- Node Relationships (GUI-ready backend view) ---
    _nr_hdr = "<th>Node</th><th>Neden önemli?</th><th>Sayılar</th><th>Detaylar</th>"
    _nr_rows: list[str] = []
    sorted_node_relationships = sorted(
        [item for item in list((node_relationships or {}).values()) if isinstance(item, dict)],
        key=lambda item: (
            len(item.get("related_suggestions", []) or [])
            + len(item.get("related_cves", []) or [])
            + len(item.get("related_endpoints", []) or [])
        ),
        reverse=True,
    )
    for _nr_rel in sorted_node_relationships:
        _nr_label = _html_escape(_operator_text_to_english(_nr_rel.get("node_label", "-") or "-"))
        _nr_sugs = _nr_rel.get("related_suggestions", []) or []
        _nr_cves = _nr_rel.get("related_cves", []) or []
        _nr_tags = _nr_rel.get("related_nuclei_tags", []) or []
        _nr_eps = _nr_rel.get("related_endpoints", []) or []

        # Top suggestion preview
        _nr_top_sug = "-"
        if _nr_sugs and isinstance(_nr_sugs[0], dict):
            _nr_top_sug = f'<strong>{_html_escape(_nr_sugs[0].get("title", "-"))}</strong>'

        _nr_ep_count = len(_nr_eps)
        _nr_counts = (
            f'CVE’ler: <strong>{len(_nr_cves)}</strong> | '
            f'Tags: <strong>{len(_nr_tags)}</strong> | '
            f'Endpoint’ler: <strong>{_nr_ep_count}</strong>'
        )

        # Full detail block
        _nr_sug_detail = ""
        if _nr_sugs:
            _nr_sug_lis_items: list[str] = []
            for s in _nr_sugs[:6]:
                if not isinstance(s, dict):
                    continue
                _nr_sug_title_raw = str(s.get("title", "-") or "-")
                _nr_sug_priority_raw = int(s.get("priority", 0) or 0)
                if discovery_low_or_critical or decision_confidence == "Low":
                    _nr_sug_title = _soften_suggestion_text(_nr_sug_title_raw)
                    _nr_sug_priority = min(_nr_sug_priority_raw, 60)
                else:
                    _nr_sug_title = _nr_sug_title_raw
                    _nr_sug_priority = _nr_sug_priority_raw
                _nr_sug_lis_items.append(
                    f'<li><strong>{_html_escape(_operator_text_to_english(_nr_sug_title))}</strong> ({_nr_sug_priority}/100)</li>'
                )
            _nr_sug_lis = "".join(_nr_sug_lis_items)
            _nr_sug_detail = f"<dt>Öneriler:</dt><dd><ul class='compact-list'>{_nr_sug_lis}</ul></dd>"
        _nr_cve_detail = ""
        if _nr_cves:
            _nr_cve_lis = "".join(
                f'<li><strong>{_html_escape(c.get("cve_id","-"))}</strong> ({int(c.get("relevance_score",0))}/100)</li>'
                for c in _nr_cves[:5] if isinstance(c, dict)
            )
            _nr_cve_detail = f"<dt>CVEs:</dt><dd><ul class='compact-list'>{_nr_cve_lis}</ul></dd>"
        _nr_tags_detail = ""
        if _nr_tags:
            _nr_tags_str = _html_escape(", ".join(str(t) for t in _nr_tags[:15]))
            _nr_tags_detail = f"<dt>Nuclei tags:</dt><dd>{_nr_tags_str}</dd>"
        _nr_eps_detail = ""
        if _nr_eps:
            _nr_ep_lis_items: list[str] = []
            for _nr_ep in _nr_eps:
                _nr_ep_text = str(_nr_ep or "").strip()
                if not _nr_ep_text:
                    continue
                if _is_url_like_text(_nr_ep_text):
                    _nr_ep_safe = _sanitize_report_url(_nr_ep_text, report_base_url)
                    if _nr_ep_safe:
                        _nr_ep_rep = variant_to_representative.get(_nr_ep_safe, _nr_ep_safe)
                        _nr_ep_cluster = representative_cluster_map.get(_nr_ep_rep)
                        _nr_ep_lis_items.append(
                            _render_representative_endpoint(
                                _nr_ep_rep,
                                report_base_url,
                                _nr_ep_cluster,
                                preview_variants=3,
                            )
                        )
                else:
                    _nr_ep_lis_items.append(_html_escape(_operator_text_to_english(_nr_ep_text)))
            if _nr_ep_lis_items:
                _nr_eps_detail = (
                    "<dt>Endpoint’ler:</dt><dd>"
                    + _render_progressive_list(
                        _nr_ep_lis_items,
                        preview_count=0 if depth_name == "deep" else 3,
                        summary_prefix="Daha fazla endpoint göster",
                    )
                    + "</dd>"
                )
        _nr_details_html = (
            f'<details><summary class="row-details-toggle">Tümünü göster ({len(_nr_sugs)} öneri, {_nr_ep_count} endpoint)</summary>'
            f'<dl class="suggestion-detail">{_nr_sug_detail}{_nr_cve_detail}{_nr_tags_detail}{_nr_eps_detail}</dl></details>'
        )
        if _nr_sugs and isinstance(_nr_sugs[0], dict):
            _nr_top_title = _operator_text_to_english(_truncate_text(str(_nr_sugs[0].get('title') or '-'), 72))
            _nr_why = (
                f"En öncelikli öneri: {_nr_top_title}; "
                "bu node yüksek etkili bir manuel doğrulama pivotudur."
            )
        elif _nr_cves:
            _nr_why = "Bu node üzerinde CVE korelasyonu var; geniş scan öncesinde exploit alakasını doğrula."
        elif _nr_tags:
            _nr_why = "Nuclei tag’leri bu node’a eşleniyor; path önceliklendirmesi için kanıt bağlantılı bağlam olarak ele al."
        elif _nr_ep_count > 0:
            _nr_why = "Bu node birden fazla endpoint’i toplar ve manuel test kapsamını hızlıca artırabilir."
        else:
            _nr_why = "Yalnızca bağlam node’u; destekleyici ilişki kanıtı olarak tut."

        _nr_rows.append(
            f"<tr><td><strong>{_nr_label}</strong></td>"
            f"<td class=\"wrap-cell\">{_html_escape(_nr_why)}</td>"
            f"<td class=\"wrap-cell node-compact-signal\">{_nr_counts}</td>"
            f"<td>{_nr_details_html}</td></tr>"
        )
    section_html += f"""
    <div class="section report-depth-operator-detail report-depth-body-balanced-deep" data-depth-body="balanced deep">
        <h2 id="graph-relationships">{_html_escape(_txt("node_relationships_title"))}</h2>
        <p class="note">{_html_escape(_txt("node_relationships_note"))}</p>
        <p class="operator-view-note">{_html_escape(_txt("node_relationships_operator_note"))}</p>
    """
    section_html += _render_summary_strip_counts(
        [
            ("node’lar", len(sorted_node_relationships)),
            ("toplam öneri", sum(len(rel.get("related_suggestions", []) or []) for rel in sorted_node_relationships)),
            ("toplam CVE linki", sum(len(rel.get("related_cves", []) or []) for rel in sorted_node_relationships)),
        ]
    )
    relationship_open = " open" if depth_name == "deep" else ""
    relationship_preview_rows = 0 if depth_name == "deep" else min(5, int(getattr(depth_config, "max_suggestions_preview", 8)))
    section_html += f'<details class="show-more report-depth-balanced-preview"{relationship_open}><summary>{_html_escape(_txt("node_relationships_preview"))}</summary>'
    section_html += _render_progressive_table(
        header_html=_nr_hdr,
        rows=_nr_rows,
        empty_row_html=f'<tr><td colspan="4">{_html_escape(_txt("node_relationships_empty"))}</td></tr>',
        preview_rows=relationship_preview_rows,
        summary_label=_txt("node_relationships_show_all"),
    )
    section_html += "</details>"
    section_html += "</div>"
    return section_html
