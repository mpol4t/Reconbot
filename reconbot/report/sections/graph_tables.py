from __future__ import annotations

from typing import Any

def render_graph_tables_section(context: dict[str, Any]) -> str:
    _html_escape = context.get("_html_escape")
    _is_url_like_text = context.get("_is_url_like_text")
    _operator_text_to_english = context.get("_operator_text_to_english")
    _render_progressive_table = context.get("_render_progressive_table")
    _render_representative_endpoint = context.get("_render_representative_endpoint")
    _sanitize_report_url = context.get("_sanitize_report_url")
    attack_graph = context.get("attack_graph")
    graph_payload_json = context.get("graph_payload_json")
    graph_payload_meta = context.get("graph_payload_meta")
    graph_payload_paths = context.get("graph_payload_paths")
    render_attack_graph_section = context.get("render_attack_graph_section")
    render_interactive_graph_block = context.get("render_interactive_graph_block")
    report_base_url = context.get("report_base_url")
    representative_cluster_map = context.get("representative_cluster_map")
    variant_to_representative = context.get("variant_to_representative")
    depth_config = context.get("report_depth_config")
    section_html = ""
    raw_open = " open" if bool(getattr(depth_config, "expand_graph_raw_tables", False)) else ""
    # --- Attack Graph ---
    graph_nodes = attack_graph.get("nodes", []) if isinstance(attack_graph, dict) else []
    graph_edges = attack_graph.get("edges", []) if isinstance(attack_graph, dict) else []
    graph_paths = attack_graph.get("paths", []) if isinstance(attack_graph, dict) else []
    empty_state = "Doğrulanmış yüzey veya bulgu olmadığı için saldırı zinciri kurulmadı."

    _best_path_conf = int(graph_payload_meta.get("best_confidence", 0) or 0)
    _best_path_seq = " → ".join(graph_payload_paths[0].get("sequence", []) or []) if graph_payload_paths else "-"

    # Graph Paths rows
    _gp_hdr = "<th>#</th><th>Path</th><th>Güven</th><th>Neden önemli?</th>"
    _gp_rows = [
        f"<tr><td><strong>{i}</strong></td>"
        f"<td>{_html_escape(' → '.join(p.get('sequence', []) or []))}</td>"
        f"<td>{int(p.get('confidence', 0))}/100</td>"
        f"<td class=\"wrap-cell\">{_html_escape(_operator_text_to_english(p.get('selection_reason') or p.get('why', '') or '-'))}</td></tr>"
        for i, p in enumerate(graph_payload_paths, start=1)
    ]

    # Graph Edges rows
    _ge_hdr = "<th>Kaynak</th><th>Hedef</th><th>Güven</th><th>Gerekçe</th>"
    _ge_rows = [
        f"<tr><td>{_html_escape(e.get('from', '-'))}</td>"
        f"<td>{_html_escape(e.get('to', '-'))}</td>"
        f"<td>{int(e.get('confidence', 0))}/100</td>"
        f"<td class=\"wrap-cell\">{_html_escape(_operator_text_to_english(e.get('reason', '-')))}</td></tr>"
        for e in graph_edges
    ]

    # Graph Nodes rows
    _gn_hdr = "<th>Node</th><th>Tip</th><th>Sayı</th><th>Neden önemli?</th><th>Detaylar</th>"
    _gn_rows: list[str] = []
    for _gn in graph_nodes:
        _gn_raw_details = _gn.get("details", []) or []
        _gn_rendered_details: list[str] = []
        for _gn_detail in _gn_raw_details[:5]:
            _gn_detail_text = str(_gn_detail or "").strip()
            if not _gn_detail_text:
                continue
            if _is_url_like_text(_gn_detail_text):
                _gn_safe = _sanitize_report_url(_gn_detail_text, report_base_url)
                if _gn_safe:
                    _gn_rep = variant_to_representative.get(_gn_safe, _gn_safe)
                    _gn_cluster = representative_cluster_map.get(_gn_rep)
                    _gn_rendered_details.append(_render_representative_endpoint(_gn_rep, report_base_url, _gn_cluster, preview_variants=3))
            else:
                _gn_rendered_details.append(_html_escape(_operator_text_to_english(_gn_detail_text)))
        _gn_details_html = "<br>".join(_gn_rendered_details) if _gn_rendered_details else "-"
        if len(_gn_raw_details) > 5:
            _gn_extra = len(_gn_raw_details) - 5
            _gn_details_html += f'<details><summary class="row-details-toggle">+{_gn_extra} ek detay</summary>'
            for _gn_extra_detail in _gn_raw_details[5:]:
                _gn_et = str(_gn_extra_detail or "").strip()
                if _gn_et:
                    if _is_url_like_text(_gn_et):
                        _gn_es = _sanitize_report_url(_gn_et, report_base_url)
                        if _gn_es:
                            _gn_er = variant_to_representative.get(_gn_es, _gn_es)
                            _gn_ec = representative_cluster_map.get(_gn_er)
                            _gn_details_html += _render_representative_endpoint(_gn_er, report_base_url, _gn_ec, preview_variants=1)
                    else:
                        _gn_details_html += f"<br>{_html_escape(_operator_text_to_english(_gn_et))}"
            _gn_details_html += "</details>"
        _gn_type = str(_gn.get("type", "-") or "-").strip().lower()
        _gn_count = int(_gn.get("count", 0) or 0)
        if _gn_type == "surface":
            _gn_why = "Giriş yüzeyi node’u; saldırı erişilebilirliğini ve ilk manuel test sırasını değiştirir."
        elif _gn_type == "finding":
            _gn_why = "Kanıt destekli bulgu node’u; salt çıkarım yerine doğrulamayı önceliklendirmek için kullan."
        elif _gn_type == "outcome":
            _gn_why = "Sonuç node’u; üst kontroller başarısız olursa oluşabilecek potansiyel etki hedefini gösterir."
        elif _gn_type == "technology":
            _gn_why = "Teknoloji node’u; stack’e özel exploit varsayımlarını ve test payload seçimini etkiler."
        elif _gn_count > 0:
            _gn_why = "Ölçülebilir aktivite içeren sinyalli node; path confidence yorumunda dikkate al."
        else:
            _gn_why = "İlişki haritalaması için destekleyici bağlam node’u."
        _gn_rows.append(
            f"<tr><td><strong>{_html_escape(_operator_text_to_english(_gn.get('label', '-') or '-'))}</strong></td>"
            f"<td>{_html_escape(_gn.get('type', '-'))}</td>"
            f"<td>{_gn_count}</td>"
            f"<td class=\"wrap-cell\">{_html_escape(_gn_why)}</td>"
            f"<td class=\"wrap-cell\">{_gn_details_html}</td></tr>"
        )

    graph_paths_table_html = f'<details class="show-more"{raw_open}><summary>Grafik path önizlemesi</summary>'
    graph_paths_table_html += _render_progressive_table(
        header_html=_gp_hdr,
        rows=_gp_rows,
        empty_row_html=f'<tr><td colspan="4">{_html_escape(empty_state)}</td></tr>',
        preview_rows=int(getattr(depth_config, "max_graph_path_preview", 5)),
        summary_label="Tüm path’leri göster",
    )
    graph_paths_table_html += "</details>"

    graph_edges_table_html = f'<details class="show-more"{raw_open}><summary>Grafik edge önizlemesi</summary>'
    graph_edges_table_html += _render_progressive_table(
        header_html=_ge_hdr,
        rows=_ge_rows,
        empty_row_html=f'<tr><td colspan="4">{_html_escape(empty_state)}</td></tr>',
        preview_rows=int(getattr(depth_config, "max_graph_edge_preview", 10)),
        summary_label="Tüm edge’leri göster",
    )
    graph_edges_table_html += "</details>"

    graph_nodes_table_html = f'<details class="show-more"{raw_open}><summary>Grafik node önizlemesi</summary>'
    graph_nodes_table_html += _render_progressive_table(
        header_html=_gn_hdr,
        rows=_gn_rows,
        empty_row_html=f'<tr><td colspan="5">{_html_escape(empty_state)}</td></tr>',
        preview_rows=int(getattr(depth_config, "max_graph_node_preview", 10)),
        summary_label="Tüm node’ları göster",
    )
    graph_nodes_table_html += "</details>"

    section_html += '<div class="report-depth-graph-section report-depth-body-balanced-deep" data-depth-body="balanced deep">'
    section_html += render_attack_graph_section(
        graph_payload_meta=graph_payload_meta,
        graph_payload_paths=graph_payload_paths,
        graph_nodes_count_raw=len(graph_nodes),
        graph_edges_count_raw=len(graph_edges),
        graph_paths_count_raw=len(graph_paths),
        best_path_confidence=_best_path_conf,
        best_path_sequence=_best_path_seq,
        interactive_graph_html=render_interactive_graph_block(graph_payload_json),
        graph_paths_table_html=graph_paths_table_html,
        graph_edges_table_html=graph_edges_table_html,
        graph_nodes_table_html=graph_nodes_table_html,
        show_raw_tables=bool(getattr(depth_config, "show_graph_raw_tables", True)),
    )
    section_html += "</div>"
    return section_html
