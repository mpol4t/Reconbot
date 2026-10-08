from __future__ import annotations

from typing import Any

from reconbot.report.texts import text as _txt


def _html_escape(value: object) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def render_attack_graph_section(
    graph_payload_meta: dict[str, Any],
    graph_payload_paths: list[dict[str, Any]],
    graph_nodes_count_raw: int,
    graph_edges_count_raw: int,
    graph_paths_count_raw: int,
    best_path_confidence: int,
    best_path_sequence: str,
    interactive_graph_html: str,
    graph_paths_table_html: str,
    graph_edges_table_html: str,
    graph_nodes_table_html: str,
    show_raw_tables: bool = True,
) -> str:
    payload_meta = graph_payload_meta if isinstance(graph_payload_meta, dict) else {}
    payload_paths = graph_payload_paths if isinstance(graph_payload_paths, list) else []

    scope_id = str(payload_meta.get("scope_id") or "").strip()
    payload_nodes = int(payload_meta.get("node_count", graph_nodes_count_raw) or graph_nodes_count_raw)
    payload_edges = int(payload_meta.get("edge_count", graph_edges_count_raw) or graph_edges_count_raw)
    payload_paths_count = int(payload_meta.get("path_count", graph_paths_count_raw) or graph_paths_count_raw)
    payload_best_conf = int(payload_meta.get("best_confidence", best_path_confidence) or best_path_confidence)
    payload_best_base_conf = int(payload_meta.get("best_base_confidence", payload_best_conf) or payload_best_conf)
    payload_best_reason = str(payload_meta.get("best_path_reason") or "").strip()
    payload_best_evidence_boost = int(payload_meta.get("best_path_evidence_boost", 0) or 0)
    payload_best_rank_score = int(payload_meta.get("best_rank_score", 0) or 0)
    graph_has_signal = bool(payload_nodes or payload_edges or payload_paths_count or payload_paths)

    best_path_from_payload = ""
    best_path_id = str(payload_meta.get("best_path_id") or "").strip()
    if best_path_id:
        for path in payload_paths:
            if not isinstance(path, dict):
                continue
            if str(path.get("id") or "").strip() != best_path_id:
                continue
            sequence = path.get("sequence", [])
            if isinstance(sequence, list):
                seq_labels = [str(item or "").strip() for item in sequence if str(item or "").strip()]
                if seq_labels:
                    best_path_from_payload = " → ".join(seq_labels)
            if not best_path_from_payload:
                best_path_from_payload = str(path.get("id") or "").strip()
            break

    best_path_note = best_path_from_payload or best_path_sequence or "-"
    if not graph_has_signal:
        best_path_note = _txt("graph_best_reason_fallback")
    best_path_reason_note = (
        payload_best_reason
        if payload_best_reason
        else _txt("graph_best_reason_fallback")
    )
    best_path_score_note = (
        _txt(
            "graph_best_score",
            rank=payload_best_rank_score,
            base=payload_best_base_conf,
            boost=payload_best_evidence_boost,
        )
        if payload_best_rank_score > 0
        else ""
    )
    payload_meta_note = (
        _txt("graph_meta_note", nodes=payload_nodes, edges=payload_edges, paths=payload_paths_count)
        if payload_nodes or payload_edges or payload_paths_count
        else _txt("graph_meta_note_empty")
    )
    scope_note = _txt("graph_scope_note", scope=_html_escape(scope_id)) if scope_id else _txt("graph_scope_note_empty")

    raw_tables_html = ""
    if show_raw_tables:
        raw_tables_html = """\

        <div class="report-depth-evidence-detail report-depth-audit-only">
            <h3 style="margin-top: 32px;">__GRAPH_RAW_TITLE__</h3>
            <p class="note">__GRAPH_RAW_NOTE__</p>
            <p class="note report-depth-deep-only">Derin mod audit incelemesi için ham node, edge ve path tablolarını açık tutar. Dengeli mod operatör grafiğini birincil görünümde tutmak için bunları ikincil yapar.</p>
            __M8__
            __M9__
            __M10__
        </div>
        """

    template = """\

    <div class="section" id="attack-graph">
        <h2>__GRAPH_TITLE__</h2>
        <p class="report-depth-explainer"><strong>Nasıl kullanılmalı?</strong> Grafik; yüzeylerin, teknolojilerin, bulguların ve olası sonuçların birbiriyle nasıl ilişkili olduğunu gösterir. Doğrulama sırasını seçmek için kullan; tek başına exploit kanıtı değildir.</p>
        <p class="note">__GRAPH_NOTE_1__</p>
        <p class="note">__GRAPH_NOTE_2__</p>
        <p class="note">__META_NOTE__</p>
        <p class="note">__SCOPE_NOTE__</p>
        <div class="kpi-grid">
            <div class="kpi">
                <div class="label">Node’lar</div>
                <div class="value">__M2__</div>
                <div class="note">__GRAPH_NODES_NOTE__</div>
            </div>
            <div class="kpi">
                <div class="label">Edge’ler</div>
                <div class="value">__M3__</div>
                <div class="note">__GRAPH_EDGES_NOTE__</div>
            </div>
            <div class="kpi">
                <div class="label">Yollar</div>
                <div class="value">__M4__</div>
                <div class="note">__GRAPH_PATHS_NOTE__</div>
            </div>
            <div class="kpi">
                <div class="label">Yol güveni</div>
                <div class="value">__M5__</div>
                <div class="note">__M6__</div>
            </div>
        </div>
        <p class="note">__BEST_REASON__</p>
        <p class="note">__BEST_SCORE__</p>
        
        __M7__
        __RAW_TABLES__
    </div>
    """
    return (
        template
        .replace("__M2__", str(graph_nodes_count_raw))
        .replace("__M3__", str(graph_edges_count_raw))
        .replace("__M4__", str(graph_paths_count_raw))
        .replace("__M5__", f"{payload_best_conf} / 100" if graph_has_signal else "-")
        .replace("__M6__", _html_escape(best_path_note))
        .replace("__M7__", str(interactive_graph_html))
        .replace("__RAW_TABLES__", raw_tables_html)
        .replace("__M8__", str(graph_paths_table_html))
        .replace("__M9__", str(graph_edges_table_html))
        .replace("__M10__", str(graph_nodes_table_html))
        .replace("__META_NOTE__", _html_escape(payload_meta_note))
        .replace("__SCOPE_NOTE__", scope_note)
        .replace("__BEST_REASON__", _html_escape(best_path_reason_note))
        .replace("__BEST_SCORE__", _html_escape(best_path_score_note))
        .replace("__GRAPH_TITLE__", _txt("graph_title"))
        .replace("__GRAPH_NOTE_1__", _txt("graph_note_1"))
        .replace("__GRAPH_NOTE_2__", _txt("graph_note_2"))
        .replace("__GRAPH_NODES_NOTE__", _txt("graph_kpi_nodes_note"))
        .replace("__GRAPH_EDGES_NOTE__", _txt("graph_kpi_edges_note"))
        .replace("__GRAPH_PATHS_NOTE__", _txt("graph_kpi_paths_note"))
        .replace("__GRAPH_RAW_TITLE__", _txt("graph_raw_title"))
        .replace("__GRAPH_RAW_NOTE__", _txt("graph_raw_note"))
    )
