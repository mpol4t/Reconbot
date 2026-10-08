from __future__ import annotations

import hashlib
from typing import Any

from reconbot.report.suggestions import operator_text_to_english as _localize_report_text

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info", "unknown")
SEVERITY_RANK: dict[str, int] = {name: idx for idx, name in enumerate(SEVERITY_ORDER)}


def _is_url_like_text(value: Any) -> bool:
    raw = str(value or "").strip()
    return raw.startswith(("http://", "https://", "//", "/"))


def _coerce_graph_confidence(value: Any, default: int = 0) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return max(0, min(100, parsed))


def _coerce_graph_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _normalize_graph_node_type(node_type: Any, label: Any = "") -> str:
    raw_type = str(node_type or "").strip().lower()
    if raw_type in {"surface", "technology", "outcome", "finding"}:
        return raw_type

    low_label = str(label or "").strip().lower()
    if any(token in low_label for token in ("nuclei", "finding", "severity", "template")):
        return "finding"
    if any(token in low_label for token in ("surface", "flow", "entry", "channel", "redirect")):
        return "surface"
    if any(token in low_label for token in ("tech", "stack", "signal", "graphql", "swagger", "openapi", "phpmyadmin")):
        return "technology"
    return "outcome"


def _slugify_graph_id(value: Any, fallback: str = "node") -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return fallback
    out_chars: list[str] = []
    prev_sep = False
    for ch in raw:
        if ("a" <= ch <= "z") or ("0" <= ch <= "9"):
            out_chars.append(ch)
            prev_sep = False
        else:
            if not prev_sep:
                out_chars.append("_")
            prev_sep = True
    normalized = "".join(out_chars).strip("_")
    return normalized or fallback


def _node_sort_key(node: dict[str, Any]) -> tuple[int, int, str, str]:
    node_id = str(node.get("id") or "").strip().lower()
    label = str(node.get("label") or "").strip().lower()
    node_type = _normalize_graph_node_type(node.get("type"), node.get("label"))
    type_rank = {"surface": 0, "technology": 1, "finding": 2, "outcome": 3}.get(node_type, 4)

    if node_id == "nuclei_findings":
        return (0, -1, label, node_id)
    if node_id.startswith("nuclei_"):
        sev = node_id.split("nuclei_", 1)[1].strip().lower()
        return (0, SEVERITY_RANK.get(sev, len(SEVERITY_ORDER)), label, node_id)
    return (1, type_rank, label, node_id)


def _edge_sort_key(edge: dict[str, Any]) -> tuple[str, str, str, int, str]:
    source = str(edge.get("from") or edge.get("source") or "").strip().lower()
    target = str(edge.get("to") or edge.get("target") or "").strip().lower()
    edge_id = str(edge.get("id") or "").strip().lower()
    confidence = _coerce_graph_confidence(edge.get("confidence", 0))
    reason = str(edge.get("reason") or "").strip().lower()
    return (source, target, edge_id, -confidence, reason)


def _path_sort_key(path: dict[str, Any]) -> tuple[int, str, str]:
    confidence = _coerce_graph_confidence(path.get("confidence", 0))
    path_id = str(path.get("id") or "").strip().lower()
    name = str(path.get("name") or "").strip().lower()
    return (-confidence, path_id, name)


def _display_text(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw or _is_url_like_text(raw):
        return raw
    return _localize_report_text(raw)


def build_graph_report_payload(
    attack_graph: dict[str, Any] | None,
    node_relationships: dict[str, Any] | None,
    scope_id: str | None = None,
) -> dict[str, Any]:
    graph = attack_graph or {}
    rel_map = node_relationships if isinstance(node_relationships, dict) else {}

    raw_nodes = graph.get("nodes", []) if isinstance(graph.get("nodes"), list) else []
    raw_edges = graph.get("edges", []) if isinstance(graph.get("edges"), list) else []
    raw_paths = graph.get("paths", []) if isinstance(graph.get("paths"), list) else []
    raw_nodes = sorted([node for node in raw_nodes if isinstance(node, dict)], key=_node_sort_key)
    raw_edges = sorted([edge for edge in raw_edges if isinstance(edge, dict)], key=_edge_sort_key)
    raw_paths = sorted([path for path in raw_paths if isinstance(path, dict)], key=_path_sort_key)

    relationships_by_id: dict[str, dict[str, Any]] = {}
    relationships_by_label: dict[str, dict[str, Any]] = {}
    for key, rel in rel_map.items():
        if not isinstance(rel, dict):
            continue
        rel_node_id = str(rel.get("node_id") or key or "").strip()
        rel_label = str(rel.get("node_label") or "").strip().lower()
        if rel_node_id:
            relationships_by_id[rel_node_id] = rel
        if rel_label:
            relationships_by_label[rel_label] = rel

    payload_nodes: list[dict[str, Any]] = []
    node_id_set: set[str] = set()
    node_label_to_id: dict[str, str] = {}

    for idx, node in enumerate(raw_nodes, start=1):
        node_id = str(node.get("id") or "").strip()
        raw_node_label = str(node.get("label") or "").strip() or f"Node {idx}"
        node_label = _display_text(raw_node_label) or raw_node_label
        if not node_id:
            node_id = _slugify_graph_id(node_label, fallback=f"node_{idx}")
        if node_id in node_id_set:
            node_id = f"{node_id}_{idx}"
        node_id_set.add(node_id)
        node_label_to_id.setdefault(raw_node_label.lower(), node_id)
        node_label_to_id.setdefault(node_label.lower(), node_id)

        rel = relationships_by_id.get(node_id) or relationships_by_label.get(node_label.lower()) or {}
        related_suggestions_raw = rel.get("related_suggestions", []) if isinstance(rel, dict) else []
        related_cves_raw = rel.get("related_cves", []) if isinstance(rel, dict) else []
        related_tags_raw = rel.get("related_nuclei_tags", []) if isinstance(rel, dict) else []
        related_endpoints_raw = rel.get("related_endpoints", []) if isinstance(rel, dict) else []

        related_suggestions: list[dict[str, Any]] = []
        for sug in related_suggestions_raw if isinstance(related_suggestions_raw, list) else []:
            if not isinstance(sug, dict):
                continue
            related_suggestions.append(
                {
                    "title": _display_text(sug.get("title") or "-"),
                    "priority": _coerce_graph_confidence(sug.get("priority", 0)),
                    "surface": _display_text(sug.get("surface") or "-"),
                }
            )

        related_cves: list[dict[str, Any]] = []
        for cve in related_cves_raw if isinstance(related_cves_raw, list) else []:
            if not isinstance(cve, dict):
                continue
            related_cves.append(
                {
                    "cve_id": str(cve.get("cve_id") or "-"),
                    "relevance_score": _coerce_graph_confidence(cve.get("relevance_score", 0)),
                    "product": str(cve.get("product") or "-"),
                    "version": str(cve.get("version") or "-"),
                }
            )

        related_tags: list[str] = []
        seen_tags: set[str] = set()
        for tag in related_tags_raw if isinstance(related_tags_raw, list) else []:
            tag_text = str(tag or "").strip()
            if tag_text and tag_text not in seen_tags:
                seen_tags.add(tag_text)
                related_tags.append(tag_text)

        related_endpoints: list[str] = []
        seen_endpoints: set[str] = set()
        for endpoint in related_endpoints_raw if isinstance(related_endpoints_raw, list) else []:
            ep_text = str(endpoint or "").strip()
            if ep_text and ep_text not in seen_endpoints:
                seen_endpoints.add(ep_text)
                related_endpoints.append(ep_text)

        if not related_endpoints:
            for detail in node.get("details", []) if isinstance(node.get("details"), list) else []:
                detail_text = str(detail or "").strip()
                if detail_text and detail_text not in seen_endpoints and _is_url_like_text(detail_text):
                    seen_endpoints.add(detail_text)
                    related_endpoints.append(detail_text)

        try:
            node_count = int(node.get("count", 0) or 0)
        except Exception:
            node_count = 0
        node_count = max(0, node_count)

        relation_weight = (
            len(related_suggestions) * 3
            + len(related_cves) * 3
            + len(related_tags)
            + len(related_endpoints)
        )
        importance = max(
            1,
            min(
                100,
                (node_count * 10)
                + relation_weight
                + (12 if _normalize_graph_node_type(node.get("type"), node_label) == "outcome" else 0),
            ),
        )
        low_signal = node_count <= 0 and relation_weight <= 2

        payload_nodes.append(
            {
                "id": node_id,
                "label": node_label,
                "type": _normalize_graph_node_type(node.get("type"), node_label),
                "count": node_count,
                "importance": importance,
                "low_signal": low_signal,
                "details": [_display_text(item) for item in (node.get("details", []) or []) if str(item or "").strip()],
                "related_suggestions": related_suggestions[:8],
                "related_cves": related_cves[:10],
                "related_nuclei_tags": related_tags[:25],
                "related_endpoints": related_endpoints[:25],
            }
        )

    payload_paths: list[dict[str, Any]] = []
    seen_path_ids: set[str] = set()
    for idx, path in enumerate(raw_paths, start=1):
        path_id = str(path.get("id") or "").strip()
        if not path_id:
            path_id = _slugify_graph_id(path.get("name"), fallback=f"path_{idx}")
        if path_id in seen_path_ids:
            path_id = f"{path_id}_{idx}"
        seen_path_ids.add(path_id)

        raw_sequence = [str(item or "").strip() for item in (path.get("sequence", []) or []) if str(item or "").strip()]
        sequence = [_display_text(item) for item in raw_sequence]
        mapped_node_ids = [node_label_to_id[label.lower()] for label in raw_sequence if label.lower() in node_label_to_id]
        path_confidence = _coerce_graph_confidence(path.get("confidence", 0))
        base_confidence = _coerce_graph_confidence(path.get("base_confidence", path_confidence))
        evidence_boost = max(0, _coerce_graph_int(path.get("evidence_boost"), 0))
        rank_score = max(0, _coerce_graph_int(path.get("rank_score"), (path_confidence * 7) + (evidence_boost * 6)))
        evidence_supported = bool(path.get("evidence_supported")) or evidence_boost > 0
        selection_reason = _display_text(path.get("selection_reason") or path.get("why") or "-")
        payload_paths.append(
            {
                "id": path_id,
                "sequence": sequence,
                "node_ids": mapped_node_ids,
                "confidence": path_confidence,
                "base_confidence": base_confidence,
                "evidence_boost": evidence_boost,
                "rank_score": rank_score,
                "evidence_supported": evidence_supported,
                "selection_reason": selection_reason,
                "why": _display_text(path.get("why") or "-"),
            }
        )

    payload_paths = sorted(
        payload_paths,
        key=lambda p: (
            -int(p.get("rank_score", 0) or 0),
            -int(p.get("confidence", 0) or 0),
            str(p.get("id") or "").lower(),
            "->".join(str(item or "").strip().lower() for item in (p.get("sequence", []) or [])),
        ),
    )

    payload_edges: list[dict[str, Any]] = []
    edge_by_pair: dict[tuple[str, str], dict[str, Any]] = {}
    seen_edge_ids: set[str] = set()
    for idx, edge in enumerate(raw_edges, start=1):
        source_raw = str(edge.get("from") or edge.get("source") or "").strip()
        target_raw = str(edge.get("to") or edge.get("target") or "").strip()
        if not source_raw or not target_raw:
            continue

        source = source_raw
        target = target_raw
        if source not in node_id_set and source.lower() in node_label_to_id:
            source = node_label_to_id[source.lower()]
        if target not in node_id_set and target.lower() in node_label_to_id:
            target = node_label_to_id[target.lower()]
        if source not in node_id_set or target not in node_id_set:
            continue

        confidence = _coerce_graph_confidence(edge.get("confidence", 0))
        edge_color = "#3fb950" if confidence >= 75 else ("#ffa657" if confidence >= 50 else "#8b949e")
        edge_id = str(edge.get("id") or "").strip() or f"{source}__{target}"
        edge_id = _slugify_graph_id(edge_id, fallback=f"edge_{idx}")
        if edge_id in seen_edge_ids:
            edge_id = f"{edge_id}_{idx}"
        seen_edge_ids.add(edge_id)

        payload_edge = {
            "id": edge_id,
            "source": source,
            "target": target,
            "confidence": confidence,
            "reason": _display_text(edge.get("reason") or "-"),
            "path_refs": [],
            "edge_color": edge_color,
            "edge_opacity": round(0.25 + (confidence / 140.0), 3),
        }
        payload_edges.append(payload_edge)
        edge_by_pair[(source, target)] = payload_edge

    payload_edges = sorted(
        payload_edges,
        key=lambda e: (
            str(e.get("source") or "").lower(),
            str(e.get("target") or "").lower(),
            str(e.get("id") or "").lower(),
            -int(e.get("confidence", 0) or 0),
        ),
    )

    for path in payload_paths:
        path_id = str(path.get("id") or "").strip()
        node_ids = path.get("node_ids", []) if isinstance(path.get("node_ids"), list) else []
        for i in range(len(node_ids) - 1):
            src = str(node_ids[i] or "").strip()
            dst = str(node_ids[i + 1] or "").strip()
            if not src or not dst:
                continue
            edge_match = edge_by_pair.get((src, dst))
            if edge_match is None:
                continue
            refs = edge_match.get("path_refs", [])
            if isinstance(refs, list) and path_id and path_id not in refs:
                refs.append(path_id)
                edge_match["path_refs"] = refs

    best_path = payload_paths[0] if payload_paths else {}
    best_confidence = int(best_path.get("confidence", 0)) if isinstance(best_path, dict) else 0
    best_base_confidence = int(best_path.get("base_confidence", best_confidence)) if isinstance(best_path, dict) else best_confidence
    best_path_id = str(best_path.get("id") or "") if isinstance(best_path, dict) else ""
    best_rank_score = int(best_path.get("rank_score", 0)) if isinstance(best_path, dict) else 0
    best_path_reason = str(best_path.get("selection_reason") or best_path.get("why") or "") if isinstance(best_path, dict) else ""
    best_path_evidence_boost = int(best_path.get("evidence_boost", 0)) if isinstance(best_path, dict) else 0
    best_path_evidence_supported = bool(best_path.get("evidence_supported")) if isinstance(best_path, dict) else False
    topology_signature = "|".join(
        [
            ",".join(sorted(str(node.get("id") or "").strip().lower() for node in payload_nodes)),
            ",".join(
                sorted(
                    f"{str(edge.get('source') or '').strip().lower()}->{str(edge.get('target') or '').strip().lower()}"
                    for edge in payload_edges
                )
            ),
        ]
    )
    topology_hash = hashlib.sha1(topology_signature.encode("utf-8")).hexdigest()[:16] if topology_signature else ""

    meta: dict[str, Any] = {
        "node_count": len(payload_nodes),
        "edge_count": len(payload_edges),
        "path_count": len(payload_paths),
        "best_confidence": best_confidence,
        "best_base_confidence": best_base_confidence,
        "best_path_id": best_path_id,
        "best_rank_score": best_rank_score,
        "best_path_reason": best_path_reason,
        "best_path_evidence_boost": best_path_evidence_boost,
        "best_path_evidence_supported": best_path_evidence_supported,
        "topology_hash": topology_hash,
    }
    if scope_id is not None and str(scope_id).strip():
        meta["scope_id"] = str(scope_id).strip()

    return {
        "nodes": payload_nodes,
        "edges": payload_edges,
        "paths": payload_paths,
        "meta": meta,
    }
