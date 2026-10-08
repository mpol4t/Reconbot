from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse, urlunparse


SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info", "unknown")
SEVERITY_RANK: dict[str, int] = {name: idx for idx, name in enumerate(SEVERITY_ORDER)}
SEVERITY_EDGE_CONFIDENCE: dict[str, int] = {
    "critical": 95,
    "high": 88,
    "medium": 76,
    "low": 64,
    "info": 56,
    "unknown": 52,
}
SEVERITY_RISK_WEIGHT: dict[str, int] = {
    "critical": 9,
    "high": 6,
    "medium": 3,
    "low": 1,
    "info": 0,
    "unknown": 1,
}
SEVERITY_PATH_EVIDENCE_WEIGHT: dict[str, int] = {
    "critical": 30,
    "high": 22,
    "medium": 14,
    "low": 7,
    "info": 3,
    "unknown": 5,
}

SURFACE_NODE_IDS: dict[str, str] = {
    "admin": "admin",
    "auth": "auth",
    "api": "api",
    "upload": "upload",
    "debug": "debug",
    "docs": "docs",
}
SURFACE_LABELS: dict[str, str] = {
    "admin": "Admin Yüzeyi",
    "auth": "Authentication Yüzeyi",
    "api": "API Yüzeyi",
    "upload": "Upload Yüzeyi",
    "debug": "Debug/Test Yüzeyi",
    "docs": "Docs/Dev Yüzeyi",
    "sensitive": "Sensitive Yüzey",
    "general": "Genel Nuclei Yüzeyi",
}
SURFACE_TEST_HINTS: dict[str, str] = {
    "admin": "Eşleşen endpoint’lerde access control, default creds ve admin workflow hardening durumunu doğrula.",
    "auth": "Nuclei ile eşleşen endpoint’lerde auth/session/reset akışlarını privilege bağlamıyla yeniden test et.",
    "api": "Nuclei ile eşleşen API route’larında object-level auth ve data exposure durumunu doğrula.",
    "upload": "Nuclei ile korele upload endpoint’lerinde upload parser/bypass kontrollerini önceliklendir.",
    "debug": "Nuclei tarafından öne çıkarılan debug/config disclosure ve verbose error path’lerini yeniden kontrol et.",
    "docs": "Docs/swagger/openapi exposure durumunu incele ve bağlı gizli endpoint’leri çıkar.",
    "sensitive": "En yüksek etkili Nuclei bulgularından başla ve exploit önkoşullarını doğrula.",
    "general": "En yüksek severity Nuclei template’lerini doğrula ve exploitability durumunu teyit et.",
}
BUCKET_TO_SURFACE: dict[str, str] = {
    "admin_like": "admin",
    "auth_like": "auth",
    "api_like": "api",
    "upload_like": "upload",
    "debug_like": "debug",
    "docs_like": "docs",
}
SURFACE_MATCH_TOKENS: dict[str, tuple[str, ...]] = {
    "admin": ("admin", "administrator"),
    "auth": ("auth", "login", "session", "oauth", "sso", "xmlrpc", "xml-rpc", "credential"),
    "api": ("api", "graphql", "rest", "endpoint"),
    "upload": ("upload", "import", "multipart", "file"),
    "debug": ("debug", "config leak", "verbose error", "test surface", "internal"),
    "docs": ("docs", "documentation", "swagger", "redoc", "openapi", "dev surface"),
}


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _normalize_severity(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw in {"critical", "high", "medium", "low", "info", "unknown"}:
        return raw
    aliases = {
        "informational": "info",
        "information": "info",
        "none": "unknown",
        "na": "unknown",
        "n/a": "unknown",
    }
    return aliases.get(raw, "unknown")


def _severity_sort_key(value: Any) -> int:
    sev = _normalize_severity(value)
    return SEVERITY_RANK.get(sev, SEVERITY_RANK["unknown"])


def _surface_sort_key(surface: str) -> tuple[int, str]:
    ordered = ("admin", "auth", "upload", "api", "debug", "docs", "sensitive", "general")
    try:
        idx = ordered.index(surface)
    except ValueError:
        idx = len(ordered)
    return (idx, surface)


def _canonical_endpoint(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.lower() == "unknown":
        return "unknown"
    try:
        parsed = urlparse(raw)
    except Exception:
        return raw.lower().rstrip("/")
    if parsed.scheme and parsed.netloc:
        path = parsed.path or "/"
        normalized = urlunparse(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                path if path else "/",
                "",
                "",
                "",
            )
        )
        return normalized.rstrip("/") or normalized
    return raw.lower().rstrip("/")


def _dedupe_preserve(items: list[str], limit: int | None = None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = str(item or "").strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
        if limit is not None and len(out) >= limit:
            break
    return out


def _merge_unique_text(existing: list[str], extra: list[str], limit: int) -> list[str]:
    merged = _dedupe_preserve(list(existing) + list(extra))
    return merged[:limit]


def _merge_unique_suggestions(
    existing: list[dict[str, Any]],
    extra: list[dict[str, Any]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in list(existing) + list(extra):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        surface = str(item.get("surface") or "").strip()
        if not title:
            continue
        key = (title.lower(), surface.lower())
        if key in seen:
            continue
        seen.add(key)
        merged.append(
            {
                "title": title,
                "priority": max(0, min(100, _safe_int(item.get("priority"), 0))),
                "surface": surface or "Nuclei",
            }
        )
        if len(merged) >= limit:
            break
    merged.sort(
        key=lambda item: (
            -_safe_int(item.get("priority"), 0),
            str(item.get("title") or "").lower(),
            str(item.get("surface") or "").lower(),
        )
    )
    return merged[:limit]


def _ensure_graph_shape(attack_graph: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    nodes = attack_graph.get("nodes")
    edges = attack_graph.get("edges")
    paths = attack_graph.get("paths")
    if not isinstance(nodes, list):
        nodes = []
    if not isinstance(edges, list):
        edges = []
    if not isinstance(paths, list):
        paths = []
    attack_graph["nodes"] = nodes
    attack_graph["edges"] = edges
    attack_graph["paths"] = paths
    return nodes, edges, paths


def _ensure_node(
    nodes: list[dict[str, Any]],
    *,
    node_id: str,
    label: str,
    node_type: str,
    count: int,
    details: list[str],
) -> dict[str, Any]:
    for node in nodes:
        if str(node.get("id") or "").strip() == node_id:
            node["label"] = str(node.get("label") or label)
            node["type"] = str(node.get("type") or node_type)
            node["count"] = max(_safe_int(node.get("count"), 0), max(0, count))
            existing_details = node.get("details", []) if isinstance(node.get("details"), list) else []
            node["details"] = _merge_unique_text(existing_details, details, limit=18)
            return node

    node = {
        "id": node_id,
        "label": label,
        "type": node_type,
        "count": max(0, count),
        "details": _dedupe_preserve(details, limit=18),
    }
    nodes.append(node)
    return node


def _ensure_edge(
    edges: list[dict[str, Any]],
    *,
    source: str,
    target: str,
    reason: str,
    confidence: int,
) -> None:
    for edge in edges:
        src = str(edge.get("from") or edge.get("source") or "").strip()
        dst = str(edge.get("to") or edge.get("target") or "").strip()
        if src == source and dst == target:
            edge["reason"] = str(edge.get("reason") or reason)
            edge["confidence"] = max(_safe_int(edge.get("confidence"), 0), max(0, min(100, confidence)))
            return
    edges.append(
        {
            "from": source,
            "to": target,
            "reason": reason,
            "confidence": max(0, min(100, confidence)),
        }
    )


def _ensure_path(
    paths: list[dict[str, Any]],
    *,
    name: str,
    confidence: int,
    sequence: list[str],
    why: str,
) -> None:
    norm = str(name or "").strip().lower()
    if not norm:
        return
    for path in paths:
        if str(path.get("name") or "").strip().lower() == norm:
            path["confidence"] = max(_safe_int(path.get("confidence"), 0), max(0, min(100, confidence)))
            if not str(path.get("why") or "").strip():
                path["why"] = why
            if not isinstance(path.get("sequence"), list) or not path.get("sequence"):
                path["sequence"] = sequence
            return
    paths.append(
        {
            "name": name,
            "confidence": max(0, min(100, confidence)),
            "sequence": sequence,
            "why": why,
        }
    )


def _normalize_surface_hint(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw in SURFACE_LABELS:
        return raw
    aliases = {
        "login": "auth",
        "authentication": "auth",
        "administrator": "admin",
        "doc": "docs",
        "documentation": "docs",
        "test": "debug",
    }
    return aliases.get(raw, "")


def _build_bucket_sets(classified_endpoints: dict[str, Any]) -> dict[str, set[str]]:
    bucket_sets: dict[str, set[str]] = {}
    for bucket, surface in BUCKET_TO_SURFACE.items():
        raw_values = classified_endpoints.get(bucket, [])
        values = raw_values if isinstance(raw_values, list) else []
        normalized = {_canonical_endpoint(item) for item in values}
        normalized = {item for item in normalized if item}
        bucket_sets[surface] = normalized
    return bucket_sets


def _infer_surfaces_for_endpoint(endpoint_norm: str, bucket_sets: dict[str, set[str]]) -> set[str]:
    if not endpoint_norm or endpoint_norm == "unknown":
        return set()

    matched: set[str] = set()
    for surface, values in bucket_sets.items():
        if endpoint_norm in values:
            matched.add(surface)
            continue
        for candidate in values:
            if not candidate or candidate == "unknown":
                continue
            if endpoint_norm.startswith(candidate.rstrip("/") + "/"):
                matched.add(surface)
                break
    return matched


def _format_severity_signal(severity_counts: dict[str, int]) -> str:
    parts: list[str] = []
    for severity in SEVERITY_ORDER:
        count = _safe_int(severity_counts.get(severity), 0)
        if count > 0:
            parts.append(f"{severity}={count}")
    return ", ".join(parts) if parts else "no-severity-signal"


def _highest_severity_from_counts(severity_counts: dict[str, int]) -> str:
    for severity in SEVERITY_ORDER:
        if _safe_int(severity_counts.get(severity), 0) > 0:
            return severity
    return "unknown"


def _extract_exploit_signal_points(group: dict[str, Any]) -> int:
    factors = group.get("review_priority_factors", [])
    if not isinstance(factors, list):
        return 0
    best_points = 0
    for factor in factors:
        text = str(factor or "").strip()
        if "exploit-practical signal" not in text.lower():
            continue
        match = re.search(r"\(\+(\d+)\)", text)
        if match:
            best_points = max(best_points, _safe_int(match.group(1), 0))
        elif text:
            best_points = max(best_points, 8)
    return min(20, best_points)


def _infer_surfaces_from_path(path: dict[str, Any]) -> tuple[set[str], bool]:
    surfaces: set[str] = set()
    has_nuclei = False
    label_map = {
        str(label or "").strip().lower(): surface
        for surface, label in SURFACE_LABELS.items()
        if surface in SURFACE_NODE_IDS
    }

    parts: list[str] = [str(path.get("name") or ""), str(path.get("why") or "")]
    sequence = path.get("sequence", [])
    if isinstance(sequence, list):
        parts.extend(str(item or "") for item in sequence)

    for part in parts:
        low = str(part or "").strip().lower()
        if not low:
            continue
        if "nuclei" in low:
            has_nuclei = True
        if low in label_map:
            surfaces.add(label_map[low])
        for label_text, surface in label_map.items():
            if label_text and label_text in low:
                surfaces.add(surface)
        for surface, tokens in SURFACE_MATCH_TOKENS.items():
            if any(token in low for token in tokens):
                surfaces.add(surface)

    return surfaces, has_nuclei


def augment_report_model_with_nuclei(
    *,
    attack_graph: dict[str, Any] | None,
    attack_chains: list[dict[str, Any]] | None,
    node_relationships: dict[str, Any] | None,
    classified_endpoints: dict[str, Any] | None,
    nuclei_entries: list[dict[str, Any]] | None,
    grouped_findings: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    graph = attack_graph if isinstance(attack_graph, dict) else {}
    graph = dict(graph)
    chains = attack_chains if isinstance(attack_chains, list) else []
    chains = [item for item in chains if isinstance(item, dict)]
    relation_map = node_relationships if isinstance(node_relationships, dict) else {}
    relation_map = {str(k): dict(v) for k, v in relation_map.items() if isinstance(v, dict)}
    classified = classified_endpoints if isinstance(classified_endpoints, dict) else {}
    raw_entries = nuclei_entries if isinstance(nuclei_entries, list) else []
    template_groups = grouped_findings if isinstance(grouped_findings, list) else []

    group_by_template: dict[str, dict[str, Any]] = {}
    for group in template_groups:
        if not isinstance(group, dict):
            continue
        template_id = str(group.get("template_id") or "").strip().lower()
        if template_id:
            group_by_template[template_id] = group

    bucket_sets = _build_bucket_sets(classified)
    normalized_entries: list[dict[str, Any]] = []
    seen_entry_keys: set[tuple[str, str, str, str]] = set()
    for item in raw_entries:
        if not isinstance(item, dict):
            continue

        template_id = str(item.get("template_id") or item.get("id") or "Unknown").strip() or "Unknown"
        name = str(item.get("name") or template_id).strip() or template_id
        severity = _normalize_severity(item.get("severity"))
        endpoint = str(item.get("endpoint") or item.get("matched_at") or "unknown").strip() or "unknown"
        endpoint_norm = _canonical_endpoint(endpoint)
        dedup_key = (template_id.lower(), endpoint_norm.lower(), severity, name.lower())
        if dedup_key in seen_entry_keys:
            continue
        seen_entry_keys.add(dedup_key)

        group = group_by_template.get(template_id.lower(), {})
        highest_surface = _normalize_surface_hint(group.get("highest_surface"))
        review_score = _safe_int(group.get("review_priority_score"), 0)
        surfaces = _infer_surfaces_for_endpoint(endpoint_norm, bucket_sets)
        if highest_surface:
            if highest_surface == "sensitive":
                surfaces.update({"admin", "auth"})
                surfaces.add("sensitive")
            else:
                surfaces.add(highest_surface)
        if not surfaces:
            surfaces.add("general")

        normalized_entries.append(
            {
                "template_id": template_id,
                "name": name,
                "severity": severity,
                "endpoint": endpoint,
                "endpoint_norm": endpoint_norm,
                "surfaces": sorted(surfaces, key=_surface_sort_key),
                "review_score": review_score,
                "finding_confidence_score": max(
                    0,
                    min(100, _safe_int(item.get("finding_confidence_score"), 65)),
                ),
                "trust_level": str(item.get("trust_level") or "").strip().lower() or "unknown",
            }
        )

    severity_counts: dict[str, int] = {severity: 0 for severity in SEVERITY_ORDER}
    for entry in normalized_entries:
        severity_counts[entry["severity"]] = severity_counts.get(entry["severity"], 0) + 1

    if not normalized_entries:
        for group in template_groups:
            if not isinstance(group, dict):
                continue
            severity = _normalize_severity(group.get("severity"))
            count = max(1, _safe_int(group.get("endpoint_count"), 1))
            severity_counts[severity] = severity_counts.get(severity, 0) + count

    surface_stats: dict[str, dict[str, Any]] = {}

    def _ensure_surface_stat(surface: str) -> dict[str, Any]:
        normalized_surface = surface if surface in SURFACE_LABELS else "general"
        if normalized_surface not in surface_stats:
            surface_stats[normalized_surface] = {
                "finding_count": 0,
                "templates": set(),
                "endpoints": [],
                "severity_counts": {severity: 0 for severity in SEVERITY_ORDER},
                "max_review_score": 0,
                "confidence_sum": 0,
                "confidence_count": 0,
            }
        return surface_stats[normalized_surface]

    for entry in normalized_entries:
        for surface in entry["surfaces"]:
            stat = _ensure_surface_stat(surface)
            stat["finding_count"] += 1
            stat["templates"].add(str(entry["template_id"]))
            stat["severity_counts"][entry["severity"]] = stat["severity_counts"].get(entry["severity"], 0) + 1
            stat["max_review_score"] = max(stat["max_review_score"], _safe_int(entry["review_score"], 0))
            stat["confidence_sum"] = _safe_int(stat.get("confidence_sum"), 0) + _safe_int(entry.get("finding_confidence_score"), 65)
            stat["confidence_count"] = _safe_int(stat.get("confidence_count"), 0) + 1
            endpoint_text = str(entry["endpoint"] or "").strip()
            if endpoint_text and endpoint_text.lower() != "unknown":
                stat["endpoints"].append(endpoint_text)

    for group in template_groups:
        if not isinstance(group, dict):
            continue
        template_id = str(group.get("template_id") or "").strip()
        if not template_id:
            continue
        surface = _normalize_surface_hint(group.get("highest_surface")) or "general"
        stat = _ensure_surface_stat(surface)
        stat["templates"].add(template_id)
        stat["max_review_score"] = max(stat["max_review_score"], _safe_int(group.get("review_priority_score"), 0))
        if not normalized_entries:
            group_severity = _normalize_severity(group.get("severity"))
            fallback_count = max(1, _safe_int(group.get("endpoint_count"), 1))
            stat["finding_count"] += fallback_count
            stat["severity_counts"][group_severity] = stat["severity_counts"].get(group_severity, 0) + fallback_count
        endpoints = group.get("endpoints", [])
        if isinstance(endpoints, list):
            for endpoint in endpoints:
                text = str(endpoint or "").strip()
                if text and text.lower() != "unknown":
                    stat["endpoints"].append(text)

    total_findings = sum(_safe_int(severity_counts.get(severity), 0) for severity in SEVERITY_ORDER)
    weighted_risk = sum(
        _safe_int(severity_counts.get(severity), 0) * SEVERITY_RISK_WEIGHT[severity]
        for severity in SEVERITY_ORDER
    )
    risk_points = 0
    risk_reason = ""
    if total_findings > 0:
        risk_points = min(
            30,
            weighted_risk
            + (4 if _safe_int(severity_counts.get("critical"), 0) > 0 else 0)
            + (2 if _safe_int(severity_counts.get("high"), 0) > 0 else 0),
        )
        risk_reason = f"Nuclei ağırlıklı severity sinyali ({_format_severity_signal(severity_counts)})."

    priority_items: list[dict[str, Any]] = []
    for surface, stat in surface_stats.items():
        template_count = len(stat["templates"])
        finding_count = _safe_int(stat.get("finding_count"), 0)
        if template_count <= 0 and finding_count <= 0:
            continue

        surface_severity_counts = stat.get("severity_counts", {})
        severity_score = (
            _safe_int(surface_severity_counts.get("critical"), 0) * 12
            + _safe_int(surface_severity_counts.get("high"), 0) * 8
            + _safe_int(surface_severity_counts.get("medium"), 0) * 5
            + _safe_int(surface_severity_counts.get("low"), 0) * 2
            + _safe_int(surface_severity_counts.get("info"), 0)
            + _safe_int(surface_severity_counts.get("unknown"), 0)
        )
        derived_score = min(100, 35 + min(30, severity_score) + min(15, template_count * 2))
        priority_score = min(100, max(derived_score, _safe_int(stat.get("max_review_score"), 0)))
        priority_count = template_count if template_count > 0 else finding_count
        signal_summary = _format_severity_signal(surface_severity_counts)
        why = (
            f"{SURFACE_LABELS.get(surface, surface)} üzerinde Nuclei korelasyonu "
            f"(templates={template_count}, bulgular={finding_count}; {signal_summary})."
        )
        priority_items.append(
            {
                "label": f"Nuclei {SURFACE_LABELS.get(surface, 'Yüzey')}",
                "count": priority_count,
                "priority_score": priority_score,
                "why": why,
                "test_first": SURFACE_TEST_HINTS.get(surface, SURFACE_TEST_HINTS["general"]),
                "signals": [
                    f"surface={surface}",
                    f"templates={template_count}",
                    f"bulgular={finding_count}",
                    signal_summary,
                    f"max_review_score={_safe_int(stat.get('max_review_score'), 0)}",
                ],
            }
        )

    priority_items.sort(
        key=lambda item: (
            -_safe_int(item.get("priority_score"), 0),
            -_safe_int(item.get("count"), 0),
            str(item.get("label") or "").lower(),
        )
    )

    nodes, edges, paths = _ensure_graph_shape(graph)
    node_label_by_id: dict[str, str] = {
        str(node.get("id") or ""): str(node.get("label") or "")
        for node in nodes
        if isinstance(node, dict) and str(node.get("id") or "").strip()
    }

    if total_findings > 0:
        top_templates: list[str] = []
        for group in sorted(
            [item for item in template_groups if isinstance(item, dict)],
            key=lambda item: (
                -_safe_int(item.get("review_priority_score"), 0),
                _severity_sort_key(item.get("severity")),
                str(item.get("name") or item.get("template_id") or "").lower(),
            ),
        ):
            label = str(group.get("name") or group.get("template_id") or "").strip()
            if label:
                top_templates.append(label)
        summary_details = [
            f"toplam_nuclei_bulgusu={total_findings}",
            _format_severity_signal(severity_counts),
        ]
        if top_templates:
            summary_details.append("öne çıkan template’ler: " + ", ".join(_dedupe_preserve(top_templates, limit=4)))

        nuclei_node = _ensure_node(
            nodes,
            node_id="nuclei_findings",
            label="Nuclei Bulguları",
            node_type="finding",
            count=total_findings,
            details=summary_details,
        )
        node_label_by_id["nuclei_findings"] = str(nuclei_node.get("label") or "Nuclei Bulguları")

        for severity in SEVERITY_ORDER:
            count = _safe_int(severity_counts.get(severity), 0)
            if count <= 0:
                continue
            severity_templates = [
                str(group.get("name") or group.get("template_id") or "").strip()
                for group in template_groups
                if isinstance(group, dict) and _normalize_severity(group.get("severity")) == severity
            ]
            node_id = f"nuclei_{severity}"
            node_label = f"Nuclei {severity.title()} Bulguları"
            severity_node = _ensure_node(
                nodes,
                node_id=node_id,
                label=node_label,
                node_type="finding",
                count=count,
                details=_dedupe_preserve(
                    [f"{count} bulgu"] + [f"template: {name}" for name in severity_templates[:4]],
                    limit=12,
                ),
            )
            node_label_by_id[node_id] = str(severity_node.get("label") or node_label)
            _ensure_edge(
                edges,
                source="nuclei_findings",
                target=node_id,
                reason=f"Nuclei bulguları severity bucket: {severity}.",
                confidence=SEVERITY_EDGE_CONFIDENCE[severity],
            )

        for surface, stat in sorted(surface_stats.items(), key=lambda item: _surface_sort_key(item[0])):
            surface_node_id = SURFACE_NODE_IDS.get(surface, "")
            if not surface_node_id:
                continue
            if surface_node_id not in node_label_by_id:
                continue
            finding_count = _safe_int(stat.get("finding_count"), 0)
            if finding_count <= 0:
                continue
            surface_severity_counts = stat.get("severity_counts", {})
            confidence = min(
                90,
                55
                + (15 if _safe_int(surface_severity_counts.get("critical"), 0) > 0 else 0)
                + (10 if _safe_int(surface_severity_counts.get("high"), 0) > 0 else 0)
                + (5 if _safe_int(surface_severity_counts.get("medium"), 0) > 0 else 0),
            )
            _ensure_edge(
                edges,
                source=surface_node_id,
                target="nuclei_findings",
                reason=(
                    f"Nuclei bulguları {SURFACE_LABELS.get(surface, surface).lower()} ile korele "
                    f"({finding_count} bulgu)."
                ),
                confidence=confidence,
            )

        best_surface: str | None = None
        best_surface_score = -1
        for surface, stat in surface_stats.items():
            if surface not in SURFACE_NODE_IDS:
                continue
            if SURFACE_NODE_IDS[surface] not in node_label_by_id:
                continue
            severity_rank_score = 0
            for severity in SEVERITY_ORDER:
                if _safe_int(stat.get("severity_counts", {}).get(severity), 0) > 0:
                    severity_rank_score = len(SEVERITY_ORDER) - SEVERITY_RANK[severity]
                    break
            score = severity_rank_score * 1000 + _safe_int(stat.get("finding_count"), 0)
            if score > best_surface_score:
                best_surface_score = score
                best_surface = surface

        if best_surface:
            best_surface_id = SURFACE_NODE_IDS[best_surface]
            best_surface_label = node_label_by_id.get(best_surface_id, SURFACE_LABELS.get(best_surface, best_surface))
            best_severity = "unknown"
            for severity in SEVERITY_ORDER:
                if _safe_int(surface_stats.get(best_surface, {}).get("severity_counts", {}).get(severity), 0) > 0:
                    best_severity = severity
                    break
            severity_node_id = f"nuclei_{best_severity}"
            severity_label = node_label_by_id.get(
                severity_node_id,
                f"Nuclei {best_severity.title()} Bulguları",
            )
            path_confidence = min(94, 60 + _safe_int(risk_points, 0))
            _ensure_path(
                paths,
                name=f"{best_surface_label} → Nuclei {best_severity.title()}",
                confidence=path_confidence,
                sequence=[best_surface_label, "Nuclei Bulguları", severity_label],
                why=(
                    f"Nuclei bulguları {best_surface_label.lower()} üzerinde yoğunlaşıyor "
                    f"ve {best_severity} severity sinyali taşıyor."
                ),
            )

    chain_name = "Nuclei → Hedefli Doğrulama"
    if total_findings > 0 and not any(str(item.get("name") or "").strip().lower() == chain_name.lower() for item in chains):
        chains.append(
            {
                "name": chain_name,
                "confidence": min(100, 60 + _safe_int(risk_points, 0)),
                "signals": [
                    f"nuclei_total_findings={total_findings}",
                    _format_severity_signal(severity_counts),
                ],
                "why": "Nuclei çıktısı, öncelik sırasıyla doğrulanması gereken aksiyon alınabilir bulgular üretti.",
                "next_tests": [
                    "en yüksek severity bulguları yeniden üret",
                    "exploit önkoşullarını doğrula",
                    "impact ve false-positive durumunu teyit et",
                ],
            }
        )

    def _ensure_relation(node_id: str, default_label: str) -> dict[str, Any]:
        rel = relation_map.get(node_id)
        if not isinstance(rel, dict):
            rel = {}
        rel["node_id"] = str(rel.get("node_id") or node_id)
        rel["node_label"] = str(rel.get("node_label") or default_label)
        rel["related_suggestions"] = rel.get("related_suggestions", []) if isinstance(rel.get("related_suggestions"), list) else []
        rel["related_cves"] = rel.get("related_cves", []) if isinstance(rel.get("related_cves"), list) else []
        rel["related_nuclei_tags"] = rel.get("related_nuclei_tags", []) if isinstance(rel.get("related_nuclei_tags"), list) else []
        rel["related_endpoints"] = rel.get("related_endpoints", []) if isinstance(rel.get("related_endpoints"), list) else []
        rel["related_technologies"] = rel.get("related_technologies", []) if isinstance(rel.get("related_technologies"), list) else []
        relation_map[node_id] = rel
        return rel

    template_suggestions: list[dict[str, Any]] = []
    for group in sorted(
        [item for item in template_groups if isinstance(item, dict)],
        key=lambda item: (
            -_safe_int(item.get("review_priority_score"), 0),
            _severity_sort_key(item.get("severity")),
            str(item.get("name") or item.get("template_id") or "").lower(),
        ),
    ):
        title = str(group.get("name") or group.get("template_id") or "").strip()
        if not title:
            continue
        template_suggestions.append(
            {
                "title": title,
                "priority": _safe_int(group.get("review_priority_score"), 0),
                "surface": str(group.get("highest_surface") or "nuclei"),
            }
        )

    endpoints_all = _dedupe_preserve(
        [str(item.get("endpoint") or "").strip() for item in normalized_entries if str(item.get("endpoint") or "").strip()],
        limit=25,
    )
    nuclei_tags = [f"severity:{severity}" for severity in SEVERITY_ORDER if _safe_int(severity_counts.get(severity), 0) > 0]
    nuclei_tags.extend(f"surface:{surface}" for surface in sorted(surface_stats.keys(), key=_surface_sort_key))
    nuclei_tags = _dedupe_preserve(nuclei_tags, limit=20)

    if total_findings > 0:
        nuclei_rel = _ensure_relation("nuclei_findings", node_label_by_id.get("nuclei_findings", "Nuclei Bulguları"))
        nuclei_rel["related_suggestions"] = _merge_unique_suggestions(
            nuclei_rel["related_suggestions"],
            template_suggestions[:8],
            limit=8,
        )
        nuclei_rel["related_endpoints"] = _merge_unique_text(nuclei_rel["related_endpoints"], endpoints_all, limit=25)
        nuclei_rel["related_nuclei_tags"] = _merge_unique_text(nuclei_rel["related_nuclei_tags"], nuclei_tags, limit=20)

        for severity in SEVERITY_ORDER:
            node_id = f"nuclei_{severity}"
            if node_id not in node_label_by_id:
                continue
            severity_rel = _ensure_relation(node_id, node_label_by_id.get(node_id, node_id))
            severity_endpoints = _dedupe_preserve(
                [
                    str(item.get("endpoint") or "").strip()
                    for item in normalized_entries
                    if _normalize_severity(item.get("severity")) == severity
                ],
                limit=25,
            )
            severity_suggestions = [
                {
                    "title": str(group.get("name") or group.get("template_id") or "Nuclei template"),
                    "priority": _safe_int(group.get("review_priority_score"), 0),
                    "surface": str(group.get("highest_surface") or "nuclei"),
                }
                for group in template_groups
                if isinstance(group, dict) and _normalize_severity(group.get("severity")) == severity
            ]
            severity_rel["related_suggestions"] = _merge_unique_suggestions(
                severity_rel["related_suggestions"],
                severity_suggestions[:6],
                limit=6,
            )
            severity_rel["related_endpoints"] = _merge_unique_text(
                severity_rel["related_endpoints"],
                severity_endpoints,
                limit=25,
            )
            severity_rel["related_nuclei_tags"] = _merge_unique_text(
                severity_rel["related_nuclei_tags"],
                [f"severity:{severity}"],
                limit=20,
            )

        for surface, node_id in SURFACE_NODE_IDS.items():
            if surface not in surface_stats:
                continue
            if node_id not in node_label_by_id:
                continue
            stat = surface_stats[surface]
            if _safe_int(stat.get("finding_count"), 0) <= 0:
                continue
            surface_rel = _ensure_relation(node_id, node_label_by_id.get(node_id, node_id))
            signal_summary = _format_severity_signal(stat.get("severity_counts", {}))
            surface_rel["related_suggestions"] = _merge_unique_suggestions(
                surface_rel["related_suggestions"],
                [
                    {
                        "title": f"Nuclei korelasyon sinyali ({_safe_int(stat.get('finding_count'), 0)} bulgu)",
                        "priority": min(100, 50 + _safe_int(stat.get("max_review_score"), 0) // 2),
                        "surface": "Nuclei",
                    }
                ],
                limit=8,
            )
            surface_rel["related_endpoints"] = _merge_unique_text(
                surface_rel["related_endpoints"],
                _dedupe_preserve(stat.get("endpoints", []), limit=25),
                limit=25,
            )
            surface_rel["related_nuclei_tags"] = _merge_unique_text(
                surface_rel["related_nuclei_tags"],
                [f"surface:{surface}", signal_summary],
                limit=20,
            )

    surface_evidence: dict[str, dict[str, Any]] = {}
    for surface, stat in surface_stats.items():
        if surface not in SURFACE_NODE_IDS:
            continue
        severity_counts_for_surface = (
            stat.get("severity_counts", {})
            if isinstance(stat.get("severity_counts"), dict)
            else {}
        )
        unique_eps = _dedupe_preserve(
            [str(item or "").strip() for item in (stat.get("endpoints", []) or [])],
            limit=None,
        )
        surface_evidence[surface] = {
            "surface": surface,
            "finding_count": _safe_int(stat.get("finding_count"), 0),
            "max_review_score": _safe_int(stat.get("max_review_score"), 0),
            "severity_peak": _highest_severity_from_counts(severity_counts_for_surface),
            "severity_weight": SEVERITY_PATH_EVIDENCE_WEIGHT.get(
                _highest_severity_from_counts(severity_counts_for_surface),
                SEVERITY_PATH_EVIDENCE_WEIGHT["unknown"],
            ),
            "unique_endpoints": len(unique_eps),
            "exploit_points": 0,
            "avg_confidence": (
                _safe_int(stat.get("confidence_sum"), 0) / max(1, _safe_int(stat.get("confidence_count"), 0))
            ),
        }

    for group in template_groups:
        if not isinstance(group, dict):
            continue
        surface_hint = _normalize_surface_hint(group.get("highest_surface")) or "general"
        group_surfaces: list[str] = []
        if surface_hint == "sensitive":
            group_surfaces = ["admin", "auth"]
        elif surface_hint in SURFACE_NODE_IDS:
            group_surfaces = [surface_hint]
        exploit_points = _extract_exploit_signal_points(group)
        for surface in group_surfaces:
            evidence = surface_evidence.get(surface)
            if not evidence:
                continue
            evidence["exploit_points"] = max(
                _safe_int(evidence.get("exploit_points"), 0),
                exploit_points,
            )
            evidence["max_review_score"] = max(
                _safe_int(evidence.get("max_review_score"), 0),
                _safe_int(group.get("review_priority_score"), 0),
            )

    def _score_evidence_for_surfaces(
        path_surfaces: set[str],
        *,
        has_nuclei_marker: bool,
    ) -> tuple[int, str]:
        matched = [
            surface_evidence[surface]
            for surface in sorted(path_surfaces, key=_surface_sort_key)
            if surface in surface_evidence
            and _safe_int(surface_evidence[surface].get("finding_count"), 0) > 0
        ]
        if not matched:
            return (0, "Bu path ile doğrudan Nuclei kanıtı eşleşmedi.")

        matched.sort(
            key=lambda item: (
                -_safe_int(item.get("severity_weight"), 0),
                -_safe_int(item.get("max_review_score"), 0),
                -_safe_int(item.get("finding_count"), 0),
                -_safe_int(item.get("unique_endpoints"), 0),
                str(item.get("surface") or ""),
            )
        )
        primary = matched[0]
        primary_score = (
            _safe_int(primary.get("severity_weight"), 0)
            + min(16, _safe_int(primary.get("finding_count"), 0) * 2)
            + min(12, _safe_int(primary.get("unique_endpoints"), 0) * 2)
            + min(14, _safe_int(primary.get("max_review_score"), 0) // 7)
            + min(12, _safe_int(primary.get("exploit_points"), 0))
        )
        secondary_score = min(
            12,
            sum(
                min(4, _safe_int(item.get("finding_count"), 0))
                + min(3, _safe_int(item.get("unique_endpoints"), 0))
                for item in matched[1:]
            ),
        )
        direct_bonus = 10 if has_nuclei_marker else 0
        confidence_weight = float(primary.get("avg_confidence", 65) or 65)
        confidence_factor = max(0.25, min(1.0, confidence_weight / 100.0))
        evidence_boost_raw = primary_score + secondary_score + direct_bonus
        evidence_boost = min(70, int(round(evidence_boost_raw * confidence_factor)))
        summary = (
            f"{SURFACE_LABELS.get(str(primary.get('surface') or ''), 'yüzey')} üzerinde Nuclei kanıtı "
            f"({str(primary.get('severity_peak') or 'unknown')} severity, "
            f"findings={_safe_int(primary.get('finding_count'), 0)}, "
            f"endpoints={_safe_int(primary.get('unique_endpoints'), 0)}, "
            f"confidence={int(round(confidence_weight))}/100)."
        )
        if _safe_int(primary.get("exploit_points"), 0) > 0:
            summary += " Exploit açısından pratik sinyal mevcut."
        if len(matched) > 1:
            summary += f" +{len(matched) - 1} korele yüzey."
        return (evidence_boost, summary)

    for path in paths:
        if not isinstance(path, dict):
            continue
        base_conf = _safe_int(path.get("confidence"), 0)
        path_surfaces, path_has_nuclei = _infer_surfaces_from_path(path)
        evidence_boost, evidence_summary = _score_evidence_for_surfaces(
            path_surfaces,
            has_nuclei_marker=path_has_nuclei,
        )
        confidence_boost = min(35, int(round(evidence_boost * 0.55)))
        adjusted_conf = min(100, base_conf + confidence_boost)
        rank_score = (base_conf * 7) + (evidence_boost * 6) + (2 if path_has_nuclei and evidence_boost > 0 else 0)
        path["base_confidence"] = base_conf
        path["evidence_boost"] = evidence_boost
        path["evidence_supported"] = evidence_boost > 0
        path["confidence"] = adjusted_conf
        path["rank_score"] = rank_score
        if evidence_boost > 0:
            path["selection_reason"] = (
                f"Yapısal confidence {base_conf}/100; "
                f"kanıt artışı +{confidence_boost}/100. {evidence_summary}"
            )
        else:
            path["selection_reason"] = f"Yapısal confidence {base_conf}/100; bu path ile doğrudan Nuclei kanıtı eşleşmedi."

    for chain in chains:
        if not isinstance(chain, dict):
            continue
        chain_text_parts: list[str] = [
            str(chain.get("name") or ""),
            str(chain.get("why") or ""),
        ]
        signals = chain.get("signals", [])
        if isinstance(signals, list):
            chain_text_parts.extend(str(item or "") for item in signals)
        chain_surfaces, chain_has_nuclei = _infer_surfaces_from_path(
            {
                "name": " ".join(chain_text_parts),
                "sequence": [],
                "why": "",
            }
        )
        evidence_boost, evidence_summary = _score_evidence_for_surfaces(
            chain_surfaces,
            has_nuclei_marker=chain_has_nuclei,
        )
        base_conf = _safe_int(chain.get("confidence"), 0)
        confidence_boost = min(28, int(round(evidence_boost * 0.45)))
        adjusted_conf = min(100, base_conf + confidence_boost)
        rank_score = (base_conf * 7) + (evidence_boost * 6)
        chain["base_confidence"] = base_conf
        chain["evidence_boost"] = evidence_boost
        chain["confidence"] = adjusted_conf
        chain["rank_score"] = rank_score
        if evidence_boost > 0:
            chain["selection_reason"] = (
                f"Yapısal confidence {base_conf}/100; "
                f"kanıt artışı +{confidence_boost}/100. {evidence_summary}"
            )
            why_text = str(chain.get("why") or "").strip()
            evidence_note = f"Kanıta göre ayarlandı: {evidence_summary}"
            if evidence_note.lower() not in why_text.lower():
                chain["why"] = (why_text + " " + evidence_note).strip()
        else:
            chain["selection_reason"] = f"Yapısal confidence {base_conf}/100; bu path ile doğrudan Nuclei kanıtı eşleşmedi."

    chains = sorted(
        chains,
        key=lambda item: (
            -_safe_int(item.get("rank_score"), _safe_int(item.get("confidence"), 0)),
            -_safe_int(item.get("confidence"), 0),
            str(item.get("name") or "").lower(),
        ),
    )
    paths.sort(
        key=lambda item: (
            -_safe_int(item.get("rank_score"), _safe_int(item.get("confidence"), 0)),
            -_safe_int(item.get("confidence"), 0),
            str(item.get("name") or "").lower(),
        )
    )

    return {
        "attack_graph": graph,
        "attack_chains": chains,
        "node_relationships": relation_map,
        "priority_items": priority_items,
        "risk_points": risk_points,
        "risk_reason": risk_reason,
    }
