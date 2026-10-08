from __future__ import annotations

from dataclasses import dataclass
from typing import Any


VALID_REPORT_DEPTHS = ("summary", "balanced", "deep")


@dataclass(frozen=True)
class ReportDepthConfig:
    name: str
    description: str
    max_suggestions_preview: int
    max_correlation_preview: int
    max_nuclei_preview: int
    max_screenshot_preview: int
    max_gobuster_preview: int
    max_ffuf_preview: int
    max_cve_preview: int
    max_katana_preview: int
    max_auth_preview: int
    max_waf_preview: int
    max_whatweb_preview: int
    max_graph_path_preview: int
    max_graph_edge_preview: int
    max_graph_node_preview: int
    show_raw_sections: bool
    expand_raw_by_default: bool
    show_graph_raw_tables: bool
    expand_graph_raw_tables: bool
    show_full_pipeline_details: bool
    show_enrichment_sections: bool
    show_discovery_detail_sections: bool
    dense_text: bool
    operator_notes: bool


_DEPTHS: dict[str, ReportDepthConfig] = {
    "summary": ReportDepthConfig(
        name="summary",
        description="decision-first view",
        max_suggestions_preview=3,
        max_correlation_preview=3,
        max_nuclei_preview=5,
        max_screenshot_preview=4,
        max_gobuster_preview=3,
        max_ffuf_preview=3,
        max_cve_preview=3,
        max_katana_preview=5,
        max_auth_preview=3,
        max_waf_preview=3,
        max_whatweb_preview=3,
        max_graph_path_preview=3,
        max_graph_edge_preview=0,
        max_graph_node_preview=0,
        show_raw_sections=False,
        expand_raw_by_default=False,
        show_graph_raw_tables=False,
        expand_graph_raw_tables=False,
        show_full_pipeline_details=False,
        show_enrichment_sections=False,
        show_discovery_detail_sections=False,
        dense_text=True,
        operator_notes=True,
    ),
    "balanced": ReportDepthConfig(
        name="balanced",
        description="operator review",
        max_suggestions_preview=8,
        max_correlation_preview=0,
        max_nuclei_preview=12,
        max_screenshot_preview=8,
        max_gobuster_preview=8,
        max_ffuf_preview=8,
        max_cve_preview=5,
        max_katana_preview=10,
        max_auth_preview=8,
        max_waf_preview=5,
        max_whatweb_preview=5,
        max_graph_path_preview=5,
        max_graph_edge_preview=10,
        max_graph_node_preview=10,
        show_raw_sections=True,
        expand_raw_by_default=False,
        show_graph_raw_tables=False,
        expand_graph_raw_tables=False,
        show_full_pipeline_details=True,
        show_enrichment_sections=True,
        show_discovery_detail_sections=True,
        dense_text=False,
        operator_notes=True,
    ),
    "deep": ReportDepthConfig(
        name="deep",
        description="full evidence view",
        max_suggestions_preview=0,
        max_correlation_preview=0,
        max_nuclei_preview=0,
        max_screenshot_preview=0,
        max_gobuster_preview=0,
        max_ffuf_preview=0,
        max_cve_preview=0,
        max_katana_preview=0,
        max_auth_preview=0,
        max_waf_preview=0,
        max_whatweb_preview=0,
        max_graph_path_preview=0,
        max_graph_edge_preview=0,
        max_graph_node_preview=0,
        show_raw_sections=True,
        expand_raw_by_default=True,
        show_graph_raw_tables=True,
        expand_graph_raw_tables=True,
        show_full_pipeline_details=True,
        show_enrichment_sections=True,
        show_discovery_detail_sections=True,
        dense_text=False,
        operator_notes=True,
    ),
}


def resolve_report_depth(value: Any = None) -> ReportDepthConfig:
    name = str(value or "balanced").strip().lower()
    if not name:
        name = "balanced"
    if name not in _DEPTHS:
        valid = ", ".join(VALID_REPORT_DEPTHS)
        raise ValueError(f"Invalid report depth '{value}'. Expected one of: {valid}.")
    return _DEPTHS[name]
