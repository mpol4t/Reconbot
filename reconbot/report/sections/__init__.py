from __future__ import annotations

from reconbot.report.html_helpers import (
    pill,
    render_progressive_list,
    render_progressive_table,
    render_report_group,
    render_report_panel,
    render_score_pill,
    render_summary_strip_counts,
    risk_band_tone,
    truncate_text,
)

from .attack_chains import render_attack_chains_section
from .correlation import render_correlation_insights_section
from .cve import render_cve_sections
from .graph_tables import render_graph_tables_section
from .ip_enrichment import render_ip_enrichment_section
from .nuclei import render_nuclei_findings_section as _render_nuclei_findings_section
from .priority import render_priority_section
from .relationships import render_relationships_section
from .risk import render_risk_section
from .screenshots import render_screenshots_section
from .suggestions_section import render_suggestions_section
from .surface import render_surface_section
from .technology import render_technology_section

__all__ = [
    "pill",
    "render_progressive_list",
    "render_progressive_table",
    "render_report_group",
    "render_report_panel",
    "render_score_pill",
    "render_summary_strip_counts",
    "risk_band_tone",
    "truncate_text",
    "render_post_discovery_sections",
    "render_nuclei_findings_section",
]

def render_post_discovery_sections(context: dict[str, object]) -> str:
    return "".join([
        render_cve_sections(context),
        render_suggestions_section(context),
        render_screenshots_section(context),
        render_correlation_insights_section(context),
        render_relationships_section(context),
        render_graph_tables_section(context),
        render_technology_section(context),
        render_risk_section(context),
        render_attack_chains_section(context),
        render_priority_section(context),
        render_surface_section(context),
    ])

def render_nuclei_findings_section(context: dict[str, object]) -> str:
    return _render_nuclei_findings_section(context)
