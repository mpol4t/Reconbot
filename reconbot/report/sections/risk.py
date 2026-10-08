from __future__ import annotations
from dataclasses import dataclass

from typing import Any

@dataclass(frozen=True)
class RiskSectionData:
    coverage_degraded_warning_html: str
    coverage_status_label: str
    closed_surface_discovery_tools: list[str]
    decision_confidence: str
    discovery_scope_label: str
    discovery_reliability: str
    has_any_tier_failure: bool
    risk_band: str
    risk_reasons: list[str]
    risk_score: int
    run_integrity_label: str
    structural_confidence: int
    tool_coverage_label: str

def render_risk_section_data(
    data: RiskSectionData,
    *,
    html_escape,
    txt,
) -> str:
    section_html = ""
    confidence_labels = {"high": "yüksek", "medium": "orta", "low": "düşük"}
    decision_confidence_label = confidence_labels.get(
        str(data.decision_confidence or "").strip().lower(),
        str(data.decision_confidence or ""),
    )
    # --- Risk Score Overview ---
    risk_driver_preview_items = [
        f"<li><strong>Sürücü:</strong> {html_escape((reason.split(': ', 1)[1] if reason.startswith('+') and ': ' in reason else reason))}</li>"
        for reason in data.risk_reasons[:5]
    ]
    risk_driver_preview_html = (
        "<ul class='compact-list'>" + "".join(risk_driver_preview_items) + "</ul>"
        if risk_driver_preview_items
        else "<ul class='compact-list'><li>Güçlü risk sürücüsü üretilmedi.</li></ul>"
    )
    risk_driver_remaining_items = [
        f"<li><strong>Sürücü:</strong> {html_escape((reason.split(': ', 1)[1] if reason.startswith('+') and ': ' in reason else reason))}</li>"
        for reason in data.risk_reasons[5:]
    ]
    risk_driver_remaining_html = ""
    if risk_driver_remaining_items:
        risk_driver_remaining_html = (
            "<details class='show-more'>"
            f"<summary>Tüm risk sürücülerini göster ({len(data.risk_reasons)})</summary>"
            f"<ul class='compact-list'>{''.join(risk_driver_remaining_items)}</ul>"
            "</details>"
        )

    section_html += f"""
    <div class="section report-depth-body-deep-only" data-depth-body="deep">
        <h2>{html_escape(txt("risk_engine_title"))}</h2>
        <p class="note">
        {html_escape(txt("risk_engine_note"))}
        </p>
        <table>
            <tr>
                <th>Metrik</th>
                <th>Değer</th>
            </tr>
            <tr>
                <td><strong>Risk Skoru</strong></td>
                <td>{data.risk_score} / 100</td>
            </tr>
            <tr>
                <td><strong>Bant</strong></td>
                <td>{data.risk_band}</td>
            </tr>
            <tr>
                <td><strong>Karar Güveni</strong></td>
                <td>{html_escape(decision_confidence_label)}</td>
            </tr>
            <tr>
                <td><strong>Discovery Kapsamı</strong></td>
                <td>{html_escape(data.discovery_scope_label or data.discovery_reliability)}</td>
            </tr>
            <tr>
                <td><strong>Rapor Bütünlüğü</strong></td>
                <td>{html_escape(data.run_integrity_label or "tamamlandı")}</td>
            </tr>
            <tr>
                <td><strong>Araç Kapsamı</strong></td>
                <td>{html_escape(data.tool_coverage_label or data.coverage_status_label)}</td>
            </tr>
            <tr>
                <td><strong>Kapsama Durumu</strong></td>
                <td>{html_escape(data.coverage_status_label)}</td>
            </tr>
            <tr>
                <td><strong>Kapalı Yüzey Keşfi Araçları</strong></td>
                <td>{html_escape(", ".join(data.closed_surface_discovery_tools) if data.closed_surface_discovery_tools else "Yok")}</td>
            </tr>
        </table>
        {data.coverage_degraded_warning_html if data.has_any_tier_failure else ''}
        <h3>Neden önemli?</h3>
        {risk_driver_preview_html}
        {risk_driver_remaining_html}
    </div>
    """
    return section_html

def render_risk_section(context: dict[str, Any]) -> str:
    return render_risk_section_data(
        RiskSectionData(
            coverage_degraded_warning_html=context.get("coverage_degraded_warning_html", ""),
            coverage_status_label=context.get("coverage_status_label", ""),
            closed_surface_discovery_tools=list(context.get("closed_surface_discovery_tools") or []),
            decision_confidence=context.get("decision_confidence_display", context.get("decision_confidence", "")),
            discovery_scope_label=context.get("discovery_scope_label", ""),
            discovery_reliability=context.get("discovery_reliability", ""),
            has_any_tier_failure=bool(context.get("has_any_tier_failure")),
            risk_band=context.get("risk_band", ""),
            risk_reasons=list(context.get("risk_reasons") or []),
            risk_score=int(context.get("risk_score") or 0),
            run_integrity_label="tamamlandı" if context.get("run_state_value") == "completed" else str(context.get("run_state_value") or "bilinmiyor"),
            structural_confidence=int(context.get("structural_confidence") or 0),
            tool_coverage_label=context.get("tool_coverage_label", ""),
        ),
        html_escape=context.get("_html_escape"),
        txt=context.get("_txt"),
    )
