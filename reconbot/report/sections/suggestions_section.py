from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from reconbot.report.suggestions import operator_text_to_english as _localize_report_text

@dataclass(frozen=True)
class SuggestionsSectionData:
    context_aware_suggestions: list[dict[str, Any]]
    discovery_reliability: str
    manual_nuclei_next_run: bool
    report_base_url: str

def render_suggestions_section_data(
    data: SuggestionsSectionData,
    *,
    html_escape,
    pill,
    render_detail_value,
    render_progressive_table,
    render_summary_strip_counts,
    truncate_text,
    txt,
    preview_rows: int = 8,
) -> str:
    section_html = ""

    def _localized_detail(value: Any) -> Any:
        text = str(value or "").strip()
        if text.startswith(("http://", "https://", "/")):
            return value
        return _localize_report_text(text)

    def _render_urls(values: Any) -> str:
        urls = [str(item or "").strip() for item in values] if isinstance(values, list) else []
        urls = [item for item in urls if item]
        if not urls:
            return "<span class=\"note\">Bu öneri genel bağlamdan üretildi; doğrudan URL kanıtı yok.</span>"
        rendered = []
        for url in urls[:12]:
            rendered.append(
                "<li class=\"wrap-cell\" "
                f"title=\"{html_escape(url)}\">"
                f"{render_detail_value(url, data.report_base_url)}"
                "</li>"
            )
        return f"<ul class=\"compact-list suggestion-url-list\">{''.join(rendered)}</ul>"

    def _render_evidence_refs(values: Any) -> str:
        refs = values if isinstance(values, list) else []
        if not refs:
            return "-"
        rendered = []
        for ref in refs[:16]:
            if isinstance(ref, dict):
                source = str(ref.get("source") or ref.get("tool") or "-").strip()
                category = str(ref.get("category") or ref.get("evidence") or ref.get("signal") or "-").strip()
                status = str(ref.get("status") or ref.get("validation_state") or "").strip()
                score = str(ref.get("score") or ref.get("confidence") or "").strip()
                url = str(ref.get("url") or "").strip()
                parts = [f"kaynak={source}", f"kanıt={category}"]
                if status:
                    parts.append(f"durum={status}")
                if score:
                    parts.append(f"skor/status={score}")
                if url:
                    parts.append(f"url={url}")
                rendered.append(f"<li>{html_escape(' | '.join(parts))}</li>")
            else:
                text = str(ref or "").strip()
                if text:
                    rendered.append(f"<li>{html_escape(text)}</li>")
        return f"<ul class=\"compact-list\">{''.join(rendered)}</ul>" if rendered else "-"

    def _render_artifacts(values: Any) -> str:
        refs = [str(item or "").strip() for item in values] if isinstance(values, list) else []
        refs = [item for item in refs if item]
        if not refs:
            return "-"
        return "<ul class=\"compact-list\">" + "".join(
            f"<li><code>{html_escape(ref)}</code></li>" for ref in refs[:12]
        ) + "</ul>"

    # --- Context-aware Suggestion Engine ---
    _sug_hdr = "<th>#</th><th>Öneri</th><th>Ayarlanmış güven</th><th>Görünürlük</th><th>Gerekçe</th><th>Detaylar</th>"
    _sug_rows: list[str] = []
    all_suggestions = list(data.context_aware_suggestions)
    sorted_suggestions = all_suggestions

    category_counts = {
        "VALIDATION": 0,
        "DISCOVERY_RECOVERY": 0,
        "ATTACK": 0,
        "HARDENING": 0,
    }
    for _item in sorted_suggestions:
        _cat = str(_item.get("category") or "").strip().upper()
        if _cat in category_counts:
            category_counts[_cat] += 1

    for _sug_idx, _sug_item in enumerate(sorted_suggestions, start=1):
        _sug_title = html_escape(_localize_report_text(_sug_item.get("title", "-") or "-"))
        _sug_surface = html_escape(_localize_report_text(_sug_item.get("surface", "-") or "-"))
        _sug_category = str(_sug_item.get("category") or "VALIDATION").strip().upper()
        _sug_adjusted = int(_sug_item.get("adjusted_confidence", 0) or 0)
        _sug_base = int(_sug_item.get("base_confidence", 0) or 0)
        _sug_visibility = str(_sug_item.get("visibility_status") or "PARTIAL").strip().upper()
        _sug_reasoning = html_escape(truncate_text(_localize_report_text(str(_sug_item.get("reasoning") or "-")), 105))
        _sug_why_raw = _localize_report_text(str(_sug_item.get("why", "-") or "-"))
        _sug_why_full = html_escape(_sug_why_raw)
        _sug_tests_raw = _sug_item.get("tests", []) if isinstance(_sug_item.get("tests"), list) else []
        _sug_tests_html = "<br>".join(render_detail_value(_localized_detail(t), data.report_base_url) for t in _sug_tests_raw) or "-"
        _sug_evidence_raw = _sug_item.get("evidence", []) if isinstance(_sug_item.get("evidence"), list) else []
        _sug_evidence_html = "<br>".join(render_detail_value(_localized_detail(e), data.report_base_url) for e in _sug_evidence_raw) or "-"
        _sug_urls_html = _render_urls(_sug_item.get("recommended_urls", []))
        _sug_evidence_refs_html = _render_evidence_refs(_sug_item.get("evidence_refs", []))
        _sug_artifacts_html = _render_artifacts(_sug_item.get("artifact_refs", []))
        _sug_validation_state = html_escape(str(_sug_item.get("validation_state") or "needs_manual_validation"))
        _sug_uncertainty = _localize_report_text(str(_sug_item.get("uncertainty_note") or "").strip())
        _sug_uncertainty_html = f"<dt>Belirsizlik notu:</dt><dd>{html_escape(_sug_uncertainty)}</dd>" if _sug_uncertainty else ""
        _sug_nuclei_map = _sug_item.get("resolved_nuclei", {}) if isinstance(_sug_item, dict) else {}
        _sug_nuclei_tags = _sug_nuclei_map.get("all_tags", []) or []
        _sug_nuclei_cli = _sug_nuclei_map.get("suggested_cli", "")
        _sug_nuclei_str = ""
        if _sug_nuclei_tags or _sug_nuclei_cli:
            _sug_tags_preview = html_escape(", ".join(str(t) for t in _sug_nuclei_tags[:6]))
            _sug_extra_tags = f' <span class="note">+{len(_sug_nuclei_tags)-6} ek</span>' if len(_sug_nuclei_tags) > 6 else ""
            if data.manual_nuclei_next_run:
                _sug_nuclei_str = (
                    f"<dt>Önerilen sonraki manuel Nuclei koşusu:</dt>"
                    f"<dd>Tags: {_sug_tags_preview}{_sug_extra_tags}</dd>"
                )
            else:
                _sug_nuclei_str = f"<dt>Nuclei tags:</dt><dd>{_sug_tags_preview}{_sug_extra_tags}</dd>"
            if _sug_nuclei_cli:
                cli_label = "Önerilen sonraki manuel Nuclei koşusu" if data.manual_nuclei_next_run else "CLI"
                _sug_nuclei_str += f"<dt>{cli_label}:</dt><dd><code style=\"font-size:11px\">{html_escape(_sug_nuclei_cli[:120])}</code></dd>"
        _sug_details_html = (
            f'<details><summary class="row-details-toggle">Detayları göster</summary>'
            f'<dl class="suggestion-detail">'
            f'<dt>Gerekçe (tam):</dt><dd>{html_escape(_localize_report_text(str(_sug_item.get("reasoning") or "-")))}</dd>'
            f'<dt>İlgili URL’ler:</dt><dd class="wrap-cell">{_sug_urls_html}</dd>'
            f'<dt>Kanıt / kaynak:</dt><dd class="wrap-cell">{_sug_evidence_refs_html}</dd>'
            f'<dt>Artifact referansları:</dt><dd class="wrap-cell">{_sug_artifacts_html}</dd>'
            f'<dt>Doğrulama durumu:</dt><dd>{_sug_validation_state}</dd>'
            f'<dt>Neden önemli?</dt><dd>{_sug_why_full}</dd>'
            f'<dt>Ne yapmalıyım?</dt><dd class="wrap-cell">{_sug_tests_html}</dd>'
            f'<dt>Neden önerildi?</dt><dd class="wrap-cell">{_sug_evidence_html}</dd>'
            f'<dt>Nasıl doğrulanır?</dt><dd class="wrap-cell">{_sug_tests_html}</dd>'
            f'<dt>Not:</dt><dd>Bu öneri exploit kanıtı değil, test planıdır.</dd>'
            f'<dt>Ayarlanmış güven:</dt><dd>{_sug_adjusted}/100 (base {_sug_base}/100)</dd>'
            + _sug_uncertainty_html
            + (_sug_nuclei_str)
            + f'</dl></details>'
        )
        _sug_priority_color = "bad" if _sug_adjusted >= 75 else ("warn" if _sug_adjusted >= 50 else "ok")
        _sug_visibility_tone = "ok" if _sug_visibility == "FULL" else ("warn" if _sug_visibility == "PARTIAL" else "bad")
        _sug_category_tone = "bad" if _sug_category == "ATTACK" else ("warn" if _sug_category in {"VALIDATION", "DISCOVERY_RECOVERY"} else "ok")

        row_class = ' class="report-depth-summary-extra"' if _sug_idx > 3 else ""
        _sug_rows.append(
            f"<tr{row_class}><td><strong>{_sug_idx}</strong></td>"
            f"<td><strong>{_sug_title}</strong><br><span class=\"note\">{_sug_surface}</span><br>{pill(_sug_category, _sug_category_tone)}</td>"
            f"<td><span class=\"pill {_sug_priority_color}\">{_sug_adjusted}/100</span><br><span class=\"note\">base {_sug_base}/100</span></td>"
            f"<td>{pill(_sug_visibility, _sug_visibility_tone)}</td>"
            f"<td class=\"wrap-cell\"><span class=\"suggestion-compact-why\">{_sug_reasoning}</span></td>"
            f"<td>{_sug_details_html}</td></tr>"
        )

    _suggestion_policy_note = txt("suggestion_engine_policy")
    if data.discovery_reliability == "CRITICAL":
        _suggestion_policy_note += f" {txt('suggestion_engine_policy_critical')}"

    section_html += f"""
    <div class="section report-depth-body-all" data-depth-body="summary balanced deep">
        <h2 id="priority-suggestions">{html_escape(txt("suggestion_engine_title"))}</h2>
        <p class="report-depth-explainer"><strong>Sırada ne yapılmalı?</strong> Öneriler mevcut kanıtı güvenli kontrol adımlarına çevirir. Yüksek öncelikli öğelerden başla ve her öneriyi onaylanmış zafiyet değil test planı olarak ele al.</p>
        <p class="note">{html_escape(txt("suggestion_engine_note"))}</p>
        <p class="operator-view-note">{html_escape(_suggestion_policy_note)}</p>
    """
    section_html += render_summary_strip_counts(
        [
            ("öneriler", len(all_suggestions)),
            ("validation", category_counts["VALIDATION"]),
            ("discovery recovery", category_counts["DISCOVERY_RECOVERY"]),
            ("attack", category_counts["ATTACK"]),
            ("hardening", category_counts["HARDENING"]),
        ]
    )
    section_html += f'<details class="show-more" open><summary>{html_escape(txt("suggestion_engine_preview"))}</summary>'
    section_html += render_progressive_table(
        header_html=_sug_hdr,
        rows=_sug_rows,
        empty_row_html=f'<tr><td colspan="6">{html_escape(txt("suggestion_engine_empty"))}</td></tr>',
        preview_rows=preview_rows,
        summary_label="Tüm önerileri göster",
    )
    section_html += "</details>"
    section_html += "</div>"
    return section_html

def render_suggestions_section(context: dict[str, Any]) -> str:
    depth_config = context.get("report_depth_config")
    max_preview = int(getattr(depth_config, "max_suggestions_preview", 8))
    return render_suggestions_section_data(
        SuggestionsSectionData(
            context_aware_suggestions=list(context.get("context_aware_suggestions") or []),
            discovery_reliability=str(context.get("discovery_reliability") or ""),
            manual_nuclei_next_run=bool(context.get("manual_nuclei_next_run")),
            report_base_url=str(context.get("report_base_url") or ""),
        ),
        html_escape=context.get("_html_escape"),
        pill=context.get("_pill"),
        render_detail_value=context.get("_render_detail_value"),
        render_progressive_table=context.get("_render_progressive_table"),
        render_summary_strip_counts=context.get("_render_summary_strip_counts"),
        truncate_text=context.get("_truncate_text"),
        txt=context.get("_txt"),
        preview_rows=max_preview,
    )
