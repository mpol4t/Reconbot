from __future__ import annotations

from typing import Any

def render_attack_chains_section(context: dict[str, Any]) -> str:
    _html_escape = context.get("_html_escape")
    _operator_text_to_english = context.get("_operator_text_to_english")
    _render_detail_value = context.get("_render_detail_value")
    _render_progressive_table = context.get("_render_progressive_table")
    _txt = context.get("_txt")
    report_base_url = str(context.get("report_base_url") or "")
    attack_chains = context.get("attack_chains")
    coverage_status_label = context.get("coverage_status_label")
    discovery_low_or_critical = context.get("discovery_low_or_critical")
    discovery_reliability = context.get("discovery_reliability")
    has_any_tier_failure = context.get("has_any_tier_failure")
    section_html = ""

    def _urls(values: Any, *, limit: int = 8) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for value in values if isinstance(values, list) else []:
            text = str(value or "").strip()
            if not text or not text.startswith(("http://", "https://", "/")):
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(text)
            if len(out) >= limit:
                break
        return out

    source_control_urls = _urls(context.get("source_control_like_for_score", []))
    chain_url_sources = {
        "upload": _urls(context.get("upload_like_for_score", [])),
        "auth": _urls((context.get("auth_like_for_score", []) or []) + (context.get("admin_like_for_score", []) or [])),
        "admin": _urls((context.get("admin_like_for_score", []) or []) + (context.get("auth_like_for_score", []) or [])),
        "api": _urls((context.get("api_like_for_score", []) or []) + (context.get("docs_like_for_score", []) or [])),
        "docs": _urls(context.get("docs_like_for_score", [])),
        "debug": _urls(context.get("debug_like_for_score", [])),
        "config": _urls(context.get("debug_like_for_score", [])),
        "source": source_control_urls,
        ".git": source_control_urls,
    }

    def _related_urls_for_chain(chain: dict[str, Any]) -> list[str]:
        text = " ".join(
            [
                str(chain.get("name") or ""),
                " ".join(str(item or "") for item in (chain.get("signals") or [])),
                str(chain.get("why") or ""),
            ]
        ).lower()
        urls: list[str] = []
        for token, token_urls in chain_url_sources.items():
            if token in text:
                for url in token_urls:
                    if url not in urls:
                        urls.append(url)
        return urls[:8]

    def _render_urls(urls: list[str]) -> str:
        if not urls:
            return "<span class='note'>Direct URL evidence yok; bu zincir genel bağlamdan üretildi.</span>"
        return "<ul class='compact-list'>" + "".join(
            f"<li title=\"{_html_escape(url)}\">{_render_detail_value(url, report_base_url)}</li>"
            for url in urls[:8]
        ) + "</ul>"

    # --- Attack Chains ---
    _ac_hdr = "<th>#</th><th>Zincir</th><th>Güven</th><th>Sinyaller</th><th>Neden önemli?</th><th>Sonraki aksiyon</th><th>Referanslar</th>"
    _ac_rows: list[str] = []
    for _ac_idx, _ac_chain in enumerate((attack_chains or []), start=1):
        if not isinstance(_ac_chain, dict):
            continue
        _ac_name = _html_escape(_operator_text_to_english(_ac_chain.get("name", "Unknown")))
        _ac_conf = int(_ac_chain.get("confidence", 0))
        _ac_sigs = _html_escape(", ".join(_ac_chain.get("signals", []) or []) or "-")
        _ac_why = _html_escape(_operator_text_to_english(_ac_chain.get("selection_reason") or _ac_chain.get("why", "") or "-"))
        _ac_tests = _html_escape(_operator_text_to_english(", ".join(_ac_chain.get("next_tests", []) or []) or "-"))
        _related_urls = _related_urls_for_chain(_ac_chain)
        _validation_state = "confirmed" if _related_urls else "needs_manual_validation"
        _source_list = _html_escape(", ".join(_ac_chain.get("signals", []) or []) or "attack_graph / classified_endpoints")
        _first_step = _html_escape(_operator_text_to_english((_ac_chain.get("next_tests", []) or ["Manual validation required"])[0]))
        _refs = (
            f'<details><summary class="row-details-toggle">Referansları göster</summary>'
            f'<dl class="suggestion-detail">'
            f'<dt>Related URLs:</dt><dd>{_render_urls(_related_urls)}</dd>'
            f'<dt>Evidence/source:</dt><dd>{_source_list}</dd>'
            f'<dt>Validation state:</dt><dd>{_validation_state}</dd>'
            f'<dt>First manual validation step:</dt><dd>{_first_step}</dd>'
            f'<dt>Not:</dt><dd>Bu zincir exploit proof değil; observed surface üzerinden manuel doğrulama planıdır.</dd>'
            f'</dl></details>'
        )
        _ac_rows.append(
            f"<tr><td><strong>{_ac_idx}</strong></td><td><strong>{_ac_name}</strong></td>"
            f"<td>{_ac_conf}/100</td><td class=\"wrap-cell\">{_ac_sigs}</td>"
            f"<td class=\"wrap-cell\">{_ac_why}</td><td class=\"wrap-cell\">{_ac_tests}</td><td>{_refs}</td></tr>"
        )
    _attack_chain_note = _txt("attack_chains_note", count=(len(attack_chains) if isinstance(attack_chains, list) else 0))
    if discovery_reliability != "HIGH":
        _low_hint = _txt("attack_chains_low_hint") if discovery_low_or_critical else ""
        _attack_chain_note += (
            _txt(
                "attack_chains_low_reliability_tail",
                coverage_status=_html_escape(coverage_status_label),
                low_hint=_low_hint,
            )
        )
    elif has_any_tier_failure:
        _attack_chain_note += (
            _txt("attack_chains_supporting_tail", coverage_status=_html_escape(coverage_status_label))
        )
    section_html += f"""
    <div class="section report-depth-body-deep-only" data-depth-body="deep">
        <h2>{_html_escape(_txt("attack_chains_title"))}</h2>
        <p class="note">{_attack_chain_note}</p>
    """
    section_html += _render_progressive_table(
        header_html=_ac_hdr,
        rows=_ac_rows,
        empty_row_html=f'<tr><td colspan="7">{_html_escape(_txt("attack_chains_empty"))}</td></tr>',
        preview_rows=5,
        summary_label=_txt("attack_chains_show_all"),
    )
    section_html += "</div>"
    return section_html
