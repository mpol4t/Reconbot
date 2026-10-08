from __future__ import annotations

from typing import Any


def render_correlation_insights_section(context: dict[str, Any]) -> str:
    html_escape = context.get("_html_escape")
    render_detail_value = context.get("_render_detail_value")
    render_score_pill = context.get("_render_score_pill")
    report_base_url = context.get("report_base_url", "")
    depth_config = context.get("report_depth_config")
    checks_results = context.get("checks_results") if isinstance(context.get("checks_results"), dict) else {}
    historical = checks_results.get("historical_urls") if isinstance(checks_results.get("historical_urls"), dict) else {}
    insights = context.get("correlation_insights")
    if not isinstance(insights, list):
        insights = []

    def _tone(severity: object) -> str:
        normalized = str(severity or "").strip().lower()
        if normalized in {"critical", "high"}:
            return "bad"
        if normalized == "medium":
            return "warn"
        return "ok"

    def _list(items: object) -> str:
        if not isinstance(items, list) or not items:
            return "<ul class='compact-list'><li>-</li></ul>"
        return "<ul class='compact-list'>" + "".join(
            f"<li>{html_escape(item)}</li>" for item in items if str(item or "").strip()
        ) + "</ul>"

    if not insights:
        historical_summary = _render_historical_summary(
            historical,
            html_escape=html_escape,
            render_detail_value=render_detail_value,
            report_base_url=report_base_url,
        )
        return f"""
        <div class="section report-depth-body-all" data-depth-body="summary balanced deep" id="correlation-insights">
            <h2>Korelasyon İçgörüleri</h2>
            {historical_summary}
            <p class="note">Mevcut kanıttan korelasyon içgörüsü üretilmedi.</p>
        </div>
        """

    cards: list[str] = []
    max_preview = int(getattr(depth_config, "max_correlation_preview", 0) or 0)
    hidden_count = max(0, len(insights) - max_preview) if max_preview > 0 else 0
    depth_name = str(getattr(depth_config, "name", "balanced"))

    for idx, insight in enumerate(insights, start=1):
        if hasattr(insight, "to_dict"):
            item = insight.to_dict()
        elif isinstance(insight, dict):
            item = insight
        else:
            continue

        title = item.get("title") or "Korelasyon içgörüsü"
        affected_asset = item.get("affected_asset") or "-"
        severity = item.get("severity") or "unknown"
        confidence = item.get("confidence") or 0
        evidence_sources = item.get("evidence_sources") if isinstance(item.get("evidence_sources"), list) else []
        related_findings = item.get("related_findings") if isinstance(item.get("related_findings"), list) else []
        manual_steps = item.get("manual_validation_steps") if isinstance(item.get("manual_validation_steps"), list) else []
        tags = item.get("tags") if isinstance(item.get("tags"), list) else []
        source_html = ", ".join(html_escape(source) for source in evidence_sources) or "-"
        related_preview = ", ".join(html_escape(value) for value in related_findings[:5]) or "-"
        related_full = _list(related_findings)
        tag_html = " ".join(
            f'<span class="nuclei-context-badge">{html_escape(tag)}</span>'
            for tag in tags[:8]
            if str(tag or "").strip()
        )
        asset_html = (
            render_detail_value(affected_asset, report_base_url)
            if callable(render_detail_value)
            else html_escape(affected_asset)
        )
        confidence_html = (
            render_score_pill(confidence)
            if callable(render_score_pill)
            else html_escape(f"{confidence}/100")
        )
        card_class = " report-depth-summary-extra" if max_preview > 0 and idx > max_preview else ""

        deep_evidence_html = ""
        if depth_name == "deep":
            deep_evidence_html = f"""
                <div class="report-depth-evidence-detail report-depth-audit-only">
                    <h4>Derin kanıt detayı</h4>
                    <p><strong>Kanıt kaynakları:</strong> {source_html}</p>
                    <p><strong>İlişkili bulgular önizlemesi:</strong> {related_preview}</p>
                    <div>
                        <h4>Tüm ilişkili bulgular / eşleşen referanslar</h4>
                        {related_full}
                        <p class="note">Derin mod audit incelemesi için kaynak adlarını, aynı-asset eşleşme bağlamını, tag’leri ve confidence metadata’sını korur.</p>
                    </div>
                </div>
            """

        cards.append(
            f"""
            <article class="nuclei-card nuclei-severity-{html_escape(str(severity).lower())}{card_class}">
                <div class="nuclei-card-head">
                    <div>
                        <h3>{html_escape(title)}</h3>
                        <p class="panel-summary">{asset_html}</p>
                        <div class="nuclei-meta-row">
                            <span class="pill {_tone(severity)}">{html_escape(severity)}</span>
                            {confidence_html}
                            {tag_html}
                        </div>
                    </div>
                </div>
                <div class="nuclei-card-grid">
                    <div>
                        <h4>Ne görüldü?</h4>
                        <p>Aynı asset veya workflow üzerinde birden fazla kaynak sinyal verdi; bu yüzden ilk triyajda öne alınır.</p>
                        <h4>Kanıt özeti</h4>
                        <p>{html_escape(item.get("evidence_summary") or "-")}</p>
                    </div>
                    <div>
                        <h4>Neden önemli?</h4>
                        <p>{html_escape(item.get("why_it_matters") or "-")}</p>
                        <h4>Sınır</h4>
                        <p>{html_escape(item.get("exploitability_assessment") or "-")}</p>
                    </div>
                    <div>
                        <h4>Ne yapmalıyım?</h4>
                        {_list(manual_steps)}
                    </div>
                    <div>
                        <h4>İlk önerilen aksiyon</h4>
                        <p>{html_escape(item.get("recommended_first_action") or "-")}</p>
                        <h4>False positive kontrolü</h4>
                        <p>{html_escape(item.get("false_positive_notes") or "-")}</p>
                    </div>
                </div>
                <details class="show-more report-depth-balanced-preview">
                    <summary>Kanıt özeti</summary>
                    <p><strong>Kanıt kaynakları:</strong> {source_html}</p>
                    <p><strong>İlişkili bulgular önizlemesi:</strong> {related_preview}</p>
                </details>
                {deep_evidence_html}
            </article>
            """
        )

    historical_summary = _render_historical_summary(
        historical,
        html_escape=html_escape,
        render_detail_value=render_detail_value,
        report_base_url=report_base_url,
    )

    return f"""
    <div class="section report-depth-body-all" data-depth-body="summary balanced deep" id="correlation-insights">
        <h2>Korelasyon İçgörüleri</h2>
        <p class="report-depth-explainer"><strong>Bu bölüm neyi gösterir?</strong> Korelasyon içgörüleri, birden fazla araçtan gelen sinyalleri birleştirir. Bağımsız kanıtlar aynı asset’i işaret ettiğinde doğrulama önceliğini artırır; exploitability otomatik olarak kanıtlanmış sayılmaz.</p>
        <p class="note">Dengeli mod her sinyalin ne anlama geldiğini ve sıradaki doğrulamayı açıklar. Derin mod audit incelemesi için kanıt kaynaklarını, ilişkili bulguları ve eşleşen referansları korur.</p>
        {f'<p class="note report-depth-summary-extra-note">Bu rapor derinliği için {len(insights)} içgörüden ilk {max_preview} tanesi gösteriliyor. Daha fazla detay için dengeli veya derin moda geç.</p>' if hidden_count else ''}
        {historical_summary}
        <div class="nuclei-grouped-findings">
            {''.join(cards)}
        </div>
    </div>
    """


def _render_historical_summary(
    historical: dict[str, Any],
    *,
    html_escape: Any,
    render_detail_value: Any,
    report_base_url: str,
) -> str:
    if not isinstance(historical, dict) or not historical.get("enabled"):
        return ""

    interesting = historical.get("interesting_live_urls")
    if not isinstance(interesting, list):
        interesting = []
    artifact = ""
    artifacts = historical.get("artifacts") if isinstance(historical.get("artifacts"), dict) else {}
    combined = artifacts.get("combined_txt") or artifacts.get("combined_json") or ""
    if combined:
        artifact = f"<p class='note'>Tam normalize edilmiş historical URL artifact: {html_escape(combined)}</p>"

    if not interesting:
        warnings = historical.get("warnings") if isinstance(historical.get("warnings"), list) else []
        warning_note = ""
        if warnings:
            warning_note = f"<p class='note'>Uyarılar: {html_escape('; '.join(str(w) for w in warnings[:3]))}</p>"
        return f"""
        <div class="panel">
            <h3>Historical URL Keşfi</h3>
            <p class="note">Mevcut archive kanıtından canlı ve ilginç historical endpoint belirlenmedi.</p>
            {warning_note}
            {artifact}
        </div>
        """

    rows: list[str] = []
    for item in interesting[:10]:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        categories = item.get("categories") if isinstance(item.get("categories"), list) else []
        sources = item.get("sources") if isinstance(item.get("sources"), list) else []
        status = str(item.get("live_check_status") or "live").replace("_", " ")
        url_html = (
            render_detail_value(url, report_base_url)
            if callable(render_detail_value)
            else html_escape(url)
        )
        rows.append(
            "<tr>"
            f"<td class='wrap-cell'>{url_html}</td>"
            f"<td>{html_escape(', '.join(str(c) for c in categories) or '-')}</td>"
            f"<td><span class='pill ok'>{html_escape(status)}</span></td>"
            f"<td>{html_escape(', '.join(str(s) for s in sources) or '-')}</td>"
            "</tr>"
        )

    return f"""
    <div class="panel">
        <h3>Historical URL Keşfi</h3>
        <p class="note">Okunabilirlik için en önemli canlı historical endpoint’ler sınırlandırıldı; aşağıdaki korelasyon kartları hangi öğenin neden doğrulamaya değer olduğunu açıklar.</p>
        <div class="table-wrap">
            <table>
                <thead><tr><th>URL</th><th>Kategori</th><th>Durum</th><th>Kaynaklar</th></tr></thead>
                <tbody>{''.join(rows)}</tbody>
            </table>
        </div>
        {artifact}
    </div>
    """
