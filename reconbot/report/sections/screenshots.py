from __future__ import annotations

from typing import Any


def render_screenshots_section(context: dict[str, Any]) -> str:
    html_escape = context.get("_html_escape")
    render_detail_value = context.get("_render_detail_value")
    render_progressive_table = context.get("_render_progressive_table")
    render_summary_strip_counts = context.get("_render_summary_strip_counts")
    report_base_url = context.get("report_base_url", "")
    depth_config = context.get("report_depth_config")
    preview_rows = int(getattr(depth_config, "max_screenshot_preview", 8))
    entry_limit = 200
    checks_results = context.get("checks_results") if isinstance(context.get("checks_results"), dict) else {}
    run_context = context.get("run_context") if isinstance(context.get("run_context"), dict) else {}
    stages = run_context.get("stages") if isinstance(run_context.get("stages"), dict) else {}
    screenshots_stage = stages.get("screenshots") if isinstance(stages.get("screenshots"), dict) else {}

    screenshots = checks_results.get("screenshots") if isinstance(checks_results.get("screenshots"), dict) else {}
    if not screenshots:
        data = run_context.get("data") if isinstance(run_context.get("data"), dict) else {}
        screenshots = data.get("screenshots") if isinstance(data.get("screenshots"), dict) else {}

    if not screenshots and not screenshots_stage:
        return ""

    def esc(value: Any) -> str:
        return html_escape(value) if callable(html_escape) else str(value or "")

    def _display_status(value: Any) -> str:
        raw = str(value or "").strip()
        labels = {
            "received": "alınan",
            "selected": "seçilen",
            "captured": "yakalandı",
            "missing_file": "dosya eksik",
            "limit": "limit",
            "done": "tamamlandı",
            "empty": "boş",
            "error": "hata",
            "failed": "başarısız",
            "partial": "kısmi",
            "timeout": "timeout",
            "missing_tool": "tool eksik",
            "skipped": "atlanmış",
        }
        return labels.get(raw, raw or "-")

    def _display_error(value: Any) -> str:
        raw = str(value or "").strip()
        if raw == "screenshot file not found for selected URL":
            return "seçilen URL için screenshot dosyası bulunamadı"
        return raw

    entries = screenshots.get("entries") if isinstance(screenshots.get("entries"), list) else []
    captured = [
        item
        for item in entries
        if isinstance(item, dict) and str(item.get("screenshot_path") or "").strip()
    ]
    selected_count = int(screenshots.get("selected_count", len(entries)) or 0)
    received = int(screenshots.get("received", 0) or 0)
    max_count = int(screenshots.get("max", 0) or 0)
    status = str(screenshots.get("status") or screenshots_stage.get("status") or "unknown")
    warnings = screenshots.get("warnings") if isinstance(screenshots.get("warnings"), list) else []
    produced_file_count = int(screenshots.get("produced_file_count", 0) or 0)
    missing_url_count = int(screenshots.get("missing_url_count", 0) or 0)
    exit_code = screenshots.get("exit_code")
    stderr_tail = str(screenshots.get("stderr_tail") or "").strip()

    if callable(render_summary_strip_counts):
        summary = render_summary_strip_counts(
            [
                (_display_status("received"), received),
                (_display_status("selected"), selected_count),
                (_display_status("captured"), len(captured)),
                (_display_status("limit"), max_count),
            ]
        )
    else:
        summary = ""

    state_note = ""
    if status in {"missing_tool", "skipped"} or str(screenshots_stage.get("status") or "").lower() == "skipped":
        warning_text = "; ".join(_display_error(w) for w in warnings[:2]) or "Screenshot capture devre dışıydı veya atlanmış."
        state_note = f'<p class="note">{esc(warning_text)}</p>'
    elif status in {"error", "timeout", "failed", "partial"}:
        warning_text = "; ".join(_display_error(w) for w in warnings[:2]) or "Screenshot capture başarısız oldu, ancak rapor üretimi devam etti."
        state_note = f'<p class="risk-note">{esc(warning_text)}</p>'
    elif not entries:
        state_note = '<p class="note">Zaten canlı ve scope içindeki URL’lerden screenshot hedefi seçilmedi.</p>'

    rows: list[str] = []
    for idx, item in enumerate(entries[:entry_limit], start=1):
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        source = str(item.get("source") or "-")
        item_status = str(item.get("status") or "-")
        title = str(item.get("title") or "-")
        path = str(item.get("screenshot_path") or "").strip()
        error = str(item.get("capture_error") or "").strip()
        url_html = (
            render_detail_value(url, report_base_url)
            if callable(render_detail_value)
            else esc(url)
        )
        if path:
            preview = (
                f'<a href="{esc(path)}" target="_blank">'
                f'<img class="screenshot-thumb" src="{esc(path)}" alt="{esc(url)} için screenshot önizlemesi">'
                f'</a><br><code>{esc(path)}</code>'
            )
        else:
            preview = f'<span class="note">{esc(_display_error(error) or "Screenshot dosyası yakalanmadı")}</span>'
        row_class = ' class="report-depth-summary-extra"' if idx > max(0, preview_rows) else ""
        rows.append(
            f"<tr{row_class}>"
            f"<td class='wrap-cell'>{url_html}</td>"
            f"<td>{esc(source)}</td>"
            f"<td>{esc(_display_status(item_status))}</td>"
            f"<td class='wrap-cell'>{esc(title)}</td>"
            f"<td>{preview}</td>"
            "</tr>"
        )

    table = ""
    if callable(render_progressive_table):
        table = render_progressive_table(
            header_html="<th>URL</th><th>Kaynak</th><th>Durum</th><th>Başlık</th><th>Artifact</th>",
            rows=rows,
            empty_row_html="<tr><td colspan='5'>Screenshot kanıtı yakalanmadı.</td></tr>",
            preview_rows=preview_rows,
            summary_label="Tüm screenshot kanıtlarını göster",
        )

    table_open = " open" if str(getattr(depth_config, "name", "balanced")) == "deep" else ""

    return f"""
    <div class="section report-depth-operator-detail report-depth-body-balanced-deep" data-depth-body="balanced deep" id="screenshots">
        <h2>Görsel Yüzey Kanıtı</h2>
        <p class="report-depth-explainer"><strong>Bu bölüm neyi gösterir?</strong> Görsel kanıt, erişilebilir bir yüzeyin nasıl göründüğünü doğrulamaya yardımcı olur. Screenshot bağlam sağlar; tek başına zafiyet kanıtı değildir.</p>
        <p class="note">Sınırlandırılmış, zaten canlı ve scope içindeki HTTP URL’lerinden alınan opsiyonel gowitness screenshot’ları. Özet ve Dengeli mod önizleme gösterir; Derin mod yakalanan tüm kanıt tablosunu gösterir.</p>
        {summary}
        {state_note}
        <p class="note">Debug: selected_count=<code>{esc(selected_count)}</code>; produced_file_count=<code>{esc(produced_file_count)}</code>; output_dir=<code>{esc((screenshots.get('artifacts') or {}).get('output_dir') if isinstance(screenshots.get('artifacts'), dict) else '')}</code>; gowitness_exit_code=<code>{esc(exit_code if exit_code is not None else 'n/a')}</code>; missing_urls=<code>{esc(missing_url_count)}</code>; command=<code>{esc(' '.join(str(part) for part in screenshots.get('command', []) if part is not None))}</code>; targets=<code>{esc((screenshots.get('artifacts') or {}).get('input') if isinstance(screenshots.get('artifacts'), dict) else '')}</code>; stderr_tail=<code>{esc(stderr_tail[-500:] if stderr_tail else 'n/a')}</code></p>
        <details class="show-more report-depth-balanced-preview"{table_open}>
            <summary>Screenshot kanıt önizlemesi</summary>
            {table}
        </details>
    </div>
    """
