from __future__ import annotations


def _coerce_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _html_escape(value: object) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def truncate_text(text: object, max_length: int) -> str:
    s = str(text or "").strip()
    if len(s) > max_length:
        return s[:max_length] + "..."
    return s


def pill(label: object, tone: str) -> str:
    return f'<span class="pill {tone}">{_html_escape(label)}</span>'


def render_score_pill(score: object) -> str:
    score = max(0, min(100, _coerce_int(score, 0)))
    if score >= 75:
        tone = "bad"
    elif score >= 55:
        tone = "warn"
    elif score >= 30:
        tone = "alert"
    else:
        tone = "ok"
    return f'<span class="pill {tone}">{score}/100</span>'


def risk_band_tone(score: object) -> str:
    score = max(0, min(100, _coerce_int(score, 0)))
    if score >= 75:
        return "bad"
    if score >= 55:
        return "warn"
    if score >= 30:
        return "alert"
    return "ok"


def render_progressive_list(
    items: list[str],
    *,
    preview_count: int = 5,
    summary_prefix: str = "Daha fazla göster",
) -> str:
    if not items:
        return ""

    preview = items[:preview_count]
    rest = items[preview_count:]
    preview_html = "".join(f"<li>{x}</li>" for x in preview)
    if not rest:
        return f"<ul class='compact-list'>{preview_html}</ul>"

    rest_html = "".join(f"<li>{x}</li>" for x in rest)
    return (
        f"<ul class='compact-list'>{preview_html}</ul>"
        f"<details class='show-more'><summary>{summary_prefix} ({len(rest)})</summary>"
        f"<ul class='compact-list'>{rest_html}</ul></details>"
    )


def render_progressive_table(
    header_html: str,
    rows: list[str],
    empty_row_html: str,
    preview_rows: int,
    summary_label: str = "Daha fazla satır göster",
) -> str:
    if not rows:
        return f"<table><tr>{header_html}</tr>{empty_row_html}</table>"

    if preview_rows <= 0 or len(rows) <= preview_rows:
        rows_str = "".join(rows)
        return f"<table><tr>{header_html}</tr>{rows_str}</table>"

    preview = rows[:preview_rows]
    rest = rows[preview_rows:]
    preview_table = f"<table><tr>{header_html}</tr>{''.join(preview)}</table>"
    rest_table = f"<table class='more-table'>{''.join(rest)}</table>"
    return (
        f"{preview_table}"
        f"<details class='show-more-table-toggle'><summary>{summary_label} ({len(rest)})</summary>"
        f"{rest_table}</details>"
    )


def render_summary_strip_counts(items: list[tuple[str, object]]) -> str:
    label_map = {
        "findings": "bulgu",
        "suggestions": "öneri",
        "correlations": "korelasyon",
        "groups": "grup",
        "queries": "sorgu",
        "matched CVEs": "eşleşen CVE",
        "high relevance (>=75)": "yüksek alaka (>=75)",
        "status 200": "status 200",
        "status 403": "status 403",
    }
    parts: list[str] = []
    for label, count in items:
        display_label = label_map.get(str(label), str(label))
        parts.append(
            f'<span class="stat-badge"><span class="val">{count}</span> {_html_escape(display_label)}</span>'
        )
    if not parts:
        return ""
    return f"<div class=\"summary-strip\">{''.join(parts)}</div>"


def render_report_group(title: str, content: str, count: int) -> str:
    badge = f' <span class="stat-badge"><span class="val">{count}</span></span>' if count > 0 else ""
    return f"""
    <div class="report-group">
        <h3>{_html_escape(title)}{badge}</h3>
        {content}
    </div>
    """


def render_report_panel(title: str, summary: str, content: str, tone: str) -> str:
    return f"""
    <article class="panel border-{tone}">
        <div class="panel-head">
            <h3>{_html_escape(title)}</h3>
            <p class="panel-summary">{_html_escape(summary)}</p>
        </div>
        <div class="panel-body">
            {content}
        </div>
    </article>
    """
