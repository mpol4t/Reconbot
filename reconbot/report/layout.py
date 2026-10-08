from __future__ import annotations


def _html_escape(value: object) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _depth_label(depth: object) -> str:
    labels = {"summary": "Özet", "balanced": "Dengeli", "deep": "Derin"}
    return labels.get(str(depth or "").strip().lower(), "Dengeli")


def _depth_mode_description(depth: object) -> str:
    descriptions = {
        "summary": "karar odaklı görünüm",
        "balanced": "operatör inceleme görünümü",
        "deep": "tam kanıt/audit görünümü",
    }
    return descriptions.get(str(depth or "").strip().lower(), descriptions["balanced"])


def render_report_style_block(graph_ui_css: str) -> str:
    style_template = """\

    <style>
        :root {
            --bg: #11161c;
            --bg2: #171e26;
            --surface: #1b232c;
            --surface-raised: #26323e;
            --surface-soft: #161d25;
            --surface-border: rgba(177, 193, 214, 0.24);
            --text-main: #f4f7fb;
            --text-muted: #b3c0cf;
            --border: var(--surface-border);
            --text: var(--text-main);
            --muted: var(--text-muted);
            --accent: #53dcc8;
            --accent2: #a0c8df;
            --accent-soft: rgba(103, 213, 255, 0.14);
            --bad: #ff7f86;
            --bad-bg: rgba(255, 127, 134, 0.13);
            --bad-border: rgba(255, 127, 134, 0.44);
            --warn: #f4c96b;
            --warn-bg: rgba(244, 201, 107, 0.14);
            --warn-border: rgba(244, 201, 107, 0.44);
            --ok: #63d69b;
            --ok-bg: rgba(99, 214, 155, 0.14);
            --ok-border: rgba(99, 214, 155, 0.44);
            --radius: 16px;
            --radius-sm: 10px;
            --shadow-soft: 0 18px 38px rgba(4, 10, 20, 0.20);
        }
        html { scroll-behavior: smooth; }
        body {
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background:
                radial-gradient(circle at 18% -10%, rgba(103, 213, 255, 0.16), transparent 36rem),
                radial-gradient(circle at 88% 4%, rgba(169, 184, 255, 0.11), transparent 32rem),
                linear-gradient(140deg, #111a2a 0%, #172337 48%, #1a2536 100%);
            color: var(--text-main);
            margin: 0; padding: 0; line-height: 1.5; font-size: 14px;
        }
        body.report-depth-summary {
            background:
                radial-gradient(circle at 16% -10%, rgba(125, 216, 201, 0.17), transparent 34rem),
                radial-gradient(circle at 88% 4%, rgba(103, 213, 255, 0.09), transparent 30rem),
                linear-gradient(140deg, #0f1b25 0%, #142637 50%, #182b36 100%);
        }
        body.report-depth-deep {
            background:
                radial-gradient(circle at 18% -10%, rgba(198, 167, 255, 0.18), transparent 36rem),
                radial-gradient(circle at 88% 4%, rgba(103, 213, 255, 0.08), transparent 32rem),
                linear-gradient(140deg, #111625 0%, #1b2038 50%, #211f3b 100%);
        }
        * { box-sizing: border-box; }
        body[class*="report-depth-"] { background: var(--bg); }
        .report-sidebar { background: var(--surface-soft) !important; }
        .report-section-disclosure { margin: 0; }
        .report-section-disclosure > summary { display: list-item; color: var(--text-main); padding: 4px 0; }
        .report-section-disclosure > summary h2 { display: inline; border: 0; font-size: 16px; }
        .report-section-disclosure > summary:hover { text-decoration: none; color: var(--accent); }
        .report-section-content { padding-top: 18px; }
        @media print { .report-section-content { display: block !important; } }
        .app-shell { display: grid; grid-template-columns: 292px minmax(0, 1fr); min-height: 100vh; }
        .report-sidebar {
            position: sticky; top: 0; height: 100vh; overflow: auto; z-index: 120;
            padding: 26px 20px; border-right: 1px solid var(--surface-border);
            background: linear-gradient(180deg, rgba(30,43,62,0.98), rgba(23,34,53,0.97));
        }
        .sidebar-brand { display: flex; align-items: center; gap: 12px; margin-bottom: 22px; padding-bottom: 18px; border-bottom: 1px solid rgba(177,193,214,0.18); }
        .brand-mark {
            width: 38px; height: 38px; border-radius: 13px; display: inline-grid; place-items: center;
            color: #071321; background: linear-gradient(135deg, var(--accent), var(--accent2)); font-weight: 800;
            box-shadow: 0 10px 22px rgba(103,213,255,0.18);
        }
        .sidebar-title { margin: 0; color: #fff; font-size: 18px; line-height: 1.1; }
        .sidebar-subtitle { margin: 2px 0 0; color: var(--text-muted); font-size: 12px; }
        .sidebar-target {
            padding: 14px; border: 1px solid var(--surface-border); border-radius: 14px;
            background: rgba(255,255,255,0.055); margin-bottom: 14px;
        }
        .sidebar-target .label, .sidebar-block-title { color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0; margin-bottom: 6px; }
        .sidebar-target code { display: block; white-space: normal; overflow-wrap: anywhere; color: #fff; font-size: 12px; }
        .sidebar-badges { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 18px; }
        .sidebar-block { margin: 18px 0 20px; padding: 14px; border: 1px solid rgba(177,193,214,0.18); border-radius: 14px; background: rgba(255,255,255,0.035); }
        .sidebar-nav { display: flex; flex-direction: column; gap: 5px; padding-top: 4px; }
        .sidebar-nav a {
            color: #c4cfdd; text-decoration: none; padding: 9px 11px; border-radius: 11px;
            border: 1px solid transparent; font-size: 13px; line-height: 1.2;
        }
        .sidebar-nav a:hover {
            color: #fff; background: rgba(255,255,255,0.07); border-color: var(--surface-border); text-decoration: none;
        }
        .sidebar-nav .sidebar-nav-disabled {
            color: rgba(196,207,221,0.55); padding: 9px 11px; border-radius: 11px;
            border: 1px solid rgba(177,193,214,0.10); font-size: 13px; line-height: 1.2;
            cursor: default;
        }
        .sidebar-nav .sidebar-nav-disabled small { display: block; color: rgba(179,192,207,0.68); margin-top: 2px; }
        .sidebar-nav a[hidden] { display: none !important; }
        .sidebar-nav a.is-active {
            color: #071321; background: linear-gradient(135deg, var(--accent), var(--accent2));
            border-color: rgba(139,222,216,0.82); font-weight: 700;
        }
        .report-main { min-width: 0; }
        .topbar {
            background: rgba(23, 34, 53, 0.82); border-bottom: 1px solid var(--surface-border);
            padding: 14px 32px; position: sticky; top: 0; z-index: 100; display: flex;
            justify-content: space-between; align-items: center; gap: 18px; backdrop-filter: blur(18px);
        }
        .topbar h1 { margin: 0; font-size: 15px; color: #fff; }
        .topbar .target { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 13px; color: var(--text-muted); overflow-wrap: anywhere; }
        .command-meta { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; align-items: center; }
        .mode-banner {
            margin: 18px 32px 0; padding: 14px 16px; border-radius: 15px;
            border: 1px solid color-mix(in srgb, var(--depth-accent) 48%, transparent);
            background:
                linear-gradient(135deg, var(--depth-accent-soft), rgba(255,255,255,0.035));
            box-shadow: 0 12px 26px rgba(4, 10, 20, 0.14);
            display: flex; justify-content: space-between; align-items: center; gap: 16px;
        }
        .mode-banner-title {
            margin: 0; color: #fff; font-size: 15px; font-weight: 700;
        }
        .mode-banner-copy {
            margin: 2px 0 0; color: #d6e5f4; font-size: 13px;
        }
        .mode-banner-badge {
            flex: 0 0 auto; border: 1px solid color-mix(in srgb, var(--depth-accent) 58%, transparent);
            background: var(--depth-accent-soft); color: #f5f8ff; border-radius: 999px;
            padding: 5px 10px; font-size: 12px; font-weight: 700;
        }
        .artifact-identity {
            margin: 14px 32px 0; padding: 12px 14px; border-radius: 14px;
            border: 1px solid rgba(177,193,214,0.20); background: rgba(20,30,47,0.54);
            display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px;
        }
        .artifact-identity .label { color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0; }
        .artifact-identity code { display: block; white-space: normal; overflow-wrap: anywhere; color: #f5f8ff; font-size: 12px; }
        .artifact-identity-warning {
            grid-column: 1 / -1; color: #ffe2a0; background: var(--warn-bg);
            border: 1px solid var(--warn-border); border-radius: 11px; padding: 8px 10px; font-size: 13px;
        }
        body.report-depth-summary .mode-banner {
            border-left: 4px solid #7dd8c9;
        }
        body.report-depth-balanced .mode-banner {
            border-left: 4px solid var(--accent);
        }
        body.report-depth-deep .mode-banner {
            border-left: 4px solid #c6a7ff;
        }
        .container { max-width: 1480px; margin: 0 auto; padding: 30px 32px 70px; }
        .section {
            margin-bottom: 24px; background: linear-gradient(180deg, rgba(36,52,74,0.94), rgba(27,40,58,0.94));
            border: 1px solid var(--surface-border); border-radius: var(--radius);
            padding: 24px; box-shadow: var(--shadow-soft);
        }
        .section.compact { padding: 20px 22px; }
        .section, .raw-section-header, #traffic-profile, #discovery, #cve-enrichment, #priority-suggestions, #screenshots, #correlation-insights, #attack-graph, #raw { scroll-margin-top: 92px; }
        h2 { margin-top: 0; font-size: 18px; color: var(--text-main); border-bottom: 1px solid var(--surface-border); padding-bottom: 12px; margin-bottom: 16px; letter-spacing: 0; }
        h3 { margin-top: 24px; font-size: 15px; color: var(--accent2); margin-bottom: 12px; }
        p { margin: 0 0 12px 0; }
        .note { color: var(--text-muted); font-size: 13px; }
        .live-note { color: #ffe2a0; font-size: 13px; font-weight: 600; background: var(--warn-bg); padding: 10px 12px; border-radius: 11px; border: 1px solid var(--warn-border); margin-bottom:12px; }
        .risk-note { color: #ffd0d3; font-size: 13px; font-weight: 600; background: var(--bad-bg); padding: 10px 12px; border-radius: 11px; border: 1px solid var(--bad-border); margin-bottom:12px; }
        .operator-view-note { font-size: 13px; color: #d3efff; margin-bottom: 16px; background: rgba(103, 213, 255, 0.12); padding: 10px 12px; border-radius: 11px; border: 1px solid rgba(103, 213, 255, 0.28); }
        .dense-view-note { font-size: 13px; color: #c3cfde; margin-bottom: 16px; background: rgba(177, 193, 214, 0.11); padding: 10px 12px; border-radius: 11px; border: 1px solid rgba(177, 193, 214, 0.2); }
        .raw-section-header { margin: 48px 0 24px 0; padding-bottom: 16px; border-bottom: 2px dashed var(--surface-border); }
        .raw-section-header h2 { border-bottom: none; margin-bottom: 8px; padding-bottom: 0; font-size: 22px; color: #fff; }
        body.report-depth-summary .report-depth-raw-detail,
        body.report-depth-summary .report-depth-raw-anchor,
        body.report-depth-summary .report-depth-body-balanced-deep,
        body.report-depth-summary .report-depth-body-deep-only,
        body.report-depth-summary .report-depth-graph-section,
        body.report-depth-summary .report-depth-operator-detail,
        body.report-depth-summary .report-depth-audit-section,
        body.report-depth-summary .report-depth-discovery-detail,
        body.report-depth-summary .report-depth-enrichment-detail,
        body.report-depth-summary .report-depth-explainer,
        body.report-depth-summary .report-depth-evidence-detail,
        body.report-depth-summary .report-depth-audit-only,
        body.report-depth-summary .report-depth-deep-only {
            display: none;
        }
        body.report-depth-balanced .report-depth-raw-anchor,
        body.report-depth-balanced .report-depth-raw-detail,
        body.report-depth-balanced .report-depth-body-deep-only,
        body.report-depth-balanced .report-depth-balanced-extra,
        body.report-depth-balanced .report-depth-audit-section,
        body.report-depth-balanced .report-depth-deep-only,
        body.report-depth-balanced .report-depth-audit-only {
            display: none;
        }
        body.report-depth-balanced .report-depth-body-summary-only,
        body.report-depth-deep .report-depth-body-summary-only {
            display: none;
        }
        body.report-depth-summary { --depth-accent: #7dd8c9; --depth-accent-soft: rgba(125, 216, 201, 0.11); }
        body.report-depth-balanced { --depth-accent: var(--accent); --depth-accent-soft: rgba(103, 213, 255, 0.10); }
        body.report-depth-deep { --depth-accent: #c6a7ff; --depth-accent-soft: rgba(198, 167, 255, 0.13); }
        .report-depth-button.is-active { box-shadow: 0 0 0 2px var(--depth-accent-soft), 0 0 18px rgba(103,213,255,0.12); }
        body.report-depth-deep .report-depth-button.is-active {
            background: linear-gradient(135deg, var(--accent), #c6a7ff);
        }
        body.report-depth-summary .report-depth-button.is-active {
            background: linear-gradient(135deg, #7dd8c9, var(--accent));
        }
        body.report-depth-summary .report-depth-summary-extra {
            display: none;
        }
        body.report-depth-summary .show-more-table-toggle {
            display: none;
        }
        .report-depth-explainer {
            color: #dce8f5; background: var(--depth-accent-soft);
            border: 1px solid color-mix(in srgb, var(--depth-accent) 42%, transparent); border-radius: 13px;
            padding: 12px 14px; margin: 0 0 16px;
        }
        .depth-mode-pill { border-color: color-mix(in srgb, var(--depth-accent) 50%, transparent); background: var(--depth-accent-soft); }
        .report-depth-explainer strong { color: #ffffff; }
        .report-depth-balanced-preview {
            border: 1px solid rgba(177,193,214,0.18); border-radius: 13px;
            background: rgba(20,30,47,0.46); padding: 12px; margin-bottom: 14px;
        }
        .report-depth-evidence-detail {
            border-top: 1px solid rgba(177,193,214,0.16); margin-top: 12px; padding-top: 12px;
        }
        .operator-plan-section { border-left: 3px solid var(--depth-accent); }
        .operator-plan-list { display: grid; gap: 12px; }
        .operator-plan-card {
            display: grid; grid-template-columns: 38px minmax(0, 1fr); gap: 12px;
            padding: 14px; border-radius: 13px; border: 1px solid rgba(177,193,214,0.18);
            background: rgba(20,30,47,0.48);
        }
        .operator-plan-card h3 { margin-top: 0; margin-bottom: 8px; color: #fff; }
        .operator-plan-card p { margin-bottom: 8px; }
        .operator-plan-rank {
            width: 30px; height: 30px; border-radius: 50%; display: grid; place-items: center;
            color: #06131f; background: var(--depth-accent); font-weight: 800;
        }
        .operator-plan-source-detail {
            margin-top: 8px; padding-top: 8px; border-top: 1px solid rgba(177,193,214,0.16);
        }
        .run-quality-section { border-left: 3px solid color-mix(in srgb, var(--depth-accent) 70%, #ffffff 10%); }
        .run-quality-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-bottom: 14px; }
        .run-quality-warnings { margin: 12px 0 16px; }
        @media (max-width: 760px) {
            .run-quality-grid { grid-template-columns: 1fr; }
        }
        .report-depth-controls { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 10px 0 12px; }
        .report-sidebar .report-depth-controls { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 6px; margin: 0; }
        .report-depth-button {
            border: 1px solid var(--surface-border); background: rgba(255,255,255,0.06); color: var(--text-main);
            border-radius: 999px; padding: 7px 10px; font-size: 12px; cursor: pointer;
        }
        .report-depth-button:hover { border-color: rgba(103,213,255,0.58); }
        .report-depth-button.is-active { color: #071321; border-color: rgba(169,184,255,0.82); background: linear-gradient(135deg, var(--accent), var(--accent2)); font-weight: 700; }
        table {
            width: 100%; border-collapse: collapse; margin: 8px 0;
            font-size: 13px; table-layout: fixed; word-wrap: break-word;
        }
        th, td {
            padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--surface-border);
            vertical-align: top;
        }
        th { background: rgba(20,30,47,0.94); font-weight: 700; color: #d4deeb; }
        td { color: #e6edf3; overflow-wrap: break-word; word-break: break-word; }
        .wrap-cell { max-width: 400px; white-space: normal; }
        .status-200 { color: var(--ok); font-weight: 600; }
        .status-403 { color: var(--warn); font-weight: 600; }
        .status-404 { color: var(--text-muted); }
        .status-other { color: var(--text-main); }
        .pill {
            display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px;
            font-weight: 600; text-transform: uppercase; letter-spacing: 0;
        }
        .pill.bad { background: var(--bad-bg); color: var(--bad); border: 1px solid var(--bad-border); }
        .pill.warn { background: var(--warn-bg); color: var(--warn); border: 1px solid var(--warn-border); }
        .pill.alert { background: var(--warn-bg); color: #f2cc60; border: 1px solid #f2cc60; }
        .pill.ok { background: var(--ok-bg); color: var(--ok); border: 1px solid var(--ok-border); }
        a { color: #8cddff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        ul { margin: 0; padding-left: 20px; }
        li { margin-bottom: 4px; }
        .compact-list { padding-left: 16px; margin-bottom: 8px; }
        .compact-list li { margin-bottom: 2px; }
        details { margin-top: 8px; }
        details summary { cursor: pointer; color: var(--accent2); font-weight: 500; font-size: 13px; margin-bottom: 8px; display: inline-block; }
        details summary:hover { text-decoration: underline; }
        .suggestion-detail {
            background: #0d1117; padding: 12px; border-radius: 6px; border: 1px solid var(--surface-border);
            margin: 8px 0 0 0;
        }
        .suggestion-detail dt { font-weight: 600; font-size: 12px; color: var(--text-muted); margin-top: 8px; margin-bottom: 2px; }
        .suggestion-detail dt:first-child { margin-top: 0; }
        .suggestion-detail dd { margin: 0; font-size: 13px; color: #e6edf3; padding-left: 8px; border-left: 2px solid var(--surface-border); }
        .cve-detail-row td { padding-top: 0; background: rgba(13, 17, 23, 0.42); }
        .cve-detail-card { margin: 0; }
        .cve-detail-block {
            max-width: none; overflow-wrap: anywhere; word-break: normal;
        }
        .cve-detail-block dd,
        .ip-enrichment-detail dd {
            max-width: 100%; overflow-wrap: anywhere; word-break: normal;
        }
        .cve-detail-block a,
        .ip-enrichment-report-grid a {
            display: inline-block; max-width: 100%; overflow: hidden; text-overflow: ellipsis; vertical-align: bottom;
        }
        .ip-enrichment-report-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin: 12px 0;
        }
        .ip-enrichment-report-grid > div {
            min-width: 0; background: rgba(13, 17, 23, 0.62); border: 1px solid var(--surface-border); border-radius: 8px; padding: 12px;
        }
        .ip-enrichment-report-grid .label {
            display: block; color: var(--text-muted); font-size: 12px; text-transform: uppercase; margin-bottom: 6px;
        }
        .ip-enrichment-report-grid strong {
            display: block; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
        }
        .stage-done { color: var(--ok); }
        .stage-running { color: var(--accent); font-weight:bold; }
        .stage-error { color: var(--bad); }
        .stage-pending, .stage-skipped { color: var(--text-muted); }
        .summary-strip {
            display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 16px;
            background: rgba(18,28,44,0.62); padding: 12px; border-radius: 13px; border: 1px solid var(--surface-border);
        }
        .stat-badge {
            display: inline-flex; align-items: center; padding: 4px 10px;
            background: rgba(255,255,255,0.07); border: 1px solid var(--surface-border);
            border-radius: 16px; font-size: 12px; color: var(--text-muted);
        }
        .stat-badge .val { font-weight: 600; color: var(--text-main); margin-right: 6px; font-size: 13px; }
        .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .kpi { background: rgba(20,30,47,0.66); border: 1px solid var(--surface-border); padding: 16px; border-radius: 14px; }
        .kpi .label { color: var(--text-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0; margin-bottom: 8px; }
        .kpi .value { font-size: 24px; font-weight: 600; color: #fff; margin-bottom: 4px; }
        .kpi .note { font-size: 12px; color: var(--text-muted); }
        .overview-core-grid { grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
        .executive-intro { font-size: 14px; color: #d3efff; margin-bottom: 24px; border-left: 3px solid var(--accent); padding-left: 12px; }
        .first-test-focus { background: var(--accent-soft); border: 1px solid rgba(76, 201, 192, 0.3); padding: 16px; border-radius: 14px; margin-bottom: 24px; }
        .first-test-focus .label { font-size: 12px; text-transform: uppercase; color: var(--accent2); font-weight: 600; margin-bottom: 4px; }
        .first-test-focus .value { font-size: 18px; font-weight: 600; color: #fff; margin-bottom: 8px; }
        .first-test-focus .note { font-size: 13px; color: #c9d1d9; }
        .suggestion-compact-why { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; font-size: 12px; color: #c9d1d9; }
        .row-details-toggle { font-size: 12px; background: #21262d; padding: 4px 8px; border-radius: 4px; border: 1px solid #30363d; color: #c9d1d9; transition: background 0.2s; }
        .row-details-toggle:hover { background: #30363d; text-decoration: none; }
        .node-compact-signal { font-size: 12px; color: #8b949e; line-height: 1.6; }
        .node-compact-signal strong { color: #c9d1d9; }
        .show-more-table-toggle { padding: 8px 12px; text-align: center; background: rgba(20,30,47,0.78); border-bottom: 1px solid var(--surface-border); border-radius: 0 0 10px 10px; }
        .show-more-table-toggle summary { margin: 0; font-size: 12px; font-weight: 600; }
        .more-table { border-top: 1px solid var(--surface-border); margin-top: 0; }
        
        __GRAPH_UI_CSS__

        .nuclei-summary-block { margin-bottom: 24px; background: #0d1117; border: 1px solid var(--surface-border); border-radius: 8px; padding: 16px; }
        .nuclei-kpi-grid { margin-bottom: 16px; }
        .nuclei-severity-strip { margin-bottom: 0; border: none; padding: 0; background: transparent; }
        .nuclei-count { font-size: 13px; padding: 4px 12px; }
        .nuclei-count-critical { border-color: var(--bad-border); background: var(--bad-bg); }
        .nuclei-count-critical .val { color: var(--bad); }
        .nuclei-count-high { border-color: rgba(248, 81, 73, 0.3); background: rgba(248, 81, 73, 0.05); }
        .nuclei-count-high .val { color: #f85149; }
        .nuclei-count-medium { border-color: var(--warn-border); background: var(--warn-bg); }
        .nuclei-count-medium .val { color: var(--warn); }
        .nuclei-count-low, .nuclei-count-info { border-color: var(--ok-border); background: var(--ok-bg); }
        .nuclei-count-low .val, .nuclei-count-info .val { color: var(--ok); }

        .nuclei-grouped-findings { display: flex; flex-direction: column; gap: 32px; }
        .nuclei-severity-group h3 { margin-top: 0; margin-bottom: 16px; font-size: 18px; color: #fff; padding-bottom: 8px; border-bottom: 2px solid var(--surface-border); display: flex; align-items: center; justify-content: space-between; }
        .nuclei-bucket-critical h3 { border-bottom-color: rgba(248, 81, 73, 0.5); }
        .nuclei-bucket-high h3 { border-bottom-color: rgba(248, 81, 73, 0.3); }
        .nuclei-bucket-medium h3 { border-bottom-color: rgba(210, 153, 34, 0.4); }
        
        .nuclei-card { display: flex; flex-direction: column; gap: 12px; margin-bottom: 16px; background: #0d1117; border-radius: 8px; border: 1px solid var(--surface-border); padding: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .nuclei-severity-critical { border-left: 4px solid var(--bad); }
        .nuclei-severity-high { border-left: 4px solid #f85149; }
        .nuclei-severity-medium { border-left: 4px solid var(--warn); }
        .nuclei-severity-low, .nuclei-severity-info { border-left: 4px solid var(--ok); }
        
        .nuclei-card-head { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0; padding-bottom: 12px; border-bottom: 1px solid var(--surface-border); }
        .nuclei-card-head h3 { margin: 0 0 4px 0; font-size: 16px; color: #fff; border: none; padding: 0; display: block; line-height: 1.3; }
        .nuclei-card-head .panel-summary { margin: 0; display: inline-block; font-size: 13px; }
        .nuclei-meta-row { margin-top: 6px; font-size: 12px; color: var(--text-muted); }
        .nuclei-card-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 12px; }
        .nuclei-card-grid h4 { margin: 0 0 8px 0; font-size: 13px; color: var(--accent2); text-transform: uppercase; letter-spacing: 0; }
        
        .nuclei-issue-preview { font-size: 14px; color: #e6edf3; margin-bottom: 0; line-height: 1.5; }
        .nuclei-priority-why { font-size: 13px; color: #c9d1d9; background: rgba(255,255,255,0.05); padding: 8px 12px; border-radius: 4px; margin-top: 8px; }
        
        .nuclei-checklist { font-size: 13px; color: #c9d1d9; }
        .nuclei-checklist li { margin-bottom: 6px; }
        
        .nuclei-endpoint-line { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
        .nuclei-endpoint-badges { display: inline-flex; gap: 4px; flex-wrap: wrap; }
        .nuclei-context-badge { font-size: 10px; padding: 1px 6px; border-radius: 4px; background: #21262d; border: 1px solid #30363d; color: #8b949e; text-transform: uppercase; letter-spacing: 0; white-space: nowrap; }
        .nuclei-context-admin { border-color: rgba(248, 81, 73, 0.4); color: #f85149; background: rgba(248, 81, 73, 0.1); }
        .nuclei-context-upload { border-color: rgba(210, 153, 34, 0.4); color: #d29922; background: rgba(210, 153, 34, 0.1); }
        .nuclei-context-auth { border-color: rgba(88, 166, 255, 0.4); color: #58a6ff; background: rgba(88, 166, 255, 0.1); }
        .nuclei-context-api { border-color: rgba(163, 113, 247, 0.4); color: #a371f7; background: rgba(163, 113, 247, 0.1); }
        .nuclei-context-sensitive { border-color: rgba(248, 81, 73, 0.6); color: #ff7b72; background: rgba(248, 81, 73, 0.15); font-weight: bold; }
        
        .nuclei-raw-inline { margin-top: 16px; background: var(--surface-soft); border: 1px solid var(--surface-border); border-radius: 12px; padding: 12px; }
        .nuclei-raw-inline summary { font-size: 13px; color: var(--text-muted); background: rgba(20,30,47,0.9); padding: 6px 12px; border-radius: 9px; border: 1px solid var(--surface-border); display: inline-block; }
        .nuclei-raw-inline table { margin-top: 12px; }
        .nuclei-raw-inline th, .nuclei-raw-inline td { border-bottom: 1px solid #21262d; }
        .screenshot-thumb { display: block; max-width: 220px; max-height: 140px; object-fit: contain; border: 1px solid var(--surface-border); border-radius: 10px; background: #070a0f; box-shadow: 0 10px 24px rgba(0,0,0,0.28); }
        code {
            color: #e8f2ff; background: rgba(11,18,29,0.62); border: 1px solid rgba(177,193,214,0.2);
            border-radius: 7px; padding: 1px 5px; overflow-wrap: anywhere;
        }
        
        .nuclei-review-pill { font-size: 12px; border-radius: 4px; padding: 3px 8px; font-weight: 600; text-transform: uppercase; display: inline-block; margin-left: 8px; }
        .review-critical { background: #490202; color: #ff7b72; border: 1px solid #8c1919; }
        .review-high { background: #4a1f00; color: #ffa657; border: 1px solid #8c4200; }
        .review-medium { background: #3d3300; color: #d29922; border: 1px solid #827000; }
        .review-low { background: #072719; color: #3fb950; border: 1px solid #14462a; }
        
        @media (max-width: 980px) {
            .nuclei-card-grid { grid-template-columns: 1fr; gap: 16px; }
        }
        @media (max-width: 1120px) {
            .app-shell { display: block; }
            .report-sidebar { position: static; height: auto; overflow: visible; border-right: 0; border-bottom: 1px solid var(--surface-border); }
            .sidebar-nav { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
            .topbar { position: static; padding: 14px 18px; align-items: flex-start; flex-direction: column; }
            .mode-banner { margin: 16px 18px 0; align-items: flex-start; flex-direction: column; }
            .command-meta { justify-content: flex-start; }
            .container { padding: 22px 16px 52px; }
        }
        @media (max-width: 720px) {
            table { display: block; overflow-x: auto; table-layout: auto; }
            th, td { min-width: 150px; }
            .kpi-grid { grid-template-columns: 1fr; }
            .report-sidebar .report-depth-controls { grid-template-columns: 1fr; }
        }
    </style>
    """
    return style_template.replace("__GRAPH_UI_CSS__", graph_ui_css)


def render_report_topbar(
    target: str,
    *,
    run_state: str = "unknown",
    profile: str = "-",
    depth: str = "balanced",
    screenshot_count: int = 0,
    nuclei_findings_count: int = 0,
) -> str:
    target_html = _html_escape(target)
    run_state_html = _html_escape(run_state or "unknown")
    profile_html = _html_escape(profile or "-")
    depth_html = _html_escape(_depth_label(depth or "balanced"))
    run_state_text = str(run_state or "").lower()
    run_state_tone = "bad" if "failed" in run_state_text else ("warn" if "interrupted" in run_state_text or "running" in run_state_text else "ok")
    template = """\

    <div class="topbar">
        <div>
            <h1>Operatör Raporu</h1>
            <span class="target">Hedef: __TARGET__</span>
        </div>
        <div class="command-meta" aria-label="Rapor komut çubuğu">
            <span class="pill __RUN_STATE_TONE__">durum: __RUN_STATE__</span>
            <span class="pill ok">profil: __PROFILE__</span>
            <span class="pill ok depth-mode-pill">Mod: <span data-report-depth-current>__DEPTH__</span></span>
            <span class="pill warn">screenshot: __SCREENSHOTS__</span>
            <span class="pill bad">Nuclei: __NUCLEI__</span>
        </div>
    </div>
    """
    return (
        template.replace("__TARGET__", target_html)
        .replace("__RUN_STATE__", run_state_html)
        .replace("__RUN_STATE_TONE__", run_state_tone)
        .replace("__PROFILE__", profile_html)
        .replace("__DEPTH__", depth_html)
        .replace("__SCREENSHOTS__", str(int(screenshot_count or 0)))
        .replace("__NUCLEI__", str(int(nuclei_findings_count or 0)))
    )


def render_report_mode_banner(depth: str = "balanced") -> str:
    depth_name = str(depth or "balanced").strip().lower()
    depth_html = _html_escape(_depth_label(depth_name))
    description_html = _html_escape(_depth_mode_description(depth_name))
    template = """\

    <div class="mode-banner" data-report-depth-banner>
      <div>
        <p class="mode-banner-title">Rapor modu: <span data-report-depth-current>__DEPTH__</span></p>
        <p class="mode-banner-copy" data-report-depth-banner-description>__DESCRIPTION__</p>
      </div>
      <span class="mode-banner-badge" data-report-depth-current>__DEPTH__</span>
    </div>
    """
    return template.replace("__DEPTH__", depth_html).replace("__DESCRIPTION__", description_html)


def render_report_sidebar(
    target: str,
    *,
    run_state: str = "unknown",
    risk_score: int = 0,
    risk_band: str = "-",
    depth: str = "balanced",
    include_ip_enrichment: bool = True,
    include_osint: bool = False,
    osint_only: bool = False,
    available_section_ids: set[str] | None = None,
) -> str:
    target_html = _html_escape(target)
    run_state_html = _html_escape(run_state or "unknown")
    risk_band_html = _html_escape(risk_band or "-")
    depth_html = _html_escape(_depth_label(depth or "balanced"))
    risk_tone = "bad" if int(risk_score or 0) >= 75 else ("warn" if int(risk_score or 0) >= 30 else "ok")
    run_state_text = str(run_state or "").lower()
    run_state_tone = "bad" if "failed" in run_state_text else ("warn" if "interrupted" in run_state_text or "running" in run_state_text else "ok")
    current_depth = str(depth or "balanced").strip().lower()

    available = {str(item) for item in (available_section_ids or set()) if str(item or "").strip()}

    def nav_link(anchor: str, label: str, scopes: str, *, disabled_reason: str | None = None) -> str:
        if available and anchor not in available:
            return ""
        if disabled_reason:
            return (
                f'<span class="sidebar-nav-disabled" data-disabled-anchor="#{_html_escape(anchor)}">'
                f'{_html_escape(label)}<small>{_html_escape(disabled_reason)}</small></span>'
            )
        allowed = {item.strip() for item in scopes.split() if item.strip()}
        hidden = current_depth not in allowed
        hidden_attrs = ' hidden tabindex="-1" aria-hidden="true"' if hidden else ""
        return (
            f'<a href="#{_html_escape(anchor)}" data-depth-nav="{_html_escape(scopes)}"{hidden_attrs}>'
            f'{_html_escape(label)}</a>'
        )

    template = """\

    <aside class="report-sidebar" aria-label="Rapor navigasyonu">
      <div class="sidebar-brand">
        <span class="brand-mark">RB</span>
        <div>
          <h1 class="sidebar-title">ReconBot</h1>
          <p class="sidebar-subtitle">Operatör Paneli</p>
        </div>
      </div>
      <div class="sidebar-target">
        <div class="label">Hedef</div>
        <code>__TARGET__</code>
      </div>
      <div class="sidebar-badges">
        <span class="pill __RUN_STATE_TONE__">__RUN_STATE__</span>
        <span class="pill __RISK_TONE__">Risk __RISK_SCORE__ / 100</span>
        <span class="pill warn">__RISK_BAND__</span>
      </div>
      <div class="sidebar-block" id="report-depth">
        <div class="sidebar-block-title">Rapor Derinliği</div>
        <div class="report-depth-controls" role="group" aria-label="Rapor derinliği anahtarı">
          <button type="button" class="report-depth-button" data-report-depth-button="summary" aria-pressed="false">Özet</button>
          <button type="button" class="report-depth-button" data-report-depth-button="balanced" aria-pressed="false">Dengeli</button>
          <button type="button" class="report-depth-button" data-report-depth-button="deep" aria-pressed="false">Derin</button>
        </div>
        <p class="note" data-report-depth-description>__DEPTH__: Modlar yalnızca raporun sunumunu değiştirir; scan verisi, severity, confidence ve artifact’lar değiştirilmez.</p>
      </div>
      <nav class="sidebar-nav" aria-label="Rapor bölümleri">
        __NAV_LINKS__
      </nav>
    </aside>
    """
    if osint_only:
        nav_items = [
            nav_link("osint-operator-brief", "Rapor Kısaca", "summary balanced deep"),
            nav_link("osint-intelligence-board", "ReconBot Ne Öğrendi?", "summary balanced deep"),
            nav_link("osint-evidence-context-fallback", "Kanıt / Bağlam / Manuel Öneri", "summary balanced deep"),
            nav_link("osint-source-health", "Kaynak Kapsamı", "summary balanced deep"),
            nav_link("osint-leak-breach-intelligence", "Darkweb / Sızıntı / İhlal", "summary balanced deep"),
            nav_link("osint-email-intelligence", "Herkese Açık İletişim", "summary balanced deep"),
            nav_link("osint-location-intelligence", "Konum İstihbaratı", "summary balanced deep"),
            nav_link("osint-public-document-intelligence", "Herkese Açık Dokümanlar", "summary balanced deep"),
            nav_link("osint-people-organization-presence", "Organizasyon / Profil Bağlamı", "summary balanced deep"),
            nav_link("osint-source-infrastructure", "Altyapı Bağlamı", "summary balanced deep"),
            nav_link("osint-manual-search-suggestions", "Manuel Arama Önerileri", "summary balanced deep"),
            nav_link("osint-diagnostics", "Gelişmiş Teşhisler", "summary balanced deep"),
        ]
    else:
        nav_items = [
            nav_link("overview", "Yönetici Özeti", "summary balanced deep"),
            nav_link("operator-plan", "İlk 15 Dakika Planı", "summary balanced deep"),
            nav_link("run-quality", "Rapor Güvenilirliği", "summary balanced deep"),
            nav_link("traffic-profile", "Trafik Profili", "summary balanced deep"),
        ]
        if include_ip_enrichment:
            nav_items.append(nav_link("ip-enrichment", "IP Zenginleştirme", "summary balanced deep"))
        if include_osint:
            nav_items.append(nav_link("osint-enrichment", "OSINT Yönetici Özeti", "summary balanced deep"))
        nav_items.extend(
            [
                nav_link("discovery", "Keşif", "balanced deep"),
                nav_link("cve-enrichment", "CVE Zenginleştirme", "balanced deep"),
                nav_link("priority-suggestions", "Öneriler", "summary balanced deep"),
                nav_link("screenshots", "Görsel Kanıt", "balanced deep"),
                nav_link("correlation-insights", "Korelasyon İçgörüleri", "summary balanced deep"),
                nav_link("attack-graph", "Saldırı Grafiği", "balanced deep"),
                nav_link("raw", "Ham Kanıt / Araç Çıktıları", "deep"),
            ]
        )
    nav_links = "\n        ".join(nav_items)
    return (
        template.replace("__TARGET__", target_html)
        .replace("__RUN_STATE__", run_state_html)
        .replace("__RUN_STATE_TONE__", run_state_tone)
        .replace("__RISK_SCORE__", str(int(risk_score or 0)))
        .replace("__RISK_TONE__", risk_tone)
        .replace("__RISK_BAND__", risk_band_html)
        .replace("__DEPTH__", depth_html)
        .replace("__NAV_LINKS__", nav_links)
    )
