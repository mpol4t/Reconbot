from __future__ import annotations

import json
import os
import posixpath
import shlex
import subprocess
import sys
import threading
import uuid
from datetime import datetime
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

_TOOL_ORDER: list[tuple[str, str]] = [
    ("nmap", "Nmap"),
    ("subfinder", "Subfinder"),
    ("dnsx", "DNSX"),
    ("httpx", "HTTPX"),
    ("katana", "Katana"),
    ("gobuster", "Gobuster"),
    ("ffuf", "FFUF"),
    ("historical_urls", "Historical"),
    ("wafw00f", "WAFW00F"),
    ("whatweb", "WhatWeb"),
    ("checks", "Web Checks"),
    ("screenshots", "Screenshots"),
    ("nuclei", "Nuclei"),
]


_DEFAULT_TOOL_ENABLED: dict[str, bool] = {
    "nmap": True,
    "subfinder": True,
    "dnsx": True,
    "httpx": True,
    "katana": True,
    "gobuster": True,
    "ffuf": False,
    "historical_urls": False,
    "wafw00f": True,
    "whatweb": True,
    "checks": True,
    "screenshots": False,
    "nuclei": True,
}


_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reconbot Control</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0b0c0a;
      --panel: #141511;
      --panel-2: #191b16;
      --line: #303326;
      --line-soft: #24271e;
      --text: #f2f4e8;
      --muted: #a9ad9b;
      --dim: #737866;
      --accent: #d8ff5f;
      --accent-2: #53d6c4;
      --warn: #ffbd5f;
      --bad: #ff6b6b;
      --ok: #79df83;
      --skip: #858a78;
      --shadow: 0 28px 90px rgba(0, 0, 0, .36);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    * { box-sizing: border-box; }

    html, body {
      width: 100%;
      height: 100%;
      margin: 0;
      background: var(--bg);
      color: var(--text);
      overflow: hidden;
    }

    body {
      min-width: 1120px;
    }

    button, input, select {
      font: inherit;
    }

    button {
      color: inherit;
    }

    .app {
      height: 100vh;
      display: grid;
      grid-template-columns: 310px minmax(560px, 1fr) 340px;
      background:
        linear-gradient(90deg, rgba(216, 255, 95, .03), transparent 28%),
        radial-gradient(circle at 72% 0%, rgba(83, 214, 196, .08), transparent 34%),
        var(--bg);
    }

    .rail,
    .inspector {
      height: 100vh;
      overflow: auto;
      background: rgba(20, 21, 17, .92);
      border-color: var(--line);
    }

    .rail {
      border-right: 1px solid var(--line);
      display: flex;
      flex-direction: column;
    }

    .inspector {
      border-left: 1px solid var(--line);
    }

    .brand {
      padding: 22px 20px 18px;
      border-bottom: 1px solid var(--line);
    }

    .brand-kicker {
      color: var(--accent);
      font-size: 11px;
      line-height: 1;
      text-transform: uppercase;
      letter-spacing: .08em;
      margin-bottom: 10px;
    }

    .brand h1 {
      margin: 0;
      font-size: 27px;
      line-height: 1.05;
      letter-spacing: 0;
    }

    .target {
      margin-top: 14px;
      min-height: 42px;
      display: flex;
      align-items: center;
      gap: 10px;
      color: var(--muted);
      word-break: break-word;
    }

    .target-dot {
      width: 8px;
      height: 8px;
      border-radius: 999px;
      flex: 0 0 auto;
      background: var(--accent-2);
      box-shadow: 0 0 0 5px rgba(83, 214, 196, .09);
    }

    .control-block {
      padding: 18px 16px;
      border-bottom: 1px solid var(--line-soft);
    }

    .setup-grid {
      display: grid;
      gap: 9px;
    }

    .field {
      display: grid;
      gap: 6px;
    }

    .field label {
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: .06em;
    }

    .input,
    .select {
      width: 100%;
      height: 36px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #0f100d;
      color: var(--text);
      padding: 0 10px;
      outline: none;
    }

    .input:focus,
    .select:focus {
      border-color: rgba(216, 255, 95, .58);
    }

    .app-actions {
      display: grid;
      grid-template-columns: 1fr 82px;
      gap: 8px;
      margin-top: 4px;
    }

    .primary-action,
    .secondary-action {
      height: 38px;
      border-radius: 8px;
      cursor: pointer;
    }

    .primary-action {
      border: 0;
      background: var(--accent);
      color: #141511;
      font-weight: 700;
    }

    .secondary-action {
      border: 1px solid var(--line);
      background: #10120e;
      color: var(--muted);
    }

    .primary-action:disabled,
    .secondary-action:disabled {
      cursor: not-allowed;
      opacity: .45;
    }

    .app-message {
      min-height: 18px;
      margin-top: 8px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.35;
    }

    .section-title {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 12px;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .08em;
    }

    .profile-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 7px;
    }

    .profile {
      height: 34px;
      border: 1px solid var(--line);
      background: #10120e;
      color: var(--muted);
      border-radius: 7px;
      cursor: default;
    }

    .app-editable .profile,
    .app-editable .tool-row {
      cursor: pointer;
    }

    .profile.is-active {
      border-color: rgba(216, 255, 95, .58);
      color: var(--text);
      background: rgba(216, 255, 95, .1);
    }

    .tool-list {
      display: flex;
      flex-direction: column;
      gap: 7px;
    }

    .tool-row {
      min-height: 46px;
      display: grid;
      grid-template-columns: 34px minmax(0, 1fr) auto;
      align-items: center;
      gap: 10px;
      padding: 7px 8px;
      border: 1px solid transparent;
      border-radius: 8px;
      background: rgba(255, 255, 255, .018);
      transition: border-color .18s ease, background .18s ease, transform .18s ease;
    }

    .tool-row.is-running {
      border-color: rgba(216, 255, 95, .34);
      background: rgba(216, 255, 95, .06);
    }

    .tool-row:hover {
      border-color: rgba(255, 255, 255, .11);
      background: rgba(255, 255, 255, .035);
      transform: translateX(1px);
    }

    .switch {
      width: 34px;
      height: 20px;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 2px;
      background: #0f100d;
      display: flex;
      align-items: center;
    }

    .switch::before {
      content: "";
      width: 14px;
      height: 14px;
      border-radius: 999px;
      background: var(--skip);
      transition: transform .2s ease, background .2s ease;
    }

    .tool-row.is-enabled .switch::before {
      transform: translateX(14px);
      background: var(--accent);
    }

    .tool-name {
      overflow: hidden;
      white-space: nowrap;
      text-overflow: ellipsis;
      font-size: 13px;
    }

    .tool-meta {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-top: 4px;
      color: var(--dim);
      font-size: 11px;
    }

    .status-pill {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 66px;
      height: 22px;
      padding: 0 8px;
      border-radius: 999px;
      border: 1px solid var(--line);
      color: var(--muted);
      background: #10120e;
      font-size: 11px;
      text-transform: uppercase;
    }

    .status-running { color: var(--accent); border-color: rgba(216, 255, 95, .45); }
    .status-done { color: var(--ok); border-color: rgba(121, 223, 131, .42); }
    .status-error { color: var(--bad); border-color: rgba(255, 107, 107, .42); }
    .status-skipped { color: var(--skip); }

    .workspace {
      min-width: 0;
      height: 100vh;
      display: grid;
      grid-template-rows: auto 1fr;
    }

    .topbar {
      min-height: 76px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      gap: 18px;
      padding: 18px 22px;
      border-bottom: 1px solid var(--line);
      background: rgba(11, 12, 10, .82);
      backdrop-filter: blur(16px);
    }

    .run-title {
      min-width: 0;
    }

    .run-title h2 {
      margin: 0;
      font-size: 18px;
      line-height: 1.2;
      letter-spacing: 0;
    }

    .run-subtitle {
      margin-top: 6px;
      color: var(--muted);
      font-size: 13px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .mode-tabs {
      height: 38px;
      display: inline-grid;
      grid-template-columns: 1fr 1fr;
      padding: 3px;
      border: 1px solid var(--line);
      border-radius: 9px;
      background: #10120e;
    }

    .mode-tab {
      min-width: 94px;
      border: 0;
      border-radius: 7px;
      background: transparent;
      color: var(--muted);
      cursor: pointer;
    }

    .mode-tab.is-active {
      background: var(--accent);
      color: #141511;
    }

    .content {
      min-height: 0;
      padding: 18px 22px 22px;
      display: grid;
      grid-template-rows: auto 1fr;
      gap: 14px;
    }

    .metric-strip {
      display: grid;
      grid-template-columns: repeat(6, minmax(96px, 1fr));
      gap: 10px;
    }

    .metric {
      min-height: 68px;
      border: 1px solid var(--line-soft);
      border-radius: 8px;
      background: rgba(20, 21, 17, .74);
      padding: 10px 11px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }

    .metric-label {
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: .06em;
    }

    .metric-value {
      font-size: 22px;
      line-height: 1;
      font-variant-numeric: tabular-nums;
    }

    .stage-bar {
      height: 3px;
      background: #1b1d17;
      border-radius: 99px;
      overflow: hidden;
    }

    .stage-bar span {
      display: block;
      height: 100%;
      width: 0;
      background: var(--accent);
      transition: width .45s ease;
    }

    .main-surface {
      min-height: 0;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: rgba(12, 13, 10, .9);
      box-shadow: var(--shadow);
      overflow: hidden;
      position: relative;
    }

    .console,
    .report-pane {
      position: absolute;
      inset: 0;
      display: none;
    }

    .main-surface[data-mode="console"] .console,
    .main-surface[data-mode="report"] .report-pane {
      display: block;
    }

    .console {
      padding: 18px;
      overflow: auto;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      font-size: 12px;
      line-height: 1.55;
      color: #dfe6d0;
      user-select: text;
      outline: none;
    }

    .console:focus {
      box-shadow: inset 0 0 0 1px rgba(216, 255, 95, .26);
    }

    .console-line {
      display: grid;
      grid-template-columns: 92px minmax(0, 1fr);
      gap: 14px;
      min-height: 22px;
      border-bottom: 1px solid rgba(255, 255, 255, .035);
      padding: 4px 0;
    }

    .console-time {
      color: var(--dim);
      font-variant-numeric: tabular-nums;
    }

    .console-text {
      min-width: 0;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }

    .console-text.is-truncated {
      color: #cfd8bd;
    }

    .console-expand {
      margin-left: 8px;
      padding: 0;
      border: 0;
      background: transparent;
      color: var(--accent);
      cursor: pointer;
      font: inherit;
      text-decoration: underline;
      text-underline-offset: 2px;
    }

    .report-toolbar {
      position: absolute;
      top: 10px;
      right: 12px;
      z-index: 2;
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 8px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(16, 18, 14, .9);
      color: var(--muted);
      font-size: 12px;
    }

    .report-toolbar input {
      accent-color: var(--accent);
    }

    .report-pane iframe {
      width: 100%;
      height: 100%;
      border: 0;
      background: #ffffff;
    }

    .report-empty {
      height: 100%;
      display: grid;
      place-items: center;
      color: var(--muted);
      text-align: center;
      padding: 24px;
    }

    .report-empty strong {
      color: var(--text);
      display: block;
      margin-bottom: 8px;
      font-size: 18px;
    }

    .inspector-inner {
      padding: 20px 18px 26px;
    }

    .panel {
      border-bottom: 1px solid var(--line-soft);
      padding: 0 0 18px;
      margin-bottom: 18px;
    }

    .panel:last-child {
      border-bottom: 0;
      margin-bottom: 0;
    }

    .panel h3 {
      margin: 0 0 12px;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: .08em;
      color: var(--muted);
    }

    .kv {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 14px;
      padding: 8px 0;
      border-bottom: 1px solid rgba(255, 255, 255, .045);
      font-size: 13px;
    }

    .kv:last-child { border-bottom: 0; }
    .kv span:first-child { color: var(--muted); }
    .kv span:last-child { color: var(--text); font-variant-numeric: tabular-nums; }

    .actions {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
    }

    .action {
      height: 36px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #10120e;
      color: var(--text);
      text-decoration: none;
      font-size: 13px;
      transition: border-color .18s ease, background .18s ease;
    }

    .action:hover {
      border-color: rgba(216, 255, 95, .45);
      background: rgba(216, 255, 95, .08);
    }

    .finding-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .finding {
      border: 1px solid var(--line-soft);
      border-radius: 8px;
      padding: 10px;
      background: rgba(255, 255, 255, .02);
    }

    .finding-title {
      font-size: 13px;
      line-height: 1.35;
      overflow-wrap: anywhere;
    }

    .finding-meta {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 8px;
      color: var(--muted);
      font-size: 11px;
    }

    .empty {
      color: var(--dim);
      font-size: 13px;
      line-height: 1.45;
    }

    @media (max-width: 1180px) {
      body { min-width: 0; overflow: auto; }
      .app {
        min-height: 100vh;
        height: auto;
        grid-template-columns: 280px minmax(520px, 1fr);
      }
      .inspector {
        grid-column: 1 / -1;
        height: auto;
        border-left: 0;
        border-top: 1px solid var(--line);
      }
      .workspace,
      .rail {
        height: 100vh;
      }
      .metric-strip {
        grid-template-columns: repeat(3, minmax(96px, 1fr));
      }
    }

    @media (max-width: 820px) {
      .app {
        display: block;
      }
      .rail,
      .workspace,
      .inspector {
        height: auto;
        min-height: auto;
      }
      .workspace {
        min-height: 760px;
      }
      .topbar {
        grid-template-columns: 1fr;
      }
      .metric-strip {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .main-surface {
        min-height: 560px;
      }
    }
  </style>
</head>
<body>
  <main class="app">
    <aside class="rail">
      <section class="brand">
        <div class="brand-kicker">Reconbot</div>
        <h1>Operator Control</h1>
        <div class="target"><span class="target-dot"></span><span id="targetText">Target bekleniyor</span></div>
      </section>

      <section class="control-block" id="setupPanel">
        <div class="section-title"><span>Setup</span><span id="appModeLabel">app</span></div>
        <div class="setup-grid">
          <div class="field">
            <label for="targetInput">Target</label>
            <input class="input" id="targetInput" autocomplete="off" spellcheck="false" placeholder="https://example.com">
          </div>
          <div class="field">
            <label for="wordlistInput">Wordlist</label>
            <input class="input" id="wordlistInput" autocomplete="off" spellcheck="false" placeholder="/path/to/wordlist.txt">
          </div>
          <div class="field">
            <label for="depthSelect">Report depth</label>
            <select class="select" id="depthSelect">
              <option value="summary">Summary</option>
              <option value="balanced">Balanced</option>
              <option value="deep">Deep</option>
            </select>
          </div>
          <div class="app-actions">
            <button class="primary-action" id="startButton">Start scan</button>
            <button class="secondary-action" id="stopButton">Stop</button>
          </div>
          <div class="app-message" id="appMessage">Ayarları seçip scan başlat.</div>
        </div>
      </section>

      <section class="control-block">
        <div class="section-title"><span>Traffic</span><span id="runState">starting</span></div>
        <div class="profile-grid" id="profileGrid">
          <button class="profile" data-profile="safe">Safe</button>
          <button class="profile" data-profile="balanced">Balanced</button>
          <button class="profile" data-profile="fast">Fast</button>
        </div>
      </section>

      <section class="control-block">
        <div class="section-title"><span>Tools</span><span id="toolCount">0 active</span></div>
        <div class="tool-list" id="toolList"></div>
      </section>
    </aside>

    <section class="workspace">
      <header class="topbar">
        <div class="run-title">
          <h2 id="workspaceTitle">Run hazırlanıyor</h2>
          <div class="run-subtitle" id="workspaceSubtitle">Stage state bekleniyor</div>
        </div>
        <div class="mode-tabs">
          <button class="mode-tab is-active" data-view="console">Console</button>
          <button class="mode-tab" data-view="report">Report</button>
        </div>
      </header>

      <section class="content">
        <div>
          <div class="metric-strip" id="metricStrip"></div>
          <div class="stage-bar" aria-hidden="true"><span id="stageProgress"></span></div>
        </div>

        <div class="main-surface" id="mainSurface" data-mode="console">
          <div class="console" id="consoleView"></div>
          <div class="report-pane" id="reportView">
            <label class="report-toolbar">
              <input type="checkbox" id="reportAutoRefresh" checked>
              Auto-refresh report
            </label>
            <div class="report-empty" id="reportEmpty">
              <div><strong>Rapor bekleniyor</strong><span>İlk report.html üretildiğinde burada açılacak.</span></div>
            </div>
            <iframe id="reportFrame" title="Reconbot report"></iframe>
          </div>
        </div>
      </section>
    </section>

    <aside class="inspector">
      <div class="inspector-inner">
        <section class="panel">
          <h3>Run</h3>
          <div class="kv"><span>Mode</span><span id="modeValue">-</span></div>
          <div class="kv"><span>Report depth</span><span id="depthValue">-</span></div>
          <div class="kv"><span>Nuclei</span><span id="nucleiValue">-</span></div>
          <div class="kv"><span>Last update</span><span id="updatedValue">-</span></div>
        </section>

        <section class="panel">
          <h3>Artifacts</h3>
          <div class="actions">
            <a class="action" href="report.html" target="_blank">Report</a>
            <a class="action" href="run_result.json" target="_blank">State</a>
            <a class="action" href="checks.json" target="_blank">Checks</a>
            <a class="action" href="reconbot.log" target="_blank">Log</a>
          </div>
        </section>

        <section class="panel">
          <h3>Live Findings</h3>
          <div class="finding-list" id="findingList"><div class="empty">Henüz canlı finding yok.</div></div>
        </section>

        <section class="panel">
          <h3>Stage Detail</h3>
          <div id="stageDetail"><div class="empty">Stage bekleniyor.</div></div>
        </section>
      </div>
    </aside>
  </main>

  <script>
    const state = {
      selectedView: "console",
      autoReport: true,
      reportAutoRefresh: true,
      reportVersion: "",
      pendingReportScrollY: 0,
      consoleHash: "",
      expandedConsoleLines: new Set(),
      setup: null,
      lastAppRunning: false,
    };

    const toolList = document.getElementById("toolList");
    const metricStrip = document.getElementById("metricStrip");
    const consoleView = document.getElementById("consoleView");
    const mainSurface = document.getElementById("mainSurface");
    const reportFrame = document.getElementById("reportFrame");
    const reportAutoRefresh = document.getElementById("reportAutoRefresh");
    const reportEmpty = document.getElementById("reportEmpty");
    const findingList = document.getElementById("findingList");
    const stageDetail = document.getElementById("stageDetail");
    const targetInput = document.getElementById("targetInput");
    const wordlistInput = document.getElementById("wordlistInput");
    const depthSelect = document.getElementById("depthSelect");
    const startButton = document.getElementById("startButton");
    const stopButton = document.getElementById("stopButton");
    const appMessage = document.getElementById("appMessage");

    function esc(value) {
      return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[ch]));
    }

    function statusClass(status) {
      const normalized = String(status || "pending").toLowerCase();
      if (normalized === "running") return "status-running";
      if (normalized === "done" || normalized === "completed") return "status-done";
      if (normalized === "error" || normalized === "failed" || normalized === "interrupted") return "status-error";
      if (normalized === "skipped" || normalized === "auto-skipped") return "status-skipped";
      return "";
    }

    function currentReportScrollY() {
      try {
        return reportFrame.contentWindow ? reportFrame.contentWindow.scrollY || 0 : 0;
      } catch (_) {
        return 0;
      }
    }

    reportFrame.addEventListener("load", () => {
      const y = state.pendingReportScrollY || 0;
      if (!y) return;
      requestAnimationFrame(() => {
        try {
          reportFrame.contentWindow.scrollTo(0, y);
        } catch (_) {}
      });
    });

    reportAutoRefresh.addEventListener("change", () => {
      state.reportAutoRefresh = reportAutoRefresh.checked;
    });

    function setView(view, manual = false) {
      if (manual) {
        state.autoReport = false;
      }
      state.selectedView = view;
      mainSurface.dataset.mode = view;
      document.querySelectorAll(".mode-tab").forEach((btn) => {
        btn.classList.toggle("is-active", btn.dataset.view === view);
      });
    }

    document.querySelectorAll(".mode-tab").forEach((btn) => {
      btn.addEventListener("click", () => setView(btn.dataset.view, true));
    });

    function setupFromDefaults(defaults) {
      const toolMap = {};
      (defaults.tools || []).forEach((tool) => {
        toolMap[tool.name] = Boolean(tool.enabled);
      });
      return {
        target: defaults.target || "",
        wordlist: defaults.wordlist || "",
        traffic_profile: defaults.traffic_profile || "balanced",
        report_depth: defaults.report_depth || "balanced",
        tools: toolMap,
      };
    }

    function syncSetupInputs(app, defaults) {
      if (!app || !app.enabled) {
        document.getElementById("setupPanel").style.display = "none";
        return;
      }
      document.getElementById("setupPanel").style.display = "block";
      document.body.classList.toggle("app-editable", !app.running);
      if (!state.setup) {
        state.setup = setupFromDefaults(defaults || {});
        targetInput.value = state.setup.target;
        wordlistInput.value = state.setup.wordlist;
        depthSelect.value = state.setup.report_depth;
      }
      const editable = !app.running;
      targetInput.disabled = !editable;
      wordlistInput.disabled = !editable;
      depthSelect.disabled = !editable;
      startButton.disabled = !editable;
      stopButton.disabled = !app.running;
      document.getElementById("appModeLabel").textContent = app.running ? "running" : "ready";
      appMessage.textContent = app.message || app.error || (editable ? "Ayarları seçip scan başlat." : "Scan çalışıyor.");
    }

    function selectedToolsAsRows(serverTools, app, runState) {
      const hasActiveRun = Boolean(app && app.current_run_dir);
      if (!app || !app.enabled || !state.setup || app.running || hasActiveRun || runState !== "idle") {
        return serverTools || [];
      }
      return (serverTools || []).map((tool) => ({
        ...tool,
        enabled: Boolean(state.setup.tools[tool.name]),
        status: Boolean(state.setup.tools[tool.name]) ? "pending" : "skipped",
        metric: Boolean(state.setup.tools[tool.name]) ? "selected" : "disabled",
      }));
    }

    function renderProfiles(profile) {
      document.querySelectorAll(".profile").forEach((btn) => {
        btn.classList.toggle("is-active", btn.dataset.profile === profile);
      });
    }

    function renderTools(tools, app) {
      const active = tools.filter((tool) => tool.enabled && tool.status !== "auto-skipped").length;
      document.getElementById("toolCount").textContent = `${active} active`;
      toolList.innerHTML = tools.map((tool) => {
        const status = esc(tool.status || "pending");
        const rowClass = [
          "tool-row",
          tool.enabled ? "is-enabled" : "",
          status === "running" ? "is-running" : "",
        ].filter(Boolean).join(" ");
        return `
          <div class="${rowClass}" data-tool="${esc(tool.name)}" title="${esc(tool.label)}">
            <span class="switch" aria-hidden="true"></span>
            <div>
              <div class="tool-name">${esc(tool.label)}</div>
              <div class="tool-meta">${esc(tool.reason || tool.metric || tool.phase || "ready")}</div>
            </div>
            <span class="status-pill ${statusClass(status)}">${status}</span>
          </div>
        `;
      }).join("");
      if (app && app.enabled && !app.running && state.setup) {
        toolList.querySelectorAll(".tool-row").forEach((row) => {
          row.addEventListener("click", () => {
            const name = row.dataset.tool;
            state.setup.tools[name] = !state.setup.tools[name];
            renderTools(selectedToolsAsRows(tools, app), app);
          });
        });
      }
    }

    function renderMetrics(summary) {
      const metrics = [
        ["Katana", summary.katana_count || 0],
        ["Checks", summary.checks_checked || 0],
        ["Gobuster", summary.gobuster_total_hits || 0],
        ["FFUF", summary.ffuf_hits || 0],
        ["Historical", summary.historical_live_count || 0],
        ["Nuclei", summary.nuclei_findings_count || 0],
      ];
      metricStrip.innerHTML = metrics.map(([label, value]) => `
        <div class="metric">
          <div class="metric-label">${esc(label)}</div>
          <div class="metric-value">${esc(value)}</div>
        </div>
      `).join("");
    }

    function consolePreview(text, key) {
      const value = String(text || "");
      const limit = 1200;
      if (value.length <= limit || state.expandedConsoleLines.has(key)) {
        return { text: value, truncated: false };
      }
      return { text: `${value.slice(0, limit)} ...`, truncated: true };
    }

    function renderConsole(lines) {
      const normalized = lines && lines.length ? lines : [{ time: "--:--:--", text: "Dashboard waiting for run output..." }];
      const hash = normalized.map((line) => `${line.time}|${line.text}`).join("\n");
      const shouldStick = consoleView.scrollTop + consoleView.clientHeight >= consoleView.scrollHeight - 48;
      if (hash !== state.consoleHash) {
        state.consoleHash = hash;
        consoleView.innerHTML = normalized.map((line, index) => {
          const key = `${line.time}|${index}|${line.text}`;
          const preview = consolePreview(line.text || "", key);
          return `
          <div class="console-line">
            <span class="console-time">${esc(line.time || "")}</span>
            <span class="console-text ${preview.truncated ? "is-truncated" : ""}">
              ${esc(preview.text)}
              ${preview.truncated ? `<button class="console-expand" data-key="${esc(key)}">show full</button>` : ""}
            </span>
          </div>
        `;
        }).join("");
        consoleView.querySelectorAll(".console-expand").forEach((button) => {
          button.addEventListener("click", () => {
            state.expandedConsoleLines.add(button.dataset.key || "");
            state.consoleHash = "";
            renderConsole(normalized);
          });
        });
        if (shouldStick) {
          consoleView.scrollTop = consoleView.scrollHeight;
        }
      }
    }

    function renderFindings(findings) {
      if (!findings || !findings.length) {
        findingList.innerHTML = '<div class="empty">Henüz canlı finding yok.</div>';
        return;
      }
      findingList.innerHTML = findings.slice(0, 8).map((finding) => `
        <div class="finding">
          <div class="finding-title">${esc(finding.name || "Unknown")}</div>
          <div class="finding-meta">
            <span>${esc(finding.severity || "unknown")}</span>
            <span>${esc(finding.template_id || "-")}</span>
          </div>
        </div>
      `).join("");
    }

    function renderStageDetail(stages) {
      const entries = Object.entries(stages || {});
      if (!entries.length) {
        stageDetail.innerHTML = '<div class="empty">Stage bekleniyor.</div>';
        return;
      }
      const current = entries.find(([, data]) => data && data.status === "running")
        || entries.slice().reverse().find(([, data]) => data && data.status && data.status !== "pending")
        || entries[0];
      const [name, data] = current;
      const artifacts = data.artifacts && typeof data.artifacts === "object" ? Object.keys(data.artifacts).length : 0;
      stageDetail.innerHTML = `
        <div class="kv"><span>Stage</span><span>${esc(name)}</span></div>
        <div class="kv"><span>Status</span><span>${esc(data.status || "pending")}</span></div>
        <div class="kv"><span>Started</span><span>${esc(data.started_at || "-")}</span></div>
        <div class="kv"><span>Ended</span><span>${esc(data.ended_at || "-")}</span></div>
        <div class="kv"><span>Artifacts</span><span>${artifacts}</span></div>
      `;
    }

    function renderReport(report) {
      if (!report || !report.available) {
        reportFrame.removeAttribute("src");
        state.reportVersion = "";
        reportFrame.style.display = "none";
        reportEmpty.style.display = "grid";
        return;
      }
      const version = String(report.mtime || "");
      const hasSrc = Boolean(reportFrame.getAttribute("src"));
      const shouldLoad = !hasSrc || (state.reportAutoRefresh && version && version !== state.reportVersion);
      if (shouldLoad) {
        state.pendingReportScrollY = currentReportScrollY();
        state.reportVersion = version;
        reportFrame.src = `report.html?v=${encodeURIComponent(version)}`;
      }
      reportFrame.style.display = "block";
      reportEmpty.style.display = "none";
    }

    function renderProgress(progress) {
      document.getElementById("stageProgress").style.width = `${Math.max(0, Math.min(100, progress || 0))}%`;
    }

    function render(data) {
      const meta = data.meta || {};
      const summary = data.summary || {};
      const report = data.report || {};
      const traffic = data.traffic || {};
      const app = data.app || {};
      const defaults = data.defaults || {};
      syncSetupInputs(app, defaults);
      if (state.lastAppRunning && !app.running) {
        state.autoReport = true;
      }
      state.lastAppRunning = Boolean(app.running);

      const setupTarget = state.setup && state.setup.target ? state.setup.target : "";
      document.getElementById("targetText").textContent = meta.target || setupTarget || "Target bekleniyor";
      document.getElementById("runState").textContent = data.run_state || "starting";
      document.getElementById("workspaceTitle").textContent = meta.target ? `Run: ${meta.target}` : "Scan hazır";
      document.getElementById("workspaceSubtitle").textContent = data.current_stage
        ? `${data.current_stage.label} / ${data.current_stage.status}`
        : (app.enabled ? "Target, profil ve tool seçimini soldan yap." : "Stage state bekleniyor");
      document.getElementById("modeValue").textContent = meta.mode || "-";
      document.getElementById("depthValue").textContent = meta.report_depth || (state.setup ? state.setup.report_depth : "-");
      document.getElementById("nucleiValue").textContent = summary.nuclei_status || (summary.nuclei_running ? "running" : "-");
      document.getElementById("updatedValue").textContent = data.updated_at || "-";

      const trafficProfile = traffic.requested_profile || traffic.profile || traffic.effective_profile || meta.traffic_profile || defaults.traffic_profile || (state.setup ? state.setup.traffic_profile : "balanced");
      renderProfiles(app.enabled && state.setup && !app.running && !app.current_run_dir ? state.setup.traffic_profile : trafficProfile);
      renderTools(selectedToolsAsRows(data.tools || [], app, data.run_state || "idle"), app);
      renderMetrics(summary);
      renderConsole(data.console || []);
      renderFindings(data.live_findings || []);
      renderStageDetail(data.stages || {});
      renderReport(report);
      renderProgress(data.progress || 0);

      if (state.autoReport && data.center_mode === "report" && report.available) {
        setView("report");
      }
    }

    document.querySelectorAll(".profile").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (!state.setup) return;
        state.setup.traffic_profile = btn.dataset.profile;
        renderProfiles(state.setup.traffic_profile);
      });
    });

    targetInput.addEventListener("input", () => {
      if (state.setup) state.setup.target = targetInput.value;
    });

    wordlistInput.addEventListener("input", () => {
      if (state.setup) state.setup.wordlist = wordlistInput.value;
    });

    depthSelect.addEventListener("change", () => {
      if (state.setup) state.setup.report_depth = depthSelect.value;
    });

    async function postJson(path, payload = {}) {
      const response = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(body.error || `HTTP ${response.status}`);
      }
      return body;
    }

    startButton.addEventListener("click", async () => {
      if (!state.setup) return;
      appMessage.textContent = "Scan başlatılıyor...";
      try {
        await postJson("/api/run", state.setup);
        state.autoReport = true;
        state.reportVersion = "";
        setView("console", false);
        await refresh();
      } catch (error) {
        appMessage.textContent = error.message;
      }
    });

    stopButton.addEventListener("click", async () => {
      appMessage.textContent = "Stop isteği gönderiliyor...";
      try {
        const result = await postJson("/api/stop", { source: "button" });
        appMessage.textContent = result.message || "Stop isteği gönderildi.";
        await refresh();
      } catch (error) {
        appMessage.textContent = error.message;
      }
    });

    consoleView.setAttribute("tabindex", "0");
    consoleView.addEventListener("keydown", async (event) => {
      const hasSelection = String(window.getSelection ? window.getSelection() : "").length > 0;
      const wantsStop = (event.ctrlKey && event.key.toLowerCase() === "c" && !hasSelection)
        || (event.metaKey && event.key === ".");
      if (!wantsStop) return;
      event.preventDefault();
      appMessage.textContent = "Console shortcut stop isteği gönderiyor...";
      try {
        const result = await postJson("/api/stop", { source: "console shortcut" });
        appMessage.textContent = result.message || "Stop isteği gönderildi.";
        await refresh();
      } catch (error) {
        appMessage.textContent = error.message;
      }
    });

    async function refresh() {
      try {
        const response = await fetch(`/api/state?ts=${Date.now()}`, { cache: "no-store" });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        render(data);
      } catch (error) {
        renderConsole([{ time: "--:--:--", text: `Dashboard API error: ${error.message}` }]);
      }
    }

    refresh();
    setInterval(refresh, 1500);
  </script>
</body>
</html>
"""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return raw
    except Exception:
        pass
    return {}


def _tail_lines(path: Path, limit: int = 160) -> list[str]:
    try:
        if not path.exists() or not path.is_file():
            return []
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        return lines[-limit:]
    except Exception:
        return []


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _safe_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in {"1", "true", "yes", "on"}:
            return True
        if low in {"0", "false", "no", "off"}:
            return False
    return default


def _default_tool_rows(selected: dict[str, bool] | None = None) -> list[dict[str, Any]]:
    selected = selected or _DEFAULT_TOOL_ENABLED
    rows: list[dict[str, Any]] = []
    for name, label in _TOOL_ORDER:
        enabled = bool(selected.get(name, _DEFAULT_TOOL_ENABLED.get(name, True)))
        rows.append(
            {
                "name": name,
                "label": label,
                "enabled": enabled,
                "status": "pending" if enabled else "skipped",
                "metric": "selected" if enabled else "disabled",
                "phase": "scan",
            }
        )
    return rows


def _tool_selection_from_rows(rows: Any) -> dict[str, bool]:
    selected = dict(_DEFAULT_TOOL_ENABLED)
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "")
            if name in selected:
                selected[name] = bool(row.get("enabled"))
    return selected


def _tool_selection_from_payload(payload_tools: Any) -> dict[str, bool]:
    selected = dict(_DEFAULT_TOOL_ENABLED)
    if isinstance(payload_tools, dict):
        for name, _label in _TOOL_ORDER:
            selected[name] = _safe_bool(payload_tools.get(name), _DEFAULT_TOOL_ENABLED.get(name, True))
    return selected


def _is_url_target(target: str) -> bool:
    target_text = str(target or "").strip().lower()
    return target_text.startswith("http://") or target_text.startswith("https://")


def _auto_skipped_tools_for_target(target: str, selected_tools: dict[str, bool]) -> dict[str, str]:
    if not _is_url_target(target):
        return {}
    reason = "auto-skipped: URL target mode"
    return {
        name: reason
        for name in ("subfinder", "dnsx", "httpx")
        if selected_tools.get(name)
    }


def _app_defaults_from_config(config_defaults: dict[str, Any] | None, base_output_dir: str | None) -> dict[str, Any]:
    cfg = config_defaults or {}
    selected_tools: dict[str, bool] = {}
    for name, _label in _TOOL_ORDER:
        field = "screenshots_enable" if name == "screenshots" else f"{name}_enabled"
        selected_tools[name] = _safe_bool(cfg.get(field), _DEFAULT_TOOL_ENABLED.get(name, True))

    return {
        "target": str(cfg.get("target") or ""),
        "wordlist": str(cfg.get("wordlist") or ""),
        "output_dir": str(base_output_dir or cfg.get("output_dir") or ""),
        "traffic_profile": str(cfg.get("traffic_profile") or "balanced"),
        "report_depth": str(cfg.get("report_depth") or "balanced"),
        "tools": _default_tool_rows(selected_tools),
    }


def _write_app_config(path: Path, payload: dict[str, Any], output_base_dir: Path) -> None:
    tools = payload.get("tools") if isinstance(payload.get("tools"), dict) else {}
    reconbot_cfg: dict[str, Any] = {
        "wordlist": str(payload.get("wordlist") or "").strip(),
        "output_dir": str(output_base_dir),
        "verbose": True,
        "traffic_profile": str(payload.get("traffic_profile") or "balanced"),
        "report_depth": str(payload.get("report_depth") or "balanced"),
    }
    for name, _label in _TOOL_ORDER:
        enabled = _safe_bool(tools.get(name), _DEFAULT_TOOL_ENABLED.get(name, True))
        field = "screenshots_enable" if name == "screenshots" else f"{name}_enabled"
        reconbot_cfg[field] = enabled
    config_payload = {"reconbot": reconbot_cfg}
    path.write_text(json.dumps(config_payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _file_mtime(path: Path) -> float:
    try:
        if path.exists():
            return path.stat().st_mtime
    except Exception:
        pass
    return 0.0


def _clock_from_line(line: str) -> str:
    text = str(line or "")
    if len(text) >= 19 and text[4] == "-" and text[13] == ":":
        return text[11:19]
    return ""


def _line_without_timestamp(line: str) -> str:
    text = str(line or "")
    if len(text) >= 20 and text[4] == "-" and text[13] == ":":
        return text[20:].strip()
    return text.strip()


def _stage_label(name: str) -> str:
    for tool_name, label in _TOOL_ORDER:
        if tool_name == name:
            return label
    return name.replace("_", " ").title()


def _tool_metric(name: str, summary: dict[str, Any], stage: dict[str, Any]) -> str:
    if name == "katana":
        return f"{_safe_int(summary.get('katana_count'))} urls"
    if name == "gobuster":
        return f"{_safe_int(summary.get('gobuster_total_hits'))} hits"
    if name == "ffuf":
        return f"{_safe_int(summary.get('ffuf_hits'))} hits"
    if name == "historical_urls":
        return f"{_safe_int(summary.get('historical_live_count'))} live"
    if name == "screenshots":
        return f"{_safe_int(summary.get('screenshots_captured_count'))} files"
    if name == "checks":
        return f"{_safe_int(summary.get('checks_checked'))} checked"
    if name == "nuclei":
        if stage.get("findings_count") is not None:
            return f"{_safe_int(stage.get('findings_count'))} findings"
        return f"{_safe_int(summary.get('nuclei_findings_count'))} findings"
    artifacts = stage.get("artifacts") if isinstance(stage.get("artifacts"), dict) else {}
    if artifacts:
        return f"{len(artifacts)} artifacts"
    return "ready"


def _normalize_skipped(run_result: dict[str, Any], initial_state: dict[str, Any]) -> set[str]:
    skipped: set[str] = set()
    for source in (
        initial_state.get("skipped_tools"),
        run_result.get("skipped_tools"),
        (run_result.get("meta") if isinstance(run_result.get("meta"), dict) else {}).get("skipped_tools"),
    ):
        if isinstance(source, list):
            skipped.update(str(item) for item in source if str(item or "").strip())
    return skipped


def _build_tools(run_result: dict[str, Any], initial_state: dict[str, Any]) -> list[dict[str, Any]]:
    stages = run_result.get("stages") if isinstance(run_result.get("stages"), dict) else {}
    summary = run_result.get("summary") if isinstance(run_result.get("summary"), dict) else {}
    skipped = _normalize_skipped(run_result, initial_state)
    selected_tools = initial_state.get("selected_tools")
    if not isinstance(selected_tools, dict):
        selected_tools = _tool_selection_from_rows((initial_state.get("defaults") or {}).get("tools") if isinstance(initial_state.get("defaults"), dict) else [])
    auto_skipped = initial_state.get("auto_skipped_tools")
    if not isinstance(auto_skipped, dict):
        auto_skipped = {}

    tools: list[dict[str, Any]] = []
    for name, label in _TOOL_ORDER:
        stage = stages.get(name) if isinstance(stages.get(name), dict) else {}
        status = str(stage.get("status") or ("skipped" if name in skipped else "pending"))
        selected = bool(selected_tools.get(name, _DEFAULT_TOOL_ENABLED.get(name, True)))
        reason = str(auto_skipped.get(name) or "")
        if not selected and status == "pending":
            status = "skipped"
        if status == "skipped" and selected and reason:
            status = "auto-skipped"
        enabled = selected and status != "skipped"
        metric = "disabled" if not selected else _tool_metric(name, summary, stage)
        tools.append(
            {
                "name": name,
                "label": label,
                "enabled": enabled,
                "selected": selected,
                "reason": reason,
                "status": status,
                "metric": metric,
                "phase": "scan",
            }
        )
    return tools


def _build_console(run_dir: Path, run_result: dict[str, Any]) -> list[dict[str, str]]:
    lines: list[dict[str, str]] = []
    run_log_lines = _tail_lines(run_dir / "reconbot.log", limit=150)
    nuclei_log_lines = _tail_lines(run_dir / "nuclei.log", limit=40)

    for line in run_log_lines:
        lines.append({"time": _clock_from_line(line) or "run", "text": _line_without_timestamp(line)})

    if nuclei_log_lines:
        lines.append({"time": "nuclei", "text": "--- nuclei.log tail ---"})
        for line in nuclei_log_lines:
            lines.append({"time": _clock_from_line(line) or "nuclei", "text": _line_without_timestamp(line)})

    if lines:
        return lines[-180:]

    stages = run_result.get("stages") if isinstance(run_result.get("stages"), dict) else {}
    for name, stage in stages.items():
        if not isinstance(stage, dict):
            continue
        status = str(stage.get("status") or "pending")
        if status == "pending":
            continue
        when = str(stage.get("ended_at") or stage.get("started_at") or "")
        lines.append({"time": when[11:19] if len(when) >= 19 else "stage", "text": f"{_stage_label(name)} -> {status}"})
    return lines[-180:]


def _build_live_findings(run_dir: Path, run_result: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    nuclei = run_result.get("nuclei") if isinstance(run_result.get("nuclei"), dict) else {}
    output_path = nuclei.get("output_path") if isinstance(nuclei, dict) else None
    candidates = []
    if output_path:
        candidates.append(Path(str(output_path)))
    candidates.append(run_dir / "nuclei_output.jsonl")

    jsonl_path = next((path for path in candidates if path.exists()), None)
    if jsonl_path is None:
        return []

    for raw_line in _tail_lines(jsonl_path, limit=80):
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        if not isinstance(item, dict):
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        findings.append(
            {
                "name": str(info.get("name") or item.get("template-id") or "Unknown"),
                "severity": str(info.get("severity") or "unknown"),
                "template_id": str(item.get("template-id") or "Unknown"),
                "matched_at": str(item.get("matched-at") or item.get("host") or item.get("url") or ""),
            }
        )
    return findings[-20:]


def _merge_meta(run_result: dict[str, Any], initial_state: dict[str, Any]) -> dict[str, Any]:
    meta = run_result.get("meta") if isinstance(run_result.get("meta"), dict) else {}
    traffic = run_result.get("traffic") if isinstance(run_result.get("traffic"), dict) else {}
    defaults = initial_state.get("defaults") if isinstance(initial_state.get("defaults"), dict) else {}
    traffic_profile = (
        traffic.get("requested_profile")
        or traffic.get("profile")
        or traffic.get("effective_profile")
        or meta.get("traffic_profile")
        or initial_state.get("traffic_profile")
        or defaults.get("traffic_profile")
        or ""
    )
    return {
        "target": meta.get("target") or initial_state.get("target") or "",
        "mode": meta.get("mode") or initial_state.get("mode") or "",
        "timestamp": meta.get("timestamp") or initial_state.get("timestamp") or "",
        "report_depth": meta.get("report_depth") or initial_state.get("report_depth") or "",
        "traffic_profile": traffic_profile,
        "skipped_tools": sorted(_normalize_skipped(run_result, initial_state)),
    }


def _build_state(
    run_dir: Path,
    initial_state: dict[str, Any],
    app_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    app_state = app_state or {}
    active_run_dir = app_state.get("current_run_dir")
    effective_run_dir = Path(active_run_dir).resolve() if active_run_dir else run_dir
    run_result = _read_json(effective_run_dir / "run_result.json")
    summary = run_result.get("summary") if isinstance(run_result.get("summary"), dict) else {}
    run_result_stages = run_result.get("stages") if isinstance(run_result.get("stages"), dict) else {}
    live_stages = _read_json(effective_run_dir / "stages_live.json")
    proc = app_state.get("proc")
    running = bool(proc is not None and getattr(proc, "poll", lambda: None)() is None)
    run_state = str(run_result.get("run_state") or ("running" if running else ("idle" if app_state.get("enabled") else "starting")))
    if live_stages and run_state not in {"completed", "failed", "interrupted"}:
        stages = live_stages
    else:
        stages = run_result_stages or live_stages
    report_path = effective_run_dir / "report.html"

    run_result_with_live = dict(run_result)
    run_result_with_live["stages"] = stages
    if not run_result and app_state.get("defaults"):
        tools = _build_tools({"stages": {}}, initial_state)
    else:
        tools = _build_tools(run_result_with_live, initial_state)
    completed_count = len([tool for tool in tools if tool["status"] in {"done", "skipped", "auto-skipped", "error"}])
    progress = round((completed_count / len(tools)) * 100) if tools else 0
    current_tool = next((tool for tool in tools if tool["status"] == "running"), None)
    if current_tool is None:
        current_tool = next((tool for tool in reversed(tools) if tool["status"] in {"done", "error", "skipped"}), None)

    nuclei_stage = stages.get("nuclei") if isinstance(stages.get("nuclei"), dict) else {}
    nuclei_started = bool(nuclei_stage and str(nuclei_stage.get("status") or "pending") != "pending")
    center_mode = "report" if report_path.exists() and (nuclei_started or run_state in {"completed", "failed", "interrupted"}) else "console"

    traffic = run_result.get("traffic") if isinstance(run_result.get("traffic"), dict) else {}
    defaults_for_traffic = app_state.get("defaults") if isinstance(app_state.get("defaults"), dict) else {}
    traffic_profile = (
        traffic.get("requested_profile")
        or traffic.get("profile")
        or traffic.get("effective_profile")
        or initial_state.get("traffic_profile")
        or defaults_for_traffic.get("traffic_profile")
        or "balanced"
    )
    if "profile" not in traffic:
        traffic = {**traffic, "profile": traffic_profile}
    if "requested_profile" not in traffic:
        traffic = {**traffic, "requested_profile": traffic_profile}

    return {
        "updated_at": datetime.now().strftime("%H:%M:%S"),
        "run_state": run_state,
        "auto_refresh_enabled": bool(run_result.get("auto_refresh_enabled", True)),
        "meta": _merge_meta(run_result, initial_state),
        "summary": summary,
        "traffic": traffic,
        "stages": stages,
        "tools": tools,
        "progress": progress,
        "current_stage": current_tool,
        "center_mode": center_mode,
        "console": _build_console(effective_run_dir, run_result_with_live),
        "live_findings": _build_live_findings(effective_run_dir, run_result),
        "report": {
            "available": report_path.exists(),
            "mtime": _file_mtime(report_path),
            "path": "report.html",
        },
        "app": {
            "enabled": bool(app_state.get("enabled", False)),
            "running": running,
            "returncode": None if proc is None or running else proc.poll(),
            "message": str(app_state.get("message") or ""),
            "error": str(app_state.get("error") or ""),
            "current_run_dir": str(effective_run_dir) if active_run_dir else "",
            "auto_skipped_tools": app_state.get("auto_skipped_tools") or {},
        },
        "defaults": app_state.get("defaults") or {},
    }


def _write_dashboard(run_dir: Path) -> bool:
    try:
        (run_dir / "dashboard.html").write_text(_DASHBOARD_HTML, encoding="utf-8")
        return True
    except Exception:
        return False


def _start_gui_bootstrap_server(
    run_dir: Path,
    port: int = 8765,
    *,
    initial_state: dict[str, Any] | None = None,
) -> tuple[ThreadingHTTPServer | None, str | None]:
    """Start the local Reconbot operator dashboard for a run directory."""
    run_dir = Path(run_dir).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    if not _write_dashboard(run_dir):
        return None, None

    initial_state = dict(initial_state or {})

    class _DashboardHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, directory=str(run_dir), **kwargs)

        def _send_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            parsed = urlparse(self.path)
            if parsed.path in {"", "/"}:
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/dashboard.html")
                self.end_headers()
                return
            if parsed.path == "/api/state":
                self._send_json(_build_state(run_dir, initial_state))
                return
            if parsed.path == "/api/logs":
                params = parse_qs(parsed.query)
                limit = _safe_int((params.get("limit") or ["180"])[0], 180)
                self._send_json({"lines": _tail_lines(run_dir / "reconbot.log", limit=max(1, limit))})
                return
            super().do_GET()

        def end_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            super().end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            return

    server: ThreadingHTTPServer | None = None
    selected_port: int | None = None
    for candidate_port in [port, *range(port + 1, port + 20)]:
        try:
            server = ThreadingHTTPServer(("127.0.0.1", candidate_port), _DashboardHandler)
            selected_port = candidate_port
            break
        except OSError:
            continue
        except Exception:
            return None, None

    if server is None or selected_port is None:
        return None, None

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{selected_port}/dashboard.html"


def _start_gui_app_server(
    *,
    base_output_dir: str | None = None,
    config_defaults: dict[str, Any] | None = None,
    port: int = 8765,
) -> tuple[ThreadingHTTPServer | None, str | None]:
    """Start Reconbot as a local app that can launch scans from the browser."""
    app_root = Path(base_output_dir).expanduser().resolve() if base_output_dir else (Path(__file__).resolve().parents[1] / "output").resolve()
    if app_root.name.lower() == "latest":
        app_root = app_root.parent
    app_root.mkdir(parents=True, exist_ok=True)
    if not _write_dashboard(app_root):
        return None, None

    defaults = _app_defaults_from_config(config_defaults, str(app_root))
    app_state: dict[str, Any] = {
        "enabled": True,
        "defaults": defaults,
        "selected_tools": _tool_selection_from_rows(defaults.get("tools")),
        "auto_skipped_tools": {},
        "current_run_dir": None,
        "proc": None,
        "starting": False,
        "request_id": None,
        "stop_requested": False,
        "message": "Ayarları seçip scan başlat.",
        "error": "",
    }
    state_lock = threading.Lock()

    def _active_run_dir() -> Path:
        with state_lock:
            current = app_state.get("current_run_dir")
        if current:
            return Path(current).resolve()
        return app_root

    def _append_app_log(run_dir: Path, message: str) -> None:
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with (run_dir / "reconbot.log").open("a", encoding="utf-8") as handle:
                handle.write(f"{timestamp} {message}\n")
        except Exception:
            pass

    def _reader_thread(proc: subprocess.Popen[str], request_dir: Path, startup_log_lines: list[str], request_id: str) -> None:
        boot_lines: list[str] = []
        resolved_run_dir: Path | None = None

        def _current_log_dir() -> Path:
            return resolved_run_dir or request_dir

        def _adopt_run_dir(candidate: str) -> None:
            nonlocal resolved_run_dir
            candidate = str(candidate or "").strip()
            if not candidate or resolved_run_dir is not None:
                return
            try:
                real_run_dir = Path(candidate).expanduser().resolve()
                if not real_run_dir.is_relative_to(app_root):
                    raise ValueError("Output marker is outside the configured output directory")
                real_run_dir.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                _append_app_log(request_dir, f"[!] Output run path parse failed: {exc}")
                return

            resolved_run_dir = real_run_dir
            with state_lock:
                if app_state.get("request_id") != request_id:
                    return
                app_state["current_run_dir"] = str(real_run_dir)
                app_state["message"] = "Scan çalışıyor."
            for startup_line in startup_log_lines:
                _append_app_log(real_run_dir, startup_line)
            for boot_line in boot_lines:
                _append_app_log(real_run_dir, boot_line)
            _append_app_log(real_run_dir, f"[+] GUI now following run dir: {real_run_dir}")

        try:
            if proc.stdout is not None:
                for line in proc.stdout:
                    text = line.rstrip("\n")
                    if text:
                        boot_lines.append(text)
                        if len(boot_lines) > 80:
                            boot_lines.pop(0)
                        _append_app_log(_current_log_dir(), text)
                        marker = "[+] Output (run):"
                        if marker in text:
                            _adopt_run_dir(text.split(marker, 1)[1])
            rc = proc.wait()
            with state_lock:
                if app_state.get("request_id") != request_id:
                    return
                app_state["message"] = f"Scan tamamlandı (exit={rc})." if rc == 0 else f"Scan bitti (exit={rc})."
                if rc != 0:
                    app_state["error"] = f"Process exit={rc}"
            _append_app_log(_current_log_dir(), f"[+] Child return code: {rc}")
        except Exception as exc:
            with state_lock:
                if app_state.get("request_id") == request_id:
                    app_state["error"] = str(exc)
            _append_app_log(_current_log_dir(), f"[!] Reader thread error: {exc}")

    def _parse_json_body(handler: SimpleHTTPRequestHandler) -> dict[str, Any]:
        length = _safe_int(handler.headers.get("Content-Length"), 0)
        if length <= 0:
            return {}
        raw = handler.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def _launch_reserved_scan(payload: dict[str, Any], request_id: str) -> tuple[dict[str, Any], HTTPStatus]:
        target = str(payload.get("target") or "").strip()
        wordlist = str(payload.get("wordlist") or "").strip()
        tools = payload.get("tools") if isinstance(payload.get("tools"), dict) else {}
        selected_tools = _tool_selection_from_payload(tools)
        auto_skipped_tools = _auto_skipped_tools_for_target(target, selected_tools)
        uses_wordlist = selected_tools.get("gobuster", True) or selected_tools.get("ffuf", False)

        if not target:
            return {"error": "Target zorunlu."}, HTTPStatus.BAD_REQUEST
        if uses_wordlist and not wordlist:
            return {"error": "wordlist required because Gobuster/FFUF enabled"}, HTTPStatus.BAD_REQUEST


        request_dir = (app_root / "app_requests" / request_id).resolve()
        request_dir.mkdir(parents=True, exist_ok=True)
        config_path = request_dir / "app_config.yaml"
        _write_app_config(config_path, payload, app_root)

        cmd = [
            sys.executable,
            "-u",
            "-m",
            "reconbot",
            target,
            "-c",
            str(config_path),
        ]
        env = dict(os.environ)
        env["RECONBOT_SKIP_PREFLIGHT"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        startup_log_lines = [
            f"[+] App scan requested: target={target}",
            f"[+] App selected traffic profile: {str(payload.get('traffic_profile') or 'balanced')}",
            f"[+] App enabled tools: {', '.join(name for name, enabled in selected_tools.items() if enabled) or '-'}",
            f"[+] App auto-skipped tools: {', '.join(f'{name} ({reason})' for name, reason in auto_skipped_tools.items()) or '-'}",
            f"[+] Child config: {config_path}",
            f"[+] Child command: {shlex.join(cmd)}",
        ]
        for log_line in startup_log_lines:
            _append_app_log(request_dir, log_line)

        with state_lock:
            if app_state["stop_requested"]:
                return {"ok": False, "error": "Scan başlatma isteği iptal edildi."}, HTTPStatus.CONFLICT
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(Path(__file__).resolve().parents[2]),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )
        except Exception as exc:
            _append_app_log(request_dir, f"[!] Scan start failed: {exc}")
            with state_lock:
                app_state["current_run_dir"] = str(request_dir)
                app_state["proc"] = None
                app_state["message"] = "Scan başlatılamadı."
                app_state["error"] = str(exc)
            return {"error": f"Scan başlatılamadı: {exc}"}, HTTPStatus.INTERNAL_SERVER_ERROR

        pid_log = f"[+] Child PID: {proc.pid}"
        startup_log_lines.append(pid_log)
        _append_app_log(request_dir, pid_log)

        with state_lock:
            app_state["current_run_dir"] = str(request_dir)
            app_state["proc"] = proc
            if app_state["stop_requested"]:
                proc.terminate()
            app_state["message"] = "Stop isteği gönderildi." if app_state["stop_requested"] else "Scan çalışıyor."
            app_state["error"] = ""
            app_state["selected_tools"] = selected_tools
            app_state["auto_skipped_tools"] = auto_skipped_tools
            app_state["traffic_profile"] = str(payload.get("traffic_profile") or "balanced")
            app_state["defaults"] = {
                **defaults,
                "target": target,
                "wordlist": wordlist,
                "traffic_profile": str(payload.get("traffic_profile") or "balanced"),
                "report_depth": str(payload.get("report_depth") or "balanced"),
                "tools": _default_tool_rows(selected_tools),
            }

        thread = threading.Thread(target=_reader_thread, args=(proc, request_dir, startup_log_lines, request_id), daemon=True)
        thread.start()
        return {"ok": True, "request_dir": str(request_dir)}, HTTPStatus.OK

    def _start_scan(payload: dict[str, Any]) -> tuple[dict[str, Any], HTTPStatus]:
        target = str(payload.get("target") or "").strip()
        tools = _tool_selection_from_payload(payload.get("tools"))
        if not target:
            return {"error": "Target zorunlu."}, HTTPStatus.BAD_REQUEST
        if (tools.get("gobuster", True) or tools.get("ffuf", False)) and not str(payload.get("wordlist") or "").strip():
            return {"error": "wordlist required because Gobuster/FFUF enabled"}, HTTPStatus.BAD_REQUEST
        # Reserve ownership before any config write or Popen; concurrent POSTs cannot pass.
        request_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:12]
        with state_lock:
            proc = app_state.get("proc")
            if app_state["starting"] or (proc is not None and proc.poll() is None):
                return {"error": "Zaten çalışan veya başlatılan bir scan var."}, HTTPStatus.CONFLICT
            app_state.update(starting=True, request_id=request_id, stop_requested=False, proc=None)
        try:
            return _launch_reserved_scan(payload, request_id)
        except Exception as exc:
            with state_lock:
                if app_state.get("request_id") == request_id:
                    proc = app_state.get("proc")
                    if proc is not None and proc.poll() is None:
                        proc.terminate()
                    app_state.update(message="Scan başlatılamadı.", error=str(exc))
            return {"error": f"Scan başlatılamadı: {exc}"}, HTTPStatus.INTERNAL_SERVER_ERROR
        finally:
            with state_lock:
                if app_state.get("request_id") == request_id:
                    app_state["starting"] = False

    def _stop_scan(source: str = "button") -> tuple[dict[str, Any], HTTPStatus]:
        with state_lock:
            proc = app_state.get("proc")
            request_id = app_state.get("request_id")
            app_state["stop_requested"] = True
            if app_state["starting"] and proc is None:
                app_state["message"] = "Scan başlatma isteği iptal ediliyor."
                return {"ok": True, "message": app_state["message"]}, HTTPStatus.OK
        if proc is None or proc.poll() is not None:
            message = "No running scan"
            _append_app_log(_active_run_dir(), f"[!] {message} ({source})")
            with state_lock:
                if app_state.get("request_id") == request_id:
                    app_state["message"] = message
            return {"ok": True, "message": message}, HTTPStatus.OK
        try:
            log_message = "[!] Stop requested from console shortcut" if source == "console shortcut" else "[!] Stop requested from GUI stop button"
            _append_app_log(_active_run_dir(), log_message)
            proc.terminate()
            with state_lock:
                if app_state.get("request_id") == request_id:
                    app_state["message"] = "Stop isteği gönderildi."
            return {"ok": True}, HTTPStatus.OK
        except Exception as exc:
            return {"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR

    class _AppHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, directory=str(app_root), **kwargs)

        def translate_path(self, path: str) -> str:
            parsed = urlparse(path).path
            parsed = posixpath.normpath(unquote(parsed)).lstrip("/")
            if not parsed or parsed == ".":
                parsed = "dashboard.html"
            root = app_root if parsed == "dashboard.html" else _active_run_dir()
            safe_parts = [part for part in parsed.split("/") if part and part not in {".", ".."}]
            return str(root.joinpath(*safe_parts))

        def _send_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            parsed = urlparse(self.path)
            if parsed.path in {"", "/"}:
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/dashboard.html")
                self.end_headers()
                return
            if parsed.path == "/api/state":
                with state_lock:
                    snapshot = dict(app_state)
                self._send_json(_build_state(_active_run_dir(), snapshot, snapshot))
                return
            if parsed.path == "/api/logs":
                params = parse_qs(parsed.query)
                limit = _safe_int((params.get("limit") or ["180"])[0], 180)
                self._send_json({"lines": _tail_lines(_active_run_dir() / "reconbot.log", limit=max(1, limit))})
                return
            super().do_GET()

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            parsed = urlparse(self.path)
            if parsed.path == "/api/run":
                payload, status = _start_scan(_parse_json_body(self))
                self._send_json(payload, status)
                return
            if parsed.path == "/api/stop":
                body = _parse_json_body(self)
                payload, status = _stop_scan(str(body.get("source") or "button"))
                self._send_json(payload, status)
                return
            self._send_json({"error": "Unknown endpoint"}, HTTPStatus.NOT_FOUND)

        def end_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            super().end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            return

    server: ThreadingHTTPServer | None = None
    selected_port: int | None = None
    for candidate_port in [port, *range(port + 1, port + 20)]:
        try:
            server = ThreadingHTTPServer(("127.0.0.1", candidate_port), _AppHandler)
            selected_port = candidate_port
            break
        except OSError:
            continue
        except Exception:
            return None, None

    if server is None or selected_port is None:
        return None, None

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{selected_port}/dashboard.html"
