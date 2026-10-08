from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconbot.report.texts import text as _txt


def graph_ui_css() -> str:
    return """
            .graph-ui-shell { margin: 12px 0 14px; border:1px solid var(--border); border-radius:12px; background: rgba(15,21,32,0.68); overflow: hidden; }
            .graph-controls { padding: 10px 12px; border-bottom:1px solid var(--border); background: rgba(22,27,34,0.72); }
            .graph-controls-row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:8px; }
            .graph-controls-row:last-of-type { margin-bottom: 4px; }
            .graph-btn {
                border:1px solid var(--border);
                background: rgba(22,27,34,0.95);
                color: var(--text);
                border-radius: 8px;
                padding: 6px 10px;
                font-size: 12px;
                cursor: pointer;
            }
            .graph-btn:hover { border-color: rgba(121,192,255,0.55); }
            .graph-btn.is-active { border-color: rgba(121,192,255,0.8); color: var(--accent2); }
            .graph-btn:disabled { opacity: 0.55; cursor: not-allowed; }
            .graph-input,
            .graph-select {
                border:1px solid var(--border);
                background: rgba(14,17,23,0.9);
                color: var(--text);
                border-radius: 8px;
                padding: 6px 9px;
                font-size: 12px;
            }
            .graph-select { min-width: 130px; }
            .graph-range-wrap { display:inline-flex; align-items:center; gap:8px; color:var(--muted); font-size:12px; }
            .graph-range-wrap input[type="range"] { width: 170px; }
            .graph-min-confidence-value { color: var(--accent2); min-width: 30px; text-align:right; }
            .graph-helper-note { margin: 0; color: var(--muted); font-size: 12px; }
            .graph-workspace { display:grid; grid-template-columns: minmax(0, 1fr) 320px; gap: 10px; padding: 10px; }
            .attack-graph-canvas {
                height: 560px;
                min-height: 560px;
                border:1px solid var(--border);
                border-radius: 10px;
                background: radial-gradient(circle at 15% 8%, rgba(88,166,255,0.08), rgba(14,17,23,0.95));
                overflow: hidden;
                position: relative;
            }
            .graph-canvas-empty {
                position: absolute;
                inset: 0;
                padding: 14px;
                color: var(--muted);
                font-size: 13px;
                pointer-events: none;
            }
            .graph-inspector {
                border:1px solid var(--border);
                border-radius: 10px;
                background: rgba(14,17,23,0.86);
                padding: 10px;
                min-height: 560px;
                max-height: 560px;
                overflow: auto;
            }
            .graph-inspector h3 { margin-bottom: 6px; }
            .graph-inspector h4 { margin: 8px 0 6px; color: var(--accent2); font-size: 13px; }
            .graph-inspector dl { margin: 0; }
            .graph-inspector dt { color: var(--muted); font-size: 12px; margin-top: 8px; }
            .graph-inspector dd { margin: 2px 0 0 0; font-size: 13px; }
            .graph-inspector .compact-list { margin-top: 4px; }
            .graph-tag-list { display:flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
            .graph-tag-pill {
                border:1px solid rgba(121,192,255,0.32);
                border-radius: 999px;
                padding: 1px 8px;
                font-size: 11px;
                color: var(--accent2);
                background: rgba(88,166,255,0.08);
            }
            .graph-data-tables { margin-top: 12px; }
            .graph-data-tables h3 { margin-top: 12px; }
            @media (max-width: 1100px) {
                .graph-workspace { grid-template-columns: 1fr; }
                .graph-inspector { min-height: 260px; max-height: none; }
            }
    """


def graph_library_script_tag(output_dir: Path) -> str:
    """A report must retain its graph without CDN connectivity."""
    library = Path(__file__).with_name("assets") / "cytoscape.min.js"
    destination = Path(output_dir) / "cytoscape.min.js"
    content = library.read_bytes()
    if not destination.exists() or destination.read_bytes() != content:
        temporary = destination.with_suffix(".js.tmp")
        temporary.write_bytes(content)
        temporary.replace(destination)
    return '<script src="cytoscape.min.js"></script>'


def serialize_json_for_script_tag(payload: Any) -> str:
    serialized = json.dumps(payload, ensure_ascii=False)
    serialized = serialized.replace("</", "<\\/")
    serialized = serialized.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return serialized


def render_interactive_graph_block(payload_json: str) -> str:
    template = """
        <div class="graph-ui-shell">
          <div class="graph-controls">
            <div class="graph-controls-row">
              <button type="button" class="graph-btn" id="graph-fit-btn">__GRAPH_UI_BTN_FIT__</button>
              <button type="button" class="graph-btn" id="graph-reset-zoom-btn">__GRAPH_UI_BTN_RESET_ZOOM__</button>
              <button type="button" class="graph-btn" id="graph-rerun-layout-btn">__GRAPH_UI_BTN_RERUN_LAYOUT__</button>
              <button type="button" class="graph-btn" id="graph-view-toggle-btn" data-full-graph="false">__GRAPH_UI_BTN_SHOW_FULL__</button>
              <input id="graph-search-input" class="graph-input" type="text" placeholder="__GRAPH_UI_SEARCH_PLACEHOLDER__" />
              <button type="button" class="graph-btn" id="graph-search-btn">__GRAPH_UI_BTN_SEARCH__</button>
            </div>
            <div class="graph-controls-row">
              <select id="graph-type-filter" class="graph-select" aria-label="Filter node type">
                <option value="all">__GRAPH_UI_FILTER_ALL__</option>
                <option value="surface">surface</option>
                <option value="technology">technology</option>
                <option value="outcome">outcome</option>
                <option value="finding">finding</option>
              </select>
              <span class="graph-range-wrap">
                __GRAPH_UI_MIN_CONFIDENCE__
                <input id="graph-min-confidence" type="range" min="0" max="100" step="1" value="0" />
                <span class="graph-min-confidence-value" id="graph-min-confidence-value">0</span>
              </span>
              <button type="button" class="graph-btn" id="graph-strongest-path-btn">__GRAPH_UI_BTN_HIGHLIGHT_PATH__</button>
              <button type="button" class="graph-btn" id="graph-low-signal-btn" data-hide-low-signal="false">__GRAPH_UI_BTN_HIDE_LOW_SIGNAL__</button>
            </div>
            <p class="graph-helper-note">__GRAPH_UI_HELPER_NOTE__</p>
          </div>
          <div class="graph-workspace">
            <div class="attack-graph-canvas" id="attack-graph-canvas">
              <div class="graph-canvas-empty">__GRAPH_UI_INITIALIZING__</div>
            </div>
            <aside class="graph-inspector" id="attack-graph-inspector">
              <h3>__GRAPH_UI_INSPECTOR_TITLE__</h3>
              <p class="note">__GRAPH_UI_INSPECTOR_NOTE__</p>
            </aside>
          </div>
        </div>

        <script id="attack-graph-payload" type="application/json">__GRAPH_PAYLOAD_JSON__</script>
        <script>
        (function () {
            function ready(callback) {
                if (document.readyState === "loading") {
                    document.addEventListener("DOMContentLoaded", callback, { once: true });
                } else {
                    callback();
                }
            }

            function escapeHtml(value) {
                return String(value == null ? "" : value)
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;")
                    .replace(/"/g, "&quot;")
                    .replace(/'/g, "&#39;");
            }

            function asArray(value) {
                return Array.isArray(value) ? value : [];
            }

            function asInt(value, fallback, maxValue) {
                var parsed = parseInt(value, 10);
                if (Number.isNaN(parsed)) {
                    return typeof fallback === "number" ? fallback : 0;
                }
                if (parsed < 0) {
                    return 0;
                }
                if (typeof maxValue === "number" && parsed > maxValue) {
                    return maxValue;
                }
                return parsed;
            }

            function asNumber(value, fallback) {
                var parsed = Number(value);
                if (Number.isFinite(parsed)) {
                    return parsed;
                }
                return typeof fallback === "number" ? fallback : 0;
            }

            function looksLikeAbsoluteUrl(value) {
                return /^https?:\\/\\//i.test(String(value || "").trim());
            }

            function endpointToHtml(value) {
                var text = String(value || "").trim();
                if (!text) {
                    return "";
                }
                if (looksLikeAbsoluteUrl(text)) {
                    return '<a class="report-link" href="' + escapeHtml(text) + '" target="_blank">' + escapeHtml(text) + "</a>";
                }
                return "<code>" + escapeHtml(text) + "</code>";
            }

            function safeReadJson(key) {
                try {
                    var raw = sessionStorage.getItem(key);
                    return raw ? JSON.parse(raw) : null;
                } catch (_err) {
                    return null;
                }
            }

            function safeWriteJson(key, value) {
                try {
                    sessionStorage.setItem(key, JSON.stringify(value));
                } catch (_err) {}
            }

            function normalizeStorageToken(value) {
                return String(value || "default")
                    .trim()
                    .replace(/[^a-z0-9_.:-]+/gi, "_")
                    .slice(0, 180) || "default";
            }

                function createStateDefaults() {
                    return {
                        fullGraph: false,
                        typeFilter: "all",
                        minConfidence: 0,
                        strongestPath: false,
                    hideLowSignal: false,
                    searchQuery: "",
                    selected: null,
                    inspectorScrollTop: 0,
                    zoom: null,
                    pan: null,
                    topologyHash: "",
                    positions: {}
                };
            }

            ready(function () {
                try {
                var payloadNode = document.getElementById("attack-graph-payload");
                var canvas = document.getElementById("attack-graph-canvas");
                var inspector = document.getElementById("attack-graph-inspector");
                if (!payloadNode || !canvas || !inspector) {
                    return;
                }

                var previousRuntime = window.__reconbotGraphRuntime;
                if (previousRuntime && typeof previousRuntime.destroy === "function") {
                    try {
                        previousRuntime.destroy();
                    } catch (_err) {}
                }
                window.__reconbotGraphRuntime = null;

                var payload = {};
                try {
                    payload = JSON.parse(payloadNode.textContent || "{}");
                } catch (_err) {
                    payload = {};
                }

                var nodesRaw = asArray(payload.nodes);
                var edgesRaw = asArray(payload.edges);
                var pathsRaw = asArray(payload.paths);
                var meta = (payload && payload.meta && typeof payload.meta === "object") ? payload.meta : {};
                var bestPathId = String(meta.best_path_id || (pathsRaw[0] && pathsRaw[0].id) || "").trim();
                var bestPathReason = String(meta.best_path_reason || "").trim();
                var bestPathReasonShort = bestPathReason.length > 240 ? (bestPathReason.slice(0, 237) + "...") : bestPathReason;
                var hasPathData = !!bestPathId || pathsRaw.length > 0;
                var scopeId = String(
                    meta.scope_id
                    || (document.querySelector('meta[name="reconbot-report-scope"]') || {}).content
                    || "default"
                ).trim() || "default";
                var topologyHash = String(meta.topology_hash || "").trim();
                var storageKey = "reconbot.report.graphState.v3." + normalizeStorageToken(scopeId);
                var persisted = safeReadJson(storageKey);
                if (!persisted || typeof persisted !== "object") {
                    persisted = {};
                }

                function renderInspectorHint(text) {
                    inspector.innerHTML = "<h3>İnceleyici</h3><p class=\\"note\\">" + escapeHtml(text) + "</p>";
                }
                var defaultInspectorHint = "__GRAPH_UI_INSPECTOR_NOTE__";
                if (bestPathReasonShort) {
                    defaultInspectorHint += " __GRAPH_UI_HINT_STRONGEST_PATH__ " + bestPathReasonShort;
                }

                if (typeof window.cytoscape !== "function") {
                    canvas.innerHTML = '<div class="graph-canvas-empty">__GRAPH_UI_LIBRARY_MISSING_CANVAS__</div>';
                    renderInspectorHint("__GRAPH_UI_LIBRARY_MISSING_INSPECTOR__");
                    return;
                }

                if (!nodesRaw.length) {
                    canvas.innerHTML = '<div class="graph-canvas-empty">__GRAPH_UI_NO_NODES_CANVAS__</div>';
                    renderInspectorHint("__GRAPH_UI_HINT_NO_NODE_DATA__");
                    return;
                }

                canvas.innerHTML = "";
                canvas.style.height = "560px";
                canvas.style.minHeight = "560px";
                canvas.style.maxHeight = "560px";
                canvas.style.width = "100%";

                var cleanupFns = [];
                function listen(target, name, handler, options) {
                    if (!target || typeof target.addEventListener !== "function") {
                        return;
                    }
                    target.addEventListener(name, handler, options);
                    cleanupFns.push(function () {
                        try {
                            target.removeEventListener(name, handler, options);
                        } catch (_err) {}
                    });
                }

                var savedPositions = (persisted.positions && typeof persisted.positions === "object") ? persisted.positions : {};
                var knownNodeIds = {};
                var elements = [];

                nodesRaw.forEach(function (node, idx) {
                    var nodeId = String((node && node.id) || ("node_" + (idx + 1))).trim();
                    if (!nodeId) {
                        return;
                    }
                    if (knownNodeIds[nodeId]) {
                        nodeId = nodeId + "_" + idx;
                    }
                    knownNodeIds[nodeId] = true;

                    var nodeElement = {
                        group: "nodes",
                        data: {
                            id: nodeId,
                            label: String((node && node.label) || nodeId),
                            type: String((node && node.type) || "surface"),
                            count: asInt(node && node.count, 0),
                            importance: asInt(node && node.importance, 1, 100),
                            low_signal: node && node.low_signal ? 1 : 0,
                            details: asArray(node && node.details),
                            related_suggestions: asArray(node && node.related_suggestions),
                            related_cves: asArray(node && node.related_cves),
                            related_nuclei_tags: asArray(node && node.related_nuclei_tags),
                            related_endpoints: asArray(node && node.related_endpoints)
                        }
                    };

                    var storedPos = savedPositions[nodeId];
                    if (storedPos && typeof storedPos === "object") {
                        var x = asNumber(storedPos.x, NaN);
                        var y = asNumber(storedPos.y, NaN);
                        if (Number.isFinite(x) && Number.isFinite(y)) {
                            nodeElement.position = { x: x, y: y };
                        }
                    }
                    elements.push(nodeElement);
                });

                edgesRaw.forEach(function (edge, idx) {
                    var src = String((edge && (edge.source || edge.from)) || "").trim();
                    var dst = String((edge && (edge.target || edge.to)) || "").trim();
                    if (!src || !dst || !knownNodeIds[src] || !knownNodeIds[dst]) {
                        return;
                    }
                    var confidence = asInt(edge && edge.confidence, 0, 100);
                    elements.push({
                        group: "edges",
                        data: {
                            id: String((edge && edge.id) || (src + "__" + dst + "_" + idx)),
                            source: src,
                            target: dst,
                            confidence: confidence,
                            reason: String((edge && edge.reason) || "-"),
                            path_refs: asArray(edge && edge.path_refs),
                            edge_color: String((edge && edge.edge_color) || (confidence >= 75 ? "#3fb950" : (confidence >= 50 ? "#ffa657" : "#8b949e"))),
                            edge_opacity: Number((edge && edge.edge_opacity) || (0.25 + (confidence / 140.0)))
                        }
                    });
                });

                var cy = window.cytoscape({
                    container: canvas,
                    elements: elements,
                    minZoom: 0.2,
                    maxZoom: 2.7,
                    wheelSensitivity: 0.24,
                    style: [
                        {
                            selector: "node",
                            style: {
                                "shape": "round-rectangle",
                                "background-color": "#30363d",
                                "border-width": 1.4,
                                "border-color": "#6e7681",
                                "width": "mapData(importance, 1, 100, 40, 84)",
                                "height": "mapData(importance, 1, 100, 28, 56)",
                                "padding": "7px",
                                "label": "data(label)",
                                "text-wrap": "wrap",
                                "text-max-width": "170px",
                                "font-size": 11,
                                "color": "#e6edf3",
                                "text-outline-width": 2,
                                "text-outline-color": "#0f1520",
                                "text-valign": "center",
                                "text-halign": "center",
                                "overlay-padding": 8
                            }
                        },
                        {
                            selector: 'node[type = "surface"]',
                            style: {
                                "background-color": "#1f6feb",
                                "border-color": "#79c0ff"
                            }
                        },
                        {
                            selector: 'node[type = "technology"]',
                            style: {
                                "background-color": "#d29922",
                                "border-color": "#ffd38a",
                                "color": "#0e1117",
                                "text-outline-color": "#d29922"
                            }
                        },
                        {
                            selector: 'node[type = "outcome"]',
                            style: {
                                "background-color": "#da3633",
                                "border-color": "#ff938f"
                            }
                        },
                        {
                            selector: 'node[type = "finding"]',
                            style: {
                                "background-color": "#a371f7",
                                "border-color": "#d2a8ff"
                            }
                        },
                        {
                            selector: "node[low_signal > 0]",
                            style: {
                                "border-style": "dashed",
                                "background-blacken": 0.15
                            }
                        },
                        {
                            selector: "edge",
                            style: {
                                "curve-style": "bezier",
                                "line-color": "data(edge_color)",
                                "target-arrow-color": "data(edge_color)",
                                "target-arrow-shape": "triangle",
                                "target-arrow-fill": "filled",
                                "arrow-scale": 0.82,
                                "width": "mapData(confidence, 0, 100, 1.2, 5.6)",
                                "opacity": "data(edge_opacity)",
                                "label": "",
                                "font-size": 9,
                                "color": "#8b949e",
                                "text-background-color": "#0f1520",
                                "text-background-opacity": 0.75,
                                "text-background-padding": "2px",
                                "overlay-padding": 8
                            }
                        },
                        {
                            selector: "node:selected",
                            style: {
                                "border-width": 3,
                                "border-color": "#79c0ff"
                            }
                        },
                        {
                            selector: "edge:selected",
                            style: {
                                "line-color": "#79c0ff",
                                "target-arrow-color": "#79c0ff"
                            }
                        },
                        {
                            selector: ".rb-dimmed",
                            style: {
                                "opacity": 0.13,
                                "text-opacity": 0
                            }
                        },
                        {
                            selector: "node.rb-strong-path",
                            style: {
                                "border-width": 3.2,
                                "border-color": "#79c0ff",
                                "z-index": 999
                            }
                        },
                        {
                            selector: "edge.rb-strong-path",
                            style: {
                                "line-color": "#79c0ff",
                                "target-arrow-color": "#79c0ff",
                                "width": 6.2,
                                "opacity": 1
                            }
                        },
                        {
                            selector: "node.rb-search-hit",
                            style: {
                                "border-width": 3.2,
                                "border-color": "#ffa657"
                            }
                        }
                    ]
                });

                var fitBtn = document.getElementById("graph-fit-btn");
                var resetZoomBtn = document.getElementById("graph-reset-zoom-btn");
                var rerunLayoutBtn = document.getElementById("graph-rerun-layout-btn");
                var viewToggleBtn = document.getElementById("graph-view-toggle-btn");
                var searchInput = document.getElementById("graph-search-input");
                var searchBtn = document.getElementById("graph-search-btn");
                var typeFilter = document.getElementById("graph-type-filter");
                var minConfidenceInput = document.getElementById("graph-min-confidence");
                var minConfidenceValue = document.getElementById("graph-min-confidence-value");
                var strongestPathBtn = document.getElementById("graph-strongest-path-btn");
                var lowSignalBtn = document.getElementById("graph-low-signal-btn");

                var state = createStateDefaults();
                state.fullGraph = Boolean(persisted.fullGraph);
                state.typeFilter = String(persisted.typeFilter || "all");
                state.minConfidence = asInt(persisted.minConfidence, 0, 100);
                state.strongestPath = Boolean(persisted.strongestPath);
                state.hideLowSignal = Boolean(persisted.hideLowSignal);
                state.searchQuery = String(persisted.searchQuery || "");
                state.selected = (persisted.selected && typeof persisted.selected === "object") ? persisted.selected : null;
                state.inspectorScrollTop = asInt(persisted.inspectorScrollTop, 0);
                state.zoom = Number.isFinite(Number(persisted.zoom)) ? Number(persisted.zoom) : null;
                state.pan = (persisted.pan && typeof persisted.pan === "object") ? {
                    x: asNumber(persisted.pan.x, 0),
                    y: asNumber(persisted.pan.y, 0)
                } : null;
                state.topologyHash = String(persisted.topologyHash || persisted.topology_hash || "");
                state.positions = (persisted.positions && typeof persisted.positions === "object") ? persisted.positions : {};
                if (!hasPathData) {
                    state.strongestPath = false;
                }

                if (typeFilter) {
                    var filterValue = state.typeFilter;
                    var allowed = ["all", "surface", "technology", "outcome", "finding"];
                    typeFilter.value = allowed.indexOf(filterValue) >= 0 ? filterValue : "all";
                }
                if (viewToggleBtn) {
                    viewToggleBtn.dataset.fullGraph = state.fullGraph ? "true" : "false";
                    viewToggleBtn.classList.toggle("is-active", state.fullGraph);
                    viewToggleBtn.textContent = state.fullGraph ? "__GRAPH_UI_BTN_OPERATOR_VIEW__" : "__GRAPH_UI_BTN_SHOW_FULL__";
                }
                if (minConfidenceInput) {
                    minConfidenceInput.value = String(state.minConfidence);
                }
                if (searchInput) {
                    searchInput.value = state.searchQuery;
                }
                if (lowSignalBtn) {
                    lowSignalBtn.dataset.hideLowSignal = state.hideLowSignal ? "true" : "false";
                    lowSignalBtn.classList.toggle("is-active", state.hideLowSignal);
                    lowSignalBtn.textContent = state.hideLowSignal ? "__GRAPH_UI_BTN_SHOW_LOW_SIGNAL__" : "__GRAPH_UI_BTN_HIDE_LOW_SIGNAL__";
                }
                if (strongestPathBtn) {
                    strongestPathBtn.disabled = !hasPathData;
                    strongestPathBtn.classList.toggle("is-active", state.strongestPath);
                    strongestPathBtn.textContent = state.strongestPath ? "__GRAPH_UI_BTN_CLEAR_PATH__" : "__GRAPH_UI_BTN_HIGHLIGHT_PATH__";
                }

                function nodeLabelById(nodeId) {
                    var node = cy.getElementById(String(nodeId || ""));
                    if (!node || !node.length) {
                        return String(nodeId || "-");
                    }
                    return String(node.data("label") || nodeId || "-");
                }

                function buildNodeWhyMatters(nodeData) {
                    var nodeType = String(nodeData && nodeData.type || "").toLowerCase();
                    var count = asInt(nodeData && nodeData.count, 0);
                    var suggestions = asArray(nodeData && nodeData.related_suggestions);
                    var cves = asArray(nodeData && nodeData.related_cves);
                    var tags = asArray(nodeData && nodeData.related_nuclei_tags);
                    var endpoints = asArray(nodeData && nodeData.related_endpoints);
                    var parts = [];

                    if (nodeType === "surface") {
                        parts.push("__GRAPH_UI_NODE_WHY_SURFACE__");
                    } else if (nodeType === "finding") {
                        parts.push("__GRAPH_UI_NODE_WHY_FINDING__");
                    } else if (nodeType === "outcome") {
                        parts.push("__GRAPH_UI_NODE_WHY_OUTCOME__");
                    } else if (nodeType === "technology") {
                        parts.push("__GRAPH_UI_NODE_WHY_TECH__");
                    } else {
                        parts.push("__GRAPH_UI_NODE_WHY_SUPPORT__");
                    }

                    if (count > 0) {
                        parts.push("__GRAPH_UI_NODE_WHY_OBSERVED_PREFIX__" + count + "__GRAPH_UI_NODE_WHY_OBSERVED_SUFFIX__");
                    }
                    if (suggestions.length) {
                        var top = suggestions[0] || {};
                        var topTitle = String(top.title || "").trim();
                        if (topTitle) {
                            parts.push("__GRAPH_UI_NODE_WHY_NEXT_PIVOT_PREFIX__" + topTitle + "__GRAPH_UI_NODE_WHY_NEXT_PIVOT_SUFFIX__");
                        }
                    } else if (cves.length) {
                        parts.push("__GRAPH_UI_NODE_WHY_CVE__");
                    } else if (tags.length || endpoints.length) {
                        parts.push("__GRAPH_UI_NODE_WHY_TAGS__");
                    }
                    return parts.join(" ");
                }

                function buildEdgeWhyMatters(edgeData) {
                    var confidence = asInt(edgeData && edgeData.confidence, 0, 100);
                    var reason = String(edgeData && edgeData.reason || "").trim();
                    if (confidence >= 75) {
                        return "__GRAPH_UI_EDGE_WHY_HIGH__"
                            + (reason ? " Gerekçe: " + reason : "");
                    }
                    if (confidence >= 50) {
                        return "__GRAPH_UI_EDGE_WHY_MEDIUM__"
                            + (reason ? " Reason: " + reason : "");
                    }
                    return "__GRAPH_UI_EDGE_WHY_LOW__"
                        + (reason ? " Gerekçe: " + reason : "");
                }

                function renderNodeInspector(nodeData) {
                    var suggestions = asArray(nodeData.related_suggestions);
                    var cves = asArray(nodeData.related_cves);
                    var tags = asArray(nodeData.related_nuclei_tags);
                    var endpoints = asArray(nodeData.related_endpoints);
                    var details = asArray(nodeData.details);

                    var suggestionsHtml = suggestions.length
                        ? ('<ul class="compact-list">' + suggestions.slice(0, 10).map(function (item) {
                            var title = escapeHtml(item && item.title ? item.title : "-");
                            var priority = asInt(item && item.priority, 0, 100);
                            return "<li><strong>" + title + "</strong> (" + priority + "/100)</li>";
                        }).join("") + "</ul>")
                        : '<p class="note">-</p>';

                    var cvesHtml = cves.length
                        ? ('<ul class="compact-list">' + cves.slice(0, 12).map(function (item) {
                            var cveId = escapeHtml(item && item.cve_id ? item.cve_id : "-");
                            var rel = asInt(item && item.relevance_score, 0, 100);
                            return "<li><strong>" + cveId + "</strong> (" + rel + "/100)</li>";
                        }).join("") + "</ul>")
                        : '<p class="note">-</p>';

                    var tagsHtml = tags.length
                        ? ('<div class="graph-tag-list">' + tags.slice(0, 30).map(function (tag) {
                            return '<span class="graph-tag-pill">' + escapeHtml(tag) + "</span>";
                        }).join("") + "</div>")
                        : '<p class="note">-</p>';

                    var endpointsHtml = endpoints.length
                        ? ('<ul class="compact-list">' + endpoints.slice(0, 30).map(function (ep) {
                            return "<li>" + endpointToHtml(ep) + "</li>";
                        }).join("") + "</ul>")
                        : '<p class="note">-</p>';

                    var detailsHtml = details.length
                        ? ('<ul class="compact-list">' + details.slice(0, 18).map(function (d) {
                            return "<li>" + escapeHtml(d) + "</li>";
                        }).join("") + "</ul>")
                        : '<p class="note">-</p>';

                    inspector.innerHTML =
                        "<h3>İnceleyici</h3>"
                        + "<h4>Node</h4>"
                        + "<dl>"
                        + "<dt>Etiket</dt><dd>" + escapeHtml(nodeData.label || "-") + "</dd>"
                        + "<dt>Tip</dt><dd>" + escapeHtml(nodeData.type || "-") + "</dd>"
                        + "<dt>Sayı</dt><dd>" + asInt(nodeData.count, 0) + "</dd>"
                        + "</dl>"
                        + "<h4>Neden önemli?</h4><p class=\\\"note\\\">" + escapeHtml(buildNodeWhyMatters(nodeData)) + "</p>"
                        + "<h4>İlişkili öneriler</h4>" + suggestionsHtml
                        + "<h4>İlişkili CVE’ler</h4>" + cvesHtml
                        + "<h4>İlişkili nuclei tag’leri</h4>" + tagsHtml
                        + "<h4>İlişkili endpoint’ler</h4>" + endpointsHtml
                        + "<h4>Node detayları</h4>" + detailsHtml;
                }

                function renderEdgeInspector(edgeData) {
                    var sourceLabel = nodeLabelById(edgeData.source);
                    var targetLabel = nodeLabelById(edgeData.target);
                    var confidence = asInt(edgeData.confidence, 0, 100);
                    var reason = String(edgeData.reason || "-");
                    inspector.innerHTML =
                        "<h3>İnceleyici</h3>"
                        + "<h4>Edge</h4>"
                        + "<dl>"
                        + "<dt>Akış</dt><dd>" + escapeHtml(sourceLabel + " -> " + targetLabel) + "</dd>"
                        + "<dt>Güven</dt><dd>" + confidence + "/100</dd>"
                        + "<dt>Gerekçe</dt><dd>" + escapeHtml(reason) + "</dd>"
                        + "</dl>"
                        + "<h4>Neden önemli?</h4><p class=\\\"note\\\">" + escapeHtml(buildEdgeWhyMatters(edgeData)) + "</p>";
                }

                function captureNodePositions() {
                    var positions = {};
                    cy.nodes().forEach(function (node) {
                        var pos = node.position();
                        if (!pos || !Number.isFinite(pos.x) || !Number.isFinite(pos.y)) {
                            return;
                        }
                        positions[node.id()] = {
                            x: Math.round(pos.x * 100) / 100,
                            y: Math.round(pos.y * 100) / 100
                        };
                    });
                    return positions;
                }

                function snapshotState() {
                    return {
                        fullGraph: state.fullGraph,
                        typeFilter: state.typeFilter,
                        minConfidence: state.minConfidence,
                        strongestPath: state.strongestPath,
                        hideLowSignal: state.hideLowSignal,
                        searchQuery: state.searchQuery,
                        selected: state.selected,
                        inspectorScrollTop: asInt(inspector.scrollTop, 0),
                        zoom: Number(cy.zoom()),
                        pan: {
                            x: Math.round(cy.pan().x * 100) / 100,
                            y: Math.round(cy.pan().y * 100) / 100
                        },
                        topologyHash: topologyHash,
                        positions: captureNodePositions()
                    };
                }

                var persistTimer = null;
                function persistStateNow() {
                    safeWriteJson(storageKey, snapshotState());
                }

                function schedulePersist(delayMs) {
                    if (persistTimer) {
                        clearTimeout(persistTimer);
                    }
                    persistTimer = setTimeout(function () {
                        persistStateNow();
                    }, typeof delayMs === "number" ? delayMs : 120);
                }

                function getStrongestPath() {
                    if (!pathsRaw.length) {
                        return null;
                    }
                    if (bestPathId) {
                        for (var i = 0; i < pathsRaw.length; i += 1) {
                            if (String((pathsRaw[i] && pathsRaw[i].id) || "") === bestPathId) {
                                return pathsRaw[i];
                            }
                        }
                    }
                    return pathsRaw[0];
                }

                function getStrongestPathElements() {
                    try {
                        var strongestPath = getStrongestPath();
                        if (!strongestPath) {
                            return cy.collection();
                        }
                        var pathId = String(strongestPath.id || "");
                        var nodes = cy.collection();
                        var edges = cy.collection();

                        asArray(strongestPath.node_ids).forEach(function (nodeId) {
                            var n = cy.getElementById(String(nodeId || ""));
                            if (n && n.length) {
                                nodes = nodes.union(n);
                            }
                        });

                        cy.edges().forEach(function (edge) {
                            var refs = asArray(edge.data("path_refs"));
                            if (pathId && refs.indexOf(pathId) !== -1) {
                                edges = edges.union(edge);
                            }
                        });

                        if (!edges.length) {
                            var seq = asArray(strongestPath.node_ids);
                            for (var i = 0; i < seq.length - 1; i += 1) {
                                var src = String(seq[i] || "");
                                var dst = String(seq[i + 1] || "");
                                if (!src || !dst) {
                                    continue;
                                }
                                var pair = cy.edges().filter(function (edge) {
                                    return String(edge.data("source")) === src && String(edge.data("target")) === dst;
                                });
                                if (pair && pair.length) {
                                    edges = edges.union(pair);
                                }
                            }
                        }

                        return nodes.union(edges);
                    } catch (_err) {
                        return cy.collection();
                    }
                }

                function updateZoomLabelDensity() {
                    var zoom = cy.zoom();
                    var showNodeLabel = zoom >= 0.58;
                    var showEdgeLabel = zoom >= 1.08;
                    cy.nodes().forEach(function (node) {
                        node.style("label", showNodeLabel ? String(node.data("label") || "") : "");
                    });
                    cy.edges().forEach(function (edge) {
                        if (!showEdgeLabel || edge.style("display") === "none") {
                            edge.style("label", "");
                            return;
                        }
                        var conf = asInt(edge.data("confidence"), 0, 100);
                        edge.style("label", conf >= 70 ? (String(conf) + "/100") : "");
                    });
                }

                function applyStrongestPathHighlight() {
                    try {
                        cy.elements().removeClass("rb-dimmed rb-strong-path");
                        if (!state.strongestPath || !hasPathData) {
                            return;
                        }
                        var strongest = getStrongestPathElements().filter(":visible");
                        if (!strongest.length) {
                            return;
                        }
                        cy.elements(":visible").difference(strongest).addClass("rb-dimmed");
                        strongest.addClass("rb-strong-path");
                    } catch (_err) {
                        try {
                            cy.elements().removeClass("rb-dimmed rb-strong-path");
                        } catch (_ignore) {}
                    }
                }

                function restoreSelectionFromState() {
                    if (!state.selected || typeof state.selected !== "object") {
                        return false;
                    }

                    var selectedKind = String(state.selected.kind || "");
                    var selectedId = String(state.selected.id || "");
                    if (!selectedKind || !selectedId) {
                        return false;
                    }

                    cy.elements().unselect();
                    if (selectedKind === "node") {
                        var node = cy.getElementById(selectedId);
                        if (node && node.length) {
                            node.select();
                            renderNodeInspector(node.data());
                            if (state.inspectorScrollTop > 0) {
                                requestAnimationFrame(function () {
                                    inspector.scrollTop = state.inspectorScrollTop;
                                });
                            }
                            return true;
                        }
                    } else if (selectedKind === "edge") {
                        var edge = cy.getElementById(selectedId);
                        if (edge && edge.length) {
                            edge.select();
                            renderEdgeInspector(edge.data());
                            if (state.inspectorScrollTop > 0) {
                                requestAnimationFrame(function () {
                                    inspector.scrollTop = state.inspectorScrollTop;
                                });
                            }
                            return true;
                        }
                    }
                    return false;
                }

                function applyFilters() {
                    state.fullGraph = viewToggleBtn ? (String(viewToggleBtn.dataset.fullGraph || "false") === "true") : Boolean(state.fullGraph);
                    state.typeFilter = typeFilter ? String(typeFilter.value || "all") : "all";
                    state.minConfidence = minConfidenceInput ? asInt(minConfidenceInput.value, 0, 100) : 0;
                    state.hideLowSignal = lowSignalBtn ? (String(lowSignalBtn.dataset.hideLowSignal || "false") === "true") : false;

                    if (minConfidenceValue) {
                        minConfidenceValue.textContent = String(state.minConfidence);
                    }

                    var forcedNodeIds = {};
                    var forcedEdgeIds = {};
                    if (state.strongestPath && hasPathData) {
                        var strongest = getStrongestPathElements();
                        strongest.nodes().forEach(function (node) {
                            forcedNodeIds[node.id()] = true;
                        });
                        strongest.edges().forEach(function (edge) {
                            forcedEdgeIds[edge.id()] = true;
                            forcedNodeIds[String(edge.data("source") || "")] = true;
                            forcedNodeIds[String(edge.data("target") || "")] = true;
                        });
                    }
                    if (state.selected && typeof state.selected === "object") {
                        var selectedKind = String(state.selected.kind || "");
                        var selectedId = String(state.selected.id || "");
                        if (selectedKind === "node" && selectedId) {
                            forcedNodeIds[selectedId] = true;
                        } else if (selectedKind === "edge" && selectedId) {
                            var selectedEdge = cy.getElementById(selectedId);
                            if (selectedEdge && selectedEdge.length) {
                                forcedEdgeIds[selectedEdge.id()] = true;
                                forcedNodeIds[String(selectedEdge.data("source") || "")] = true;
                                forcedNodeIds[String(selectedEdge.data("target") || "")] = true;
                            }
                        }
                    }

                    function operatorViewVisible(node) {
                        var nodeType = String(node.data("type") || "").toLowerCase();
                        var lowSignal = asInt(node.data("low_signal"), 0, 1) > 0;
                        var count = asInt(node.data("count"), 0);
                        var suggestionCount = asArray(node.data("related_suggestions")).length;
                        var cveCount = asArray(node.data("related_cves")).length;
                        var tagCount = asArray(node.data("related_nuclei_tags")).length;
                        var endpointCount = asArray(node.data("related_endpoints")).length;
                        var signalScore = count + (suggestionCount * 2) + (cveCount * 2) + Math.min(4, endpointCount) + Math.min(2, tagCount);
                        var keyType = nodeType === "surface" || nodeType === "outcome" || nodeType === "technology" || nodeType === "finding";
                        if (!keyType) {
                            return false;
                        }
                        if (nodeType === "finding") {
                            return true;
                        }
                        if (!lowSignal && signalScore > 0) {
                            return true;
                        }
                        return signalScore >= 3;
                    }

                    var visibleNodeIds = {};
                    cy.nodes().forEach(function (node) {
                        var typeOk = state.typeFilter === "all" || String(node.data("type") || "") === state.typeFilter;
                        var lowSignal = asInt(node.data("low_signal"), 0, 1) > 0;
                        var lowSignalOk = !(state.hideLowSignal && lowSignal);
                        var operatorOk = state.fullGraph || operatorViewVisible(node);
                        var visible = typeOk && lowSignalOk && operatorOk;
                        if (forcedNodeIds[node.id()]) {
                            visible = true;
                        }
                        node.style("display", visible ? "element" : "none");
                        if (visible) {
                            visibleNodeIds[node.id()] = true;
                        }
                    });

                    var effectiveMinConfidence = state.fullGraph ? state.minConfidence : Math.max(state.minConfidence, 45);
                    cy.edges().forEach(function (edge) {
                        var confidenceOk = asInt(edge.data("confidence"), 0, 100) >= effectiveMinConfidence;
                        if (forcedEdgeIds[edge.id()]) {
                            confidenceOk = true;
                        }
                        var sourceVisible = !!visibleNodeIds[String(edge.data("source") || "")];
                        var targetVisible = !!visibleNodeIds[String(edge.data("target") || "")];
                        edge.style("display", (confidenceOk && sourceVisible && targetVisible) ? "element" : "none");
                    });

                    applyStrongestPathHighlight();
                    updateZoomLabelDensity();
                    schedulePersist(150);
                }

                function clearSearchHighlights() {
                    cy.nodes().removeClass("rb-search-hit");
                }

                function searchNodeByLabel(fitMatches, selectFirstMatch) {
                    clearSearchHighlights();
                    if (!searchInput) {
                        return;
                    }
                    var query = String(searchInput.value || "").trim().toLowerCase();
                    state.searchQuery = query;
                    if (!query) {
                        schedulePersist(120);
                        return;
                    }
                    var matches = cy.nodes(":visible").filter(function (node) {
                        return String(node.data("label") || "").toLowerCase().indexOf(query) !== -1;
                    });
                    if (!matches.length) {
                        renderInspectorHint("__GRAPH_UI_HINT_NO_SEARCH_MATCH__");
                        schedulePersist(120);
                        return;
                    }
                    matches.addClass("rb-search-hit");
                    if (fitMatches) {
                        cy.fit(matches, 90);
                    }
                    var first = matches[0];
                    var shouldSelect = (typeof selectFirstMatch === "boolean") ? selectFirstMatch : true;
                    if (first && shouldSelect) {
                        cy.elements().unselect();
                        first.select();
                        state.selected = { kind: "node", id: first.id() };
                        state.inspectorScrollTop = 0;
                        renderNodeInspector(first.data());
                    }
                    schedulePersist(120);
                }

                function runLayout(shouldFit) {
                    cy.layout({
                        name: "cose",
                        animate: false,
                        fit: !!shouldFit,
                        padding: 52,
                        randomize: false,
                        nodeRepulsion: function (node) {
                            return 5500 + (asInt(node.data("importance"), 10) * 140);
                        },
                        idealEdgeLength: function (edge) {
                            return 115 + ((100 - asInt(edge.data("confidence"), 0, 100)) * 0.85);
                        },
                        edgeElasticity: function (edge) {
                            return 110 + ((100 - asInt(edge.data("confidence"), 0, 100)) * 0.55);
                        },
                        gravity: 1.06,
                        numIter: 1200,
                        coolingFactor: 0.95,
                        initialTemp: 220
                    }).run();
                }

                function restoreViewportIfPossible() {
                    var sameTopology = topologyHash && state.topologyHash && topologyHash === state.topologyHash;
                    if (!sameTopology) {
                        return false;
                    }
                    if (typeof state.zoom !== "number" || !state.pan || typeof state.pan !== "object") {
                        return false;
                    }
                    cy.zoom(state.zoom);
                    cy.pan({ x: asNumber(state.pan.x, 0), y: asNumber(state.pan.y, 0) });
                    return true;
                }

                function usableSavedPositionRatio() {
                    var total = 0;
                    var usable = 0;
                    cy.nodes().forEach(function (node) {
                        total += 1;
                        if (state.positions && state.positions[node.id()]) {
                            usable += 1;
                        }
                    });
                    if (total <= 0) {
                        return 0;
                    }
                    return usable / total;
                }

                var canReusePositions = Boolean(topologyHash) && topologyHash === state.topologyHash && usableSavedPositionRatio() >= 0.65;

                if (fitBtn) {
                    listen(fitBtn, "click", function () {
                        var visible = cy.elements(":visible");
                        if (visible.length) {
                            cy.fit(visible, 56);
                            schedulePersist(80);
                        }
                    });
                }

                if (resetZoomBtn) {
                    listen(resetZoomBtn, "click", function () {
                        cy.zoom(1);
                        var visibleNodes = cy.nodes(":visible");
                        if (visibleNodes.length) {
                            cy.center(visibleNodes);
                        }
                        updateZoomLabelDensity();
                        schedulePersist(80);
                    });
                }

                if (rerunLayoutBtn) {
                    listen(rerunLayoutBtn, "click", function () {
                        runLayout(true);
                    });
                }

                if (viewToggleBtn) {
                    listen(viewToggleBtn, "click", function () {
                        var current = String(viewToggleBtn.dataset.fullGraph || "false") === "true";
                        var next = !current;
                        viewToggleBtn.dataset.fullGraph = next ? "true" : "false";
                        viewToggleBtn.classList.toggle("is-active", next);
                        viewToggleBtn.textContent = next ? "__GRAPH_UI_BTN_OPERATOR_VIEW__" : "__GRAPH_UI_BTN_SHOW_FULL__";
                        state.fullGraph = next;
                        applyFilters();
                        var visible = cy.elements(":visible");
                        if (visible.length) {
                            cy.fit(visible, 62);
                        }
                        schedulePersist(90);
                    });
                }

                if (searchBtn) {
                    listen(searchBtn, "click", function () {
                        searchNodeByLabel(true, true);
                    });
                }

                if (searchInput) {
                    listen(searchInput, "keydown", function (event) {
                        if (event.key === "Enter") {
                            event.preventDefault();
                            searchNodeByLabel(true, true);
                        }
                    });
                }

                if (typeFilter) {
                    listen(typeFilter, "change", applyFilters);
                }

                if (minConfidenceInput) {
                    listen(minConfidenceInput, "input", applyFilters);
                }

                if (strongestPathBtn) {
                    listen(strongestPathBtn, "click", function () {
                        if (!hasPathData) {
                            return;
                        }
                        state.strongestPath = !state.strongestPath;
                        strongestPathBtn.classList.toggle("is-active", state.strongestPath);
                        strongestPathBtn.textContent = state.strongestPath ? "__GRAPH_UI_BTN_CLEAR_PATH__" : "__GRAPH_UI_BTN_HIGHLIGHT_PATH__";
                        applyFilters();
                        if (state.strongestPath) {
                            var strongest = getStrongestPathElements().filter(":visible");
                            if (strongest.length && strongest.nodes().length) {
                                cy.fit(strongest, 78);
                            }
                            if (!state.selected && bestPathReasonShort) {
                                renderInspectorHint("__GRAPH_UI_HINT_STRONGEST_PATH__ " + bestPathReasonShort);
                            }
                        }
                        schedulePersist(80);
                    });
                }

                if (lowSignalBtn) {
                    listen(lowSignalBtn, "click", function () {
                        var current = String(lowSignalBtn.dataset.hideLowSignal || "false") === "true";
                        var next = !current;
                        lowSignalBtn.dataset.hideLowSignal = next ? "true" : "false";
                        lowSignalBtn.classList.toggle("is-active", next);
                        lowSignalBtn.textContent = next ? "__GRAPH_UI_BTN_SHOW_LOW_SIGNAL__" : "__GRAPH_UI_BTN_HIDE_LOW_SIGNAL__";
                        applyFilters();
                    });
                }

                listen(inspector, "scroll", function () {
                    state.inspectorScrollTop = asInt(inspector.scrollTop, 0);
                    schedulePersist(120);
                }, { passive: true });

                listen(window, "resize", function () {
                    if (!cy || cy.destroyed()) {
                        return;
                    }
                    cy.resize();
                    updateZoomLabelDensity();
                }, { passive: true });
                var scrollResizeTimer = null;
                listen(window, "scroll", function () {
                    if (!cy || cy.destroyed()) {
                        return;
                    }
                    if (scrollResizeTimer) {
                        clearTimeout(scrollResizeTimer);
                    }
                    scrollResizeTimer = setTimeout(function () {
                        cy.resize();
                        updateZoomLabelDensity();
                    }, 80);
                }, { passive: true });

                listen(document, "visibilitychange", function () {
                    if (document.visibilityState === "hidden") {
                        persistStateNow();
                    }
                });
                listen(window, "beforeunload", function () {
                    persistStateNow();
                });

                cy.on("tap", "node", function (event) {
                    var node = event.target;
                    state.selected = { kind: "node", id: node.id() };
                    state.inspectorScrollTop = 0;
                    renderNodeInspector(node.data());
                    schedulePersist(80);
                });

                cy.on("tap", "edge", function (event) {
                    var edge = event.target;
                    state.selected = { kind: "edge", id: edge.id() };
                    state.inspectorScrollTop = 0;
                    renderEdgeInspector(edge.data());
                    schedulePersist(80);
                });

                cy.on("tap", function (event) {
                    if (event.target === cy) {
                        state.selected = null;
                        state.inspectorScrollTop = 0;
                        renderInspectorHint(defaultInspectorHint);
                        schedulePersist(80);
                    }
                });

                cy.on("zoom pan", function () {
                    updateZoomLabelDensity();
                    schedulePersist(140);
                });
                cy.on("dragfree", "node", function () {
                    schedulePersist(80);
                });
                cy.on("layoutstop", function () {
                    updateZoomLabelDensity();
                    schedulePersist(80);
                });

                applyFilters();
                if (searchInput && state.searchQuery) {
                    searchNodeByLabel(false, false);
                }

                if (canReusePositions) {
                    cy.resize();
                    if (!restoreViewportIfPossible()) {
                        var visible = cy.elements(":visible");
                        if (visible.length) {
                            cy.fit(visible, 56);
                        }
                    }
                } else {
                    runLayout(true);
                }

                if (!restoreSelectionFromState()) {
                    renderInspectorHint(defaultInspectorHint);
                }

                requestAnimationFrame(function () {
                    requestAnimationFrame(function () {
                        if (!cy || cy.destroyed()) {
                            return;
                        }
                        cy.resize();
                        updateZoomLabelDensity();
                    });
                });

                persistStateNow();

                window.__reconbotGraphRuntime = {
                    cy: cy,
                    destroy: function () {
                        try {
                            persistStateNow();
                        } catch (_err) {}
                        if (persistTimer) {
                            clearTimeout(persistTimer);
                            persistTimer = null;
                        }
                        if (scrollResizeTimer) {
                            clearTimeout(scrollResizeTimer);
                            scrollResizeTimer = null;
                        }
                        cleanupFns.forEach(function (fn) {
                            try {
                                fn();
                            } catch (_err) {}
                        });
                        cleanupFns = [];
                        if (cy && !cy.destroyed()) {
                            try {
                                cy.destroy();
                            } catch (_err) {}
                        }
                        canvas.innerHTML = "";
                    }
                };
                } catch (err) {
                    try {
                        if (canvas && String(canvas.textContent || "").indexOf("__GRAPH_UI_INITIALIZING__") !== -1) {
                            canvas.innerHTML = '<div class="graph-canvas-empty">__GRAPH_UI_INIT_FAILED_CANVAS__</div>';
                        }
                    } catch (_ignore) {}
                    try {
                        renderInspectorHint("__GRAPH_UI_INIT_FAILED_INSPECTOR__");
                    } catch (_ignore2) {}
                    try {
                        console.error("ReconBot graph init error:", err);
                    } catch (_ignore3) {}
                }
            });
        })();
        </script>
    """
    return (
        template
        .replace("__GRAPH_PAYLOAD_JSON__", payload_json, 1)
        .replace("__GRAPH_UI_BTN_FIT__", _txt("graph_ui_btn_fit"))
        .replace("__GRAPH_UI_BTN_RESET_ZOOM__", _txt("graph_ui_btn_reset_zoom"))
        .replace("__GRAPH_UI_BTN_RERUN_LAYOUT__", _txt("graph_ui_btn_rerun_layout"))
        .replace("__GRAPH_UI_BTN_SHOW_FULL__", _txt("graph_ui_btn_show_full"))
        .replace("__GRAPH_UI_BTN_OPERATOR_VIEW__", _txt("graph_ui_btn_operator_view"))
        .replace("__GRAPH_UI_SEARCH_PLACEHOLDER__", _txt("graph_ui_search_placeholder"))
        .replace("__GRAPH_UI_BTN_SEARCH__", _txt("graph_ui_btn_search"))
        .replace("__GRAPH_UI_FILTER_ALL__", _txt("graph_ui_filter_label"))
        .replace("__GRAPH_UI_MIN_CONFIDENCE__", _txt("graph_ui_min_confidence"))
        .replace("__GRAPH_UI_BTN_HIGHLIGHT_PATH__", _txt("graph_ui_btn_highlight_path"))
        .replace("__GRAPH_UI_BTN_CLEAR_PATH__", _txt("graph_ui_btn_clear_path"))
        .replace("__GRAPH_UI_BTN_HIDE_LOW_SIGNAL__", _txt("graph_ui_btn_hide_low_signal"))
        .replace("__GRAPH_UI_BTN_SHOW_LOW_SIGNAL__", _txt("graph_ui_btn_show_low_signal"))
        .replace("__GRAPH_UI_HELPER_NOTE__", _txt("graph_ui_helper_note"))
        .replace("__GRAPH_UI_INITIALIZING__", _txt("graph_ui_initializing"))
        .replace("__GRAPH_UI_INSPECTOR_TITLE__", _txt("graph_ui_inspector_title"))
        .replace("__GRAPH_UI_INSPECTOR_NOTE__", _txt("graph_ui_inspector_note"))
        .replace("__GRAPH_UI_INIT_FAILED_CANVAS__", _txt("graph_ui_init_failed_canvas"))
        .replace("__GRAPH_UI_INIT_FAILED_INSPECTOR__", _txt("graph_ui_init_failed_inspector"))
        .replace("__GRAPH_UI_LIBRARY_MISSING_CANVAS__", _txt("graph_ui_library_missing_canvas"))
        .replace("__GRAPH_UI_LIBRARY_MISSING_INSPECTOR__", _txt("graph_ui_library_missing_inspector"))
        .replace("__GRAPH_UI_HINT_NO_NODE_DATA__", _txt("graph_ui_hint_no_node_data"))
        .replace("__GRAPH_UI_HINT_NO_SEARCH_MATCH__", _txt("graph_ui_hint_no_search_match"))
        .replace("__GRAPH_UI_HINT_STRONGEST_PATH__", _txt("graph_ui_hint_strongest_path"))
        .replace("__GRAPH_UI_NO_NODES_CANVAS__", _txt("graph_ui_no_nodes_canvas"))
        .replace("__GRAPH_UI_NO_DATA_CANVAS__", _txt("graph_ui_no_data_canvas"))
        .replace("__GRAPH_UI_NODE_WHY_SURFACE__", _txt("graph_ui_node_why_surface"))
        .replace("__GRAPH_UI_NODE_WHY_FINDING__", _txt("graph_ui_node_why_finding"))
        .replace("__GRAPH_UI_NODE_WHY_OUTCOME__", _txt("graph_ui_node_why_outcome"))
        .replace("__GRAPH_UI_NODE_WHY_TECH__", _txt("graph_ui_node_why_technology"))
        .replace("__GRAPH_UI_NODE_WHY_SUPPORT__", _txt("graph_ui_node_why_support"))
        .replace("__GRAPH_UI_NODE_WHY_OBSERVED_PREFIX__", _txt("graph_ui_node_why_observed_prefix"))
        .replace("__GRAPH_UI_NODE_WHY_OBSERVED_SUFFIX__", _txt("graph_ui_node_why_observed_suffix"))
        .replace("__GRAPH_UI_NODE_WHY_NEXT_PIVOT_PREFIX__", _txt("graph_ui_node_why_next_pivot_prefix"))
        .replace("__GRAPH_UI_NODE_WHY_NEXT_PIVOT_SUFFIX__", _txt("graph_ui_node_why_next_pivot_suffix"))
        .replace("__GRAPH_UI_NODE_WHY_CVE__", _txt("graph_ui_node_why_cve"))
        .replace("__GRAPH_UI_NODE_WHY_TAGS__", _txt("graph_ui_node_why_tags"))
        .replace("__GRAPH_UI_EDGE_WHY_HIGH__", _txt("graph_ui_edge_why_high"))
        .replace("__GRAPH_UI_EDGE_WHY_MEDIUM__", _txt("graph_ui_edge_why_medium"))
        .replace("__GRAPH_UI_EDGE_WHY_LOW__", _txt("graph_ui_edge_why_low"))
    )
