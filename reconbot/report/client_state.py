from __future__ import annotations


def build_report_state_script() -> str:
    return """
        <script>
            (function () {
                if (window.__reconbotReportStateInitialized) {
                    return;
                }
                window.__reconbotReportStateInitialized = true;

                const detailsStateKey = "reconbot.report.detailsState.v2";
                const scrollKey = "reconbot.report.scrollY";
                const validReportDepths = ["summary", "balanced", "deep"];

                function safeReadJson(key) {
                    try {
                        const raw = sessionStorage.getItem(key);
                        return raw ? JSON.parse(raw) : null;
                    } catch (_err) {
                        return null;
                    }
                }

                function normalizeToken(value) {
                    return String(value || "")
                        .toLowerCase()
                        .replace(/\\s+/g, " ")
                        .replace(/[^a-z0-9\\-_.:/ ]+/g, "")
                        .trim();
                }

                function normalizeSummaryText(value) {
                    return normalizeToken(value)
                        .replace(/\\(\\s*\\d+\\s*(?:of|\\/)\\s*\\d+\\s*\\)/g, "")
                        .replace(/\\+\\s*\\d+\\s+more/g, "")
                        .replace(/\\(\\s*\\d+\\s*\\)/g, "")
                        .replace(/\\s+/g, " ")
                        .trim();
                }

                function hashString(value) {
                    let hash = 5381;
                    const text = String(value || "");
                    for (let i = 0; i < text.length; i += 1) {
                        hash = ((hash << 5) + hash) + text.charCodeAt(i);
                        hash &= 0xffffffff;
                    }
                    return Math.abs(hash).toString(36);
                }

                function reportScopeId() {
                    const scopeMeta = document.querySelector('meta[name="reconbot-report-scope"]');
                    const scope = scopeMeta ? String(scopeMeta.content || "").trim() : "";
                    return scope || window.location.pathname || "default";
                }

                function reportDepthStorageKey() {
                    const scope = reportScopeId();
                    const readable = normalizeToken(scope).slice(0, 80).replace(/\\s+/g, "-") || "default";
                    return "reconbot.report.depth." + hashString(scope) + "." + readable;
                }

                function currentReportDepth() {
                    const body = document.body;
                    for (const depth of validReportDepths) {
                        if (body.classList.contains("report-depth-" + depth)) {
                            return depth;
                        }
                    }
                    const depthMeta = document.querySelector('meta[name="reconbot-report-depth"]');
                    const depth = depthMeta ? String(depthMeta.content || "").trim().toLowerCase() : "";
                    return validReportDepths.includes(depth) ? depth : "balanced";
                }

                function reportDepthDescription(depth) {
                    if (depth === "summary") {
                        return "karar odaklı görünüm";
                    }
                    if (depth === "deep") {
                        return "tam kanıt/audit görünümü";
                    }
                    return "operatör inceleme görünümü";
                }

                function reportDepthLabel(depth) {
                    if (depth === "summary") {
                        return "Özet";
                    }
                    if (depth === "deep") {
                        return "Derin";
                    }
                    return "Dengeli";
                }

                function navLinkAllowedForDepth(link, depth) {
                    const scope = String(link.getAttribute("data-depth-nav") || "summary balanced deep");
                    return scope.split(/\\s+/).filter(Boolean).includes(depth);
                }

                function visibleSidebarLinks(depth) {
                    return Array.from(document.querySelectorAll('.sidebar-nav a[href^="#"]'))
                        .filter(function (link) { return navLinkAllowedForDepth(link, depth); });
                }

                function syncSidebarNavForDepth(depth, options) {
                    const links = Array.from(document.querySelectorAll('.sidebar-nav a[href^="#"]'));
                    if (!links.length) {
                        return;
                    }
                    links.forEach(function (link) {
                        const allowed = navLinkAllowedForDepth(link, depth);
                        link.hidden = !allowed;
                        if (allowed) {
                            link.removeAttribute("tabindex");
                            link.removeAttribute("aria-hidden");
                        } else {
                            link.setAttribute("tabindex", "-1");
                            link.setAttribute("aria-hidden", "true");
                            link.classList.remove("is-active");
                        }
                    });
                    const currentHash = (window.location.hash || "").slice(1);
                    const currentLink = currentHash
                        ? links.find(function (link) { return String(link.getAttribute("href") || "") === "#" + currentHash; })
                        : null;
                    const activeLink = links.find(function (link) { return link.classList.contains("is-active"); });
                    const needsOverview = (currentLink && currentLink.hidden) || (activeLink && activeLink.hidden);
                    if (needsOverview) {
                        const overview = links.find(function (link) { return String(link.getAttribute("href") || "") === "#overview"; });
                        if (overview) {
                            links.forEach(function (link) { link.classList.toggle("is-active", link === overview); });
                            if (!options || options.scrollToOverview !== false) {
                                window.location.hash = "overview";
                            } else if (window.history && typeof window.history.replaceState === "function") {
                                window.history.replaceState(null, "", "#overview");
                            }
                        }
                    }
                }

                function resizeGraphAfterDepthChange() {
                    try {
                        const runtime = window.__reconbotGraphRuntime;
                        const cy = runtime && runtime.cy;
                        if (!cy || (typeof cy.destroyed === "function" && cy.destroyed())) {
                            return;
                        }
                        window.requestAnimationFrame(function () {
                            try {
                                cy.resize();
                                const visible = typeof cy.elements === "function" ? cy.elements(":visible") : null;
                                if (visible && typeof visible.length === "number" && visible.length > 0 && typeof cy.fit === "function") {
                                    cy.fit(visible, 56);
                                }
                            } catch (_err) {}
                        });
                    } catch (_err) {}
                }

                function setReportDepth(depth, options) {
                    const normalized = String(depth || "").trim().toLowerCase();
                    if (!validReportDepths.includes(normalized)) {
                        return;
                    }
                    const persist = !options || options.persist !== false;
                    validReportDepths.forEach(function (item) {
                        document.body.classList.remove("report-depth-" + item);
                    });
                    document.body.classList.add("report-depth-" + normalized);
                    document.dispatchEvent(new Event("reconbot:report-depth-change"));

                    document.querySelectorAll("[data-report-depth-current]").forEach(function (label) {
                        label.textContent = reportDepthLabel(normalized);
                    });
                    document.querySelectorAll("[data-report-depth-description]").forEach(function (description) {
                        description.textContent = reportDepthLabel(normalized) + ": " + reportDepthDescription(normalized) + ". Modlar yalnızca raporun sunumunu değiştirir; scan verisi, severity, confidence ve artifact’lar değiştirilmez.";
                    });
                    document.querySelectorAll("[data-report-depth-banner-description]").forEach(function (description) {
                        description.textContent = reportDepthDescription(normalized);
                    });
                    document.querySelectorAll("[data-report-depth-button]").forEach(function (button) {
                        const isActive = String(button.getAttribute("data-report-depth-button") || "") === normalized;
                        button.classList.toggle("is-active", isActive);
                        button.setAttribute("aria-pressed", isActive ? "true" : "false");
                    });
                    syncSidebarNavForDepth(normalized, options || {});
                    if (typeof window.__reconbotUpdateActiveNav === "function") {
                        window.__reconbotUpdateActiveNav({ preferHash: true });
                    }
                    if (persist) {
                        try {
                            localStorage.setItem(reportDepthStorageKey(), normalized);
                        } catch (_err) {
                            try {
                                sessionStorage.setItem(reportDepthStorageKey(), normalized);
                            } catch (_innerErr) {}
                        }
                    }
                    resizeGraphAfterDepthChange();
                }

                function initReportDepthSwitcher() {
                    const storageKey = reportDepthStorageKey();
                    let stored = "";
                    try {
                        stored = localStorage.getItem(storageKey) || "";
                    } catch (_err) {}
                    if (!stored) {
                        try {
                            stored = sessionStorage.getItem(storageKey) || "";
                        } catch (_err) {}
                    }
                    const initialDepth = validReportDepths.includes(String(stored).toLowerCase())
                        ? String(stored).toLowerCase()
                        : currentReportDepth();
                    setReportDepth(initialDepth, { persist: false });
                    document.querySelectorAll("[data-report-depth-button]").forEach(function (button) {
                        button.addEventListener("click", function () {
                            setReportDepth(button.getAttribute("data-report-depth-button"));
                        });
                    });
                }

                function initSidebarNavState() {
                    const links = Array.from(document.querySelectorAll('.sidebar-nav a[href^="#"]'));
                    if (!links.length) {
                        return;
                    }
                    const linkById = new Map();
                    links.forEach(function (link) {
                        const id = String(link.getAttribute("href") || "").slice(1);
                        if (id) {
                            linkById.set(id, link);
                        }
                    });

                    function elementIsVisible(element) {
                        if (!element || !(element instanceof HTMLElement)) {
                            return false;
                        }
                        const style = window.getComputedStyle(element);
                        if (style.display === "none" || style.visibility === "hidden") {
                            return false;
                        }
                        return Boolean(element.offsetParent || element.getClientRects().length);
                    }

                    function visibleNavTargets() {
                        const depth = currentReportDepth();
                        return links
                            .filter(function (link) { return !link.hidden && navLinkAllowedForDepth(link, depth); })
                            .map(function (link) {
                                const id = String(link.getAttribute("href") || "").slice(1);
                                const target = id ? document.getElementById(id) : null;
                                return { id: id, link: link, target: target };
                            })
                            .filter(function (item) { return Boolean(item.id && item.target && elementIsVisible(item.target)); });
                    }

                    function setActiveLink(targetLink) {
                        links.forEach(function (link) {
                            link.classList.toggle("is-active", targetLink === link && !link.hidden);
                        });
                    }

                    function setActive(id) {
                        const depth = currentReportDepth();
                        const link = linkById.get(id);
                        const targetLink = link && navLinkAllowedForDepth(link, depth) && !link.hidden
                            ? link
                            : (visibleNavTargets()[0] || {}).link;
                        if (targetLink) {
                            setActiveLink(targetLink);
                        }
                    }

                    function updateActiveFromScroll(options) {
                        const items = visibleNavTargets();
                        if (!items.length) {
                            return;
                        }
                        if ((window.scrollY || 0) <= 8) {
                            setActiveLink(items[0].link);
                            return;
                        }

                        const hash = (window.location.hash || "").slice(1);
                        if (options && options.preferHash && hash) {
                            const hashed = items.find(function (item) { return item.id === hash; });
                            if (hashed) {
                                setActiveLink(hashed.link);
                                return;
                            }
                        }

                        const activationLine = Math.max(96, Math.min(160, Math.round(window.innerHeight * 0.22)));
                        let active = items[0];
                        for (const item of items) {
                            const rect = item.target.getBoundingClientRect();
                            if (rect.top <= activationLine) {
                                active = item;
                            } else {
                                break;
                            }
                        }
                        setActiveLink(active.link);
                    }

                    let activeUpdateFrame = 0;
                    function scheduleActiveUpdate(options) {
                        if (activeUpdateFrame) {
                            window.cancelAnimationFrame(activeUpdateFrame);
                        }
                        activeUpdateFrame = window.requestAnimationFrame(function () {
                            activeUpdateFrame = 0;
                            updateActiveFromScroll(options || {});
                        });
                    }

                    const targets = visibleNavTargets().map(function (item) { return item.target; });
                    if (!targets.length) {
                        return;
                    }

                    window.__reconbotUpdateActiveNav = scheduleActiveUpdate;
                    syncSidebarNavForDepth(currentReportDepth(), { scrollToOverview: false });
                    updateActiveFromScroll({ preferHash: true });
                    window.addEventListener("scroll", function () { scheduleActiveUpdate(); }, { passive: true });
                    window.addEventListener("resize", function () { scheduleActiveUpdate(); }, { passive: true });
                    window.addEventListener("hashchange", function () {
                        setActive((window.location.hash || "").slice(1));
                        scheduleActiveUpdate({ preferHash: true });
                    });
                    links.forEach(function (link) {
                        link.addEventListener("click", function () {
                            if (link.hidden) {
                                return;
                            }
                            setActive(String(link.getAttribute("href") || "").slice(1));
                            window.setTimeout(function () { scheduleActiveUpdate({ preferHash: true }); }, 80);
                        });
                    });
                }

                function sectionScope(node) {
                    const section = node.closest(".section, .panel, .report-group, .raw-section-header");
                    if (!section) {
                        return "page";
                    }
                    if (section.id) {
                        return "id:" + normalizeToken(section.id);
                    }
                    const heading = section.querySelector("h1, h2, h3");
                    if (heading) {
                        return "heading:" + normalizeSummaryText(heading.textContent || "");
                    }
                    return "section";
                }

                function localSignal(node) {
                    const table = node.querySelector("table");
                    if (table) {
                        const headers = Array.from(table.querySelectorAll("th"))
                            .slice(0, 6)
                            .map(function (th) { return normalizeSummaryText(th.textContent || ""); })
                            .filter(Boolean);
                        if (headers.length) {
                            return "table:" + headers.join("|");
                        }
                    }
                    const detailLabels = Array.from(node.querySelectorAll("dt"))
                        .slice(0, 4)
                        .map(function (dt) { return normalizeSummaryText(dt.textContent || ""); })
                        .filter(Boolean);
                    if (detailLabels.length) {
                        return "dl:" + detailLabels.join("|");
                    }
                    const nestedHeading = node.querySelector("h3, h4");
                    if (nestedHeading) {
                        return "heading:" + normalizeSummaryText(nestedHeading.textContent || "");
                    }
                    const firstItem = node.querySelector("li");
                    if (firstItem) {
                        return "li:" + normalizeSummaryText((firstItem.textContent || "").slice(0, 80));
                    }
                    return "summary-only";
                }

                function ancestorSummaryPath(node) {
                    const parts = [];
                    let current = node.parentElement ? node.parentElement.closest("details") : null;
                    while (current) {
                        const summary = current.querySelector("summary");
                        const summaryText = normalizeSummaryText(summary ? (summary.textContent || "") : "details");
                        if (summaryText) {
                            parts.push(summaryText);
                        }
                        current = current.parentElement ? current.parentElement.closest("details") : null;
                    }
                    parts.reverse();
                    return parts.join(">");
                }

                function assignStableDetailsKeys() {
                    const detailsNodes = Array.from(document.querySelectorAll("details"));
                    const usedKeys = new Set();
                    detailsNodes.forEach(function (node) {
                        if (!(node instanceof HTMLElement)) {
                            return;
                        }
                        const existingKey = String(node.dataset.rbDetailsKey || "").trim();
                        if (existingKey) {
                            if (!node.id) {
                                node.id = existingKey;
                            }
                            usedKeys.add(existingKey);
                            return;
                        }

                        const summary = node.querySelector("summary");
                        const summaryText = normalizeSummaryText(summary ? (summary.textContent || "") : "details");
                        const scope = sectionScope(node);
                        const ancestors = ancestorSummaryPath(node);
                        const signal = localSignal(node);
                        const base = [scope, ancestors, summaryText, signal].join("|");
                        let key = "rb-detail-" + hashString(base);

                        if (usedKeys.has(key)) {
                            const textSignal = normalizeToken((node.textContent || "").slice(0, 120));
                            key = key + "-" + hashString(base + "|" + textSignal);
                        }
                        let candidate = key;
                        let suffix = 1;
                        while (usedKeys.has(candidate)) {
                            suffix += 1;
                            candidate = key + "-" + suffix;
                        }
                        key = candidate;
                        usedKeys.add(key);

                        node.dataset.rbDetailsKey = key;
                        if (!node.id) {
                            node.id = key;
                        }
                    });
                }

                function saveAllDetailsState() {
                    const state = {};
                    document.querySelectorAll("details").forEach(function (node) {
                        const key = String(node.dataset.rbDetailsKey || "").trim();
                        if (!key) {
                            return;
                        }
                        state[key] = Boolean(node.open);
                    });
                    try {
                        sessionStorage.setItem(detailsStateKey, JSON.stringify(state));
                    } catch (_err) {}
                }

                function saveDetailsNodeState(node) {
                    if (!node || node.tagName.toLowerCase() !== "details") {
                        return;
                    }
                    const key = String(node.dataset.rbDetailsKey || "").trim();
                    if (!key) {
                        return;
                    }
                    const state = safeReadJson(detailsStateKey);
                    const nextState = (state && typeof state === "object") ? state : {};
                    nextState[key] = Boolean(node.open);
                    try {
                        sessionStorage.setItem(detailsStateKey, JSON.stringify(nextState));
                    } catch (_err) {}
                }

                function restoreDetailsState() {
                    const saved = safeReadJson(detailsStateKey);
                    if (!saved || typeof saved !== "object") {
                        return;
                    }
                    document.querySelectorAll("details").forEach(function (node) {
                        const key = String(node.dataset.rbDetailsKey || "").trim();
                        if (!key) {
                            return;
                        }
                        if (Object.prototype.hasOwnProperty.call(saved, key)) {
                            node.open = Boolean(saved[key]);
                        }
                    });
                }

                function saveScrollPosition() {
                    try {
                        sessionStorage.setItem(scrollKey, String(window.scrollY || 0));
                    } catch (_err) {}
                }

                function restoreScrollPosition() {
                    const raw = sessionStorage.getItem(scrollKey);
                    if (!raw) {
                        return;
                    }
                    const y = parseInt(raw, 10);
                    if (!Number.isNaN(y) && y >= 0) {
                        requestAnimationFrame(function () {
                            window.scrollTo(0, y);
                        });
                    }
                }

                function initReportState() {
                    // Keep the decision, plan and finding evidence prominent;
                    // auxiliary inventories remain available without long scrolling.
                    document.querySelectorAll(".report-main .section").forEach(function (section) {
                        const heading = section.querySelector(":scope > h2");
                        if (!heading) return;
                        heading.textContent = heading.textContent.replace(/^[^A-Za-z0-9\\u00c0-\\u024f]+/, "");
                        if (["overview", "operator-plan", "run-quality", "findings", "osint-enrichment", "screenshots"].includes(section.id)) return;
                        if (section.closest("details")) return;
                        const disclosure = document.createElement("details");
                        disclosure.className = "report-section-disclosure";
                        disclosure.open = currentReportDepth() === "deep";
                        const summary = document.createElement("summary");
                        summary.appendChild(heading);
                        disclosure.appendChild(summary);
                        const content = document.createElement("div");
                        content.className = "report-section-content";
                        while (section.firstChild) content.appendChild(section.firstChild);
                        disclosure.appendChild(content);
                        section.appendChild(disclosure);
                    });
                    document.querySelectorAll('.sidebar-nav a[href^="#"]').forEach(function (link) {
                        link.addEventListener("click", function () {
                            const section = document.getElementById(link.getAttribute("href").slice(1));
                            let ancestor = section && section.parentElement;
                            while (ancestor) {
                                if (ancestor.tagName === "DETAILS") ancestor.open = true;
                                ancestor = ancestor.parentElement;
                            }
                            const disclosure = section && section.querySelector(":scope > .report-section-disclosure");
                            if (disclosure) disclosure.open = true;
                        });
                    });
                    document.addEventListener("reconbot:report-depth-change", function () {
                        const expanded = currentReportDepth() === "deep";
                        document.querySelectorAll(".report-section-disclosure, .report-evidence-disclosure").forEach(function (node) { node.open = expanded; });
                    });
                    const beforePrint = new Map();
                    window.addEventListener("beforeprint", function () {
                        document.querySelectorAll(".report-section-disclosure, .report-evidence-disclosure").forEach(function (node) { beforePrint.set(node, node.open); node.open = true; });
                    });
                    window.addEventListener("afterprint", function () { beforePrint.forEach(function (open, node) { node.open = open; }); beforePrint.clear(); });
                    initReportDepthSwitcher();
                    initSidebarNavState();
                    assignStableDetailsKeys();
                    restoreDetailsState();
                    restoreScrollPosition();
                }

                window.__reconbotSetReportDepth = setReportDepth;

                if (document.readyState === "loading") {
                    document.addEventListener("DOMContentLoaded", initReportState, { once: true });
                } else {
                    initReportState();
                }

                document.addEventListener("toggle", function (event) {
                    const target = event.target;
                    if (target && target.tagName && target.tagName.toLowerCase() === "details") {
                        saveDetailsNodeState(target);
                        if (target.open && target.querySelector(".attack-graph-canvas")) resizeGraphAfterDepthChange();
                    }
                }, true);

                window.addEventListener("scroll", saveScrollPosition, { passive: true });
                document.addEventListener("visibilitychange", function () {
                    if (document.visibilityState === "hidden") {
                        saveAllDetailsState();
                        saveScrollPosition();
                    }
                });
                window.addEventListener("beforeunload", function () {
                    saveAllDetailsState();
                    saveScrollPosition();
                });
            })();
        </script>
    """
