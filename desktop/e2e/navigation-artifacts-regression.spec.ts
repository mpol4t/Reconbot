import { expect, test, type Page, type TestInfo } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import type { E2EScenario } from "../src/main/e2eFixture";
import { launchReconBot, readFixture, setRunScenario, setWindowSize } from "./harness";

const evidenceDir = path.resolve(__dirname, "../test-results/reconbot-navigation-evidence");
const fixtureRunsDir = path.resolve(__dirname, "fixtures/runs");
const diagnostics: Array<{ test: string; scenario: string; errors: string[]; warnings: string[] }> = [];

type View = "dashboard" | "configure" | "terminal" | "report" | "artifacts" | "findings" | "pipeline" | "settings";

const views: Array<{ view: View; heading: RegExp }> = [
  { view: "dashboard", heading: /Operational Situation/i },
  { view: "configure", heading: /Scan Control/i },
  { view: "terminal", heading: /Interactive PTY/i },
  { view: "report", heading: /Report status|Report view/i },
  { view: "artifacts", heading: /Outputs and scan history/i },
  { view: "findings", heading: /Findings/i },
  { view: "pipeline", heading: /Evidence graph|Kanıt grafiği/i },
  { view: "settings", heading: /Tool Parameters|Default Scan Profile/i }
];

function writeEvidence(name: string, value: unknown): void {
  fs.mkdirSync(evidenceDir, { recursive: true });
  fs.writeFileSync(path.join(evidenceDir, name), JSON.stringify(value, null, 2));
}

async function activeView(page: Page): Promise<string | null> {
  return page.locator(".view-pane.active").getAttribute("data-view");
}

async function assertSelectedView(page: Page, view: View, previous?: View): Promise<void> {
  const selectedButton = page.locator(`.nav-rail button[data-view="${view}"]`);
  await expect(selectedButton).toHaveAttribute("aria-current", "page");
  await expect(selectedButton).toHaveClass(/active/);
  if (previous && previous !== view) {
    const previousButton = page.locator(`.nav-rail button[data-view="${previous}"]`);
    await expect(previousButton).not.toHaveClass(/active/);
    await expect(previousButton).not.toHaveAttribute("aria-current", "page");
  }

  const selectedPane = page.locator(`.view-pane[data-view="${view}"]`);
  await expect(selectedPane).toBeVisible();
  await expect(selectedPane).not.toHaveAttribute("hidden", "");
  for (const other of views.filter((item) => item.view !== view)) {
    const pane = page.locator(`.view-pane[data-view="${other.view}"]`);
    if (await pane.count()) {
      await expect(pane).toBeHidden();
      await expect(pane).toHaveAttribute("hidden", "");
      expect(await pane.evaluate((element) => getComputedStyle(element).pointerEvents)).toBe("none");
    }
  }

  if (view === "settings") {
    await expect(selectedPane.getByText(/Tool Parameters|Default Scan Profile/i).first()).toBeVisible();
  } else {
    await expect(selectedPane.getByText(views.find((item) => item.view === view)!.heading).first()).toBeVisible();
  }
}

function collectDiagnostic(testInfo: TestInfo, scenario: string, errors: string[], warnings: string[]): void {
  diagnostics.push({ test: testInfo.title, scenario, errors: [...errors], warnings: [...warnings] });
  writeEvidence("renderer-console-errors.json", diagnostics);
}

test.describe("sidebar navigation and historical artifact integrity", () => {
  test.beforeAll(() => {
    fs.mkdirSync(evidenceDir, { recursive: true });
  });

  test("terminal fills available width and height after resizing and returning to its tab", async ({}, testInfo) => {
    const harness = await launchReconBot(testInfo, "active-running");
    try {
      const page = harness.page;
      await page.locator('.nav-rail button[data-view="terminal"]').click();
      await expect(page.locator(".xterm-rows")).toContainText("ReconBot E2E terminal ready");
      for (const [width, height] of [[1800, 1100], [1000, 720], [1500, 900]]) {
        await setWindowSize(harness.app, width, height);
        await expect.poll(() => page.locator(".terminal-host").evaluate((host) => {
          const screen = host.querySelector(".xterm-screen") as HTMLElement;
          return { widthGap: host.clientWidth - screen.clientWidth, heightGap: host.clientHeight - screen.clientHeight };
        })).toMatchObject({ widthGap: expect.any(Number), heightGap: expect.any(Number) });
        await expect.poll(() => page.locator(".terminal-host").evaluate((host) => {
          const screen = host.querySelector(".xterm-screen") as HTMLElement;
          return host.clientWidth - screen.clientWidth < 32 && host.clientHeight - screen.clientHeight < 24;
        })).toBe(true);
      }
      await page.locator('.nav-rail button[data-view="dashboard"]').click();
      await setWindowSize(harness.app, 1800, 1000);
      await page.locator('.nav-rail button[data-view="terminal"]').click();
      await expect.poll(async () => {
        const fixture = await readFixture(harness.app);
        return (fixture.calls.filter((call) => call.channel === "terminal:resize").at(-1)?.payload as { cols?: number })?.cols || 0;
      }).toBeGreaterThan(150);
      await harness.app.evaluate(({ BrowserWindow }) => {
        BrowserWindow.getAllWindows()[0].webContents.send("terminal:data", "\r\nWIDTH-PROBE " + "0123456789".repeat(18) + " END\r\n");
      });
      await expect(page.locator(".xterm-rows")).toContainText("WIDTH-PROBE");
      await expect(page.locator(".xterm-rows")).toContainText("ReconBot E2E terminal ready");
      await page.screenshot({ path: path.join(evidenceDir, "terminal-fitted.png") });
      expect(harness.errors).toEqual([]);
    } finally { await harness.close(); }
  });

  test("live report rewrites preserve the loaded document, scroll and expanded evidence", async ({}, testInfo) => {
    const reportPath = path.join(fixtureRunsDir, "complete-report-run/report.html");
    const originalStat = fs.statSync(reportPath);
    const originalHtml = fs.readFileSync(reportPath, "utf8");
    const harness = await launchReconBot(testInfo, "complete-report");
    try {
      const page = harness.page;
      await page.locator('.nav-rail button[data-view="report"]').click();
      const iframe = page.locator('iframe[title="ReconBot report"]');
      await expect(page.frameLocator('iframe[title="ReconBot report"]').getByRole("heading", { name: "Complete report fixture A" })).toBeVisible();
      const frame = page.frames().find((item) => item.url().startsWith("reconbot-report://"))!;
      const src = await iframe.getAttribute("src");
      await frame.evaluate(() => {
        document.body.style.minHeight = "3000px";
        const details = document.createElement("details");
        details.id = "reading-evidence";
        details.open = true;
        details.innerHTML = "<summary>Expanded evidence</summary><p>Reading here</p>";
        document.body.append(details);
        window.scrollTo(0, 700);
      });
      await expect.poll(() => frame.evaluate(() => window.scrollY)).toBe(700);
      for (let rewrite = 1; rewrite <= 3; rewrite++) {
        fs.writeFileSync(reportPath, `${originalHtml}\n<!-- live-update-${rewrite} -->\n`);
        const time = new Date(originalStat.mtimeMs + rewrite * 5000);
        fs.utimesSync(reportPath, time, time);
        await page.waitForTimeout(1700);
        await expect(iframe).toHaveAttribute("src", src!);
        expect(await frame.evaluate(() => window.scrollY)).toBe(700);
        expect(await frame.locator("#reading-evidence").evaluate((node) => (node as HTMLDetailsElement).open)).toBe(true);
      }
      await expect(page.getByText("Report updated", { exact: true })).toBeVisible();
      await page.getByRole("button", { name: "Reload", exact: true }).click();
      await expect(iframe).not.toHaveAttribute("src", src!);
      await expect(page.frameLocator('iframe[title="ReconBot report"]').getByRole("heading", { name: "Complete report fixture A" })).toBeVisible();
      expect(harness.errors).toEqual([]);
    } finally {
      fs.writeFileSync(reportPath, originalHtml);
      fs.utimesSync(reportPath, originalStat.atime, originalStat.mtime);
      await harness.close();
    }
  });

  test("navigation matrix remains operator-owned across run-state polling", async ({}, testInfo) => {
    test.setTimeout(360_000);
    const scenarios: E2EScenario[] = [
      "idle",
      "active-running",
      "complete-report",
      "incomplete-partial",
      "interrupted",
      "malformed-json"
    ];
    const matrix: Array<Record<string, unknown>> = [];

    for (const scenario of scenarios) {
      const harness = await launchReconBot(testInfo, scenario);
      try {
        let previous: View = "dashboard";
        for (const item of views) {
          await harness.page.locator(`.nav-rail button[data-view="${item.view}"]`).click();
          await assertSelectedView(harness.page, item.view, previous);
          const immediately = await activeView(harness.page);
          await harness.page.waitForTimeout(3_200);
          await assertSelectedView(harness.page, item.view, previous);
          const afterTwoRunPolls = await activeView(harness.page);
          matrix.push({
            scenario,
            requestedView: item.view,
            immediately,
            afterTwoRunPolls,
            passed: immediately === item.view && afterTwoRunPolls === item.view
          });
          expect(harness.errors, `${scenario}/${item.view} renderer errors`).toEqual([]);
          previous = item.view;
        }
        if (scenario === "malformed-json") {
          await harness.page.locator('.nav-rail button[data-view="artifacts"]').click();
          await expect(harness.page.getByText("https://malformed-fallback.example", { exact: false }).first()).toBeVisible();
          await harness.page.screenshot({ path: path.join(evidenceDir, "navigation-after-polling.png"), fullPage: false });
        }
        collectDiagnostic(testInfo, scenario, harness.errors, harness.warnings);
      } finally {
        await harness.close();
      }
    }

    expect(matrix).toHaveLength(scenarios.length * views.length);
    expect(matrix.every((row) => row.passed === true)).toBe(true);
    writeEvidence("sidebar-navigation-matrix.json", matrix);
  });

  test("incomplete historical Artifacts opens from Dashboard and survives every polling cycle", async ({}, testInfo) => {
    const harness = await launchReconBot(testInfo, "incomplete-partial");
    try {
      const page = harness.page;
      const timings: Array<{ checkpoint: string; activeView: string | null }> = [];
      timings.push({ checkpoint: "before_click", activeView: await activeView(page) });

      await page.locator('.nav-rail button[data-view="artifacts"]').click();
      timings.push({ checkpoint: "immediately_after_click", activeView: await activeView(page) });
      await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => resolve())));
      timings.push({ checkpoint: "after_react_commit", activeView: await activeView(page) });
      await page.waitForTimeout(250);
      timings.push({ checkpoint: "after_250ms", activeView: await activeView(page) });
      await page.waitForTimeout(1_500);
      timings.push({ checkpoint: "after_1_5s_poll", activeView: await activeView(page) });
      await page.waitForTimeout(3_500);
      timings.push({ checkpoint: "after_5s_history_poll", activeView: await activeView(page) });
      await page.waitForTimeout(1_000);
      timings.push({ checkpoint: "after_6s", activeView: await activeView(page) });

      expect(timings[0].activeView).toBe("dashboard");
      expect(timings.slice(1).every((item) => item.activeView === "artifacts")).toBe(true);
      await assertSelectedView(page, "artifacts", "dashboard");
      await expect(page.getByRole("heading", { name: "Outputs and scan history" })).toBeVisible();
      await expect(page.locator(".current-artifacts-panel .run-directory")).toBeVisible();
      await expect(page.getByText("The scan has not completed; report.html has not been generated.")).toBeVisible();
      await expect(page.getByText("kln", { exact: true }).first()).toBeVisible();
      await expect(page.getByRole("button", { name: /Open Raw Log/i })).toBeEnabled();
      await expect(page.getByRole("button", { name: /Open stages_live\.json/i })).toBeEnabled();
      await expect(page.getByRole("button", { name: /Open State JSON/i })).toBeDisabled();
      await expect(page.getByRole("button", { name: /Open Report External/i })).toBeDisabled();

      await page.getByRole("button", { name: /^Refresh$/i }).click();
      await page.waitForTimeout(5_200);
      await assertSelectedView(page, "artifacts");
      await page.screenshot({ path: path.join(evidenceDir, "artifacts-open-incomplete-history.png"), fullPage: false });
      expect(harness.errors).toEqual([]);
      collectDiagnostic(testInfo, "incomplete-partial", harness.errors, harness.warnings);
    } finally {
      await harness.close();
    }
  });

  test("missing report opens a useful state and routes explicitly to Artifacts", async ({}, testInfo) => {
    const harness = await launchReconBot(testInfo, "incomplete-partial");
    try {
      const page = harness.page;
      await page.locator('.nav-rail button[data-view="report"]').click();
      await assertSelectedView(page, "report", "dashboard");
      await expect(page.getByRole("heading", { name: "No report.html exists for this run." })).toBeVisible();
      await expect(page.getByText("Run exists but report.html is missing", { exact: false })).toBeVisible();
      await expect(page.getByRole("button", { name: "Open Run Folder" })).toBeEnabled();
      await expect(page.getByRole("button", { name: "Open Log" })).toBeEnabled();
      await expect(page.getByRole("button", { name: "Open JSON" })).toBeDisabled();
      await expect(page.locator('.view-pane[data-view="dashboard"]')).toBeHidden();
      await page.screenshot({ path: path.join(evidenceDir, "report-missing-useful-state.png"), fullPage: false });

      await page.getByRole("button", { name: "Go to Artifacts" }).click();
      await assertSelectedView(page, "artifacts", "report");
      expect(harness.errors).toEqual([]);
      collectDiagnostic(testInfo, "incomplete-partial", harness.errors, harness.warnings);
    } finally {
      await harness.close();
    }
  });

  test("history row and Report action honor distinct explicit destinations", async ({}, testInfo) => {
    const harness = await launchReconBot(testInfo, "incomplete-partial");
    try {
      const page = harness.page;
      await page.locator('.nav-rail button[data-view="artifacts"]').click();
      const incompleteRow = page.locator(".history-row", { hasText: "incomplete-partial-run" });
      await incompleteRow.click();
      await assertSelectedView(page, "dashboard", "artifacts");

      await page.locator('.nav-rail button[data-view="artifacts"]').click();
      const completeRow = page.locator(".history-row", { hasText: "complete-a.example" });
      await completeRow.getByRole("button", { name: "Report", exact: true }).click();
      await assertSelectedView(page, "report", "artifacts");
      await expect(page.frameLocator('iframe[title="ReconBot report"]').getByRole("heading", { name: "Complete report fixture A" })).toBeVisible();
      await page.waitForTimeout(3_200);
      await assertSelectedView(page, "report");
      await page.locator('.nav-rail button[data-view="artifacts"]').click();
      const selectionsBefore = (await readFixture(harness.app)).calls.filter((call) => call.channel === "history:select-run").length;
      await completeRow.getByRole("button", { name: "Report", exact: true }).focus();
      await page.keyboard.press("Enter");
      await assertSelectedView(page, "report", "artifacts");
      expect((await readFixture(harness.app)).calls.filter((call) => call.channel === "history:select-run")).toHaveLength(selectionsBefore + 1);
      expect(harness.errors).toEqual([]);
      collectDiagnostic(testInfo, "history destinations", harness.errors, harness.warnings);
    } finally {
      await harness.close();
    }
  });

  test("ArtifactPane degrades per file for no-run, log-only, and report-failed states", async ({}, testInfo) => {
    for (const scenario of ["idle", "log-only", "report-failed"] as E2EScenario[]) {
      const harness = await launchReconBot(testInfo, scenario);
      try {
        const page = harness.page;
        await page.locator('.nav-rail button[data-view="artifacts"]').click();
        await assertSelectedView(page, "artifacts", "dashboard");
        if (scenario === "idle") {
          await expect(page.getByText("No run has been selected. Select a previous run or start a new scan.", { exact: false })).toBeVisible();
          await expect(page.locator(".artifact-card:not(:disabled)")).toHaveCount(0);
        }
        if (scenario === "log-only") {
          await expect(page.getByText("https://log-only.example", { exact: false }).first()).toBeVisible();
          await expect(page.getByRole("button", { name: /Open Raw Log/i })).toBeEnabled();
          await expect(page.getByRole("button", { name: /Open State JSON/i })).toBeDisabled();
          await expect(page.getByRole("button", { name: /Open stages_live\.json/i })).toBeDisabled();
          await expect(page.getByRole("button", { name: /Open Report External/i })).toBeDisabled();
        }
        if (scenario === "report-failed") {
          await expect(page.getByText("Report generation failed. Available logs and state files can still be inspected.", { exact: false })).toBeVisible();
          await page.locator('.nav-rail button[data-view="report"]').click();
          await expect(page.locator('.view-pane[data-view="report"] .report-status')).toContainText("Report generation failed");
          await expect(page.getByRole("heading", { name: "No report.html exists for this run." })).toBeVisible();
        }
        expect(harness.errors).toEqual([]);
        collectDiagnostic(testInfo, scenario, harness.errors, harness.warnings);
      } finally {
        await harness.close();
      }
    }
  });

  test("complete filesystem report loads through reconbot-report and remains loadable", async ({}, testInfo) => {
    const harness = await launchReconBot(testInfo, "complete-report");
    try {
      const page = harness.page;
      await page.locator('.nav-rail button[data-view="report"]').click();
      await assertSelectedView(page, "report", "dashboard");
      const frame = page.locator('iframe[title="ReconBot report"]');
      await expect(frame).toHaveAttribute("src", /^reconbot-report:\/\/run\/report\.html\?/);
      await expect(page.frameLocator('iframe[title="ReconBot report"]').getByRole("heading", { name: "Complete report fixture A" })).toBeVisible();
      await page.screenshot({ path: path.join(evidenceDir, "complete-report-loaded.png"), fullPage: false });

      await page.locator('.nav-rail button[data-view="artifacts"]').click();
      await assertSelectedView(page, "artifacts", "report");
      await page.locator('.nav-rail button[data-view="report"]').click();
      await expect(frame).toBeVisible();
      await expect(page.frameLocator('iframe[title="ReconBot report"]').getByRole("heading", { name: "Complete report fixture A" })).toBeVisible();
      expect(harness.errors).toEqual([]);
      collectDiagnostic(testInfo, "complete-report", harness.errors, harness.warnings);
    } finally {
      await harness.close();
    }
  });

  test("run switching clears stale report A and loads report C", async ({}, testInfo) => {
    const harness = await launchReconBot(testInfo, "complete-report");
    try {
      const page = harness.page;
      await page.locator('.nav-rail button[data-view="report"]').click();
      await expect(page.frameLocator('iframe[title="ReconBot report"]').getByRole("heading", { name: "Complete report fixture A" })).toBeVisible();

      await setRunScenario(harness.app, "incomplete-partial");
      await expect(page.getByRole("heading", { name: "No report.html exists for this run." })).toBeVisible({ timeout: 5_000 });
      await expect(page.locator('iframe[title="ReconBot report"]')).toHaveCount(0);
      expect(page.frames().some((item) => item.url().startsWith("reconbot-report://") && item.url().includes("complete-report-run"))).toBe(false);

      await setRunScenario(harness.app, "complete-report-c");
      await expect(page.locator('iframe[title="ReconBot report"]')).toBeVisible({ timeout: 5_000 });
      const reportFrame = page.frameLocator('iframe[title="ReconBot report"]');
      await expect(reportFrame.getByRole("heading", { name: "Complete report fixture C" })).toBeVisible();
      await expect(reportFrame.getByRole("heading", { name: "Complete report fixture A" })).toHaveCount(0);
      await page.screenshot({ path: path.join(evidenceDir, "run-switch-no-stale-report.png"), fullPage: false });
      expect(harness.errors).toEqual([]);
      collectDiagnostic(testInfo, "complete-report -> incomplete-partial -> complete-report-c", harness.errors, harness.warnings);
    } finally {
      await harness.close();
    }
  });
});

test("English default and persistent Turkish selection preserve report document and AI draft", async ({}, testInfo) => {
  const userDataDir = fs.mkdtempSync(path.resolve(__dirname, "../test-results/locale-user-data-"));
  const first = await launchReconBot(testInfo, "complete-report", { userDataDir });
  try {
    const page = first.page;
    await expect(page.locator("html")).toHaveAttribute("lang", "en");
    await expect(page.locator('.nav-rail [data-view="settings"] strong')).toHaveText("Settings");
    await page.locator('.nav-rail [data-view="report"]').click();
    const frame = page.frames().find((item) => item.url().startsWith("reconbot-report://"));
    await expect(page.frameLocator('iframe').getByRole("heading", { name: "Complete report fixture A" })).toBeVisible();
    const loadedFrame = frame || page.frames().find((item) => item.url().startsWith("reconbot-report://"))!;
    await loadedFrame.evaluate(() => { document.body.style.minHeight = "3000px"; document.body.dataset.localeProbe = "same-document"; window.scrollTo(0, 600); });
    await expect.poll(() => loadedFrame.evaluate(() => window.scrollY)).toBe(600);
    await expect(page.locator(".ai-hub .primary-ai-action")).toContainText(/Open chat|Explain report/);
    await page.locator(".ai-hub .primary-ai-action").click();
    await page.locator(".ai-input-row textarea").fill("Türkçe taslağım: token=exact-value");
    await page.getByRole("combobox", { name: "Interface language" }).selectOption("tr");
    await expect(page.locator("html")).toHaveAttribute("lang", "tr");
    await expect(page.locator('.nav-rail [data-view="settings"] strong')).toHaveText("Ayarlar");
    await expect(page.locator(".ai-input-row textarea")).toHaveValue("Türkçe taslağım: token=exact-value");
    expect(await loadedFrame.evaluate(() => document.body.dataset.localeProbe)).toBe("same-document");
    expect(await loadedFrame.evaluate(() => window.scrollY)).toBe(600);
    expect(first.errors).toEqual([]);
  } finally { await first.close(); }
  const second = await launchReconBot(testInfo, "complete-report", { userDataDir });
  try {
    await expect(second.page.locator("html")).toHaveAttribute("lang", "tr");
    await expect(second.page.locator('.nav-rail [data-view="settings"] strong')).toHaveText("Ayarlar");
    await second.page.getByRole("combobox", { name: "Arayüz dili" }).selectOption("en");
    await expect(second.page.locator('.nav-rail [data-view="settings"] strong')).toHaveText("Settings");
    expect(second.errors).toEqual([]);
  } finally { await second.close(); }
});

test("finding filters constrain real evidence, copy exact locations and reset when switching runs", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo, "historical");
  try {
    const page = harness.page;
    await page.locator('.nav-rail [data-view="findings"]').click();
    const rows = page.locator(".finding-result");
    const total = await rows.count();
    expect(total).toBeGreaterThan(3);
    await page.getByRole("combobox", { name: "Severity filter" }).selectOption("critical");
    await expect(rows).toHaveCount(2);
    await page.getByRole("combobox", { name: "Source", exact: true }).selectOption("nuclei");
    await page.getByRole("textbox", { name: "Search findings…" }).fill("/admin");
    await expect(rows).toHaveCount(1);
    await rows.first().click();
    await expect(page.locator(".finding-inspector h2")).toHaveText("E2E exposed admin surface");
    await page.getByRole("button", { name: "Copy location", exact: true }).click();
    await expect(page.locator(".copy-feedback")).toHaveText("Copied");
    expect((await readFixture(harness.app)).calls).toContainEqual({ channel: "clipboard:copy", payload: "http://localhost:8082/admin" });
    await page.getByRole("textbox", { name: "Search findings…" }).fill("no-match-ever");
    await expect(rows).toHaveCount(0);
    await expect(page.locator(".finding-inspector h2")).toHaveCount(0);
    await page.getByRole("button", { name: "Clear filters", exact: true }).click();
    await expect(rows).toHaveCount(total);
    await rows.first().click();
    await setRunScenario(harness.app, "complete-report-c");
    await expect(page.getByRole("textbox", { name: "Search findings…" })).toHaveValue("");
    await expect(page.locator(".finding-inspector h2")).toHaveCount(0);
    await expect(rows.filter({ hasText: "E2E exposed admin surface" })).toHaveCount(0);
    expect(harness.errors).toEqual([]);
  } finally { await harness.close(); }
});

test("Copilot resize uses keyboard and pointer bounds, and narrow layout restores the workspace", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo, "historical");
  try {
    const page = harness.page;
    await setWindowSize(harness.app, 1920, 1080);
    await expect(page.locator(".ai-hub .primary-ai-action")).toContainText(/Open chat|Explain report/);
    await page.locator(".ai-hub .primary-ai-action").click();
    const resizer = page.getByRole("separator", { name: "Resize Copilot" });
    await resizer.focus(); await page.keyboard.press("End");
    await expect(resizer).toHaveAttribute("aria-valuenow", "640");
    await page.keyboard.press("ArrowLeft");
    await expect(resizer).toHaveAttribute("aria-valuenow", "640");
    await page.keyboard.press("Home");
    await expect(resizer).toHaveAttribute("aria-valuenow", "360");
    const box = (await resizer.boundingBox())!;
    await page.mouse.move(box.x + box.width / 2, box.y + 150); await page.mouse.down();
    await page.mouse.move(1920 - 510, box.y + 150); await page.mouse.up();
    await expect(resizer).toHaveAttribute("aria-valuenow", "510");
    const workspace = (await page.locator(".workspace").boundingBox())!, drawer = (await page.locator(".ai-drawer").boundingBox())!;
    expect(workspace.x + workspace.width).toBeLessThanOrEqual(drawer.x + 1);
    await page.locator(".ai-input-row textarea").fill("draft survives narrow layout");
    await setWindowSize(harness.app, 1280, 800);
    await expect(page.locator(".workspace")).toBeHidden();
    await expect(page.locator(".ai-input-row textarea")).toHaveValue("draft survives narrow layout");
    await page.locator(".ai-drawer").getByTitle("Close", { exact: true }).click();
    await expect(page.locator(".workspace")).toBeVisible();
    await expect(page.locator(".ai-hub .primary-ai-action")).toContainText(/Open chat|Explain report/);
    await page.locator(".ai-hub .primary-ai-action").click();
    await expect(page.locator(".ai-input-row textarea")).toHaveValue("draft survives narrow layout");
    expect(harness.errors).toEqual([]);
  } finally { await harness.close(); }
});

test("finding pagination exposes additional matches and filtering resets the page size", async ({}, testInfo) => {
  const jsonlPath = path.join(fixtureRunsDir, "complete-report-run/nuclei_output.jsonl");
  const original = fs.existsSync(jsonlPath) ? fs.readFileSync(jsonlPath) : null;
  fs.writeFileSync(jsonlPath, Array.from({ length: 65 }, (_, index) => JSON.stringify({
    "template-id": `pagination-${index}`, "matched-at": `https://complete-a.example/evidence/${index}`,
    info: { name: `Pagination evidence ${index}`, severity: "high", tags: ["pagination"] },
  })).join("\n") + "\n");
  let harness: Awaited<ReturnType<typeof launchReconBot>> | undefined;
  try {
    harness = await launchReconBot(testInfo, "complete-report");
    const page = harness.page;
    await page.locator('.nav-rail [data-view="findings"]').click();
    await page.getByRole("combobox", { name: "Source", exact: true }).selectOption("nuclei");
    await expect(page.locator(".finding-result")).toHaveCount(50);
    await page.getByRole("button", { name: "Show more findings", exact: true }).click();
    await expect(page.locator(".finding-result")).toHaveCount(65);
    await expect(page.getByRole("button", { name: "Show more findings", exact: true })).toHaveCount(0);
    await page.getByRole("textbox", { name: "Search findings…" }).fill("pagination");
    await expect(page.locator(".finding-result")).toHaveCount(50);
    expect(harness.errors).toEqual([]);
  } finally {
    if (original) fs.writeFileSync(jsonlPath, original); else fs.unlinkSync(jsonlPath);
    await harness?.close();
  }
});
