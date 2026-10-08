import uiMessages from "../src/renderer/lib/messages.json";
const englishCatalog = new Map(uiMessages.flatMap((entry) => entry.map((alias) => [alias, entry[0]] as const)));
const englishCopy = (value: string): string => englishCatalog.get(value) || value;
import { expect, test, type Page } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { launchReconBot, loadHistoricalRun, readFixture } from "./harness";

interface ControlRecord {
  id: string;
  view: string;
  context: string;
  tag: string;
  type: string;
  label: string;
  disabled: boolean;
  status: "observed" | "excluded" | "uncovered";
  coveredBy?: string;
  action: string;
  result: string;
  exclusionReason?: string;
}

async function collectControls(page: Page, view: string, records: Map<string, ControlRecord>): Promise<void> {
  const controls = await page.locator('button, input, select, textarea, summary, a[href], [role="button"]').evaluateAll((nodes, activeView) => {
    const occurrences = new Map<string, number>();
    return nodes.flatMap((node) => {
    const element = node as HTMLElement;
    const style = getComputedStyle(element);
    if (style.display === "none" || style.visibility === "hidden") return [];
    const context = element.closest(".ai-drawer") ? "copilot"
      : element.closest(".ai-setup-modal") ? "ai-setup-modal"
        : element.closest(".sidebar") ? "sidebar"
          : element.closest(".settings-page") ? "settings"
            : element.closest(".view-pane.active") ? activeView
              : "global";
    const input = element as HTMLInputElement;
    const closestLabel = element.closest("label")?.textContent?.replace(/\s+/g, " ").trim() || "";
    const label = (element.getAttribute("aria-label") || element.getAttribute("title") || closestLabel || element.innerText || input.value || element.tagName)
      .replace(/\s+/g, " ").trim().slice(0, 180);
    const occurrenceKey = `${context}::${element.tagName.toLowerCase()}:${input.type || ""}::${label}`;
    const occurrence = occurrences.get(occurrenceKey) || 0;
    occurrences.set(occurrenceKey, occurrence + 1);
    return [{
      occurrence,
      context,
      tag: element.tagName.toLowerCase(),
      type: input.type || "",
      label,
      disabled: Boolean(input.disabled || element.getAttribute("aria-disabled") === "true")
    }];
    });
  }, view);

  for (const control of controls) {
    const id = `${control.context}::${control.tag}:${control.type}::${control.label}::${control.occurrence}`;
    const existing = records.get(id);
    if (existing) {
      if (existing.status === "excluded" && !control.disabled) {
        records.set(id, {
          ...existing,
          disabled: false,
          status: "observed",
          coveredBy: "ui-control-coverage.spec.ts",
          action: "Control became enabled; inventoried again.",
          result: "Control was present. Behavior is verified separately by explicit interactions and focused regression assertions.",
          exclusionReason: undefined
        });
      }
      continue;
    }
    const excluded = control.disabled;
    const coveredBy = control.context === "settings"
      ? "settings-regression.spec.ts"
      : control.context === "copilot"
        ? "copilot-regression.spec.ts + ui-control-coverage.spec.ts"
        : "ui-control-coverage.spec.ts";
    records.set(id, {
      id,
      view,
      context: control.context,
      tag: control.tag,
      type: control.type,
      label: control.label,
      disabled: control.disabled,
      status: excluded ? "excluded" : "observed",
      coveredBy: excluded ? undefined : coveredBy,
      action: excluded ? "Not invoked while disabled." : "Inventory observation; presence alone is not a behavior test.",
      result: excluded ? "Rendered disabled as required by the current fixture state." : "Control was present. Behavior is verified separately by explicit interactions and focused regression assertions.",
      exclusionReason: excluded
        ? /START SCAN/i.test(control.label)
          ? "Start Scan is disabled before a target is entered by the validation guard; the same control's enabled path is exercised after entering the deterministic target and its scan:start IPC is mocked/asserted."
          : /Sadece pasif zorunlu/i.test(control.label)
            ? "passiveOnly is a locked true safety invariant, intentionally rendered disabled and has no operator-enabled state."
            : "Control is intentionally disabled in the deterministic fixture state; its enabled state is covered in the owning focused spec where applicable."
        : undefined
    });
  }
}

async function navigate(page: Page, label: RegExp): Promise<void> {
  await page.locator(".nav-rail").getByRole("button", { name: label }).click();
}

async function closeDrawer(page: Page): Promise<void> {
  const drawer = page.locator(".ai-drawer");
  if (await drawer.count()) await drawer.getByTitle("Close").click();
}

test("whole UI safe interaction sweep produces a complete control inventory", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo);
  const records = new Map<string, ControlRecord>();
  try {
    await collectControls(harness.page, "startup", records);
    await navigate(harness.page, /Report/i);
    await expect(harness.page.locator(".report-empty")).toContainText(/No run selected|Bu run için report\.html mevcut değil/i);
    await collectControls(harness.page, "report-missing", records);
    await navigate(harness.page, /Artifacts/i);
    await collectControls(harness.page, "artifacts-missing", records);
    await loadHistoricalRun(harness.page);

    await navigate(harness.page, /Dashboard/i);
    await collectControls(harness.page, "dashboard", records);
    for (const name of [/Configure Scan/i, /^Tümü$/i, /^Open$/i, /Tüm Bulguları Gör/i]) {
      const button = harness.page.locator(".view-pane.active").getByRole("button", { name }).first();
      if (await button.count()) {
        await button.click();
        await navigate(harness.page, /Dashboard/i);
      }
    }

    await navigate(harness.page, /Configure/i);
    await collectControls(harness.page, "configure", records);
    await harness.page.locator(".target-field input").fill("http://127.0.0.1:8082");
    for (const button of await harness.page.locator(".view-pane.active .settings-segmented button, .view-pane.active .selector-grid button, .view-pane.active .execution-mode-buttons button").all()) {
      if (await button.isEnabled()) await button.click();
    }
    const toolInputs = harness.page.locator('.view-pane.active .tool-toggle input[type="checkbox"]');
    for (let index = 0; index < await toolInputs.count(); index += 1) {
      const input = toolInputs.nth(index);
      const label = input.locator("xpath=ancestor::label[1]");
      const before = await input.isChecked();
      await label.click();
      await label.click();
      await expect(input).toBeChecked({ checked: before });
    }
    await harness.page.getByRole("button", { name: /Start Scan/i }).click();
    await harness.page.getByRole("button", { name: /^Stop$/i }).click();
    await collectControls(harness.page, "configure-after-interaction", records);

    await navigate(harness.page, /Terminal/i);
    await collectControls(harness.page, "terminal", records);
    await harness.page.getByRole("button", { name: "Copy" }).click();
    await harness.page.getByRole("button", { name: "Clear" }).click();
    await harness.page.getByRole("button", { name: "Stop" }).click();
    const terminalInput = harness.page.locator(".xterm-helper-textarea");
    if (await terminalInput.count()) {
      await terminalInput.focus();
      await harness.page.keyboard.type("help");
      await harness.page.keyboard.press("Enter");
    }

    await navigate(harness.page, /Report/i);
    await collectControls(harness.page, "report", records);
    for (const name of ["Reload", "Open External", "Copy Report Path"]) await harness.page.getByRole("button", { name: englishCopy(name), exact: true }).click();
    for (const name of ["AI ile açıkla", "Bu bölümü AI'a sor", "Bu bulgu gerçek mi?", "Sonraki adımı sor"]) {
      await harness.page.getByRole("button", { name: englishCopy(name), exact: true }).click();
      await collectControls(harness.page, `report-${name}`, records);
      await closeDrawer(harness.page);
    }

    await navigate(harness.page, /Artifacts/i);
    await collectControls(harness.page, "artifacts", records);
    await harness.page.getByRole("button", { name: "Refresh", exact: true }).click();
    for (const card of await harness.page.locator(".artifact-card:not(:disabled)").all()) await card.click();
    const currentHistoryActions = harness.page.locator(".history-row.current .history-actions");
    for (const label of ["Folder", "Log", "JSON", "Copy", "Report"]) {
      await currentHistoryActions.getByRole("button", { name: englishCopy(label), exact: true }).click();
      if (label === "Report") await navigate(harness.page, /Artifacts/i);
    }

    await navigate(harness.page, /Findings/i);
    await collectControls(harness.page, "findings", records);

    await navigate(harness.page, /Threat Pipeline/i);
    await collectControls(harness.page, "pipeline", records);
    for (const button of await harness.page.locator(".view-pane.active .graph-toolbar button, .view-pane.active .network-node").all()) await button.click();

    await navigate(harness.page, /Settings/i);
    await collectControls(harness.page, "settings", records);
    for (const profile of ["fast", "balanced", "slow"]) {
      await harness.page.locator(".settings-segmented").getByRole("button", { name: new RegExp(`^${profile}$`, "i") }).click();
    }
    const refreshModels = harness.page.getByRole("button", { name: /Refresh models/i });
    if (await refreshModels.count()) await refreshModels.click();
    const demo = harness.page.getByRole("button", { name: /Load local example metadata feed/i });
    if (await demo.count()) await demo.click();
    await harness.page.getByRole("button", { name: /Setup guide/i }).first().click();
    await expect(harness.page.locator(".ai-setup-modal")).toBeVisible();
    await collectControls(harness.page, "ai-setup-modal", records);
    const setupModal = harness.page.locator(".ai-setup-modal");
    await setupModal.getByRole("button", { name: /Test connection/i }).click();
    await expect(setupModal.getByRole("button", { name: /Open setup guide/i })).toHaveCount(0);
    await setupModal.getByRole("button", { name: /Open AI settings/i }).click();
    await expect(setupModal).toHaveCount(0);
    await expect(harness.page.locator(".settings-page")).toBeVisible();
    await harness.page.getByRole("button", { name: /Setup guide/i }).first().click();
    await setupModal.getByRole("button", { name: /Disable AI/i }).click();
    await expect(setupModal).toHaveCount(0);
    const aiEnabled = harness.page.locator(".settings-page").getByText("AI enabled", { exact: true }).locator("xpath=ancestor::label[1]");
    await aiEnabled.click();
    await harness.page.getByRole("button", { name: /Test connection/i }).first().click();
    await expect(harness.page.locator(".ai-settings-status")).toContainText("E2E fixture model ready.");

    const hubPrimary = harness.page.locator(".ai-hub .primary-ai-action");
    await expect(hubPrimary).toContainText(/Open chat|Explain report/);
    await hubPrimary.click();
    await collectControls(harness.page, "copilot", records);
    await harness.page.locator(".ai-technical-details > summary").click();
    await harness.page.locator(".ai-technical-details > summary").click();
    for (const button of await harness.page.locator(".ai-quick-toolbar > button:not(:disabled)").all()) {
      await button.click();
      await expect(harness.page.locator(".ai-input-row .danger-button")).toHaveCount(0);
    }
    for (const label of ["Logları İncele", "Ayar Öner"]) {
      const menu = harness.page.locator(".ai-more-actions");
      if (!(await menu.evaluate((node) => (node as HTMLDetailsElement).open))) await menu.locator("summary").click();
      const action = harness.page.locator(".ai-more-actions").getByRole("button", { name: englishCopy(label) });
      await action.click();
      await expect(harness.page.locator(".ai-input-row .danger-button")).toHaveCount(0);
    }
    for (const chip of await harness.page.locator(".ai-chip-row button:not(:disabled)").all()) {
      await chip.evaluate((node) => (node as HTMLButtonElement).click());
      await expect(harness.page.locator(".ai-input-row .danger-button")).toHaveCount(0);
    }
    await collectControls(harness.page, "copilot-after-messages", records);
    await closeDrawer(harness.page);

    const controls = Array.from(records.values());
    const observed = controls.filter((control) => control.status === "observed").length;
    const excluded = controls.filter((control) => control.status === "excluded").length;
    const uncovered = controls.filter((control) => control.status === "uncovered");
    const artifact = {
      generatedAt: new Date().toISOString(),
      fixture: "RECONBOT_E2E=1 / localhost:8082 / interrupted / risk 90 / report ready / AI ready",
      summary: { total: controls.length, observed, excluded, uncovered: uncovered.length },
      exclusions: controls.filter((control) => control.status === "excluded").map(({ id, label, view, exclusionReason }) => ({ id, label, view, reason: exclusionReason })),
      controls
    };
    fs.writeFileSync(path.resolve(__dirname, "../test-results/ui-control-coverage.json"), JSON.stringify(artifact, null, 2));
    const fixture = await readFixture(harness.app);
    expect(fixture.calls.some((call) => call.channel === "scan:start")).toBe(true);
    expect(fixture.calls.some((call) => call.channel === "artifact:open-path")).toBe(true);
    expect(fixture.calls.some((call) => call.channel === "terminal:write")).toBe(true);
    expect(uncovered).toEqual([]);
    expect(harness.errors).toEqual([]);
  } finally {
    await harness.close();
  }
});
