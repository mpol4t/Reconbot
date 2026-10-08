import uiMessages from "../src/renderer/lib/messages.json";
import { expect, test, type Locator, type Page } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import type { AIRequest } from "../src/shared/api";
import { launchReconBot, loadHistoricalRun, readFixture, setWindowSize } from "./harness";

interface LayoutSnapshot {
  page: Record<string, number>;
  scroll: Record<string, number>;
  scrollTop: number;
  scrollHeight: number;
  clientHeight: number;
  pageStyle: Record<string, string>;
  scrollStyle: Record<string, string>;
  activeVisible: boolean;
  mountToken: string;
}

async function layoutSnapshot(page: Page, initializeMountToken = false): Promise<LayoutSnapshot> {
  return page.locator(".settings-page").evaluate((root, initialize) => {
    const settings = root as HTMLElement;
    if (initialize && !settings.dataset.e2eMountToken) settings.dataset.e2eMountToken = `mount-${Date.now()}`;
    const scroll = settings.querySelector<HTMLElement>(".settings-scroll");
    const active = settings.closest<HTMLElement>(".view-pane");
    if (!scroll || !active) throw new Error("Settings layout nodes missing");
    const rect = settings.getBoundingClientRect();
    const scrollRect = scroll.getBoundingClientRect();
    const pageStyle = getComputedStyle(settings);
    const scrollStyle = getComputedStyle(scroll);
    return {
      page: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
      scroll: { x: scrollRect.x, y: scrollRect.y, width: scrollRect.width, height: scrollRect.height },
      scrollTop: scroll.scrollTop,
      scrollHeight: scroll.scrollHeight,
      clientHeight: scroll.clientHeight,
      pageStyle: {
        overflow: pageStyle.overflow,
        minHeight: pageStyle.minHeight,
        position: pageStyle.position,
        display: pageStyle.display,
        visibility: pageStyle.visibility,
        opacity: pageStyle.opacity
      },
      scrollStyle: {
        overflow: scrollStyle.overflow,
        minHeight: scrollStyle.minHeight,
        position: scrollStyle.position,
        display: scrollStyle.display,
        visibility: scrollStyle.visibility,
        opacity: scrollStyle.opacity
      },
      activeVisible: getComputedStyle(active).visibility === "visible" && active.getBoundingClientRect().height > 0,
      mountToken: settings.dataset.e2eMountToken || ""
    };
  }, initializeMountToken);
}

async function formSnapshot(root: Locator): Promise<Array<Record<string, string | boolean>>> {
  return root.locator("input, select, textarea").evaluateAll((controls) => controls.map((node, index) => {
    const control = node as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
    const label = control.closest("label")?.querySelector("span")?.textContent?.trim() || "";
    return {
      index: String(index),
      tag: control.tagName,
      type: control instanceof HTMLInputElement ? control.type : "",
      label,
      value: control.value,
      checked: control instanceof HTMLInputElement ? control.checked : false,
      disabled: control.disabled
    };
  }));
}

async function assertStableLayout(page: Page, baseline: LayoutSnapshot): Promise<void> {
  const current = await layoutSnapshot(page);
  expect(Math.abs(await page.evaluate(() => window.scrollY))).toBeLessThan(1);
  expect(current.mountToken).toBe(baseline.mountToken);
  expect(current.activeVisible).toBe(true);
  expect(current.page.width).toBeGreaterThan(500);
  expect(current.page.height).toBeGreaterThan(400);
  expect(current.scroll.width).toBeGreaterThan(450);
  expect(current.scroll.height).toBeGreaterThan(300);
  expect(current.scrollHeight).toBeGreaterThanOrEqual(current.clientHeight);
  expect(Math.abs(current.page.height - baseline.page.height)).toBeLessThan(3);
  expect(current.pageStyle.overflow).not.toBe("visible");
  expect(current.scrollStyle.overflow).toMatch(/auto|scroll/);
  await expect(page.locator(".settings-sticky-bar")).toBeVisible();
  await expect(page.locator(".view-pane.active .settings-page")).toHaveCount(1);
}

async function activateToggle(toggle: Locator): Promise<void> {
  const coverage = await toggle.evaluate((node) => {
    const rect = node.getBoundingClientRect();
    const y = rect.top + rect.height / 2;
    return {
      center: Boolean(document.elementFromPoint(rect.left + rect.width / 2, y)?.closest(".ai-drawer")),
      left: Boolean(document.elementFromPoint(rect.left + Math.min(14, rect.width / 4), y)?.closest(".ai-drawer"))
    };
  });
  if (coverage.left) await toggle.evaluate((node) => {
    node.querySelector<HTMLInputElement>('input[type="checkbox"]')?.focus({ preventScroll: true });
    (node as HTMLElement).click();
  });
  else if (coverage.center) await toggle.click({ position: { x: 14, y: Math.max(4, (await toggle.boundingBox())?.height || 8) / 2 } });
  else await toggle.click();
}

async function prepareToggleForInteraction(toggle: Locator): Promise<void> {
  await toggle.evaluate((node) => node.scrollIntoView({ block: "center", inline: "nearest" }));
  await waitForRendererPaint(toggle.page());
  const covered = await toggle.evaluate((node) => {
    const rect = node.getBoundingClientRect();
    const y = Math.min(window.innerHeight - 1, Math.max(0, rect.top + rect.height / 2));
    return Boolean(document.elementFromPoint(rect.left + Math.min(14, rect.width / 4), y)?.closest(".ai-drawer"));
  });
  if (!covered) await toggle.click({ trial: true, position: { x: 14, y: 12 } });
  await waitForRendererPaint(toggle.page());
}

async function waitForRendererPaint(page: Page): Promise<void> {
  await page.evaluate(() => new Promise<void>((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  }));
}

function aiSettingsSection(page: Page): Locator {
  return page.locator(".settings-section").filter({ has: page.getByRole("heading", { name: "Operator Copilot" }) }).first();
}

function aiControl(section: Locator, label: string): Locator {
  return section.locator("label").filter({ has: section.page().getByText(uiMessages.find((entry) => entry.includes(label))?.[0] || label, { exact: true }) }).first().locator("input, select").first();
}

async function setAiValue(section: Locator, label: string, value: string): Promise<void> {
  const control = aiControl(section, label);
  await control.scrollIntoViewIfNeeded();
  if (await control.evaluate((node) => node instanceof HTMLSelectElement)) await control.selectOption(value);
  else {
    await control.fill(value);
    await control.blur();
  }
}

async function setAiToggle(section: Locator, label: string, checked: boolean): Promise<void> {
  const control = aiControl(section, label);
  if (await control.isChecked() === checked) return;
  await activateToggle(control.locator("xpath=ancestor::label[contains(@class, 'setting-toggle')][1]"));
  await expect(control).toBeChecked({ checked });
}

async function openCopilotAndSend(page: Page, message: string): Promise<void> {
  const action = page.locator(".ai-hub .primary-ai-action");
  await expect(action).toBeEnabled();
  await expect(action).toContainText(/Explain report|Open chat/);
  await waitForRendererPaint(page);
  await action.click();
  await expect(page.locator(".ai-drawer")).toBeVisible();
  const textarea = page.locator(".ai-input-row textarea");
  await expect(textarea).toBeVisible();
  await textarea.fill(message);
  await page.locator('.ai-input-row button[type="submit"]').click();
  await expect(page.locator(".ai-input-row .danger-button")).toHaveCount(0);
}

const variants = [
  { state: "no-target" as const, drawer: false, width: 1440, height: 900 },
  { state: "no-target" as const, drawer: true, width: 1440, height: 900 },
  { state: "no-target" as const, drawer: false, width: 1100, height: 780 },
  { state: "no-target" as const, drawer: true, width: 1100, height: 780 },
  { state: "historical" as const, drawer: false, width: 1440, height: 900 },
  { state: "historical" as const, drawer: true, width: 1440, height: 900 },
  { state: "historical" as const, drawer: false, width: 1100, height: 780 },
  { state: "historical" as const, drawer: true, width: 1100, height: 780 }
];



for (const variant of variants) {
  test(`Settings remains mounted: ${variant.state}, drawer=${variant.drawer}, ${variant.width}x${variant.height}`, async ({}, testInfo) => {
    const harness = await launchReconBot(testInfo);
    try {
      await setWindowSize(harness.app, variant.width, variant.height);
      if (variant.state === "historical") await loadHistoricalRun(harness.page);
      if (variant.drawer) {
        const aiButton = harness.page.locator(".ai-hub .primary-ai-action");
        await expect(aiButton).toContainText(/Explain report|Open chat/);
        await aiButton.click();
        await expect(harness.page.locator(".ai-drawer")).toBeVisible();
      }
      await harness.page.locator('.nav-rail [data-view="settings"]').click();
      const root = harness.page.locator(".settings-page");
      if (variant.drawer && variant.width <= 1280) {
        await expect(harness.page.locator(".ai-drawer")).toHaveCount(0);
      }
      await expect(root).toBeVisible();
      await expect(root.locator(".ai-settings-status")).toContainText("E2E fixture model ready.");
      const baseline = await layoutSnapshot(harness.page, true);
      const formBefore = await formSnapshot(root);
      const booleans = root.locator('input[type="checkbox"]:not(:disabled)');
      const booleanCount = await booleans.count();
      const toggleDiagnostics: Array<Record<string, unknown>> = [];
      expect(booleanCount).toBeGreaterThan(10);

      const beforeName = variant.state === "historical" && variant.drawer && variant.width === 1440
        ? "settings-before-historical-drawer.png"
        : "";
      if (beforeName) {
        await harness.page.screenshot({ path: path.resolve(__dirname, `../test-results/${beforeName}`), fullPage: false });
        await harness.page.screenshot({ path: path.resolve(__dirname, "../test-results/before-settings-toggle.png"), fullPage: false });
      }

      for (let index = 0; index < booleanCount; index += 1) {
        const control = booleans.nth(index);
        const toggle = control.locator("xpath=ancestor::label[contains(@class, 'setting-toggle')][1]");
        await prepareToggleForInteraction(toggle);
        const initial = await control.isChecked();
        const beforeToggleLayout = await layoutSnapshot(harness.page);
        const beforeToggleBox = await toggle.boundingBox();
        const beforeToggleForm = await formSnapshot(root);
        await activateToggle(toggle);
        await expect(control).toBeChecked({ checked: !initial });
        await waitForRendererPaint(harness.page);
        await assertStableLayout(harness.page, baseline);
        await expect.poll(async () => {
          const currentBox = await toggle.boundingBox();
          return Math.abs((currentBox?.y || 0) - (beforeToggleBox?.y || 0));
        }, { message: `${index}: toggle scroll restoration` }).toBeLessThan(64);
        const afterToggleLayout = await layoutSnapshot(harness.page);
        const afterToggleBox = await toggle.boundingBox();
        const toggleLabel = `${index}: ${(await toggle.textContent())?.replace(/\s+/g, " ").trim() || "toggle"}`;
        expect(beforeToggleBox, `${toggleLabel} before box`).not.toBeNull();
        expect(afterToggleBox, `${toggleLabel} after box`).not.toBeNull();
        expect(Math.abs((afterToggleBox?.y || 0) - (beforeToggleBox?.y || 0)), toggleLabel).toBeLessThan(64);
        if (beforeToggleLayout.scrollTop > 64) expect(afterToggleLayout.scrollTop, toggleLabel).toBeGreaterThan(32);
        toggleDiagnostics.push({ label: toggleLabel, initial, before: beforeToggleLayout, after: afterToggleLayout, beforeY: beforeToggleBox?.y, afterY: afterToggleBox?.y });
        const afterToggleForm = await formSnapshot(root);
        const changedValues = afterToggleForm.filter((item, itemIndex) => item.value !== beforeToggleForm[itemIndex]?.value || item.checked !== beforeToggleForm[itemIndex]?.checked);
        expect(changedValues).toHaveLength(1);
        expect(changedValues[0].type).toBe("checkbox");
        if (beforeName && index === 0) {
          await harness.page.screenshot({ path: path.resolve(__dirname, "../test-results/after-settings-toggle.png"), fullPage: false });
          await harness.page.screenshot({ path: path.resolve(__dirname, "../test-results/settings-toggle-fixed.png"), fullPage: false });
        }
        await activateToggle(toggle);
        await expect(control).toBeChecked({ checked: initial });
        await waitForRendererPaint(harness.page);
        await assertStableLayout(harness.page, baseline);
      }

      const selects = root.locator("select:not(:disabled)");
      for (let index = 0; index < await selects.count(); index += 1) {
        const select = selects.nth(index);
        const original = await select.inputValue();
        const values = await select.locator("option").evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value));
        const alternate = values.find((value) => value !== original);
        if (!alternate) continue;
        await select.scrollIntoViewIfNeeded();
        await select.selectOption(alternate);
        await assertStableLayout(harness.page, baseline);
        await select.selectOption(original);
      }

      const formAfter = await formSnapshot(root);
      expect(formAfter).toEqual(formBefore);
      const scroll = root.locator(".settings-scroll");
      await scroll.evaluate((node) => { node.scrollTop = node.scrollHeight; });
      await expect(root.locator(".settings-tool-card").last()).toBeVisible();
      await assertStableLayout(harness.page, baseline);

      if (beforeName) await harness.page.screenshot({ path: path.resolve(__dirname, "../test-results/settings-after-fixed.png"), fullPage: false });
      expect(harness.errors).toEqual([]);

      const measurementName = `settings-measurements-${variant.state}-${variant.drawer ? "drawer" : "closed"}-${variant.width}.json`;
      fs.writeFileSync(path.resolve(__dirname, `../test-results/${measurementName}`), JSON.stringify({ baseline, final: await layoutSnapshot(harness.page), booleanCount, toggles: toggleDiagnostics }, null, 2));
    } finally {
      await harness.close();
    }
  });
}

test("Settings editable fields round-trip and complete nested config reaches mocked scan IPC", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo);
  try {
    await harness.page.locator('.nav-rail [data-view="settings"]').click();
    const root = harness.page.locator(".settings-page");
    await expect(root.locator(".ai-settings-status")).toContainText("E2E fixture model ready.");
    const baseline = await layoutSnapshot(harness.page, true);
    const before = await formSnapshot(root);
    const endpointModelSelect = root.locator("label").filter({ has: harness.page.getByText("Endpoint models", { exact: true }) }).first().locator("select");
    const originalEndpointModel = await endpointModelSelect.inputValue();
    const editable = root.locator('input:not([type="checkbox"]):not([readonly]):not(:disabled)');
    for (let index = 0; index < await editable.count(); index += 1) {
      const input = editable.nth(index);
      const original = await input.inputValue();
      const type = await input.getAttribute("type");
      const label = (await input.locator("xpath=ancestor::label[1]").locator("span").first().textContent())?.trim() || "";
      let alternate: string;
      if (type === "number") {
        const min = Number(await input.getAttribute("min"));
        const max = Number(await input.getAttribute("max"));
        const value = Number(original || 0);
        const candidate = Number.isFinite(max) && value + 1 > max ? value - 1 : value + 1;
        alternate = String(Number.isFinite(min) ? Math.max(min, candidate) : candidate);
      } else if (/base url/i.test(label)) alternate = "http://127.0.0.1:1235/v1";
      else if (/model/i.test(label)) alternate = "e2e/mistral-instruct";
      else if (/env/i.test(label)) alternate = "RECONBOT_E2E_KEY";
      else if (/url|endpoint/i.test(label)) alternate = "https://example.com/reconbot-e2e.json";
      else if (/path|file/i.test(label)) alternate = "/tmp/reconbot-e2e.json";
      else alternate = original ? `${original}-e2e` : "reconbot-e2e";
      await input.scrollIntoViewIfNeeded();
      await input.fill(alternate);
      await input.blur();
      await assertStableLayout(harness.page, baseline);
      await input.fill(original);
      await input.blur();
    }
    // Manual model edits intentionally activate the manual fallback by clearing
    // the endpoint selection. Restore the coupled selection as part of this
    // full-form round trip instead of treating that functional behavior as drift.
    await endpointModelSelect.selectOption(originalEndpointModel);
    expect(await formSnapshot(root)).toEqual(before);

    const firstToggle = root.locator('input[type="checkbox"]:not(:disabled)').first();
    const firstToggleLabel = firstToggle.locator("xpath=ancestor::label[contains(@class, 'setting-toggle')][1]");
    const initial = await firstToggle.isChecked();
    await activateToggle(firstToggleLabel);
    await activateToggle(firstToggleLabel);
    await expect(firstToggle).toBeChecked({ checked: initial });

    await harness.page.getByRole("button", { name: /Configure/i }).click();
    await harness.page.locator(".target-field input").fill("http://127.0.0.1:8082");
    await harness.page.getByRole("button", { name: /Start Scan/i }).click();
    const fixture = await readFixture(harness.app);
    const scanCall = [...fixture.calls].reverse().find((call) => call.channel === "scan:start");
    expect(scanCall).toBeTruthy();
    const payload = scanCall?.payload as Record<string, unknown>;
    expect(payload.target).toBe("http://127.0.0.1:8082");
    expect(payload.tools).toBeTruthy();
    expect(payload.toolSettings).toBeTruthy();
    expect(payload.ai).toBeTruthy();
    expect((payload.toolSettings as Record<string, unknown>).osint).toBeTruthy();
    expect(harness.errors).toEqual([]);
  } finally {
    await harness.close();
  }
});

test("Thinking OFF reaches persistence, Python and provider as disabled with no reasoning fields", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo, "historical");
  try {
    await harness.page.locator('.nav-rail [data-view="settings"]').click();
    const section = aiSettingsSection(harness.page);
    const toggle = aiControl(section, "Thinking/Reasoning");
    await expect(toggle).not.toBeChecked();
    await openCopilotAndSend(harness.page, "Reasoning kapalı ayar izi.");
    const fixture = await readFixture(harness.app);
    const request = [...fixture.calls].reverse().find((call) => call.channel === "ai:request" && (call.payload as AIRequest | undefined)?.user_message === "Reasoning kapalı ayar izi.")?.payload as AIRequest;
    const pythonConfig = [...fixture.calls].reverse().find((call) => call.channel === "ai:python-config")?.payload as Record<string, unknown>;
    const plan = [...fixture.calls].reverse().find((call) => call.channel === "ai:plan")?.payload as Record<string, unknown>;
    const provider = [...fixture.calls].reverse().find((call) => call.channel === "ai:provider-payload")?.payload as Record<string, unknown>;
    expect(request.aiConfig?.disableReasoning).toBe(true);
    expect(pythonConfig.disableReasoning).toBe(true);
    expect(plan.disableReasoning).toBe(true);
    expect(plan.reasoningFieldsSent).toEqual([]);
    expect(plan.reasoningConfigurationReason).toBe("disabled_by_user");
    expect(provider.reasoningFields).toEqual([]);
    await harness.page.locator(".ai-technical-details summary").click();
    const details = harness.page.locator(".ai-technical-details");
    await expect(details).toContainText(/thinking_reasoning_configured: disabled/i);
    await expect(details).toContainText("reasoning_fields_sent: none");
    await expect(details).toContainText("reasoning_configuration_reason: disabled_by_user");
    expect(harness.errors).toEqual([]);
  } finally {
    await harness.close();
  }
});

test("every visible AI setting reaches persistence, IPC, Python plan and the next provider payload", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo, "historical");
  try {
    await harness.page.locator('.nav-rail [data-view="settings"]').click();
    const section = aiSettingsSection(harness.page);
    await expect(section).toBeVisible();

    await setAiToggle(section, "AI enabled", false);
    await expect(harness.page.locator(".ai-hub")).toContainText("AI disabled");
    await setAiToggle(section, "AI enabled", true);
    await setAiValue(section, "Base URL", "http://127.0.0.1:4321/v1");
    await setAiValue(section, "Endpoint modelleri", "qwen/qwen3-8b");
    await setAiValue(section, "API key env var", "RECONBOT_E2E_AI_KEY");
    await setAiValue(section, "Temperature", "0.73");
    await setAiValue(section, "Timeout", "300");
    await setAiValue(section, "Max context chars", "777");
    await setAiValue(section, "Response mode", "deep_analysis");
    await setAiToggle(section, "Thinking/Reasoning", true);
    await setAiValue(section, "Max output tokens", "24000");
    await setAiToggle(section, "Report-ready prompt", true);
    await setAiToggle(section, "Settings recommendations", false);
    await setAiToggle(section, "Approved settings changes", false);

    await expect.poll(async () => {
      const snapshot = await readFixture(harness.app);
      const call = [...snapshot.calls].reverse().find((item) => item.channel === "settings:save-ai");
      return (call?.payload as Record<string, unknown> | undefined)?.timeout;
    }).toBe(300);
    await expect(harness.page.locator(".ai-hub")).toContainText("Report ready \u00b7 Summarize with AI");
    await expect(section.locator(".setting-toggle").filter({ hasText: "Settings recommendations" })).toContainText("Settings suggestions disabled.");
    await expect(section.locator(".ai-settings-status")).toContainText("E2E fixture model ready.");

    const selectedQuestion = "Seçili model ayar izi.";
    await openCopilotAndSend(harness.page, selectedQuestion);
    let fixture = await readFixture(harness.app);
    const request = [...fixture.calls].reverse().find((call) => call.channel === "ai:request" && (call.payload as AIRequest | undefined)?.user_message === selectedQuestion)?.payload as AIRequest;
    const persisted = [...fixture.calls].reverse().find((call) => call.channel === "settings:save-ai")?.payload as Record<string, unknown>;
    const pythonConfig = [...fixture.calls].reverse().find((call) => call.channel === "ai:python-config")?.payload as Record<string, unknown>;
    const plan = [...fixture.calls].reverse().find((call) => call.channel === "ai:plan")?.payload as Record<string, unknown>;
    const provider = [...fixture.calls].reverse().find((call) => call.channel === "ai:provider-payload")?.payload as Record<string, unknown>;

    for (const stage of [persisted, request.aiConfig as unknown as Record<string, unknown>, pythonConfig]) {
      expect(stage.enabled).toBe(true);
      expect(stage.baseUrl).toBe("http://127.0.0.1:4321/v1");
      expect(stage.model).toBe("qwen/qwen3-8b");
      expect(stage.selectedModel).toBe("qwen/qwen3-8b");
      expect(stage.apiKeyEnv).toBe("RECONBOT_E2E_AI_KEY");
      expect(stage.temperature).toBe(0.73);
      expect(stage.timeout).toBe(300);
      expect(stage.maxContextChars).toBe(777);
      expect(stage.maxOutputTokens).toBe(24000);
      expect(stage.responseMode).toBe("deep_analysis");
      expect(stage.disableReasoning).toBe(false);
      expect(stage.autoBriefOnReportReady).toBe(true);
      expect(stage.allowSettingsRecommendations).toBe(false);
      expect(stage.allowApprovedSettingsChanges).toBe(false);
    }
    expect(plan.configuredTimeoutSec).toBe(300);
    expect(plan.effectiveRequestTimeoutSec).toBe(300);
    expect(plan.totalProcessWatchdogSec).toBe(1565);
    expect(plan.configuredMaxOutputTokens).toBe(24000);
    expect(Number(plan.effectiveMaxOutputTokens)).toBeLessThan(24000);
    expect(plan.outputLimitReason).toBe("loaded_context_window_and_request_input");
    expect(plan.configuredMaxContextChars).toBe(777);
    expect(plan.effectiveInjectedContextChars).toBe(777);
    expect(plan.loadedContextLength).toBe(8192);
    expect(Number(plan.estimatedInputTokens) + Number(plan.effectiveMaxOutputTokens) + Number(plan.reservedSafetyMarginTokens)).toBeLessThanOrEqual(8192);
    expect(plan.reasoningFieldsSent).toEqual(["reasoning_effort"]);
    expect(plan.reasoningConfigurationReason).toBe("supported_fields_sent");
    expect(provider.baseUrl).toBe("http://127.0.0.1:4321/v1");
    expect(provider.model).toBe("qwen/qwen3-8b");
    expect(provider.temperature).toBe(0.73);
    expect(provider.configuredTimeoutSec).toBe(300);
    expect(provider.maxContextChars).toBe(777);
    expect(provider.max_tokens).toBe(plan.effectiveMaxOutputTokens);
    expect(provider.reasoningFields).toEqual(["reasoning_effort"]);

    await harness.page.locator(".ai-technical-details summary").click();
    const details = harness.page.locator(".ai-technical-details");
    await expect(details).toContainText("configured_timeout_sec: 300");
    await expect(details).toContainText("effective_attempt_timeout_sec: 300");
    await expect(details).toContainText("configured_max_output_tokens: 24000");
    await expect(details).toContainText(`effective_max_output_tokens: ${String(plan.effectiveMaxOutputTokens)}`);
    await expect(details).toContainText("loaded_context_length: 8192");
    await expect(details).toContainText("reasoning_fields_sent: reasoning_effort");
    await harness.page.screenshot({ path: path.resolve(__dirname, "../test-results/ai-settings-provider-trace.png") });

    await harness.page.locator('.nav-rail [data-view="settings"]').click();
    const manualSection = aiSettingsSection(harness.page);
    await setAiValue(manualSection, "Manual model name", "e2e/manual-instruct");
    await expect(manualSection.locator(".ai-settings-status")).toContainText("E2E fixture model ready.");
    const manualQuestion = "Elle girilen model ayar izi.";
    await openCopilotAndSend(harness.page, manualQuestion);
    fixture = await readFixture(harness.app);
    const manualRequest = [...fixture.calls].reverse().find((call) => call.channel === "ai:request" && (call.payload as AIRequest | undefined)?.user_message === manualQuestion)?.payload as AIRequest;
    const manualProvider = [...fixture.calls].reverse().find((call) => call.channel === "ai:provider-payload")?.payload as Record<string, unknown>;
    expect(manualRequest.aiConfig?.selectedModel).toBe("");
    expect(manualRequest.aiConfig?.manualModelName).toBe("e2e/manual-instruct");
    expect(manualRequest.aiConfig?.model).toBe("e2e/manual-instruct");
    expect(manualProvider.model).toBe("e2e/manual-instruct");
    expect(manualProvider.reasoningFields).toEqual([]);
    const statusRequests = fixture.calls.filter((call) => call.channel === "ai:request" && (call.payload as AIRequest | undefined)?.action === "status");
    expect(statusRequests.some((call) => (call.payload as AIRequest).aiConfig?.baseUrl === "http://127.0.0.1:4321/v1")).toBe(true);
    expect(statusRequests.some((call) => (call.payload as AIRequest).aiConfig?.model === "e2e/manual-instruct")).toBe(true);
    expect(harness.errors).toEqual([]);
  } finally {
    await harness.close();
  }
});

test("saved AI settings survive Electron restart and drive the next request", async ({}, testInfo) => {
  const userDataDir = fs.mkdtempSync(path.join(path.resolve(__dirname, "../test-results"), "ai-persistence-"));
  const first = await launchReconBot(testInfo, "historical", { userDataDir });
  await first.page.locator('.nav-rail [data-view="settings"]').click();
  const firstSection = aiSettingsSection(first.page);
  await setAiValue(firstSection, "Temperature", "0.61");
  await setAiValue(firstSection, "Timeout", "300");
  await setAiValue(firstSection, "Max context chars", "4321");
  await setAiValue(firstSection, "Max output tokens", "24000");
  await setAiValue(firstSection, "Response mode", "fast_operator");
  await expect.poll(async () => {
    const snapshot = await readFixture(first.app);
    const saved = [...snapshot.calls].reverse().find((call) => call.channel === "settings:save-ai")?.payload as Record<string, unknown> | undefined;
    return saved?.maxContextChars;
  }).toBe(4321);
  await first.close();

  const second = await launchReconBot(testInfo, "historical", { userDataDir });
  try {
    await second.page.locator('.nav-rail [data-view="settings"]').click();
    const section = aiSettingsSection(second.page);
    await expect(aiControl(section, "Temperature")).toHaveValue("0.61");
    await expect(aiControl(section, "Timeout")).toHaveValue("300");
    await expect(aiControl(section, "Max context chars")).toHaveValue("4321");
    await expect(aiControl(section, "Max output tokens")).toHaveValue("24000");
    await expect(aiControl(section, "Response mode")).toHaveValue("fast_operator");
    await openCopilotAndSend(second.page, "Restart sonrası ayar izi.");
    const fixture = await readFixture(second.app);
    const request = [...fixture.calls].reverse().find((call) => call.channel === "ai:request" && (call.payload as AIRequest | undefined)?.user_message === "Restart sonrası ayar izi.")?.payload as AIRequest;
    expect(request.aiConfig?.temperature).toBe(0.61);
    expect(request.aiConfig?.timeout).toBe(300);
    expect(request.aiConfig?.maxContextChars).toBe(4321);
    expect(request.aiConfig?.maxOutputTokens).toBe(24000);
    expect(request.aiConfig?.responseMode).toBe("fast_operator");
    expect(second.errors).toEqual([]);
  } finally {
    await second.close();
  }
});
