import { _electron as electron, expect, type ElectronApplication, type Page, type TestInfo } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import type { E2EScenario } from "../src/main/e2eFixture";

export interface Harness {
  app: ElectronApplication;
  page: Page;
  errors: string[];
  warnings: string[];
  close(): Promise<void>;
}

const testResultsDir = path.resolve(__dirname, "../test-results");

export async function launchReconBot(
  testInfo: TestInfo,
  scenario: E2EScenario = "idle",
  options: { userDataDir?: string; liveAi?: boolean; loopbackTarget?: string } = {},
): Promise<Harness> {
  fs.mkdirSync(testResultsDir, { recursive: true });
  const errors: string[] = [];
  const warnings: string[] = [];
  const userDataDir = options.userDataDir || fs.mkdtempSync(path.join(testResultsDir, "electron-user-data-"));
  const app = await electron.launch({
    args: [path.resolve(__dirname, "..")],
    cwd: path.resolve(__dirname, ".."),
    env: {
      ...process.env,
      RECONBOT_E2E: "1",
      RECONBOT_E2E_HIDDEN: "1",
      RECONBOT_E2E_SCENARIO: scenario,
      RECONBOT_REPO_ROOT: path.resolve(__dirname, "../.."),
      RECONBOT_E2E_USER_DATA_DIR: userDataDir,
      RECONBOT_E2E_LIVE_AI: options.liveAi ? "1" : "0",
      RECONBOT_E2E_LOOPBACK_TARGET: options.loopbackTarget || '',
      RECONBOT_PYTHON: path.resolve(__dirname, "../../.venv/bin/python")
    }
  });
  const page = await app.firstWindow();
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(`console: ${message.text()}`);
    if (message.type() === "warning") warnings.push(`console.warn: ${message.text()}`);
  });
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
  page.on("requestfailed", (request) => {
    if (!request.url().startsWith("reconbot-report:")) errors.push(`requestfailed: ${request.method()} ${request.url()} ${request.failure()?.errorText || ""}`);
  });
  await page.waitForLoadState("domcontentloaded");
  await expect(page.locator(".app-shell")).toBeVisible();

  return {
    app,
    page,
    errors,
    warnings,
    close: async () => {
      const safeName = testInfo.title.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").toLowerCase();
      const diagnostic = {
        test: testInfo.title,
        url: page.url(),
        activeView: await page.locator(".view-pane.active").getAttribute("class").catch(() => null),
        errors,
        warnings
      };
      fs.writeFileSync(path.join(testResultsDir, `console-errors-${safeName}.json`), JSON.stringify(diagnostic, null, 2));
      const aggregatePath = path.join(testResultsDir, "console-errors.json");
      let aggregate: unknown[] = [];
      try {
        const parsed = JSON.parse(fs.readFileSync(aggregatePath, "utf8"));
        if (Array.isArray(parsed)) aggregate = parsed;
      } catch {
        aggregate = [];
      }
      aggregate.push(diagnostic);
      fs.writeFileSync(aggregatePath, JSON.stringify(aggregate, null, 2));
      await app.close();
    }
  };
}

export async function setWindowSize(app: ElectronApplication, width: number, height: number): Promise<void> {
  await app.evaluate(({ BrowserWindow }, size) => {
    const win = BrowserWindow.getAllWindows()[0];
    win.setSize(size.width, size.height);
  }, { width, height });
}

export async function loadHistoricalRun(page: Page): Promise<void> {
  await page.getByRole("button", { name: /Artifacts/i }).click();
  const row = page.locator(".history-row").first();
  await expect(row).toBeVisible();
  await row.click();
  await expect(page.locator(".notice-action")).toContainText(/Rescan target|Hedefi yeniden tara/);
}

export async function readFixture(app: ElectronApplication): Promise<{ calls: Array<{ channel: string; payload?: unknown }>; scenario: string }> {
  return app.evaluate(() => {
    const fixture = (globalThis as typeof globalThis & { __reconbotE2E?: { snapshot(): { calls: Array<{ channel: string; payload?: unknown }>; scenario: string } } }).__reconbotE2E;
    if (!fixture) throw new Error("RECONBOT_E2E fixture is unavailable");
    return fixture.snapshot();
  });
}

export async function setRunScenario(app: ElectronApplication, scenario: E2EScenario): Promise<void> {
  await app.evaluate((_electron, nextScenario) => {
    const fixture = (globalThis as typeof globalThis & {
      __reconbotE2E?: { setRunScenario(scenario: E2EScenario): void };
    }).__reconbotE2E;
    if (!fixture) throw new Error("RECONBOT_E2E fixture is unavailable");
    fixture.setRunScenario(nextScenario);
  }, scenario);
}
