import { SqlmapValidation } from "./sqlmapValidation";
import { AuthenticationValidation } from './authenticationValidation';
import type { AuthenticationRequest } from '../shared/authentication';
import type { SqlmapRequest } from "../shared/sqlmap";
import { app, BrowserWindow, clipboard, dialog, ipcMain, nativeImage, net, protocol, shell } from "electron";
import { WordlistPreferenceStore } from './wordlistPreferences';
import type { WordlistSlot } from '../shared/wordlists';
import { execFileSync } from "node:child_process";
import { lookup as dnsLookup } from "node:dns/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { loadConfigDefaults } from "./configDefaults";
import { readRunStateSnapshot } from "./artifactWatcher";
import { runAiAssistant } from "./aiAssistant";
import { buildAiRunContextSnapshot } from "../shared/aiContextSnapshot";
import { normalizeAiConfig } from "../shared/aiSettingsContract";
import { ReconbotProcess } from "./reconbotProcess";
import { createE2EFixture, isE2EMode, sanitizeE2EScanConfig } from "./e2eFixture";
import type { E2EScenario } from "./e2eFixture";
import type { AIConfig, AIRequest, AIRequestProgress, ConfigDefaults, HostTelemetry, IpEnrichmentRequest, ResolvedIpInfo, ScanConfig, ScanHistoryItem } from "../shared/api";

function resolveRepoRoot(): string {
  if (process.env.RECONBOT_REPO_ROOT) {
    return path.resolve(process.env.RECONBOT_REPO_ROOT);
  }
  if (app.isPackaged) {
    const workspace = path.join(process.env.RECONBOT_E2E_USER_DATA_DIR || path.join(app.getPath("appData"), "reconbot-operator-console"), "workspace");
    fs.mkdirSync(workspace, { recursive: true });
    const config = path.join(workspace, "config.yaml");
    if (!fs.existsSync(config)) fs.copyFileSync(path.join(process.resourcesPath, "defaults", "config.yaml"), config);
    // Finder does not inherit the interactive shell's Homebrew PATH.
    process.env.PATH = [...new Set([process.env.PATH || "", path.join(os.homedir(), "go", "bin"), path.join(os.homedir(), ".local", "bin"), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"])].join(path.delimiter);
    return workspace;
  }
  const cwd = process.cwd();
  return path.basename(cwd) === "desktop" ? path.resolve(cwd, "..") : cwd;
}

function isWithin(parent: string, candidate: string): boolean {
  const relative = path.relative(parent, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function isSafeExternalUrl(rawUrl: string): boolean {
  try {
    const protocolName = new URL(rawUrl).protocol;
    return protocolName === "http:" || protocolName === "https:" || protocolName === "mailto:";
  } catch {
    return false;
  }
}

function isReportUrl(rawUrl: string): boolean {
  try {
    return new URL(rawUrl).protocol === "reconbot-report:";
  } catch {
    return false;
  }
}

function isInternalReportNavigation(rawUrl: string): boolean {
  if (rawUrl.startsWith("#")) {
    return true;
  }
  return isReportUrl(rawUrl);
}

function openSafeExternalUrl(rawUrl: string): void {
  if (!isSafeExternalUrl(rawUrl)) {
    console.warn(`[desktop] blocked unsafe external URL: ${rawUrl}`);
    return;
  }
  void shell.openExternal(rawUrl).catch((error) => {
    console.warn(`[desktop] failed to open external URL: ${error}`);
  });
}

const repoRoot = resolveRepoRoot();
// Keep the original application ID for saved settings when the display name changes.
const existingUserDataPath = path.join(app.getPath("appData"), "reconbot-operator-console");
app.setName("ReconBot");
app.setPath("userData", existingUserDataPath);
const appIconPath = path.join(app.getAppPath(), "resources", "reconbot-icon.png");
if (process.env.RECONBOT_E2E_USER_DATA_DIR) {
  app.setPath("userData", path.resolve(process.env.RECONBOT_E2E_USER_DATA_DIR));
}
let defaults: ConfigDefaults = loadConfigDefaults(repoRoot);
const reconbotProcess = new ReconbotProcess(repoRoot, defaults);
const sqlmapValidation = new SqlmapValidation(repoRoot);
const authenticationValidation = new AuthenticationValidation(repoRoot);
const e2eMode = isE2EMode();
const supportedE2EScenarios = new Set<E2EScenario>([
  "idle",
  "historical",
  "active-running",
  "complete-report",
  "complete-report-c",
  "incomplete-partial",
  "interrupted",
  "report-failed",
  "malformed-json",
  "log-only"
]);
const requestedE2EScenario = String(process.env.RECONBOT_E2E_SCENARIO || "idle") as E2EScenario;
const e2eLiveAi = process.env.RECONBOT_E2E_LIVE_AI === "1";
const e2eFixture = e2eMode
  ? createE2EFixture(supportedE2EScenarios.has(requestedE2EScenario) ? requestedE2EScenario : "idle")
  : null;
if (e2eFixture) {
  (globalThis as typeof globalThis & { __reconbotE2E?: typeof e2eFixture }).__reconbotE2E = e2eFixture;
}
let mainWindow: BrowserWindow | null = null;
let previousCpuSample: { idle: number; total: number } | null = null;
let previousNetworkSample: { rxBytes: number; txBytes: number; sampledAt: number } | null = null;
const ignoredNetworkInterfaces = /^(lo|utun|llw|awdl|bridge|gif|stf|anpi|ap)\d*/i;
const vmStatPageSizePattern = /page size of (\d+) bytes/i;
const AI_SETTINGS_FILE = "reconbot-ai-settings.json";

function aiSettingsPath(): string {
  return path.join(app.getPath("userData"), AI_SETTINGS_FILE);
}

function loadPersistedAiSettings(): AIConfig {
  const fallback = normalizeAiConfig(defaults.ai);
  try {
    const settingsPath = aiSettingsPath();
    if (!fs.existsSync(settingsPath)) return fallback;
    const parsed = JSON.parse(fs.readFileSync(settingsPath, "utf8")) as Partial<AIConfig>;
    return normalizeAiConfig(parsed);
  } catch (error) {
    console.warn(`[desktop] persisted AI settings could not be loaded: ${error instanceof Error ? error.message : String(error)}`);
    return fallback;
  }
}

function savePersistedAiSettings(input: AIConfig): { ok: true; config: AIConfig; path: string } | { ok: false; error: string } {
  try {
    const config = normalizeAiConfig(input);
    const settingsPath = aiSettingsPath();
    fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
    const temporaryPath = `${settingsPath}.tmp`;
    fs.writeFileSync(temporaryPath, JSON.stringify(config, null, 2), { encoding: "utf8", mode: 0o600 });
    fs.renameSync(temporaryPath, settingsPath);
    return { ok: true, config, path: settingsPath };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

protocol.registerSchemesAsPrivileged([
  {
    scheme: "reconbot-report",
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true
    }
  }
]);

function registerReportProtocol(): void {
  protocol.handle("reconbot-report", (request) => {
    const currentRunDir = e2eFixture?.currentRunDir() || reconbotProcess.getCurrentRunDir();
    if (!currentRunDir) {
      return new Response("No current run directory.", { status: 404 });
    }

    const url = new URL(request.url);
    const requestedPath = decodeURIComponent(url.pathname.replace(/^\/+/, "")) || "report.html";
    const resolved = path.resolve(currentRunDir, requestedPath);
    if (!isWithin(currentRunDir, resolved)) {
      return new Response("Report path is outside current run directory.", { status: 403 });
    }
    if (!fs.existsSync(resolved)) {
      return new Response("Report artifact not found.", { status: 404 });
    }
    if (path.basename(resolved) === "report.html") {
      const html = fs
        .readFileSync(resolved, "utf8")
        .replace(/<meta\s+http-equiv=["']refresh["'][^>]*>/gi, "")
        .replace(/(<meta\s+name=["']reconbot-auto-refresh["']\s+content=["'])true(["'][^>]*>)/i, "$1false$2");
      return new Response(html, {
        headers: {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store"
        }
      });
    }
    return net.fetch(pathToFileURL(resolved).toString());
  });
}

function safeArtifactRoot(): string {
  return path.resolve(reconbotProcess.getOutputBaseDir());
}

function isSafeArtifactPath(candidate: string): boolean {
  const resolved = path.resolve(candidate);
  const currentRunDir = reconbotProcess.getCurrentRunDir();
  return Boolean((currentRunDir && isWithin(currentRunDir, resolved)) || isWithin(safeArtifactRoot(), resolved));
}

function formatTurkishDate(date: Date): string {
  return new Intl.DateTimeFormat("tr-TR", { day: "numeric", month: "long" }).format(date);
}

function formatTime(date: Date): string {
  return new Intl.DateTimeFormat("tr-TR", { hour: "2-digit", minute: "2-digit" }).format(date);
}

function displayTarget(target: string): string {
  const fallback = target.trim() || "unknown target";
  try {
    const url = new URL(fallback);
    return url.port ? `${url.hostname}:${url.port}` : url.hostname;
  } catch {
    return fallback.replace(/^https?:\/\//i, "").replace(/\/.*$/, "") || fallback;
  }
}

function resolveHostname(rawTarget: string): string {
  const target = rawTarget.trim();
  if (!target) return "";
  try {
    return new URL(target).hostname;
  } catch {
    return target.replace(/\/.*$/, "");
  }
}

function isIpAddress(value: string): boolean {
  const text = value.trim();
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(text) || (text.includes(":") && /^[0-9a-f:]+$/i.test(text));
}

async function resolveTargetIp(rawTarget: string): Promise<ResolvedIpInfo> {
  const target = rawTarget.trim();
  const hostname = resolveHostname(target);
  if (!target || !hostname || isIpAddress(hostname)) {
    return { available: false, target, hostname, ip: "" };
  }
  try {
    const records = await dnsLookup(hostname, { all: true, verbatim: false });
    const record = records.find((item) => item.family === 4) ?? records[0];
    return record
      ? { available: true, target, hostname, ip: record.address }
      : { available: false, target, hostname, ip: "" };
  } catch (error) {
    return {
      available: false,
      target,
      hostname,
      ip: "",
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

function listScanHistory(): ScanHistoryItem[] {
  const runsRoot = path.join(safeArtifactRoot(), "runs");
  if (!fs.existsSync(runsRoot)) return [];
  return fs
    .readdirSync(runsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(runsRoot, entry.name))
    .filter((runDir) => isWithin(runsRoot, runDir))
    .map(runDir => {
      const report = path.join(runDir, "report.html"), state = path.join(runDir, "run_result.json");
      const source = fs.existsSync(report) ? report : fs.existsSync(state) ? state : runDir;
      try { return { runDir, mtime: fs.statSync(source).mtimeMs }; } catch { return { runDir, mtime: 0 }; }
    })
    .sort((a, b) => b.mtime - a.mtime).slice(0, 40).map(row => row.runDir)
    .map((runDir) => {
      const snapshot = readRunStateSnapshot(runDir, true, false);
      const reportPath = path.join(runDir, "report.html");
      const statePath = path.join(runDir, "run_result.json");
      const rawLog = path.join(runDir, "reconbot.log");
      const statTarget = fs.existsSync(reportPath) ? reportPath : fs.existsSync(statePath) ? statePath : runDir;
      const mtime = fs.statSync(statTarget).mtime;
      const target = snapshot.target || "unknown target";
      const dateLabel = formatTurkishDate(mtime);
      return {
        runDir,
        displayName: `${displayTarget(target)} — ${dateLabel}`,
        target,
        dateLabel,
        timeLabel: formatTime(mtime),
        risk: snapshot.risk,
        reportReady: snapshot.report.exists,
        runState: snapshot.runState,
        isHistorical: true,
        completeness: snapshot.completeness,
        processAttached: false,
        updatedAt: mtime.toISOString(),
        paths: {
          report: reportPath,
          rawLog,
          stateJson: statePath,
          stagesJson: snapshot.artifacts?.paths.stagesJson,
          configOrRequest: snapshot.artifacts?.paths.configOrRequest
        },
        exists: snapshot.artifacts?.exists
      };
    })
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
    .slice(0, 40);
}

function readCpuSample(): { idle: number; total: number } {
  return os.cpus().reduce(
    (sum, cpu) => {
      const total = Object.values(cpu.times).reduce((acc, value) => acc + value, 0);
      return {
        idle: sum.idle + cpu.times.idle,
        total: sum.total + total
      };
    },
    { idle: 0, total: 0 }
  );
}

function cpuUsagePercent(): number | null {
  const sample = readCpuSample();
  if (!previousCpuSample) {
    previousCpuSample = sample;
    return null;
  }
  const idleDelta = sample.idle - previousCpuSample.idle;
  const totalDelta = sample.total - previousCpuSample.total;
  previousCpuSample = sample;
  if (totalDelta <= 0 || idleDelta < 0) return null;
  return Math.max(0, Math.min(100, Math.round((1 - idleDelta / totalDelta) * 100)));
}

function diskUsagePercent(): number | null {
  try {
    const output = execFileSync("/bin/df", ["-k", "/"], { encoding: "utf8", timeout: 1000 });
    const line = output.trim().split(/\r?\n/)[1] || "";
    const columns = line.trim().split(/\s+/);
    const capacity = columns[4] || "";
    const parsed = Number.parseInt(capacity.replace("%", ""), 10);
    return Number.isFinite(parsed) ? Math.max(0, Math.min(100, parsed)) : null;
  } catch {
    return null;
  }
}

function readNetworkBytes(): { rxBytes: number; txBytes: number } | null {
  try {
    const output = execFileSync("/usr/sbin/netstat", ["-ibn"], { encoding: "utf8", timeout: 1000 });
    const interfaces = new Map<string, { rxBytes: number; txBytes: number }>();
    for (const line of output.split(/\r?\n/).slice(1)) {
      const columns = line.trim().split(/\s+/);
      if (columns.length < 10 || columns[0] === "Name") continue;
      const name = columns[0];
      if (ignoredNetworkInterfaces.test(name)) continue;
      const rxBytes = Number.parseInt(columns[6], 10);
      const txBytes = Number.parseInt(columns[9], 10);
      if (!Number.isFinite(rxBytes) || !Number.isFinite(txBytes)) continue;
      const current = interfaces.get(name);
      interfaces.set(name, {
        rxBytes: Math.max(current?.rxBytes ?? 0, rxBytes),
        txBytes: Math.max(current?.txBytes ?? 0, txBytes)
      });
    }
    const totals = Array.from(interfaces.values()).reduce(
      (sum, item) => ({
        rxBytes: sum.rxBytes + item.rxBytes,
        txBytes: sum.txBytes + item.txBytes
      }),
      { rxBytes: 0, txBytes: 0 }
    );
    return totals.rxBytes || totals.txBytes ? totals : null;
  } catch {
    return null;
  }
}

function networkThroughput(): { rxKBps: number | null; txKBps: number | null; label: string } {
  const current = readNetworkBytes();
  const now = Date.now();
  if (!current) {
    previousNetworkSample = null;
    return { rxKBps: null, txKBps: null, label: "n/a" };
  }
  if (!previousNetworkSample) {
    previousNetworkSample = { ...current, sampledAt: now };
    return { rxKBps: null, txKBps: null, label: "sampling" };
  }
  const elapsedSeconds = Math.max(0.001, (now - previousNetworkSample.sampledAt) / 1000);
  const rxDelta = current.rxBytes - previousNetworkSample.rxBytes;
  const txDelta = current.txBytes - previousNetworkSample.txBytes;
  previousNetworkSample = { ...current, sampledAt: now };
  if (elapsedSeconds < 0.25) return { rxKBps: null, txKBps: null, label: "sampling" };
  if (rxDelta < 0 || txDelta < 0) return { rxKBps: null, txKBps: null, label: "n/a" };
  const rxKBps = Math.round((rxDelta / 1024 / elapsedSeconds) * 10) / 10;
  const txKBps = Math.round((txDelta / 1024 / elapsedSeconds) * 10) / 10;
  return {
    rxKBps,
    txKBps,
    label: `rx ${rxKBps.toFixed(1)} KB/s · tx ${txKBps.toFixed(1)} KB/s`
  };
}

function parseVmStatPages(output: string): { pageSize: number; pages: Map<string, number> } | null {
  const pageSizeMatch = output.match(vmStatPageSizePattern);
  const pageSize = pageSizeMatch ? Number.parseInt(pageSizeMatch[1], 10) : 4096;
  if (!Number.isFinite(pageSize) || pageSize <= 0) return null;

  const pages = new Map<string, number>();
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/^Pages\s+([^:]+):\s+([\d.]+)/i);
    if (!match) continue;
    const key = match[1].trim().toLowerCase();
    const value = Number.parseInt(match[2].replace(/\./g, ""), 10);
    if (Number.isFinite(value)) pages.set(key, value);
  }
  return pages.size ? { pageSize, pages } : null;
}

function macMemorySnapshot(totalMemoryBytes: number): Pick<
  HostTelemetry,
  "ramUsedPercent" | "ramLabel" | "ramDetail" | "ramApproximate" | "freeMemoryBytes"
> | null {
  try {
    const output = execFileSync("/usr/bin/vm_stat", { encoding: "utf8", timeout: 1000 });
    const parsed = parseVmStatPages(output);
    if (!parsed || totalMemoryBytes <= 0) return null;

    const pageBytes = (name: string): number => (parsed.pages.get(name) ?? 0) * parsed.pageSize;
    const activeBytes = pageBytes("active");
    const wiredBytes = pageBytes("wired down");
    const compressedBytes = pageBytes("occupied by compressor");
    const freeBytes = pageBytes("free") + pageBytes("speculative");
    const pressureBytes = activeBytes + wiredBytes + compressedBytes;
    const ramUsedPercent = Math.max(0, Math.min(100, Math.round((pressureBytes / totalMemoryBytes) * 100)));

    return {
      ramUsedPercent,
      ramLabel: "Host memory approx",
      ramDetail: "active + wired + compressed",
      ramApproximate: true,
      freeMemoryBytes: freeBytes
    };
  } catch {
    return null;
  }
}

function fallbackMemorySnapshot(totalMemoryBytes: number): Pick<
  HostTelemetry,
  "ramUsedPercent" | "ramLabel" | "ramDetail" | "ramApproximate" | "freeMemoryBytes"
> {
  const freeMemoryBytes = os.freemem();
  if (process.platform === "darwin") {
    return {
      ramUsedPercent: null,
      ramLabel: "Host memory n/a",
      ramDetail: "vm_stat unavailable",
      ramApproximate: false,
      freeMemoryBytes
    };
  }
  const ramUsedPercent =
    totalMemoryBytes > 0
      ? Math.max(0, Math.min(100, Math.round(((totalMemoryBytes - freeMemoryBytes) / totalMemoryBytes) * 100)))
      : null;
  return {
    ramUsedPercent,
    ramLabel: "Host used approx",
    ramDetail: "total - free",
    ramApproximate: true,
    freeMemoryBytes
  };
}

function hostTelemetry(): HostTelemetry {
  const totalMemoryBytes = os.totalmem();
  const memory = process.platform === "darwin"
    ? macMemorySnapshot(totalMemoryBytes) ?? fallbackMemorySnapshot(totalMemoryBytes)
    : fallbackMemorySnapshot(totalMemoryBytes);
  const netSample = networkThroughput();
  return {
    uptimeSeconds: Math.round(os.uptime()),
    appUptimeSeconds: Math.round(process.uptime()),
    cpuLoadPercent: cpuUsagePercent(),
    ramUsedPercent: memory.ramUsedPercent,
    ramLabel: memory.ramLabel,
    ramDetail: memory.ramDetail,
    ramApproximate: memory.ramApproximate,
    diskUsedPercent: diskUsagePercent(),
    netRxKBps: netSample.rxKBps,
    netTxKBps: netSample.txKBps,
    freeMemoryBytes: memory.freeMemoryBytes,
    totalMemoryBytes,
    network: netSample.label,
    sampledAt: new Date().toISOString()
  };
}

function createWindow(): void {
  const preloadPath = path.join(__dirname, "../preload/preload.js");
  console.log("[desktop] preload path:", preloadPath);
  mainWindow = new BrowserWindow({
    show: !(e2eMode && process.env.RECONBOT_E2E_HIDDEN === "1"),
    width: 1440,
    height: 920,
    minWidth: e2eMode ? 900 : 1120,
    minHeight: e2eMode ? 700 : 760,
    title: "ReconBot Operator Console",
    icon: appIconPath,
    backgroundColor: "#090b0d",
    webPreferences: {
      preload: preloadPath,
      backgroundThrottling: !(e2eMode && process.env.RECONBOT_E2E_HIDDEN === "1"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webviewTag: false
    }
  });

  mainWindow.webContents.setWindowOpenHandler((details) => {
    // target=_blank, rel=noopener, and window.open() links from embedded reports arrive here.
    if (isSafeExternalUrl(details.url)) {
      openSafeExternalUrl(details.url);
    } else if (!isInternalReportNavigation(details.url)) {
      console.warn(`[desktop] blocked window open: ${details.url}`);
    }
    return { action: "deny" };
  });
  mainWindow.webContents.on("will-navigate", (event, url) => {
    const devUrl = process.env.ELECTRON_RENDERER_URL || "";
    const appUrl = `file://${path.join(__dirname, "../renderer/index.html")}`;
    const allowed = (devUrl && url.startsWith(devUrl)) || url.startsWith(appUrl);
    if (!allowed && isSafeExternalUrl(url)) {
      event.preventDefault();
      openSafeExternalUrl(url);
      return;
    }
    if (!allowed) {
      event.preventDefault();
    }
  });
  mainWindow.webContents.on("will-frame-navigate", (event) => {
    if (event.isMainFrame || event.isSameDocument || isInternalReportNavigation(event.url)) {
      return;
    }
    event.preventDefault();
    if (isSafeExternalUrl(event.url)) {
      openSafeExternalUrl(event.url);
    } else {
      console.warn(`[desktop] blocked frame navigation: ${event.url}`);
    }
  });
  mainWindow.webContents.once("did-finish-load", () => {
    if (mainWindow) reconbotProcess.attach(mainWindow.webContents);
  });

  if (process.env.ELECTRON_RENDERER_URL) {
    mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    mainWindow.loadFile(path.join(__dirname, "../renderer/index.html"));
  }
}

ipcMain.handle("config:get-defaults", () => {
  defaults = loadConfigDefaults(repoRoot);
  defaults.ai = loadPersistedAiSettings();
  reconbotProcess.setDefaults(defaults);
  return defaults;
});

const wordlistPreferences = new WordlistPreferenceStore(path.join(app.getPath('userData'), 'wordlist-preferences.json'), repoRoot);
ipcMain.handle('wordlists:read', () => wordlistPreferences.read());
ipcMain.handle('wordlists:save', (_event, slot: WordlistSlot, preference: { path: string; locked: boolean }) => wordlistPreferences.save(slot, preference));
ipcMain.handle('wordlists:choose', async () => {
  const result = await dialog.showOpenDialog({ title: 'Select a wordlist', properties: ['openFile'] });
  return result.canceled ? null : result.filePaths[0] || null;
});

ipcMain.handle("settings:save-ai", (_event, config: AIConfig) => {
  const result = savePersistedAiSettings(config);
  if (e2eFixture) e2eFixture.action("settings:save-ai", result.ok ? result.config : config);
  if (result.ok) {
    defaults = { ...defaults, ai: result.config };
    reconbotProcess.setDefaults(defaults);
  }
  return result;
});

ipcMain.handle("target:resolve-ip", (_event, target: string) => e2eFixture
  ? { available: false, target: String(target || ""), hostname: "", ip: "" }
  : resolveTargetIp(String(target || "")));
ipcMain.handle("sqlmap:start", (_event, request: SqlmapRequest) => {
  const snapshot = e2eFixture?.readRunState() ?? readRunStateSnapshot(reconbotProcess.getCurrentRunDir(), reconbotProcess.isCurrentRunHistorical(), reconbotProcess.isProcessAttached());
  return sqlmapValidation.start(request, snapshot.currentRunDir, snapshot.target);
});
ipcMain.handle("sqlmap:stop", () => sqlmapValidation.stop());
ipcMain.handle("sqlmap:read", (_event, jobId?: string) => sqlmapValidation.snapshot(e2eFixture?.readRunState().currentRunDir ?? reconbotProcess.getCurrentRunDir(), jobId));
ipcMain.handle('authentication:start', (_event, request: AuthenticationRequest) => {
  const snapshot = e2eFixture?.readRunState() ?? readRunStateSnapshot(reconbotProcess.getCurrentRunDir(), reconbotProcess.isCurrentRunHistorical(), reconbotProcess.isProcessAttached());
  return authenticationValidation.start(request, snapshot.currentRunDir, snapshot.target);
});
ipcMain.handle('authentication:stop', () => authenticationValidation.stop());
ipcMain.handle('authentication:read', (_event, jobId?: string, rejectedPage?: number) => authenticationValidation.snapshot(e2eFixture?.readRunState().currentRunDir ?? reconbotProcess.getCurrentRunDir(), jobId, rejectedPage));
ipcMain.handle("scan:start", (_event, config: ScanConfig) => e2eFixture?.action("scan:start", sanitizeE2EScanConfig(config)) ?? reconbotProcess.startScan(config));
ipcMain.handle("ip-enrichment:start", (_event, request: IpEnrichmentRequest) => e2eFixture?.action("ip-enrichment:start", request) ?? reconbotProcess.startIpEnrichment(request));
ipcMain.handle("ip-enrichment:skip", (_event, request: IpEnrichmentRequest) => e2eFixture?.action("ip-enrichment:skip", request) ?? reconbotProcess.skipIpEnrichment(request));
ipcMain.handle("scan:stop", () => e2eFixture?.action("scan:stop") ?? reconbotProcess.stopScan());
ipcMain.on("terminal:write", (_event, data: string) => {
  if (e2eFixture) e2eFixture.action("terminal:write", String(data));
  else reconbotProcess.write(String(data));
});
ipcMain.handle("terminal:get-buffer", () => e2eFixture ? "ReconBot E2E terminal ready\r\n" : reconbotProcess.getTerminalBuffer());
ipcMain.on("terminal:resize", (_event, cols: number, rows: number) => {
  if (!Number.isInteger(cols) || !Number.isInteger(rows) || cols < 2 || rows < 1 || cols > 1000 || rows > 1000) return;
  if (e2eFixture) e2eFixture.action("terminal:resize", { cols, rows });
  else reconbotProcess.resize(cols, rows);
});

ipcMain.handle("run:read-state", () => {
  if (e2eFixture) return e2eFixture.readRunState();
  const currentRunDir = reconbotProcess.getCurrentRunDir();
  return readRunStateSnapshot(
    currentRunDir,
    reconbotProcess.isCurrentRunHistorical(),
    reconbotProcess.isProcessAttached()
  );
});

ipcMain.handle("host:get-telemetry", () => e2eFixture?.telemetry() ?? hostTelemetry());
ipcMain.handle("history:list-runs", () => e2eFixture?.history() ?? listScanHistory());

ipcMain.handle("history:select-run", (_event, runDir: string) => {
  if (e2eFixture) return e2eFixture.selectHistoricalRun(String(runDir || ""));
  const runsRoot = path.join(safeArtifactRoot(), "runs");
  const resolved = path.resolve(String(runDir || ""));
  if (!isWithin(runsRoot, resolved)) {
    return { ok: false, error: "Run directory is outside scan history root." };
  }
  if (!fs.existsSync(resolved)) {
    return { ok: false, error: "Run directory does not exist." };
  }
  reconbotProcess.selectRunDir(resolved);
  const snapshot = readRunStateSnapshot(resolved, true, false);
  return {
    ok: true,
    message: `Geçmiş tarama yüklendi: ${snapshot.target || path.basename(resolved)}`,
    snapshot
  };
});

ipcMain.handle("artifact:open-path", async (_event, targetPath: string) => {
  if (e2eFixture) return e2eFixture.action("artifact:open-path", targetPath);
  const resolved = path.resolve(String(targetPath || ""));
  if (!isSafeArtifactPath(resolved)) {
    return { ok: false, error: "Path is outside allowed artifact roots." };
  }
  if (!fs.existsSync(resolved)) {
    return { ok: false, error: "Path does not exist." };
  }
  const error = await shell.openPath(resolved);
  return error ? { ok: false, error } : { ok: true };
});

ipcMain.handle("external:open-url", async (_event, rawUrl: string) => {
  const url = String(rawUrl || "");
  if (!isSafeExternalUrl(url)) {
    return { ok: false, error: "Blocked unsafe external URL." };
  }
  if (e2eFixture) return e2eFixture.action("external:open-url", url);
  try {
    await shell.openExternal(url);
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
});

ipcMain.handle("clipboard:copy", (_event, text: string) => {
  if (e2eFixture) return e2eFixture.action("clipboard:copy", text);
  clipboard.writeText(String(text || ""));
  return { ok: true };
});

ipcMain.handle("ai:request", (event, request: AIRequest) => {
  const onProgress = (progress: AIRequestProgress): void => {
    if (!event.sender.isDestroyed()) event.sender.send("ai:request-progress", progress);
  };
  if (e2eFixture && !e2eLiveAi) return e2eFixture.ai(request, onProgress);
  const currentRunDir = reconbotProcess.getCurrentRunDir();
  const effectiveRunDir = currentRunDir || String(request.runDir || "");
  const snapshot = effectiveRunDir
    ? readRunStateSnapshot(
        effectiveRunDir,
        reconbotProcess.isCurrentRunHistorical(),
        reconbotProcess.isProcessAttached()
      )
    : undefined;
  return runAiAssistant(repoRoot, {
    ...request,
    runDir: effectiveRunDir,
    run_id: effectiveRunDir || request.run_id,
    target: snapshot?.target || request.target,
    aiRunContext: snapshot
      ? buildAiRunContextSnapshot({
          runState: snapshot,
          contextProfile: request.contextProfile,
          requestId: request.request_id
        })
      : request.aiRunContext
  }, onProgress);
});

app.whenReady().then(() => {
  const icon = nativeImage.createFromPath(appIconPath);
  if (process.platform === "darwin" && !icon.isEmpty()) app.dock?.setIcon(icon);
  registerReportProtocol();
  createWindow();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

app.on("window-all-closed", () => {
  void Promise.all([reconbotProcess.dispose(), sqlmapValidation.dispose(), authenticationValidation.dispose()]);
  if (process.platform !== "darwin") app.quit();
});

let quitAfterCleanup = false;
let quitCleanup: Promise<void> | undefined;
app.on("before-quit", (event) => {
  if (quitAfterCleanup) return;
  event.preventDefault();
  quitCleanup ??= Promise.all([reconbotProcess.dispose(), sqlmapValidation.dispose(), authenticationValidation.dispose()]).then(() => undefined).finally(() => {
    quitAfterCleanup = true;
    app.quit();
  });
});
