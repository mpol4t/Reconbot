import fs from "node:fs";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import type { WebContents } from "electron";
import * as pty from "node-pty";
import type { ActionResult, ConfigDefaults, IpEnrichmentRequest, ScanConfig } from "../shared/api";
import { metadataFeedBackendConfig, validateMetadataFeedUiConfig } from "../shared/metadataFeed";
import { TOOL_ORDER } from "./configDefaults";
import { pythonExecutable } from "./pythonRuntime";

const OUTPUT_RUN_PATTERN = /^\[\+\]\s+Output \(run\):\s+(.+?)\s*$/;
const ANSI_PATTERN = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;
const MAX_TERMINAL_BUFFER_CHARS = 200_000;
function toolField(name: string): string { return name === "screenshots" ? "screenshots_enable" : `${name}_enabled`; }
type PendingEnrichment = { request: IpEnrichmentRequest; token: string; skip: boolean };

export class ReconbotProcess {
  private terminal?: pty.IPty;
  private job?: pty.IPty;
  private webContents = new Set<WebContents>();
  private currentRunDir = "";
  private currentRunHistorical = false;
  private activeRunDir = "";
  private activeTarget = "";
  private activeToken = "";
  private outputBaseDir: string;
  private scanRunning = false;
  private scanStarting = false;
  private launchGeneration = 0;
  private ipEnrichmentRunning = false;
  private terminalBuffer = "";
  private pendingLine = "";
  private pendingEnrichment?: PendingEnrichment;
  private stopping = false;
  private terminalCols = 120;
  private terminalRows = 36;
  private stopTimer?: ReturnType<typeof setTimeout>;

  constructor(private readonly repoRoot: string, defaults: ConfigDefaults) {
    this.outputBaseDir = defaults.outputDir;
  }
  setDefaults(defaults: ConfigDefaults): void { this.outputBaseDir = defaults.outputDir; }
  attach(contents: WebContents): void {
    this.webContents.add(contents);
    contents.once("destroyed", () => this.webContents.delete(contents));
    this.ensureTerminal();
  }
  getCurrentRunDir(): string { return this.currentRunDir; }
  isCurrentRunHistorical(): boolean { return this.currentRunHistorical; }
  isProcessAttached(): boolean { return this.scanRunning || this.ipEnrichmentRunning; }
  selectRunDir(runDir: string): void {
    this.currentRunDir = path.resolve(runDir);
    this.currentRunHistorical = this.currentRunDir !== this.activeRunDir || !this.scanRunning;
    this.broadcast("run-dir:changed", this.currentRunDir);
  }
  getOutputBaseDir(): string { return this.outputBaseDir; }
  getTerminalBuffer(): string { return this.terminalBuffer; }

  private pythonExecutable(): string { return pythonExecutable(this.repoRoot); }
  private runPythonDependencyPreflight(python: string): Promise<ActionResult> {
    return new Promise(resolve => execFile(python, ["-m", "reconbot", "--check-runtime"], {
      cwd: this.repoRoot, env: { ...process.env, PYTHONUNBUFFERED: "1" }, encoding: "utf8", timeout: 15000, maxBuffer: 1024 * 1024
    }, (failure, stdout, stderr) => {
      if (!failure) { resolve({ ok: true }); return; }
      const error = [stdout, stderr, failure.message].filter(Boolean).join("\n").trim();
      this.logTerminal(error);
      resolve({ ok: false, error: error || "Python bağımlılık kontrolü başarısız." });
    }));
  }
  ensureTerminal(): void {
    if (this.terminal) return;
    const configuredShell = process.env.SHELL;
    const terminalShell = configuredShell && fs.existsSync(configuredShell) ? configuredShell : process.platform === "darwin" ? "/bin/zsh" : "/bin/sh";
    const terminal = pty.spawn(terminalShell, ["-l"], {
      name: "xterm-256color", cwd: this.repoRoot, cols: this.terminalCols, rows: this.terminalRows,
      env: { ...process.env, PYTHONUNBUFFERED: "1" } as Record<string, string>
    });
    this.terminal = terminal;
    terminal.onData((data) => this.emitTerminal(data));
    terminal.onExit(() => { if (this.terminal === terminal) this.terminal = undefined; });
  }
  write(data: string): void {
    if (this.job) { this.job.write(data); return; }
    this.ensureTerminal();
    this.terminal?.write(data);
  }
  resize(cols: number, rows: number): void {
    if (!Number.isInteger(cols) || !Number.isInteger(rows) || cols < 2 || rows < 1 || cols > 1000 || rows > 1000) return;
    this.terminalCols = cols;
    this.terminalRows = rows;
    this.terminal?.resize(cols, rows);
    this.job?.resize(cols, rows);
  }

  private launchJob(args: string[], enrichment: boolean): ActionResult {
    try {
      this.pendingLine = "";
      this.stopping = false;
      const job = pty.spawn(this.pythonExecutable(), args, {
        name: "xterm-256color", cwd: this.repoRoot, cols: this.terminalCols, rows: this.terminalRows,
        env: { ...process.env, PYTHONUNBUFFERED: "1", RECONBOT_SUPPRESS_REPORT_OPEN: "1" } as Record<string, string>
      });
      this.job = job;
      this.scanRunning = true;
      this.ipEnrichmentRunning = enrichment;
      job.onData((data) => { if (this.job === job) this.handleTerminalData(data, !enrichment); });
      job.onExit(({ exitCode, signal }) => {
        if (this.job !== job) return;
        this.handleTerminalData("\n", !enrichment);
        this.job = undefined;
        this.scanRunning = false;
        this.ipEnrichmentRunning = false;
        if (this.stopTimer) clearTimeout(this.stopTimer);
        this.stopTimer = undefined;
        const stopped = this.stopping;
        this.stopping = false;
        this.logTerminal(`[reconbot-electron] child return code: ${exitCode}; signal: ${signal || 0}`);
        const pending = this.pendingEnrichment;
        this.pendingEnrichment = undefined;
        if (!enrichment && !stopped && exitCode === 0 && !signal && pending?.token === this.activeToken) {
          const result = this.launchIpEnrichment(pending.request, this.activeRunDir, pending.skip);
          if (!result.ok) this.logTerminal(result.error || "IP incelemesi başlatılamadı.");
        }
      });
      return { ok: true };
    } catch (error) {
      this.job = undefined;
      this.scanRunning = this.ipEnrichmentRunning = false;
      this.pendingEnrichment = undefined;
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  async startScan(config: ScanConfig): Promise<ActionResult> {
    if (this.scanRunning || this.scanStarting) return { ok: false, error: "Bir tarama zaten çalışıyor." };
    const target = config.target.trim();
    if (!target) return { ok: false, error: "Target is required." };
    if (config.runMode !== "osint_only" && (config.tools.gobuster || config.tools.ffuf) && !config.wordlist.trim()) {
      return { ok: false, error: "wordlist required because Gobuster/FFUF enabled" };
    }
    const validation = validateMetadataFeedUiConfig(config.toolSettings.osint.leakSources?.metadataFeed);
    if (validation.errors.length) return { ok: false, error: validation.errors[0] };
    const provider = config.toolSettings.osint.darkweb.customHttpsProvider;
    if (provider.enabled && (!provider.providerUrl.trim().toLowerCase().startsWith("https://") || provider.providerUrl.toLowerCase().includes(".onion"))) {
      return { ok: false, error: "Custom HTTPS metadata provider için geçerli HTTPS URL gerekli." };
    }
    this.scanStarting = true;
    const generation = ++this.launchGeneration;
    let preflight: ActionResult;
    try { preflight = await this.runPythonDependencyPreflight(this.pythonExecutable()); }
    finally { if (generation === this.launchGeneration) this.scanStarting = false; }
    if (generation !== this.launchGeneration) return { ok: false, error: "Scan launch cancelled." };
    if (!preflight.ok) return preflight;
    try {
      const requestDir = path.join(this.outputBaseDir, "app_requests", `${Date.now()}-${randomUUID()}`);
      fs.mkdirSync(requestDir, { recursive: true });
      const configPath = path.join(requestDir, "app_config.yaml");
      fs.writeFileSync(configPath, JSON.stringify(this.buildConfigPayload(config), null, 2), "utf8");
      this.activeRunDir = "";
      this.activeTarget = target;
      this.activeToken = randomUUID();
      this.pendingEnrichment = undefined;
      this.currentRunDir = "";
      this.currentRunHistorical = false;
      this.broadcast("run-dir:changed", "");
      this.logTerminal(`[reconbot-electron] app config: ${configPath}`);
      const args = ["-u", "-m", "reconbot", target, "-c", configPath];
      const result = this.launchJob(args, false);
      return { ...result, requestDir, configPath };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  startIpEnrichment(request: IpEnrichmentRequest): ActionResult { return this.requestEnrichment(request, false); }
  skipIpEnrichment(request: IpEnrichmentRequest): ActionResult { return this.requestEnrichment(request, true); }
  private requestEnrichment(request: IpEnrichmentRequest, skip: boolean): ActionResult {
    if (!request.resolvedIp.trim() || !request.originalTarget.trim()) return { ok: false, error: "Hedef ve IP gerekli." };
    if (this.ipEnrichmentRunning || this.stopping) return { ok: false, error: "Mevcut işin tamamlanmasını bekleyin." };
    const copy = structuredClone(request);
    if (this.scanRunning) {
      if (copy.originalTarget.trim() !== this.activeTarget) return { ok: false, error: "IP hedefi aktif taramayla eşleşmiyor." };
      this.pendingEnrichment = { request: copy, token: this.activeToken, skip };
      return { ok: true, message: "IP incelemesi aktif taramaya bağlandı." };
    }
    return this.launchIpEnrichment(copy, this.currentRunDir, skip);
  }

  private launchIpEnrichment(request: IpEnrichmentRequest, runDir: string, skip = false): ActionResult {
    if (!runDir) return { ok: false, error: "Önce bir tarama başlatın veya rapor seçin." };
    try {
      const payload = JSON.parse(fs.readFileSync(path.join(runDir, "run_result.json"), "utf8"));
      const target = String(payload.meta?.target || payload.target || "");
      if (target !== request.originalTarget.trim()) return { ok: false, error: "IP hedefi seçilen çalışma kaydıyla eşleşmiyor." };
      const requestPath = path.join(runDir, "ip_enrichment_request.json");
      fs.writeFileSync(requestPath, JSON.stringify({
        run_dir: runDir, run_id: path.basename(runDir), original_target: target,
        resolved_ip: request.resolvedIp.trim(), hostname: request.hostname || "",
        scan_mode: skip ? "skipped" : request.scanMode === "detailed" ? "detailed" : "quick",
        operator_action: skip ? "skip" : "run", requested_at: new Date().toISOString()
      }, null, 2), "utf8");
      this.activeRunDir = runDir;
      this.activeTarget = target;
      this.logTerminal(`[reconbot-electron] IP enrichment run: ${runDir}`);
      return { ...this.launchJob(["-u", "-m", "reconbot.orchestration.ip_enrichment", requestPath], true), requestDir: runDir, configPath: requestPath };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  stopScan(): ActionResult {
    this.launchGeneration++;
    this.scanStarting = false;
    this.pendingEnrichment = undefined;
    if (!this.job) return { ok: true, message: "No running scan" };
    if (this.stopping) return { ok: true, message: "Stop already requested" };
    this.stopping = true;
    const job = this.job;
    job.kill("SIGINT");
    if (this.stopTimer) clearTimeout(this.stopTimer);
    this.stopTimer = setTimeout(() => { if (this.job === job) job.kill("SIGKILL"); }, 8000);
    this.stopTimer.unref();
    return { ok: true, message: "Stop requested" };
  }
  dispose(): Promise<void> {
    const job = this.job;
    const stopped = job ? new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, 10000);
      timer.unref();
      job.onExit(() => { clearTimeout(timer); resolve(); });
    }) : Promise.resolve();
    this.stopScan();
    try { this.terminal?.kill(); } catch { /* Already closed. */ }
    this.terminal = undefined;
    return stopped;
  }

  private buildConfigPayload(scanConfig: ScanConfig): Record<string, unknown> {
    const githubSource = scanConfig.toolSettings.osint.sources.githubCodeSearch;
    const githubApiKeyEnv = githubSource.apiKeyEnv.trim() || "GITHUB_TOKEN";
    const darkwebProvider = scanConfig.toolSettings.osint.darkweb.customHttpsProvider;
    const darkwebApiKeyEnv = darkwebProvider.apiKeyEnv.trim() || "DARKWEB_METADATA_TOKEN";
    const reconbot: Record<string, unknown> = {
      wordlist: scanConfig.wordlist.trim(),
      output_dir: this.outputBaseDir,
      verbose: true,
      traffic_profile: scanConfig.trafficProfile,
      run_mode: scanConfig.runMode,
      scan_profile: scanConfig.scanProfile === "custom" ? "balanced" : scanConfig.scanProfile,
      osint_enabled: scanConfig.runMode === "osint_only" || scanConfig.runMode === "normal_scan_plus_osint",
      osint_profile: scanConfig.osintProfile || "safe_mvp",
      tool_settings: {
        ...scanConfig.toolSettings,
        osint: {
          ...scanConfig.toolSettings.osint,
          passive_only: true,
          sources: {
            ...scanConfig.toolSettings.osint.sources,
            githubCodeSearch: {
              enabled: githubSource.enabled,
              apiKeyEnv: githubApiKeyEnv,
              apiKeyConfigured: Boolean(process.env[githubApiKeyEnv])
            }
          },
          leakSources: {
            ...scanConfig.toolSettings.osint.leakSources,
            metadataFeed: metadataFeedBackendConfig(scanConfig.toolSettings.osint.leakSources?.metadataFeed)
          },
          darkweb: {
            ...scanConfig.toolSettings.osint.darkweb,
            customHttpsProvider: {
              ...darkwebProvider,
              apiKeyEnv: darkwebApiKeyEnv,
              apiKeyConfigured: Boolean(process.env[darkwebApiKeyEnv])
            }
          }
        }
      },
      report_depth: scanConfig.reportDepth,
      detailed_nmap_enabled: scanConfig.detailedNmapEnabled !== false
    };
    const settings = scanConfig.toolSettings;
    reconbot.detailed_nmap_enabled = Boolean(settings.ipNmap.enabled && settings.ipNmap.mode === "deep");
    if (scanConfig.ipEnrichment) {
      reconbot.ip_enrichment = {
        status: scanConfig.ipEnrichment.status,
        original_target: scanConfig.ipEnrichment.originalTarget,
        resolved_ip: scanConfig.ipEnrichment.resolvedIp,
        hostname: scanConfig.ipEnrichment.hostname || "",
        scan_mode: scanConfig.ipEnrichment.scanMode || "",
        requested_at: scanConfig.ipEnrichment.requestedAt || "",
        note: scanConfig.ipEnrichment.note || ""
      };
    }
    for (const [name] of TOOL_ORDER) {
      reconbot[toolField(name)] = Boolean(scanConfig.tools[name]);
    }
    return { reconbot };
  }

  private handleTerminalData(data: string, parseRun = true): void {
    this.emitTerminal(data);
    if (!parseRun) return;
    this.pendingLine += data;
    let newline: number;
    while ((newline = this.pendingLine.indexOf("\n")) >= 0) {
      const line = this.pendingLine.slice(0, newline).replace(ANSI_PATTERN, "").replace(/\r/g, "");
      this.pendingLine = this.pendingLine.slice(newline + 1);
      const match = line.match(OUTPUT_RUN_PATTERN);
      if (!match || this.activeRunDir) continue;
      const runDir = path.resolve(this.repoRoot, match[1].trim());
      const relative = path.relative(path.join(this.outputBaseDir, "runs"), runDir);
      if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) continue;
      this.activeRunDir = runDir;
      if (!this.currentRunHistorical) {
        this.currentRunDir = runDir;
        this.broadcast("run-dir:changed", runDir);
      }
    }
    if (this.pendingLine.length > MAX_TERMINAL_BUFFER_CHARS) this.pendingLine = "";
  }
  private logTerminal(line: string): void { this.emitTerminal(`${line}\r\n`); }
  private emitTerminal(data: string): void {
    this.terminalBuffer = (this.terminalBuffer + data).slice(-MAX_TERMINAL_BUFFER_CHARS);
    this.broadcast("terminal:data", data);
  }
  private broadcast(channel: string, payload: string): void {
    for (const contents of this.webContents) if (!contents.isDestroyed()) contents.send(channel, payload);
  }
}
export function terminalShellSummary(): string {
  return `${process.env.SHELL || (process.platform === "darwin" ? "/bin/zsh" : "/bin/sh")} on ${os.platform()}`;
}
