import { contextBridge, ipcRenderer, type IpcRendererEvent } from "electron";
import type { AIRequest, AIRequestProgress, IpEnrichmentRequest, ReconbotApi, ScanConfig } from "../shared/api";

const api: ReconbotApi = {
  getConfigDefaults: () => ipcRenderer.invoke("config:get-defaults"),
  startAuthentication: request => ipcRenderer.invoke('authentication:start', request),
  stopAuthentication: () => ipcRenderer.invoke('authentication:stop'),
  readAuthentication: (jobId, rejectedPage) => ipcRenderer.invoke('authentication:read', jobId, rejectedPage),
  readWordlistPreferences: () => ipcRenderer.invoke('wordlists:read'),
  saveWordlistPreference: (slot, preference) => ipcRenderer.invoke('wordlists:save', slot, preference),
  chooseWordlistFile: () => ipcRenderer.invoke('wordlists:choose'),
  saveAiSettings: (config) => ipcRenderer.invoke("settings:save-ai", config),
  resolveTargetIp: (target: string) => ipcRenderer.invoke("target:resolve-ip", target),
  startScan: (config: ScanConfig) => ipcRenderer.invoke("scan:start", config),
  startIpEnrichment: (request: IpEnrichmentRequest) => ipcRenderer.invoke("ip-enrichment:start", request),
  skipIpEnrichment: (request: IpEnrichmentRequest) => ipcRenderer.invoke("ip-enrichment:skip", request),
  startSqlmap: request => ipcRenderer.invoke("sqlmap:start", request),
  stopSqlmap: () => ipcRenderer.invoke("sqlmap:stop"),
  readSqlmap: jobId => ipcRenderer.invoke("sqlmap:read", jobId),
  stopScan: () => ipcRenderer.invoke("scan:stop"),
  writeTerminal: (data: string) => ipcRenderer.send("terminal:write", data),
  resizeTerminal: (cols: number, rows: number) => ipcRenderer.send("terminal:resize", cols, rows),
  getTerminalBuffer: () => ipcRenderer.invoke("terminal:get-buffer"),
  readRunState: () => ipcRenderer.invoke("run:read-state"),
  selectScanHistoryRun: (runDir: string) => ipcRenderer.invoke("history:select-run", runDir),
  getHostTelemetry: () => ipcRenderer.invoke("host:get-telemetry"),
  listScanHistory: () => ipcRenderer.invoke("history:list-runs"),
  openPath: (targetPath: string) => ipcRenderer.invoke("artifact:open-path", targetPath),
  openExternalUrl: (url: string) => ipcRenderer.invoke("external:open-url", url),
  copyText: (text: string) => ipcRenderer.invoke("clipboard:copy", text),
  aiRequest: (request: AIRequest) => ipcRenderer.invoke("ai:request", request),
  onAiRequestProgress: (callback: (progress: AIRequestProgress) => void) => {
    const listener = (_event: IpcRendererEvent, progress: AIRequestProgress): void => callback(progress);
    ipcRenderer.on("ai:request-progress", listener);
    return () => ipcRenderer.removeListener("ai:request-progress", listener);
  },
  onTerminalData: (callback: (data: string) => void) => {
    const listener = (_event: IpcRendererEvent, data: string): void => callback(data);
    ipcRenderer.on("terminal:data", listener);
    return () => ipcRenderer.removeListener("terminal:data", listener);
  },
  onRunDirChanged: (callback: (runDir: string) => void) => {
    const listener = (_event: IpcRendererEvent, runDir: string): void => callback(runDir);
    ipcRenderer.on("run-dir:changed", listener);
    return () => ipcRenderer.removeListener("run-dir:changed", listener);
  }
};

contextBridge.exposeInMainWorld("reconbot", api);
