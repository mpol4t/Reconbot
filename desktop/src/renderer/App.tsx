import { t, useLanguage } from "./lib/i18n";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { AIConfig, AIResponse, AIStatus, ConfigDefaults, HostTelemetry, IpEnrichmentState, ResolvedIpInfo, RunStateSnapshot, ScanConfig, ScanHistoryItem } from "../shared/api";
import { validateMetadataFeedUiConfig } from "../shared/metadataFeed";
import ArtifactPane from "./components/ArtifactPane";
import AIAssistantPanel from "./components/AIAssistantPanel";
import AISetupGuide from "./components/AISetupGuide";
import ConfigurePane from "./components/ConfigurePane";
import DashboardPane from "./components/DashboardPane";
import ErrorBoundary from "./components/ErrorBoundary";
import SqlmapPane from "./components/SqlmapPane";
import AuthenticationPane from './components/AuthenticationPane';
import FindingsPane from "./components/FindingsPane";
import ReportPane from "./components/ReportPane";
import Sidebar, { type ActiveView } from "./components/Sidebar";
import StatusBar from "./components/StatusBar";
import TerminalPane from "./components/TerminalPane";
import ThreatPipeline from "./components/ThreatPipeline";
import { buildOperatorModel } from "./lib/operatorModel";
import SettingsPane from "./components/SettingsPane";
import { configFromDefaults, defaultAiConfig, getEffectiveAiModel, normalizeAiConfig, normalizeScanConfig } from "./lib/settingsModel";

const AI_STATUS_TTL_MS = 30_000;
const AI_STATUS_DEBOUNCE_MS = 1000;

type AiRuntimeState = "idle" | "busy" | "queued" | "timeout" | "reasoning_without_final";
type HistoricalRunState = { runDir: string; target: string; label: string } | null;

const fallbackDefaults: ConfigDefaults = {
  repoRoot: "",
  wordlist: "",
  outputDir: "",
  trafficProfile: "balanced",
  scanProfile: "balanced",
  reportDepth: "balanced",
  tools: [],
  ai: { ...defaultAiConfig }
};

const emptyRunState: RunStateSnapshot = {
  currentRunDir: "",
  runState: "idle",
  isHistorical: false,
  completeness: "empty",
  processAttached: false,
  artifacts: {
    availableCount: 0,
    availableFiles: [],
    missingExpected: [],
    paths: {
      runDir: "",
      rawLog: "",
      stateJson: "",
      stagesJson: "",
      configOrRequest: "",
      report: ""
    },
    exists: {
      runDir: false,
      rawLog: false,
      stateJson: false,
      stagesJson: false,
      configOrRequest: false,
      report: false
    }
  },
  target: "",
  profile: "",
  risk: {
    score: null,
    label: "pending",
    source: "pending"
  },
  decision: {
    summary: "",
    firstAction: "",
    strongestPath: "",
    source: "derived"
  },
  currentStage: "",
  stages: [],
  metrics: {
    katanaCount: 0,
    gobusterHits: 0,
    ffufHits: 0,
    checksCount: 0,
    checksLogin: 0,
    checksDocs: 0,
    checksCaptcha: 0,
    checksRatelimit: 0,
    nucleiFindings: 0,
    screenshotsCount: 0
  },
  findings: [],
  report: {
    exists: false,
    mtime: 0,
    path: "",
    viewUrl: "",
    status: "missing",
    failureReason: ""
  },
  ipEnrichment: undefined,
  logTail: [],
  updatedAt: ""
};

function ipStatusLabel(ipPromptState: "passive" | "ask" | "accepted" | "ignored", enrichment?: IpEnrichmentState): string {
  const status = enrichment?.status || "";
  if (status === "done" || status === "completed" || status === "already_covered") return "done";
  if (status === "failed") return "error";
  if (status === "error") return "error";
  if (status === "running") return "running";
  if (status === "skipped") return "skipped";
  if (status === "quick_ip_scan_requested" || status === "detailed_nmap_requested") return "queued";
  if (status === "available_skipped") return ipPromptState === "accepted" ? "queued" : "";
  if (ipPromptState === "accepted") return "queued";
  if (ipPromptState === "ignored") return "skipped";
  return "";
}

function numericIpResult(value: unknown): number {
  const parsed = Number(value ?? 0);
  return Number.isFinite(parsed) ? parsed : 0;
}

function countIpResult(value: unknown, fallback?: unknown): number {
  if (Array.isArray(value)) return value.length;
  return numericIpResult(fallback);
}

function ipStatusText(status: string, enrichment?: IpEnrichmentState): string {
  if (!status) return "";
  if (status === "queued") return "IP enrichment: queued";
  if (status === "running") return "IP enrichment: running";
  if (status === "skipped") return "IP enrichment: skipped";
  if (status === "error") return "IP enrichment: error";
  const results = enrichment?.results || {};
  if (status === "done") {
    const ports = countIpResult(results.openPorts ?? results.open_ports, results.openPortsCount ?? results.open_ports_count);
    const probes = countIpResult(results.probes, results.probesCount ?? results.probes_count);
    return `IP enrichment: done · ${enrichment?.resolvedIp || "resolved IP"} · ${ports} ports · ${probes} probes`;
  }
  return `IP enrichment: ${status}`;
}

function isFinalIpStatus(status: string): boolean {
  return status === "done" || status === "skipped" || status === "error";
}

function aiStatusLabel(status: AIStatus | null): string {
  if (!status) return "AI bağlantısı kontrol ediliyor...";
  if (status.connection === "checking") return "AI bağlantısı kontrol ediliyor...";
  if (status.connection === "checking_connection") return "AI bağlantısı kontrol ediliyor...";
  if (status.connection === "disabled") return "AI devre dışı";
  if (status.connection === "busy") return "Model yanıt üretiyor";
  if (status.connection === "queued") return "İstek sırada";
  if (status.connection === "timeout") return "Model yavaş yanıt verdi / zaman aşımı";
  if (status.connection === "model_timeout") return "Model yavaş yanıt verdi / zaman aşımı";
  if (status.connection === "model_busy") return "Model meşgul";
  if (status.connection === "reasoning_without_final") return "Model final cevap üretmedi";
  if (status.connection === "model_missing") return "Model yüklü değil veya adı eşleşmiyor";
  if (status.connection === "invalid_response") return "Endpoint OpenAI-compatible olmayan cevap döndürdü";
  if (status.ready) return "Yerel model bağlı";
  return "AI bağlantısı yok";
}

function aiStatusAvailableModels(status: AIStatus | null | undefined): string[] {
  return Array.isArray(status?.available_models) ? status.available_models : [];
}

function normalizeRunState(snapshot?: Partial<RunStateSnapshot> | null): RunStateSnapshot {
  const source = snapshot || {};
  return {
    ...emptyRunState,
    ...source,
    risk: { ...emptyRunState.risk, ...(source.risk || {}) },
    decision: { ...emptyRunState.decision, ...(source.decision || {}) },
    stages: Array.isArray(source.stages) ? source.stages : [],
    metrics: { ...emptyRunState.metrics, ...(source.metrics || {}) },
    findings: Array.isArray(source.findings) ? source.findings : [],
    report: { ...emptyRunState.report, ...(source.report || {}) },
    artifacts: {
      ...emptyRunState.artifacts!,
      ...(source.artifacts || {}),
      paths: { ...emptyRunState.artifacts!.paths, ...(source.artifacts?.paths || {}) },
      exists: { ...emptyRunState.artifacts!.exists, ...(source.artifacts?.exists || {}) },
      availableFiles: Array.isArray(source.artifacts?.availableFiles) ? source.artifacts.availableFiles : [],
      missingExpected: Array.isArray(source.artifacts?.missingExpected) ? source.artifacts.missingExpected : []
    },
    logTail: Array.isArray(source.logTail) ? source.logTail : []
  };
}

function unavailableAiStatus(config: AIConfig, message = "AI durumu okunamadı"): AIStatus {
  return {
    ...checkingAiStatus(config),
    connection: "error",
    user_message_tr: message,
    operator_action_tr: "AI opsiyoneldir; ana ReconBot arayüzü kullanılabilir.",
    setup_hint_tr: "Preload/IPC hazır değilse uygulama AI panelini devre dışı bırakır.",
    available_models: []
  };
}

function normalizeAiBaseUrl(baseUrl: string): string {
  const trimmed = (baseUrl || "http://127.0.0.1:1234/v1").trim().replace(/\/+$/, "");
  if (trimmed.endsWith("/v1")) return trimmed;
  if (trimmed.includes("/v1/")) return `${trimmed.split("/v1/", 1)[0]}/v1`;
  return `${trimmed}/v1`;
}

function aiConfigForRequest(config: AIConfig): AIConfig {
  const safeConfig = normalizeAiConfig(config);
  const effectiveModel = getEffectiveAiModel(safeConfig);
  return {
    ...safeConfig,
    baseUrl: normalizeAiBaseUrl(safeConfig.baseUrl),
    model: effectiveModel,
    effectiveModel
  };
}

function checkingAiStatus(config: AIConfig): AIStatus {
  const safeConfig = normalizeAiConfig(config);
  const effectiveModel = getEffectiveAiModel(safeConfig);
  return {
    enabled: safeConfig.enabled,
    provider: safeConfig.provider,
    baseUrl: safeConfig.baseUrl,
    model: effectiveModel,
    selectedModel: safeConfig.selectedModel,
    manualModelName: safeConfig.manualModelName,
    effectiveModel,
    connection: "checking_connection",
    ready: false,
    can_chat: false,
    user_message_tr: "AI bağlantısı kontrol ediliyor...",
    operator_action_tr: "Bu kontrol arka planda çalışır ve ReconBot kullanımını engellemez.",
    setup_hint_tr: "Local endpoint hazır değilse Kurulum Rehberi'ni aç.",
    checked_at: new Date().toISOString(),
    available_models: []
  };
}

function disabledAiStatus(config: AIConfig): AIStatus {
  return {
    ...checkingAiStatus(config),
    connection: "disabled",
    user_message_tr: "AI devre dışı.",
    operator_action_tr: "AI kullanmak için Settings > AI içinden etkinleştir.",
    setup_hint_tr: "ReconBot AI opsiyoneldir; ReconBot AI olmadan normal çalışır."
  };
}

function aiStatusFromResponse(response: AIResponse, config: AIConfig): AIStatus {
  const effectiveModel = getEffectiveAiModel(config);
  const rawStatus = response.aiStatus || response.ai?.status;
  if (rawStatus) {
    const availableModels = Array.isArray(rawStatus.available_models)
      ? rawStatus.available_models
      : Array.isArray(response.availableModels)
        ? response.availableModels
        : [];
    const returnedModel = String(rawStatus.effectiveModel || rawStatus.effective_model || rawStatus.model || "");
    const statusMatchesRequest = !returnedModel || returnedModel === effectiveModel;
    const selectedModelAvailable = availableModels.length ? availableModels.includes(effectiveModel) : rawStatus.selectedModelAvailable ?? rawStatus.selected_model_available;
    return {
      ...checkingAiStatus(config),
      ...rawStatus,
      model: effectiveModel,
      selectedModel: config.selectedModel,
      manualModelName: config.manualModelName,
      effectiveModel,
      effective_model: effectiveModel,
      testedModel: statusMatchesRequest ? String(rawStatus.testedModel || rawStatus.tested_model || rawStatus.model || effectiveModel) : undefined,
      tested_model: statusMatchesRequest ? String(rawStatus.tested_model || rawStatus.testedModel || rawStatus.model || effectiveModel) : undefined,
      selectedModelAvailable,
      selected_model_available: selectedModelAvailable,
      connection: statusMatchesRequest ? rawStatus.connection : "needs_recheck",
      ready: Boolean(rawStatus.ready && statusMatchesRequest),
      can_chat: Boolean(rawStatus.can_chat && statusMatchesRequest),
      reason: statusMatchesRequest ? rawStatus.reason : "stale_model_status",
      user_message_tr: statusMatchesRequest
        ? rawStatus.user_message_tr
        : "Model/baseUrl değiştiği için bağlantı testi tekrar gerekli.",
      operator_action_tr: statusMatchesRequest
        ? rawStatus.operator_action_tr
        : "Bağlantıyı Test Et ile seçili modeli tekrar doğrula.",
      available_models: availableModels
    };
  }
  const availableModels = Array.isArray(response.availableModels) ? response.availableModels : [];
  return {
    ...checkingAiStatus(config),
    model: effectiveModel,
    selectedModel: config.selectedModel,
    manualModelName: config.manualModelName,
    effectiveModel,
    testedModel: response.ok ? effectiveModel : undefined,
    tested_model: response.ok ? effectiveModel : undefined,
    connection: response.ok ? "ready" : "error",
    ready: Boolean(response.ok),
    can_chat: Boolean(response.ok),
    user_message_tr: response.error || (response.ok ? "Bağlantı başarılı. Yerel model hazır." : "AI durumu alınamadı."),
    operator_action_tr: response.ok ? "AI sohbeti kullanılabilir." : "Bağlantıyı Test Et ile tekrar dene.",
    setup_hint_tr: response.ok ? "Model hazır." : "Kurulum Rehberi'ni aç.",
    available_models: availableModels
  };
}

function runtimeAiStatus(base: AIStatus | null, runtime: AiRuntimeState, config: AIConfig, reasoningWithoutFinalCount = 0): AIStatus | null {
  if (runtime === "idle") return base;
  const fallback = base || checkingAiStatus(config);
  const effectiveModel = getEffectiveAiModel(config);
  const alignedFallback = {
    ...fallback,
    model: effectiveModel,
    selectedModel: config.selectedModel,
    manualModelName: config.manualModelName,
    effectiveModel,
    effective_model: effectiveModel
  };
  if (runtime === "busy") {
    return {
      ...alignedFallback,
      connection: "busy",
      ready: fallback.ready,
      can_chat: false,
      user_message_tr: "Model yanıt üretiyor.",
      operator_action_tr: "Mevcut isteği bekle veya AI panelinden İsteği iptal et.",
      setup_hint_tr: "LM Studio kuyruğunu doldurmamak için aynı anda tek AI isteği çalışır.",
      checked_at: new Date().toISOString()
    };
  }
  if (runtime === "queued") {
    return {
      ...alignedFallback,
      connection: "queued",
      ready: fallback.ready,
      can_chat: false,
      user_message_tr: "İstek sırada.",
      operator_action_tr: "Önceki AI isteği tamamlanmadan yenisi gönderilmedi.",
      setup_hint_tr: "Hızlı promptlara art arda basmak LM Studio kuyruğunu doldurmaz.",
      checked_at: new Date().toISOString()
    };
  }
  if (runtime === "reasoning_without_final") {
    return {
      ...alignedFallback,
      connection: "reasoning_without_final",
      ready: fallback.ready,
      can_chat: false,
      user_message_tr: "Model final cevap üretmedi. Bu bir bağlantı hatası değil; model cevap formatı uyumsuzluğu olabilir.",
      operator_action_tr: "Thinking/Reasoning kapalı bırak, max output token artır veya final message.content döndüren instruct model seç.",
      setup_hint_tr: "Reasoning trace kullanıcıya gösterilmez veya chat geçmişine yazılmaz.",
      reasoning_without_final_count: reasoningWithoutFinalCount,
      checked_at: new Date().toISOString()
    };
  }
  return {
    ...alignedFallback,
    connection: "timeout",
    ready: fallback.ready,
    can_chat: false,
    user_message_tr: "Model yavaş yanıt verdi / zaman aşımı.",
    operator_action_tr: "Context boyutu fazla olabilir veya LM Studio kuyruğu dolmuş olabilir.",
    setup_hint_tr: "maxContextChars değerini düşür, mevcut isteği bekle veya local server kuyruğu takıldıysa yeniden başlat.",
    checked_at: new Date().toISOString()
  };
}

export default function App(): JSX.Element {
  useLanguage();
  const [defaults, setDefaults] = useState<ConfigDefaults | null>(null);
  const [scanConfig, setScanConfig] = useState<ScanConfig | null>(null);
  const [runState, setRunState] = useState<RunStateSnapshot>(emptyRunState);
  const [activeView, setActiveView] = useState<ActiveView>("dashboard");
  const [sqlmapSeed, setSqlmapSeed] = useState<{ url: string; findingId?: string; nonce: number } | null>(null);
  const [graphFocus, setGraphFocus] = useState("");
  const [terminalMounted, setTerminalMounted] = useState(true);
  const [message, setMessage] = useState("Loading config defaults...");
  const [terminalBuffer, setTerminalBuffer] = useState("");
  const [telemetry, setTelemetry] = useState<HostTelemetry | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [resolvedIp, setResolvedIp] = useState<ResolvedIpInfo | null>(null);
  const [ipPromptState, setIpPromptState] = useState<"passive" | "ask" | "accepted" | "ignored">("passive");
  const [reportUpdateKey, setReportUpdateKey] = useState("");
  const [aiPanelOpen, setAiPanelOpen] = useState(false);
  const [aiSessionStarted, setAiSessionStarted] = useState(false);
  useEffect(() => { if (aiPanelOpen) setAiSessionStarted(true); }, [aiPanelOpen]);
  const [copilotWidth, setCopilotWidth] = useState(() => {
    try { const value = Number(localStorage.getItem("reconbot.ui.copilotWidth")); return value >= 360 && value <= 640 ? value : 440; }
    catch { return 440; }
  });
  const resizeCopilot = useCallback((width: number) => {
    const next = Math.min(640, Math.max(360, Math.round(width)));
    setCopilotWidth(next);
    try { localStorage.setItem("reconbot.ui.copilotWidth", String(next)); } catch { /* Session preference remains usable. */ }
  }, []);
  const [aiInitialQuestion, setAiInitialQuestion] = useState("");
  const [aiInitialMode, setAiInitialMode] = useState("chat");
  const [aiInitialSource, setAiInitialSource] = useState("chat_input");
  const [aiInitialPromptId, setAiInitialPromptId] = useState(0);
  const [aiBrief, setAiBrief] = useState("");
  const [aiConnection, setAiConnection] = useState<AIStatus | null>(null);
  const [aiRuntimeState, setAiRuntimeState] = useState<AiRuntimeState>("idle");
  const [aiReasoningWithoutFinalCount, setAiReasoningWithoutFinalCount] = useState(0);
  const [aiSetupOpen, setAiSetupOpen] = useState(false);
  const [aiSuggestionReady, setAiSuggestionReady] = useState(false);
  const [historicalRun, setHistoricalRun] = useState<HistoricalRunState>(null);
  const lastIpStatusRef = useRef("");
  const lastReportUpdateRef = useRef("");
  const aiStatusCacheRef = useRef<{ key: string; status: AIStatus; checkedAt: number } | null>(null);
  const aiStatusInFlightRef = useRef<{ key: string; promise: Promise<AIStatus | null> } | null>(null);
  const latestAiStatusKeyRef = useRef("");
  const aiStatusTimerRef = useRef<number | null>(null);
  const lastPersistedAiRef = useRef("");
  const changeActiveView = useCallback((nextView: ActiveView, _reason: string) => {
    setActiveView(nextView);
  }, []);

  useEffect(() => {
    let alive = true;
    const loadDefaults = window.reconbot?.getConfigDefaults;
    if (!loadDefaults) {
      setDefaults(fallbackDefaults);
      setScanConfig(configFromDefaults(fallbackDefaults));
      setAiConnection(unavailableAiStatus(defaultAiConfig));
      setMessage("Desktop IPC hazır değil; arayüz güvenli modda açıldı.");
      return () => {
        alive = false;
      };
    }
    loadDefaults()
      .then((loadedDefaults) => {
        if (!alive) return;
        const safeDefaults = loadedDefaults || fallbackDefaults;
        setDefaults(safeDefaults);
        setScanConfig(normalizeScanConfig(configFromDefaults(safeDefaults), safeDefaults));
        setMessage("Scan workspace ready");
      })
      .catch((error) => {
        if (!alive) return;
        setDefaults(fallbackDefaults);
        setScanConfig(configFromDefaults(fallbackDefaults));
        setAiConnection(unavailableAiStatus(defaultAiConfig));
        setMessage(t("Could not load configuration defaults: {detail}", { detail: error instanceof Error ? error.message : String(error) }));
      });
    return () => {
      alive = false;
    };
  }, []);

  const refreshRunState = useCallback(async () => {
    try {
      const snapshot = await window.reconbot?.readRunState?.();
      setRunState(current => snapshot?.updatedAt && current.updatedAt === snapshot.updatedAt
        && current.currentRunDir === snapshot.currentRunDir && current.runState === snapshot.runState
        && current.isHistorical === snapshot.isHistorical && current.processAttached === snapshot.processAttached
        ? current : normalizeRunState(snapshot));
    } catch (error) {
      console.warn("[renderer] readRunState failed", error);
      setMessage(t("Could not refresh run state; the last valid snapshot is retained: {detail}", { detail: error instanceof Error ? error.message : String(error) }));
    }
  }, []);

  useEffect(() => {
    const unsubscribe = window.reconbot?.onRunDirChanged?.((runDir) => {
      setMessage(runDir ? `Following run: ${runDir}` : "Waiting for child run directory...");
      refreshRunState();
    }) || (() => undefined);
    const timer = window.setInterval(refreshRunState, 1500);
    refreshRunState();
    return () => {
      unsubscribe();
      window.clearInterval(timer);
    };
  }, [refreshRunState]);

  useEffect(() => {
    let alive = true;
    const terminalBufferReader = window.reconbot?.getTerminalBuffer;
    if (terminalBufferReader) {
      terminalBufferReader()
        .then((buffer) => {
          if (alive) setTerminalBuffer(buffer || "");
        })
        .catch((error) => console.warn("[renderer] getTerminalBuffer failed", error));
    }
    let pending = "";
    let timer: number | undefined;
    const unsubscribe = window.reconbot?.onTerminalData?.((data) => {
      pending = (pending + data).slice(-120_000);
      if (timer !== undefined) return;
      timer = window.setTimeout(() => {
        const chunk = pending; pending = ""; timer = undefined;
        if (alive) setTerminalBuffer(current => (current + chunk).slice(-120_000));
      }, 120);
    }) || (() => undefined);
    return () => {
      alive = false;
      if (timer !== undefined) window.clearTimeout(timer);
      unsubscribe();
    };
  }, []);

  const refreshTelemetry = useCallback(async () => {
    try {
      const snapshot = await window.reconbot?.getHostTelemetry?.();
      setTelemetry(snapshot || null);
    } catch (error) {
      console.warn("[renderer] getHostTelemetry failed", error);
      setTelemetry(null);
    }
  }, []);

  const refreshHistory = useCallback(async () => {
    try {
      const rows = await window.reconbot?.listScanHistory?.();
      setHistory(Array.isArray(rows) ? rows : []);
    } catch (error) {
      console.warn("[renderer] listScanHistory failed", error);
      setHistory([]);
    }
  }, []);

  useEffect(() => {
    refreshTelemetry();
    const timer = window.setInterval(refreshTelemetry, 2000);
    return () => window.clearInterval(timer);
  }, [refreshTelemetry]);

  useEffect(() => {
    refreshHistory();
    const timer = window.setInterval(refreshHistory, 5000);
    return () => window.clearInterval(timer);
  }, [refreshHistory]);

  const canStart = useMemo(() => Boolean(scanConfig?.target.trim()), [scanConfig]);
  const operatorModel = useMemo(() => buildOperatorModel(runState), [runState]);
  const ipEnrichmentAvailable = Boolean(resolvedIp?.available && resolvedIp.ip);
  const effectiveAiModel = scanConfig ? getEffectiveAiModel(scanConfig.ai) : defaultAiConfig.model;
  const aiConfigKey = scanConfig
    ? [
      scanConfig.ai.enabled,
      scanConfig.ai.provider,
      normalizeAiBaseUrl(scanConfig.ai.baseUrl),
      effectiveAiModel,
      scanConfig.ai.apiKeyEnv,
      scanConfig.ai.timeout
    ].join("|")
    : "";

  const handleScanConfigChange = useCallback((nextConfig: ScanConfig) => {
    setScanConfig(defaults ? normalizeScanConfig(nextConfig, defaults) : nextConfig);
  }, [defaults]);

  useEffect(() => {
    if (!scanConfig?.ai || !window.reconbot?.saveAiSettings) return;
    const serialized = JSON.stringify(scanConfig.ai);
    if (lastPersistedAiRef.current === serialized) return;
    const timer = window.setTimeout(() => {
      void window.reconbot.saveAiSettings(scanConfig.ai).then((result) => {
        if (!result.ok) {
          setMessage(`AI ayarları kaydedilemedi: ${result.error || "unknown error"}`);
          return;
        }
        lastPersistedAiRef.current = serialized;
      }).catch((error) => {
        setMessage(`AI ayarları kaydedilemedi: ${error instanceof Error ? error.message : String(error)}`);
      });
    }, 150);
    return () => window.clearTimeout(timer);
  }, [scanConfig?.ai]);

  const handleAiActivityChange = useCallback((state: AiRuntimeState) => {
    setAiRuntimeState(state);
    if (state === "reasoning_without_final") {
      setAiReasoningWithoutFinalCount((count) => count + 1);
    }
  }, []);

  useEffect(() => {
    if (!scanConfig?.target.trim()) {
      setResolvedIp(null);
      setIpPromptState("passive");
      return;
    }
    let alive = true;
    const target = scanConfig.target.trim();
    const timer = window.setTimeout(() => {
      window.reconbot?.resolveTargetIp?.(target)
        .then((result) => {
          if (!alive) return;
          setResolvedIp(result || null);
          setIpPromptState("passive");
        })
        .catch((error) => {
          console.warn("[renderer] resolveTargetIp failed", error);
          if (alive) setResolvedIp(null);
        });
    }, 350);
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [scanConfig?.target]);

  const ipEnrichmentMetadata = useCallback((status: IpEnrichmentState["status"], scanMode: IpEnrichmentState["scanMode"], note: string): IpEnrichmentState | undefined => {
    if (!scanConfig || !resolvedIp) return undefined;
    return {
      status,
      originalTarget: scanConfig.target.trim(),
      resolvedIp: resolvedIp.ip || "",
      hostname: resolvedIp.hostname,
      scanMode,
      requestedAt: new Date().toISOString(),
      note
    };
  }, [resolvedIp, scanConfig]);

  const startScan = useCallback(async () => {
    if (!scanConfig) return;
    const metadataFeedValidation = validateMetadataFeedUiConfig(scanConfig.toolSettings.osint.leakSources?.metadataFeed);
    if (metadataFeedValidation.errors.length) {
      setMessage(metadataFeedValidation.errors[0]);
      changeActiveView("settings", "start-scan:metadata-validation");
      return;
    }
    setTerminalMounted(true);
    changeActiveView("terminal", "start-scan");
    setHistoricalRun(null);
    const shouldOfferIpEnrichment = scanConfig.runMode !== "osint_only" && ipEnrichmentAvailable;
    if (!window.reconbot?.startScan) {
      setMessage("Desktop IPC hazır değil; scan başlatılamadı.");
      return;
    }
    let result;
    try {
      result = await window.reconbot.startScan({
        ...scanConfig,
        ipEnrichment: shouldOfferIpEnrichment
          ? ipEnrichmentMetadata("available_skipped", "skipped", "Resolved IP enrichment is available; operator choice is pending for auxiliary context only.")
          : undefined
      });
    } catch (error) {
      setMessage(`Failed to start scan: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    if (result.ok && shouldOfferIpEnrichment) {
      setIpPromptState("ask");
      setMessage("Resolved IP detected. Choose whether to attach auxiliary IP enrichment.");
    } else {
      setMessage(result.ok ? `Started: ${result.configPath}` : result.error || "Failed to start scan");
    }
  }, [changeActiveView, ipEnrichmentAvailable, ipEnrichmentMetadata, scanConfig]);

  const ignoreIpEnrichment = useCallback(() => {
    if (!scanConfig || !resolvedIp?.available || !resolvedIp.ip) return;
    const primaryTarget = runState.target || scanConfig.target.trim();
    setIpPromptState("ignored");
    setMessage("IP enrichment skipped for this target.");
    void window.reconbot?.skipIpEnrichment?.({
      originalTarget: primaryTarget,
      resolvedIp: resolvedIp.ip,
      hostname: resolvedIp.hostname,
      scanMode: "quick"
    }).then((result) => {
      if (!result?.ok) setMessage(result?.error || "Failed to store IP enrichment skip state");
    }).catch((error) => setMessage(`Failed to store IP enrichment skip state: ${error instanceof Error ? error.message : String(error)}`));
  }, [resolvedIp, runState.target, scanConfig]);

  const startIpEnrichmentScan = useCallback(async (mode: "quick" | "detailed") => {
    if (!scanConfig || !resolvedIp?.available || !resolvedIp.ip) return;
    const primaryTarget = runState.target || scanConfig.target.trim();
    setIpPromptState("accepted");
    setTerminalMounted(true);
    changeActiveView("terminal", "start-ip-enrichment");
    if (!window.reconbot?.startIpEnrichment) {
      setMessage("Desktop IPC hazır değil; IP enrichment başlatılamadı.");
      setIpPromptState("ask");
      return;
    }
    let result;
    try {
      result = await window.reconbot.startIpEnrichment({
        originalTarget: primaryTarget,
        resolvedIp: resolvedIp.ip,
        hostname: resolvedIp.hostname,
        scanMode: mode
      });
    } catch (error) {
      setMessage(`Failed to start IP enrichment: ${error instanceof Error ? error.message : String(error)}`);
      setIpPromptState("ask");
      return;
    }
    setMessage(result.ok ? result.message || `Started IP enrichment for ${primaryTarget}: ${result.configPath}` : result.error || "Failed to start IP enrichment");
    if (!result.ok) setIpPromptState("ask");
  }, [changeActiveView, resolvedIp, runState.target, scanConfig]);

  const acceptIpEnrichment = useCallback((mode: "quick" | "detailed" = "quick") => {
    void startIpEnrichmentScan(mode);
  }, [startIpEnrichmentScan]);

  const loadHistoricalRun = useCallback(async (runDir: string, destination: ActiveView = "dashboard") => {
    if (!window.reconbot?.selectScanHistoryRun) {
      setMessage("Geçmiş tarama yükleme IPC metodu mevcut değil.");
      return;
    }
    let result;
    try {
      result = await window.reconbot.selectScanHistoryRun(runDir);
    } catch (error) {
      setMessage(t("Could not load historical scan: {detail}", { detail: error instanceof Error ? error.message : String(error) }));
      return;
    }
    if (!result.ok || !result.snapshot) {
      setMessage(result.error || "Geçmiş tarama yüklenemedi.");
      return;
    }
    const snapshot = normalizeRunState(result.snapshot);
    setRunState(snapshot);
    setHistoricalRun({
      runDir,
      target: snapshot.target || "unknown target",
      label: `${snapshot.target || "unknown target"} · ${new Date(snapshot.updatedAt).toLocaleString("tr-TR")}`
    });
    setMessage(t("History loaded: {target}", { target: snapshot.target || runDir }));
    setAiBrief("");
    changeActiveView(destination, `history-selection:${destination}`);
  }, [changeActiveView]);

  const rescanHistoricalTarget = useCallback(() => {
    if (!historicalRun || !scanConfig) return;
    handleScanConfigChange({ ...scanConfig, target: historicalRun.target });
    changeActiveView("configure", "historical-rescan");
    setMessage(t("Target ready for a new scan: {target}", { target: historicalRun.target }));
  }, [changeActiveView, handleScanConfigChange, historicalRun, scanConfig]);

  useEffect(() => {
    const status = ipStatusLabel(ipPromptState, runState.ipEnrichment);
    if (status === "skipped") setIpPromptState("ignored");
    if (status === "running" || status === "done" || status === "error") setIpPromptState("accepted");
  }, [ipPromptState, runState.ipEnrichment]);

  const ipEnrichmentStatus = ipStatusLabel(ipPromptState, runState.ipEnrichment);
  const ipEnrichmentStatusText = ipStatusText(ipEnrichmentStatus, runState.ipEnrichment);

  useEffect(() => {
    const previousStatus = lastIpStatusRef.current;
    lastIpStatusRef.current = ipEnrichmentStatus;
    if (!isFinalIpStatus(ipEnrichmentStatus) || !runState.report.exists || !runState.report.mtime) return;

    const endedAt = runState.ipEnrichment?.endedAt || runState.ipEnrichment?.startedAt || "";
    const reloadKey = [
      runState.currentRunDir,
      ipEnrichmentStatus,
      endedAt,
      String(runState.report.mtime)
    ].join("|");
    if (lastReportUpdateRef.current === reloadKey) return;

    const transitionedFromActive = previousStatus === "queued" || previousStatus === "running";
    const reportChangedAfterFinal = isFinalIpStatus(previousStatus) && previousStatus === ipEnrichmentStatus;
    const firstFinalSnapshot = previousStatus === "" && Boolean(runState.ipEnrichment);
    if (!transitionedFromActive && !reportChangedAfterFinal && !firstFinalSnapshot) return;

    lastReportUpdateRef.current = reloadKey;
    setReportUpdateKey(reloadKey);
    setMessage("Report updated with IP enrichment");
  }, [
    ipEnrichmentStatus,
    runState.currentRunDir,
    runState.ipEnrichment,
    runState.report.exists,
    runState.report.mtime
  ]);

  const stopScan = useCallback(async () => {
    try {
      const result = await window.reconbot?.stopScan?.();
      setMessage(result?.message || result?.error || "Stop requested");
    } catch (error) {
      setMessage(`Stop request failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }, []);

  const navigate = useCallback((view: ActiveView) => {
    if (window.matchMedia("(max-width: 1280px)").matches) setAiPanelOpen(false);
    if (view === "terminal") setTerminalMounted(true);
    changeActiveView(view, `sidebar:${view}`);
  }, [changeActiveView]);

  const openAiWithQuestion = useCallback((mode: string, question: string, source = "quick_action") => {
    setAiInitialMode(mode);
    setAiInitialQuestion(question);
    setAiInitialSource(source);
    setAiInitialPromptId((value) => value + 1);
    setAiPanelOpen(true);
  }, []);

  const openAiSettings = useCallback(() => {
    setAiPanelOpen(false);
    changeActiveView("settings", "copilot-settings");
  }, [changeActiveView]);

  const disableAi = useCallback(() => {
    if (!scanConfig) return;
    const nextConfig = { ...scanConfig, ai: { ...scanConfig.ai, enabled: false } };
    handleScanConfigChange(nextConfig);
    setAiConnection(disabledAiStatus(nextConfig.ai));
    setMessage("AI devre dışı. ReconBot normal çalışmaya devam eder.");
  }, [handleScanConfigChange, scanConfig]);

  const testAiConnection = useCallback(async (announce = true, force = true) => {
    if (!scanConfig) return null;
    if (!window.reconbot?.aiRequest) {
      const failed = unavailableAiStatus(scanConfig.ai);
      setAiConnection(failed);
      if (announce) setMessage(failed.user_message_tr);
      return failed;
    }
    const requestConfig = aiConfigForRequest(scanConfig.ai);
    const statusKey = [
      requestConfig.enabled,
      requestConfig.provider,
      requestConfig.baseUrl,
      getEffectiveAiModel(requestConfig),
      requestConfig.apiKeyEnv,
      requestConfig.timeout
    ].join("|");
    if (!requestConfig.enabled) {
      const disabled = disabledAiStatus(requestConfig);
      setAiConnection(disabled);
      if (announce) setMessage(disabled.user_message_tr);
      return disabled;
    }
    const cached = aiStatusCacheRef.current;
    if (!force && cached?.key === statusKey && Date.now() - cached.checkedAt < AI_STATUS_TTL_MS) {
      setAiConnection(cached.status);
      if (announce) setMessage(cached.status.user_message_tr);
      return cached.status;
    }
    if (aiStatusInFlightRef.current?.key === statusKey) {
      const reused = await aiStatusInFlightRef.current.promise;
      if (reused && announce) setMessage(reused.user_message_tr);
      return reused;
    }
    latestAiStatusKeyRef.current = statusKey;
    setAiConnection(checkingAiStatus(requestConfig));
    const promise = window.reconbot.aiRequest({
      action: "status",
      aiConfig: requestConfig,
      settings: {
        scan_profile: scanConfig.scanProfile,
        osint_profile: scanConfig.osintProfile,
        tool_settings: scanConfig.toolSettings
      }
    }).then((response) => {
      const status = aiStatusFromResponse(response, requestConfig);
      aiStatusCacheRef.current = { key: statusKey, status, checkedAt: Date.now() };
      if (latestAiStatusKeyRef.current === statusKey) {
        setAiConnection(status);
        if (announce) setMessage(status.user_message_tr);
      }
      return status;
    }).catch((error) => {
      const status = unavailableAiStatus(requestConfig, `AI durumu okunamadı: ${error instanceof Error ? error.message : String(error)}`);
      if (latestAiStatusKeyRef.current === statusKey) {
        setAiConnection(status);
        if (announce) setMessage(status.user_message_tr);
      }
      return status;
    }).finally(() => {
      if (aiStatusInFlightRef.current?.key === statusKey) aiStatusInFlightRef.current = null;
    });
    aiStatusInFlightRef.current = { key: statusKey, promise };
    return promise;
  }, [scanConfig]);

  useEffect(() => {
    if (!scanConfig) return;
    if (aiStatusTimerRef.current) window.clearTimeout(aiStatusTimerRef.current);
    const requestConfig = aiConfigForRequest(scanConfig.ai);
    if (!requestConfig.enabled) {
      setAiConnection(disabledAiStatus(requestConfig));
      return;
    }
    if (aiConnection) {
      const availableModels = aiStatusAvailableModels(aiConnection);
      const previousTestedModel = aiConnection.testedModel || aiConnection.tested_model || aiConnection.model;
      const testedModelStillCurrent = previousTestedModel === getEffectiveAiModel(requestConfig)
        && aiConnection.baseUrl === requestConfig.baseUrl
        && aiConnection.provider === requestConfig.provider;
      const selectedModelAvailable = availableModels.length ? availableModels.includes(getEffectiveAiModel(requestConfig)) : undefined;
      setAiConnection({
        ...aiConnection,
        enabled: requestConfig.enabled,
        provider: requestConfig.provider,
        baseUrl: requestConfig.baseUrl,
        model: getEffectiveAiModel(requestConfig),
        selectedModel: requestConfig.selectedModel,
        manualModelName: requestConfig.manualModelName,
        effectiveModel: getEffectiveAiModel(requestConfig),
        effective_model: getEffectiveAiModel(requestConfig),
        testedModel: testedModelStillCurrent ? previousTestedModel : undefined,
        tested_model: testedModelStillCurrent ? previousTestedModel : undefined,
        selectedModelAvailable,
        selected_model_available: selectedModelAvailable,
        connection: "needs_recheck",
        ready: false,
        can_chat: false,
        reason: "ai_config_changed",
        user_message_tr: "AI ayarları değişti; bağlantı tekrar kontrol edilmeli.",
        operator_action_tr: "Model/baseUrl değiştiği için bağlantı testi tekrar gerekli.",
        setup_hint_tr: "Bu durum chat isteği göndermez; yalnız /models health check planlanır.",
        available_models: availableModels,
        checked_at: new Date().toISOString()
      });
    }
    aiStatusTimerRef.current = window.setTimeout(() => {
      void testAiConnection(false, false);
    }, AI_STATUS_DEBOUNCE_MS);
    return () => {
      if (aiStatusTimerRef.current) window.clearTimeout(aiStatusTimerRef.current);
    };
  }, [aiConfigKey]);

  if (!defaults || !scanConfig) {
    return (
      <main className="app-shell loading-shell">
        <section className="loading">
          <div className="bot-mark large" aria-hidden="true"><span /></div>
          <strong>{t("ReconBot Operator Console")}</strong>
          <span>{t("Loading desktop cockpit")}</span>
        </section>
      </main>
    );
  }

  const showIpModal = Boolean(ipPromptState === "ask" && resolvedIp?.available && resolvedIp.ip);
  const modalHostname = resolvedIp?.hostname || scanConfig.target.trim();
  const visibleAiStatus = runtimeAiStatus(aiConnection, aiRuntimeState, aiConfigForRequest(scanConfig.ai), aiReasoningWithoutFinalCount);

  return (
    <main className="app-shell" data-ai-open={aiPanelOpen} style={{ "--copilot-width": `${copilotWidth}px` } as import("react").CSSProperties}>
      <Sidebar
        activeView={activeView}
        runState={runState}
        aiSessionStarted={aiSessionStarted}
        aiStatus={visibleAiStatus}
        aiStatusLabel={aiStatusLabel(visibleAiStatus)}
        aiModel={effectiveAiModel}
        aiSuggestionReady={aiSuggestionReady}
        aiReportPromptEnabled={scanConfig.ai.autoBriefOnReportReady}
        onNavigate={navigate}
        onOpenAi={() => setAiPanelOpen(true)}
        onOpenAiSetup={() => setAiSetupOpen(true)}
        onOpenAiSettings={openAiSettings}
        onTestAiConnection={() => { void testAiConnection(true); }}
        onAiQuickAction={(mode, question) => openAiWithQuestion(mode, question, "quick_action")}
      />

      <section className="workspace">
        <StatusBar runState={runState} config={scanConfig} />
        <div className="notice-bar">
          <span className={runState.runState === "running" ? "dot live" : "dot"} />
          <span>{message.startsWith("History loaded: ") ? t("History loaded: {target}", { target: message.slice(16) }) : message.startsWith("Following run: ") ? t("Following run: {path}", { path: message.slice(15) }) : t(message)}</span>
          {historicalRun && (
            <button type="button" className="notice-action" title={historicalRun.target} onClick={rescanHistoricalTarget}>
              {t("Rescan target")}</button>
          )}
          {ipEnrichmentStatusText && (
            <span className={`ip-status-pill status-${ipEnrichmentStatus}`}>
              {ipEnrichmentStatusText}
            </span>
          )}
        </div>

        <ErrorBoundary title={t("App bölümü yüklenemedi")}>
          <div className="view-stack">
            <section data-view="dashboard" hidden={activeView !== "dashboard"} aria-hidden={activeView !== "dashboard"} className={`view-pane ${activeView === "dashboard" ? "active" : "inactive"}`}>
              <DashboardPane
                model={operatorModel}
                onOpenGraph={id => { setGraphFocus(id || ""); changeActiveView("pipeline", "dashboard:graph"); }}
                runState={runState}
                telemetry={telemetry}
                terminalBuffer={terminalBuffer}
                onNavigate={navigate}
              />
            </section>

            <section data-view="configure" hidden={activeView !== "configure"} aria-hidden={activeView !== "configure"} className={`view-pane ${activeView === "configure" ? "active" : "inactive"}`}>
              <ConfigurePane
                defaults={defaults}
                config={scanConfig}
                runState={runState}
                statusMessage={message}
                resolvedIp={resolvedIp}
                ipPromptState={ipPromptState}
                onChange={handleScanConfigChange}
                onStart={startScan}
                onStop={stopScan}
                canStart={canStart}
              />
            </section>

            {terminalMounted && (
              <section data-view="terminal" hidden={activeView !== "terminal"} aria-hidden={activeView !== "terminal"} className={`view-pane ${activeView === "terminal" ? "active" : "inactive"}`}>
                <TerminalPane active={activeView === "terminal"} runState={runState} onStop={stopScan} />
              </section>
            )}

            <section data-view="report" hidden={activeView !== "report"} aria-hidden={activeView !== "report"} className={`view-pane ${activeView === "report" ? "active" : "inactive"}`}>
              <ErrorBoundary
                title={t("Report bölümü yüklenemedi")}
                resetKey={`${runState.currentRunDir}|${runState.report.path}|${runState.report.viewUrl}`}
                runDir={runState.currentRunDir}
                onRetry={refreshRunState}
                onReturnDashboard={() => changeActiveView("dashboard", "report-error:return-dashboard")}
              >
                <ReportPane
                  runState={runState}
                  updateKey={reportUpdateKey}
                  updateMessage={t("Report updated with IP enrichment")}
                  onAskAi={(mode, question) => openAiWithQuestion(mode, question, "report_button")}
                  onNavigateValidation={() => changeActiveView("validation", "report:sqlmap-evidence")}
                  onNavigateArtifacts={() => changeActiveView("artifacts", "report-missing:go-artifacts")}
                  onRefreshState={() => { void refreshRunState(); }}
                />
              </ErrorBoundary>
            </section>

            <section data-view="artifacts" hidden={activeView !== "artifacts"} aria-hidden={activeView !== "artifacts"} className={`view-pane ${activeView === "artifacts" ? "active" : "inactive"}`}>
              <ErrorBoundary
                title={t("Artifacts bölümü yüklenemedi")}
                resetKey={`${runState.currentRunDir}|${runState.completeness}`}
                runDir={runState.currentRunDir}
                onRetry={() => {
                  void refreshRunState();
                  void refreshHistory();
                }}
                onReturnDashboard={() => changeActiveView("dashboard", "artifacts-error:return-dashboard")}
              >
                <ArtifactPane
                  runState={runState}
                  history={history}
                  onRefreshHistory={refreshHistory}
                  onSelectHistoryRun={loadHistoricalRun}
                />
              </ErrorBoundary>
            </section>

            <section data-view="findings" hidden={activeView !== "findings"} aria-hidden={activeView !== "findings"} className={`view-pane ${activeView === "findings" ? "active" : "inactive"}`}>
              <FindingsPane model={operatorModel} runKey={runState.currentRunDir} onValidateSqlmap={(url, findingId) => { setSqlmapSeed({ url, findingId, nonce: Date.now() }); changeActiveView("validation", "findings:sqlmap"); }} />
            </section>

            <section data-view="validation" hidden={activeView !== "validation"} aria-hidden={activeView !== "validation"} className={`view-pane ${activeView === "validation" ? "active" : "inactive"}`}>
              <SqlmapPane runDir={runState.currentRunDir} target={runState.target} active={activeView === "validation"} seed={sqlmapSeed} />
            </section>

            <section data-view="authentication" hidden={activeView !== "authentication"} aria-hidden={activeView !== "authentication"} className={`view-pane ${activeView === "authentication" ? "active" : "inactive"}`}>
              <AuthenticationPane runDir={runState.currentRunDir} target={runState.target} active={activeView === 'authentication'} />
            </section>

            <section data-view="pipeline" hidden={activeView !== "pipeline"} aria-hidden={activeView !== "pipeline"} className={`view-pane ${activeView === "pipeline" ? "active" : "inactive"}`}>
              <div className="pipeline-page">
                <ThreatPipeline runState={runState} model={operatorModel} variant="chain" active={activeView === "pipeline" && !aiPanelOpen} focusSignalId={graphFocus} />
              </div>
            </section>

            <section data-view="settings" hidden={activeView !== "settings"} aria-hidden={activeView !== "settings"} className={`view-pane ${activeView === "settings" ? "active" : "inactive"}`}>
              <SettingsPane
                defaults={defaults}
                config={scanConfig}
                aiStatus={visibleAiStatus}
                onChange={handleScanConfigChange}
                onTestAiConnection={() => { void testAiConnection(true); }}
                onOpenAiSetup={() => setAiSetupOpen(true)}
                onRejectAiSettingsValue={setMessage}
              />
            </section>
          </div>
        </ErrorBoundary>
      </section>

      {showIpModal && (
        <div className="modal-backdrop ip-enrichment-modal-backdrop" role="presentation">
          <section className="ip-enrichment-modal" role="dialog" aria-modal="true" aria-labelledby="ip-enrichment-title">
            <span className="micro-label">{t("Resolved IP detected:")}</span>
            <h2 id="ip-enrichment-title">{modalHostname} -&gt; {resolvedIp?.ip}</h2>
            <p>
              {t("The URL/domain scan remains the primary run. IP enrichment attaches auxiliary network context only.")}</p>
            <div className="modal-actions">
              <button type="button" onClick={ignoreIpEnrichment}>{t("Skip")}</button>
              <button type="button" className="primary" onClick={() => acceptIpEnrichment("quick")}>
                {t("Lightweight IP Enrichment")}</button>
              <button type="button" className="secondary-action" onClick={() => acceptIpEnrichment("detailed")}>
                {t("Detailed Nmap")}</button>
            </div>
          </section>
        </div>
      )}
      <ErrorBoundary title={t("AI paneli yüklenemedi")} compact>
        <AIAssistantPanel
          defaults={defaults}
          open={aiPanelOpen}
          width={copilotWidth}
          onResize={resizeCopilot}
          runState={runState}
          config={scanConfig}
          aiStatus={visibleAiStatus}
          brief={aiBrief}
          initialQuestion={aiInitialQuestion}
          initialMode={aiInitialMode}
          initialSource={aiInitialSource}
          initialPromptId={aiInitialPromptId}
          onClose={() => setAiPanelOpen(false)}
          onConfigChange={handleScanConfigChange}
          onTestConnection={() => { void testAiConnection(true); }}
          onOpenSettings={openAiSettings}
          onOpenSetupGuide={() => setAiSetupOpen(true)}
          onDisableAi={disableAi}
          onAiActivityChange={handleAiActivityChange}
          onStatus={(status) => {
            setAiSuggestionReady(status.includes("Ayar önerisi"));
            setMessage(status);
          }}
        />
        <AISetupGuide
          open={aiSetupOpen}
          aiConfig={scanConfig.ai}
          aiStatus={visibleAiStatus || undefined}
          onClose={() => setAiSetupOpen(false)}
          onTestConnection={() => { void testAiConnection(true); }}
          onOpenSettings={openAiSettings}
          onDisableAi={disableAi}
        />
      </ErrorBoundary>
    </main>
  );
}
