import fs from "node:fs";
import path from "node:path";
import type {
  AIRequest,
  AIRequestProgress,
  AIResponse,
  AIResponsePreferences,
  AISelectedFindingReference,
  ActionResult,
  HostTelemetry,
  RunStateSnapshot,
  ScanConfig,
  ScanHistoryItem
} from "../shared/api";
import { readRunStateSnapshot } from "./artifactWatcher";

export type E2EScenario =
  | "idle"
  | "historical"
  | "active-running"
  | "complete-report"
  | "complete-report-c"
  | "incomplete-partial"
  | "interrupted"
  | "report-failed"
  | "malformed-json"
  | "log-only";

const e2eRepoRoot = path.resolve(process.env.RECONBOT_REPO_ROOT || path.resolve(process.cwd(), ".."));
export const E2E_FIXTURE_RUNS_ROOT = path.join(e2eRepoRoot, "desktop", "e2e", "fixtures", "runs");
export const E2E_RUN_DIR = path.join(E2E_FIXTURE_RUNS_ROOT, "legacy-copilot-run");

const scenarioRunNames: Partial<Record<E2EScenario, string>> = {
  historical: "legacy-copilot-run",
  "active-running": "active-running-run",
  "complete-report": "complete-report-run",
  "complete-report-c": "complete-report-run-c",
  "incomplete-partial": "incomplete-partial-run",
  interrupted: "interrupted-run",
  "report-failed": "report-failed-run",
  "malformed-json": "malformed-json-run",
  "log-only": "log-only-run"
};

const idleSnapshot: RunStateSnapshot = {
  currentRunDir: "",
  runState: "idle",
  isHistorical: false,
  completeness: "empty",
  processAttached: false,
  artifacts: {
    availableCount: 0,
    availableFiles: [],
    missingExpected: [],
    paths: { runDir: "", rawLog: "", stateJson: "", stagesJson: "", configOrRequest: "", report: "" },
    exists: { runDir: false, rawLog: false, stateJson: false, stagesJson: false, configOrRequest: false, report: false }
  },
  target: "",
  profile: "fast",
  risk: { score: null, label: "pending", source: "e2e_fixture" },
  decision: { summary: "No run selected", firstAction: "Set a target", strongestPath: "", source: "e2e_fixture" },
  currentStage: "idle",
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
  report: { exists: false, mtime: 0, path: "", viewUrl: "", status: "missing", failureReason: "" },
  logTail: [],
  updatedAt: "2026-07-15T09:00:00.000Z"
};

const historicalSnapshot: RunStateSnapshot = {
  currentRunDir: E2E_RUN_DIR,
  currentRunResult: {
    run_state: "interrupted",
    target: "http://localhost:8082",
    profile: "fast",
    risk_score: 90,
    decision: { summary: "Interrupted run with operator validation required." },
    source_health: { score: 42, status: "partial" }
  },
  runState: "interrupted",
  isHistorical: true,
  completeness: "report_ready",
  processAttached: false,
  artifacts: {
    availableCount: 4,
    availableFiles: ["reconbot.log", "report.html", "run_result.json", "stages_live.json"],
    missingExpected: [],
    paths: {
      runDir: E2E_RUN_DIR,
      rawLog: `${E2E_RUN_DIR}/reconbot.log`,
      stateJson: `${E2E_RUN_DIR}/run_result.json`,
      stagesJson: `${E2E_RUN_DIR}/stages_live.json`,
      configOrRequest: "",
      report: `${E2E_RUN_DIR}/report.html`
    },
    exists: {
      runDir: true,
      rawLog: true,
      stateJson: true,
      stagesJson: true,
      configOrRequest: false,
      report: true
    }
  },
  target: "http://localhost:8082",
  profile: "fast",
  risk: { score: 90, label: "critical", source: "e2e_fixture" },
  decision: {
    summary: "Interrupted run; available evidence is partial.",
    firstAction: "Validate the reported Nuclei match manually.",
    strongestPath: "http://localhost:8082/admin",
    source: "e2e_fixture"
  },
  currentStage: "nuclei",
  stages: [
    { name: "katana", label: "Katana", status: "done", metric: "12 URLs", reason: "fixture" },
    { name: "nuclei", label: "Nuclei", status: "interrupted", metric: "3 findings", reason: "operator stopped run" }
  ],
  metrics: {
    katanaCount: 12,
    gobusterHits: 2,
    ffufHits: 1,
    checksCount: 4,
    checksLogin: 1,
    checksDocs: 1,
    checksCaptcha: 0,
    checksRatelimit: 1,
    nucleiFindings: 3,
    screenshotsCount: 2
  },
  findings: [
    {
      name: "E2E exposed admin surface",
      severity: "critical",
      templateId: "e2e-admin-panel",
      matchedAt: "http://localhost:8082/admin",
      source: "nuclei",
      tags: ["panel", "fixture"],
      validation: "unvalidated",
      operatorValidationRequired: true,
      confidence: "medium"
    },
    {
      name: "E2E file read template match",
      severity: "critical",
      templateId: "e2e-file-read",
      matchedAt: "http://localhost:8082/evidence/read",
      source: "nuclei",
      tags: ["file", "fixture"],
      validation: "operator_validation_required",
      operatorValidationRequired: true,
      confidence: "medium",
      verificationState: "unverified",
      statusCode: 200,
      responseEvidencePresent: true,
      missingEvidenceFields: ["product_fingerprint", "explicit_validation_evidence"]
    },
    {
      name: "E2E header disclosure template match",
      severity: "high",
      templateId: "e2e-header-disclosure",
      matchedAt: "http://localhost:8082/",
      source: "nuclei",
      tags: ["headers", "fixture"],
      validation: "operator_validation_required",
      operatorValidationRequired: true,
      confidence: "low",
      verificationState: "unverified",
      missingEvidenceFields: ["status_or_redirect", "product_fingerprint", "explicit_validation_evidence"]
    }
  ],
  report: {
    exists: true,
    mtime: 1_752_568_000_000,
    path: `${E2E_RUN_DIR}/report.html`,
    viewUrl: "reconbot-report://run/report.html",
    status: "ready",
    failureReason: ""
  },
  osint: { enabled: true, status: "partial", mode: "safe_mvp", totalSignals: 3, riskScoreImpact: "none" },
  logTail: ["[info] deterministic E2E run", "[warn] run interrupted by operator"],
  updatedAt: "2026-07-15T09:20:00.000Z"
};

const historyItem: ScanHistoryItem = {
  runDir: E2E_RUN_DIR,
  displayName: "localhost:8082 — 15 Temmuz",
  target: "http://localhost:8082",
  dateLabel: "15 Temmuz",
  timeLabel: "12:20",
  risk: historicalSnapshot.risk,
  reportReady: true,
  runState: "interrupted",
  isHistorical: true,
  completeness: "report_ready",
  processAttached: false,
  updatedAt: historicalSnapshot.updatedAt,
  paths: {
    report: historicalSnapshot.report.path,
    rawLog: `${E2E_RUN_DIR}/reconbot.log`,
    stateJson: `${E2E_RUN_DIR}/run_result.json`,
    stagesJson: `${E2E_RUN_DIR}/stages_live.json`,
    configOrRequest: ""
  },
  exists: historicalSnapshot.artifacts?.exists
};

function runDirForScenario(scenario: E2EScenario): string {
  const name = scenarioRunNames[scenario];
  return name ? path.join(E2E_FIXTURE_RUNS_ROOT, name) : "";
}

function filesystemSnapshot(scenario: E2EScenario, selectedFromHistory = false): RunStateSnapshot {
  if (scenario === "idle") return structuredClone(idleSnapshot);
  if (scenario === "historical") return structuredClone(historicalSnapshot);
  const runDir = runDirForScenario(scenario);
  const processAttached = scenario === "active-running" && !selectedFromHistory;
  return readRunStateSnapshot(runDir, selectedFromHistory || !processAttached, processAttached);
}

function scenarioForRunDir(runDir: string): E2EScenario | null {
  const resolved = path.resolve(runDir);
  for (const [scenario, name] of Object.entries(scenarioRunNames) as Array<[E2EScenario, string]>) {
    if (resolved === path.join(E2E_FIXTURE_RUNS_ROOT, name)) return scenario;
  }
  return null;
}

function historyFromSnapshot(snapshot: RunStateSnapshot): ScanHistoryItem {
  const displayTarget = snapshot.target || "unknown target";
  return {
    runDir: snapshot.currentRunDir,
    displayName: `${displayTarget.replace(/^https?:\/\//i, "")} — fixture`,
    target: displayTarget,
    dateLabel: "fixture",
    timeLabel: "12:57",
    risk: snapshot.risk,
    reportReady: snapshot.report.exists,
    runState: snapshot.runState,
    isHistorical: true,
    completeness: snapshot.completeness,
    processAttached: false,
    updatedAt: snapshot.updatedAt,
    paths: {
      report: snapshot.report.path,
      rawLog: snapshot.artifacts?.paths.rawLog || "",
      stateJson: snapshot.artifacts?.paths.stateJson || "",
      stagesJson: snapshot.artifacts?.paths.stagesJson || "",
      configOrRequest: snapshot.artifacts?.paths.configOrRequest || ""
    },
    exists: snapshot.artifacts?.exists
  };
}

const readyStatus = {
  enabled: true,
  provider: "openai_compatible",
  baseUrl: "http://127.0.0.1:1234/v1",
  model: "mistralai/mistral-7b-instruct-v0.3",
  selectedModel: "mistralai/mistral-7b-instruct-v0.3",
  effectiveModel: "mistralai/mistral-7b-instruct-v0.3",
  connection: "ready" as const,
  ready: true,
  can_chat: true,
  user_message_tr: "E2E fixture model ready.",
  operator_action_tr: "Chat is available.",
  setup_hint_tr: "Deterministic E2E fixture.",
  checked_at: "2026-07-15T09:00:00.000Z",
  available_models: ["mistralai/mistral-7b-instruct-v0.3", "qwen/qwen3-8b"],
  endpoint_debug: {
    httpStatus: 200,
    endpointPath: "/models + /api/v1/models",
    modelMetadata: {
      loadedContextLength: 8192,
      modelMaxContextLength: 32768,
      contextMetadataSource: "lm_studio_loaded_instance",
      loadedState: true,
      type: "llm",
      capabilities: { reasoning: false },
      supportedReasoningFields: []
    }
  }
};

type FixtureConversationFinding = AISelectedFindingReference & { url?: string };

const genericFindingTokens = new Set([
  "remote", "code", "execution", "rce", "file", "read", "exposure", "disclosure",
  "vulnerability", "finding", "bulgu", "template", "match", "nuclei", "critical", "high",
]);

function normalizedIdentity(value: string): string {
  return value.toLocaleLowerCase("tr-TR").replace(/[^a-z0-9çğıöşü]+/gi, " ").trim();
}

function runConversationFindings(request: AIRequest): FixtureConversationFinding[] {
  const findings: FixtureConversationFinding[] = [];
  const append = (raw: Record<string, unknown>, ordinal: number, runId: string): void => {
    const info = raw.info && typeof raw.info === "object" ? raw.info as Record<string, unknown> : {};
    const title = String(raw.title || raw.name || info.name || raw.template_id || raw["template-id"] || "").trim();
    if (!title) return;
    const templateId = String(raw.template_id || raw["template-id"] || raw.templateId || "").trim();
    findings.push({
      finding_id: String(raw.id || raw.finding_id || templateId),
      template_id: templateId,
      title,
      source: String(raw.source || raw.tool || "nuclei"),
      ordinal,
      run_id: runId,
      url: String(raw.matched_url || raw["matched-at"] || raw.matchedAt || raw.url || ""),
    });
  };
  const runId = path.basename(String(request.runDir || request.run_id || ""));
  try {
    const runResult = JSON.parse(fs.readFileSync(path.join(String(request.runDir || ""), "run_result.json"), "utf8")) as Record<string, unknown>;
    const nuclei = runResult.nuclei && typeof runResult.nuclei === "object" ? runResult.nuclei as Record<string, unknown> : {};
    const rawFindings = Array.isArray(nuclei.findings) ? nuclei.findings : [];
    rawFindings.forEach((finding, index) => {
      if (!finding || typeof finding !== "object") return;
      const before = findings.length;
      append(finding as Record<string, unknown>, index + 1, runId);
      const candidate = findings.at(-1);
      if (findings.length > before && candidate && findings.slice(0, -1).some((item) =>
        (candidate.template_id && item.template_id === candidate.template_id)
        || normalizedIdentity(item.title) === normalizedIdentity(candidate.title)
      )) findings.pop();
    });
  } catch {
    // Some fixture scenarios intentionally have no complete run_result.json.
  }
  const contextFindings = request.aiRunContext?.top_findings;
  if (!findings.length && Array.isArray(contextFindings)) {
    contextFindings.forEach((finding, index) => append(finding as unknown as Record<string, unknown>, index + 1, runId));
  }
  return findings;
}

function explicitFindingMatches(findings: FixtureConversationFinding[], text: string): FixtureConversationFinding[] {
  const normalizedText = normalizedIdentity(text);
  const textTokens = new Set(normalizedText.split(" "));
  const tokensByFinding = findings.map((finding) => new Set(
    normalizedIdentity(finding.title).split(" ").filter((token) => token.length >= 4 && !genericFindingTokens.has(token)),
  ));
  const tokenCounts = new Map<string, number>();
  tokensByFinding.forEach((tokens) => tokens.forEach((token) => tokenCounts.set(token, (tokenCounts.get(token) || 0) + 1)));
  return findings.filter((finding, index) => {
    const title = normalizedIdentity(finding.title);
    const templateId = normalizedIdentity(finding.template_id || "");
    return Boolean(
      (finding.url && text.toLocaleLowerCase("tr-TR").includes(finding.url.toLocaleLowerCase("tr-TR")))
      || (title.length >= 6 && normalizedText.includes(title))
      || (templateId.length >= 4 && normalizedText.includes(templateId))
      || [...tokensByFinding[index]].some((token) => tokenCounts.get(token) === 1 && textTokens.has(token))
    );
  });
}

function findingOrdinal(text: string): number | null {
  const normalized = text.toLocaleLowerCase("tr-TR");
  const words: Array<[RegExp, number]> = [
    [/\b(?:ilk\s+bulgu(?:yu|nun|ya)?|birinci|birincisi)\b/i, 1],
    [/\b(?:ikinci(?:\s+bulgu(?:yu|nun|ya)?)?|ikincisi|ikinciyi)\b/i, 2],
    [/\b(?:üçüncü|üçüncüsü)\b/i, 3],
    [/\b(?:dördüncü|dördüncüsü)\b/i, 4],
    [/\b(?:beşinci|beşincisi)\b/i, 5],
  ];
  for (const [pattern, ordinal] of words) if (pattern.test(normalized)) return ordinal;
  const numeric = normalized.match(/\b(\d{1,2})\s*\.\s*(?:s[ıi](?:n[ıi])?|si(?:ni)?|sü(?:nü)?|bulgu(?:yu|nun|ya)?)\b/i);
  return numeric ? Number(numeric[1]) : null;
}

function resolveFixtureFinding(
  request: AIRequest,
  question: string,
): { finding: FixtureConversationFinding; reason: "title" | "ordinal" | "history" | "reference" } | null {
  const findings = runConversationFindings(request);
  const latestMatches = explicitFindingMatches(findings, question);
  if (latestMatches.length === 1) return { finding: latestMatches[0], reason: "title" };
  const primaryCount = request.aiRunContext?.top_findings?.length || findings.length;
  const ordinal = findingOrdinal(question);
  if (ordinal && ordinal <= primaryCount && findings[ordinal - 1]) return { finding: findings[ordinal - 1], reason: "ordinal" };
  const reference = request.selected_finding_reference;
  if (reference) {
    const referenced = findings.find((finding) =>
      (reference.template_id && finding.template_id === reference.template_id)
      || (reference.finding_id && finding.finding_id === reference.finding_id)
      || normalizedIdentity(reference.title) === normalizedIdentity(finding.title)
    );
    if (referenced) return { finding: referenced, reason: "reference" };
  }
  const history = [...(request.conversation_history || [])].reverse();
  for (const turn of history) {
    if (turn.role !== "user") continue;
    const matches = explicitFindingMatches(findings, turn.content);
    if (matches.length === 1) return { finding: matches[0], reason: "history" };
  }
  return null;
}

function planFor(request: AIRequest) {
  const chars = String(request.question || request.user_message || "").length;
  const question = String(request.question || request.user_message || "").toLocaleLowerCase("tr-TR");
  const countMatch = question.match(/\b(?:ilk\s+)?(\d{1,2})\s*(?:maddelik|maddede|madde|ad[ıi]ml[ıi]k|ad[ıi]m|öneri|yol|bulgu|neden|sebep)/i);
  const requestedItemCount = countMatch ? Math.min(10, Math.max(1, Number(countMatch[1]))) : null;
  const requestedFormat = countMatch
    ? (/ad[ıi]m/i.test(countMatch[0]) ? "numbered_list" : "list")
    : /(?:tek\s+)?paragraf\s+(?:halinde|olarak|biçiminde)/i.test(question)
      ? "paragraph"
      : null;
  const responsePreferences: AIResponsePreferences = {
    requested_item_count: requestedItemCount,
    requested_format: requestedFormat,
    single_sentence: /\b(?:tek|bir|1)\s+cümle(?:de|lik)?\b/i.test(question),
    short_answer: /\b(?:k[ıi]sa\s+cevap|k[ıi]saca|özetle)\b/i.test(question),
    no_heading: /(?:ba[şs]l[ıi]k\s+(?:kullanma|olmas[ıi]n)|ba[şs]l[ıi]ks[ıi]z)/i.test(question),
  } as const;
  const explicitPlan = /(?:\b\d{1,2}\s*ad[ıi]ml[ıi]k\b|\bad[ıi]m\s+ad[ıi]m\b|\bs[ıi]rayla\b[^?.!]{0,80}\bad[ıi]m|\bplan\w*\b[^?.!]{0,40}\b(?:ver|haz[ıi]rla|olu[şs]tur|dönü[şs]tür|yaz))/i.test(question);
  const operationalGuidance = /(?:\bnas[ıi]l\b[^?.!]{0,70}\b(?:do[ğg]rula|kontrol|test|incele|teyit)|\bhangi\s+ad[ıi]mlar[ıi]\s+izle|\b(?:ilk\s+)?ne\s+yapmal[ıi]y[ıi]m)/i.test(question);
  const selectedFindingExplanation = Boolean(request.selected_finding_reference)
    && /(?:false[- ]?positive|yanl[ıi]ş\s+pozitif|bulgu|eşleşme|zafiyet)/i.test(question);
  const answerIntent = /(detaylı|ayrıntılı|deep|geniş analiz)/i.test(question)
    ? "deep_analysis"
    : explicitPlan
      ? "numbered_action_plan"
      : operationalGuidance
        ? "operational_guidance"
      : request.contextProfile === "finding_question" || request.contextProfile === "continuation" || selectedFindingExplanation
        ? "finding_question"
      : request.contextProfile === "report_summary" || /(özet|özetle|30 saniye|kısaca)/i.test(question)
        ? "short_summary"
        : "normal_question";
  const configCap = Math.max(64, Number(request.aiConfig?.maxOutputTokens || 2400));
  const loadedContextLength = 8192;
  const safetyMargin = 984;
  const mode = request.aiConfig?.responseMode || "adaptive";
  const configuredContextChars = Math.max(0, Number(request.aiConfig?.maxContextChars || 24000));
  const modeContextTarget = mode === "fast_operator" ? 3000 : mode === "deep_analysis" ? 9000 : 6000;
  const injectedContextChars = Math.min(configuredContextChars, modeContextTarget);
  const estimatedInput = 800 + Math.ceil((chars + injectedContextChars) / 3);
  const effectiveOutput = Math.min(configCap, 32768, Math.max(1, loadedContextLength - safetyMargin - estimatedInput));
  const outputLimitReason = effectiveOutput < configCap ? "loaded_context_window_and_request_input" : "";
  const configuredTimeout = Math.max(1, Number(request.aiConfig?.timeout || 60));
  const reasoningSupported = String(request.aiConfig?.model || "").includes("qwen") && request.aiConfig?.disableReasoning === false;
  const reasoningFields = reasoningSupported ? ["reasoning_effort"] : [];
  const reasoningConfigurationReason = request.aiConfig?.disableReasoning
    ? "disabled_by_user"
    : reasoningFields.length
      ? "supported_fields_sent"
      : "unsupported_by_selected_model_or_provider";
  return {
    modelProfile: "lightweight_instruct",
    answerIntent,
    contextProfile: request.contextProfile || "general_chat",
    userMessageChars: chars,
    injectedContextChars,
    estimatedInputTokens: estimatedInput,
    effectiveMaxOutputTokens: effectiveOutput,
    effectiveRequestTimeoutSec: configuredTimeout,
    totalProcessWatchdogSec: configuredTimeout * 5 + 65,
    disableReasoning: Boolean(request.aiConfig?.disableReasoning),
    retryPolicy: { maxAttempts: 4, contextLengthCompaction: 1, unknownHttp400Retries: 0, transportTimeoutRetries: 0 },
    contextWasCompacted: false,
    compatibilityNotes: ["deterministic_e2e_fixture"],
    estimatedContextWindowTokens: loadedContextLength,
    contextBudgetChars: injectedContextChars,
    compatible: true,
    incompatibilityReason: "",
    userMessageFits: true,
    historyTurnsReceived: Array.isArray(request.conversation_history) ? request.conversation_history.length : 0,
    historyTurnsSent: Math.min(10, Array.isArray(request.conversation_history) ? request.conversation_history.length : 0),
    historyWasCompacted: Array.isArray(request.conversation_history) && request.conversation_history.length > 10,
    historyBudgetChars: 4_000,
    outputBudgetReason: `Configured ceiling ${configCap}; effective ${effectiveOutput}; source user_settings; limit ${outputLimitReason || "none"}.`,
    systemPromptReserveTokens: 320,
    compactSystemPrompt: true,
    reservedOutputTokens: effectiveOutput,
    estimatedTotalTokens: estimatedInput + effectiveOutput,
    configuredMaxOutputTokens: configCap,
    configuredMaxContextChars: Number(request.aiConfig?.maxContextChars || 24000),
    effectiveInjectedContextChars: injectedContextChars,
    configuredTimeoutSec: configuredTimeout,
    loadedContextLength,
    modelMaxContextLength: 32768,
    contextMetadataSource: "lm_studio_loaded_instance",
    conservativeContextFallbackUsed: false,
    reservedSafetyMarginTokens: safetyMargin,
    outputValueSource: "user_settings",
    outputLimitReason,
    timeoutValueSource: "user_settings",
    timeoutLimitReason: "",
    providerTemperature: Number(request.aiConfig?.temperature || 0),
    reasoningFieldsSent: reasoningFields,
    providerPayloadFields: ["model", "messages", "temperature", "max_tokens", "stream", ...reasoningFields],
    estimatedHistoryTokens: Math.ceil((Array.isArray(request.conversation_history) ? JSON.stringify(request.conversation_history).length : 0) / 3),
    reasoningConfigurationReason,
    responsePreferences,
  };
}

export interface E2EFixture {
  calls: Array<{ channel: string; payload?: unknown }>;
  readRunState(): RunStateSnapshot;
  selectHistoricalRun(runDir?: string): { ok: true; message: string; snapshot: RunStateSnapshot };
  history(): ScanHistoryItem[];
  telemetry(): HostTelemetry;
  action(channel: string, payload?: unknown): ActionResult;
  ai(request: AIRequest, onProgress?: (progress: AIRequestProgress) => void): Promise<AIResponse>;
  setRunScenario(scenario: E2EScenario): void;
  currentRunDir(): string;
  snapshot(): { calls: Array<{ channel: string; payload?: unknown }>; scenario: string };
}

export function createE2EFixture(initialScenario: E2EScenario = "idle"): E2EFixture {
  let scenario = initialScenario;
  const calls: Array<{ channel: string; payload?: unknown }> = [];
  let cancelCurrent: (() => void) | null = null;
  const record = (channel: string, payload?: unknown): void => { calls.push({ channel, payload }); };
  const fixtureSnapshot = (): RunStateSnapshot => {
    const snapshot = filesystemSnapshot(scenario);
    const target = process.env.RECONBOT_E2E_LOOPBACK_TARGET;
    if (target) {
      const parsed = new URL(target);
      if (!['127.0.0.1', 'localhost'].includes(parsed.hostname) || parsed.protocol !== 'http:') throw new Error('E2E target overrides must use HTTP loopback.');
      return { ...snapshot, target };
    }
    return snapshot;
  };

  return {
    calls,
    readRunState: fixtureSnapshot,
    selectHistoricalRun: (requestedRunDir = E2E_RUN_DIR) => {
      const selectedScenario = scenarioForRunDir(requestedRunDir) || "historical";
      scenario = selectedScenario;
      record("history:select-run", requestedRunDir);
      const snapshot = selectedScenario === "historical"
        ? structuredClone(historicalSnapshot)
        : filesystemSnapshot(selectedScenario, true);
      return { ok: true, message: "Deterministic historical run loaded.", snapshot };
    },
    history: () => [
      structuredClone(historyItem),
      ...(["complete-report", "incomplete-partial", "interrupted", "report-failed", "malformed-json", "log-only"] as E2EScenario[])
        .map((item) => historyFromSnapshot(filesystemSnapshot(item, true)))
    ],
    telemetry: () => ({
      uptimeSeconds: 600,
      appUptimeSeconds: 30,
      cpuLoadPercent: 12,
      ramUsedPercent: 35,
      ramLabel: "E2E memory",
      ramDetail: "fixture",
      ramApproximate: false,
      diskUsedPercent: 22,
      netRxKBps: 1.2,
      netTxKBps: 0.8,
      freeMemoryBytes: 8_000_000_000,
      totalMemoryBytes: 16_000_000_000,
      network: "rx 1.2 KB/s · tx 0.8 KB/s",
      sampledAt: new Date().toISOString()
    }),
    action: (channel, payload) => {
      record(channel, payload);
      return { ok: true, message: `E2E mock handled ${channel}`, configPath: channel === "scan:start" ? "/reconbot-e2e/config.yaml" : undefined };
    },
    ai: async (request, onProgress) => {
      record("ai:request", request);
      if (request.action === "status") {
        const selectedModel = String(request.aiConfig?.model || readyStatus.model);
        const reasoning = selectedModel.includes("qwen");
        const status = {
          ...readyStatus,
          model: selectedModel,
          selectedModel,
          effectiveModel: selectedModel,
          testedModel: selectedModel,
          endpoint_debug: {
            ...readyStatus.endpoint_debug,
            modelMetadata: {
              loadedContextLength: 8192,
              modelMaxContextLength: reasoning ? 32768 : 32768,
              contextMetadataSource: "lm_studio_loaded_instance",
              loadedState: true,
              type: "llm",
              capabilities: { reasoning },
              supportedReasoningFields: reasoning ? ["reasoning_effort"] : []
            }
          }
        };
        return { ok: true, status: "ready", aiStatus: status, availableModels: readyStatus.available_models };
      }
      if (request.action === "cancel") {
        cancelCurrent?.();
        cancelCurrent = null;
        return { ok: true, answer: "İstek iptal edildi.", status: "cancelled" };
      }
      const question = String(request.question || request.user_message || "");
      const progress = (state: AIRequestProgress["state"], attempt: number): void => {
        onProgress?.({ request_id: request.request_id || "", state, attempt, timestamp: new Date().toISOString() });
      };
      const resolvedPlan = planFor(request);
      record("ai:plan", { request_id: request.request_id, latestQuestion: question, ...resolvedPlan });
      record("ai:python-config", { request_id: request.request_id, ...request.aiConfig });
      record("ai:provider-payload", {
        request_id: request.request_id,
        baseUrl: request.aiConfig?.baseUrl,
        model: request.aiConfig?.model,
        temperature: request.aiConfig?.temperature,
        configuredTimeoutSec: request.aiConfig?.timeout,
        responseMode: request.aiConfig?.responseMode,
        maxContextChars: request.aiConfig?.maxContextChars,
        apiKeyEnvName: request.aiConfig?.apiKeyEnv,
        max_tokens: resolvedPlan.effectiveMaxOutputTokens,
        stream: false,
        fields: resolvedPlan.providerPayloadFields,
        reasoningFields: resolvedPlan.reasoningFieldsSent,
      });
      const base: AIResponse = {
        ok: true,
        model: readyStatus.model,
        request_id: request.request_id,
        user_message: question,
        latest_user_message: question,
        request_plan: resolvedPlan,
        finish_reason: "stop",
        lm_request_sent: true,
        local_answer_generated: false,
        answer_source: "model",
        attempt_count: 1,
        transport_attempt_count: 1,
        answer_repair_attempt_count: 0,
        answer_repair_transport_attempt_count: 0,
        relevance_validation_result: "not_applicable",
        relevance_validation_reason: "",
        answer_intent: resolvedPlan.answerIntent,
        response_preferences: resolvedPlan.responsePreferences,
        context_profile: request.contextProfile,
        history_turns_sent: Math.min(10, Array.isArray(request.conversation_history) ? request.conversation_history.length : 0),
        history_compacted: Array.isArray(request.conversation_history) && request.conversation_history.length > 10,
        context_compacted: false,
      };
      const modelResponse = (answer: string, extras: Partial<AIResponse> = {}): AIResponse => ({
        ...base,
        ...extras,
        answer,
        endpoint_debug: {
          httpStatus: 200,
          endpointPath: "/chat/completions",
          providerPayloadFields: resolvedPlan.providerPayloadFields,
          providerMessages: [
            { role: "system", content: "You are ReconBot Operator Copilot." },
            ...(Array.isArray(request.conversation_history) ? request.conversation_history : []),
            { role: "user", content: question },
          ],
          rawProviderContent: answer,
          finishReason: String(extras.finish_reason || "stop"),
          providerTemperature: Number(request.aiConfig?.temperature || 0),
        },
      });
      progress("waiting_for_model", 1);
      if (question.includes("[[CANCEL]]")) {
        return new Promise((resolve) => {
          cancelCurrent = () => resolve({ ...base, ok: false, unavailable: true, status: "cancelled", answer: "İstek iptal edildi." });
        });
      }
      if (question.includes("[[DELAY_SUCCESS]]")) {
        await new Promise((resolve) => setTimeout(resolve, 450));
        return modelResponse("Gecikmeli fakat geçerli model yanıtı.");
      }
      if (question.includes("[[SLOW_STATUS]]")) {
        await new Promise((resolve) => setTimeout(resolve, 4000));
        progress("validating_answer", 1);
        await new Promise((resolve) => setTimeout(resolve, 800));
        progress("completed", 1);
        return { ...base, answer: "Yavaş fixture yanıtı tamamlandı; durum çubuğu chat kaydırmasından bağımsız kaldı." };
      }
      if (question.includes("[[TIMEOUT]]")) return { ...base, ok: false, unavailable: true, status: "model_timeout", answer: "Model yanıt süresi doldu; taslak korundu.", preserve_user_message: true };
      if (question.includes("[[CONTEXT]]")) return {
        ...base,
        ok: false,
        unavailable: true,
        status: "context_length_exceeded",
        answer: "Konuşma bağlamı modelin yüklü context sınırını aştı.",
        preserve_user_message: true,
        endpoint_debug: { httpStatus: 400, http400Category: "context_length_exceeded", providerMessage: "prompt tokens exceed context window" },
      };
      if (question.includes("[[MODEL_BUSY]]")) return { ...base, ok: false, unavailable: true, status: "model_busy", answer: "Model meşgul veya sırada; istek otomatik yeniden gönderilmedi.", preserve_user_message: true };
      if (question.includes("[[MALFORMED]]")) return { ...base, ok: false, unavailable: true, status: "invalid_response", answer: "Endpoint OpenAI chat completions formatına uymayan cevap döndürdü.", preserve_user_message: true };
      if (question.includes("[[MISMATCH]]")) return { ...base, request_id: "stale-response-id", answer: "Bu yanıt aktif isteğe ait değil." };
      if (question.includes("[[REASONING_ONLY]]") && request.retryTag !== "short_context") return { ...base, ok: false, unavailable: true, status: "reasoning_without_final", answer: "Model final cevap üretmedi.", preserve_user_message: true };
      if (question.includes("[[EMPTY]]")) return { ...base, answer: "" };
      if (question.includes("[[WHITESPACE]]")) return { ...base, answer: "   \n\t" };
      if (question.includes("[[REDACTED_ONLY]]")) return { ...base, answer: "[REDACTED]\nBazı hassas değerler güvenlik için gizlendi." };
      if (question.includes("[[TRUNCATED]]") && request.retryTag !== "continuation") return { ...base, answer: "Bu kısmi cevap kullanılabilir, fakat devamı token sınırına takıldı.", finish_reason: "length", output_truncated: true };
      if (question === "Devamını getir.") return { ...base, answer: "Önceki kısmi cevabın kaldığı yerden devamı; başlangıç tekrarlanmadı." };
      if (question === "Sadece evet yaz.") return modelResponse("Evet");
      if (question.includes("[[PRESERVE_CONTENT]]")) return modelResponse(question);
      if (question.includes("[[GENERIC_REPORT_REPAIR]]")) {
        record("lm:chat", { attempt: 1, answer: "Bu raporda farklı veri toplama yöntemleri değerlendirilmiştir." });
        record("lm:chat", { attempt: 1, repair: true, repairReason: "answer_not_relevant", latestQuestion: question });
        return {
          ...base,
          answer: "http://localhost:8082 taraması kesilmiş durumda; risk 90/100 ve artifactte 7 Nuclei eşleşmesi bulunuyor.",
          answer_source: "repaired_model",
          repair_attempted: true,
          repair_reason: "answer_not_relevant",
          attempt_count: 2,
          transport_attempt_count: 1,
          answer_repair_attempt_count: 1,
          answer_repair_transport_attempt_count: 1,
          relevance_validation_result: "passed_after_repair",
          relevance_validation_reason: "answer_not_relevant",
        };
      }
      if (question.includes("[[GENERIC_THEN_REPAIR]]")) {
        record("lm:chat", { attempt: 1, answer: "Run durumu: interrupted. Risk: 90. Operatör doğrulaması gerekir." });
        record("lm:chat", { attempt: 2, repair: true, latestQuestion: question });
        return { ...base, answer: "1. Kritik bulguyu doğrula.\n2. Etkilenen uç noktayı sınırla.\n3. Kanıtı kaydet.\n4. Düzeltmeyi uygula.\n5. Yeniden doğrula.", answer_source: "repaired_model", repair_attempted: true, repair_reason: "requested_items_missing", attempt_count: 2, transport_attempt_count: 1, answer_repair_attempt_count: 1, answer_repair_transport_attempt_count: 1 };
      }
      if (question.includes("[[PLACEHOLDER_REPAIR]]")) {
        record("lm:chat", { attempt: 1, answer: "Exploit Payload: <URL>\nBypass: [URL]\nKalıcılık: {{url}}" });
        record("lm:chat", { attempt: 2, repair: true, repairReason: "unresolved_placeholder_values", latestQuestion: question });
        return {
          ...base,
          answer: "Gerçek artifact URL: http://localhost:8082/admin\nE2E exposed admin surface kaydını matched request/response ile doğrula.",
          answer_source: "repaired_model",
          repair_attempted: true,
          repair_reason: "unresolved_placeholder_values",
          attempt_count: 2,
          transport_attempt_count: 1,
          answer_repair_attempt_count: 1,
          answer_repair_transport_attempt_count: 1,
        };
      }
      if (question.includes("[[PLACEHOLDER_FALLBACK]]")) {
        record("lm:chat", { attempt: 1, answer: "Exploit Payload: <URL>\nBypass: <URL>\nKalıcılık: <URL>" });
        record("lm:chat", { attempt: 2, repair: true, answer: "Endpoint: <URL>" });
        return {
          ...base,
          answer: [
            "1. E2E exposed admin surface kaydının template ve matched kanıtını aç.",
            "2. http://localhost:8082/admin için hedefe aitlik ve soft-error kontrolü yap.",
            "3. Etkiyi düşük etkili ve yetkili doğrulamayla sınırla.",
            "4. Doğrulanırsa ilgili config düzeltmesini ve sorumlu ekibi belirle.",
            "5. Aynı artifact URL ve template kanıtıyla yeniden test et.",
          ].join("\n"),
          answer_source: "local_fallback",
          local_answer_generated: true,
          fallback_reason: "unresolved_placeholder_values",
          repair_attempted: true,
          repair_reason: "unresolved_placeholder_values",
          attempt_count: 2,
          transport_attempt_count: 1,
          answer_repair_attempt_count: 1,
          answer_repair_transport_attempt_count: 1,
        };
      }
      if (question.includes("[[EMPTY_REPORT]]")) return { ...base, answer: "Yerel rapor özeti: run interrupted; bulgular manuel doğrulama gerektirir.", answer_source: "local_fallback", local_answer_generated: true, fallback_reason: "empty_message_content" };
      if (question.includes("[[REASONING_ONLY]]")) return { ...base, answer: "Final-only kısa context retry kullanılabilir bir yanıt üretti." };
      if (question.includes("[[TEN_LINES]]")) {
        return { ...base, answer: Array.from({ length: 10 }, (_, index) => `Normal görünür satır ${index + 1}`).join("\n") };
      }
      if (question.includes("[[BOTTOM_FALLBACK]]")) {
        return {
          ...base,
          answer: Array.from({ length: 20 }, (_, index) => `${index + 1}. E2E exposed admin surface doğrulama satırı ${index + 1}${index === 19 ? " · SON SATIR TAMAM" : ""}`).join("\n"),
          answer_source: "local_fallback",
          local_answer_generated: true,
          fallback_reason: "unresolved_placeholder_values",
          repair_attempted: true,
          repair_reason: "unresolved_placeholder_values",
          attempt_count: 2,
          transport_attempt_count: 1,
          answer_repair_attempt_count: 1,
          answer_repair_transport_attempt_count: 1,
        };
      }
      if (question.includes("[[LONG]]")) {
        const paragraph = "Uzun yanıt satırları kendi balonunda iç scroll üretmeden konuşma akışında yer almalı. ";
        return { ...base, answer: `${paragraph.repeat(150)}\nhttps://example.com/operator/reference/${"very-long-segment-".repeat(12)}end\n\n\`\`\`bash\nprintf 'safe fixture'\n\`\`\`` };
      }
      const selected = resolveFixtureFinding(request, question);
      if (selected) {
        const finding = selected.finding;
        const preferences = resolvedPlan.responsePreferences;
        let answer: string;
        if (/hangi\s+bulgu|konuştuğumuz\s+bulgu/i.test(question)) {
          answer = `${finding.title} bulgusu hakkında konuşuyorduk.`;
        } else if (preferences.requested_item_count) {
          answer = Array.from(
            { length: preferences.requested_item_count },
            (_, index) => `${index + 1}. ${finding.title} için soruyla ilgili anlamlı açıklama ${index + 1}.`,
          ).join("\n");
        } else if (/false[- ]?positive|yanl[ıi]ş\s+pozitif/i.test(question)) {
          answer = `${finding.title} ortak hata sayfası, yönlendirme veya ürün izi eksikliği aynı imzayı ürettiğinde false-positive olabilir.`;
        } else if (resolvedPlan.answerIntent === "numbered_action_plan") {
          answer = `1. ${finding.title} için artifact kanıtını aç.\n2. Gerçek yanıtı baseline ile karşılaştır.\n3. Hedefe aitliği doğrula.\n4. Sonucu kanıtla kaydet.`;
        } else if (resolvedPlan.answerIntent === "operational_guidance") {
          answer = `${finding.title} için önce gerçek yanıtı aynı hedefteki negatif baseline yanıtla karşılaştır.`;
        } else {
          answer = `${finding.title} henüz doğrulanmamış bir Nuclei template eşleşmesidir.`;
        }
        return modelResponse(answer, { selected_finding_reference: finding });
      }
      if (/false[- ]?positive|yanl[ıi]ş\s+pozitif/i.test(question)) {
        return modelResponse("Evet. Ortak hata sayfası, login yönlendirmesi veya ürün izinin bulunmaması false-positive ihtimalini artırır.");
      }
      if (question === "Üç bulguyu önem sırasına koy.") {
        return {
          ...base,
          answer: [
            "1. E2E exposed admin surface — critical — Nuclei template eşleşmesi — unverified — http://localhost:8082/admin",
            "2. E2E file read template match — critical — Nuclei template eşleşmesi — unverified — http://localhost:8082/evidence/read",
            "3. E2E header disclosure template match — high — Nuclei template eşleşmesi — unverified — http://localhost:8082/",
            "Bu kayıtlar henüz doğrulanmadı; false-positive ihtimali var ve artifactteki matched URL/response doğrulanmalı.",
          ].join("\n"),
        };
      }
      if (question === "2.sini biraz daha aç.") {
        return {
          ...base,
          answer: [
            "İkinci bulgu E2E file read template match başlıklı bir Nuclei template eşleşmesidir.",
            "Kaynak: nuclei · severity: critical · doğrulama: unverified.",
            "Artifactteki gerçek matched URL: http://localhost:8082/evidence/read · gözlenen HTTP status: 200.",
            "File-read etkisi henüz doğrulanmadı; false-positive ihtimali var. Artifactteki matched response doğrulanmalı; ürün fingerprinti ve explicit validation evidence eksik.",
          ].join("\n"),
        };
      }
      if (question === "1. dediğini nasıl kontrol edeceğim? Adım adım anlat.") {
        return {
          ...base,
          answer: [
            "Bu bulgu doğrulanmış bir zafiyet değil; unverified bir Nuclei template eşleşmesidir.",
            "1. Findings kaydındaki template kimliği, kaynak ve severity alanlarını artifact ile karşılaştır.",
            "2. Yalnız artifactteki http://localhost:8082/evidence/read matched URL’sinin hedefe ait olduğunu doğrula.",
            "3. Kaydedilmiş HTTP 200 yanıtını redirect, 404 ve soft-error davranışıyla karşılaştır; yeni endpoint üretme.",
            "4. Ürün fingerprinti ve explicit validation evidence eksikse file-read veya ürün kurulu sonucuna varma.",
            "5. False-positive ihtimalini kapatamıyorsan kaydı henüz doğrulanmadı olarak bırak ve savunma ekibine kanıt eksikleriyle ilet.",
          ].join("\n"),
        };
      }
      return modelResponse(`Doğrudan yanıt: ${question}\n\nBu interrupted run kısmi kanıt içeriyor; Nuclei bulgusu operatör doğrulaması gerektirir.`);
    },
    setRunScenario: (next) => { scenario = next; },
    currentRunDir: () => runDirForScenario(scenario),
    snapshot: () => ({ calls: structuredClone(calls), scenario })
  };
}

export function isE2EMode(): boolean {
  return process.env.RECONBOT_E2E === "1";
}

export function sanitizeE2EScanConfig(config: ScanConfig): ScanConfig {
  return structuredClone(config);
}
