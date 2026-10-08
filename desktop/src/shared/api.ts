import type { SqlmapRequest, SqlmapSnapshot } from "./sqlmap";
import type { AuthenticationRequest, AuthenticationSnapshot } from './authentication';
import type { WordlistSlot, WordlistPreferences, WordlistSaveResult } from './wordlists';

export type TrafficProfile = "safe" | "balanced" | "fast";
export type ScanProfile = "fast" | "balanced" | "slow" | "custom";
export type RunMode = "normal_scan_only" | "osint_only" | "normal_scan_plus_osint";
export type ReportDepth = "summary" | "balanced" | "deep";
export type AIResponseMode = "adaptive" | "fast_operator" | "deep_analysis";

export interface AIConfig {
  enabled: boolean;
  provider: "openai_compatible";
  baseUrl: string;
  model: string;
  selectedModel?: string;
  manualModelName?: string;
  effectiveModel?: string;
  apiKeyEnv: string;
  temperature: number;
  timeout: number;
  maxContextChars: number;
  maxOutputTokens: number;
  maxReasoningTokens: number;
  disableReasoning: boolean;
  responseMode: AIResponseMode;
  autoBriefOnReportReady: boolean;
  allowSettingsRecommendations: boolean;
  allowApprovedSettingsChanges: boolean;
}

export type AIConnectionState =
  | "idle"
  | "ready"
  | "disabled"
  | "checking_connection"
  | "needs_recheck"
  | "busy"
  | "queued"
  | "endpoint_unreachable"
  | "model_missing"
  | "model_not_loaded"
  | "model_incompatible"
  | "input_too_large"
  | "context_length_exceeded"
  | "reasoning_without_final"
  | "model_timeout"
  | "model_busy"
  | "invalid_response"
  | "timeout"
  | "error"
  | "checking";

export interface AIStatus {
  enabled: boolean;
  provider: string;
  baseUrl: string;
  model: string;
  selectedModel?: string;
  manualModelName?: string;
  effectiveModel?: string;
  testedModel?: string;
  selectedModelAvailable?: boolean;
  effective_model?: string;
  tested_model?: string;
  selected_model_available?: boolean;
  reason?: string;
  connection: AIConnectionState;
  ready: boolean;
  can_chat: boolean;
  user_message_tr: string;
  operator_action_tr: string;
  setup_hint_tr: string;
  checked_at: string;
  available_models?: string[];
  reasoning_without_final_count?: number;
  endpoint_debug?: AIEndpointDebug;
}

export interface AIEndpointDebug {
  httpStatus?: number;
  endpointPath?: string;
  requestedModel?: string;
  returnedModel?: string;
  finishReason?: string;
  hasMessageContent?: boolean;
  hasReasoningContent?: boolean;
  contentLength?: number;
  requestId?: string;
  parserReason?: string;
  modelMetadata?: Record<string, unknown>;
  modelProfile?: string;
  providerMessage?: string;
  providerErrorType?: string;
  providerErrorCode?: string;
  providerErrorParam?: string;
  http400Category?: string;
  providerPayloadFields?: string[];
  providerMessages?: Array<{ role: "system" | "user" | "assistant"; content: string }>;
  rawProviderContent?: string;
  providerContentRedacted?: boolean;
  initialRawProviderContent?: string;
  reasoningFieldsSent?: string[];
  providerTemperature?: number;
}

export interface ResolvedAIRequestPlan {
  modelProfile: string;
  answerIntent: string;
  contextProfile: string;
  userMessageChars: number;
  injectedContextChars: number;
  estimatedInputTokens: number;
  effectiveMaxOutputTokens: number;
  effectiveRequestTimeoutSec: number;
  totalProcessWatchdogSec: number;
  disableReasoning: boolean;
  retryPolicy: Record<string, unknown>;
  contextWasCompacted: boolean;
  compatibilityNotes: string[];
  estimatedContextWindowTokens: number;
  contextBudgetChars: number;
  compatible: boolean;
  incompatibilityReason: string;
  userMessageFits: boolean;
  historyTurnsReceived: number;
  historyTurnsSent: number;
  historyWasCompacted: boolean;
  historyBudgetChars: number;
  outputBudgetReason: string;
  systemPromptReserveTokens: number;
  compactSystemPrompt: boolean;
  reservedOutputTokens: number;
  estimatedTotalTokens: number;
  configuredMaxOutputTokens: number;
  configuredMaxContextChars: number;
  effectiveInjectedContextChars: number;
  configuredTimeoutSec: number;
  loadedContextLength: number;
  modelMaxContextLength: number;
  contextMetadataSource: string;
  conservativeContextFallbackUsed: boolean;
  reservedSafetyMarginTokens: number;
  outputValueSource: string;
  outputLimitReason: string;
  timeoutValueSource: string;
  timeoutLimitReason: string;
  providerTemperature: number;
  reasoningFieldsSent: string[];
  providerPayloadFields: string[];
  estimatedHistoryTokens: number;
  reasoningConfigurationReason: string;
  responsePreferences: AIResponsePreferences;
}

export type AIRequestProgressState =
  | "preparing_request"
  | "waiting_for_model"
  | "validating_answer"
  | "repairing_answer"
  | "generating_local_fallback"
  | "completed"
  | "cancelled"
  | "timeout"
  | "context_error"
  | "unusable_answer";

export interface AIRequestProgress {
  request_id: string;
  state: AIRequestProgressState;
  attempt: number;
  timestamp?: string;
}

export interface ToolDefault {
  name: string;
  label: string;
  enabled: boolean;
}

export interface ConfigDefaults {
  repoRoot: string;
  wordlist: string;
  outputDir: string;
  trafficProfile: TrafficProfile;
  scanProfile: ScanProfile;
  reportDepth: ReportDepth;
  tools: ToolDefault[];
  ai: AIConfig;
}

export interface ToolSettings {
  katana: {
    enabled: boolean;
    maxDepth: number;
    timeout: number;
    rateLimit: number;
    maxUrls: number;
  };
  gobuster: {
    enabled: boolean;
    wordlistProfile: "small" | "medium" | "large";
    threads: number;
    timeout: number;
    extensions: string;
  };
  ffuf: {
    enabled: boolean;
    wordlistProfile: "small" | "medium" | "large";
    rateLimit: number;
    timeout: number;
    maxResults: number;
  };
  checks: {
    enabled: boolean;
    timeout: number;
    followRedirects: boolean;
    maxBodySize: number;
  };
  screenshots: {
    enabled: boolean;
    timeout: number;
    maxScreenshots: number;
  };
  nuclei: {
    enabled: boolean;
    severityFilter: string;
    templateProfile: "safe" | "standard" | "broad";
    rateLimit: number;
    timeout: number;
    maxTemplates: number;
  };
  ipNmap: {
    enabled: boolean;
    mode: "fast" | "basic" | "deep";
    topPorts: number;
    timeout: number;
  };
  osint: {
    enabled: boolean;
    mode: "safe_mvp";
    includeCertificateTransparency: boolean;
    includeKnownBreachCatalog: boolean;
    includeHistoricalUrls: boolean;
    includePublicCodeReferences: boolean;
    includeSearchDorkSuggestions: boolean;
    includeInfrastructureIntelligence: boolean;
    includeOrganizationIntelligence: boolean;
    maxSignals: number;
    timeout: number;
    passiveOnly: true;
    sources: {
      githubCodeSearch: {
        enabled: boolean;
        apiKeyEnv: string;
        apiKeyConfigured: boolean;
      };
      wayback: {
        enabled: boolean;
        timeout: number;
        retryCount: number;
      };
      crtsh: {
        enabled: boolean;
        timeout: number;
        retryCount: number;
      };
      knownBreachCatalog: {
        enabled: boolean;
      };
    };
    leakSources: {
      metadataFeed: {
        enabled: boolean;
        providerId: "local_demo_feed" | "custom_https_metadata_feed" | "future_trusted_provider_profile" | string;
        sourceName: string;
        sourceType?: "local_file" | "https_json" | "local_json" | "";
        feedPath: string;
        feedUrl: string;
        apiKeyEnv: string;
        timeout: number;
        maxResults: number;
      };
    };
    darkweb: {
      enabled: boolean;
      manualMetadataImport: {
        enabled: boolean;
        sourceName: string;
        filePath: string;
        maxResults: number;
      };
      customHttpsProvider: {
        enabled: boolean;
        providerUrl: string;
        apiKeyEnv: string;
        apiKeyConfigured: boolean;
        maxResults: number;
        timeout: number;
      };
    };
  };
}

export interface ScanConfig {
  target: string;
  wordlist: string;
  trafficProfile: TrafficProfile;
  scanProfile: ScanProfile;
  runMode: RunMode;
  osintEnabled: boolean;
  osintProfile: "safe_mvp";
  reportDepth: ReportDepth;
  tools: Record<string, boolean>;
  toolSettings: ToolSettings;
  detailedNmapEnabled?: boolean;
  ipEnrichment?: IpEnrichmentState;
  ai: AIConfig;
}

export interface ResolvedIpInfo {
  available: boolean;
  target: string;
  hostname: string;
  ip: string;
  error?: string;
}

export interface IpEnrichmentState {
  status:
    | "not_available"
    | "available_skipped"
    | "quick_ip_scan_requested"
    | "detailed_nmap_requested"
    | "skipped"
    | "running"
    | "done"
    | "already_covered"
    | "error"
    | "completed"
    | "failed";
  originalTarget: string;
  resolvedIp: string;
  hostname?: string;
  scanMode?: "skipped" | "quick" | "lightweight" | "detailed" | "detailed_nmap" | "already_covered";
  requestedAt?: string;
  startedAt?: string;
  endedAt?: string;
  note?: string;
  artifacts?: Record<string, string | number | boolean | null>;
  toolsUsed?: string[];
  tools_used?: string[];
  results?: {
    openPorts?: Array<Record<string, string | number | boolean | null>>;
    open_ports?: Array<Record<string, string | number | boolean | null>>;
    services?: Array<Record<string, string | number | boolean | null>>;
    probes?: Array<Record<string, string | number | boolean | null>>;
    openPortsCount?: number;
    open_ports_count?: number;
    servicesCount?: number;
    services_count?: number;
    probesCount?: number;
    probes_count?: number;
    artifacts?: Record<string, string | number | boolean | null>;
    source?: string;
    validationState?: string;
    validation_state?: string;
    riskNote?: string;
    risk_note?: string;
  };
}

export interface IpEnrichmentRequest {
  originalTarget: string;
  resolvedIp: string;
  hostname?: string;
  scanMode: "quick" | "detailed";
}

export interface ActionResult {
  ok: boolean;
  error?: string;
  message?: string;
  requestDir?: string;
  configPath?: string;
  command?: string;
}

export interface AISettingChange {
  path: string;
  current: unknown;
  proposed: unknown;
  reason_tr: string;
}

export interface AISettingsActionPlan {
  type: "settings_recommendation";
  title_tr: string;
  reason_tr: string;
  changes: AISettingChange[];
  risk_score_impact: number;
  requires_user_approval: true;
}

export interface AIConversationTurn {
  role: "user" | "assistant";
  content: string;
}

export interface AISelectedFindingReference {
  finding_id?: string;
  template_id?: string;
  title: string;
  source: string;
  ordinal: number;
  run_id: string;
}

export interface AIResponsePreferences {
  requested_item_count: number | null;
  requested_format: "list" | "numbered_list" | "paragraph" | null;
  single_sentence: boolean;
  short_answer: boolean;
  no_heading: boolean;
}

export interface AIRequest {
  action: "chat" | "brief" | "settings" | "status" | "apply_settings" | "context" | "cancel";
  runDir?: string;
  question?: string;
  request_id?: string;
  created_at?: string;
  source?: "chat_input" | "quick_action" | "report_button" | "section_button" | "retry" | string;
  user_message?: string;
  conversation_history?: AIConversationTurn[];
  selected_finding_reference?: AISelectedFindingReference;
  known_compatibility_notes?: string[];
  run_id?: string;
  target?: string;
  mode?: string;
  contextProfile?: "quick_report_summary" | "question_answer" | "log_troubleshooting" | "settings_recommendation" | string;
  aiConfig?: AIConfig;
  settings?: unknown;
  aiRunContext?: AiRunContextSnapshot;
  plan?: AISettingsActionPlan;
  approved?: boolean;
  retryTag?: "no_think" | "short_context" | string;
  modelMetadata?: Record<string, unknown>;
  discoverRuntimeCapabilities?: boolean;
  aiDiagnostics?: Record<string, unknown>;
}

export interface AIResponse {
  ok: boolean;
  answer?: string;
  model?: string;
  unavailable?: boolean;
  error?: string;
  status?: "ready" | "unavailable" | "disabled" | string;
  ai?: { status?: AIStatus };
  aiStatus?: AIStatus;
  availableModels?: string[];
  references?: string[];
  evidence?: string[];
  evidence_paths?: string[];
  request_id?: string;
  created_at?: string;
  source?: string;
  user_message?: string;
  latest_user_message?: string;
  lm_request_sent?: boolean;
  local_answer_generated?: boolean;
  context_profile?: string;
  run_id?: string;
  target?: string;
  action_plan?: AISettingsActionPlan | null;
  settings?: unknown;
  applied?: Array<{ path: string; old: unknown; new: unknown; reason_tr: string }>;
  errors?: string[];
  finish_reason?: string;
  output_truncated?: boolean;
  answer_intent?: string;
  effective_max_tokens?: number;
  model_profile?: string;
  endpoint_debug?: AIEndpointDebug;
  request_plan?: ResolvedAIRequestPlan;
  answer_repair_request_plan?: ResolvedAIRequestPlan | null;
  preserve_user_message?: boolean;
  answer_source?: "model" | "repaired_model" | "local_fallback" | string;
  fallback_reason?: string;
  repair_attempted?: boolean;
  repair_reason?: string;
  attempt_count?: number;
  transport_attempt_count?: number;
  answer_repair_attempt_count?: number;
  answer_repair_transport_attempt_count?: number;
  relevance_validation_result?: "not_applicable" | "passed" | "failed" | "passed_after_repair" | "fallback_grounded" | string;
  relevance_validation_reason?: string;
  compatibility_notes?: string[];
  selected_finding_reference?: AISelectedFindingReference;
  response_preferences?: AIResponsePreferences;
  history_turns_sent?: number;
  history_compacted?: boolean;
  context_compacted?: boolean;
  failure_reason_category?: string;
  failure_reason_tr?: string;
}

export interface StageRow {
  name: string;
  label: string;
  status: string;
  metric: string;
  reason: string;
}

export interface Metrics {
  katanaCount: number;
  gobusterHits: number;
  ffufHits: number;
  checksCount: number;
  checksLogin: number;
  checksDocs: number;
  checksCaptcha: number;
  checksRatelimit: number;
  nucleiFindings: number;
  screenshotsCount: number;
}

export interface LiveFinding {
  name: string;
  severity: string;
  templateId: string;
  matchedAt: string;
  source?: string;
  tags?: string[];
  validation?: string;
  operatorValidationRequired?: boolean;
  confidence?: string | number;
  verificationState?: "unverified" | "partially_verified" | "verified" | string;
  statusCode?: string | number;
  redirect?: unknown;
  fingerprint?: unknown;
  validationEvidence?: unknown;
  responseEvidencePresent?: boolean;
  missingEvidenceFields?: string[];
}

export interface ReportState {
  exists: boolean;
  mtime: number;
  path: string;
  viewUrl: string;
  status?: "missing" | "pending" | "ready" | "failed";
  failureReason?: string;
}

export type RunLifecycleState =
  | "idle"
  | "queued"
  | "running"
  | "interrupted"
  | "completed"
  | "failed"
  | "incomplete"
  | "unknown";

export type RunCompleteness = "empty" | "partial" | "report_pending" | "report_ready";

export interface RunArtifactSnapshot {
  availableCount: number;
  availableFiles: string[];
  missingExpected: string[];
  paths: {
    runDir: string;
    rawLog: string;
    stateJson: string;
    stagesJson: string;
    configOrRequest: string;
    report: string;
  };
  exists: {
    runDir: boolean;
    rawLog: boolean;
    stateJson: boolean;
    stagesJson: boolean;
    configOrRequest: boolean;
    report: boolean;
  };
}

export interface RiskState {
  score: number | null;
  label: string;
  source: string;
}

export interface DecisionSnapshot {
  summary: string;
  firstAction: string;
  strongestPath: string;
  source: string;
}

export interface RunStateSnapshot {
  effectiveSettings?: string[];
  currentRunDir: string;
  currentRunResult?: Record<string, unknown>;
  runState: string;
  isHistorical?: boolean;
  completeness?: RunCompleteness;
  processAttached?: boolean;
  artifacts?: RunArtifactSnapshot;
  target: string;
  profile: string;
  risk: RiskState;
  decision: DecisionSnapshot;
  currentStage: string;
  stages: StageRow[];
  metrics: Metrics;
  findings: LiveFinding[];
  report: ReportState;
  ipEnrichment?: IpEnrichmentState;
  osint?: {
    enabled: boolean;
    status: string;
    mode: string;
    totalSignals: number;
    riskScoreImpact: string;
  };
  logTail: string[];
  updatedAt: string;
}

export interface AiTopFinding {
  title: string;
  severity: string;
  source: string;
  template_id?: string;
  url?: string;
  tags?: string[];
  validation?: string;
  operator_validation_required?: boolean;
  confidence?: string | number;
  verification_state?: "unverified" | "partially_verified" | "verified" | string;
  status_code?: string | number;
  redirect?: unknown;
  fingerprint?: unknown;
  validation_evidence?: unknown;
  response_evidence_present?: boolean;
  missing_evidence_fields?: string[];
}

export interface AiRunContextSnapshot {
  ai_model?: string;
  ai_baseUrl?: string;
  ai_provider?: string;
  target: string;
  run_id: string;
  run_dir: string;
  report_path: string;
  run_state: string;
  is_running: boolean;
  is_interrupted: boolean;
  is_completed: boolean;
  profile: string;
  mode: string;
  risk_score: number | null;
  risk_band: string;
  findings_count: number;
  nuclei_findings_count: number;
  findings_by_severity: Record<string, number>;
  top_findings: AiTopFinding[];
  tool_stage_status: Record<string, Record<string, unknown>>;
  source_health_summary: Record<string, unknown>;
  osint_summary: Record<string, unknown>;
  darkweb_summary: Record<string, unknown>;
  validation_notes: string[];
  current_report_confidence: Record<string, unknown>;
  last_errors: string[];
  partial_coverage_notes: string[];
  context_profile?: string;
  request_id?: string;
}

export interface HostTelemetry {
  uptimeSeconds: number;
  appUptimeSeconds: number;
  cpuLoadPercent: number | null;
  ramUsedPercent: number | null;
  ramLabel: string;
  ramDetail: string;
  ramApproximate: boolean;
  diskUsedPercent: number | null;
  netRxKBps: number | null;
  netTxKBps: number | null;
  freeMemoryBytes: number;
  totalMemoryBytes: number;
  network: string;
  sampledAt: string;
}

export interface ScanHistoryItem {
  runDir: string;
  displayName: string;
  target: string;
  dateLabel: string;
  timeLabel: string;
  risk: RiskState;
  reportReady: boolean;
  runState: string;
  isHistorical?: boolean;
  completeness?: RunCompleteness;
  processAttached?: boolean;
  updatedAt: string;
  paths: {
    report: string;
    rawLog: string;
    stateJson: string;
    stagesJson?: string;
    configOrRequest?: string;
  };
  exists?: RunArtifactSnapshot["exists"];
}

export interface HistoricalRunLoadResult extends ActionResult {
  snapshot?: RunStateSnapshot;
}

export interface ReconbotApi {
  startAuthentication(request: AuthenticationRequest): Promise<ActionResult>;
  stopAuthentication(): Promise<ActionResult>;
  readAuthentication(jobId?: string, rejectedPage?: number): Promise<AuthenticationSnapshot>;
  startSqlmap(request: SqlmapRequest): Promise<ActionResult>;
  stopSqlmap(): Promise<ActionResult>;
  readSqlmap(jobId?: string): Promise<SqlmapSnapshot>;
  getConfigDefaults(): Promise<ConfigDefaults>;
  readWordlistPreferences(): Promise<WordlistPreferences>;
  saveWordlistPreference(slot: WordlistSlot, preference: { path: string; locked: boolean }): Promise<WordlistSaveResult>;
  chooseWordlistFile(): Promise<string | null>;
  saveAiSettings(config: AIConfig): Promise<ActionResult & { config?: AIConfig; path?: string }>;
  resolveTargetIp(target: string): Promise<ResolvedIpInfo>;
  startScan(config: ScanConfig): Promise<ActionResult>;
  startIpEnrichment(request: IpEnrichmentRequest): Promise<ActionResult>;
  skipIpEnrichment(request: IpEnrichmentRequest): Promise<ActionResult>;
  stopScan(): Promise<ActionResult>;
  writeTerminal(data: string): void;
  resizeTerminal(cols: number, rows: number): void;
  getTerminalBuffer(): Promise<string>;
  readRunState(): Promise<RunStateSnapshot>;
  selectScanHistoryRun(runDir: string): Promise<HistoricalRunLoadResult>;
  getHostTelemetry(): Promise<HostTelemetry>;
  listScanHistory(): Promise<ScanHistoryItem[]>;
  openPath(path: string): Promise<ActionResult>;
  openExternalUrl(url: string): Promise<ActionResult>;
  copyText(text: string): Promise<ActionResult>;
  aiRequest(request: AIRequest): Promise<AIResponse>;
  onAiRequestProgress(callback: (progress: AIRequestProgress) => void): () => void;
  onTerminalData(callback: (data: string) => void): () => void;
  onRunDirChanged(callback: (runDir: string) => void): () => void;
}
