import { t } from "../lib/i18n";
import { Bot, Check, Copy, FileText, Logs, MoreHorizontal, Send, Settings2, ShieldQuestion, Sparkles, X } from "lucide-react";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { AIConversationTurn, AIRequestProgress, AIRequestProgressState, AIResponse, AISelectedFindingReference, AISettingsActionPlan, AIStatus, ResolvedAIRequestPlan, RunStateSnapshot, ScanConfig } from "../../shared/api";
import { buildAiRunContextSnapshot, compareAiContextToVisibleState } from "../../shared/aiContextSnapshot";
import { AISetupHelpCard } from "./AISetupGuide";
import { applyAiPlanToConfig, settingsForAi } from "../lib/aiSettings";
import { LinkifiedText } from "../lib/linkifyText";
import { getEffectiveAiModel, normalizeAiConfig } from "../lib/settingsModel";
import { AI_RUNTIME_LIMITS } from "../../shared/aiSettingsContract";

type ChatRole = "user" | "assistant" | "status" | "error";
type AIRequestSource = "chat_input" | "quick_action" | "report_button" | "section_button" | "retry";

interface ChatRow {
  id: string;
  role: ChatRole;
  text: string;
  evidence?: string[];
  evidencePaths?: string[];
  requestId?: string;
  truncated?: boolean;
  question?: string;
  mode?: string;
  answerSource?: string;
  localAnswerGenerated?: boolean;
  contextProfile?: string;
  recoverableText?: string;
  displayText?: string;
  failureStatus?: string;
  source?: AIRequestSource | string;
}

interface RecoverableDraft {
  requestId: string;
  text: string;
  displayText: string;
  mode: string;
  source: AIRequestSource | string;
  status: string;
}

interface CurrentRequest {
  requestId: string;
  status: AIRequestProgressState;
  attempt: number;
  mode: string;
  source: AIRequestSource | string;
  submittedMessage: string;
  displayText: string;
  startedAt: number;
}

type AiActivityState = "idle" | "busy" | "queued" | "timeout" | "reasoning_without_final";
type RetryStrategy = "short_context" | "continuation";

interface AIAssistantPanelProps {
  defaults: import("../../shared/api").ConfigDefaults;
  open: boolean;
  width: number;
  onResize: (width: number) => void;
  runState: RunStateSnapshot;
  config: ScanConfig;
  aiStatus: AIStatus | null;
  brief: string;
  initialQuestion: string;
  initialMode: string;
  initialSource: AIRequestSource | string;
  initialPromptId: number;
  onClose: () => void;
  onConfigChange: (config: ScanConfig) => void;
  onTestConnection: () => void;
  onOpenSettings: () => void;
  onOpenSetupGuide: () => void;
  onDisableAi: () => void;
  onAiActivityChange: (state: AiActivityState) => void;
  onStatus: (status: string) => void;
}

const quickModes = [
  { mode: "report", label: "Raporu Açıkla", icon: FileText, question: "Mevcut run contextine göre bu raporu kısa ve doğal biçimde açıkla. Tekrarlayan şablon kullanma; kanıt bloğu ekleme." },
  { mode: "logs", label: "Logları İncele", icon: Logs, question: "Loglardaki önemli hata ve timeoutları yorumla." },
  { mode: "next", label: "Sonraki Adımlar", icon: Sparkles, question: "Bu run için sonraki güvenli operatör adımı ne olmalı?" },
  { mode: "settings", label: "Ayar Öner", icon: Settings2, question: "Mevcut scan profile ve traffic-related ayarlara göre daha düşük trafikli ayar öner. Genel rapor özeti yazma." },
  { mode: "trust", label: "Bu Sonuç Güvenilir mi?", icon: ShieldQuestion, question: "Bu rapora güvenebilir miyim? Kapsam, limitler ve kısa kanıtla açıkla." }
];

const chips = [
  "Bu raporu kısa bir operatör brifingi olarak özetle",
  "Source health neden düşük?",
  "Bu bulgu gerçek mi?",
  "Daha düşük trafikli ayar öner"
];

const LONG_MESSAGE_COLLAPSE_CHARS = 10_000;
const LONG_MESSAGE_PREVIEW_CHARS = 6_000;

const ACTIVE_REQUEST_STATES = new Set<AIRequestProgressState>([
  "preparing_request",
  "waiting_for_model",
  "validating_answer",
  "repairing_answer",
  "generating_local_fallback",
]);

const REQUEST_STATUS_TR: Record<AIRequestProgressState, string> = {
  preparing_request: "İstek hazırlanıyor",
  waiting_for_model: "Model yanıt üretiyor",
  validating_answer: "Yanıt doğruluk ve kalite denetiminde",
  repairing_answer: "Yanıt düzeltiliyor",
  generating_local_fallback: "Model yanıtı kullanılamadı · ReconBot yedek yanıt hazırlıyor",
  completed: "Yanıt tamamlandı",
  cancelled: "İstek iptal edildi",
  timeout: "Model zaman aşımına uğradı",
  context_error: "Bağlam sınırı aşıldı",
  unusable_answer: "Model kullanılabilir yanıt üretemedi",
};

function progressStateForFailure(status: string): AIRequestProgressState {
  if (status === "cancelled") return "cancelled";
  if (status === "timeout" || status === "model_timeout") return "timeout";
  if (status === "input_too_large" || status === "context_length_exceeded" || status === "context_failure") return "context_error";
  return "unusable_answer";
}

function failureMessage(response: AIResponse): string {
  const base = response.answer || response.error || "Model kullanılabilir final cevap üretmedi.";
  const reason = response.failure_reason_tr || (
    response.status === "reasoning_without_final" ? "Yalnız reasoning üretip final cevap vermedi"
      : response.status === "input_too_large" || response.status === "context_length_exceeded" ? "Bağlam sınırı aşıldı"
        : response.status === "timeout" || response.status === "model_timeout" ? "Zaman aşımı"
          : ""
  );
  return reason && !base.includes(reason) ? `${base}\nNeden: ${reason}.` : base;
}

function requestIdFor(source: string): string {
  return `${source}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function cleanDisplayText(text: string): string {
  return String(text || "").replace(/\r\n?/g, "\n").trim();
}

function shortModel(model: string): string {
  return model.split("@")[0].replace("-uncensored-hauhaucs-aggressive", "");
}

const operationalQuestionPattern = /(saldır|saldir|exploit|payload|bypass|shell|rce|gizlen|stealth|evasion|attack)/i;
const reportQuestionPattern = /(rapor|bulgu|finding|risk|source\s*health|kaynak|nuclei|osint|darkweb|leak|log|tarama|scan|artifact|kanıt|kanit)/i;
const summaryQuestionPattern = /(özet|özetle|kısaca|30\s*saniye|5\s*satır|durumu yorumla)/i;
const findingQuestionPattern = /(bulgu|finding|nuclei|cve|zafiyet|eşleşme|kanıt|kanit)/i;
const followupQuestionPattern = /(bu bulgu|bunlar|bunları|bunu|ikincisi(?:ni)?|ikinciyi|önceki bulgu|konuştuğumuz bulgu|önceki cevap|devam et|devamını|daha kısa|kısalt|biraz aç|biraz daha|daha fazla|daha ayrıntılı|daha detaylı|ayrıntılandır|detaylandır|peki önce|\b(?:ilk|birinci|ikinci|üçüncü|dördüncü|beşinci)\s+bulgu\b|\b[1-9]\s*\.\s*(?:si(?:ni)?|sini|dediğini|maddeyi|bulguyu)?)/i;
const trustQuestionPattern = /(güvenilir|güvenebilir|doğru mu|gerçek mi|false.?positive|kapsam|source\s*health|kaynak\s*sağlığ)/i;
const settingsQuestionPattern = /(ayar|setting|config|profil|rate.?limit|timeout değeri)/i;
const logsQuestionPattern = /(log|hata|error|timeout|zaman aşımı|stage|aşama)/i;
const aiFailureDiagnosticsPattern = /(zaman aşımı|timeout|http\s*400|neden hata verdi|model neden cevap vermedi)/i;
const actionGuidanceQuestionPattern = /(?:\b\d{1,2}\s*ad[ıi]ml[ıi]k\b|\bad[ıi]m\s+ad[ıi]m\b|\bs[ıi]rayla\b[^?.!]{0,80}\bad[ıi]m|\bplan\w*\b[^?.!]{0,40}\b(?:ver|haz[ıi]rla|olu[şs]tur|dönü[şs]tür|yaz)|\bnas[ıi]l\b[^?.!]{0,70}\b(?:do[ğg]rula|kontrol|test|incele|teyit)|\bhangi\s+ad[ıi]mlar[ıi]\s+izle)/i;

function compactConversationMemory(turns: AIConversationTurn[]): AIConversationTurn[] {
  const compacted = turns.slice(-AI_RUNTIME_LIMITS.maximumRendererMemoryTurns);
  let chars = compacted.reduce((total, turn) => total + turn.content.length + 16, 0);
  while (compacted.length > 2 && chars > AI_RUNTIME_LIMITS.maximumRendererMemoryChars) {
    const removed = compacted.shift();
    chars -= (removed?.content.length || 0) + 16;
  }
  return compacted;
}

function contextProfileForQuestion(mode: string, question: string): string {
  const normalizedQuestion = question.toLocaleLowerCase("tr-TR");
  if (["report", "brief"].includes(mode)) return "report_summary";
  if (mode === "trust") return "trust";
  if (mode === "next") return "operational_question";
  if (mode === "finding") return "finding_question";
  if (aiFailureDiagnosticsPattern.test(normalizedQuestion)) return "ai_failure_diagnostics";
  if (mode === "continuation" || followupQuestionPattern.test(normalizedQuestion)) return "continuation";
  if (actionGuidanceQuestionPattern.test(normalizedQuestion)) return "operational_question";
  if (mode === "logs" || logsQuestionPattern.test(normalizedQuestion)) return "logs";
  if (mode === "settings" || settingsQuestionPattern.test(normalizedQuestion)) return "settings";
  if (trustQuestionPattern.test(normalizedQuestion)) {
    return /false.?positive/i.test(normalizedQuestion) ? "general_chat" : "trust";
  }
  if (summaryQuestionPattern.test(normalizedQuestion)) return "report_summary";
  if (findingQuestionPattern.test(normalizedQuestion)) return "finding_question";
  if (operationalQuestionPattern.test(normalizedQuestion)) return "operational_question";
  if (reportQuestionPattern.test(normalizedQuestion)) return "finding_question";
  return "general_chat";
}

export default function AIAssistantPanel({
  defaults,
  open,
  width,
  onResize,
  runState,
  config,
  aiStatus,
  brief,
  initialQuestion,
  initialMode,
  initialSource,
  initialPromptId,
  onClose,
  onConfigChange,
  onTestConnection,
  onOpenSettings,
  onOpenSetupGuide,
  onDisableAi,
  onAiActivityChange,
  onStatus
}: AIAssistantPanelProps): JSX.Element | null {
  const [composerDraft, setComposerDraft] = useState("");
  const [recoverableDraft, setRecoverableDraft] = useState<RecoverableDraft | null>(null);
  const [currentRequest, setCurrentRequest] = useState<CurrentRequest | null>(null);
  const [requestProgress, setRequestProgress] = useState<AIRequestProgress | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [latestResponse, setLatestResponse] = useState<AIResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [activeMode, setActiveMode] = useState("chat");
  const [rows, setRows] = useState<ChatRow[]>([]);
  const [requestPlan, setRequestPlan] = useState<ResolvedAIRequestPlan | null>(null);
  const [plan, setPlan] = useState<AISettingsActionPlan | null>(null);
  const [reasoningFix, setReasoningFix] = useState<{ question: string; mode: string } | null>(null);
  const [showModelGuidance, setShowModelGuidance] = useState(false);
  const [reasoningActionMessage, setReasoningActionMessage] = useState("");
  const [pendingPrompt, setPendingPrompt] = useState<{ text: string; mode: string; source: AIRequestSource | string } | null>(null);
  const [jsonVisible, setJsonVisible] = useState(false);
  const [applyMessage, setApplyMessage] = useState("");
  const [systemNotice, setSystemNotice] = useState("");
  const [expandedRows, setExpandedRows] = useState<Set<string>>(() => new Set());
  const [newMessageCount, setNewMessageCount] = useState(0);
  const [technicalDetailsOpen, setTechnicalDetailsOpen] = useState(false);
  const lastInitial = useRef("");
  const activeRequestId = useRef("");
  const currentRequestRef = useRef<CurrentRequest | null>(null);
  const conversationHistoryRef = useRef<AIConversationTurn[]>([]);
  const selectedFindingReferenceRef = useRef<AISelectedFindingReference | undefined>(undefined);
  const conversationScopeRef = useRef("");
  const lastRequest = useRef<{ key: string; at: number }>({ key: "", at: 0 });
  const busyRef = useRef(false);
  const chatEndRef = useRef<HTMLDivElement | null>(null);
  const chatLogRef = useRef<HTMLDivElement | null>(null);
  const chatContentRef = useRef<HTMLDivElement | null>(null);
  const nearBottomRef = useRef(true);
  const pendingFollowRef = useRef(false);
  const previousRowCountRef = useRef(0);
  const previousLastRowIdRef = useRef("");
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const safeAiConfig = useMemo(() => {
    const normalized = normalizeAiConfig(config?.ai);
    const effectiveModel = getEffectiveAiModel(normalized);
    return {
      ...normalized,
      model: effectiveModel,
      effectiveModel
    };
  }, [config?.ai]);
  const effectiveAiModel = safeAiConfig.effectiveModel || getEffectiveAiModel(safeAiConfig);
  const safeRunState = runState || ({} as RunStateSnapshot);
  const safeConfig = useMemo(() => ({ ...config, ai: safeAiConfig }) as ScanConfig, [config, safeAiConfig]);
  const lastModelRef = useRef(effectiveAiModel);

  const targetLine = useMemo(() => {
    const target = safeRunState.target || config?.target || "rapor bekleniyor";
    const riskScore = safeRunState.risk?.score ?? null;
    const risk = riskScore !== null ? `${riskScore}/100` : safeRunState.risk?.label || "pending";
    return `${target} · ${safeRunState.runState || "idle"} · risk ${risk}`;
  }, [config?.target, safeRunState.risk?.label, safeRunState.risk?.score, safeRunState.runState, safeRunState.target]);
  const endpointReady = Boolean(aiStatus?.ready);
  const endpointDisabled = aiStatus?.connection === "disabled";
  const availableModelIds = useMemo(() => (
    Array.isArray(aiStatus?.available_models)
      ? aiStatus.available_models.filter((model): model is string => typeof model === "string" && model.trim().length > 0)
      : []
  ), [aiStatus?.available_models]);
  const compatibleModelOptions = useMemo(() => {
    const preferred = "mistralai/mistral-7b-instruct-v0.3";
    const endpointModels = availableModelIds.filter((model) => {
      const normalized = model.toLowerCase();
      const looksInstruct = /(instruct|mistral|llama|gemma|qwen2\.5)/i.test(model);
      const knownReasoningOnly = normalized.includes("qwen3.5-9b-uncensored-hauhaucs");
      return looksInstruct && !knownReasoningOnly;
    });
    const ordered = [preferred, ...endpointModels];
    return Array.from(new Set(ordered))
      .filter((model) => model !== effectiveAiModel)
      .slice(0, 4)
      .map((model) => ({ model, label: shortModel(model) }));
  }, [availableModelIds, effectiveAiModel]);
  const previewProfile = useMemo(() => contextProfileForQuestion(activeMode, composerDraft || initialQuestion || ""), [activeMode, composerDraft, initialQuestion]);
  const aiContextPreview = useMemo(() => buildAiRunContextSnapshot({
    runState: safeRunState,
    config: safeConfig,
    contextProfile: previewProfile,
    requestId: activeRequestId.current || "not-sent"
  }), [previewProfile, safeConfig, safeRunState]);

  const addRow = useCallback((
    role: ChatRole,
    text: string,
    evidence?: string[],
    evidencePaths?: string[],
    requestId?: string,
    extras: Partial<ChatRow> = {}
  ) => {
    if (nearBottomRef.current) pendingFollowRef.current = true;
    const cleaned = cleanDisplayText(text);
    const effectiveRole = role !== "status" && !cleaned ? "status" : role;
    const effectiveText = cleaned || (role === "assistant" ? "Model kullanılabilir bir final metin döndürmedi. Mesajın korundu; yeniden deneyebilirsin." : "");
    if (!effectiveText) return;
    setRows((current) => {
      const previous = current[current.length - 1];
      if (effectiveRole === "status" && previous?.role === "status" && previous.text === effectiveText) return current;
      return [...current, { id: `${Date.now()}-${Math.random()}`, role: effectiveRole, text: effectiveText, evidence, evidencePaths, requestId, ...extras }].slice(-80);
    });
  }, []);

  const finishOwnedRequest = useCallback((
    requestId: string,
    finalState: AIRequestProgressState = "completed",
    attempt = currentRequestRef.current?.attempt || 1,
  ): void => {
    if (currentRequestRef.current?.requestId !== requestId) return;
    setRequestProgress({ request_id: requestId, state: finalState, attempt, timestamp: new Date().toISOString() });
    currentRequestRef.current = null;
    activeRequestId.current = "";
    busyRef.current = false;
    setCurrentRequest(null);
    setBusy(false);
    onAiActivityChange("idle");
    window.setTimeout(() => {
      setRequestProgress((current) => current?.request_id === requestId && current.state === finalState ? null : current);
    }, 1800);
  }, [onAiActivityChange]);

  const failOwnedRequest = useCallback((
    request: CurrentRequest,
    status: string,
    message: string,
  ): void => {
    if (currentRequestRef.current?.requestId !== request.requestId) return;
    const recoverable: RecoverableDraft = {
      requestId: request.requestId,
      text: request.submittedMessage,
      displayText: request.displayText,
      mode: request.mode,
      source: request.source,
      status,
    };
    setRecoverableDraft(recoverable);
    addRow("error", message, undefined, undefined, request.requestId, {
      mode: request.mode,
      source: request.source,
      displayText: request.displayText,
      recoverableText: request.submittedMessage,
      failureStatus: status,
    });
    finishOwnedRequest(request.requestId, progressStateForFailure(status), request.attempt);
  }, [addRow, finishOwnedRequest]);

  const scrollEndAfterLayout = useCallback((behavior: ScrollBehavior = "auto"): void => {
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => {
        if (!nearBottomRef.current && !pendingFollowRef.current) return;
        chatEndRef.current?.scrollIntoView({ block: "end", behavior });
        const log = chatLogRef.current;
        log?.scrollTo({ top: log.scrollHeight, behavior });
        nearBottomRef.current = true;
        pendingFollowRef.current = false;
      });
    });
  }, []);

  useEffect(() => {
    const latestRowId = rows.at(-1)?.id || "";
    const added = rows.length > previousRowCountRef.current || Boolean(latestRowId && latestRowId !== previousLastRowIdRef.current);
    previousRowCountRef.current = rows.length;
    previousLastRowIdRef.current = latestRowId;
    if (!added) return;
    if (nearBottomRef.current) {
      setNewMessageCount(0);
    } else {
      setNewMessageCount((count) => count + 1);
    }
  }, [rows]);

  useLayoutEffect(() => {
    if (!open || (!nearBottomRef.current && !pendingFollowRef.current)) return;
    scrollEndAfterLayout(busy ? "smooth" : "auto");
  }, [busy, currentRequest, expandedRows, open, rows, scrollEndAfterLayout, technicalDetailsOpen]);

  useEffect(() => {
    const content = chatContentRef.current;
    if (!content || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => {
      if (nearBottomRef.current || pendingFollowRef.current) scrollEndAfterLayout("auto");
    });
    observer.observe(content);
    return () => observer.disconnect();
  }, [scrollEndAfterLayout]);

  useEffect(() => {
    const textarea = textareaRef.current;
    if (!textarea) return;
    textarea.style.height = "auto";
    textarea.style.height = `${Math.min(textarea.scrollHeight, 132)}px`;
  }, [composerDraft]);

  const conversationScope = safeRunState.currentRunDir || `no-run:${safeRunState.target || config?.target || ""}`;
  useEffect(() => {
    if (!conversationScopeRef.current) {
      conversationScopeRef.current = conversationScope;
      return;
    }
    if (conversationScopeRef.current === conversationScope) return;
    conversationScopeRef.current = conversationScope;
    conversationHistoryRef.current = [];
    selectedFindingReferenceRef.current = undefined;
    setRows([]);
    setRecoverableDraft(null);
    setLatestResponse(null);
    setRequestPlan(null);
    setRequestProgress(null);
    setSystemNotice("Yeni run seçildi · Konuşma geçmişi sıfırlandı");
    const owned = currentRequestRef.current;
    if (owned) {
      activeRequestId.current = "";
      currentRequestRef.current = null;
      busyRef.current = false;
      setCurrentRequest(null);
      setBusy(false);
      onAiActivityChange("idle");
      void window.reconbot?.aiRequest?.({ action: "cancel", aiConfig: safeAiConfig, request_id: owned.requestId, source: "retry" });
    }
  }, [conversationScope, onAiActivityChange, safeAiConfig]);

  useEffect(() => {
    if (!currentRequest) return;
    const update = (): void => setElapsedSeconds(Math.max(0, Math.floor((Date.now() - currentRequest.startedAt) / 1000)));
    update();
    const timer = window.setInterval(update, 1000);
    return () => window.clearInterval(timer);
  }, [currentRequest]);

  useEffect(() => {
    const subscribe = window.reconbot?.onAiRequestProgress;
    if (!subscribe) return;
    return subscribe((progress) => {
      const owned = currentRequestRef.current;
      if (!owned || progress.request_id !== owned.requestId || activeRequestId.current !== owned.requestId) return;
      const next: CurrentRequest = {
        ...owned,
        status: progress.state,
        attempt: Math.max(owned.attempt, progress.attempt || 0),
      };
      currentRequestRef.current = next;
      setCurrentRequest(next);
      setRequestProgress({ ...progress, attempt: next.attempt });
    });
  }, []);

  const openExternalUrl = useCallback((url: string): void => {
    void window.reconbot?.openExternalUrl?.(url)
      .then((result) => {
        if (result && !result.ok) onStatus(result.error || "Link açılamadı.");
      })
      .catch((error) => onStatus(`Link açılamadı: ${error instanceof Error ? error.message : String(error)}`));
  }, [onStatus]);

  const askAi = useCallback(async (
    question: string,
    mode = "chat",
    options: {
      retryTag?: RetryStrategy;
      forceNoThink?: boolean;
      shortContext?: boolean;
      source?: AIRequestSource | string;
      fromComposer?: boolean;
      displayText?: string;
      appendUserRow?: boolean;
    } = {}
  ) => {
    const submittedMessage = question;
    if (!submittedMessage.trim()) return;
    const source = options.source || "chat_input";
    const previousResponse = latestResponse;
    const inferredProfile = contextProfileForQuestion(mode, submittedMessage);
    const previousUserQuestion = [...conversationHistoryRef.current]
      .reverse()
      .find((turn) => turn.role === "user")?.content || "";
    const historyAwareProfile = inferredProfile === "continuation" && aiFailureDiagnosticsPattern.test(previousUserQuestion)
      ? "ai_failure_diagnostics"
      : inferredProfile;
    const contextProfile = options.shortContext
      ? (reportQuestionPattern.test(submittedMessage) ? "report_summary" : "continuation")
      : historyAwareProfile;
    const requestKey = `${mode}:${source}:${safeRunState.currentRunDir || ""}:${submittedMessage}:${options.retryTag || ""}:${safeAiConfig.responseMode}`;
    const now = Date.now();
    if (busyRef.current) {
      onAiActivityChange("queued");
      addRow("status", "Model yanıt üretiyor. Yeni istek kuyruğa eklenmedi; mevcut isteği bekle veya iptal et.");
      return;
    }
    if (lastRequest.current.key === requestKey && now - lastRequest.current.at < 4000) {
      onAiActivityChange("queued");
      addRow("status", "Aynı AI isteği kısa süre önce gönderildi; tekrar kuyruğa eklenmedi.");
      window.setTimeout(() => onAiActivityChange("idle"), 1200);
      return;
    }
    if (mode === "settings" && !safeAiConfig.allowSettingsRecommendations) {
      addRow("status", "AI ayar önerileri Settings içinde kapalı.");
      return;
    }
    if (!endpointReady) {
      addRow(
        "status",
        endpointDisabled
          ? "AI devre dışı. Settings > AI içinden etkinleştirebilir veya ReconBot'u AI olmadan kullanmaya devam edebilirsin."
          : "Yerel AI endpoint'e ulaşılamıyor. Modeli başlatmak için aşağıdaki adımları izle."
      );
      return;
    }
    lastRequest.current = { key: requestKey, at: now };
    const requestId = requestIdFor(source);
    const createdAt = new Date().toISOString();
    const displayText = options.displayText || submittedMessage;
    const acceptedRequest: CurrentRequest = {
      requestId,
      status: "preparing_request",
      attempt: 1,
      mode,
      source,
      submittedMessage,
      displayText,
      startedAt: now,
    };
    activeRequestId.current = requestId;
    currentRequestRef.current = acceptedRequest;
    setCurrentRequest(acceptedRequest);
    setRequestProgress({ request_id: requestId, state: "preparing_request", attempt: 1, timestamp: createdAt });
    setElapsedSeconds(0);
    setRecoverableDraft({ requestId, text: submittedMessage, displayText, mode, source, status: "working" });
    busyRef.current = true;
    setBusy(true);
    setActiveMode(mode);
    setLatestResponse(null);
    onAiActivityChange("busy");
    setApplyMessage("");
    setReasoningActionMessage("");
    setSystemNotice("");
    if (options.appendUserRow !== false) {
      addRow("user", displayText, undefined, undefined, requestId, { question: submittedMessage, mode, source, displayText });
    }
    if (options.fromComposer) {
      setComposerDraft("");
      if (textareaRef.current) textareaRef.current.style.height = "auto";
      setPendingPrompt(null);
      setActiveMode("chat");
    }
    let aiRunContext = buildAiRunContextSnapshot({
      runState: safeRunState,
      config: safeConfig,
      contextProfile,
      requestId
    });
    let consistency = compareAiContextToVisibleState(aiRunContext, safeRunState);
    if (!consistency.ok) {
      console.warn("[ai] context mismatch before send; rebuilding", consistency.warnings, aiRunContext);
      aiRunContext = buildAiRunContextSnapshot({
        runState: safeRunState,
        config: safeConfig,
        contextProfile,
        requestId
      });
      consistency = compareAiContextToVisibleState(aiRunContext, safeRunState);
      if (!consistency.ok) {
        console.warn("[ai] rebuilt context still mismatched; request blocked", consistency.warnings, aiRunContext);
        failOwnedRequest(acceptedRequest, "context_failure", `AI context güncel UI ile eşleşmedi; stale context gönderilmedi. ${consistency.warnings[0] || ""}`);
        return;
      }
    }
    const action = mode === "settings" ? "settings" : "chat";
    const aiConfig = {
      ...safeAiConfig,
      ...(options.forceNoThink ? { disableReasoning: true } : {})
    };
    if (!window.reconbot?.aiRequest) {
      failOwnedRequest(acceptedRequest, "invalid_response", "AI durumu okunamadı. Desktop IPC metodu mevcut değil.");
      return;
    }
    const waitingRequest: CurrentRequest = { ...acceptedRequest, status: "waiting_for_model", attempt: 1 };
    currentRequestRef.current = waitingRequest;
    setCurrentRequest(waitingRequest);
    setRequestProgress({ request_id: requestId, state: "waiting_for_model", attempt: 1, timestamp: new Date().toISOString() });
    let response: AIResponse;
    try {
      response = await window.reconbot.aiRequest({
        action,
        request_id: requestId,
        created_at: createdAt,
        source,
        user_message: submittedMessage,
        conversation_history: conversationHistoryRef.current,
        selected_finding_reference: selectedFindingReferenceRef.current,
        mode,
        contextProfile,
        question: submittedMessage,
        runDir: safeRunState.currentRunDir || "",
        run_id: safeRunState.currentRunDir || "",
        target: safeRunState.target || config?.target || "",
        aiConfig,
        aiRunContext,
        settings: settingsForAi(safeConfig),
        retryTag: options.retryTag,
        modelMetadata: aiStatus?.endpoint_debug?.modelMetadata,
        discoverRuntimeCapabilities: true,
        aiDiagnostics: {
          latestRequestStatus: previousResponse?.status || aiStatus?.connection || "idle",
          providerHttpStatus: previousResponse?.endpoint_debug?.httpStatus || 0,
          providerError: previousResponse?.endpoint_debug?.providerMessage || previousResponse?.error || "",
          effectiveRequestPlan: previousResponse?.request_plan || null,
          configuredTimeoutSec: safeAiConfig.timeout,
          effectiveAttemptTimeoutSec: previousResponse?.request_plan?.effectiveRequestTimeoutSec || safeAiConfig.timeout,
          configuredMaxOutputTokens: safeAiConfig.maxOutputTokens,
          effectiveMaxOutputTokens: previousResponse?.request_plan?.effectiveMaxOutputTokens || safeAiConfig.maxOutputTokens,
          conversationTurns: conversationHistoryRef.current.length,
        }
      });
    } catch (error) {
      failOwnedRequest(acceptedRequest, "invalid_response", `AI durumu okunamadı: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    if (activeRequestId.current !== requestId || currentRequestRef.current?.requestId !== requestId) return;
    if (response.request_id && response.request_id !== requestId) {
      onStatus("Eski AI yanıtı atlandı");
      failOwnedRequest(
        acceptedRequest,
        "invalid_response",
        "AI yanıtı aktif istekle eşleşmedi. Gönderilen mesaj korunuyor; yeniden deneyebilirsin."
      );
      return;
    }
    setRequestPlan(response.request_plan || null);
    setLatestResponse(response);
    if (response.selected_finding_reference) {
      selectedFindingReferenceRef.current = response.selected_finding_reference;
    }
    if (response.unavailable) {
      const responseStatus = String(response.status || "");
      setReasoningFix(null);
      setShowModelGuidance(false);
      if (responseStatus === "busy" || responseStatus === "queued") {
        onAiActivityChange("queued");
        onStatus("Model meşgul");
      } else if (responseStatus === "reasoning_without_final") {
        onAiActivityChange("reasoning_without_final");
        onStatus("Model final cevap üretmedi");
      } else if (responseStatus === "timeout" || responseStatus === "model_timeout" || (response.answer || "").includes("yanıt süresi uzun")) {
        onAiActivityChange("timeout");
        onStatus("Model yavaş yanıt verdi / zaman aşımı");
      } else if (responseStatus === "model_busy") {
        onAiActivityChange("queued");
        onStatus("Model meşgul");
      } else if (responseStatus === "input_too_large" || responseStatus === "context_length_exceeded") {
        onStatus("Mesaj/model context sınırı aşıldı");
      } else if (responseStatus === "model_incompatible") {
        onStatus("Seçili model chat için uyumsuz");
      } else {
        onStatus("AI isteği tamamlanamadı");
      }
      failOwnedRequest(
        acceptedRequest,
        responseStatus || "invalid_response",
        failureMessage(response)
      );
      return;
    } else if (response.ok && cleanDisplayText(response.answer || "")) {
      onStatus("Yerel model bağlı");
      setReasoningFix(null);
      setShowModelGuidance(false);
      setReasoningActionMessage("");
      setPendingPrompt(null);
    } else {
      onStatus("Model kullanılabilir final cevap döndürmedi");
      failOwnedRequest(
        acceptedRequest,
        String(response.status || "invalid_response"),
        failureMessage(response)
      );
      return;
    }
    const truncated = Boolean(response.output_truncated || response.finish_reason === "length");
    if (truncated) {
      onStatus("Cevap token limitine takıldı");
    }
    addRow(
      "assistant",
      response.answer || response.error || "",
      response.evidence,
      response.evidence_paths,
      requestId,
      {
        truncated,
        question: submittedMessage,
        mode,
        answerSource: response.answer_source || (response.local_answer_generated ? "local_fallback" : "model"),
        localAnswerGenerated: response.local_answer_generated === true,
        contextProfile: response.context_profile || contextProfile,
      }
    );
    const completedTurns: AIConversationTurn[] = [
      ...conversationHistoryRef.current,
      { role: "user", content: submittedMessage },
      { role: "assistant", content: cleanDisplayText(response.answer || "") },
    ];
    conversationHistoryRef.current = compactConversationMemory(completedTurns);
    setRecoverableDraft((current) => current?.requestId === requestId ? null : current);
    if (response.action_plan && Array.isArray(response.action_plan.changes)) {
      setPlan(response.action_plan);
      onStatus("Ayar önerisi hazır");
    }
    finishOwnedRequest(requestId, "completed", Math.max(1, Number(response.attempt_count || currentRequestRef.current?.attempt || 1)));
  }, [addRow, aiStatus, config?.target, endpointDisabled, endpointReady, failOwnedRequest, finishOwnedRequest, latestResponse, onAiActivityChange, onStatus, safeAiConfig, safeConfig, safeRunState]);

  const clearConversation = useCallback((): void => {
    if (busyRef.current) return;
    conversationHistoryRef.current = [];
    selectedFindingReferenceRef.current = undefined;
    setRows([]);
    setRecoverableDraft(null);
    setLatestResponse(null);
    setRequestPlan(null);
    setPlan(null);
    setReasoningFix(null);
    setSystemNotice("Yeni sohbet · Yalnız Copilot konuşma geçmişi temizlendi");
    setNewMessageCount(0);
  }, []);

  useEffect(() => {
    if (!open || !initialQuestion) return;
    const key = `${initialPromptId}:${initialMode}:${initialQuestion}`;
    if (lastInitial.current === key) return;
    lastInitial.current = key;
    setActiveMode(initialMode || "chat");
    setComposerDraft(initialQuestion);
    setPendingPrompt({ text: initialQuestion, mode: initialMode || "chat", source: initialSource || "report_button" });
    setSystemNotice("Soru hazırlandı · Gönder ile onayla");
  }, [initialMode, initialQuestion, initialSource, initialPromptId, open]);

  useEffect(() => {
    if (!open) {
      lastModelRef.current = effectiveAiModel;
      return;
    }
    if (lastModelRef.current === effectiveAiModel) return;
    lastModelRef.current = effectiveAiModel;
    setReasoningFix(null);
    setShowModelGuidance(false);
    setReasoningActionMessage("");
    setApplyMessage("");
    if (!busyRef.current) onAiActivityChange("idle");
    addRow("status", `Model ${shortModel(effectiveAiModel)} seçildi. Model formatı uyarısı kapatıldı; yeniden Gönder'e bas.`);
  }, [addRow, effectiveAiModel, onAiActivityChange, open]);

  const cancelRequest = async (): Promise<void> => {
    const owned = currentRequestRef.current;
    if (!busyRef.current || !owned) return;
    const requestId = owned.requestId;
    activeRequestId.current = "";
    currentRequestRef.current = null;
    busyRef.current = false;
    setBusy(false);
    setCurrentRequest(null);
    setRequestProgress({ request_id: requestId, state: "cancelled", attempt: owned.attempt, timestamp: new Date().toISOString() });
    setRecoverableDraft({
      requestId,
      text: owned.submittedMessage,
      displayText: owned.displayText,
      mode: owned.mode,
      source: owned.source,
      status: "cancelled",
    });
    setLatestResponse({
      ok: false,
      unavailable: true,
      status: "cancelled",
      answer: "AI isteği operatör tarafından iptal edildi.",
      error: "cancelled_by_operator",
      request_id: requestId,
      latest_user_message: owned.submittedMessage,
      lm_request_sent: true,
      local_answer_generated: false,
      endpoint_debug: {
        httpStatus: 0,
        parserReason: "cancelled_by_operator",
        providerMessage: "",
      },
    });
    onAiActivityChange("idle");
    addRow("error", "AI isteği iptal edildi.", undefined, undefined, requestId, {
      mode: owned.mode,
      source: owned.source,
      displayText: owned.displayText,
      recoverableText: owned.submittedMessage,
      failureStatus: "cancelled",
    });
    if (window.reconbot?.aiRequest) {
      void window.reconbot.aiRequest({ action: "cancel", aiConfig: safeAiConfig, request_id: requestId, source: "retry" });
    }
    window.setTimeout(() => {
      setRequestProgress((current) => current?.request_id === requestId && current.state === "cancelled" ? null : current);
    }, 1800);
  };

  const applyPlan = async (): Promise<void> => {
    if (!plan || !safeAiConfig.allowApprovedSettingsChanges) return;
    if (!window.reconbot?.aiRequest) {
      setApplyMessage("AI durumu okunamadı. Desktop IPC metodu mevcut değil.");
      return;
    }
    const response = await window.reconbot.aiRequest({
      action: "apply_settings",
      aiConfig: safeAiConfig,
      settings: settingsForAi(safeConfig),
      plan,
      approved: true
    });
    if (!response.ok) {
      setApplyMessage(response.errors?.[0] || response.error || "Ayar önerisi guard tarafından reddedildi.");
      return;
    }
    try {
      onConfigChange(applyAiPlanToConfig(safeConfig, plan, defaults));
    } catch (error) {
      setApplyMessage(error instanceof Error ? error.message : "Ayar önerisi doğrulanamadı.");
      return;
    }
    setApplyMessage("Kullanıcı onaylı AI ayar değişikliği uygulandı. Scan otomatik başlatılmadı.");
    onStatus("Ayar önerisi uygulandı");
  };

  const retryReasoning = (strategy: RetryStrategy): void => {
    if (!reasoningFix) return;
    void askAi(reasoningFix.question, reasoningFix.mode, { retryTag: strategy, shortContext: true, forceNoThink: true, source: "retry" });
  };

  const continueAnswer = useCallback((row: ChatRow): void => {
    void askAi("Devamını getir.", "continuation", {
      retryTag: "continuation",
      source: "retry",
      displayText: "Devamını getir",
    });
  }, [askAi]);

  const restoreDraft = useCallback((text: string): void => {
    setComposerDraft((current) => {
      if (!current.trim()) {
        setSystemNotice("Taslak geri yüklendi");
        return text;
      }
      setSystemNotice("Kurtarılan taslak mevcut metnin altına eklendi");
      return `${current}\n\n${text}`;
    });
    textareaRef.current?.focus();
  }, []);

  const retryFailure = useCallback((row: ChatRow): void => {
    if (!row.recoverableText) return;
    const compactContext = row.failureStatus === "reasoning_without_final" || row.failureStatus === "context_length_exceeded" || row.failureStatus === "input_too_large";
    void askAi(row.recoverableText, row.mode || "chat", {
      source: "retry",
      displayText: row.displayText || row.recoverableText,
      shortContext: compactContext,
      forceNoThink: row.failureStatus === "reasoning_without_final",
      retryTag: compactContext ? "short_context" : undefined,
      appendUserRow: false,
    });
  }, [askAi]);

  const increaseMaxOutputTokens = (): void => {
    const current = Number(safeAiConfig.maxOutputTokens || 900);
    const next = Math.min(Math.max(current + 300, 1200), 3000);
    onConfigChange({ ...safeConfig, ai: { ...safeAiConfig, maxOutputTokens: next } });
    setReasoningActionMessage(`Max output tokens ${next} olarak ayarlandı. Tekrar Gönder veya daha kısa context ile dene.`);
  };

  const selectCompatibleModel = (model: string): void => {
    onConfigChange({
      ...safeConfig,
      ai: {
        ...safeAiConfig,
        model,
        selectedModel: model,
        manualModelName: model,
        effectiveModel: model,
        disableReasoning: true,
        responseMode: "fast_operator",
        maxOutputTokens: Math.min(Math.max(Number(safeAiConfig.maxOutputTokens || 1200), 900), 1200)
      }
    });
    setReasoningFix(null);
    setShowModelGuidance(false);
    setReasoningActionMessage("");
    addRow("status", `${shortModel(model)} seçildi. Model formatı uyarısı kapatıldı; yanıt için tekrar Gönder'e bas.`);
  };

  const scrollToLatest = (): void => {
    nearBottomRef.current = true;
    pendingFollowRef.current = true;
    setNewMessageCount(0);
    const log = chatLogRef.current;
    if (!log) return;
    log.scrollTo({ top: log.scrollHeight, behavior: "auto" });
    scrollEndAfterLayout("smooth");
  };

  const toggleRowExpanded = (rowId: string): void => {
    setExpandedRows((current) => {
      const next = new Set(current);
      if (next.has(rowId)) next.delete(rowId);
      else next.add(rowId);
      return next;
    });
  };

  if (!open) return null;

  return (
    <aside
      className="ai-drawer"
      aria-label={t("ReconBot AI Operator Copilot")}
      data-recoverable-request-id={recoverableDraft?.requestId || undefined}
    >
      <div className="copilot-resizer" role="separator" tabIndex={0} aria-orientation="vertical"
        aria-label={t("Resize Copilot")} aria-valuemin={360} aria-valuemax={640} aria-valuenow={width}
        onKeyDown={(event) => {
          if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
            event.preventDefault(); onResize(width + (event.key === "ArrowLeft" ? 24 : -24));
          }
          if (event.key === "Home") { event.preventDefault(); onResize(360); }
          if (event.key === "End") { event.preventDefault(); onResize(640); }
        }}
        onPointerDown={(event) => {
          event.preventDefault(); event.currentTarget.setPointerCapture(event.pointerId);
        }}
        onPointerMove={(event) => {
          if (event.currentTarget.hasPointerCapture(event.pointerId)) onResize(window.innerWidth - event.clientX);
        }}
        onPointerUp={(event) => { if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId); }}
      />
      <header className="ai-drawer-head">
        <div>
          <span className="micro-label"><Bot size={13} /> {" "}{t("RECONBOT AI")}</span>
          <h2>{t("Operator Copilot")}</h2>
          <small>{shortModel(effectiveAiModel)} · {aiStatus?.connection || "checking"} · {targetLine}</small>
        </div>
        <div className="ai-drawer-head-actions">
          <button type="button" className="ai-new-chat-button" disabled={busy} onClick={clearConversation}>{t("Yeni sohbet")}</button>
          <button type="button" className="icon-button" onClick={onClose} title={t("Kapat")}>
            <X size={16} />
          </button>
        </div>
      </header>

      <div className="ai-assistant-support">
      <details className="ai-technical-details" onToggle={(event) => setTechnicalDetailsOpen(event.currentTarget.open)}>
        <summary>{t("Teknik detaylar")}</summary>
        {latestResponse?.answer_repair_request_plan && <pre data-testid="ai-repair-plan">{JSON.stringify(latestResponse.answer_repair_request_plan, null, 2)}</pre>}
        <div className="ai-context-preview">
          <strong>{t("AI Context Preview")}</strong>
          <div>
            <span>{t("target:")}{" "}{aiContextPreview.target || "n/a"}</span>
            <span>{t("run_id:")}{" "}{aiContextPreview.run_id || "n/a"}</span>
            <span>{t("run_state:")}{" "}{aiContextPreview.run_state || "n/a"}</span>
            <span>{t("risk_score:")}{" "}{aiContextPreview.risk_score !== null ? `${aiContextPreview.risk_score}/100` : t("n/a")}</span>
            <span>{t("risk_band:")}{" "}{aiContextPreview.risk_band || "n/a"}</span>
            <span>{t("nuclei_findings_count:")}{" "}{aiContextPreview.nuclei_findings_count}</span>
            <span>{t("context_profile:")}{" "}{latestResponse?.context_profile || requestPlan?.contextProfile || aiContextPreview.context_profile || "n/a"}</span>
            <span>{t("ai_model:")}{" "}{aiContextPreview.ai_model || effectiveAiModel}</span>
            <span>{t("request_id:")}{" "}{aiContextPreview.request_id || "not-sent"}</span>
            <span>{t("top_findings:")}{" "}{aiContextPreview.top_findings.map((finding) => finding.title).join(" | ") || "none"}</span>
            <span>{t("selected_model:")}{" "}{effectiveAiModel}</span>
            <span>{t("base_url:")}{" "}{safeAiConfig.baseUrl}</span>
            <span>{t("configured_temperature:")}{" "}{safeAiConfig.temperature}</span>
            <span>{t("provider_temperature:")}{" "}{requestPlan?.providerTemperature ?? latestResponse?.endpoint_debug?.providerTemperature ?? "n/a"}</span>
            <span>{t("configured_timeout_sec:")}{" "}{safeAiConfig.timeout}</span>
            <span>{t("effective_attempt_timeout_sec:")}{" "}{requestPlan?.effectiveRequestTimeoutSec ?? "n/a"}</span>
            <span>{t("total_process_watchdog_sec:")}{" "}{requestPlan?.totalProcessWatchdogSec ?? "n/a"}</span>
            <span>{t("configured_max_output_tokens:")}{" "}{safeAiConfig.maxOutputTokens}</span>
            <span>{t("effective_max_output_tokens:")}{" "}{requestPlan?.effectiveMaxOutputTokens ?? "n/a"}</span>
            <span>{t("output_limit_reason:")}{" "}{requestPlan?.outputLimitReason || "none"}</span>
            <span>{t("configured_max_context_chars:")}{" "}{safeAiConfig.maxContextChars}</span>
            <span>{t("effective_injected_context_chars:")}{" "}{requestPlan?.effectiveInjectedContextChars ?? "n/a"}</span>
            <span>{t("loaded_context_length:")}{" "}{requestPlan?.loadedContextLength ?? "n/a"}</span>
            <span>{t("model_max_context_length:")}{" "}{requestPlan?.modelMaxContextLength || "n/a"}</span>
            <span>{t("context_metadata_source:")}{" "}{requestPlan?.contextMetadataSource || "n/a"}</span>
            <span>{t("conservative_context_fallback:")}{" "}{requestPlan?.conservativeContextFallbackUsed ? t("yes") : t("no")}</span>
            <span>{t("estimated_prompt_tokens:")}{" "}{requestPlan?.estimatedInputTokens ?? "n/a"}</span>
            <span>{t("reserved_safety_margin_tokens:")}{" "}{requestPlan?.reservedSafetyMarginTokens ?? "n/a"}</span>
            <span>{t("response_mode:")}{" "}{safeAiConfig.responseMode}</span>
            <span>{t("thinking_reasoning_configured:")}{" "}{safeAiConfig.disableReasoning ? t("disabled") : t("enabled")}</span>
            <span>{t("report_ready_prompt:")}{" "}{safeAiConfig.autoBriefOnReportReady ? t("enabled") : t("disabled")}</span>
            <span>{t("settings_recommendations:")}{" "}{safeAiConfig.allowSettingsRecommendations ? t("enabled") : t("disabled")}</span>
            <span>{t("approved_settings_changes:")}{" "}{safeAiConfig.allowApprovedSettingsChanges ? t("enabled") : t("disabled")}</span>
            <span>{t("reasoning_fields_sent:")}{" "}{(latestResponse?.endpoint_debug?.reasoningFieldsSent || requestPlan?.reasoningFieldsSent || []).join(", ") || "none"}</span>
            <span>{t("reasoning_configuration_reason:")}{" "}{requestPlan?.reasoningConfigurationReason || (safeAiConfig.disableReasoning ? "disabled_by_user" : "unsupported_by_selected_model_or_provider")}</span>
            <span>{t("provider_payload_fields:")}{" "}{(latestResponse?.endpoint_debug?.providerPayloadFields || requestPlan?.providerPayloadFields || []).join(", ") || "n/a"}</span>
            <span>{t("exact_latest_user_message:")}{" "}{latestResponse?.latest_user_message || "n/a"}</span>
            <span>{t("request_status:")}{" "}{requestProgress?.state || currentRequest?.status || latestResponse?.status || "idle"}</span>
            <span>{t("answer_source:")}{" "}{latestResponse?.answer_source || (latestResponse?.local_answer_generated ? "local_fallback" : "n/a")}</span>
            <span>{t("answer_intent:")}{" "}{latestResponse?.answer_intent || requestPlan?.answerIntent || "n/a"}</span>
            <span>{t("selected_finding_title:")}{" "}{latestResponse?.selected_finding_reference?.title || "n/a"}</span>
            <span>{t("selected_finding_ordinal:")}{" "}{latestResponse?.selected_finding_reference?.ordinal ?? "n/a"}</span>
            <span>{t("requested_format:")}{" "}{latestResponse?.response_preferences?.requested_format || requestPlan?.responsePreferences?.requested_format || "none"}</span>
            <span>{t("requested_item_count:")}{" "}{latestResponse?.response_preferences?.requested_item_count ?? requestPlan?.responsePreferences?.requested_item_count ?? "none"}</span>
            <span>{t("single_sentence_requested:")}{" "}{(latestResponse?.response_preferences?.single_sentence ?? requestPlan?.responsePreferences?.single_sentence) ? t("yes") : t("no")}</span>
            <span>{t("short_answer_requested:")}{" "}{(latestResponse?.response_preferences?.short_answer ?? requestPlan?.responsePreferences?.short_answer) ? t("yes") : t("no")}</span>
            <span>{t("no_heading_requested:")}{" "}{(latestResponse?.response_preferences?.no_heading ?? requestPlan?.responsePreferences?.no_heading) ? t("yes") : t("no")}</span>
            <span>{t("history_turns_received:")}{" "}{requestPlan?.historyTurnsReceived ?? 0}</span>
            <span>{t("history_turns_sent:")}{" "}{latestResponse?.history_turns_sent ?? requestPlan?.historyTurnsSent ?? 0}</span>
            <span>{t("estimated_history_tokens:")}{" "}{requestPlan?.estimatedHistoryTokens ?? 0}</span>
            <span>{t("history_compacted:")}{" "}{(latestResponse?.history_compacted || requestPlan?.historyWasCompacted) ? t("yes") : t("no")}</span>
            <span>{t("transport_attempt_count:")}{" "}{latestResponse?.transport_attempt_count ?? latestResponse?.attempt_count ?? 0}</span>
            <span>{t("answer_repair_attempt_count:")}{" "}{latestResponse?.answer_repair_attempt_count ?? (latestResponse?.repair_attempted ? 1 : 0)}</span>
            <span>{t("answer_repair_transport_attempt_count:")}{" "}{latestResponse?.answer_repair_transport_attempt_count ?? 0}</span>
            <span>{t("repair_reason:")}{" "}{latestResponse?.repair_reason || "n/a"}</span>
            <span>{t("relevance_validation_result:")}{" "}{latestResponse?.relevance_validation_result || "n/a"}</span>
            <span>{t("relevance_validation_reason:")}{" "}{latestResponse?.relevance_validation_reason || "n/a"}</span>
            <span>{t("failure_category:")}{" "}{latestResponse?.failure_reason_category || "n/a"}</span>
            <span>{t("provider_http_status:")}{" "}{latestResponse?.endpoint_debug?.httpStatus || "n/a"}</span>
            <span>{t("provider_message:")}{" "}{latestResponse?.endpoint_debug?.providerMessage || "n/a"}</span>
            <span>{t("provider_error_type:")}{" "}{latestResponse?.endpoint_debug?.providerErrorType || "n/a"}</span>
            <span>{t("provider_error_code:")}{" "}{latestResponse?.endpoint_debug?.providerErrorCode || "n/a"}</span>
            <span>{t("provider_error_param:")}{" "}{latestResponse?.endpoint_debug?.providerErrorParam || "n/a"}</span>
            <span>{t("http_400_category:")}{" "}{latestResponse?.endpoint_debug?.http400Category || "n/a"}</span>
            <span>{t("finish_reason:")}{" "}{latestResponse?.finish_reason || "n/a"}</span>
            <span>{t("context_compacted:")}{" "}{(latestResponse?.context_compacted || requestPlan?.contextWasCompacted) ? t("yes") : t("no")}</span>
            <span>{t("local_fallback:")}{" "}{latestResponse?.local_answer_generated ? t("yes") : t("no")}</span>
          </div>
          {latestResponse?.endpoint_debug?.providerMessages?.length ? (
            <div className="ai-request-plan">
              <strong>{t("Modele gönderilen mesajlar")}</strong>
              <pre data-testid="ai-provider-messages">{JSON.stringify(latestResponse.endpoint_debug.providerMessages, null, 2)}</pre>
            </div>
          ) : null}
          {latestResponse?.endpoint_debug?.rawProviderContent !== undefined ? (
            <div className="ai-request-plan">
              <strong>{t("Raw provider content / rendered response")}</strong>
              {latestResponse.endpoint_debug.initialRawProviderContent !== undefined ? (
                <pre data-testid="ai-initial-raw-provider-content">{latestResponse.endpoint_debug.initialRawProviderContent}</pre>
              ) : null}
              <pre data-testid="ai-raw-provider-content">{latestResponse.endpoint_debug.rawProviderContent}</pre>
              <pre data-testid="ai-rendered-response">{latestResponse.answer || ""}</pre>
            </div>
          ) : null}
          {requestPlan && (
            <div className="ai-request-plan">
              <strong>{t("Resolved request plan")}</strong>
              <span>{requestPlan.modelProfile} · {requestPlan.answerIntent}</span>
              <span>{requestPlan.estimatedInputTokens} {" "}{t("input token tahmini ·")}{" "}{requestPlan.effectiveMaxOutputTokens} {" "}{t("output")}</span>
              <span>{t("Output budget reason:")}{" "}{requestPlan.outputBudgetReason}</span>
              <span>{t("Total planned:")}{" "}{requestPlan.estimatedTotalTokens} {" "}{t("+ safety")}{" "}{requestPlan.reservedSafetyMarginTokens} / {requestPlan.loadedContextLength} {" "}{t("· system reserve")}{" "}{requestPlan.systemPromptReserveTokens}</span>
              <span>{requestPlan.effectiveRequestTimeoutSec}{t("s/attempt ·")}{" "}{requestPlan.totalProcessWatchdogSec}{t("s watchdog")}</span>
              <span>{t("Context compact:")}{" "}{requestPlan.contextWasCompacted ? t("yes") : t("no")}</span>
              <span>{t("History:")}{" "}{requestPlan.historyTurnsSent}/{requestPlan.historyTurnsReceived} {" "}{t("turn · compact")}{" "}{requestPlan.historyWasCompacted ? t("yes") : t("no")}</span>
              {requestPlan.compatibilityNotes.map((note) => <span key={note}>{note}</span>)}
            </div>
          )}
        </div>
      </details>

      {!endpointReady && (
        <AISetupHelpCard
          aiConfig={safeAiConfig}
          aiStatus={aiStatus || undefined}
          onTestConnection={onTestConnection}
          onOpenSettings={onOpenSettings}
          onOpenGuide={onOpenSetupGuide}
          onDisableAi={onDisableAi}
        />
      )}
      </div>

      <div className="ai-quick-toolbar" aria-label={t("Copilot hızlı işlemleri")}>
        {quickModes.filter((item) => ["report", "next", "trust"].includes(item.mode)).map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.mode}
              type="button"
              disabled={!endpointReady || busy || (item.mode === "settings" && !safeAiConfig.allowSettingsRecommendations)}
              onClick={() => askAi(t(item.question), item.mode, { source: "quick_action", displayText: t(item.label) })}
            >
              <Icon size={14} />
              <span>{t(item.label)}</span>
            </button>
          );
        })}
        <details className="ai-more-actions">
          <summary><MoreHorizontal size={14} /> {" "}{t("Diğer")}</summary>
          <div>
            {quickModes.filter((item) => ["logs", "settings"].includes(item.mode)).map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.mode}
                  type="button"
                  disabled={!endpointReady || busy || (item.mode === "settings" && !safeAiConfig.allowSettingsRecommendations)}
                  onClick={() => askAi(t(item.question), item.mode, { source: "quick_action", displayText: t(item.label) })}
                >
                  <Icon size={14} /> {t(item.label)}
                </button>
              );
            })}
          </div>
        </details>
      </div>

      <div className="ai-chip-row" aria-label={t("Önerilen sorular")}>
        {chips.map((chip) => (
          <button key={chip} type="button" disabled={!endpointReady || busy} onClick={() => { void askAi(t(chip), "chat", { source: "quick_action" }); }}>{t(chip)}</button>
        ))}
      </div>

      <div className="ai-system-notice" role="status" aria-hidden={!systemNotice}>{t(systemNotice) || " "}</div>

      <div
        ref={chatLogRef}
        className="ai-chat-log"
        onScroll={(event) => {
          const node = event.currentTarget;
          nearBottomRef.current = node.scrollHeight - node.scrollTop - node.clientHeight < 72;
          if (nearBottomRef.current && newMessageCount) setNewMessageCount(0);
        }}
      >
        <div ref={chatContentRef} className="ai-chat-content">
        {rows.length === 0 && (
          <div className="ai-empty">
            <strong>{safeRunState.report?.exists ? t("Rapor hazır. Ne öğrenmek istiyorsun?") : t("Copilot hazır.")}</strong>
            <small>{brief || t("Rapor, log, bulgu veya ayarlar hakkında soru sorabilirsin.")}</small>
          </div>
        )}
        {rows.filter((row) => row.text.trim()).map((row) => {
          const isLong = row.text.length > LONG_MESSAGE_COLLAPSE_CHARS;
          const expanded = expandedRows.has(row.id);
          const visibleText = isLong && !expanded ? `${row.text.slice(0, LONG_MESSAGE_PREVIEW_CHARS).trimEnd()}…` : row.text;
          const isLocalFallback = row.role === "assistant" && row.answerSource === "local_fallback" && row.localAnswerGenerated === true;
          return (
          <article key={row.id} className={`ai-message ${row.role}${isLocalFallback ? " local-fallback" : ""}${isLong && !expanded ? " is-collapsed" : ""}`} data-message-id={row.id}>
            {isLocalFallback && (
              <div className="ai-answer-source">
                <span className="ai-answer-source-label">{t("ReconBot yedek yanıtı")}</span>
                <small>
                  {row.contextProfile === "ai_failure_diagnostics"
                    ? t("Model kullanılabilir cevap üretmediği için bu yanıt son AI istek durumu ve provider tanısından oluşturuldu.")
                    : t("Model kullanılabilir cevap üretmediği için bu yanıt mevcut run artifactlerinden oluşturuldu.")}
                </small>
              </div>
            )}
            <div className="ai-message-body">
              <LinkifiedText text={row.role === "error" || row.role === "status" ? t(visibleText) : visibleText} onOpenUrl={openExternalUrl} />
            </div>
            {isLong && (
              <button type="button" className="ai-message-expand" onClick={() => toggleRowExpanded(row.id)}>
                {expanded ? t("Daralt") : t("Devamını göster")}
              </button>
            )}
            {row.role === "assistant" && row.text.trim() && (
              <div className="ai-message-actions">
                <button
                  type="button"
                  onClick={() => {
                    const write = window.reconbot?.copyText
                      ? window.reconbot.copyText(row.text)
                      : navigator.clipboard?.writeText(row.text);
                    void Promise.resolve(write).catch((error) => {
                      onStatus(`Kopyalama başarısız: ${error instanceof Error ? error.message : String(error)}`);
                    });
                  }}
                >
                  <Copy size={13} /> {t("Kopyala")}</button>
              </div>
            )}
            {row.role === "error" && row.recoverableText && (
              <div className="ai-failure-actions">
                <button type="button" disabled={busy} onClick={() => retryFailure(row)}>
                  {row.failureStatus === "context_length_exceeded" ? t("Bağlamı küçültüp tekrar dene") : t("Tekrar dene")}
                </button>
                {row.failureStatus === "context_length_exceeded" && <button type="button" disabled={busy} onClick={clearConversation}>{t("Yeni sohbet")}</button>}
                <button type="button" onClick={() => restoreDraft(row.recoverableText || "")}>{t("Taslağı geri yükle")}</button>
                <button
                  type="button"
                  onClick={() => {
                    const write = window.reconbot?.copyText
                      ? window.reconbot.copyText(row.recoverableText || "")
                      : navigator.clipboard?.writeText(row.recoverableText || "");
                    void Promise.resolve(write);
                  }}
                ><Copy size={13} /> {" "}{t("Kopyala")}</button>
                {row.failureStatus === "reasoning_without_final" && <button type="button" onClick={onOpenSettings}>{t("AI Ayarları")}</button>}
              </div>
            )}
            {row.role === "assistant" && row.truncated && (
              <div className="ai-output-warning">
                <strong>{t("Cevap token limitine takıldı.")}</strong>
                <span>{t("Max output artır veya Deep Analysis Mode kullan. Cevap yarıda kesilmiş olabilir.")}</span>
                <button type="button" disabled={busy} onClick={() => continueAnswer(row)}><Send size={13} /> {" "}{t("Devamını getir")}</button>
              </div>
            )}
            {row.evidence && row.evidence.length > 0 && (
              <div className="ai-evidence">
                <strong>{t("Kanıt")}</strong>
                {row.evidence.slice(0, 6).map((item) => (
                  <span key={item}>
                    <LinkifiedText text={item} onOpenUrl={openExternalUrl} />
                  </span>
                ))}
              </div>
            )}
            {row.evidencePaths && row.evidencePaths.length > 0 && (
              <details className="ai-evidence-details">
                <summary>{t("Kanıt detayları")}</summary>
                {row.evidencePaths.slice(0, 8).map((path) => <code key={path}>{path}</code>)}
              </details>
            )}
          </article>
          );
        })}
        {plan && (
          <section className="ai-plan-card">
            <header>
              <div><span className="micro-label">{t("AI Ayar Önerisi")}</span><strong>{plan.title_tr}</strong></div>
              <span className="panel-chip">{t("approval required")}</span>
            </header>
            <p>{plan.reason_tr}</p>
            <div className="ai-change-list">
              {plan.changes.map((change) => (
                <div className="ai-change" key={change.path}>
                  <code>{change.path}</code>
                  <span>{String(change.current)} -&gt; <strong>{String(change.proposed)}</strong></span>
                  <small>{change.reason_tr}</small>
                </div>
              ))}
            </div>
            <div className="ai-plan-actions">
              <button type="button" className="primary" disabled={!safeAiConfig.allowApprovedSettingsChanges} onClick={applyPlan}><Check size={14} /> {" "}{t("Uygula")}</button>
              <button type="button" onClick={() => setPlan(null)}>{t("Reddet")}</button>
              <button type="button" onClick={() => setJsonVisible((value) => !value)}><Copy size={14} /> {" "}{t("JSON")}</button>
            </div>
            {jsonVisible && <pre className="ai-plan-json">{JSON.stringify(plan, null, 2)}</pre>}
            {applyMessage && <small className="ai-apply-message">{applyMessage}</small>}
          </section>
        )}

        {reasoningFix && (
          <section className="ai-plan-card ai-reasoning-card">
            <header>
              <div><span className="micro-label">{t("Model formatı")}</span><strong>{t("Model final cevap üretmedi")}</strong></div>
            </header>
            <p>{t("Düşünme izi gösterilmedi. Compact final-only retry veya farklı bir instruct model deneyebilirsin.")}</p>
            <div className="ai-plan-actions">
              <button type="button" className="primary" disabled={busy} onClick={() => retryReasoning("short_context")}>{t("Kısa context ile dene")}</button>
              <button type="button" disabled={busy} onClick={increaseMaxOutputTokens}>{t("Output artır")}</button>
              <button type="button" onClick={onOpenSettings}>{t("AI Ayarları")}</button>
              <button type="button" onClick={() => setShowModelGuidance((value) => !value)}>{t("Model önerileri")}</button>
            </div>
            {reasoningActionMessage && <small className="ai-apply-message">{reasoningActionMessage}</small>}
            {showModelGuidance && (
              <div className="ai-model-guidance">
                <strong>{t("Final message.content döndüren instruct modeller:")}</strong>
                {compatibleModelOptions.length > 0 ? compatibleModelOptions.map((item) => (
                  <button key={item.model} type="button" onClick={() => selectCompatibleModel(item.model)}><Check size={13} /> {t(item.label)}</button>
                )) : <span>{t("Qwen2.5 / Llama 3.x / Mistral / Gemma Instruct")}</span>}
              </div>
            )}
          </section>
        )}
        {newMessageCount > 0 && (
          <button type="button" className="ai-new-message-button" onClick={scrollToLatest}>
            {newMessageCount} {t("yeni mesaj · En sona git")}</button>
        )}
        <div ref={chatEndRef} aria-hidden="true" />
        </div>
      </div>

      {requestProgress && (
        <div
          className={`ai-request-status is-${requestProgress.state}`}
          role="status"
          aria-live="polite"
          data-request-id={requestProgress.request_id}
          data-request-state={requestProgress.state}
        >
          <span className="ai-working-dot" aria-hidden="true" />
          <strong>{t(REQUEST_STATUS_TR[requestProgress.state])}</strong>
          <small>{elapsedSeconds} {" "}{t("sn")}{requestProgress.attempt > 0 ? t(" · attempt {count}", { count: requestProgress.attempt }) : ""}</small>
          {currentRequest && ACTIVE_REQUEST_STATES.has(requestProgress.state) && (
            <button type="button" className="danger-button" onClick={() => { void cancelRequest(); }}>{t("İptal")}</button>
          )}
        </div>
      )}

      <form
        className="ai-input-row"
        onSubmit={(event) => {
          event.preventDefault();
          const submittedMessage = composerDraft;
          if (!submittedMessage.trim()) return;
          const pending = pendingPrompt && pendingPrompt.text === submittedMessage ? pendingPrompt : null;
          void askAi(submittedMessage, pending?.mode || "chat", {
            source: pending?.source || "chat_input",
            fromComposer: true,
          });
        }}
      >
        <textarea
          ref={textareaRef}
          rows={1}
          value={composerDraft}
          disabled={!endpointReady}
          onChange={(event) => {
            const value = event.target.value;
            setComposerDraft(value);
            if (!pendingPrompt || pendingPrompt.text !== value) {
              setPendingPrompt(null);
              setActiveMode("chat");
            }
          }}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey) {
              event.preventDefault();
              if (!busy && composerDraft.trim()) event.currentTarget.form?.requestSubmit();
            }
          }}
          placeholder={endpointReady ? t("Mesaj yaz… Shift+Enter ile yeni satır") : t("AI endpoint hazır değil")}
        />
        {busy ? (
          <button type="button" className="danger-button" onClick={() => { void cancelRequest(); }}><X size={15} /> {" "}{t("İptal")}</button>
        ) : (
          <button type="submit" className="primary" disabled={!endpointReady || !composerDraft.trim()}><Send size={15} /> {" "}{t("Gönder")}</button>
        )}
      </form>
    </aside>
  );
}
