import { execFile } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import path from "node:path";
import type { AIRequest, AIRequestProgress, AIResponse } from "../shared/api";
import { AI_RUNTIME_LIMITS, DEFAULT_AI_CONFIG } from "../shared/aiSettingsContract";
import { pythonExecutable } from "./pythonRuntime";

const INFERENCE_ACTIONS = new Set(["chat", "brief", "settings"]);
const DUPLICATE_WINDOW_MS = 4000;
export function aiProcessWatchdogMs(configuredTimeoutSec: number): number {
  const timeoutSec = Math.max(1, Number(configuredTimeoutSec || DEFAULT_AI_CONFIG.timeout));
  return (
    timeoutSec * (
      AI_RUNTIME_LIMITS.maximumTransportCompatibilityAttempts
      + AI_RUNTIME_LIMITS.maximumAnswerRepairAttempts
    )
    + AI_RUNTIME_LIMITS.runtimeCapabilityDiscoveryTimeoutSeconds
    + AI_RUNTIME_LIMITS.processOverheadSeconds
    + AI_RUNTIME_LIMITS.electronWatchdogOverheadSeconds
  ) * 1000;
}
export const AI_PROCESS_HARD_TIMEOUT_MS = aiProcessWatchdogMs(DEFAULT_AI_CONFIG.timeout);
const maxConcurrentAIRequests = 1;
const maxQueuedAIRequests = 0;
let currentInference: { child: ChildProcess; key: string; requestId: string; startedAt: number } | null = null;
let lastInferenceKey = "";
let lastInferenceAt = 0;
let compatibilityCache: { key: string; notes: string[] } = { key: "", notes: [] };

export function normalizeCompatibilityBaseUrl(value: string): string {
  const raw = String(value || "").trim().replace(/\/+$/, "");
  try {
    const parsed = new URL(raw);
    parsed.protocol = parsed.protocol.toLowerCase();
    parsed.hostname = parsed.hostname.toLowerCase();
    parsed.hash = "";
    parsed.search = "";
    parsed.pathname = parsed.pathname.replace(/\/+$/, "") || "/";
    return parsed.toString().replace(/\/+$/, "");
  } catch {
    return raw.toLowerCase();
  }
}

function endpointModelCompatibilityKey(request: AIRequest): string {
  const config = request.aiConfig;
  return [
    String(config?.provider || "openai_compatible").toLowerCase(),
    normalizeCompatibilityBaseUrl(String(config?.baseUrl || "")),
    String(config?.selectedModel || config?.model || "").trim(),
  ].join("|");
}

function requestId(request: AIRequest): string {
  return request.request_id || "";
}

function inferenceKey(request: AIRequest): string {
  return [
    request.action,
    request.mode || "",
    request.contextProfile || "",
    request.retryTag || "",
    request.runDir || "",
    request.user_message || request.question || "",
    JSON.stringify(request.conversation_history || []),
    JSON.stringify(request.selected_finding_reference || {}),
    request.source || "",
    JSON.stringify(request.aiConfig || {})
  ].join("|");
}

function busyResponse(request: AIRequest): AIResponse {
  return {
    ok: false,
    unavailable: true,
    status: "busy",
    request_id: requestId(request),
    user_message: request.user_message || request.question,
    latest_user_message: request.user_message || request.question,
    source: request.source,
    lm_request_sent: false,
    local_answer_generated: false,
    answer: "Model yanıt üretiyor. Mevcut isteği bekle veya İsteği iptal et butonunu kullan.",
    error: `AI request manager busy: maxConcurrentAIRequests=${maxConcurrentAIRequests}, maxQueuedAIRequests=${maxQueuedAIRequests}`
  };
}

export function runAiAssistant(
  repoRoot: string,
  request: AIRequest,
  onProgress?: (progress: AIRequestProgress) => void,
): Promise<AIResponse> {
  if (request.action === "cancel") {
    if (currentInference) {
      if (requestId(request) && currentInference.requestId && requestId(request) !== currentInference.requestId) {
        return Promise.resolve({
          ok: false,
          status: "stale_cancel",
          request_id: requestId(request),
          lm_request_sent: false,
          local_answer_generated: false,
          answer: "Eski iptal isteği aktif yeni AI isteğine uygulanmadı."
        });
      }
      currentInference.child.kill();
      currentInference = null;
      onProgress?.({ request_id: requestId(request), state: "cancelled", attempt: 0, timestamp: new Date().toISOString() });
      return Promise.resolve({ ok: true, status: "cancelled", request_id: requestId(request), lm_request_sent: false, local_answer_generated: false, answer: "AI isteği iptal edildi." });
    }
    return Promise.resolve({ ok: true, status: "idle", request_id: requestId(request), lm_request_sent: false, local_answer_generated: false, answer: "İptal edilecek aktif AI isteği yok." });
  }
  const isInference = INFERENCE_ACTIONS.has(request.action);
  const key = inferenceKey(request);
  const now = Date.now();
  if (isInference && currentInference) {
    return Promise.resolve(busyResponse(request));
  }
  if (isInference && key === lastInferenceKey && now - lastInferenceAt < DUPLICATE_WINDOW_MS) {
    return Promise.resolve({
      ok: false,
      unavailable: true,
      status: "queued",
      request_id: requestId(request),
      user_message: request.user_message || request.question,
      latest_user_message: request.user_message || request.question,
      source: request.source,
      lm_request_sent: false,
      local_answer_generated: false,
      answer: "Aynı AI isteği kısa süre önce gönderildi; tekrar kuyruğa eklenmedi."
    });
  }
  if (isInference) {
    lastInferenceKey = key;
    lastInferenceAt = now;
  }
  const endpointCompatibilityKey = isInference ? endpointModelCompatibilityKey(request) : "";
  if (isInference && compatibilityCache.key !== endpointCompatibilityKey) {
    compatibilityCache = { key: endpointCompatibilityKey, notes: [] };
  }
  const childRequest: AIRequest = isInference && compatibilityCache.notes.length
    ? { ...request, known_compatibility_notes: [...compatibilityCache.notes] }
    : request;
  const timeout = isInference
    ? aiProcessWatchdogMs(Number(request.aiConfig?.timeout || DEFAULT_AI_CONFIG.timeout))
    : Math.max(2000, Number(request.aiConfig?.timeout || 60) * 1000 + 5000);
  const env = {
    ...process.env,
    PYTHONPATH: [repoRoot, process.env.PYTHONPATH].filter(Boolean).join(path.delimiter)
  };
  return new Promise((resolve) => {
    let progressBuffer = "";
    let stdinError = "";
    const child = execFile(
      pythonExecutable(repoRoot),
      ["-m", "reconbot.ai.assistant"],
      {
        cwd: repoRoot,
        env,
        timeout,
        maxBuffer: 1024 * 1024 * 4
      },
      (error, stdout, stderr) => {
        if (isInference && currentInference?.child === child) currentInference = null;
        const raw = stdout.trim();
        if (!raw) {
          resolve({
            ok: false,
            unavailable: true,
            request_id: requestId(request),
            user_message: request.user_message || request.question,
            latest_user_message: request.user_message || request.question,
            source: request.source,
            lm_request_sent: false,
            local_answer_generated: false,
            status: error?.killed ? "model_timeout" : "unavailable",
            answer: error?.killed ? "Model yavaş yanıt verdi / zaman aşımı." : undefined,
            error: String(error?.message || stdinError || stderr || "AI assistant returned no output.")
          });
          return;
        }
        try {
          const parsed = JSON.parse(raw) as AIResponse;
          if (isInference && parsed.ok && compatibilityCache.key === endpointCompatibilityKey) {
            const learned = (parsed.compatibility_notes || []).filter((note) =>
              note.includes("system_role_rejected") || note.includes("unsupported_reasoning_fields")
            );
            if (learned.length) compatibilityCache = { key: endpointCompatibilityKey, notes: [...new Set(learned)] };
          }
          resolve({
            ...parsed,
            request_id: parsed.request_id || requestId(request),
            user_message: parsed.user_message || request.user_message || request.question,
            latest_user_message: parsed.latest_user_message || parsed.user_message || request.user_message || request.question,
            lm_request_sent: Boolean(parsed.lm_request_sent),
            local_answer_generated: Boolean(parsed.local_answer_generated),
            source: parsed.source || request.source
          });
        } catch (parseError) {
          resolve({
            ok: false,
            unavailable: true,
            request_id: requestId(request),
            user_message: request.user_message || request.question,
            latest_user_message: request.user_message || request.question,
            source: request.source,
            lm_request_sent: false,
            local_answer_generated: false,
            status: "invalid_response",
            answer: "AI assistant geçersiz JSON döndürdü; model yanıtı gösterilmedi.",
            error: `AI assistant JSON parse failure: ${parseError instanceof Error ? parseError.message : String(parseError)}`
          });
        }
      }
    );
    child.stderr?.on("data", (chunk: Buffer | string) => {
      progressBuffer += String(chunk);
      const lines = progressBuffer.split(/\r?\n/);
      progressBuffer = lines.pop() || "";
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("{")) continue;
        try {
          const parsed = JSON.parse(trimmed) as Partial<AIRequestProgress> & { type?: string };
          if (parsed.type !== "ai_progress" || parsed.request_id !== requestId(request) || !parsed.state) continue;
          onProgress?.({
            request_id: parsed.request_id,
            state: parsed.state,
            attempt: Math.max(0, Number(parsed.attempt || 0)),
            timestamp: parsed.timestamp,
          });
        } catch {
          // Non-progress stderr remains available to the exec callback for normal diagnostics.
        }
      }
    });
    if (isInference) currentInference = { child, key, requestId: requestId(request), startedAt: now };
    child.stdin?.on("error", (streamError) => {
      // A fast operator cancellation can terminate Python while the request body is
      // still flushing. Capture the stream failure for the normal exec callback;
      // without a listener Node treats EPIPE as an uncaught main-process error.
      stdinError = streamError instanceof Error ? streamError.message : String(streamError);
    });
    child.stdin?.end(JSON.stringify(childRequest));
  });
}
