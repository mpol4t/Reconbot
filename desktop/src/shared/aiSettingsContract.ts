import contractJson from "../../../reconbot/ai/settings_contract.json";
import type { AIConfig, AIResponseMode } from "./api";

type RuntimeLimits = {
  unknownModelContextTokens: number;
  minimumAcceptedContextTokens: number;
  maximumAcceptedContextTokens: number;
  safetyMarginFraction: number;
  minimumSafetyMarginTokens: number;
  charsPerTokenEstimate: number;
  systemPromptTokenReserve: number;
  compactSystemPromptTokenReserve: number;
  maximumHistoryTurns: number;
  maximumRendererMemoryTurns: number;
  maximumRendererMemoryChars: number;
  maximumTransportCompatibilityAttempts: number;
  maximumAnswerRepairAttempts: number;
  runtimeCapabilityDiscoveryTimeoutSeconds: number;
  processOverheadSeconds: number;
  electronWatchdogOverheadSeconds: number;
  hardMaximumOutputTokens: number;
};

interface ContractShape {
  contractVersion: number;
  defaults: AIConfig;
  runtimeLimits: RuntimeLimits;
  actionSettings: Record<string, { type: string; minimum?: number; maximum?: number; values?: string[] }>;
}

export const AI_SETTINGS_CONTRACT = contractJson as ContractShape;
export const DEFAULT_AI_CONFIG: AIConfig = Object.freeze({ ...AI_SETTINGS_CONTRACT.defaults });
export const AI_RUNTIME_LIMITS = Object.freeze({ ...AI_SETTINGS_CONTRACT.runtimeLimits });

export function validAiSettingChange(path: string, value: unknown): boolean {
  const rule = AI_SETTINGS_CONTRACT.actionSettings[path];
  if (!rule) return false;
  if (rule.type === "integer") return typeof value === "number" && Number.isSafeInteger(value) && value >= rule.minimum! && value <= rule.maximum!;
  if (rule.type === "boolean") return typeof value === "boolean";
  if (rule.type === "enum") return typeof value === "string" && Boolean(rule.values?.includes(value));
  if (rule.type === "severity") return typeof value === "string" && value.trim().length > 0 && value.split(",").every((part) => rule.values?.includes(part.trim()));
  if (rule.type === "env") return typeof value === "string" && (value === "" || /^[A-Z_][A-Z0-9_]{0,80}$/.test(value));
  return false;
}

function boolValue(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" ? value : fallback;
}

function numberValue(value: unknown, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function responseMode(value: unknown): AIResponseMode {
  return value === "deep_analysis" || value === "fast_operator" ? value : "adaptive";
}

export function getEffectiveAiModel(value?: Partial<AIConfig> | null): string {
  const source = value || {};
  for (const candidate of [source.selectedModel, source.manualModelName, source.model, source.effectiveModel]) {
    if (typeof candidate === "string" && candidate.trim()) return candidate.trim();
  }
  return DEFAULT_AI_CONFIG.model;
}

export function normalizeAiConfig(value?: Partial<AIConfig> | null): AIConfig {
  const source = value || {};
  const selectedModel = stringValue(source.selectedModel, "").trim();
  const manualModelName = stringValue(source.manualModelName, "").trim();
  const legacyModel = stringValue(source.model, DEFAULT_AI_CONFIG.model).trim();
  const normalizedSelection = selectedModel || (!manualModelName ? legacyModel : "");
  const normalizedManual = manualModelName || (!normalizedSelection ? legacyModel : "");
  const effectiveModel = getEffectiveAiModel({
    ...source,
    selectedModel: normalizedSelection,
    manualModelName: normalizedManual,
    model: legacyModel,
  });
  return {
    enabled: boolValue(source.enabled, DEFAULT_AI_CONFIG.enabled),
    provider: "openai_compatible",
    baseUrl: stringValue(source.baseUrl, DEFAULT_AI_CONFIG.baseUrl),
    model: effectiveModel,
    selectedModel: normalizedSelection,
    manualModelName: normalizedManual,
    effectiveModel,
    apiKeyEnv: stringValue(source.apiKeyEnv, DEFAULT_AI_CONFIG.apiKeyEnv),
    temperature: numberValue(source.temperature, DEFAULT_AI_CONFIG.temperature),
    timeout: numberValue(source.timeout, DEFAULT_AI_CONFIG.timeout),
    maxContextChars: numberValue(source.maxContextChars, DEFAULT_AI_CONFIG.maxContextChars),
    maxOutputTokens: numberValue(source.maxOutputTokens, DEFAULT_AI_CONFIG.maxOutputTokens),
    maxReasoningTokens: numberValue(source.maxReasoningTokens, DEFAULT_AI_CONFIG.maxReasoningTokens),
    disableReasoning: boolValue(source.disableReasoning, DEFAULT_AI_CONFIG.disableReasoning),
    responseMode: responseMode(source.responseMode),
    autoBriefOnReportReady: boolValue(source.autoBriefOnReportReady, DEFAULT_AI_CONFIG.autoBriefOnReportReady),
    allowSettingsRecommendations: boolValue(source.allowSettingsRecommendations, DEFAULT_AI_CONFIG.allowSettingsRecommendations),
    allowApprovedSettingsChanges: boolValue(source.allowApprovedSettingsChanges, DEFAULT_AI_CONFIG.allowApprovedSettingsChanges),
  };
}
