from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from .settings_contract import AI_SETTING_DEFAULTS


ProviderName = Literal["openai_compatible"]
AIResponseMode = Literal["adaptive", "fast_operator", "deep_analysis"]
RequestedResponseFormat = Literal["list", "numbered_list", "paragraph"]
AIConnectionState = Literal[
    "idle",
    "ready",
    "disabled",
    "checking",
    "checking_connection",
    "needs_recheck",
    "busy",
    "queued",
    "endpoint_unreachable",
    "model_missing",
    "model_not_loaded",
    "model_incompatible",
    "input_too_large",
    "context_length_exceeded",
    "reasoning_without_final",
    "model_timeout",
    "model_busy",
    "invalid_response",
    "timeout",
    "error",
]


@dataclass(frozen=True)
class AIConfig:
    enabled: bool = bool(AI_SETTING_DEFAULTS["enabled"])
    provider: ProviderName = "openai_compatible"
    baseUrl: str = str(AI_SETTING_DEFAULTS["baseUrl"])
    model: str = str(AI_SETTING_DEFAULTS["model"])
    selectedModel: str = str(AI_SETTING_DEFAULTS["selectedModel"])
    manualModelName: str = str(AI_SETTING_DEFAULTS["manualModelName"])
    effectiveModel: str = str(AI_SETTING_DEFAULTS["model"])
    apiKeyEnv: str = str(AI_SETTING_DEFAULTS["apiKeyEnv"])
    temperature: float = float(AI_SETTING_DEFAULTS["temperature"])
    timeout: int = int(AI_SETTING_DEFAULTS["timeout"])
    maxContextChars: int = int(AI_SETTING_DEFAULTS["maxContextChars"])
    maxOutputTokens: int = int(AI_SETTING_DEFAULTS["maxOutputTokens"])
    maxReasoningTokens: int = int(AI_SETTING_DEFAULTS["maxReasoningTokens"])
    disableReasoning: bool = bool(AI_SETTING_DEFAULTS["disableReasoning"])
    responseMode: AIResponseMode = str(AI_SETTING_DEFAULTS["responseMode"])  # type: ignore[assignment]
    autoBriefOnReportReady: bool = bool(AI_SETTING_DEFAULTS["autoBriefOnReportReady"])
    allowSettingsRecommendations: bool = bool(AI_SETTING_DEFAULTS["allowSettingsRecommendations"])
    allowApprovedSettingsChanges: bool = bool(AI_SETTING_DEFAULTS["allowApprovedSettingsChanges"])


@dataclass(frozen=True)
class ContextReference:
    path: str
    value: Any
    label_tr: str = ""


@dataclass(frozen=True)
class AIContext:
    context: dict[str, Any]
    references: list[ContextReference] = field(default_factory=list)
    truncated: bool = False


@dataclass(frozen=True)
class ChatMessage:
    role: Literal["system", "user", "assistant"]
    content: str


@dataclass(frozen=True)
class ResponsePreferences:
    """Explicit presentation constraints; never a semantic answer intent."""

    requested_item_count: int | None = None
    requested_format: RequestedResponseFormat | None = None
    single_sentence: bool = False
    short_answer: bool = False
    no_heading: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "requested_item_count": self.requested_item_count,
            "requested_format": self.requested_format,
            "single_sentence": self.single_sentence,
            "short_answer": self.short_answer,
            "no_heading": self.no_heading,
        }


@dataclass(frozen=True)
class ChatResponse:
    ok: bool
    answer: str
    model: str
    unavailable: bool = False
    error: str = ""
    status: str = ""
    action_plan: dict[str, Any] | None = None
    references: list[str] = field(default_factory=list)
    lm_request_sent: bool = False
    local_answer_generated: bool = False
    latest_user_message: str = ""
    finish_reason: str = ""
    output_truncated: bool = False
    endpoint_debug: dict[str, Any] = field(default_factory=dict)
    attempt_count: int = 0
    compatibility_notes: list[str] = field(default_factory=list)
    answer_source: str = "model"
    fallback_reason: str = ""
    repair_reason: str = ""
    repair_attempted: bool = False
    transport_attempt_count: int = 0
    answer_repair_attempt_count: int = 0


@dataclass(frozen=True)
class ResolvedAIRequestPlan:
    model_profile: str
    answer_intent: str
    context_profile: str
    user_message_chars: int
    injected_context_chars: int
    estimated_input_tokens: int
    effective_max_output_tokens: int
    effective_request_timeout_sec: int
    total_process_watchdog_sec: int
    disable_reasoning: bool
    retry_policy: dict[str, Any]
    context_was_compacted: bool
    compatibility_notes: list[str] = field(default_factory=list)
    estimated_context_window_tokens: int = 0
    context_budget_chars: int = 0
    compatible: bool = True
    incompatibility_reason: str = ""
    user_message_fits: bool = True
    history_turns_received: int = 0
    history_turns_sent: int = 0
    history_was_compacted: bool = False
    history_budget_chars: int = 0
    output_budget_reason: str = ""
    system_prompt_reserve_tokens: int = 0
    compact_system_prompt: bool = False
    reserved_output_tokens: int = 0
    estimated_total_tokens: int = 0
    configured_max_output_tokens: int = 0
    configured_max_context_chars: int = 0
    effective_injected_context_chars: int = 0
    configured_timeout_sec: int = 0
    loaded_context_length: int = 0
    model_max_context_length: int = 0
    context_metadata_source: str = ""
    conservative_context_fallback_used: bool = False
    reserved_safety_margin_tokens: int = 0
    output_value_source: str = "user_settings"
    output_limit_reason: str = ""
    timeout_value_source: str = "user_settings"
    timeout_limit_reason: str = ""
    provider_temperature: float = 0.0
    reasoning_fields_sent: list[str] = field(default_factory=list)
    provider_payload_fields: list[str] = field(default_factory=list)
    estimated_history_tokens: int = 0
    reasoning_configuration_reason: str = ""
    response_preferences: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "modelProfile": self.model_profile,
            "answerIntent": self.answer_intent,
            "contextProfile": self.context_profile,
            "userMessageChars": self.user_message_chars,
            "injectedContextChars": self.injected_context_chars,
            "estimatedInputTokens": self.estimated_input_tokens,
            "effectiveMaxOutputTokens": self.effective_max_output_tokens,
            "effectiveRequestTimeoutSec": self.effective_request_timeout_sec,
            "totalProcessWatchdogSec": self.total_process_watchdog_sec,
            "disableReasoning": self.disable_reasoning,
            "retryPolicy": self.retry_policy,
            "contextWasCompacted": self.context_was_compacted,
            "compatibilityNotes": self.compatibility_notes,
            "estimatedContextWindowTokens": self.estimated_context_window_tokens,
            "contextBudgetChars": self.context_budget_chars,
            "compatible": self.compatible,
            "incompatibilityReason": self.incompatibility_reason,
            "userMessageFits": self.user_message_fits,
            "historyTurnsReceived": self.history_turns_received,
            "historyTurnsSent": self.history_turns_sent,
            "historyWasCompacted": self.history_was_compacted,
            "historyBudgetChars": self.history_budget_chars,
            "outputBudgetReason": self.output_budget_reason,
            "systemPromptReserveTokens": self.system_prompt_reserve_tokens,
            "compactSystemPrompt": self.compact_system_prompt,
            "reservedOutputTokens": self.reserved_output_tokens,
            "estimatedTotalTokens": self.estimated_total_tokens,
            "configuredMaxOutputTokens": self.configured_max_output_tokens,
            "configuredMaxContextChars": self.configured_max_context_chars,
            "effectiveInjectedContextChars": self.effective_injected_context_chars,
            "configuredTimeoutSec": self.configured_timeout_sec,
            "loadedContextLength": self.loaded_context_length,
            "modelMaxContextLength": self.model_max_context_length,
            "contextMetadataSource": self.context_metadata_source,
            "conservativeContextFallbackUsed": self.conservative_context_fallback_used,
            "reservedSafetyMarginTokens": self.reserved_safety_margin_tokens,
            "outputValueSource": self.output_value_source,
            "outputLimitReason": self.output_limit_reason,
            "timeoutValueSource": self.timeout_value_source,
            "timeoutLimitReason": self.timeout_limit_reason,
            "providerTemperature": self.provider_temperature,
            "reasoningFieldsSent": self.reasoning_fields_sent,
            "providerPayloadFields": self.provider_payload_fields,
            "estimatedHistoryTokens": self.estimated_history_tokens,
            "reasoningConfigurationReason": self.reasoning_configuration_reason,
            "responsePreferences": self.response_preferences,
        }


@dataclass(frozen=True)
class AIStatus:
    enabled: bool
    provider: str
    baseUrl: str
    model: str
    connection: AIConnectionState
    ready: bool
    can_chat: bool
    user_message_tr: str
    operator_action_tr: str
    setup_hint_tr: str
    checked_at: str
    available_models: list[str] = field(default_factory=list)
    effective_model: str = ""
    tested_model: str = ""
    selected_model_available: bool | None = None
    reason: str = ""
    endpoint_debug: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SettingChange:
    path: str
    current: Any
    proposed: Any
    reason_tr: str


@dataclass(frozen=True)
class SettingsRecommendation:
    type: Literal["settings_recommendation"]
    title_tr: str
    reason_tr: str
    changes: list[SettingChange]
    risk_score_impact: int = 0
    requires_user_approval: bool = True
