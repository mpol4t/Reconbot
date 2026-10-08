from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def read_text(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def test_ai_settings_complex_rows_are_full_width_to_prevent_grid_collapse() -> None:
    settings_pane = read_text("desktop/src/renderer/components/SettingsPane.tsx")
    theme = read_text("desktop/src/renderer/styles/theme.css")

    assert "settings-fields compact-fields ai-settings-fields" in settings_pane
    assert ".ai-settings-fields > .ai-settings-status" in theme
    assert ".ai-settings-fields > .ai-settings-warning" in theme
    assert ".ai-settings-fields > .ai-model-picker" in theme
    assert ".ai-settings-fields > .about-box" in theme
    assert "grid-column: 1 / -1;" in theme


def test_settings_layout_uses_fixed_header_single_scroller_and_full_width_osint() -> None:
    settings = read_text("desktop/src/renderer/components/SettingsPane.tsx")
    theme = read_text("desktop/src/renderer/styles/theme.css")

    assert settings.index('className="settings-sticky-bar"') < settings.index('className="settings-scroll"')
    assert "<ToolCard wide" in settings
    assert "grid-template-rows: auto minmax(0, 1fr);" in theme
    assert ".settings-tool-card.wide" in theme


def test_copilot_debug_details_are_collapsed_and_normal_messages_hide_ids() -> None:
    panel = read_text("desktop/src/renderer/components/AIAssistantPanel.tsx")

    assert '<details className="ai-technical-details"' in panel
    assert '<summary>{t("Teknik detaylar")}</summary>' in panel
    assert "AI Context Preview" in panel
    assert "Gönderilen prompt" not in panel
    assert "Yanıt bu soruya ait" not in panel


def test_copilot_textarea_keyboard_history_and_draft_recovery_contracts() -> None:
    panel = read_text("desktop/src/renderer/components/AIAssistantPanel.tsx")
    api = read_text("desktop/src/shared/api.ts")
    theme = read_text("desktop/src/renderer/styles/theme.css")

    assert "<textarea" in panel
    assert 'event.key === "Enter" && !event.shiftKey' in panel
    assert "event.currentTarget.form?.requestSubmit()" in panel
    assert ".slice(-80)" in panel
    assert "chatEndRef.current?.scrollIntoView" in panel
    assert "new ResizeObserver" in panel
    assert "ai-new-message-button" in panel
    assert "nearBottomRef" in panel
    assert 'const [composerDraft, setComposerDraft] = useState("")' in panel
    assert "const [recoverableDraft, setRecoverableDraft]" in panel
    assert "const [currentRequest, setCurrentRequest]" in panel
    assert 'setComposerDraft("")' in panel
    assert "currentRequestRef.current?.requestId" in panel
    assert 'appendUserRow: false' in panel
    assert "AI yanıtı aktif istekle eşleşmedi" in panel
    assert "Taslağı geri yükle" in panel
    assert "Tekrar dene" in panel
    assert "conversation_history: conversationHistoryRef.current" in panel
    assert "compactConversationMemory(completedTurns)" in panel
    assert 'question.toLocaleLowerCase("tr-TR")' in panel
    assert "conversation_history?: AIConversationTurn[]" in api
    assert "input_too_large" in panel
    assert ".ai-input-row textarea" in theme
    assert "max-height: 132px" in theme


def test_copilot_technical_details_expose_safe_traceability_fields() -> None:
    panel = read_text("desktop/src/renderer/components/AIAssistantPanel.tsx")

    for field in [
        "selected_model:",
        "request_status:",
        "answer_source:",
        "context_profile:",
        "answer_intent:",
        "history_turns_sent:",
        "transport_attempt_count:",
        "answer_repair_attempt_count:",
        "report_ready_prompt:",
        "settings_recommendations:",
        "approved_settings_changes:",
        "repair_reason:",
        "failure_category:",
        "finish_reason:",
        "context_compacted:",
        "local_fallback:",
    ]:
        assert field in panel
    assert "reasoning_content" not in panel
    assert "Output budget reason:" in panel
    assert "estimatedTotalTokens" in panel


def test_copilot_compact_actions_and_safe_links_remain_available() -> None:
    panel = read_text("desktop/src/renderer/components/AIAssistantPanel.tsx")
    linkify = read_text("desktop/src/renderer/lib/linkifyText.tsx")

    for label in ["Raporu Açıkla", "Sonraki Adımlar", "Bu Sonuç Güvenilir mi?", "Logları İncele", "Ayar Öner", "Diğer"]:
        assert label in panel
    assert "LinkifiedText" in panel
    assert "openExternalUrl" in panel
    assert "title={token.url}" in linkify


def test_copilot_message_visibility_source_and_scroll_contracts() -> None:
    panel = read_text("desktop/src/renderer/components/AIAssistantPanel.tsx")
    theme = read_text("desktop/src/renderer/styles/theme.css")

    assert "const LONG_MESSAGE_COLLAPSE_CHARS = 10_000" in panel
    assert 'row.text.length > LONG_MESSAGE_COLLAPSE_CHARS' in panel
    assert 'row.text.split("\\n").length > 16' not in panel
    assert "ReconBot yedek yanıtı" in panel
    assert "Model kullanılabilir cevap üretmediği için bu yanıt mevcut run artifactlerinden oluşturuldu." in panel
    assert "Model kullanılabilir cevap üretmediği için bu yanıt son AI istek durumu ve provider tanısından oluşturuldu." in panel
    assert 'row.answerSource === "local_fallback" && row.localAnswerGenerated === true' in panel
    assert 'className="ai-chat-content"' in panel
    assert "chatEndRef.current?.scrollIntoView" in panel
    assert "new ResizeObserver" in panel
    assert "scrollbar-gutter: stable" in theme
    assert "overflow-x: hidden" in theme
    assert ".ai-message.is-collapsed" in theme
    message_rule = theme[theme.index(".ai-message {"):theme.index(".ai-message.user {")]
    assert "overflow: visible" in message_rule
    assert "overflow: hidden" not in message_rule


def test_copilot_request_progress_is_persistent_outside_chat_history() -> None:
    panel = read_text("desktop/src/renderer/components/AIAssistantPanel.tsx")
    theme = read_text("desktop/src/renderer/styles/theme.css")
    preload = read_text("desktop/src/main/preload.ts")
    main = read_text("desktop/src/main/main.ts")
    manager = read_text("desktop/src/main/aiAssistant.ts")
    api = read_text("desktop/src/shared/api.ts")

    for state in [
        "preparing_request",
        "waiting_for_model",
        "validating_answer",
        "repairing_answer",
        "generating_local_fallback",
        "completed",
        "cancelled",
        "timeout",
        "context_error",
        "unusable_answer",
    ]:
        assert state in panel
        assert state in api
    assert 'className={`ai-request-status' in panel
    assert 'className="ai-working-indicator"' not in panel
    assert panel.index('className={`ai-request-status') < panel.index('<form\n        className="ai-input-row"')
    assert "onAiRequestProgress" in preload
    assert 'event.sender.send("ai:request-progress"' in main
    assert 'parsed.type !== "ai_progress"' in manager
    assert ".ai-request-status" in theme
    assert "position: sticky" in theme[theme.index(".ai-request-status {"):theme.index(".ai-request-status strong")]


def test_historical_provenance_lifecycle_and_artifact_availability_are_separate() -> None:
    api = read_text("desktop/src/shared/api.ts")
    watcher = read_text("desktop/src/main/artifactWatcher.ts")
    main = read_text("desktop/src/main/main.ts")

    assert "export type RunLifecycleState" in api
    assert "export type RunCompleteness" in api
    assert "isHistorical?: boolean" in api
    assert "processAttached?: boolean" in api
    assert "artifacts?: RunArtifactSnapshot" in api
    assert "runState: lifecycle" in watcher
    assert "isHistorical: historical" in watcher
    assert "completeness: inferCompleteness" in watcher
    assert "processAttached: attached" in watcher
    assert "processAttached && !historical" in watcher
    assert "targetFromStructuredArtifact(currentRunDir)" in watcher
    assert "targetFromLog(logTail)" in watcher
    assert 'currentRunDir ? "unknown target" : ""' in watcher
    assert "readRunStateSnapshot(runDir, true, false)" in main


def test_partial_artifact_and_missing_report_panes_have_independent_actions() -> None:
    artifact = read_text("desktop/src/renderer/components/ArtifactPane.tsx")
    report = read_text("desktop/src/renderer/components/ReportPane.tsx")

    for label in [
        "Open Run Folder",
        "Open Raw Log",
        "Open State JSON",
        "Open stages_live.json",
        "Open Config / Request",
        "Open Report External",
        "Copy currentRunDir",
    ]:
        assert label in artifact
    assert "Bu tarama tamamlanmamış. report.html henüz üretilmemiş." in artifact
    assert "Missing expected artifacts:" in artifact
    assert "disabled={!item.available}" in artifact
    assert "Bu run için report.html mevcut değil." in report
    assert "Go to Artifacts" in report
    assert "Refresh state" in report
    assert "report.exists || !report.viewUrl" in report
    assert "reportIdentity" in report


def test_sidebar_view_selection_is_explicit_and_inactive_panes_are_hidden() -> None:
    app = read_text("desktop/src/renderer/App.tsx")
    sidebar = read_text("desktop/src/renderer/components/Sidebar.tsx")
    theme = read_text("desktop/src/renderer/styles/theme.css")

    assert 'changeActiveView(view, `sidebar:${view}`)' in app
    assert 'changeActiveView(destination, `history-selection:${destination}`)' in app
    assert 'hidden={activeView !== "artifacts"}' in app
    assert 'hidden={activeView !== "report"}' in app
    assert 'data-view={item.view}' in sidebar
    assert 'aria-current={activeView === item.view ? "page" : undefined}' in sidebar
    assert ".view-pane[hidden]" in theme
