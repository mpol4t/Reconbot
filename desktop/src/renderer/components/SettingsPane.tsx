import { t } from "../lib/i18n";
import { Bot, Camera, CheckCircle2, FileSearch, Globe, Radar, Search, ShieldAlert, SlidersHorizontal } from "lucide-react";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { AIStatus, ConfigDefaults, ScanConfig, ToolSettings } from "../../shared/api";
import { LOCAL_EXAMPLE_METADATA_FEED, METADATA_FEED_PROVIDERS, metadataFeedStatusPreview, normalizeMetadataFeed, validateMetadataFeedUiConfig } from "../../shared/metadataFeed";
import { applyScanProfile, getEffectiveAiModel, markCustom, normalizeAiConfig, normalizeScanConfig, scanProfiles } from "../lib/settingsModel";

interface SettingsPaneProps {
  defaults: ConfigDefaults;
  config: ScanConfig;
  aiStatus: AIStatus | null;
  onChange: (config: ScanConfig) => void;
  onTestAiConnection: () => void;
  onOpenAiSetup: () => void;
  onRejectAiSettingsValue: (message: string) => void;
}

type ToolKey = keyof ToolSettings;
type BadgeTone = "muted" | "warn" | "bad" | "ok";

function timeoutWarnings(value: number, low: number, high: number): string[] {
  if (value < low) return ["May miss"];
  if (value > high) return ["Slow"];
  return [];
}

function profileImpact(settings: ToolSettings): { speed: string; noise: string; coverage: string; traffic: string } {
  const speedScore =
    (settings.katana.maxDepth > 3 ? 1 : 0) +
    (settings.gobuster.threads < 10 ? 1 : 0) +
    (settings.ffuf.rateLimit < 50 ? 1 : 0) +
    (settings.screenshots.maxScreenshots > 30 ? 1 : 0) +
    (settings.nuclei.maxTemplates > 2000 ? 1 : 0);
  const noiseScore =
    (settings.gobuster.threads > 50 ? 2 : settings.gobuster.threads > 30 ? 1 : 0) +
    (settings.ffuf.rateLimit > 200 ? 2 : settings.ffuf.rateLimit > 120 ? 1 : 0) +
    (settings.nuclei.rateLimit > 30 ? 1 : 0) +
    (settings.katana.maxUrls > 500 ? 1 : 0);
  const coverageScore =
    (settings.katana.maxDepth >= 3 ? 1 : 0) +
    (settings.katana.maxUrls >= 100 ? 1 : 0) +
    (settings.screenshots.maxScreenshots >= 10 ? 1 : 0) +
    (settings.nuclei.severityFilter.includes("low") ? 1 : 0);
  return {
    speed: speedScore >= 3 ? "Slow" : speedScore <= 1 ? "Fast" : "Balanced",
    noise: noiseScore >= 3 ? "High" : noiseScore === 0 ? "Low" : "Medium",
    coverage: coverageScore >= 3 ? "High" : coverageScore <= 1 ? "Low" : "Medium",
    traffic: noiseScore >= 3 ? "High" : noiseScore === 0 ? "Low" : "Medium"
  };
}

function aiStatusTone(status: AIStatus | null): BadgeTone {
  if (!status || ["checking", "checking_connection", "needs_recheck", "busy", "queued", "timeout", "model_timeout", "model_busy", "reasoning_without_final"].includes(status.connection)) return "warn";
  if (status.ready) return "ok";
  if (status.connection === "disabled") return "muted";
  return "bad";
}

function aiStatusTitle(status: AIStatus | null): string {
  if (!status || status.connection === "checking" || status.connection === "checking_connection") return "AI bağlantısı kontrol ediliyor...";
  if (status.connection === "needs_recheck") return "Bağlantı tekrar kontrol edilmeli";
  if (status.connection === "busy") return "Model yanıt üretiyor";
  if (status.connection === "queued") return "İstek sırada";
  if (status.connection === "timeout") return "Model yavaş yanıt verdi / zaman aşımı";
  if (status.connection === "model_timeout") return "Model yavaş yanıt verdi / zaman aşımı";
  if (status.connection === "model_busy") return "Model meşgul";
  if (status.connection === "reasoning_without_final") return "Model final cevap üretmedi";
  if (status.ready) return "Yerel model bağlı";
  if (status.connection === "disabled") return "AI devre dışı";
  if (status.connection === "model_missing" || status.connection === "model_not_loaded") return "Model yüklü değil veya adı eşleşmiyor";
  if (status.connection === "invalid_response") return "Endpoint OpenAI-compatible olmayan cevap döndürdü";
  return "AI bağlantısı yok";
}

function normalizedBaseUrlPreview(value: string): string {
  const trimmed = value.trim().replace(/\/+$/, "");
  if (!trimmed) return "http://127.0.0.1:1234/v1";
  if (trimmed.endsWith("/v1")) return trimmed;
  const marker = "/v1/";
  const markerIndex = trimmed.indexOf(marker);
  if (markerIndex >= 0) return trimmed.slice(0, markerIndex + 3);
  return `${trimmed}/v1`;
}

function baseUrlHint(value: string): string {
  const normalized = normalizedBaseUrlPreview(value);
  if (value.trim().replace(/\/+$/, "") !== normalized) {
    return t("OpenAI-compatible endpoints usually end with /v1. ReconBot will use {url}.", {url: normalized});
  }
  return "LM Studio / llama.cpp endpoint. Default http://127.0.0.1:1234/v1";
}

function isObviouslyNonChatModel(model: string): boolean {
  return /(^|[\/_.-])(embed(ding)?|rerank(er)?|cross[-_]?encoder|sentence[-_]?transformer|clip|whisper|tts)($|[\/_.-])/i.test(model);
}

export default function SettingsPane({ defaults, config: rawConfig, aiStatus, onChange, onTestAiConnection, onOpenAiSetup, onRejectAiSettingsValue }: SettingsPaneProps): JSX.Element {
  const config = useMemo(() => normalizeScanConfig(rawConfig, defaults), [defaults, rawConfig]);
  const settingsScrollRef = useRef<HTMLDivElement | null>(null);
  const interactionAnchorRef = useRef<HTMLElement | null>(null);
  const pendingScrollRestoreRef = useRef<{ top: number; token: number; anchor: HTMLElement | null; anchorY: number | null } | null>(null);

  const emitChange = (nextConfig: ScanConfig): void => {
    const token = Date.now();
    const anchor = interactionAnchorRef.current || document.activeElement?.closest<HTMLElement>(".setting-toggle") || null;
    interactionAnchorRef.current = null;
    pendingScrollRestoreRef.current = {
      top: settingsScrollRef.current?.scrollTop ?? 0,
      token,
      anchor,
      anchorY: anchor?.getBoundingClientRect().top ?? null
    };
    window.setTimeout(() => {
      if (pendingScrollRestoreRef.current?.token === token) pendingScrollRestoreRef.current = null;
    }, 500);
    onChange(nextConfig);
  };

  useLayoutEffect(() => {
    const pending = pendingScrollRestoreRef.current;
    const scroller = settingsScrollRef.current;
    if (!pending || !scroller) return;
    const restore = (): void => {
      scroller.scrollTop = Math.min(pending.top, Math.max(0, scroller.scrollHeight - scroller.clientHeight));
      if (pending.anchor?.isConnected && pending.anchorY !== null) {
        const delta = pending.anchor.getBoundingClientRect().top - pending.anchorY;
        if (Math.abs(delta) >= 0.5) {
          scroller.scrollTop = Math.max(0, Math.min(scroller.scrollTop + delta, scroller.scrollHeight - scroller.clientHeight));
        }
      }
    };
    restore();
    const frame = window.requestAnimationFrame(() => {
      restore();
      if (pendingScrollRestoreRef.current?.token === pending.token) pendingScrollRestoreRef.current = null;
    });
    return () => window.cancelAnimationFrame(frame);
  }, [aiStatus, rawConfig]);

  const updateTool = <K extends ToolKey>(tool: K, patch: Partial<ToolSettings[K]>, toolName?: string): void => {
    const nextSettings = {
      ...config.toolSettings,
      [tool]: {
        ...config.toolSettings[tool],
        ...patch
      }
    };
    const enabledPatch = Object.prototype.hasOwnProperty.call(patch, "enabled")
      ? { [toolName || tool]: Boolean((patch as { enabled?: boolean }).enabled) }
      : {};
    emitChange(markCustom({
      ...config,
      tools: { ...config.tools, ...enabledPatch },
      toolSettings: nextSettings
    }));
  };

  const updateOsint = (patch: Partial<ToolSettings["osint"]>): void => {
    const enabled = Object.prototype.hasOwnProperty.call(patch, "enabled")
      ? Boolean(patch.enabled)
      : config.toolSettings.osint.enabled;
    emitChange(markCustom({
      ...config,
      osintEnabled: enabled,
      osintProfile: "safe_mvp",
      toolSettings: {
        ...config.toolSettings,
        osint: {
          ...config.toolSettings.osint,
          ...patch,
          enabled,
          mode: "safe_mvp",
          passiveOnly: true
        }
      }
    }));
  };

  const updateMetadataFeed = (patch: Partial<ToolSettings["osint"]["leakSources"]["metadataFeed"]>): void => {
    const current = normalizeMetadataFeed(config.toolSettings.osint.leakSources?.metadataFeed);
    const nextFeed = normalizeMetadataFeed({ ...current, ...patch });
    updateOsint({
      leakSources: {
        ...config.toolSettings.osint.leakSources,
        metadataFeed: nextFeed
      }
    });
  };

  const updateDarkweb = (patch: Partial<ToolSettings["osint"]["darkweb"]>): void => {
    updateOsint({
      darkweb: {
        ...config.toolSettings.osint.darkweb,
        ...patch
      }
    });
  };

  const updateManualDarkwebImport = (patch: Partial<ToolSettings["osint"]["darkweb"]["manualMetadataImport"]>): void => {
    updateDarkweb({
      manualMetadataImport: {
        ...config.toolSettings.osint.darkweb.manualMetadataImport,
        ...patch
      }
    });
  };

  const updateCustomDarkwebProvider = (patch: Partial<ToolSettings["osint"]["darkweb"]["customHttpsProvider"]>): void => {
    updateDarkweb({
      customHttpsProvider: {
        ...config.toolSettings.osint.darkweb.customHttpsProvider,
        ...patch
      }
    });
  };

  const updateOsintSource = <K extends keyof ToolSettings["osint"]["sources"]>(
    source: K,
    patch: Partial<ToolSettings["osint"]["sources"][K]>
  ): void => {
    updateOsint({
      sources: {
        ...config.toolSettings.osint.sources,
        [source]: {
          ...config.toolSettings.osint.sources[source],
          ...patch
        }
      }
    });
  };

  const toolSettings = config.toolSettings;
  const impact = profileImpact(toolSettings);
  const metadataFeed = normalizeMetadataFeed(toolSettings.osint.leakSources?.metadataFeed);
  const metadataFeedValidation = validateMetadataFeedUiConfig(metadataFeed);
  const metadataFeedPreview = metadataFeedStatusPreview(metadataFeed);
  const darkweb = toolSettings.osint.darkweb;
  const availableAiModels = aiStatus?.available_models || [];
  const selectedAiModel = config.ai.selectedModel?.trim() || "";
  const manualAiModel = config.ai.manualModelName?.trim() || "";
  const effectiveAiModel = getEffectiveAiModel(config.ai);
  const selectedModelMissing = Boolean(selectedAiModel && availableAiModels.length > 0 && !availableAiModels.includes(selectedAiModel));
  const updateAi = (patch: Partial<ScanConfig["ai"]>): void => {
    const nextSource: Partial<ScanConfig["ai"]> = {
      ...config.ai,
      ...patch
    };
    if (Object.prototype.hasOwnProperty.call(patch, "manualModelName") && !Object.prototype.hasOwnProperty.call(patch, "selectedModel")) {
      nextSource.selectedModel = "";
    }
    const nextAi = normalizeAiConfig(nextSource);
    emitChange({ ...config, ai: nextAi });
  };

  return (
    <section
      className="settings-page compact-settings"
      onChangeCapture={(event) => {
        const control = event.target;
        interactionAnchorRef.current = control instanceof HTMLInputElement && control.type === "checkbox"
          ? control.closest<HTMLElement>(".setting-toggle")
          : null;
      }}
    >
      <div className="settings-sticky-bar">
        <div>
          <span className="micro-label">{t("Settings")}</span>
          <strong>{t("Tool Parameters")}</strong>
        </div>
        <div className="impact-summary">
          <Impact label={t("Speed")} value={t(impact.speed)} />
          <Impact label={t("Noise")} value={impact.noise} />
          <Impact label={t("Coverage")} value={impact.coverage} />
          <Impact label={t("Traffic")} value={impact.traffic} />
        </div>
      </div>

      <div ref={settingsScrollRef} className="settings-scroll">

        <section className="cockpit-panel settings-section dense">
          <header className="panel-head compact-head">
            <div>
              <span className="micro-label"><SlidersHorizontal size={12} /> {" "}{t("Default Profile Presets")}</span>
              <h2>{t("Default Scan Profile")}</h2>
            </div>
            <span className="panel-chip">{config.scanProfile}</span>
          </header>
          <div className="settings-segmented compact">
            {scanProfiles.map((profile) => (
              <button
                key={t(profile)}
                type="button"
                className={config.scanProfile === profile ? "selected" : ""}
                onClick={() => emitChange(applyScanProfile(config, defaults, profile))}
              >
                {t(profile)}
              </button>
            ))}
            <button type="button" className={config.scanProfile === "custom" ? "selected" : ""} disabled={config.scanProfile !== "custom"}>
              {t("custom")}</button>
          </div>
        </section>

        <section className="cockpit-panel settings-section dense">
          <header className="panel-head compact-head">
            <div>
              <span className="micro-label">{t("Global Limits")}</span>
              <h2>{t("Shared Guardrails")}</h2>
            </div>
          </header>
          <div className="global-limit-grid">
            <LimitInfo title={t("Global timeout")} badge="Config only" text="No single backend global timeout exists yet. Per-tool timeouts below are written to generated config where supported." />
            <LimitInfo title={t("Max runtime")} badge="Config only" text="No run-wide max runtime field exists yet. Keep high per-tool timeouts conservative to avoid long hangs." />
            <LimitInfo title={t("Concurrency / rate")} badge="Config only" text="Use Gobuster threads, FFUF rate, and Nuclei rate below. Higher values increase traffic/noise and may trigger WAFs." />
          </div>
        </section>

        <section className="cockpit-panel settings-section dense">
          <header className="panel-head compact-head">
            <div>
              <span className="micro-label">{t("RECONBOT AI")}</span>
              <h2>{t("Operator Copilot")}</h2>
              <p>{t("Local OpenAI-compatible endpoint. Secret değerleri saklanmaz; yalnız env var adı tutulur. ReconBot AI olmadan normal çalışır.")}</p>
            </div>
            <span className="panel-chip">{t(aiStatusTitle(aiStatus))}</span>
          </header>
          <div className="settings-fields compact-fields ai-settings-fields">
            <div className={`ai-settings-status tone-${aiStatusTone(aiStatus)}`}>
              <div>
                <strong>{t("Bağlantı Durumu ·")}{" "}{t(aiStatusTitle(aiStatus))}</strong>
                <small>{t(aiStatus?.user_message_tr || "AI durumu henüz kontrol edilmedi.")}</small>
                <small>{t(aiStatus?.operator_action_tr || "Bağlantıyı Test Et butonu ile durumu kontrol et.")}</small>
              </div>
              <div className="ai-settings-actions">
                <button type="button" className="primary" onClick={onTestAiConnection}><CheckCircle2 size={14} /> {" "}{t("Bağlantıyı Test Et")}</button>
                <button type="button" onClick={onOpenAiSetup}><Bot size={14} /> {" "}{t("Kurulum Rehberi")}</button>
              </div>
            </div>
            {aiStatus?.connection === "reasoning_without_final" && Number(aiStatus.reasoning_without_final_count || 0) >= 2 && (
              <div className="ai-settings-warning">
                {t("Bu model ReconBot chat için uyumsuz davranıyor olabilir: final content yerine reasoning_content üretiyor. Daha stabil kullanım için final message.content döndüren instruct model seç. Qwen reasoning modellerinde Thinking/Reasoning kapalı olmalı. LM Studio'da final content döndüren instruct model daha stabil çalışır. Bu bir bağlantı hatası değil; model cevap formatı uyumsuzluğu.")}</div>
            )}
            <Toggle label={t("AI enabled")} checked={config.ai.enabled} onChange={(enabled) => updateAi({ enabled })} />
            <TextField label={t("Provider")} value={config.ai.provider} readOnly badge="Locked" hint={t("OpenAI-compatible local endpoint.")} onChange={() => undefined} />
            <TextField label={t("Base URL")} value={config.ai.baseUrl} hint={t(baseUrlHint(config.ai.baseUrl))} onChange={(baseUrl) => updateAi({ baseUrl })} />
            <div className="ai-model-picker">
              <label className="field compact-field dense-field">
                <span>{t("Endpoint modelleri")}</span>
                <select
                  value={selectedAiModel}
                  disabled={availableAiModels.length === 0}
                  onChange={(event) => {
                    updateAi({ selectedModel: event.target.value });
                  }}
                >
                  <option value="">{t("Manual model name kullan")}</option>
                  {availableAiModels.length === 0 && selectedAiModel && <option value={selectedAiModel}>{t("Önce Modelleri Yenile ·")}{" "}{selectedAiModel}</option>}
                  {availableAiModels.length > 0 && selectedModelMissing && (
                    <option value={selectedAiModel}>{selectedAiModel} {" "}{t("· seçili, endpointte yok")}</option>
                  )}
                  {availableAiModels.map((model) => (
                    <option key={model} value={model}>{model}{isObviouslyNonChatModel(model) ? t(" · chat uyumsuz") : ""}</option>
                  ))}
                </select>
                <small>{availableAiModels.length ? `${availableAiModels.length} model /models endpoint'inden okundu.` : t("Endpoint model listesi destekliyorsa burada görünür.")}</small>
              </label>
              <div className="ai-settings-actions compact-actions">
                <button type="button" onClick={onTestAiConnection}><Bot size={14} /> {" "}{t("Modelleri Yenile")}</button>
              </div>
              {selectedModelMissing && (
                <div className="ai-settings-warning">
                  {t("Seçili model endpoint üzerinde görünmüyor. Yüklü modellerden birini seç veya model adını elle düzelt.")}</div>
              )}
            </div>
            <TextField label={t("Manual model name")} value={manualAiModel} hint={`Endpoint modeli seçilmediyse sonraki istekte kullanılır. Etkili model: ${effectiveAiModel}`} onChange={(manualModelName) => updateAi({ manualModelName })} />
            <TextField label={t("API key env var")} value={config.ai.apiKeyEnv} hint={t("Opsiyonel. Secret değeri değil, sadece ortam değişkeni adı.")} onChange={(apiKeyEnv) => updateAi({ apiKeyEnv })} />
            <NumberField label={t("Temperature")} value={config.ai.temperature} recommended="0.2" impact="Düşük değer daha tutarlı operatör yanıtı üretir." onChange={(temperature) => updateAi({ temperature })} />
            <NumberField label={t("Timeout")} value={config.ai.timeout} recommended="60s" impact="Bu değer her provider denemesinin operatör tavanıdır; 300 veya 600 saniye gizlice 180'e düşürülmez. Etkili değer Teknik detaylarda görünür." onChange={(timeout) => updateAi({ timeout })} />
            <NumberField label={t("Max context chars")} value={config.ai.maxContextChars} recommended="24000" impact="ReconBot artifact context tavanıdır. Etkili enjekte edilen miktar profil, geçmiş ve yüklü model penceresine göre Teknik detaylarda açıklanır." onChange={(maxContextChars) => updateAi({ maxContextChars })} />
            <label className="field compact-field dense-field">
              <span>{t("Response mode")}</span>
              <select
                value={config.ai.responseMode}
                onChange={(event) => {
                  const responseMode = event.target.value;
                  updateAi({ responseMode: responseMode === "deep_analysis" || responseMode === "fast_operator" ? responseMode : "adaptive" });
                }}
              >
                <option value="adaptive">{t("Adaptive")}</option>
                <option value="fast_operator">{t("Fast Operator Mode")}</option>
                <option value="deep_analysis">{t("Deep Analysis Mode")}</option>
              </select>
              <small>{t("Adaptive varsayılandır ve model/intent/input boyutuna göre plan yapar. Fast gecikmeyi, Deep daha geniş analiz bütçesini tercih eder.")}</small>
            </label>
            <Toggle
              label={t("Thinking/Reasoning")}
              checked={!config.ai.disableReasoning}
              badge={config.ai.disableReasoning ? "kapalı" : "açık"}
              help="Kapalıyken reasoning alanı gönderilmez. Açıkken de yalnız endpoint ve model metadata'sı açıkça destek bildirirse desteklenen alan gönderilir."
              onChange={(reasoningEnabled) => updateAi({ disableReasoning: !reasoningEnabled })}
            />
            <NumberField label={t("Max output tokens")} value={config.ai.maxOutputTokens} recommended="2400" impact="Kullanıcı tavanıdır. Planner yalnız yüklü context, provider kapasitesi, input boyutu veya belgeli hard limit gerektiğinde düşürür ve nedeni Teknik detaylarda gösterir." onChange={(maxOutputTokens) => updateAi({ maxOutputTokens })} />
            <Toggle label={t("Report-ready prompt")} checked={config.ai.autoBriefOnReportReady} help="Hub içindeki 'özet çıkarabilirim' durumunu ve sonraki provider promptundaki report-ready tercihini değiştirir; kendi başına LLM çağrısı başlatmaz." onChange={(autoBriefOnReportReady) => updateAi({ autoBriefOnReportReady })} />
            <Toggle label={t("Settings recommendations")} checked={config.ai.allowSettingsRecommendations} help={config.ai.allowSettingsRecommendations ? "AI ayar önerisi kartları açık." : "Ayar önerileri kapalı."} onChange={(allowSettingsRecommendations) => updateAi({ allowSettingsRecommendations })} />
            <Toggle label={t("Approved settings changes")} checked={config.ai.allowApprovedSettingsChanges} onChange={(allowApprovedSettingsChanges) => updateAi({ allowApprovedSettingsChanges })} />
            <div className="about-box">
              <strong>{t("About")}</strong>
              <small>{t("ReconBot Operator Console · Build info moved from the sidebar AI hub. AI cannot change target, risk score, secrets, report artifacts, safety flags, or start scans.")}</small>
            </div>
          </div>
        </section>

        <section className="settings-tool-grid compact">
          <ToolCard icon={<Radar size={14} />} title={t("Katana")} description={t("Crawler depth and URL cap. Larger crawls increase runtime and duplicate/noisy URLs.")}>
            <Toggle label={t("Enabled")} checked={toolSettings.katana.enabled} onChange={(enabled) => updateTool("katana", { enabled }, "katana")} />
            <NumberField label={t("Max depth")} value={toolSettings.katana.maxDepth} recommended="1-3" impact="Higher depth finds nested routes but grows crawl size." warnings={[
              ...(toolSettings.katana.maxDepth > 3 ? ["Noisy"] : []),
              ...(toolSettings.katana.maxDepth <= 1 ? ["May miss"] : [])
            ]} onChange={(value) => updateTool("katana", { maxDepth: value })} />
            <NumberField label={t("Timeout")} value={toolSettings.katana.timeout} recommended="10-30s" impact="Longer waits tolerate slow pages but slow the run." warnings={timeoutWarnings(toolSettings.katana.timeout, 10, 30)} onChange={(value) => updateTool("katana", { timeout: value })} />
            <NumberField label={t("Rate limit (requests/s)")} value={toolSettings.katana.rateLimit} recommended="low/medium" impact="Saniyedeki istek sınırı. 0, trafik profilinin hızını kullanır." warnings={[
              ...(toolSettings.katana.rateLimit === 0 ? ["High traffic"] : []),
              ...(toolSettings.katana.rateLimit > 20 ? ["Slow"] : [])
            ]} onChange={(value) => updateTool("katana", { rateLimit: value })} />
            <NumberField label={t("Max retained URLs")} value={toolSettings.katana.maxUrls} recommended="50-300" impact="Saklanan URL sayısını sınırlar; bir tarama çağrısı içinde ek istekler olabilir." warnings={[
              ...(toolSettings.katana.maxUrls > 500 ? ["Noisy"] : []),
              ...(toolSettings.katana.maxUrls < 25 ? ["May miss"] : [])
            ]} onChange={(value) => updateTool("katana", { maxUrls: value })} />
          </ToolCard>

          <ToolCard icon={<Search size={14} />} title={t("Gobuster")} description={t("Directory discovery. More threads and extensions multiply requests.")}>
            <Toggle label={t("Enabled")} checked={toolSettings.gobuster.enabled} onChange={(enabled) => updateTool("gobuster", { enabled }, "gobuster")} />
            <SelectField label={t("Wordlist profile")} badge="Config only" value={toolSettings.gobuster.wordlistProfile} options={["small", "medium", "large"]} hint={wordlistHint(toolSettings.gobuster.wordlistProfile)} onChange={(value) => updateTool("gobuster", { wordlistProfile: value as ToolSettings["gobuster"]["wordlistProfile"] })} />
            <NumberField label={t("Threads")} value={toolSettings.gobuster.threads} recommended="10-30" impact="Higher threads speed discovery but increase traffic spikes." warnings={[
              ...(toolSettings.gobuster.threads > 50 ? ["High traffic"] : []),
              ...(toolSettings.gobuster.threads < 5 ? ["Slow"] : [])
            ]} onChange={(value) => updateTool("gobuster", { threads: value })} />
            <NumberField label={t("Timeout")} value={toolSettings.gobuster.timeout} recommended="5-15s" impact="Low values miss slow endpoints; high values make dead paths slow." warnings={timeoutWarnings(toolSettings.gobuster.timeout, 5, 15)} onChange={(value) => updateTool("gobuster", { timeout: value })} />
            <TextField label={t("Extensions")} value={toolSettings.gobuster.extensions} badge="Config only" hint={t("More extensions increase coverage but multiply requests.")} onChange={(value) => updateTool("gobuster", { extensions: value })} />
          </ToolCard>

          <ToolCard icon={<FileSearch size={14} />} title={t("FFUF")} description={t("Fuzzing limits. Keep rates moderate unless the scope explicitly allows noisy traffic.")}>
            <Toggle label={t("Enabled")} checked={toolSettings.ffuf.enabled} onChange={(enabled) => updateTool("ffuf", { enabled }, "ffuf")} />
            <SelectField label={t("Wordlist profile")} badge="Config only" value={toolSettings.ffuf.wordlistProfile} options={["small", "medium", "large"]} hint={wordlistHint(toolSettings.ffuf.wordlistProfile)} onChange={(value) => updateTool("ffuf", { wordlistProfile: value as ToolSettings["ffuf"]["wordlistProfile"] })} />
            <NumberField label={t("Rate limit")} value={toolSettings.ffuf.rateLimit} recommended="50-200" impact="High rates can trigger WAF/rate limits; low rates are safer but slow." warnings={[
              ...(toolSettings.ffuf.rateLimit > 200 ? ["High traffic"] : []),
              ...(toolSettings.ffuf.rateLimit < 25 ? ["Slow"] : [])
            ]} onChange={(value) => updateTool("ffuf", { rateLimit: value })} />
            <NumberField label={t("Timeout")} value={toolSettings.ffuf.timeout} recommended="5-15s" impact="Controls how long FFUF waits per response." warnings={timeoutWarnings(toolSettings.ffuf.timeout, 5, 15)} onChange={(value) => updateTool("ffuf", { timeout: value })} />
            <NumberField label={t("Max results")} value={toolSettings.ffuf.maxResults} recommended="50-200" impact="Too many results may indicate noisy matching or soft-error issues." badge="Config only" warnings={toolSettings.ffuf.maxResults > 300 ? ["Noisy"] : []} onChange={(value) => updateTool("ffuf", { maxResults: value })} />
          </ToolCard>

          <ToolCard icon={<FileSearch size={14} />} title={t("Web Checks")} description={t("Lightweight HTTP page checks and evidence collection.")}>
            <Toggle label={t("Enabled")} checked={toolSettings.checks.enabled} onChange={(enabled) => updateTool("checks", { enabled }, "checks")} />
            <NumberField label={t("Timeout")} value={toolSettings.checks.timeout} recommended="5-10s" impact="Low may miss slow valid pages; high slows the whole scan." warnings={timeoutWarnings(toolSettings.checks.timeout, 5, 10)} onChange={(value) => updateTool("checks", { timeout: value })} />
            <Toggle label={t("Follow redirects")} checked={toolSettings.checks.followRedirects} help={toolSettings.checks.followRedirects ? "Better context, but may leave original host depending on redirect target." : "Safer scope control, but less context."} onChange={(enabled) => updateTool("checks", { followRedirects: enabled })} />
            <NumberField label={t("Max body size")} value={toolSettings.checks.maxBodySize} recommended="512KB-2MB" impact="Limits downloaded and decoded response bytes." warnings={[
              ...(toolSettings.checks.maxBodySize > 2_097_152 ? ["Slow"] : []),
              ...(toolSettings.checks.maxBodySize < 524_288 ? ["May miss"] : [])
            ]} onChange={(value) => updateTool("checks", { maxBodySize: value })} />
          </ToolCard>

          <ToolCard icon={<Camera size={14} />} title={t("Screenshots")} description={t("Visual evidence capture. More screenshots increase disk usage and runtime.")}>
            <Toggle label={t("Enabled")} checked={toolSettings.screenshots.enabled} onChange={(enabled) => updateTool("screenshots", { enabled }, "screenshots")} />
            <NumberField label={t("Timeout")} value={toolSettings.screenshots.timeout} recommended="10-30s" impact="Too low can capture blank/half-loaded pages; too high slows scans heavily." warnings={timeoutWarnings(toolSettings.screenshots.timeout, 10, 30)} onChange={(value) => updateTool("screenshots", { timeout: value })} />
            <NumberField label={t("Max screenshots")} value={toolSettings.screenshots.maxScreenshots} recommended="10-50" impact="Controls visual evidence volume." warnings={[
              ...(toolSettings.screenshots.maxScreenshots > 50 ? ["Slow"] : []),
              ...(toolSettings.screenshots.maxScreenshots < 5 ? ["May miss"] : [])
            ]} onChange={(value) => updateTool("screenshots", { maxScreenshots: value })} />
          </ToolCard>

          <ToolCard icon={<ShieldAlert size={14} />} title={t("Nuclei")} description={t("Evidence-driven template scanning. Template names alone are not proof.")}>
            <Toggle label={t("Enabled")} checked={toolSettings.nuclei.enabled} onChange={(enabled) => updateTool("nuclei", { enabled }, "nuclei")} />
            <TextField label={t("Severity filter")} value={toolSettings.nuclei.severityFilter} hint={toolSettings.nuclei.severityFilter.includes("info") || toolSettings.nuclei.severityFilter.includes("low") ? t("Including info/low increases coverage but can add noise.") : t("Cleaner report, but may miss context signals.")} onChange={(value) => updateTool("nuclei", { severityFilter: value })} />
            <SelectField label={t("Template profile")} value={toolSettings.nuclei.templateProfile} options={["safe", "standard", "broad"]} badge="Config only" hint={t("Large template sets increase runtime and noisy findings.")} onChange={(value) => updateTool("nuclei", { templateProfile: value as ToolSettings["nuclei"]["templateProfile"] })} />
            <NumberField label={t("Rate limit")} value={toolSettings.nuclei.rateLimit} recommended="conservative" impact="High Nuclei rate increases traffic and may trigger WAF/rate limits." warnings={toolSettings.nuclei.rateLimit > 30 ? ["High traffic"] : []} onChange={(value) => updateTool("nuclei", { rateLimit: value })} />
            <NumberField label={t("Timeout")} value={toolSettings.nuclei.timeout} recommended="5-15s" impact="Controls template wait time." warnings={timeoutWarnings(toolSettings.nuclei.timeout, 5, 15)} onChange={(value) => updateTool("nuclei", { timeout: value })} />
            <NumberField label={t("Max target URLs")} value={toolSettings.nuclei.maxTemplates} recommended="500-2000" impact="Taranacak URL sayısını sınırlar; şablon veya bulgu sayısını sınırlamaz." warnings={toolSettings.nuclei.maxTemplates > 3000 ? ["Noisy"] : []} onChange={(value) => updateTool("nuclei", { maxTemplates: value })} />
          </ToolCard>

          <ToolCard icon={<Radar size={14} />} title={t("IP / Nmap Enrichment")} description={t("Auxiliary IP context. It should not override URL/domain findings without strong evidence.")}>
            <Toggle label={t("Enabled")} checked={toolSettings.ipNmap.enabled} onChange={(enabled) => updateTool("ipNmap", { enabled })} />
            <SelectField label={t("Mode")} value={toolSettings.ipNmap.mode} options={["fast", "basic", "deep"]} hint={toolSettings.ipNmap.mode === "deep" ? t("More service detail, slower and noisier.") : t("Lower traffic, less service detail.")} onChange={(value) => updateTool("ipNmap", { mode: value as ToolSettings["ipNmap"]["mode"] })} />
            <NumberField label={t("Top ports")} value={toolSettings.ipNmap.topPorts} recommended="100-1000" impact="Top ports are fast and practical; full range is very slow/noisy." warnings={toolSettings.ipNmap.topPorts > 1000 ? ["Noisy"] : []} onChange={(value) => updateTool("ipNmap", { topPorts: value })} />
            <NumberField label={t("Timeout")} value={toolSettings.ipNmap.timeout} recommended="30-120s" impact="Large timeouts can make dead hosts very slow." warnings={toolSettings.ipNmap.timeout > 180 ? ["Slow"] : []} onChange={(value) => updateTool("ipNmap", { timeout: value })} />
          </ToolCard>

          <ToolCard wide icon={<Globe size={14} />} title={t("OSINT Enrichment")} description={t("Varsayılan tercih. Gerçek run modu Configure ekranında seçilir. OSINT ana risk skorunu etkilemez.")}>
            <Toggle label={t("Varsayılan etkin")} checked={toolSettings.osint.enabled} help="Yalnızca varsayılan tercihi kontrol eder; bu run'a OSINT dahil olup olmayacağı Configure ekranında belirlenir." onChange={(enabled) => updateOsint({ enabled })} />
            <TextField label={t("Mode")} value={toolSettings.osint.mode} readOnly badge="Locked" hint={t("safe_mvp only")} onChange={() => undefined} />
            <Toggle label={t("Certificate transparency")} checked={toolSettings.osint.includeCertificateTransparency} help="Canlı pasif CT metadata lookup; subdomain probing yapılmaz." onChange={(enabled) => updateOsint({ includeCertificateTransparency: enabled })} />
            <Toggle label={t("Known breach catalog")} checked={toolSettings.osint.includeKnownBreachCatalog} help="HIBP-style public ihlal kataloğu metadata'sı." onChange={(enabled) => updateOsint({ includeKnownBreachCatalog: enabled })} />
            <Toggle label={t("Historical URL metadata")} checked={toolSettings.osint.includeHistoricalUrls} help="Canlı Wayback CDX metadata lookup; geçmiş URL'ler fetch edilmez." onChange={(enabled) => updateOsint({ includeHistoricalUrls: enabled })} />
            <Toggle label={t("Public code referansları")} checked={toolSettings.osint.includePublicCodeReferences} badge="Sadece öneri" help="Manuel arama URL'leri üretir; code scraping veya secret validation yapmaz." onChange={(enabled) => updateOsint({ includePublicCodeReferences: enabled })} />
            <Toggle label={t("Search dork önerileri")} checked={toolSettings.osint.includeSearchDorkSuggestions} badge="Sadece öneri" help="Yalnızca operatör rehberliği üretir; ReconBot arama sonuçlarını scrape etmez." onChange={(enabled) => updateOsint({ includeSearchDorkSuggestions: enabled })} />
            <Toggle label={t("Altyapı istihbaratı")} checked={toolSettings.osint.includeInfrastructureIntelligence} help="Yalnızca pasif DNS/IP bağlamı ve lookup shortcut'ları." onChange={(enabled) => updateOsint({ includeInfrastructureIntelligence: enabled })} />
            <Toggle label={t("Organizasyon istihbaratı")} checked={toolSettings.osint.includeOrganizationIntelligence} help="Yalnızca pasif public organizasyon bağlamı." onChange={(enabled) => updateOsint({ includeOrganizationIntelligence: enabled })} />
            <div className="metadata-feed-subsection">
              <div className="metadata-feed-head">
                <div>
                  <strong>{t("OSINT Sources")}</strong>
                  <small>{t("Provider setup. Token değerleri saklanmaz veya gösterilmez.")}</small>
                </div>
              </div>
              <Toggle label={t("GitHub Code Search")} checked={toolSettings.osint.sources.githubCodeSearch.enabled} help="Token varsa canlı GitHub Search API metadata araması yapılır; token yoksa sadece manuel öneriler üretilir." onChange={(enabled) => updateOsintSource("githubCodeSearch", { enabled })} />
              <TextField label={t("GitHub token env")} value={toolSettings.osint.sources.githubCodeSearch.apiKeyEnv} hint={t("Default GITHUB_TOKEN. Sadece env var adı saklanır.")} onChange={(apiKeyEnv) => updateOsintSource("githubCodeSearch", { apiKeyEnv })} />
              <TextField label={t("Token detected")} value={toolSettings.osint.sources.githubCodeSearch.apiKeyConfigured ? "yes" : "no"} readOnly badge="Secret-safe" hint={t("Boolean durum; token değeri asla UI/config/report içine yazılmaz.")} onChange={() => undefined} />
              <Toggle label={t("Wayback")} checked={toolSettings.osint.sources.wayback.enabled} help="Wayback CDX metadata lookup." onChange={(enabled) => updateOsintSource("wayback", { enabled })} />
              <NumberField label={t("Wayback timeout")} value={toolSettings.osint.sources.wayback.timeout} recommended="8-30s" impact="Düşük değer kısmi tarihsel URL kapsamına yol açabilir." warnings={timeoutWarnings(toolSettings.osint.sources.wayback.timeout, 5, 45)} onChange={(timeout) => updateOsintSource("wayback", { timeout })} />
              <NumberField label={t("Wayback retry count")} value={toolSettings.osint.sources.wayback.retryCount} recommended="0-2" impact="Küçük bounded retry/backoff; tüm OSINT run'ını uzun süre bloklamaz." warnings={toolSettings.osint.sources.wayback.retryCount > 2 ? ["Slow"] : []} onChange={(retryCount) => updateOsintSource("wayback", { retryCount })} />
              <Toggle label={t("crt.sh")} checked={toolSettings.osint.sources.crtsh.enabled} help="Certificate Transparency metadata lookup; aktif probing yapmaz." onChange={(enabled) => updateOsintSource("crtsh", { enabled })} />
              <NumberField label={t("crt.sh timeout")} value={toolSettings.osint.sources.crtsh.timeout} recommended="8-30s" impact="Düşük değer CT kapsamını kısmi bırakabilir." warnings={timeoutWarnings(toolSettings.osint.sources.crtsh.timeout, 5, 45)} onChange={(timeout) => updateOsintSource("crtsh", { timeout })} />
              <NumberField label={t("crt.sh retry count")} value={toolSettings.osint.sources.crtsh.retryCount} recommended="0-2" impact="Küçük bounded retry/backoff; başarısız olursa kaynak sağlığına yazılır." warnings={toolSettings.osint.sources.crtsh.retryCount > 2 ? ["Slow"] : []} onChange={(retryCount) => updateOsintSource("crtsh", { retryCount })} />
              <Toggle label={t("Known Breach Catalog")} checked={toolSettings.osint.sources.knownBreachCatalog.enabled} help="Sadece herkese açık ihlal metadata kataloğu; credential/dump toplanmaz." onChange={(enabled) => updateOsintSource("knownBreachCatalog", { enabled })} />
            </div>
            <div className="metadata-feed-subsection">
              <div className="metadata-feed-head">
                <div>
                  <strong>{t("Darkweb Metadata Intelligence")}</strong>
                  <small>{t("Metadata-only. Tor/onion crawling desteklenmez.")}</small>
                </div>
              </div>
              <div className="metadata-feed-safety">
                <small>{t("Credential, dump veya ham sızıntı kaydı içeren dosya/sağlayıcı kullanmayın.")}</small>
                <small>{t("ReconBot bu verileri toplamaz ve saklamaz.")}</small>
                <small>{t("Tor/onion crawling desteklenmez.")}</small>
                <small>{t("Metadata referansları aktif zafiyet değildir.")}</small>
              </div>
              <Toggle label={t("Darkweb intelligence enabled")} checked={darkweb.enabled} help="Yalnızca metadata-only kaynakları raporlar." onChange={(enabled) => updateDarkweb({ enabled })} />
              <Toggle label={t("Manual metadata import")} checked={darkweb.manualMetadataImport.enabled} help="Local metadata-only JSON dosyası. İçerik UI state içine yüklenmez." onChange={(enabled) => updateManualDarkwebImport({ enabled })} />
              <TextField label={t("Manual source name")} value={darkweb.manualMetadataImport.sourceName} hint={t("Opsiyonel kaynak etiketi.")} onChange={(sourceName) => updateManualDarkwebImport({ sourceName })} />
              <TextField label={t("Manual metadata file path")} value={darkweb.manualMetadataImport.filePath} hint={t("Metadata-only JSON. Credential/dump/raw içerik bastırılır.")} onChange={(filePath) => updateManualDarkwebImport({ filePath })} />
              <NumberField label={t("Manual max results")} value={darkweb.manualMetadataImport.maxResults} recommended="25" impact="Manuel metadata import sonucunu sınırlar." onChange={(maxResults) => updateManualDarkwebImport({ maxResults })} />
              <Toggle label={t("Custom HTTPS provider")} checked={darkweb.customHttpsProvider.enabled} help="Provider profile placeholder. Yalnızca https:// URL kabul edilir; canlı entegrasyon yoktur." onChange={(enabled) => updateCustomDarkwebProvider({ enabled })} />
              <TextField label={t("Provider URL")} value={darkweb.customHttpsProvider.providerUrl} hint={t("Yalnızca https:// metadata endpoint. http/file/onion reddedilir.")} onChange={(providerUrl) => updateCustomDarkwebProvider({ providerUrl })} />
              <TextField label={t("API key env var name")} value={darkweb.customHttpsProvider.apiKeyEnv} hint={t("Secret değeri değil, sadece ortam değişkeni adı.")} onChange={(apiKeyEnv) => updateCustomDarkwebProvider({ apiKeyEnv })} />
              <TextField label={t("Token detected")} value={darkweb.customHttpsProvider.apiKeyConfigured ? "yes" : "no"} readOnly badge="Secret-safe" hint={t("Boolean durum; token değeri asla UI/config/report içine yazılmaz.")} onChange={() => undefined} />
              <NumberField label={t("Provider max results")} value={darkweb.customHttpsProvider.maxResults} recommended="25" impact="Gelecek provider adapter sonucu için sınır." onChange={(maxResults) => updateCustomDarkwebProvider({ maxResults })} />
              <NumberField label={t("Provider timeout")} value={darkweb.customHttpsProvider.timeout} recommended="10s" impact="Gelecek HTTPS metadata provider timeout değeri." onChange={(timeout) => updateCustomDarkwebProvider({ timeout })} />
            </div>
            <NumberField label={t("Max signals")} value={toolSettings.osint.maxSignals} recommended="25-100" impact="Signal cap controls report noise before suppression/deduplication." warnings={[
              ...(toolSettings.osint.maxSignals > 200 ? ["Noisy"] : []),
              ...(toolSettings.osint.maxSignals < 10 ? ["May miss"] : [])
            ]} onChange={(value) => updateOsint({ maxSignals: value })} />
            <NumberField label={t("Timeout")} value={toolSettings.osint.timeout} recommended="10-60s" impact="Çok düşük değer kısmi bağlam döndürebilir; çok yüksek değer rapor üretimini yavaşlatabilir." warnings={timeoutWarnings(toolSettings.osint.timeout, 10, 60)} onChange={(value) => updateOsint({ timeout: value })} />
            <Toggle label={t("Sadece pasif zorunlu")} checked={toolSettings.osint.passiveOnly} disabled help="Yalnızca pasif public intelligence. Credential yok, marketplace yok, login-required breach DB yok, exploit aktivitesi yok." onChange={() => undefined} />
            <div className="metadata-feed-subsection">
              <div className="metadata-feed-head">
                <div>
                  <strong>{t("Darkweb / Sızıntı / İhlal Metadata Feed’i")}</strong>
                  <small>{t("Sadece metadata. Tor/onion yok. Credential, dump veya ham sızıntı kaydı toplanmaz.")}</small>
                </div>
              </div>
              <div className="metadata-feed-safety">
                <small>{t("Provider registry runtime öncesinde metadata-only feed kurallarını uygular.")}</small>
                <small>{t("Bu collector yalnızca normalize edilmiş breach/leak metadata tüketir.")}</small>
                <small>{t("ReconBot credential, password, hash, token, private key, session cookie, raw dump, paste raw content, personal record veya ham sızıntı kaydı toplamaz.")}</small>
                <small>{t("Credential, dump, raw paste content veya personal record içeren feed yapılandırma.")}</small>
                <small>{t("API key değeri buraya yazılmaz. Sadece ortam değişkeni adı girilir.")}</small>
                <small>{t("ReconBot API key değerini run_result.json veya raporlara yazmaz.")}</small>
                <small>{t("Metadata referansları aktif zafiyet bulgusu değildir ve risk skorunu etkilemez.")}</small>
              </div>
              <button type="button" className="metadata-feed-demo-button" onClick={() => updateMetadataFeed(LOCAL_EXAMPLE_METADATA_FEED)}>
                {t("Local örnek metadata feed’i yükle")}<small>{t("Demo fixture sadece yerel test içindir.")}</small>
              </button>
              <Toggle label={t("Metadata feed’i etkinleştir")} checked={metadataFeed.enabled} help="Varsayılan kapalı. Yalnızca güvenilir normalize metadata feed'leri için etkinleştir." onChange={(enabled) => updateMetadataFeed({ enabled })} />
              <label className="field compact-field dense-field">
                <span>{t("Provider")}</span>
                <select
                  value={metadataFeed.providerId}
                  onChange={(event) => {
                    const providerId = event.target.value as ToolSettings["osint"]["leakSources"]["metadataFeed"]["providerId"];
                    updateMetadataFeed({
                      providerId,
                      sourceType: providerId === "local_demo_feed" ? "local_file" : providerId === "custom_https_metadata_feed" ? "https_json" : "",
                      feedPath: providerId === "local_demo_feed" ? metadataFeed.feedPath : "",
                      feedUrl: providerId === "custom_https_metadata_feed" ? metadataFeed.feedUrl : "",
                      apiKeyEnv: providerId === "custom_https_metadata_feed" ? metadataFeed.apiKeyEnv : ""
                    });
                  }}
                >
                  {METADATA_FEED_PROVIDERS.map((provider) => (
                    <option key={provider.id} value={provider.id}>{provider.label}</option>
                  ))}
                </select>
                <small>{METADATA_FEED_PROVIDERS.find((provider) => provider.id === metadataFeed.providerId)?.description || "Provider profile"}</small>
              </label>
              <TextField label={t("Kaynak adı")} value={metadataFeed.sourceName} hint={t("Opsiyonel display/source etiketi; provider URL hardcode edilmez.")} onChange={(sourceName) => updateMetadataFeed({ sourceName })} />
              <TextField label={t("Kaynak tipi")} value={metadataFeed.sourceType || "provider_profile"} readOnly badge="Locked" hint={t("Provider seçimine göre otomatik belirlenir.")} onChange={() => undefined} />
              {metadataFeed.providerId === "local_demo_feed" && (
                <TextField label={t("Local JSON dosya yolu")} value={metadataFeed.feedPath} hint={t("Yalnızca düz local path. Feed içeriği UI state içine yüklenmez veya kopyalanmaz.")} onChange={(feedPath) => updateMetadataFeed({ feedPath })} />
              )}
              {metadataFeed.providerId === "custom_https_metadata_feed" && (
                <TextField label={t("HTTPS JSON endpoint")} value={metadataFeed.feedUrl} hint={t("Yalnızca https:// endpoint kabul edilir.")} onChange={(feedUrl) => updateMetadataFeed({ feedUrl })} />
              )}
              {metadataFeed.providerId === "custom_https_metadata_feed" && (
                <TextField label={t("API key ortam değişkeni adı")} value={metadataFeed.apiKeyEnv} hint={t("Opsiyonel. Yalnızca ortam değişkeni adını sakla; secret değerini asla yazma.")} onChange={(apiKeyEnv) => updateMetadataFeed({ apiKeyEnv })} />
              )}
              {metadataFeed.providerId === "future_trusted_provider_profile" && (
                <div className="metadata-feed-message warn">{t("Provider profile yakında. Bu provider etkinken scan başlatılamaz.")}</div>
              )}
              <NumberField label={t("Zaman aşımı")} value={metadataFeed.timeout} recommended="10s" impact="HTTPS/local feed okuma timeout değeri." onChange={(timeout) => updateMetadataFeed({ timeout })} />
              <NumberField label={t("Maksimum sonuç")} value={metadataFeed.maxResults} recommended="25" impact="Bu feed'den rapora yazılacak metadata referanslarını sınırlar." onChange={(maxResults) => updateMetadataFeed({ maxResults })} />
              <div className="metadata-feed-preview">
                {metadataFeedPreview.map((message) => <small key={message}>{message}</small>)}
              </div>
              {[...metadataFeedValidation.warnings, ...metadataFeedValidation.errors].map((message) => (
                <div key={message} className={`metadata-feed-message ${metadataFeedValidation.errors.includes(message) ? "error" : "warn"}`}>{message}</div>
              ))}
            </div>
          </ToolCard>
        </section>
      </div>
    </section>
  );
}

function wordlistHint(value: string): string {
  if (value === "small") return "Fast, low-noise, less coverage.";
  if (value === "large") return "More coverage but slower and noisier.";
  return "Balanced coverage and runtime.";
}

function Impact({ label, value }: { label: string; value: string }): JSX.Element {
  const tone = value === "High" || value === "Slow" ? "warn" : value === "Low" || value === "Fast" ? "ok" : "muted";
  return <span className={`impact-pill ${tone}`}><small>{t(label)}</small><strong>{t(value)}</strong></span>;
}

function LimitInfo({ title, badge, text }: { title: string; badge: string; text: string }): JSX.Element {
  return (
    <div className="limit-info">
      <strong>{title}</strong>
      <Badge tone="muted">{t(badge)}</Badge>
      <small>{t(text)}</small>
    </div>
  );
}

function ToolCard({ title, description, icon, children, wide = false }: { title: string; description: string; icon: JSX.Element; children: ReactNode; wide?: boolean }): JSX.Element {
  return (
    <article className={`cockpit-panel settings-tool-card compact-card ${wide ? "wide" : ""}`}>
      <header className="panel-head compact-head">
        <div>
          <span className="micro-label">{icon} {" "}{t("Tool Parameters")}</span>
          <h2>{t(title)}</h2>
          <p>{t(description)}</p>
        </div>
      </header>
      <div className="settings-fields compact-fields">{children}</div>
    </article>
  );
}

function Badge({ tone = "muted", children }: { tone?: BadgeTone; children: ReactNode }): JSX.Element {
  return <span className={`setting-badge ${tone}`}>{children}</span>;
}

function WarningBadges({ warnings, badge }: { warnings?: string[]; badge?: string }): JSX.Element | null {
  const items = [...(badge ? [badge] : []), ...(warnings || [])].filter(Boolean);
  if (!items.length) return null;
  return (
    <span className="setting-badges">
      {items.map((item) => (
        <Badge key={item} tone={item === "Config only" || item === "Locked" ? "muted" : item === "May miss" ? "bad" : "warn"}>{t(item)}</Badge>
      ))}
    </span>
  );
}

function formatNumberDraft(value: number): string {
  if (!Number.isFinite(value)) return "";
  return Number.isInteger(value) ? String(value) : String(value);
}

function parseDraftNumber(value: string): number | null {
  const trimmed = value.trim().replace(",", ".");
  if (!trimmed) return null;
  const parsed = Number(trimmed);
  return Number.isFinite(parsed) ? parsed : null;
}

function Toggle({
  label,
  checked,
  disabled,
  badge,
  help,
  onChange
}: {
  label: string;
  checked: boolean;
  disabled?: boolean;
  badge?: string;
  help?: string;
  onChange: (value: boolean) => void;
}): JSX.Element {
  return (
    <label className={`setting-toggle ${disabled ? "disabled" : ""}`}>
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />
      <span className="toggle-track" aria-hidden="true"><i /></span>
      <span className="setting-copy">
        <strong>{t(label)}</strong>
        <WarningBadges badge={badge} />
        {help && <small>{t(help)}</small>}
      </span>
    </label>
  );
}

function NumberField({
  label,
  value,
  recommended,
  impact,
  warnings,
  badge,
  min = 0,
  max,
  onChange
}: {
  label: string;
  value: number;
  recommended?: string;
  impact?: string;
  warnings?: string[];
  badge?: string;
  min?: number;
  max?: number;
  onChange: (value: number) => void;
}): JSX.Element {
  const [draft, setDraft] = useState(formatNumberDraft(value));
  const [focused, setFocused] = useState(false);
  const [validationMessage, setValidationMessage] = useState("");

  useEffect(() => {
    if (!focused) setDraft(formatNumberDraft(value));
  }, [focused, value]);

  const commitDraft = (): void => {
    setFocused(false);
    const parsed = parseDraftNumber(draft);
    if (parsed === null) {
      setValidationMessage(draft.trim() ? "Geçersiz sayı; önceki geçerli değer korundu." : "Boş bırakıldı; önceki geçerli değer korundu.");
      setDraft(formatNumberDraft(value));
      return;
    }
    const lowerBounded = Math.max(min, parsed);
    const bounded = typeof max === "number" ? Math.min(max, lowerBounded) : lowerBounded;
    const normalized = Number.isInteger(value) ? Math.round(bounded) : bounded;
    setValidationMessage(normalized !== parsed ? `Değer ${normalized} olarak sınırlandı.` : "");
    setDraft(formatNumberDraft(normalized));
    if (normalized !== value) onChange(normalized);
  };

  return (
    <label className="field compact-field dense-field">
      <span>{t(label)}<WarningBadges warnings={warnings} badge={badge} /></span>
      <input
        type="text"
        inputMode="decimal"
        value={draft}
        onFocus={() => {
          setFocused(true);
          setValidationMessage("");
        }}
        onChange={(event) => setDraft(event.target.value)}
        onBlur={commitDraft}
        onKeyDown={(event) => {
          if (event.key === "Enter") event.currentTarget.blur();
          if (event.key === "Escape") {
            setDraft(formatNumberDraft(value));
            setValidationMessage("");
            event.currentTarget.blur();
          }
        }}
      />
      {(recommended || impact) && <small>{recommended ? t("Recommended: {value}. ", { value: recommended }) : ""}{t(impact || "")}</small>}
      {validationMessage && <small className="field-validation-warning">{t(validationMessage)}</small>}
    </label>
  );
}

function TextField({
  label,
  value,
  readOnly,
  badge,
  hint,
  onChange
}: {
  label: string;
  value: string;
  readOnly?: boolean;
  badge?: string;
  hint?: string;
  onChange: (value: string) => void;
}): JSX.Element {
  return (
    <label className="field compact-field dense-field">
      <span>{t(label)}<WarningBadges badge={badge} /></span>
      <input value={value} readOnly={readOnly} onChange={(event) => onChange(event.target.value)} />
      {hint && <small>{t(hint || "")}</small>}
    </label>
  );
}

function SelectField({
  label,
  value,
  options,
  badge,
  hint,
  onChange
}: {
  label: string;
  value: string;
  options: string[];
  badge?: string;
  hint?: string;
  onChange: (value: string) => void;
}): JSX.Element {
  return (
    <label className="field compact-field dense-field">
      <span>{t(label)}<WarningBadges badge={badge} /></span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((option) => <option key={t(option)} value={t(option)}>{t(option)}</option>)}
      </select>
      {hint && <small>{t(hint || "")}</small>}
    </label>
  );
}
