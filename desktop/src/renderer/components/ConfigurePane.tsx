import { t } from "../lib/i18n";
import WordlistField from './WordlistField';
import {
  Bug,
  Camera,
  Crosshair,
  DatabaseZap,
  FileSearch,
  Globe,
  History,
  Radar,
  Route,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Target,
  Zap
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { ConfigDefaults, ReportDepth, ResolvedIpInfo, RunStateSnapshot, ScanConfig } from "../../shared/api";
import { applyRunMode, applyScanProfile, markCustom, runModes, scanProfiles } from "../lib/settingsModel";

interface ConfigurePaneProps {
  defaults: ConfigDefaults;
  config: ScanConfig;
  runState: RunStateSnapshot;
  statusMessage: string;
  resolvedIp: ResolvedIpInfo | null;
  ipPromptState: "passive" | "ask" | "accepted" | "ignored";
  onChange: (config: ScanConfig) => void;
  onStart: () => void;
  onStop: () => void;
  canStart: boolean;
}

const depths: ReportDepth[] = ["summary", "balanced", "deep"];
const executionLabels: Record<ScanConfig["runMode"], string> = {
  normal_scan_only: "Normal Scan",
  osint_only: "OSINT Only",
  normal_scan_plus_osint: "Scan + OSINT"
};
const executionNotes: Record<ScanConfig["runMode"], string> = {
  normal_scan_only: "Existing active scanner flow only. OSINT is not included.",
  osint_only: "Active scanners will be skipped. Passive public OSINT sources will run.",
  normal_scan_plus_osint: "Selected scan tools run first, then passive OSINT context is attached."
};

function labelize(value: string): string {
  return value
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function isUrlTarget(target: string): boolean {
  return /^https?:\/\//i.test(target.trim());
}

function toolIcon(name: string): LucideIcon {
  const normalized = name.toLowerCase();
  if (normalized.includes("nmap")) return Radar;
  if (normalized.includes("subfinder") || normalized.includes("dnsx")) return Route;
  if (normalized.includes("httpx") || normalized.includes("whatweb")) return Globe;
  if (normalized.includes("katana")) return Radar;
  if (normalized.includes("gobuster")) return Search;
  if (normalized.includes("ffuf")) return Bug;
  if (normalized.includes("historical")) return History;
  if (normalized.includes("waf")) return ShieldCheck;
  if (normalized.includes("check")) return FileSearch;
  if (normalized.includes("screenshot")) return Camera;
  if (normalized.includes("nuclei")) return ShieldAlert;
  return SlidersHorizontal;
}

function stageForTool(runState: RunStateSnapshot, toolName: string): { status: string; reason: string } {
  const normalized = toolName.toLowerCase().replace(/_enabled$|_enable$/g, "");
  const row = runState.stages.find((stage) => {
    const haystack = `${stage.name} ${stage.label}`.toLowerCase();
    return haystack.includes(normalized) || normalized.includes(stage.name.toLowerCase());
  });
  return {
    status: row?.status || "selected",
    reason: row?.reason || row?.metric || ""
  };
}

export default function ConfigurePane({
  defaults,
  config,
  runState,
  statusMessage,
  resolvedIp,
  onChange,
  onStart,
  onStop,
  canStart
}: ConfigurePaneProps): JSX.Element {
  const update = (patch: Partial<ScanConfig>): void => onChange({ ...config, ...patch });
  const updateTool = (name: string, enabled: boolean): void => {
    const nextSettings = { ...config.toolSettings };
    if (name === "katana") nextSettings.katana = { ...nextSettings.katana, enabled };
    if (name === "gobuster") nextSettings.gobuster = { ...nextSettings.gobuster, enabled };
    if (name === "ffuf") nextSettings.ffuf = { ...nextSettings.ffuf, enabled };
    if (name === "checks") nextSettings.checks = { ...nextSettings.checks, enabled };
    if (name === "screenshots") nextSettings.screenshots = { ...nextSettings.screenshots, enabled };
    if (name === "nuclei") nextSettings.nuclei = { ...nextSettings.nuclei, enabled };
    onChange(markCustom({ ...config, tools: { ...config.tools, [name]: enabled }, toolSettings: nextSettings }));
  };
  const selectedTools = Object.values(config.tools).filter(Boolean).length;
  const isRunning = runState.runState === "running";
  const urlMode = isUrlTarget(config.target);
  const osintOnly = config.runMode === "osint_only";
  const osintIncluded = config.runMode === "osint_only" || config.runMode === "normal_scan_plus_osint";
  const executedToolsText = osintOnly ? "OSINT Only: active tools skipped" : `${selectedTools}/${defaults.tools.length}`;
  const osintStatusText = !osintIncluded
    ? "disabled for this run"
    : runState.osint?.enabled
      ? `${runState.osint.status}: ${runState.osint.totalSignals} signals`
      : osintOnly && isRunning
        ? "running: OSINT"
        : osintOnly
          ? "ready: passive OSINT"
          : "included: passive OSINT";

  return (
    <section className="configure-grid">
      <div className="cockpit-panel setup-panel">
        <header className="panel-head large">
          <div>
            <span className="micro-label"><Target size={12} /> {" "}{t("Configure")}</span>
            <h2>{t("Scan Control")}</h2>
          </div>
          <span className={`panel-chip ${isRunning ? "live" : ""}`}>{isRunning ? t("running") : t("ready")}</span>
        </header>

        <div className="form-grid">
          <label className="field target-field">
            <span><Crosshair size={13} /> {" "}{t("Target")}</span>
            <input
              value={config.target}
              onChange={(event) => update({ target: event.target.value })}
              placeholder={t("https://target.local or domain")}
            />
          </label>

          <WordlistField slot="discovery" label="Wordlist" value={config.wordlist} onChange={wordlist => update({ wordlist })} placeholder={defaults.wordlist || t('Required when Gobuster or FFUF is enabled')} />
        </div>

        <div className="selector-grid">
          <div className="segmented">
            <span>{t("Scan profile")}</span>
            <div>
              {scanProfiles.map((profile) => (
                <button
                  key={profile}
                  type="button"
                  className={config.scanProfile === profile ? "selected" : ""}
                  onClick={() => onChange(applyScanProfile(config, defaults, profile))}
                >
                  <Zap size={13} /> {t(profile)}
                </button>
              ))}
              {config.scanProfile === "custom" && <button type="button" className="selected">{t("Custom")}</button>}
            </div>
          </div>

          <div className="segmented">
            <span>{t("Report depth")}</span>
            <div>
              {depths.map((depth) => (
                <button
                  key={t(depth)}
                  type="button"
                  className={config.reportDepth === depth ? "selected" : ""}
                  onClick={() => update({ reportDepth: depth })}
                >
                  {t(depth)}
                </button>
              ))}
            </div>
          </div>
        </div>

        {resolvedIp?.available && (
          <div className="ip-enrichment-card">
            <div className="ip-enrichment-copy">
              <span className="micro-label"><Server size={12} /> {" "}{t("Passive DNS")}</span>
              <strong title={`${resolvedIp.hostname} -> ${resolvedIp.ip}`}>{t("Resolved IP found:")}{" "}{resolvedIp.ip}</strong>
              <p>{resolvedIp.hostname} {" "}{t("resolves before scan start. The primary scan target remains the URL/domain you entered.")}</p>
            </div>
          </div>
        )}

        <div className="execution-mode-panel">
          <div>
            <span className="micro-label"><Globe size={12} /> {" "}{t("Execution Mode")}</span>
            <strong>{t(executionLabels[config.runMode])}</strong>
            <small>{t(executionNotes[config.runMode])}</small>
          </div>
          <div className="execution-mode-buttons" role="group" aria-label={t("Execution mode")}>
            {runModes.map((mode) => (
              <button
                key={mode.value}
                type="button"
                className={config.runMode === mode.value ? "selected" : ""}
                onClick={() => onChange(applyRunMode(config, mode.value))}
                title={t(mode.description)}
              >
                {t(executionLabels[mode.value])}
              </button>
            ))}
          </div>
          <div className="execution-mode-summary">
            <span className={osintOnly ? "mode-chip warn" : "mode-chip ok"}>{osintOnly ? t("Active scanners skipped") : t("Scan tools active")}</span>
            <span className={osintIncluded ? "mode-chip ok" : "mode-chip muted"}>{osintIncluded ? t("OSINT included") : t("OSINT disabled")}</span>
          </div>
        </div>

        <div className="control-deck">
          <button className="primary launch-button" disabled={!canStart} onClick={onStart} type="button">
            <span>{t("Start Scan")}</span>
            <small>{t(executionLabels[config.runMode])}</small>
          </button>
          <button className="danger-button" onClick={onStop} type="button">
            {t("Stop")}</button>
        </div>

        <div className="config-readout">
          <div>
            <span className="micro-label">{t("Selected tools")}</span>
            <strong>{executedToolsText}</strong>
          </div>
          <div>
            <span className="micro-label">{t("Defaults")}</span>
            <strong>{t("config.yaml loaded")}</strong>
          </div>
          <div>
            <span className="micro-label">{t("Generated config")}</span>
            <strong>{statusMessage.includes("Started:") ? statusMessage.replace("Started: ", "") : t("created on scan start")}</strong>
          </div>
        </div>
      </div>

      <div className="cockpit-panel tools-panel">
        <header className="panel-head">
          <div>
            <span className="micro-label"><SlidersHorizontal size={12} /> {" "}{t("Tool matrix")}</span>
            <h2>{t("Enabled Stages")}</h2>
          </div>
          <span className="panel-chip">{osintOnly ? t("OSINT-only") : `${selectedTools} armed`}</span>
        </header>
        {osintOnly && (
          <p className="operator-view-note compact-note">{t("OSINT Only selected: active scanner tools below are kept as defaults but skipped for this run.")}</p>
        )}
        <div className="tool-grid">
          {defaults.tools.map((tool) => {
            const enabled = Boolean(config.tools[tool.name]);
            const Icon = toolIcon(tool.name);
            const stage = stageForTool(runState, tool.name);
            const autoSkipped = urlMode && ["subfinder", "dnsx", "httpx"].some((item) => tool.name.toLowerCase().includes(item));
            const executionSkipped = osintOnly;
            return (
              <label key={tool.name} className={`tool-toggle ${enabled ? "enabled" : ""} ${autoSkipped || executionSkipped ? "auto-skipped" : ""} ${executionSkipped ? "execution-skipped" : ""}`}>
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={(event) => updateTool(tool.name, event.target.checked)}
                />
                <span className="tool-icon" aria-hidden="true"><Icon size={18} /></span>
                <span>
                  <strong>{tool.label || labelize(tool.name)}</strong>
                  <small title={executionSkipped ? t("OSINT Only mode") : autoSkipped ? t("URL target mode") : stage.reason}>
                    {executionSkipped ? t("skipped: OSINT Only") : autoSkipped ? t("auto-skipped: URL target mode") : enabled ? `${stage.status}${stage.reason ? ` · ${stage.reason}` : ""}` : t("disabled")}
                  </small>
                </span>
              </label>
            );
          })}
          <div className={`tool-toggle osint-tool ${osintIncluded ? "enabled" : ""}`}>
            <span className="tool-icon" aria-hidden="true"><Globe size={18} /></span>
            <span>
              <strong>{t("OSINT Enrichment")}</strong>
              <small>{osintStatusText}</small>
            </span>
          </div>
        </div>
      </div>

      <div className="cockpit-panel configure-notes">
        <div>
          <span className="micro-label">{t("Selected profile")}</span>
          <strong>{config.scanProfile.toUpperCase()} / {config.reportDepth.toUpperCase()}</strong>
        </div>
        <p>
          {t("URL target mode keeps domain discovery tools visible but marks subfinder, dnsx and httpx as auto-skipped when the Python core intentionally skips them.")}</p>
        <p>
          {t("Overrides here are written only to the generated app config for this run; project defaults stay in config.yaml. OSINT Only skips active scanners and runs passive public enrichment only.")}</p>
      </div>
    </section>
  );
}
