import { t } from "../lib/i18n";
import { AlertTriangle, Copy, FileJson, FileText, FolderOpen, RefreshCw, ScrollText } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { RunStateSnapshot, ScanHistoryItem } from "../../shared/api";

interface ArtifactPaneProps {
  runState: RunStateSnapshot;
  history: ScanHistoryItem[];
  onRefreshHistory: () => void;
  onSelectHistoryRun: (runDir: string, destination?: "dashboard" | "report") => void;
}

interface ArtifactAction {
  title: string;
  description: string;
  path: string;
  available: boolean;
  action: "open" | "copy";
  icon: LucideIcon;
}

function execute(item: ArtifactAction): void {
  if (!item.available || !item.path) return;
  if (item.action === "copy") {
    void window.reconbot.copyText(item.path);
  } else {
    void window.reconbot.openPath(item.path);
  }
}

function riskLabel(item: ScanHistoryItem): string {
  if (item.risk.score !== null) return `${item.risk.score}/100`;
  return item.risk.label || "pending";
}

function historyStateLabel(item: ScanHistoryItem): string {
  if (item.runState === "interrupted") return "interrupted";
  if (item.runState === "failed") return "failed";
  if (item.runState === "incomplete" || item.completeness === "partial") return "incomplete";
  if (item.reportReady || item.completeness === "report_ready") return "report ready";
  return "report pending";
}

function stateExplanation(runState: RunStateSnapshot): string {
  if (!runState.currentRunDir) return "Henüz bir run seçilmedi. Geçmiş listesinden bir run seçebilir veya yeni tarama başlatabilirsiniz.";
  if (runState.report.status === "failed") return "Bu run için rapor üretimi başarısız olmuş. Mevcut log ve durum dosyaları yine de incelenebilir.";
  if (!runState.report.exists && runState.runState === "incomplete") return "Bu tarama tamamlanmamış. report.html henüz üretilmemiş.";
  if (["failed", "interrupted", "incomplete"].includes(runState.runState)) return "Tarama tamamlanmadı veya bazı aşamalar başarısız. Rapor bulunması taramanın tamamlandığı anlamına gelmez.";
  if (runState.report.exists) return "Rapor mevcut. Kapsam ve aşama durumları aşağıdaki çalışma kaydından kontrol edilebilir.";
  return "Bu tarama tamamlanmamış. report.html henüz üretilmemiş.";
}

export default function ArtifactPane({ runState, history, onRefreshHistory, onSelectHistoryRun }: ArtifactPaneProps): JSX.Element {
  const currentRunDir = runState.currentRunDir;
  const artifacts = runState.artifacts;
  const paths = artifacts?.paths || {
    runDir: currentRunDir,
    rawLog: currentRunDir ? `${currentRunDir}/reconbot.log` : "",
    stateJson: currentRunDir ? `${currentRunDir}/run_result.json` : "",
    stagesJson: currentRunDir ? `${currentRunDir}/stages_live.json` : "",
    configOrRequest: "",
    report: runState.report.path
  };
  const exists = artifacts?.exists || {
    runDir: Boolean(currentRunDir),
    rawLog: false,
    stateJson: false,
    stagesJson: false,
    configOrRequest: false,
    report: runState.report.exists
  };
  const actions: ArtifactAction[] = [
    {
      title: "Open Run Folder",
      description: "Inspect every artifact currently present in this run.",
      path: paths.runDir,
      available: exists.runDir,
      action: "open",
      icon: FolderOpen
    },
    {
      title: "Open Raw Log",
      description: "Open reconbot.log when the run produced it.",
      path: paths.rawLog,
      available: exists.rawLog,
      action: "open",
      icon: ScrollText
    },
    {
      title: "Open State JSON",
      description: "Open run_result.json only when it exists.",
      path: paths.stateJson,
      available: exists.stateJson,
      action: "open",
      icon: FileJson
    },
    {
      title: "Open stages_live.json",
      description: "Inspect partial stage progress independently of run_result.json.",
      path: paths.stagesJson,
      available: exists.stagesJson,
      action: "open",
      icon: FileJson
    },
    {
      title: "Open Config / Request",
      description: "Open the available generated config or request metadata.",
      path: paths.configOrRequest,
      available: exists.configOrRequest,
      action: "open",
      icon: FileText
    },
    {
      title: "Open Report External",
      description: "Open report.html only when the file exists.",
      path: paths.report,
      available: exists.report,
      action: "open",
      icon: FileText
    },
    {
      title: "Copy currentRunDir",
      description: "Copy the exact tracked run directory.",
      path: currentRunDir,
      available: exists.runDir,
      action: "copy",
      icon: Copy
    }
  ];

  return (
    <section className="artifacts-page" data-testid="artifacts-pane">
      <div className="page-title">
        <div>
          <span className="micro-label">{t("Artifacts")}</span>
          <h1>{t("Çıktılar ve Geçmiş Taramalar")}</h1>
        </div>
        <button type="button" onClick={onRefreshHistory}><RefreshCw size={14} /> {" "}{t("Refresh")}</button>
      </div>

      {Boolean(runState.effectiveSettings?.length) && <details className="effective-settings">
        <summary>{t("Bu taramada uygulanan ayarlar")}</summary>
        <ul>{runState.effectiveSettings?.map((setting) => <li key={setting}>{setting}</li>)}</ul>
      </details>}
      <div className="artifact-layout">
        <section className="cockpit-panel current-artifacts-panel">
          <header className="panel-head">
            <div>
              <span className="micro-label">{t("Current run artifacts")}</span>
              <h2>{t("Aktif Çıktılar")}</h2>
            </div>
            <span className="panel-chip">{currentRunDir ? t("{count} available", { count: artifacts?.availableCount ?? 0 }) : t("no run")}</span>
          </header>

          <div className={`run-integrity-state ${runState.report.exists ? "ready" : "partial"}`}>
            <AlertTriangle size={17} aria-hidden="true" />
            <div>
              <strong>{t(stateExplanation(runState))}</strong>
              <dl>
                <div><dt>{t("Run state")}</dt><dd>{runState.runState || "unknown"}</dd></div>
                <div><dt>{t("Completeness")}</dt><dd>{runState.completeness || "unknown"}</dd></div>
                <div><dt>{t("Historical")}</dt><dd>{runState.isHistorical ? t("yes") : t("no")}</dd></div>
                <div><dt>{t("Process attached")}</dt><dd>{runState.processAttached ? t("yes") : t("no")}</dd></div>
                <div><dt>{t("Available artifacts")}</dt><dd>{artifacts?.availableCount ?? 0}</dd></div>
              </dl>
              <code className="run-directory" title={currentRunDir}>{currentRunDir || "No run selected"}</code>
              <p className="missing-artifacts">
                {t("Missing expected artifacts:")}{artifacts?.missingExpected?.length ? artifacts.missingExpected.join(", ") : t("none")}
              </p>
            </div>
          </div>

          <div className="artifact-grid compact-artifacts">
            {actions.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.title}
                  className="artifact-card"
                  disabled={!item.available}
                  type="button"
                  onClick={() => execute(item)}
                >
                  <span className="micro-label"><Icon size={13} /> {item.action === "copy" ? t("copy") : t("open")}</span>
                  <strong>{t(item.title)}</strong>
                  <small>{t(item.description)}</small>
                  <code>{item.available ? item.path : t("Unavailable for this run")}</code>
                </button>
              );
            })}
          </div>
        </section>

        <section className="cockpit-panel history-panel">
          <header className="panel-head">
            <div>
              <span className="micro-label">{t("Scan history")}</span>
              <h2>{t("Geçmiş Taramalar")}</h2>
            </div>
            <span className="panel-chip">{history.length} {" "}{t("runs")}</span>
          </header>
          <div className="history-list">
            {history.length ? history.map((item) => {
              const logAvailable = item.exists ? item.exists.rawLog : Boolean(item.paths.rawLog);
              const stateAvailable = item.exists ? item.exists.stateJson : Boolean(item.paths.stateJson);
              return (
                <article
                  className={item.runDir === currentRunDir ? "history-row current" : "history-row"}
                  key={item.runDir}
                  role="button"
                  tabIndex={0}
                  onClick={() => onSelectHistoryRun(item.runDir, "dashboard")}
                  onKeyDown={(event) => {
                    if (event.target !== event.currentTarget) return;
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      onSelectHistoryRun(item.runDir, "dashboard");
                    }
                  }}
                >
                  <div>
                    <strong title={item.displayName}>{item.displayName}</strong>
                    <small title={item.runDir}>
                      {item.target} · {item.timeLabel} {" "}{t("· risk")}{" "}{riskLabel(item)} · <span className={`history-state ${historyStateLabel(item).replace(/\s+/g, "-")}`}>{t(historyStateLabel(item))}</span>
                    </small>
                    <code title={item.runDir}>{item.runDir}</code>
                  </div>
                  <div className="history-actions">
                    <button type="button" disabled={!item.reportReady} onClick={(event) => { event.stopPropagation(); onSelectHistoryRun(item.runDir, "report"); }}>{t("Report")}</button>
                    <button type="button" onClick={(event) => { event.stopPropagation(); void window.reconbot.openPath(item.runDir); }}>{t("Folder")}</button>
                    <button type="button" disabled={!logAvailable} onClick={(event) => { event.stopPropagation(); void window.reconbot.openPath(item.paths.rawLog); }}>{t("Log")}</button>
                    <button type="button" disabled={!stateAvailable} onClick={(event) => { event.stopPropagation(); void window.reconbot.openPath(item.paths.stateJson); }}>{t("JSON")}</button>
                    <button type="button" onClick={(event) => { event.stopPropagation(); void window.reconbot.copyText(item.runDir); }}>{t("Copy")}</button>
                  </div>
                </article>
              );
            }) : (
              <div className="empty-signal">
                <FolderOpen size={18} />
                <span>{t("No scan history found under the configured output directory.")}</span>
              </div>
            )}
          </div>
        </section>
      </div>
    </section>
  );
}
