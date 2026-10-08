import { Activity, ChevronDown, Crosshair, FolderOpen, ShieldAlert } from "lucide-react";
import type { RunStateSnapshot, ScanConfig } from "../../shared/api";
import { t } from "../lib/i18n";
import { summarizeStages } from "../lib/stageModel";

interface StatusBarProps { runState: RunStateSnapshot; config: ScanConfig; }
function riskTone(label: string): string {
  const value = label.toLowerCase();
  if (value.includes("critical")) return "critical";
  if (value.includes("high")) return "high";
  if (value.includes("elevated") || value.includes("medium")) return "elevated";
  if (value.includes("low")) return "low";
  return "pending";
}

export default function StatusBar({ runState, config }: StatusBarProps): JSX.Element {
  const progress = summarizeStages(runState.stages);
  const risk = runState.risk ?? { score: null, label: "pending", source: "pending" };
  const state = runState.runState || "idle";
  const reportLabel = runState.report.exists
    ? state === "completed" ? "Report ready" : "Partial report"
    : runState.report.status === "failed" ? "Report failed" : "Report pending";
  return (
    <header className="system-bar">
      <div className="status-cell target-cell">
        <span className="micro-label"><Crosshair size={12} /> {t("Current target")}</span>
        <strong title={runState.target || config.target}>{runState.target || config.target || t("No target selected")}</strong>
      </div>
      <div className="status-cell lifecycle-cell">
        <span className={`run-pill state-${state.toLowerCase()}`}><i className="status-indicator" />{t(state[0].toUpperCase() + state.slice(1))}</span>
        <small className="report-availability">{t(reportLabel)}</small>
      </div>
      <div className="status-cell progress-cell">
        <span className="micro-label" title={t("Completed recorded tools only; skipped and unrecorded tools are excluded. This is not a time estimate.")}><Activity size={12} /> {t("Tools completed")} <strong>{progress.done}/{progress.total}</strong></span>
        <span className="progress-track" role="progressbar" aria-label={t("Tools completed")} aria-valuemin={0} aria-valuemax={Math.max(1, progress.total)} aria-valuenow={progress.done} aria-valuetext={t("{done}/{total} completed", progress)}><i style={{ width: `${progress.total ? progress.done / progress.total * 100 : 0}%` }} /></span>
      </div>
      <div className={`status-cell risk-cell risk-${riskTone(risk.label || "pending")}`}>
        <span className="micro-label"><ShieldAlert size={12} /> {t("Risk score")}</span>
        <strong title={risk.source}>{risk.score === null ? "—" : `${risk.score}/100`}</strong>
      </div>
      <details className="run-details">
        <summary title={t("Run details")}><FolderOpen size={15} /><span>{t("Run details")}</span><ChevronDown size={13} /></summary>
        <div className="run-details-popover">
          <div><span>{t("Profile")}</span><strong>{t(runState.profile || config.trafficProfile)}</strong></div>
          <div><span>{t("Report depth")}</span><strong>{t(config.reportDepth)}</strong></div>
          <div><span>{t("Run directory")}</span><code>{runState.currentRunDir || t("Not available")}</code></div>
          <div><span>{t("Report")}</span><code>{runState.report.path || t("Not available")}</code></div>
        </div>
      </details>
    </header>
  );
}
