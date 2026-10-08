import { Check, ChevronDown, CircleDashed, LoaderCircle, Minus, OctagonAlert } from "lucide-react";
import { t } from "../lib/i18n";
import { normalizeStageStatus, summarizeStages } from "../lib/stageModel";
import type { ReportState, StageRow } from "../../shared/api";

const phases = [
  { id: "recon", label: "Recon", tools: ["nmap", "subfinder", "dnsx", "httpx"] },
  { id: "discovery", label: "Discovery", tools: ["katana", "historical_urls"] },
  { id: "enumeration", label: "Enumeration", tools: ["gobuster", "ffuf", "whatweb", "wafw00f"] },
  { id: "vuln", label: "Vuln Scan", tools: ["nuclei"] },
  { id: "analysis", label: "Analysis", tools: ["checks", "screenshots"] },
  { id: "report", label: "Report", tools: ["report"] }
];

interface Props { stages: StageRow[]; currentStage: string; report: ReportState; runState: string; }
export default function StageMatrix({ stages, currentStage, report, runState }: Props): JSX.Element {
  const reportRow: StageRow = { name: "report", label: t("Report"), status: report.exists
    ? runState === "completed" ? "done" : "partial"
    : report.status === "failed" ? "error" : "pending", metric: t(report.exists
      ? runState === "completed" ? "Report ready" : "Partial report" : "Report pending"), reason: report.failureReason || "" };
  return <section className="cockpit-panel stage-strip-panel">
    <header className="panel-head"><h2>{t("Tarama Aşamaları")}</h2>
      <span className="panel-chip">{runState === "running" ? t(currentStage) || t("Running") : t(runState)}</span>
    </header>
    <div className="stage-phase-strip">{phases.map((phase, index) => {
      const rows = phase.id === "report" ? [reportRow] : stages.filter(row => phase.tools.includes(row.name));
      const summary = summarizeStages(rows);
      const Icon = summary.status === "done" ? Check : summary.status === "running" ? LoaderCircle
        : summary.status === "skipped" ? Minus : ["partial", "error", "interrupted"].includes(summary.status) ? OctagonAlert : CircleDashed;
      const metric = phase.id === "report" ? reportRow.metric : !rows.length || summary.status === "unknown" ? t("Not recorded")
        : summary.status === "skipped" ? t("{count} skipped", { count: summary.skipped })
        : t("{done}/{total} completed", summary);
      return <details className={`stage-phase status-${summary.status}`} key={phase.id}>
        <summary title={`${t(phase.label)} · ${t(summary.status)}`}><span className="stage-index">{index + 1}</span><div><strong>{t(phase.label)}</strong>
          <small>{metric}{phase.id !== "report" && summary.skipped > 0 && summary.total > 0 ? ` · ${t("{count} skipped", { count: summary.skipped })}` : ""}</small>
        </div><Icon className="stage-status-icon" size={14} /><ChevronDown className="stage-chevron" size={11} /></summary>
        <div className="stage-tool-details"><strong>{t(phase.label)} · {t(summary.status)}</strong>
          {rows.length ? rows.map(row => <div className="stage-tool-row" key={row.name}><span>{t(row.label)}</span>
            <span className={`tool-state status-${normalizeStageStatus(row.status)}`}>{t(normalizeStageStatus(row.status))}</span>
            {row.reason && <small>{row.reason === "No stage status was recorded." ? t(row.reason) : row.reason}</small>}</div>) : <p>{t("No stage status was recorded.")}</p>}
        </div>
      </details>;
    })}</div>
  </section>;
}
