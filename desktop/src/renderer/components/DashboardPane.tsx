import { t } from "../lib/i18n";
import type { HostTelemetry, RunStateSnapshot } from "../../shared/api";
import type { ActiveView } from "./Sidebar";
import { Bug, Camera, Globe, Radar, Search, ShieldAlert } from "lucide-react";
import FindingsList from "./FindingsList";
import MetricCard from "./MetricCard";
import MiniAttackChain from "./MiniAttackChain";
import RunHealth from "./RunHealth";
import StageMatrix from "./StageMatrix";
import type { OperatorModel } from "../lib/operatorModel";
import { normalizeStageStatus } from "../lib/stageModel";

interface DashboardPaneProps {
  runState: RunStateSnapshot;
  model: OperatorModel;
  onOpenGraph: (signalId?: string) => void;
  telemetry: HostTelemetry | null;
  terminalBuffer: string;
  onNavigate: (view: ActiveView) => void;
}

function strongestSummary(runState: RunStateSnapshot): string {
  if (runState.decision?.summary) return runState.decision.summary;
  if (runState.metrics.nucleiFindings > 0) {
    return t("{count} Nuclei matches require operator validation.", { count: runState.metrics.nucleiFindings });
  }
  if (runState.metrics.gobusterHits || runState.metrics.ffufHits) {
    return t("Discovery produced exposed paths; review content and status codes.");
  }
  if (runState.runState === "running") {
    return t("Scan is running. Findings will populate as artifacts arrive.");
  }
  return t("No active risk signal yet. Start a scan or select an existing run.");
}

function actionLabel(runState: RunStateSnapshot): string {
  if (runState.decision?.firstAction) return runState.decision.firstAction;
  if (runState.metrics.nucleiFindings > 0) return t("Validate highest-severity nuclei evidence");
  if (runState.metrics.gobusterHits || runState.metrics.ffufHits) return t("Review discovered directories and files");
  return t("Start scan and monitor stage transitions");
}

function riskDisplay(runState: RunStateSnapshot): string {
  if (runState.risk?.score !== null && runState.risk?.score !== undefined) return `${runState.risk.score}`;
  return (runState.risk?.label || "pending").toUpperCase();
}

function plainTerminalLines(buffer: string, fallback: string[]): string[] {
  const stripped = buffer.replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, "").replace(/\r/g, "");
  return (stripped.split("\n").filter(Boolean).slice(-10).length ? stripped.split("\n").filter(Boolean).slice(-10) : fallback);
}

function numericResult(value: unknown): number {
  const parsed = Number(value ?? 0);
  return Number.isFinite(parsed) ? parsed : 0;
}

function countResult(value: unknown, fallback?: unknown): number {
  if (Array.isArray(value)) return value.length;
  return numericResult(fallback);
}

export default function DashboardPane({
  runState,
  telemetry,
  terminalBuffer,
  onNavigate, model, onOpenGraph
}: DashboardPaneProps): JSX.Element {
  const operatorModel = model;
  const signalCount = operatorModel.signals.length;
  const enrichment = runState.ipEnrichment;
  const enrichmentResults = enrichment?.results || {};
  const enrichmentOpenPorts = countResult(enrichmentResults.openPorts ?? enrichmentResults.open_ports, enrichmentResults.openPortsCount ?? enrichmentResults.open_ports_count);
  const enrichmentServices = countResult(enrichmentResults.services, enrichmentResults.servicesCount ?? enrichmentResults.services_count);
  const enrichmentProbes = countResult(enrichmentResults.probes, enrichmentResults.probesCount ?? enrichmentResults.probes_count);
  const enrichmentActivity = enrichment?.status
    ? [
        enrichment.scanMode === "already_covered"
          ? "Primary Nmap already covered resolved IP; reusing as auxiliary context."
          : enrichment.status === "done"
            ? `IP enrichment done · ${enrichment.resolvedIp || "resolved IP"} · ${enrichmentOpenPorts} ports · ${enrichmentProbes} probes`
            : `IP enrichment ${enrichment.status} · open_ports=${enrichmentOpenPorts}, services=${enrichmentServices}, probes=${enrichmentProbes}`
      ]
    : [];
  const activityRows = (enrichmentActivity.length ? enrichmentActivity : [])
    .concat(runState.logTail.length ? runState.logTail.slice(-6).reverse() : ["No live activity yet."])
    .slice(0, 6);
  const failedStages = runState.stages.filter((stage) => ["error", "failed", "partial", "interrupted"].includes(stage.status));
  const skippedStages = runState.stages.filter((stage) => stage.status === "skipped");
  const nucleiStage = runState.stages.find((stage) => stage.name === "nuclei");
  const nucleiResultLabel = runState.metrics.nucleiFindings ? "review now"
    : nucleiStage?.status === "done" ? "bulgu bulunmadı"
    : nucleiStage?.status === "skipped" ? "çalıştırılmadı"
    : ["error", "failed", "partial", "interrupted"].includes(nucleiStage?.status || "") ? "kapsam eksik"
    : "bekleniyor";
  const resultLabel = (name: string, count: number, populated: string) => {
    const stage = runState.stages.find(item => item.name === name);
    const status = normalizeStageStatus(stage?.status || "unknown");
    if (status === "skipped") return "çalıştırılmadı";
    if (["error", "partial", "interrupted"].includes(status)) return "kapsam eksik";
    if (count > 0) return populated;
    if (status === "done") return "bulgu bulunmadı";
    return status === "unknown" ? "Not recorded" : status;
  };
  const metrics = [
    { label: "Katana URLs", value: runState.metrics.katanaCount, delta: resultLabel("katana", runState.metrics.katanaCount, "crawl surface"), tone: "cyan" as const, icon: Radar },
    { label: "Gobuster Hits", value: runState.metrics.gobusterHits, delta: resultLabel("gobuster", runState.metrics.gobusterHits, "content paths"), tone: "blue" as const, icon: Search },
    { label: "FFUF Hits", value: runState.metrics.ffufHits, delta: resultLabel("ffuf", runState.metrics.ffufHits, "fuzz hits"), tone: "green" as const, icon: Bug },
    { label: "Nuclei Findings", value: runState.metrics.nucleiFindings, delta: nucleiResultLabel, tone: "red" as const, icon: ShieldAlert },
    { label: "Web Checks", value: runState.metrics.checksCount, delta: resultLabel("checks", runState.metrics.checksCount, "signals"), tone: "amber" as const, icon: Globe },
    { label: "Screenshots", value: runState.metrics.screenshotsCount, delta: resultLabel("screenshots", runState.metrics.screenshotsCount, "visual proof"), tone: "violet" as const, icon: Camera },
    ...(runState.osint?.enabled
      ? [{
          label: "OSINT",
          value: t(runState.osint.status),
          delta: t("{count} signals · risk {risk}", {count: runState.osint.totalSignals, risk: t(runState.osint.riskScoreImpact)}),
          tone: "blue" as const,
          icon: Globe
        }]
      : [])
  ];

  return (
    <section className="dashboard-cockpit">
      <div className="page-title">
        <div>
          <span className="micro-label">{t("Dashboard")}</span>
          <h1>{t("Operational Situation")}</h1>
        </div>
        <button type="button" onClick={() => onNavigate("configure")}>{t("Configure Scan")}</button>
      </div>

      {Boolean(failedStages.length || skippedStages.length) && <div className={`run-integrity-state ${failedStages.length ? "partial" : "selected-scope"}`} role="status">
        <div>
          {failedStages.length > 0 && <><p><strong>{t("Selected checks did not finish:")}</strong> {failedStages.map((stage) => stage.label).join(", ")}.</p>
            <details><summary>{t("Completion details")}</summary>{failedStages.map(stage => <p key={stage.name}>{stage.label}: {stage.reason || t(stage.status)}</p>)}</details></>}
          {skippedStages.length > 0 && <details><summary>{t("Outside this scan's selected scope")} · {skippedStages.length}</summary><p>{skippedStages.map((stage) => stage.label).join(", ")}.</p><p>{t("Disabled or inapplicable checks are not failures. Results apply to the selected checks; no matches do not prove the target has no vulnerabilities.")}</p></details>}
        </div>
      </div>}
      <div className="metric-strip" style={{ gridTemplateColumns: `repeat(${metrics.length}, minmax(0, 1fr))` }}>
        {metrics.map((metric) => (
          <MetricCard key={metric.label} {...metric} />
        ))}
      </div>

      <StageMatrix stages={runState.stages} currentStage={runState.currentStage} report={runState.report} runState={runState.runState} />

      <div className="dashboard-content-grid">
        <div className="dashboard-main-column">
          <div className="dashboard-middle-grid">
            <section className="cockpit-panel operator-summary">
              <header className="panel-head">
                <div>
                  <span className="micro-label">{t("Operator summary")}</span>
                  <h2>{t("Operatör Özeti")}</h2>
                </div>
              </header>
              <div className="risk-callout">
                <div className={runState.metrics.nucleiFindings || runState.risk?.label === "high" || runState.risk?.label === "critical" ? "risk-emblem hot" : "risk-emblem"}>
                  <ShieldAlert size={22} />
                  <strong>{riskDisplay(runState)}</strong>
                </div>
                <div>
                  <strong>{signalCount ? t("Operasyon sinyali tespit edildi") : t("İzleme modunda")}</strong>
                  <p>{strongestSummary(runState)}</p>
                </div>
              </div>
              <div className="next-action">
                <span className="micro-label">{t("İlk önerilen aksiyon")}</span>
                <button type="button" onClick={() => onNavigate(signalCount ? "findings" : "terminal")}>
                  {actionLabel(runState)}
                </button>
              </div>
            </section>

            <section className="cockpit-panel live-findings-panel">
              <header className="panel-head">
                <div>
                  <span className="micro-label">{t("Live findings")}</span>
                  <h2>{t("Canlı Bulgular")}</h2>
                </div>
                <button type="button" onClick={() => onNavigate("findings")}>{t("Tümü")}</button>
              </header>
              <FindingsList model={operatorModel} compact />
            </section>

          </div>

          <div className="dashboard-bottom-grid">
            <section className="cockpit-panel terminal-preview">
              <header className="panel-head">
                <div>
                  <span className="micro-label">{t("Live terminal")}</span>
                  <h2>{t("Canlı Terminal")}</h2>
                </div>
                <button type="button" onClick={() => onNavigate("terminal")}>{t("Open")}</button>
              </header>
              <pre>
                {plainTerminalLines(terminalBuffer, ["ReconBot PTY ready.", "Waiting for scan command..."]).join("\n")}
              </pre>
            </section>

            <section className="cockpit-panel activity-panel">
              <header className="panel-head">
                <div>
                  <span className="micro-label">{t("Recent activity")}</span>
                  <h2>{t("Son Aktiviteler")}</h2>
                </div>
              </header>
              <div className="activity-list">
                {activityRows.map((line, index) => (
                  <div key={`${line}-${index}`}>
                    <span>{runState.updatedAt || "--:--"}</span>
                    <p title={line}>{line}</p>
                  </div>
                ))}
              </div>
            </section>
          </div>
        </div>

        <aside className="dashboard-right">
          <MiniAttackChain model={operatorModel} onOpen={onOpenGraph} />
          <RunHealth runState={runState} telemetry={telemetry} />
        </aside>
      </div>
    </section>
  );
}
