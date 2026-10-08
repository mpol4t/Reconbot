import { t } from "../lib/i18n";
import { Activity, Radio, Wifi } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { HostTelemetry, RunStateSnapshot } from "../../shared/api";

interface RunHealthProps {
  runState: RunStateSnapshot;
  telemetry: HostTelemetry | null;
}

function TelemetryTile({
  icon: Icon,
  label,
  valueText,
  detail,
  tone = "cyan"
}: {
  icon: LucideIcon;
  label: string;
  valueText: string;
  detail: string;
  tone?: "cyan" | "green" | "amber" | "blue";
}): JSX.Element {
  return (
    <div className={`telemetry-tile tone-${tone}`}>
      <span className="telemetry-icon"><Icon size={15} /></span>
      <div>
        <small>{t(label)}</small>
        <strong title={valueText}>{valueText}</strong>
        <em title={detail}>{detail}</em>
      </div>
    </div>
  );
}

export default function RunHealth({ runState, telemetry }: RunHealthProps): JSX.Element {
  const cpuText = typeof telemetry?.cpuLoadPercent === "number" ? `${telemetry.cpuLoadPercent}%` : "n/a";
  const memoryText = typeof telemetry?.ramUsedPercent === "number" ? `${telemetry.ramUsedPercent}%` : "n/a";
  const memoryLabel = telemetry?.ramLabel?.replace(/^Host memory approx$/i, "Memory approx") || "Memory approx";
  const memoryDetail = telemetry ? `${telemetry.ramDetail}${telemetry.ramApproximate ? " · approx" : ""}` : "n/a";
  const networkText = telemetry?.network || "n/a";

  return (
    <section className="cockpit-panel run-health-panel">
      <header className="panel-head">
        <div>
          <span className="micro-label">{t("Host telemetry")}</span>
          <h2>{t("System Status")}</h2>
        </div>
        <span className={`panel-chip ${runState.runState === "running" ? "live" : ""}`}>{runState.runState || "idle"}</span>
      </header>

      <div className="telemetry-grid">
        <TelemetryTile icon={Activity} label={t("CPU")} valueText={cpuText} detail="sample delta" tone="cyan" />
        <TelemetryTile
          icon={Radio}
          label={memoryLabel}
          valueText={memoryText}
          detail={memoryDetail}
          tone="green"
        />
        <TelemetryTile icon={Wifi} label={t("Network")} valueText={networkText} detail="rx/tx if available" tone="blue" />
      </div>

      <div className="telemetry-footer" aria-label={t("Run linkage summary")}>
        <span>{runState.runState || "idle"}</span>
        <span>{runState.report.exists ? t("report ready") : t("report pending")}</span>
        <span>{runState.currentRunDir ? t("run linked") : t("no run")}</span>
      </div>
    </section>
  );
}
