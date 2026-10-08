import { t } from "../lib/i18n";
interface SystemStatusProps {
  runState: string;
}

export default function SystemStatus({ runState }: SystemStatusProps): JSX.Element {
  const gauges = [
    ["CPU", "18%", "cyan"],
    ["RAM", "64%", "blue"],
    ["DISK", "23%", "violet"]
  ];

  return (
    <section className="cockpit-panel system-panel">
      <header className="panel-head">
        <div>
          <span className="micro-label">{t("System status")}</span>
          <h2>{t("Sistem Durumu")}</h2>
        </div>
        <span className="panel-chip">{runState || "idle"}</span>
      </header>
      <div className="gauge-grid">
        {gauges.map(([label, value, tone]) => (
          <div className={`gauge gauge-${tone}`} key={label}>
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
      <div className="mini-stats">
        <span>{t("Uptime")}</span>
        <strong>00:14:32</strong>
        <span>{t("Network")}</span>
        <strong>{t("1.2 MB/s")}</strong>
      </div>
    </section>
  );
}
