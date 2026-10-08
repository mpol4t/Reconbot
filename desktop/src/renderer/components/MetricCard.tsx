import { t } from "../lib/i18n";
import type { LucideIcon } from "lucide-react";

interface MetricCardProps {
  label: string;
  value: string | number;
  delta?: string;
  tone?: "cyan" | "blue" | "green" | "red" | "amber" | "violet";
  icon: LucideIcon;
}

export default function MetricCard({ label, value, delta, tone = "cyan", icon: Icon }: MetricCardProps): JSX.Element {
  return (
    <article className={`metric-card tone-${tone}`}>
      <div className="metric-icon" aria-hidden="true">
        <Icon size={20} strokeWidth={1.9} />
      </div>
      <div>
        <span className="micro-label">{t(label)}</span>
        <strong>{value}</strong>
        {delta && <small>{t(delta)}</small>}
      </div>
    </article>
  );
}
