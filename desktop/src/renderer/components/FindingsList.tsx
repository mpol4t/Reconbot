import { t } from "../lib/i18n";
import { Search } from "lucide-react";
import type { OperatorModel, OperatorSignal } from "../lib/operatorModel";
import { buildOperatorModel, severityTone, tagsForSignal } from "../lib/operatorModel";
import type { RunStateSnapshot } from "../../shared/api";

interface FindingsListProps {
  model?: OperatorModel;
  runState?: RunStateSnapshot;
  compact?: boolean;
  signals?: OperatorSignal[];
}

export function buildFindingSignals(runState: RunStateSnapshot): OperatorSignal[] {
  return buildOperatorModel(runState).signals;
}

export function SignalCard({ signal, compact = false, selected = false, onClick }: {
  signal: OperatorSignal;
  compact?: boolean;
  selected?: boolean;
  onClick?: () => void;
}): JSX.Element {
  const Icon = signal.icon;
  const tone = severityTone(signal.severity);
  return (
    <article
      className={`finding-card severity-${tone} ${selected ? "selected" : ""}`}
      onClick={onClick}
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={(event) => {
        if (!onClick) return;
        if (event.key === "Enter" || event.key === " ") onClick();
      }}
    >
      <div className="finding-card-top">
        <span className="severity-badge"><Icon size={12} /> {signal.severity}</span>
        <small>{signal.source} / {signal.type}</small>
      </div>
      <strong title={signal.title}>{signal.title}</strong>
      {!compact && <p title={t(signal.description)}>{t(signal.description)}</p>}
      <span title={signal.location}>{signal.location}</span>
      <div className="threat-tags">
        {tagsForSignal(signal).map((tag) => <span key={tag}>{tag}</span>)}
      </div>
      {!compact && signal.actionHint && <small title={t(signal.actionHint)}>{t(signal.actionHint)}</small>}
    </article>
  );
}

export default function FindingsList({ model, runState, compact = false, signals }: FindingsListProps): JSX.Element {
  const rows = (signals ?? model?.signals ?? (runState ? buildOperatorModel(runState).signals : [])).slice(0, compact ? 5 : 36);

  if (!rows.length) {
    return (
      <div className="empty-signal">
        <Search size={18} />
        <span>{t("No vulnerability findings or exposure signals yet.")}</span>
      </div>
    );
  }

  return (
    <div className={`finding-stack ${compact ? "compact" : ""}`}>
      {rows.map((signal) => (
        <SignalCard key={signal.id} signal={signal} compact={compact} />
      ))}
    </div>
  );
}
