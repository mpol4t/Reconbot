import { t } from "../lib/i18n";
import { ArrowUpRight, GitBranch } from "lucide-react";
import type { OperatorModel } from "../lib/operatorModel";
interface Props { model: OperatorModel; onOpen: (signalId?: string) => void; }
export default function MiniAttackChain({ model, onOpen }: Props): JSX.Element {
  const evidence = model.signals.filter(signal => signal.type !== "status");
  const signals = evidence.slice(0, 24);
  const sources = [...new Set(evidence.map(signal => signal.source))];
  const sourceAt = (index: number) => ({ x: 140 + Math.cos(index * 2.399) * 58, y: 130 + Math.sin(index * 2.399) * 48 });
  return <section className="cockpit-panel mini-chain-panel mini-evidence-panel">
    <header className="panel-head"><h2><GitBranch size={14} /> {t("Evidence links")}</h2><button type="button" onClick={() => onOpen()}>{t("Graph")} <ArrowUpRight size={12} /></button></header>
    <svg className="mini-evidence-graph mini-force-preview" viewBox="0 0 280 265" aria-label={t("Evidence graph preview")}>
      {signals.map((signal, index) => {
        const source = sourceAt(sources.indexOf(signal.source));
        const angle = index * 2.399, radius = 28 + Math.sqrt(index + 1) * 10;
        const point = {x:Math.max(18,Math.min(262,source.x + Math.cos(angle) * radius)),y:Math.max(25,Math.min(240,source.y + Math.sin(angle) * radius))};
        return <g key={signal.id} className={`mini-evidence-node severity-${signal.severity}`}>
          <line x1={source.x} y1={source.y} x2={point.x} y2={point.y} />
          <g role="button" tabIndex={0} aria-label={signal.title} transform={`translate(${point.x} ${point.y})`} onClick={() => onOpen(signal.id)} onKeyDown={event => { if (["Enter", " "].includes(event.key)) { event.preventDefault(); onOpen(signal.id); } }}>
            <title>{`${signal.title}\n${signal.location}`}</title><circle r="12" fill="transparent" /><circle className="mini-dot" r={index < 3 ? 4.5 : 3} />
          </g>
        </g>;
      })}
      {sources.map((source,index)=>{const point=sourceAt(index);return <g key={source} className="mini-source-dot"><circle cx={point.x} cy={point.y} r="6" /><text x={point.x+10} y={point.y+4}>{source}</text></g>;})}
    </svg>
    <div className="mini-map-summary"><strong>{evidence.length}</strong> {t("signals")} · {sources.length} {t("sources")}</div>
    <p>{t(signals.length ? "Select a finding to inspect its evidence links." : "Evidence links will appear when scan results arrive.")}</p>
  </section>;
}
