import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowRight, Copy, Search, ShieldCheck } from "lucide-react";
import type { OperatorModel } from "../lib/operatorModel";
import { t } from "../lib/i18n";

interface Props { model: OperatorModel; runKey: string; onValidateSqlmap?: (url: string, findingId: string) => void; }
const PAGE_SIZE = 50;
const severities = ["critical", "high", "medium", "low", "info"];

export default function FindingsPane({ model, runKey, onValidateSqlmap }: Props): JSX.Element {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [source, setSource] = useState("all");
  const [selectedId, setSelectedId] = useState("");
  const [limit, setLimit] = useState(PAGE_SIZE);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const requestVersion = useRef(0);
  const sources = useMemo(() => [...new Set(model.signals.map((row) => row.source))], [model]);
  const filtered = useMemo(() => model.signals.filter((row) => {
    const matchesQuery = `${row.title} ${row.location} ${row.source} ${row.tags.join(" ")}`.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase());
    return matchesQuery && (severity === "all" || row.severity === severity) && (source === "all" || row.source === source);
  }), [model, query, severity, source]);
  const selected = filtered.find((row) => row.id === selectedId);
  useEffect(() => { setQuery(""); setSeverity("all"); setSource("all"); setSelectedId(""); setLimit(PAGE_SIZE); }, [runKey]);
  useEffect(() => { setLimit(PAGE_SIZE); }, [query, severity, source]);
  useEffect(() => { requestVersion.current += 1; setCopyState("idle"); }, [selectedId, runKey]);
  const copyLocation = async (): Promise<void> => {
    if (!selected) return;
    const version = requestVersion.current;
    try {
      if (window.reconbot?.copyText) await window.reconbot.copyText(selected.location);
      else await navigator.clipboard.writeText(selected.location);
      if (version === requestVersion.current) setCopyState("copied");
    } catch { if (version === requestVersion.current) setCopyState("failed"); }
  };
  return (
    <section className="findings-workspace">
      <header className="page-title">
        <div><span className="micro-label">{t("Analysis")}</span><h1>{t("Findings")}</h1></div>
        <span className="results-count">{filtered.length} / {model.signals.length} {t("signals")}</span>
      </header>
      <div className="finding-filters">
        <label className="finding-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("Search findings…")} aria-label={t("Search findings…")} /></label>
        <select value={severity} aria-label={t("Severity filter")} onChange={(event) => setSeverity(event.target.value)}>
          <option value="all">{t("All severities")}</option>
          {severities.map((item) => <option key={item} value={item}>{t(item[0].toUpperCase() + item.slice(1))}</option>)}
        </select>
        <select value={source} aria-label={t("Source")} onChange={(event) => setSource(event.target.value)}>
          <option value="all">{t("All sources")}</option>
          {sources.map((item) => <option key={item} value={item}>{item}</option>)}
        </select>
      </div>
      <div className="findings-split">
        <div className="finding-results" role="region" aria-label={t("Findings")}>
          {filtered.slice(0, limit).map((row) => (
            <button type="button" key={row.id} aria-pressed={row.id === selectedId} onClick={() => setSelectedId(row.id)} className={`finding-result ${row.id === selectedId ? "selected" : ""}`}>
              <span className={`severity-marker severity-${row.severity}`} aria-label={t(row.severity[0].toUpperCase() + row.severity.slice(1))} />
              <span className="finding-result-copy"><span><strong>{row.title}</strong><small>{row.source} · {row.severity}</small></span><code>{row.location}</code></span>
              <ArrowRight size={15} />
            </button>
          ))}
          {!filtered.length && <div className="findings-empty"><Search size={24} /><p>{t("No findings match your filters.")}</p><button type="button" onClick={() => { setQuery(""); setSeverity("all"); setSource("all"); }}>{t("Clear filters")}</button></div>}
          {filtered.length > limit && <button type="button" className="load-more-findings" onClick={() => setLimit((value) => value + PAGE_SIZE)}><ArrowDown size={14} />{t("Show more findings")}</button>}
        </div>
        <aside className="finding-inspector" aria-label={t("Finding details")}>
          {selected ? <>
            <span className={`severity-badge severity-${selected.severity}`}>{selected.severity}</span>
            <h2>{selected.title}</h2>
            <p>{selected.description}</p>
            <dl><div><dt>{t("Source")}</dt><dd>{selected.source}</dd></div><div><dt>{t("Matched location")}</dt><dd><code>{selected.location}</code></dd></div></dl>
            <button type="button" onClick={() => { void copyLocation(); }}><Copy size={14} />{t("Copy location")}</button>
            {onValidateSqlmap && /^https?:\/\//i.test(selected.location) && <button type="button" onClick={() => onValidateSqlmap(selected.location, selected.id)}>{t("Validate with SQLmap")}</button>}
            <span className="copy-feedback" role="status">{copyState === "copied" ? t("Copied") : copyState === "failed" ? t("Copy failed") : ""}</span>
            <div className="finding-validation"><ShieldCheck size={18} /><div><strong>{t("Validation")}</strong><p>{t(selected.source === "nuclei" ? "A template match needs manual validation; it is not proof of exploitation." : "Review the available evidence before drawing a security conclusion.")}</p></div></div>
            {selected.actionHint && <div className="finding-next-action"><span className="micro-label">{t("Next action")}</span><p>{selected.actionHint}</p></div>}
            <div className="threat-tags">{selected.tags.map((tag) => <span key={tag}>{tag}</span>)}</div>
          </> : <div className="inspector-empty"><ShieldCheck size={28} /><p>{t("Select a finding to inspect its evidence.")}</p></div>}
        </aside>
      </div>
    </section>
  );
}
