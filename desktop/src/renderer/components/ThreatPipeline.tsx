import { t } from "../lib/i18n";
import { useEffect, useMemo, useState } from "react";
import { GitBranch, Search } from "lucide-react";
import type { RunStateSnapshot } from "../../shared/api";
import type { OperatorModel, OperatorSignal } from "../lib/operatorModel";
import { buildOperatorModel, severityTone, tagsForSignal } from "../lib/operatorModel";
import type { AttackGraphFilter, AttackGraphNodeId } from "../lib/attackGraph";
import { buildAttackGraphModel, buildScanNetwork, buildFindingNetwork } from "../lib/attackGraph";
import EvidenceGraph, { graphMetricLabel, graphNodeLabel } from "./EvidenceGraph";
import { SignalCard } from "./FindingsList";

interface ThreatPipelineProps {
  runState: RunStateSnapshot;
  model?: OperatorModel;
  variant?: "feed" | "chain";
  onOpenFindings?: () => void;
  active?: boolean;
  focusSignalId?: string;
}

function useModel(model: OperatorModel | undefined, runState: RunStateSnapshot): OperatorModel {
  return useMemo(() => model ?? buildOperatorModel(runState), [model, runState]);
}

function FeedCard({ signal }: { signal: OperatorSignal }): JSX.Element {
  const Icon = signal.icon;
  const tone = severityTone(signal.severity);
  return (
    <article className={`threat-card severity-${tone}`}>
      <div className="threat-card-top">
        <span className="severity-badge"><Icon size={12} /> {signal.severity}</span>
        <small>{signal.source} / {signal.type}</small>
      </div>
      <strong title={signal.title}>{signal.title}</strong>
      <p title={signal.location}>{signal.location}</p>
      <div className="threat-tags">
        {tagsForSignal(signal).slice(0, 3).map((tag) => <span key={tag}>{tag}</span>)}
      </div>
    </article>
  );
}

function FeedView({ runState, model, onOpenFindings }: ThreatPipelineProps): JSX.Element {
  const operatorModel = useModel(model, runState);
  const signals = operatorModel.signals.filter((signal) => signal.type !== "status").slice(0, 5);

  return (
    <section className="cockpit-panel threat-panel threat-feed-panel">
      <header className="panel-head">
        <div>
          <span className="micro-label"><GitBranch size={12} /> {" "}{t("Threat pipeline")}</span>
          <h2>{t("Tehdit Akışı")}</h2>
        </div>
        <span className={`panel-chip ${runState.runState === "running" ? "live" : ""}`}>
          {runState.runState === "running" ? t("canli") : t("standby")}
        </span>
      </header>

      <div className="threat-filter-row" aria-label={t("visual severity filters")}>
        <span className="filter-pill">{t("Tümü")}</span>
        <span className="filter-pill critical">{t("Critical")}</span>
        <span className="filter-pill high">{t("High")}</span>
        <span className="filter-pill medium">{t("Medium")}</span>
        <span className="filter-pill low">{t("Low")}</span>
        <span className="filter-pill info">{t("Info")}</span>
      </div>

      <div className="threat-feed">
        {signals.length ? signals.map((signal) => (
          <FeedCard signal={signal} key={signal.id} />
        )) : (
          <div className="empty-signal tight">
            <Search size={16} />
            <span>{t("No active signal.")}</span>
          </div>
        )}
      </div>

      <button type="button" onClick={onOpenFindings}>{t("Tüm Bulguları Gör")}</button>
    </section>
  );
}

const graphFilters: Array<{ id: AttackGraphFilter; label: string }> = [
  { id: "all", label: "Tümü" }, { id: "recon", label: "Recon" },
  { id: "exposure", label: "Exposure" }, { id: "vulnerability", label: "Template matches" },
  { id: "evidence", label: "Evidence" }, { id: "critical-high", label: "Critical/High" }
];

function RecordedAddress({ url, onLocate, detail = false }: { url: string; onLocate?: () => void; detail?: boolean }): JSX.Element {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const copy = async () => {
    try { const result = await window.reconbot.copyText(url); setCopyState(result.ok ? "copied" : "failed"); }
    catch { setCopyState("failed"); }
  };
  return <article className={detail ? "graph-address-detail" : "discovery-url-row"}>
    <code>{url}</code><div className="discovery-url-actions">
      {onLocate && <button type="button" onClick={onLocate}>{t("Show on graph")}</button>}
      <button type="button" onClick={() => void copy()}>{t(copyState === "copied" ? "Copied" : "Copy URL")}</button>
    </div>{copyState === "failed" && <small role="status">{t("Could not copy URL. Try again.")}</small>}
  </article>;
}

function ChainView({ runState, model, active = true, focusSignalId }: ThreatPipelineProps): JSX.Element {
  const operatorModel = useModel(model, runState);
  const [mode, setMode] = useState<"findings" | "all" | "workflow">("findings");
  const [selectedNode, setSelectedNode] = useState<AttackGraphNodeId | null>(null);
  const [activeFilter, setActiveFilter] = useState<AttackGraphFilter>("all");
  const [expanded, setExpanded] = useState<ReadonlySet<AttackGraphNodeId>>(new Set());
  const network = useMemo(() => buildScanNetwork(runState, operatorModel), [operatorModel, runState]);
  const graph = useMemo(() => mode === "findings" ? buildFindingNetwork(network, expanded, selectedNode) : mode === "all" ? network : buildAttackGraphModel(runState, operatorModel), [mode, network, expanded, selectedNode, operatorModel, runState]);
  useEffect(() => { setSelectedNode(null); setActiveFilter("all"); setExpanded(new Set()); }, [runState.currentRunDir]);
  useEffect(() => {
    if (!active || !focusSignalId) return;
    const signal = operatorModel.signals.find(signal => signal.id === focusSignalId);
    if (signal && signal.type !== "status") { setMode("findings"); setSelectedNode(`finding:${focusSignalId}`); }
    setActiveFilter("all");
  }, [focusSignalId, active]);
  const selected = graph.nodes.find(node => node.id === selectedNode) ?? graph.nodes[0];
  const discoveryURLs = useMemo(() => {
    if (selected?.cluster?.kind !== "urls") return [];
    const linked = new Set(network.edges.filter(edge => edge.from === `source:${selected.cluster!.source}`).map(edge => edge.to));
    const matched = new Set(network.edges.filter(edge => edge.to.startsWith("finding:")).map(edge => edge.from));
    return network.nodes.filter(node => linked.has(node.id) && node.id.startsWith("endpoint:") && !matched.has(node.id));
  }, [network, selected]);
  const isURLGroup = selected?.cluster?.kind === "urls";
  const isEndpoint = selected?.id.startsWith("endpoint:");
  const endpointSources = isEndpoint ? network.edges.filter(edge => edge.to === selected.id && edge.from.startsWith("source:")).map(edge => edge.from.slice(7)) : [];
  const visibleEvidence = operatorModel.signals.filter(signal => selected?.signalIds.includes(signal.id) && (
    activeFilter === "all" || activeFilter === "critical-high" && ["critical", "high"].includes(signal.severity) || signal.type === activeFilter));
  const changeMode = (next: "findings" | "all" | "workflow") => { setMode(next); setSelectedNode(null); setActiveFilter("all"); };
  const toggleCluster = (id: AttackGraphNodeId) => setExpanded(current => {
    const next = new Set(current); if (next.has(id)) next.delete(id); else next.add(id); return next;
  });
  const selectNode = (id: AttackGraphNodeId) => {
    if (id.startsWith("cluster:")) { setSelectedNode(id); toggleCluster(id); }
    else setSelectedNode(current => current === id ? null : id);
  };
  const locateURL = (id: AttackGraphNodeId) => {
    if (selected?.cluster) setExpanded(current => new Set([...current, selected.id]));
    setSelectedNode(id);
  };
  return <div className="pipeline-page-inner">
    <section className="cockpit-panel threat-panel attack-network-panel evidence-network-panel">
      <header className="panel-head large"><div><span className="micro-label"><GitBranch size={12} /> {t("Threat pipeline")}</span><h2>{t("Evidence graph")}</h2></div>
        <span className={`panel-chip ${runState.runState === "running" ? "live" : ""}`}>{t(runState.runState)}</span></header>
      <div className="graph-mode-row"><div className="graph-mode-switch">
        <button type="button" className={mode === "findings" ? "active" : ""} aria-pressed={mode === "findings"} onClick={() => changeMode("findings")}>{t("Finding focus")}</button>
        <button type="button" className={mode === "all" ? "active" : ""} aria-pressed={mode === "all"} onClick={() => changeMode("all")}>{t("All discovery data")}</button>
        <button type="button" className={mode === "workflow" ? "active" : ""} aria-pressed={mode === "workflow"} onClick={() => changeMode("workflow")}>{t("Source workflow")}</button>
      </div></div>
      <p className="graph-scope-note">{t(mode === "findings" ? "Click + to expand a group. Read its addresses or findings in the right panel." : mode === "all" ? "Recorded URLs, sources and findings. Connections show evidence associations, not proven exploitation." : "Source workflow and observed signals. Links describe the workflow, not a confirmed attack path.")}</p>
      <div className="graph-toolbar" aria-label={t("Attack graph filters")}>{graphFilters.map(filter => <button type="button" key={filter.id} className={activeFilter === filter.id ? "active" : ""} aria-pressed={activeFilter === filter.id} onClick={() => setActiveFilter(filter.id)}>{t(filter.label)}</button>)}</div>
      <EvidenceGraph graph={graph} selected={selectedNode} filter={activeFilter} onSelect={selectNode} onClear={() => setSelectedNode(null)} onReset={() => { setSelectedNode(null); setActiveFilter("all"); setExpanded(new Set()); }} active={active} resetKey={`${runState.currentRunDir}|${mode}`} />
      {selected && <div className="network-detail-panel"><span className={`severity-badge severity-${selected.severity}`}>{selected.severity}</span><div><strong>{graphNodeLabel(selected)}</strong><p>{graphMetricLabel(selected.metric)} · {t(selected.status)}</p><small>{t(selected.actionHint)}</small></div>{selected.cluster && <button type="button" className="cluster-toggle" aria-expanded={selected.cluster.expanded} onClick={() => toggleCluster(selected.id)}>{t(selected.cluster.kind === "findings" ? selected.cluster.expanded ? "Collapse findings" : "Expand findings" : selected.cluster.expanded ? "Collapse URLs" : "Expand URLs")}</button>}</div>}
    </section>
    <section className="cockpit-panel pipeline-evidence-panel"><header className="panel-head"><div><span className="micro-label">{t(isURLGroup ? "Discovery addresses" : isEndpoint ? "Recorded address" : "Evidence stream")}</span><h2 title={selected?.label}>{selected ? graphNodeLabel(selected) : t("Pipeline Evidence")}</h2></div><div className="graph-inspector-actions">{selectedNode && <button type="button" onClick={() => { setSelectedNode(null); setActiveFilter("all"); }}>{t("Show all findings")}</button>}<span className="panel-chip">{isURLGroup ? graphMetricLabel(`${discoveryURLs.length} URLs`) : `${visibleEvidence.length} ${t("signals")}`}</span></div></header>
      <div className="pipeline-evidence-list">
        {isURLGroup ? discoveryURLs.map(node => <RecordedAddress key={node.id} url={node.label} onLocate={() => locateURL(node.id)} />) : <>
          {isEndpoint && <><RecordedAddress key={selected.id} url={selected.label} detail /><p className="graph-address-sources">{t("Sources")}: {endpointSources.join(", ")}</p></>}
          {visibleEvidence.length ? visibleEvidence.map(signal => <SignalCard key={signal.id} signal={signal} selected={selectedNode === `finding:${signal.id}`} onClick={() => { setMode("findings"); setSelectedNode(`finding:${signal.id}`); }} />) : <div className="empty-signal"><Search size={18} /><span>{t("No evidence linked to this node for the selected filter.")}</span></div>}
        </>}
      </div>
    </section>
  </div>;
}

export default function ThreatPipeline(props: ThreatPipelineProps): JSX.Element {
  if (props.variant === "chain") return <ChainView {...props} />;
  return <FeedView {...props} />;
}
