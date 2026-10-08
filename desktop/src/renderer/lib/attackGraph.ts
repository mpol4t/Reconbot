import {
  Bug,
  Camera,
  Crosshair,
  FileWarning,
  Globe,
  LockKeyhole,
  Radar,
  ScanSearch,
  Search,
  ShieldAlert,
  Target
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { RunStateSnapshot } from "../../shared/api";
import type { OperatorModel, OperatorSignal, SignalSeverity } from "./operatorModel";

export type AttackGraphNodeId =
  | "target"
  | "recon"
  | "katana"
  | "web"
  | "gobuster"
  | "ffuf"
  | "exposure"
  | "evidence"
  | "nuclei"
  | "vulnerability"
  | "impact" | `endpoint:${string}` | `finding:${string}` | `source:${string}` | `host:${string}` | `cluster:${string}`;

export type AttackGraphNodeStatus = "pending" | "active" | "evidence" | "confirmed";
export type AttackGraphFilter = "all" | "recon" | "exposure" | "vulnerability" | "evidence" | "critical-high";

export interface AttackGraphNode {
  id: AttackGraphNodeId;
  label: string;
  shortLabel: string;
  type: AttackGraphFilter;
  metric: string;
  status: AttackGraphNodeStatus;
  severity: SignalSeverity;
  evidenceCount: number;
  signalIds: string[];
  actionHint: string;
  x: number;
  y: number;
  size: number;
  icon: LucideIcon;
  source?: string;
  cluster?: { source: string; count: number; expanded: boolean; kind: "urls" | "findings" };
}

export interface AttackGraphEdge {
  id: string;
  from: AttackGraphNodeId;
  to: AttackGraphNodeId;
  hot: boolean;
  kind?: "workflow" | "match";
}

export interface AttackGraphModel {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  omitted?: number;
  grouped?: number;
}

const severityRank: Record<SignalSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
};

function activeStageText(runState: RunStateSnapshot): string {
  if (runState.runState !== "running") return "";
  const running = runState.stages.find((stage) => stage.status.toLowerCase() === "running");
  return `${runState.currentStage} ${running?.name || ""} ${running?.label || ""}`.toLowerCase();
}

function highestSeverity(signals: OperatorSignal[]): SignalSeverity {
  return signals.reduce<SignalSeverity>((highest, signal) => (
    severityRank[signal.severity] < severityRank[highest] ? signal.severity : highest
  ), "info");
}

function statusFromSignals(signals: OperatorSignal[], active: boolean): AttackGraphNodeStatus {
  if (signals.some((signal) => signal.verified)) return "confirmed";
  if (signals.length) return "evidence";
  return active ? "active" : "pending";
}

function ids(signals: OperatorSignal[]): string[] {
  return signals.map((signal) => signal.id);
}

function nodeSize(count: number): number {
  return Math.max(40, Math.min(62, 42 + count * 5));
}

function graphNode(
  spec: Omit<AttackGraphNode, "severity" | "status" | "evidenceCount" | "signalIds" | "size"> & {
    signals: OperatorSignal[];
    active?: boolean;
    fallbackStatus?: AttackGraphNodeStatus;
  }
): AttackGraphNode {
  const status = spec.fallbackStatus ?? statusFromSignals(spec.signals, Boolean(spec.active));
  return {
    id: spec.id,
    label: spec.label,
    shortLabel: spec.shortLabel,
    type: spec.type,
    metric: spec.metric,
    actionHint: spec.actionHint,
    x: spec.x,
    y: spec.y,
    icon: spec.icon,
    status,
    severity: highestSeverity(spec.signals),
    evidenceCount: spec.signals.length,
    signalIds: ids(spec.signals),
    size: nodeSize(spec.signals.length)
  };
}

export function buildAttackGraphModel(runState: RunStateSnapshot, model: OperatorModel): AttackGraphModel {
  const signals = model.signals;
  const stageText = activeStageText(runState);
  const bySource = (source: OperatorSignal["source"]): OperatorSignal[] => signals.filter((signal) => signal.source === source);
  const byType = (type: OperatorSignal["type"]): OperatorSignal[] => signals.filter((signal) => signal.type === type);
  const byNode = (nodeId: string): OperatorSignal[] => signals.filter((signal) => signal.nodeIds.includes(nodeId as never));
  const exposureSignals = Array.from(new Map([...byNode("exposure"), ...byType("exposure")].map((signal) => [signal.id, signal])).values());
  const vulnerabilitySignals = Array.from(new Map([...bySource("nuclei"), ...byType("vulnerability")].map((signal) => [signal.id, signal])).values());
  const evidenceSignals = Array.from(new Map([...bySource("screenshots"), ...byType("evidence")].map((signal) => [signal.id, signal])).values());
  const reconSignals = Array.from(new Map([...bySource("katana"), ...bySource("web_checks")].map((signal) => [signal.id, signal])).values());
  const targetStatus: AttackGraphNodeStatus = runState.target || runState.currentRunDir ? "evidence" : runState.runState === "running" ? "active" : "pending";
  const impactSignals = signals.filter((signal) => signal.nodeIds.includes("impact"));
  const impactStatus: AttackGraphNodeStatus = runState.risk.score !== null
    ? "evidence"
    : impactSignals.length ? statusFromSignals(impactSignals, false) : "pending";

  const nodes: AttackGraphNode[] = [
    graphNode({
      id: "target",
      label: "Target",
      shortLabel: "Target",
      type: "all",
      metric: runState.target || "no run",
      signals: [],
      fallbackStatus: targetStatus,
      actionHint: runState.currentRunDir ? "Recorded target scope; this does not prove initial access." : "Start a scan to populate the attack graph.",
      x: 11,
      y: 53,
      icon: Target
    }),
    graphNode({
      id: "recon",
      label: "Recon",
      shortLabel: "Recon",
      type: "recon",
      metric: `${runState.stages.filter((stage) => /nmap|subfinder|dnsx|httpx/i.test(stage.name)).filter((stage) => stage.status === "done").length} tools`,
      signals: reconSignals,
      active: /nmap|subfinder|dnsx|httpx|recon/i.test(stageText),
      actionHint: "Confirm reachable scope and baseline services.",
      x: 25,
      y: 34,
      icon: ScanSearch
    }),
    graphNode({
      id: "katana",
      label: "Katana Crawl",
      shortLabel: "Katana",
      type: "recon",
      metric: `${runState.metrics.katanaCount} URLs`,
      signals: bySource("katana"),
      active: /katana|crawl|discovery/i.test(stageText),
      actionHint: "Use crawl URLs to scope high-value manual checks.",
      x: 42,
      y: 18,
      icon: Radar
    }),
    graphNode({
      id: "web",
      label: "Web Checks",
      shortLabel: "Web",
      type: "recon",
      metric: `${runState.metrics.checksCount} checks`,
      signals: bySource("web_checks"),
      active: /checks|whatweb|web/i.test(stageText),
      actionHint: "Review login, docs, captcha and rate-limit context.",
      x: 43,
      y: 43,
      icon: Globe
    }),
    graphNode({
      id: "gobuster",
      label: "Gobuster",
      shortLabel: "Gobuster",
      type: "exposure",
      metric: `${runState.metrics.gobusterHits} hits`,
      signals: bySource("gobuster"),
      active: /gobuster/i.test(stageText),
      actionHint: "Review status codes and sensitive path names.",
      x: 38,
      y: 66,
      icon: Search
    }),
    graphNode({
      id: "ffuf",
      label: "FFUF",
      shortLabel: "FFUF",
      type: "exposure",
      metric: `${runState.metrics.ffufHits} hits`,
      signals: bySource("ffuf"),
      active: /ffuf/i.test(stageText),
      actionHint: "Correlate fuzz hits with auth and backup naming.",
      x: 25,
      y: 76,
      icon: Bug
    }),
    graphNode({
      id: "exposure",
      label: "Exposure Surface",
      shortLabel: "Exposure",
      type: "exposure",
      metric: `${exposureSignals.length} signals`,
      signals: exposureSignals,
      actionHint: "Validate sensitive paths before exploit attempts.",
      x: 59,
      y: 55,
      icon: FileWarning
    }),
    graphNode({
      id: "evidence",
      label: "Evidence",
      shortLabel: "Evidence",
      type: "evidence",
      metric: `${runState.metrics.screenshotsCount} screenshots`,
      signals: evidenceSignals,
      actionHint: "Use visual evidence to confirm operator context.",
      x: 72,
      y: 31,
      icon: Camera
    }),
    graphNode({
      id: "nuclei",
      label: "Nuclei",
      shortLabel: "Nuclei",
      type: "vulnerability",
      metric: `${runState.metrics.nucleiFindings} findings`,
      signals: bySource("nuclei"),
      active: /nuclei|vuln/i.test(stageText),
      actionHint: "Validate high severity templates first.",
      x: 74,
      y: 72,
      icon: ShieldAlert
    }),
    graphNode({
      id: "vulnerability",
      label: "Template matches",
      shortLabel: "Matches",
      type: "vulnerability",
      metric: `${vulnerabilitySignals.length} signals`,
      signals: vulnerabilitySignals,
      actionHint: "Replay strongest evidence and document deterministic proof.",
      x: 86,
      y: 63,
      icon: LockKeyhole
    }),
    graphNode({
      id: "impact",
      label: "Risk context",
      shortLabel: "Risk",
      type: "critical-high",
      metric: runState.risk.score === null ? runState.risk.label : `${runState.risk.score}/100`,
      signals: impactSignals,
      fallbackStatus: impactStatus,
      actionHint: runState.decision.firstAction || model.firstAction,
      x: 90,
      y: 38,
      icon: Crosshair
    })
  ];

  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const edgeSpecs: Array<[AttackGraphNodeId, AttackGraphNodeId]> = [
    ["target", "recon"],
    ["recon", "katana"],
    ["recon", "web"],
    ["recon", "gobuster"],
    ["recon", "ffuf"],
    ["katana", "exposure"],
    ["web", "exposure"],
    ["gobuster", "exposure"],
    ["ffuf", "exposure"],
    ["exposure", "evidence"],
    ["exposure", "nuclei"],
    ["nuclei", "vulnerability"],
    ["evidence", "impact"],
    ["exposure", "impact"],
    ["vulnerability", "impact"]
  ];

  const edges = edgeSpecs.map(([from, to]) => {
    const target = nodeMap.get(to);
    const source = nodeMap.get(from);
    return {
      id: `${from}-${to}`,
      from,
      to,
      kind: "workflow" as const,
      hot: Boolean(
        target && source &&
        source.status !== "pending" &&
        (target.status === "active" || target.status === "evidence" || target.status === "confirmed")
      )
    };
  });

  return { nodes, edges };
}

/** Actual scanner → matched endpoint → finding associations, never inferred exploitation. */
export function buildEvidenceGraphModel(model: OperatorModel, page = 0): AttackGraphModel {
  const all = model.signals.filter(signal => signal.source === "nuclei");
  const matches = all.slice(page * 8, page * 8 + 8);
  const nodes: AttackGraphNode[] = [graphNode({ id: "nuclei", label: "Nuclei", shortLabel: "Nuclei", type: "vulnerability",
    metric: `${all.length} matches`, signals: matches, actionHint: "Scanner matches require independent validation.", x: 14, y: 50, icon: ShieldAlert })];
  const edges: AttackGraphEdge[] = [];
  const endpoints = [...new Set(matches.map(signal => signal.location))];
  endpoints.forEach((location, index) => {
    const linked = matches.filter(signal => signal.location === location);
    const id: AttackGraphNodeId = `endpoint:${location}`;
    let label = location;
    try { const url = new URL(location); label = url.pathname || url.host; } catch { /* Preserve recorded non-URL evidence. */ }
    nodes.push(graphNode({ id, label: location, shortLabel: label, type: "exposure", metric: `${linked.length} matches`, signals: linked,
      actionHint: "This endpoint was recorded by the scanner; exploitability is not implied.", x: 45, y: endpoints.length === 1 ? 50 : 18 + index * 71 / (endpoints.length - 1), icon: Globe }));
    edges.push({ id: `nuclei-${id}`, from: "nuclei", to: id, hot: true, kind: "match" });
  });
  matches.forEach((signal, index) => {
    const id: AttackGraphNodeId = `finding:${signal.id}`;
    nodes.push(graphNode({ id, label: signal.title, shortLabel: signal.title, type: "vulnerability", metric: signal.severity,
      signals: [signal], actionHint: signal.verified ? "Explicit validation evidence is recorded." : "Unconfirmed scanner match; validate the recorded evidence.",
      x: 69, y: matches.length === 1 ? 50 : 18 + index * 71 / (matches.length - 1), icon: ShieldAlert }));
    edges.push({ id: `endpoint-${id}`, from: `endpoint:${signal.location}`, to: id, hot: true, kind: "match" });
  });
  return { nodes, edges };
}

export function filterNode(node: AttackGraphNode, filter: AttackGraphFilter): boolean {
  if (filter === "all") return true;
  if (filter === "critical-high") return node.severity === "critical" || node.severity === "high";
  return node.type === filter;
}

/** Scan associations from recorded artifacts. No inferred exploit/attack edges. */
export function buildScanNetwork(runState: RunStateSnapshot, model: OperatorModel): AttackGraphModel {
  const record = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
  const result = record(runState.currentRunResult);
  const data = record(result.data);
  const nodes = new Map<AttackGraphNodeId, AttackGraphNode>();
  const edges = new Map<string, AttackGraphEdge>();
  const evidence = model.signals.filter(signal => signal.type !== "status");
  let omitted = Math.max(0, (runState.metrics?.nucleiFindings || 0) - evidence.filter(signal => signal.source === "nuclei").length);
  const add = (id: AttackGraphNodeId, label: string, type: AttackGraphFilter, signals: OperatorSignal[] = []) => {
    if (nodes.has(id)) return nodes.get(id)!;
    const node = graphNode({ id, label, shortLabel: label, type, metric: "", signals, x: 50, y: 50, icon: Globe,
      fallbackStatus: signals.some(s => s.verified) ? "confirmed" : "evidence",
      actionHint: "Recorded scan association; this link does not prove exploitation." });
    nodes.set(id, node); return node;
  };
  const link = (from: AttackGraphNodeId, to: AttackGraphNodeId) => {
    const id = JSON.stringify([from, to]); edges.set(id, { id, from, to, hot: false, kind: "match" });
  };
  if (!runState.currentRunDir && !runState.target) return { nodes: [], edges: [] };
  add("target", runState.target || "Target", "all", evidence).metric = `${evidence.length} signals`;
  const sourceType = (source: string): AttackGraphFilter => source === "nuclei" ? "vulnerability" : source === "screenshots" ? "evidence" : ["gobuster", "ffuf"].includes(source) ? "exposure" : "recon";
  const sourceNode = (source: string) => {
    const id: AttackGraphNodeId = `source:${source}`;
    const signals = evidence.filter(s => s.source === source);
    add(id, source, sourceType(source), signals).metric = `${signals.length} signals`;
    link("target", id); return id;
  };
  const endpoint = (raw: unknown, source: string) => {
    if (typeof raw !== "string" || !/^https?:\/\//i.test(raw)) return null;
    const id: AttackGraphNodeId = `endpoint:${raw}`;
    if (!nodes.has(id) && nodes.size >= 650) { omitted++; return null; }
    const related = evidence.filter(s => s.location === raw);
    const node = add(id, raw, sourceType(source), related);
    node.metric = `${related.length} signals`;
    link(sourceNode(source), id); return id;
  };
  // Reserve the display budget for evidence before adding discovery inventories.
  for (const signal of evidence) {
    if (signal.type === "status") continue;
    const source = sourceNode(signal.source);
    const url = endpoint(signal.location, signal.source);
    const id: AttackGraphNodeId = `finding:${signal.id}`;
    if (nodes.size >= 750) { omitted++; continue; }
    const node = add(id, signal.title, signal.type, [signal]);
    node.source = signal.source; node.metric = signal.severity; node.actionHint = signal.actionHint || "Recorded scan association; this link does not prove exploitation.";
    link(url || source, id);
  }
  const katana = record(result.katana);
  for (const url of (Array.isArray(katana.urls) ? katana.urls : Array.isArray(data.katana_urls) ? data.katana_urls : [])) endpoint(url, "katana");
  for (const source of ["gobuster", "ffuf"]) {
    const buckets = record(record(result[source]).results ?? data[`${source}_results`]);
    for (const rows of Object.values(buckets)) if (Array.isArray(rows)) for (const row of rows) endpoint(record(row).url, source);
  }
  const checks = record(result.checks ?? data.checks_results);
  for (const urls of Object.values(record(checks.classified_endpoints))) if (Array.isArray(urls)) for (const url of urls) endpoint(url, "web_checks");
  return { nodes: [...nodes.values()], edges: [...edges.values()], omitted };
}

/** Presentation only: fold inventories and overflow findings without changing recorded data. */
export function buildFindingNetwork(network: AttackGraphModel, expanded: ReadonlySet<AttackGraphNodeId> = new Set(), focused: AttackGraphNodeId | null = null): AttackGraphModel {
  const findings = network.nodes.filter(node => node.id.startsWith("finding:")).sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);
  const shownFindings = new Set(findings.slice(0, 12).map(node => node.id));
  if (focused?.startsWith("finding:")) shownFindings.add(focused);
  const overflow = new Map<string, AttackGraphNode[]>();
  for (const node of findings) if (!shownFindings.has(node.id)) {
    const source = node.source || "findings";
    overflow.set(source, [...(overflow.get(source) || []), node]);
  }
  const findingClusters: AttackGraphNode[] = [];
  for (const [source, members] of overflow) {
    const hub = network.nodes.find(node => node.id === `source:${source}`);
    if (!hub) { for (const node of members) shownFindings.add(node.id); continue; }
    const id: AttackGraphNodeId = `cluster:findings:${source}`;
    const open = expanded.has(id);
    if (open) for (const node of members) shownFindings.add(node.id);
    findingClusters.push({ ...hub, id, label: `${source}: ${members.length} more findings`, shortLabel: `${members.length} more findings`,
      metric: `${members.length} findings`, severity: members[0].severity, status: "evidence",
      signalIds: members.flatMap(node => node.signalIds), evidenceCount: members.length,
      actionHint: "Additional findings grouped by source. Expand to inspect each finding.",
      cluster: { source, count: members.length, expanded: open, kind: "findings" } });
  }
  const findingLinks = network.edges.filter(edge => edge.to.startsWith("finding:"));
  const evidenceEndpoints = new Set(findingLinks.map(edge => edge.from));
  const shownEndpoints = new Set(findingLinks.filter(edge => shownFindings.has(edge.to)).map(edge => edge.from));
  const discovery = new Map(network.nodes.filter(node => node.id.startsWith("endpoint:") && !evidenceEndpoints.has(node.id)).map(node => [node.id, node]));
  const nodes = network.nodes.filter(node => node.id.startsWith("finding:") ? shownFindings.has(node.id) : node.id.startsWith("endpoint:") ? shownEndpoints.has(node.id) : true);
  const kept = new Set(nodes.map(node => node.id));
  const edges = network.edges.filter(edge => kept.has(edge.from) && kept.has(edge.to));
  for (const cluster of findingClusters) {
    nodes.push(cluster);
    const from: AttackGraphNodeId = `source:${cluster.cluster!.source}`;
    edges.push({ id: JSON.stringify([from, cluster.id]), from, to: cluster.id, hot: false, kind: "match" });
  }
  const visible = new Set<AttackGraphNodeId>();
  for (const source of network.nodes.filter(node => node.id.startsWith("source:"))) {
    const members = new Set(network.edges.filter(edge => edge.from === source.id && discovery.has(edge.to)).map(edge => edge.to));
    if (!members.size) continue;
    const id: AttackGraphNodeId = `cluster:${source.id.slice(7)}`;
    const open = expanded.has(id);
    nodes.push({ ...source, id, label: `${source.label}: ${members.size} discovery URLs`, shortLabel: `${members.size} discovery URLs`,
      metric: `${members.size} URLs`, severity: "info", status: "evidence", signalIds: [], evidenceCount: 0,
      actionHint: "Discovery URLs without linked findings. Expand to inspect recorded addresses.",
      cluster: { source: source.label, count: members.size, expanded: open, kind: "urls" } });
    edges.push({ id: JSON.stringify([source.id, id]), from: source.id, to: id, hot: false, kind: "match" });
    if (open) for (const member of members) {
      if (!visible.has(member)) { nodes.push(discovery.get(member)!); visible.add(member); }
      edges.push({ id: JSON.stringify([id, member]), from: id, to: member, hot: false, kind: "match" });
    }
  }
  return { nodes, edges, omitted: network.omitted, grouped: discovery.size - visible.size };
}
