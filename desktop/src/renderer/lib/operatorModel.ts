import {
  AlertTriangle,
  Bug,
  Camera,
  Crosshair,
  FileWarning,
  Globe,
  LockKeyhole,
  Radar,
  Search,
  ShieldAlert,
  Target
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { LiveFinding, RunStateSnapshot } from "../../shared/api";

export type SignalSeverity = "critical" | "high" | "medium" | "low" | "info";
export type SignalType = "vulnerability" | "exposure" | "recon" | "evidence" | "status";
export type SignalSource = "nuclei" | "gobuster" | "ffuf" | "web_checks" | "katana" | "screenshots" | "report" | "engine";
export type ChainNodeId = "initial" | "discovery" | "enumeration" | "exposure" | "validation" | "impact";
export type ChainNodeStatus = "pending" | "active" | "evidence" | "confirmed" | "blocked";

export interface OperatorSignal {
  id: string;
  title: string;
  description: string;
  severity: SignalSeverity;
  type: SignalType;
  source: SignalSource;
  location: string;
  tags: string[];
  timestamp: string;
  score?: number;
  confidence?: number;
  verified?: boolean;
  actionHint?: string;
  nodeIds: ChainNodeId[];
  icon: LucideIcon;
}

export interface AttackChainNode {
  id: ChainNodeId;
  label: string;
  status: ChainNodeStatus;
  severity: SignalSeverity;
  metric: string;
  evidenceCount: number;
  signalIds: string[];
  explanation: string;
  actionHint: string;
  icon: LucideIcon;
}

export interface OperatorModel {
  signals: OperatorSignal[];
  attackChain: AttackChainNode[];
  topSignal: OperatorSignal | null;
  firstAction: string;
  strongestPath: string;
}

const severityRank: Record<SignalSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
};

function normalizeSeverity(value: string | undefined): SignalSeverity {
  const normalized = (value || "").toLowerCase();
  if (normalized.includes("critical")) return "critical";
  if (normalized.includes("high")) return "high";
  if (normalized.includes("medium") || normalized.includes("elevated")) return "medium";
  if (normalized.includes("low")) return "low";
  return "info";
}

export function severityTone(value: string): SignalSeverity {
  return normalizeSeverity(value);
}

function signalPriority(signal: OperatorSignal): number {
  const statusPenalty = signal.type === "status" ? 20 : 0;
  const evidenceBonus = signal.type === "vulnerability" ? -2 : signal.type === "exposure" ? -1 : 0;
  return (severityRank[signal.severity] ?? 9) * 10 + statusPenalty + evidenceBonus;
}

function signalId(prefix: string, value: string): string {
  return `${prefix}-${encodeURIComponent(value)}`;
}

function fromNuclei(finding: LiveFinding): OperatorSignal {
  const severity = normalizeSeverity(finding.severity);
  return {
    id: signalId("nuclei", JSON.stringify([finding.templateId, finding.matchedAt])),
    title: finding.name || finding.templateId || "Nuclei finding",
    description: "Security template evidence requires operator validation.",
    severity,
    type: "vulnerability",
    source: "nuclei",
    location: finding.matchedAt || finding.templateId || "nuclei",
    tags: ["nuclei", finding.templateId || "template", severity].filter(Boolean),
    timestamp: "live",
    verified: finding.verificationState === "verified" && Boolean(finding.validationEvidence && (typeof finding.validationEvidence !== "object" || Object.keys(finding.validationEvidence).length)),
    actionHint: "Validate exploitability and affected endpoint scope.",
    nodeIds: ["validation", "impact"],
    icon: ShieldAlert
  };
}

export function buildOperatorSignals(runState: RunStateSnapshot): OperatorSignal[] {
  const signals: OperatorSignal[] = runState.findings.map(fromNuclei);

  if (runState.metrics.gobusterHits > 0) {
    signals.push({
      id: "gobuster-content-hits",
      title: "Gobuster content exposure signals",
      description: "Directory brute force produced paths that may expose application surface.",
      severity: runState.metrics.gobusterHits > 20 ? "high" : "medium",
      type: "exposure",
      source: "gobuster",
      location: `${runState.metrics.gobusterHits} discovered paths`,
      tags: ["content", "paths", "enumeration"],
      timestamp: runState.updatedAt || "live",
      actionHint: "Review status codes and sensitive filenames first.",
      nodeIds: ["enumeration", "exposure"],
      icon: Search
    });
  }

  if (runState.metrics.ffufHits > 0) {
    signals.push({
      id: "ffuf-fuzz-hits",
      title: "FFUF fuzzing hits require review",
      description: "Fuzzing produced candidate endpoints or files for validation.",
      severity: runState.metrics.ffufHits > 20 ? "high" : "medium",
      type: "exposure",
      source: "ffuf",
      location: `${runState.metrics.ffufHits} fuzz hits`,
      tags: ["fuzzing", "paths", "enumeration"],
      timestamp: runState.updatedAt || "live",
      actionHint: "Prioritize auth, backup, config and admin-looking paths.",
      nodeIds: ["enumeration", "exposure"],
      icon: Bug
    });
  }

  if (runState.metrics.checksLogin > 0) {
    signals.push({
      id: "web-checks-login-surface",
      title: "Login/auth surface observed",
      description: "Web checks identified authentication surface that may affect exposure and validation scope.",
      severity: "medium",
      type: "exposure",
      source: "web_checks",
      location: `${runState.metrics.checksLogin} login/auth signal${runState.metrics.checksLogin === 1 ? "" : "s"}`,
      tags: ["auth", "login", "surface"],
      timestamp: runState.updatedAt || "live",
      actionHint: "Inspect auth behavior and access-control assumptions.",
      nodeIds: ["exposure"],
      icon: LockKeyhole
    });
  }

  if (runState.metrics.checksDocs > 0) {
    signals.push({
      id: "web-checks-docs-surface",
      title: "Public docs/resource surface observed",
      description: "Web checks identified documentation or resource endpoints useful for reconnaissance.",
      severity: "info",
      type: "recon",
      source: "web_checks",
      location: `${runState.metrics.checksDocs} docs/resource signal${runState.metrics.checksDocs === 1 ? "" : "s"}`,
      tags: ["docs", "metadata", "surface"],
      timestamp: runState.updatedAt || "live",
      actionHint: "Review docs for API, admin or version disclosure.",
      nodeIds: ["discovery", "exposure"],
      icon: Globe
    });
  }

  if (runState.metrics.checksCaptcha > 0 || runState.metrics.checksRatelimit > 0) {
    signals.push({
      id: "web-checks-control-signal",
      title: "Web control signal observed",
      description: "Captcha or rate-limit behavior can affect safe validation and traffic profile choices.",
      severity: "low",
      type: "evidence",
      source: "web_checks",
      location: `${runState.metrics.checksCaptcha} captcha / ${runState.metrics.checksRatelimit} rate-limit`,
      tags: ["control", "traffic", "validation"],
      timestamp: runState.updatedAt || "live",
      actionHint: "Use a safer profile if controls start throttling the scan.",
      nodeIds: ["validation"],
      icon: AlertTriangle
    });
  }

  if (runState.metrics.katanaCount > 0) {
    signals.push({
      id: "katana-crawl-surface",
      title: "Crawl surface discovered",
      description: "Crawler found URLs that shape the reachable attack surface.",
      severity: "info",
      type: "recon",
      source: "katana",
      location: `${runState.metrics.katanaCount} Katana URLs`,
      tags: ["crawl", "surface", "recon"],
      timestamp: runState.updatedAt || "live",
      actionHint: "Use crawl surface to scope manual validation.",
      nodeIds: ["discovery"],
      icon: Radar
    });
  }

  if (runState.metrics.screenshotsCount > 0) {
    signals.push({
      id: "screenshot-evidence",
      title: "Screenshot evidence available",
      description: "Visual evidence was captured for reachable web surfaces.",
      severity: "info",
      type: "evidence",
      source: "screenshots",
      location: `${runState.metrics.screenshotsCount} screenshots`,
      tags: ["visual", "evidence"],
      timestamp: runState.updatedAt || "live",
      actionHint: "Use screenshots to confirm UI context before exploitation.",
      nodeIds: ["exposure", "impact"],
      icon: Camera
    });
  }

  const unique = new Map<string, OperatorSignal>();
  for (const signal of signals) {
    if (!unique.has(signal.id)) unique.set(signal.id, signal);
  }

  return Array.from(unique.values()).sort((a, b) => {
    const priorityDelta = signalPriority(a) - signalPriority(b);
    if (priorityDelta !== 0) return priorityDelta;
    return a.title.localeCompare(b.title);
  });
}

function highestSeverity(signals: OperatorSignal[]): SignalSeverity {
  return signals.reduce<SignalSeverity>((highest, signal) => (
    severityRank[signal.severity] < severityRank[highest] ? signal.severity : highest
  ), "info");
}

function nodeStatus(id: ChainNodeId, signals: OperatorSignal[], activeStage: string, riskLabel: string): ChainNodeStatus {
  if (id === "initial") return signals.length || activeStage || riskLabel !== "pending" ? "evidence" : "pending";
  if (id === "discovery" && /katana|discover|crawl/i.test(activeStage)) return "active";
  if (id === "enumeration" && /gobuster|ffuf|enum/i.test(activeStage)) return "active";
  if (id === "validation" && /nuclei|vuln/i.test(activeStage)) return "active";
  const linked = signals.filter((signal) => signal.nodeIds.includes(id));
  if (linked.some((signal) => signal.verified)) return "confirmed";
  if (linked.length) return "evidence";
  return "pending";
}

export function buildAttackChain(runState: RunStateSnapshot, signals: OperatorSignal[]): AttackChainNode[] {
  const activeStage = runState.runState === "running" ? `${runState.currentStage} ${runState.stages.find((stage) => stage.status.toLowerCase() === "running")?.name || ""}` : "";
  const riskLabel = (runState.risk?.label || "pending").toLowerCase();
  const nodeSpecs: Array<{
    id: ChainNodeId;
    label: string;
    metric: string;
    explanation: string;
    actionHint: string;
    icon: LucideIcon;
  }> = [
    {
      id: "initial",
      label: "Target scope",
      metric: runState.target || "target pending",
      explanation: "Target context and initial reachable surface.",
      actionHint: "Confirm target scope and profile before deeper validation.",
      icon: Target
    },
    {
      id: "discovery",
      label: "Discovery",
      metric: `${runState.metrics.katanaCount} URLs`,
      explanation: "Crawler and metadata signals define reachable application surface.",
      actionHint: "Review crawl clusters and metadata endpoints.",
      icon: Radar
    },
    {
      id: "enumeration",
      label: "Enumeration",
      metric: `${runState.metrics.gobusterHits + runState.metrics.ffufHits} hits`,
      explanation: "Directory and fuzzing results reveal content and hidden paths.",
      actionHint: "Prioritize sensitive names, unusual status codes and auth paths.",
      icon: Search
    },
    {
      id: "exposure",
      label: "Exposure",
      metric: `${signals.filter((signal) => signal.nodeIds.includes("exposure")).length} signals`,
      explanation: "Exposure signals indicate admin, config, auth or file surfaces.",
      actionHint: "Validate sensitive paths before exploit testing.",
      icon: FileWarning
    },
    {
      id: "validation",
      label: "Vulnerability Validation",
      metric: `${runState.metrics.nucleiFindings} nuclei`,
      explanation: "Template and manual evidence confirm likely vulnerability paths.",
      actionHint: "Replay the strongest evidence and record deterministic proof.",
      icon: ShieldAlert
    },
    {
      id: "impact",
      label: "Risk context",
      metric: runState.risk?.score === null ? riskLabel : `${runState.risk?.score}/100`,
      explanation: "Decision and report context summarize likely operational impact.",
      actionHint: runState.decision?.firstAction || "Use the report to select the highest confidence action.",
      icon: Crosshair
    }
  ];

  return nodeSpecs.map((spec) => {
    const linked = signals.filter((signal) => signal.nodeIds.includes(spec.id));
    return {
      ...spec,
      status: nodeStatus(spec.id, signals, activeStage, riskLabel),
      severity: highestSeverity(linked),
      evidenceCount: linked.length,
      signalIds: linked.map((signal) => signal.id)
    };
  });
}

export function buildOperatorModel(runState: RunStateSnapshot): OperatorModel {
  const signals = buildOperatorSignals(runState);
  const attackChain = buildAttackChain(runState, signals);
  const topSignal = signals.find((signal) => signal.type !== "status") ?? signals[0] ?? null;
  return {
    signals,
    attackChain,
    topSignal,
    firstAction: runState.decision?.firstAction || topSignal?.actionHint || "Start scan and monitor stage transitions.",
    strongestPath: runState.decision?.strongestPath || attackChain.filter((node) => node.status !== "pending").map((node) => node.label).join(" → ")
  };
}

export function tagsForSignal(signal: OperatorSignal): string[] {
  const tags = [signal.source, signal.type, ...signal.tags];
  return Array.from(new Set(tags.filter(Boolean))).slice(0, 4);
}
