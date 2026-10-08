import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";
import type {
  DecisionSnapshot,
  IpEnrichmentState,
  LiveFinding,
  ReportState,
  RiskState,
  RunArtifactSnapshot,
  RunCompleteness,
  RunLifecycleState,
  RunStateSnapshot,
  StageRow
} from "../shared/api";
import { TOOL_ORDER } from "./configDefaults";

function readJson(filePath: string): Record<string, unknown> {
  try {
    if (!fs.existsSync(filePath)) return {};
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function readStructuredFile(filePath: string): Record<string, unknown> {
  try {
    if (!fs.existsSync(filePath)) return {};
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = filePath.endsWith(".json") ? JSON.parse(raw) : yaml.load(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function asNumber(value: unknown): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function asRiskNumber(value: unknown): number | null {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return null;
  if (parsed < 0 || parsed > 100) return null;
  return Math.round(parsed);
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function firstPresent(...values: unknown[]): unknown {
  return values.find((value) => value !== undefined && value !== null && value !== "" && (!Array.isArray(value) || value.length > 0));
}

function nestedValue(source: Record<string, unknown>, keys: string[]): unknown {
  let current: unknown = source;
  for (const key of keys) {
    const record = asRecord(current);
    if (!Object.prototype.hasOwnProperty.call(record, key)) return undefined;
    current = record[key];
  }
  return current;
}

function labelFromScore(score: number): string {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "elevated";
  return "low";
}

function normalizeRiskLabel(value: string): string {
  const label = value.trim().toLowerCase();
  if (!label) return "";
  if (["critical", "crit"].includes(label)) return "critical";
  if (["high", "elevated"].includes(label)) return label;
  if (["medium", "moderate"].includes(label)) return "elevated";
  if (["low", "info", "informational"].includes(label)) return "low";
  if (["pending", "monitoring"].includes(label)) return label;
  return label;
}

function riskScoreFromReportHtml(reportPath: string): number | null {
  try {
    if (!reportPath || !fs.existsSync(reportPath)) return null;
    const html = fs.readFileSync(reportPath, "utf8");
    const overviewMatch = html.match(/<div class="label">\s*Risk Skoru\s*<\/div>\s*<div class="value">\s*(\d{1,3})\s*\/\s*100\s*<\/div>/i);
    const pillMatch = html.match(/Risk\s+(\d{1,3})\s*\/\s*100/i);
    return asRiskNumber(overviewMatch?.[1] ?? pillMatch?.[1]);
  } catch {
    return null;
  }
}

function riskState(runResult: Record<string, unknown>, reportPath: string): RiskState {
  const scoreCandidates: Array<{ keys: string[]; source: string }> = [
    { keys: ["report", "risk_score"], source: "run_result.report.risk_score" },
    { keys: ["report", "overview", "risk_score"], source: "run_result.report.overview.risk_score" },
    { keys: ["report", "summary", "risk_score"], source: "run_result.report.summary.risk_score" },
    { keys: ["decision", "risk_score"], source: "run_result.decision.risk_score" },
    { keys: ["decision", "score"], source: "run_result.decision.score" },
    { keys: ["summary", "risk_score"], source: "run_result.summary.risk_score" },
    { keys: ["risk_score"], source: "run_result.risk_score" },
    { keys: ["risk", "score"], source: "run_result.risk.score" }
  ];

  for (const candidate of scoreCandidates) {
    const score = asRiskNumber(nestedValue(runResult, candidate.keys));
    if (score !== null) {
      return {
        score,
        label: labelFromScore(score),
        source: candidate.source
      };
    }
  }

  const reportScore = riskScoreFromReportHtml(reportPath);
  if (reportScore !== null) {
    return {
      score: reportScore,
      label: labelFromScore(reportScore),
      source: "report.html risk overview"
    };
  }

  const traffic = asRecord(runResult.traffic);
  const risk = asRecord(runResult.risk);
  const label = normalizeRiskLabel(
    asString(traffic.risk_level ?? risk.level ?? runResult.risk_level ?? runResult.risk, "")
  );
  if (label) {
    return {
      score: null,
      label,
      source: label === "pending" || label === "monitoring" ? "pending" : "run_result risk label"
    };
  }

  return {
    score: null,
    label: runResult && Object.keys(runResult).length ? "monitoring" : "pending",
    source: "pending"
  };
}

function stringifyPath(value: unknown): string {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    return value
      .map((item) => {
        if (typeof item === "string") return item;
        const record = asRecord(item);
        return asString(record.label ?? record.name ?? record.title ?? record.id, "");
      })
      .filter(Boolean)
      .join(" → ");
  }
  const record = asRecord(value);
  return asString(record.label ?? record.name ?? record.title ?? record.path ?? record.description, "");
}

function decisionSnapshot(runResult: Record<string, unknown>): DecisionSnapshot {
  const decision = asRecord(runResult.decision);
  const overview = asRecord(runResult.overview);
  const topChain = asRecord(runResult.top_chain);
  const strongest = asRecord(runResult.strongest_path);
  const attack = asRecord(runResult.attack_graph);
  const summary = asString(
    overview.summary ??
      overview.operator_summary ??
      decision.summary ??
      decision.operator_summary ??
      topChain.summary ??
      strongest.summary,
    ""
  );
  const firstAction = asString(
    overview.first_action ??
      overview.recommended_action ??
      decision.first_action ??
      decision.recommended_action ??
      topChain.first_action ??
      strongest.first_action,
    ""
  );
  const strongestPath = stringifyPath(
    overview.strongest_path ??
      decision.strongest_path ??
      topChain.path ??
      topChain.nodes ??
      strongest.path ??
      strongest.nodes ??
      attack.strongest_path
  );

  return {
    summary,
    firstAction,
    strongestPath,
    source: summary || firstAction || strongestPath ? "run_result decision/overview" : "derived"
  };
}

function tailLines(filePath: string, limit: number): string[] {
  try {
    if (!fs.existsSync(filePath)) return [];
    return fs.readFileSync(filePath, "utf8").split(/\r?\n/).filter(Boolean).slice(-limit);
  } catch {
    return [];
  }
}

function safeDirectoryFiles(runDir: string): string[] {
  try {
    if (!runDir || !fs.statSync(runDir).isDirectory()) return [];
    return fs.readdirSync(runDir, { withFileTypes: true })
      .filter((entry) => entry.isFile())
      .map((entry) => entry.name)
      .sort((left, right) => left.localeCompare(right));
  } catch {
    return [];
  }
}

const CONFIG_OR_REQUEST_NAMES = [
  "app_config.yaml",
  "app_config.yml",
  "config.yaml",
  "config.yml",
  "request.json",
  "request.yaml",
  "request.yml",
  "scan_request.json"
];

function firstExistingFile(runDir: string, names: string[]): string {
  if (!runDir) return "";
  for (const name of names) {
    const candidate = path.join(runDir, name);
    try {
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // A partially written or concurrently removed file remains unavailable.
    }
  }
  return "";
}

function artifactSnapshot(runDir: string, reportPath: string): RunArtifactSnapshot {
  let runDirExists = false;
  try {
    runDirExists = Boolean(runDir && fs.statSync(runDir).isDirectory());
  } catch {
    runDirExists = false;
  }
  const rawLog = runDir ? path.join(runDir, "reconbot.log") : "";
  const stateJson = runDir ? path.join(runDir, "run_result.json") : "";
  const stagesJson = runDir ? path.join(runDir, "stages_live.json") : "";
  const configOrRequest = firstExistingFile(runDir, CONFIG_OR_REQUEST_NAMES);
  const availableFiles = runDirExists ? safeDirectoryFiles(runDir) : [];
  const exists = {
    runDir: runDirExists,
    rawLog: Boolean(rawLog && fs.existsSync(rawLog)),
    stateJson: Boolean(stateJson && fs.existsSync(stateJson)),
    stagesJson: Boolean(stagesJson && fs.existsSync(stagesJson)),
    configOrRequest: Boolean(configOrRequest),
    report: Boolean(reportPath && fs.existsSync(reportPath))
  };
  const expected: Array<[string, boolean]> = [
    ["reconbot.log", exists.rawLog],
    ["run_result.json", exists.stateJson],
    ["stages_live.json", exists.stagesJson],
    ["report.html", exists.report]
  ];
  return {
    availableCount: availableFiles.length,
    availableFiles,
    missingExpected: expected.filter(([, present]) => !present).map(([name]) => name),
    paths: {
      runDir,
      rawLog,
      stateJson,
      stagesJson,
      configOrRequest,
      report: reportPath
    },
    exists
  };
}

function targetFromLog(logLines: string[]): string {
  for (const line of logLines) {
    const initialized = line.match(/\bRun initialized:\s*target=(.+?)\s+output=/i);
    if (initialized?.[1]?.trim()) return initialized[1].trim();
    const targetMarker = line.match(/\bTarget\s*\([^)]*\):\s*(.+?)\s*$/i);
    if (targetMarker?.[1]?.trim()) return targetMarker[1].trim();
  }
  return "";
}

function targetFromStructuredArtifact(runDir: string): string {
  const configPath = firstExistingFile(runDir, CONFIG_OR_REQUEST_NAMES);
  if (!configPath) return "";
  const source = readStructuredFile(configPath);
  const meta = asRecord(source.meta);
  const request = asRecord(source.request);
  const scan = asRecord(source.scan);
  const reconbot = asRecord(source.reconbot);
  return asString(firstPresent(source.target, meta.target, request.target, scan.target, reconbot.target), "");
}

function normalizeLifecycleState(value: unknown): RunLifecycleState | "" {
  const state = asString(value, "").trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (!state) return "";
  if (["idle"].includes(state)) return "idle";
  if (["queued", "pending", "preparing"].includes(state)) return "queued";
  if (["running", "active", "in_progress"].includes(state)) return "running";
  if (["interrupted", "stopped", "cancelled", "canceled", "aborted"].includes(state)) return "interrupted";
  if (["completed", "complete", "done", "finished", "success", "succeeded"].includes(state)) return "completed";
  if (["failed", "failure", "error", "errored"].includes(state)) return "failed";
  if (["incomplete", "partial"].includes(state)) return "incomplete";
  if (["unknown"].includes(state)) return "unknown";
  return "";
}

function inferLifecycleState(
  runDir: string,
  runResult: Record<string, unknown>,
  stages: StageRow[],
  reportExists: boolean,
  processAttached: boolean,
  logLines: string[]
): RunLifecycleState {
  if (!runDir) return "idle";
  const meta = asRecord(runResult.meta);
  const explicit = normalizeLifecycleState(firstPresent(
    runResult.run_state,
    runResult.runState,
    runResult.lifecycle_state,
    runResult.status,
    meta.run_state,
    meta.status
  ));
  if (explicit && explicit !== "completed") return explicit;
  if (explicit === "completed") {
    return stages.some((stage) => ["error", "failed", "partial", "interrupted", "running", "pending"].includes(stage.status)) ? "incomplete" : explicit;
  }

  const combinedLog = logLines.join("\n");
  if (/\b(interrupted|cancelled|canceled|aborted|stop requested|terminated by operator)\b/i.test(combinedLog)) return "interrupted";
  if (/\b(run failed|fatal error|report generation failed|traceback)\b/i.test(combinedLog)) return "failed";
  if (processAttached && stages.some((stage) => stage.status === "running")) return "running";
  if (stages.some((stage) => ["error", "failed", "partial", "interrupted"].includes(stage.status))) return "incomplete";
  if (stages.some((stage) => ["running", "pending"].includes(stage.status))) return "incomplete";
  if (reportExists) return "completed";
  if (Object.keys(runResult).length || logLines.length || stages.some((stage) => stage.status !== "pending")) return "incomplete";
  return "unknown";
}

function inferReportStatus(
  runDir: string,
  reportExists: boolean,
  lifecycle: RunLifecycleState,
  stages: StageRow[],
  artifacts: RunArtifactSnapshot,
  logLines: string[]
): Pick<ReportState, "status" | "failureReason"> {
  if (reportExists) return { status: "ready", failureReason: "" };
  if (!runDir || !artifacts.exists.runDir) return { status: "missing", failureReason: "" };
  const reportStage = stages.find((stage) => stage.name === "report");
  const combinedLog = logLines.join("\n");
  if (reportStage?.status === "error" || /\breport (generation )?failed\b/i.test(combinedLog)) {
    return { status: "failed", failureReason: "report generation failed" };
  }
  if (lifecycle === "failed" && artifacts.exists.stateJson) {
    return { status: "failed", failureReason: "run failed before report generation completed" };
  }
  if (artifacts.availableCount > 0) return { status: "pending", failureReason: "" };
  return { status: "missing", failureReason: "" };
}

function inferCompleteness(artifacts: RunArtifactSnapshot, reportStatus: ReportState["status"]): RunCompleteness {
  if (!artifacts.exists.runDir || artifacts.availableCount === 0) return "empty";
  if (reportStatus === "ready") return "report_ready";
  if (reportStatus === "pending" && (artifacts.exists.stateJson || artifacts.exists.stagesJson)) return "report_pending";
  return "partial";
}

function isWithin(parent: string, candidate: string): boolean {
  const relative = path.relative(parent, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function skippedTools(runResult: Record<string, unknown>): Set<string> {
  const skipped = new Set<string>();
  const meta = asRecord(runResult.meta);
  for (const source of [runResult.skipped_tools, meta.skipped_tools]) {
    if (Array.isArray(source)) {
      for (const item of source) {
        if (typeof item === "string" && item.trim()) skipped.add(item.trim());
      }
    }
  }
  return skipped;
}

function metricFor(name: string, summary: Record<string, unknown>, stage: Record<string, unknown>): string {
  if (name === "katana") return `${asNumber(summary.katana_count)} urls`;
  if (name === "gobuster") return `${asNumber(summary.gobuster_total_hits)} hits`;
  if (name === "ffuf") return `${asNumber(summary.ffuf_hits)} hits`;
  if (name === "checks") return `${asNumber(summary.checks_checked)} checked`;
  if (name === "nuclei") return `${asNumber(stage.findings_count ?? summary.nuclei_findings_count)} findings`;
  const artifacts = asRecord(stage.artifacts);
  return Object.keys(artifacts).length ? `${Object.keys(artifacts).length} artifacts` : "ready";
}

function stageRows(runResult: Record<string, unknown>, liveStages: Record<string, unknown>): StageRow[] {
  const summary = asRecord(runResult.summary);
  const resultStages = asRecord(runResult.stages);
  const skipped = skippedTools(runResult);
  return TOOL_ORDER.map(([name, label]) => {
    const stage = { ...asRecord(resultStages[name]), ...asRecord(liveStages[name]) };
    const status = asString(stage.status, skipped.has(name) ? "skipped" : "unknown");
    return {
      name,
      label,
      status,
      metric: metricFor(name, summary, stage),
      reason: asString(stage.error ?? stage.reason, status === "skipped" ? "disabled or skipped by run config" : status === "unknown" ? "No stage status was recorded." : "")
    };
  });
}

function ipEnrichmentState(runResult: Record<string, unknown>): IpEnrichmentState | undefined {
  const source = asRecord(runResult.ip_enrichment);
  if (!Object.keys(source).length) return undefined;
  const status = asString(source.status, "");
  if (!status) return undefined;
  const normalizedStatus = status as IpEnrichmentState["status"];
  return {
    status: normalizedStatus,
    originalTarget: asString(source.original_target ?? source.originalTarget, ""),
    resolvedIp: asString(source.resolved_ip ?? source.resolvedIp, ""),
    hostname: asString(source.hostname, ""),
    scanMode: asString(source.scan_mode ?? source.scanMode, "") as IpEnrichmentState["scanMode"],
    requestedAt: asString(source.requested_at ?? source.requestedAt, ""),
    startedAt: asString(source.started_at ?? source.startedAt, ""),
    endedAt: asString(source.ended_at ?? source.endedAt, ""),
    note: asString(source.note, ""),
    artifacts: asRecord(source.artifacts) as IpEnrichmentState["artifacts"],
    toolsUsed: Array.isArray(source.tools_used) ? source.tools_used.map((item) => asString(item, "")).filter(Boolean) : [],
    tools_used: Array.isArray(source.tools_used) ? source.tools_used.map((item) => asString(item, "")).filter(Boolean) : [],
    results: asRecord(source.results) as IpEnrichmentState["results"]
  };
}

function osintState(runResult: Record<string, unknown>): RunStateSnapshot["osint"] | undefined {
  const source = asRecord(runResult.osint);
  if (!Object.keys(source).length || source.enabled !== true) return undefined;
  const summary = asRecord(source.summary);
  return {
    enabled: true,
    status: asString(source.status, "unknown"),
    mode: asString(source.mode, "safe_mvp"),
    totalSignals: asNumber(summary.total_signals),
    riskScoreImpact: asString(summary.risk_score_impact, "none")
  };
}

function normalizeFinding(item: unknown): LiveFinding | null {
  const row = asRecord(item);
  if (!Object.keys(row).length) return null;
  const info = asRecord(row.info);
  const templateId = asString(row["template-id"] ?? row.templateID ?? row.template_id ?? row.id, "");
  const name = asString(row.name ?? row.title ?? info.name ?? templateId, "Unknown");
  const matchedAt = asString(row["matched-at"] ?? row.matchedAt ?? row.matched_at ?? row.host ?? row.url, "");
  const rawTags = Array.isArray(info.tags ?? row.tags) ? (info.tags ?? row.tags) as unknown[] : [];
  if (!name && !templateId && !matchedAt) return null;
  const statusCode = firstPresent(row.status_code, row["status-code"], row.http_status, row.httpStatus);
  const redirect = firstPresent(row.redirect, row.redirect_url, row.redirectUrl, row.final_url, row.finalUrl, row.location, row.redirect_chain);
  const fingerprint = firstPresent(row.fingerprint, row.response_fingerprint, row.responseFingerprint, row.technology_fingerprint, row.technologyFingerprint, row.product_fingerprint, row.productFingerprint, row.detected_product);
  const validationEvidence = firstPresent(row.validation_evidence, row.validationEvidence, row.validated_evidence, row.validatedEvidence, row.manual_validation, row.manualValidation, row.proof, row.validation_details);
  const responseEvidencePresent = [row.response, row.request, row.matched_response].some((value) => value !== undefined && value !== null && value !== "");
  return {
    name: name || templateId || "Unknown",
    severity: asString(row.severity ?? info.severity, "unknown"),
    templateId: templateId || "Unknown",
    matchedAt,
    source: asString(row.source ?? row.tool, "nuclei"),
    tags: rawTags.map((tag) => asString(tag, "")).filter(Boolean).slice(0, 8),
    validation: asString(row.validation ?? row.validation_status ?? row.validationState, "operator_validation_required"),
    operatorValidationRequired: row.operator_validation_required === false ? false : true,
    confidence: row.confidence as string | number | undefined,
    verificationState: asString(firstPresent(row.verification_state, row.verificationState, row.validation_state, row.validationState), "unverified"),
    statusCode: typeof statusCode === "string" || typeof statusCode === "number" ? statusCode : undefined,
    redirect,
    fingerprint,
    validationEvidence,
    responseEvidencePresent,
    missingEvidenceFields: Array.isArray(row.missing_evidence_fields)
      ? row.missing_evidence_fields.map((value) => asString(value)).filter(Boolean)
      : undefined,
  };
}

function findingsFromRunResult(runResult: Record<string, unknown>): LiveFinding[] {
  const candidates: unknown[] = [];
  const nuclei = asRecord(runResult.nuclei);
  const dataNuclei = asRecord(asRecord(runResult.data).nuclei_results);
  const rootNuclei = asRecord(runResult.nuclei_results);
  for (const source of [nuclei, dataNuclei, rootNuclei]) {
    for (const key of ["findings", "Findings", "results", "Results", "items", "data", "Data"]) {
      const rows = source[key];
      if (Array.isArray(rows)) candidates.push(...rows);
    }
  }
  if (Array.isArray(runResult.findings)) candidates.push(...runResult.findings);
  return candidates.map(normalizeFinding).filter((finding): finding is LiveFinding => finding !== null);
}

function dedupeFindings(findings: LiveFinding[]): LiveFinding[] {
  const unique = new Map<string, LiveFinding>();
  for (const finding of findings) {
    const key = `${finding.source || "nuclei"}|${finding.templateId}|${finding.matchedAt}`.toLowerCase();
    if (!unique.has(key)) unique.set(key, finding);
  }
  return Array.from(unique.values());
}

function readFindings(runDir: string, runResult: Record<string, unknown>): LiveFinding[] {
  const nuclei = asRecord(runResult.nuclei);
  const toolsNuclei = asRecord(asRecord(runResult.tools).nuclei);
  const artifacts = asRecord(toolsNuclei.artifacts);
  const candidates = [asString(nuclei.output_path), asString(artifacts.output), path.join(runDir, "nuclei_output.jsonl")]
    .filter(Boolean)
    .map((candidate) => path.resolve(candidate))
    .filter((candidate) => isWithin(runDir, candidate));
  const jsonlPath = candidates.find((candidate) => fs.existsSync(candidate));
  const fallback = findingsFromRunResult(runResult);
  if (!jsonlPath) return dedupeFindings(fallback).slice(-100);

  const live = tailLines(jsonlPath, 100)
    .map((line) => {
      try {
        return normalizeFinding(JSON.parse(line) as Record<string, unknown>);
      } catch {
        return null;
      }
    })
    .filter((finding): finding is LiveFinding => finding !== null);
  return dedupeFindings([...live, ...fallback]).slice(-100);
}

function buildRunStateSnapshot(currentRunDir: string, historical = false, processAttached = false): RunStateSnapshot {
  const runResult = currentRunDir ? readJson(path.join(currentRunDir, "run_result.json")) : {};
  const liveStages = currentRunDir ? readJson(path.join(currentRunDir, "stages_live.json")) : {};
  const meta = asRecord(runResult.meta);
  const liveMeta = asRecord(liveStages.meta);
  const liveConfig = asRecord(liveStages.config);
  const summary = asRecord(runResult.summary);
  const traffic = asRecord(runResult.traffic);
  const findings = currentRunDir ? readFindings(currentRunDir, runResult) : [];
  const nucleiStage = asRecord(liveStages.nuclei ?? asRecord(runResult.stages).nuclei);
  const toolsNuclei = asRecord(asRecord(runResult.tools).nuclei);
  const nucleiFindingsCount = Math.max(
    asNumber(summary.nuclei_findings_count),
    asNumber(nucleiStage.findings_count),
    asNumber(toolsNuclei.findings_count),
    findings.length
  );
  const stages = stageRows(
    {
      ...runResult,
      summary: {
        ...summary,
        nuclei_findings_count: nucleiFindingsCount
      }
    },
    liveStages
  );
  const currentStage = processAttached && !historical ? stages.find((stage) => stage.status === "running") : undefined;
  const reportPath = currentRunDir ? path.join(currentRunDir, "report.html") : "";
  const reportExists = Boolean(reportPath && fs.existsSync(reportPath));
  let reportMtime = 0;
  try {
    reportMtime = reportExists ? fs.statSync(reportPath).mtimeMs : 0;
  } catch {
    reportMtime = 0;
  }
  const artifacts = artifactSnapshot(currentRunDir, reportPath);
  const logTail = currentRunDir ? tailLines(artifacts.paths.rawLog, 120) : [];
  const recordedStages = { ...asRecord(runResult.stages), ...liveStages };
  const attached = processAttached && !historical;
  const lifecycle = inferLifecycleState(currentRunDir, runResult, stages.filter((stage) => stage.name in recordedStages), reportExists, attached, logTail);
  const reportStatus = inferReportStatus(currentRunDir, reportExists, lifecycle, stages, artifacts, logTail);
  const target = asString(firstPresent(
    meta.target,
    runResult.target,
    liveMeta.target,
    liveConfig.target,
    targetFromStructuredArtifact(currentRunDir),
    targetFromLog(logTail)
  ), currentRunDir ? "unknown target" : "");

  const effective = currentRunDir ? readJson(path.join(currentRunDir, "effective_config.json")) : {};
  const limits = asRecord(effective.limits);
  const rates = asRecord(effective.traffic);
  const tools = asRecord(effective.tools);
  const enabled = (name: string) => tools[name] === true || tools[`${name}_enabled`] === true;
  const effectiveSettings: string[] = [];
  if (Object.keys(effective).length) {
    if (effective.run_mode === "osint_only") effectiveSettings.push("Yalnız OSINT: aktif tarama araçları çalıştırılmadı.");
    if (enabled("nmap")) effectiveSettings.push(`Nmap: ${asString(asRecord(rates.nmap).timing)} · ${effective.nmap_mode === "all_ports" ? "tüm portlar" : `${limits.nmap_top_ports} port`} · ${limits.nmap_timeout_sec} sn`);
    if (enabled("katana")) effectiveSettings.push(`Katana: ${asRecord(rates.katana).rate_limit} istek/sn · ${limits.katana_timeout_sec} sn · saklanan URL sınırı: ${limits.katana_max_urls || "yok"}`);
    if (enabled("nuclei")) effectiveSettings.push(`Nuclei: ${asRecord(rates.nuclei).rate_limit} istek/sn · ${limits.nuclei_timeout_sec} sn/istek · hedef URL sınırı: ${limits.nuclei_pool_limit}`);
    if (enabled("gobuster")) effectiveSettings.push(`Gobuster: ${asRecord(rates.gobuster).threads} iş parçacığı · ${limits.gobuster_timeout} sn/istek`);
    if (enabled("ffuf")) effectiveSettings.push(`FFUF: ${asRecord(rates.ffuf).rate} istek/sn · ${limits.ffuf_timeout} sn/istek`);
    if (enabled("checks")) effectiveSettings.push(`Web kontrolleri: ${limits.checks_timeout_sec} sn/istek`);
    if (enabled("screenshots")) effectiveSettings.push(`Ekran görüntüleri: ${limits.screenshots_limit} görüntü · ${limits.screenshots_timeout} sn`);
    effectiveSettings.push(`Etkin araçlar: ${Object.entries(tools).filter(([, value]) => value === true).map(([name]) => name.replace(/_enabled$|_enable$/, "")).join(", ") || "yok"}`);
  }
  return {
    effectiveSettings,
    currentRunDir,
    currentRunResult: runResult,
    runState: lifecycle,
    isHistorical: historical,
    completeness: inferCompleteness(artifacts, reportStatus.status),
    processAttached: attached,
    artifacts,
    target,
    profile: asString(traffic.requested_profile ?? traffic.profile ?? traffic.effective_profile ?? meta.traffic_profile, ""),
    risk: riskState(runResult, reportPath),
    decision: decisionSnapshot(runResult),
    currentStage: lifecycle === "running" ? currentStage?.label ?? "" : "",
    stages,
    metrics: {
      katanaCount: asNumber(summary.katana_count),
      gobusterHits: asNumber(summary.gobuster_total_hits),
      ffufHits: asNumber(summary.ffuf_hits),
      checksCount: asNumber(summary.checks_checked),
      checksLogin: asNumber(summary.checks_login),
      checksDocs: asNumber(summary.checks_docs),
      checksCaptcha: asNumber(summary.checks_captcha),
      checksRatelimit: asNumber(summary.checks_ratelimit),
      nucleiFindings: nucleiFindingsCount,
      screenshotsCount: asNumber(summary.screenshots_captured_count)
    },
    findings,
    report: {
      exists: reportExists,
      mtime: reportMtime,
      path: reportPath,
      viewUrl: reportExists ? "reconbot-report://run/report.html" : "",
      ...reportStatus
    },
    ipEnrichment: ipEnrichmentState(runResult),
    osint: osintState(runResult),
    logTail,
    updatedAt: new Date().toISOString()
  };
}

// A bounded cache avoids re-parsing full historical reports/logs on the main thread.
// Every top-level file version and any nested Nuclei output dependency is checked.
const snapshotCache = new Map<string, { signature: string; value: RunStateSnapshot; bytes: number }>();
let snapshotBytes = 0;
let lastSnapshotTime = 0;
function runVersion(runDir: string, previous?: RunStateSnapshot): string {
  try {
    const names = fs.readdirSync(runDir).sort();
    const result = previous?.currentRunResult ?? readJson(path.join(runDir, "run_result.json"));
    const nuclei = asRecord(result.nuclei), tools = asRecord(asRecord(result.tools).nuclei);
    const extra = [asString(nuclei.output_path), asString(asRecord(tools.artifacts).output)]
      .filter(Boolean).map(value => path.resolve(value)).filter(value => isWithin(runDir, value));
    return [...new Set([...names.map(name => path.join(runDir, name)), ...extra])].map(file => {
      try { const stat = fs.statSync(file); return `${file}:${stat.ino}:${stat.size}:${stat.mtimeMs}:${stat.ctimeMs}`; }
      catch { return `${file}:missing`; }
    }).join("|");
  } catch { return "missing"; }
}
export function readRunStateSnapshot(currentRunDir: string, historical = false, processAttached = false): RunStateSnapshot {
  if (!currentRunDir) return buildRunStateSnapshot(currentRunDir, historical, processAttached);
  const key = `${currentRunDir}|${historical}|${processAttached}`;
  const cached = snapshotCache.get(key);
  const before = runVersion(currentRunDir, cached?.value);
  if (cached?.signature === before) {
    snapshotCache.delete(key); snapshotCache.set(key, cached);
    return cached.value;
  }
  const value = buildRunStateSnapshot(currentRunDir, historical, processAttached);
  lastSnapshotTime = Math.max(Date.now(), lastSnapshotTime + 1);
  value.updatedAt = new Date(lastSnapshotTime).toISOString();
  if (cached) { snapshotBytes -= cached.bytes; snapshotCache.delete(key); }
  // Do not cache a read that raced a file rewrite.
  const after = runVersion(currentRunDir, value);
  if (before === after) {
    const bytes = Buffer.byteLength(JSON.stringify(value));
    if (bytes <= 32 * 1024 * 1024) {
      snapshotCache.set(key, { signature: after, value, bytes });
      snapshotBytes += bytes;
      while (snapshotCache.size > 64 || snapshotBytes > 32 * 1024 * 1024) {
        const oldest = snapshotCache.keys().next().value as string;
        snapshotBytes -= snapshotCache.get(oldest)!.bytes; snapshotCache.delete(oldest);
      }
    }
  }
  return value;
}
