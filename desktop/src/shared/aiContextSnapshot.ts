import type { AiRunContextSnapshot, AiTopFinding, RunStateSnapshot, ScanConfig } from "./api";

const TOP_FINDINGS_LIMIT = 8;
const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  unknown: 5
};

export interface CurrentAiAppState {
  runState: RunStateSnapshot;
  config?: ScanConfig;
  contextProfile?: string;
  requestId?: string;
}

export interface AiContextConsistencyResult {
  ok: boolean;
  warnings: string[];
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function asList(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function asNumber(value: unknown): number | null {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
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

function firstNumber(...values: unknown[]): number | null {
  for (const value of values) {
    const parsed = asNumber(value);
    if (parsed !== null) return Math.max(0, Math.min(100, Math.round(parsed)));
  }
  return null;
}

function maxCount(...values: unknown[]): number {
  return Math.max(
    0,
    ...values
      .map((value) => asNumber(value))
      .filter((value): value is number => value !== null)
      .map((value) => Math.max(0, Math.round(value)))
  );
}

function riskBand(score: number | null, label: string): string {
  const normalized = label.trim().toLowerCase();
  if (normalized && normalized !== "pending" && normalized !== "monitoring") return normalized;
  if (score === null) return normalized || "unknown";
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "elevated";
  return "low";
}

function normalizeSeverity(value: unknown): string {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized.includes("critical")) return "critical";
  if (normalized.includes("high")) return "high";
  if (normalized.includes("medium") || normalized.includes("moderate")) return "medium";
  if (normalized.includes("low")) return "low";
  if (normalized.includes("info")) return "info";
  return "unknown";
}

function firstPresent(...values: unknown[]): unknown {
  return values.find((value) => value !== undefined && value !== null && value !== "" && (!Array.isArray(value) || value.length > 0));
}

function verificationState(
  explicitValue: unknown,
  validationEvidence: unknown,
  statusCode: unknown,
  redirect: unknown,
  fingerprint: unknown,
  responseEvidencePresent: boolean,
): "unverified" | "partially_verified" | "verified" {
  const explicit = String(explicitValue || "").trim().toLowerCase();
  const hasValidationEvidence = validationEvidence !== undefined && validationEvidence !== null && validationEvidence !== "";
  if (["verified", "validated", "confirmed", "manually_verified", "operator_verified"].includes(explicit) && hasValidationEvidence) {
    return "verified";
  }
  if (
    ["partially_verified", "partial", "partially_validated"].includes(explicit)
    || [statusCode, redirect, fingerprint].some((value) => value !== undefined && value !== null && value !== "")
    || responseEvidencePresent
  ) {
    return "partially_verified";
  }
  return "unverified";
}

function findingFromRecord(item: unknown, fallbackSource = "nuclei"): AiTopFinding | null {
  const row = asRecord(item);
  if (!Object.keys(row).length) return null;
  const info = asRecord(row.info);
  const rawTags = asList(info.tags ?? row.tags);
  const tags = rawTags.map((tag) => String(tag)).filter(Boolean).slice(0, 8);
  const templateId = asString(row["template-id"] ?? row.templateID ?? row.template_id ?? row.id, "");
  const title = asString(row.title ?? row.name ?? info.name ?? templateId, "");
  const url = asString(row["matched-at"] ?? row.matchedAt ?? row.matched_at ?? row.url ?? row.host ?? row.matchedAt, "");
  if (!title && !url && !templateId) return null;
  const statusCode = firstPresent(row.status_code, row["status-code"], row.http_status, row.httpStatus) as string | number | undefined;
  const redirect = firstPresent(row.redirect, row.redirect_url, row.redirectUrl, row.final_url, row.finalUrl, row.location, row.redirect_chain);
  const fingerprint = firstPresent(row.fingerprint, row.response_fingerprint, row.responseFingerprint, row.technology_fingerprint, row.technologyFingerprint, row.product_fingerprint, row.productFingerprint, row.detected_product);
  const validationEvidence = firstPresent(row.validation_evidence, row.validationEvidence, row.validated_evidence, row.validatedEvidence, row.manual_validation, row.manualValidation, row.proof, row.validation_details);
  const responseEvidencePresent = [row.response, row.request, row.matched_response].some((value) => value !== undefined && value !== null && value !== "");
  const explicitVerification = firstPresent(row.verification_state, row.verificationState, row.validation_state, row.validationState, row.validation);
  const state = verificationState(explicitVerification, validationEvidence, statusCode, redirect, fingerprint, responseEvidencePresent);
  const missingEvidenceFields = [
    ...(!url ? ["matched_url"] : []),
    ...(statusCode === undefined && redirect === undefined ? ["status_or_redirect"] : []),
    ...(fingerprint === undefined ? ["product_fingerprint"] : []),
    ...(validationEvidence === undefined ? ["explicit_validation_evidence"] : []),
  ];
  return {
    title: title || templateId || "Nuclei finding",
    severity: normalizeSeverity(row.severity ?? info.severity),
    source: asString(row.source ?? row.tool, fallbackSource) || fallbackSource,
    template_id: templateId || undefined,
    url: url || undefined,
    tags,
    validation: asString(row.validation ?? row.validation_status ?? row.validationState, "operator_validation_required"),
    operator_validation_required: row.operator_validation_required === false ? false : true,
    confidence: (row.confidence as string | number | undefined) ?? (info.confidence as string | number | undefined),
    verification_state: state,
    status_code: statusCode,
    redirect,
    fingerprint,
    validation_evidence: validationEvidence,
    response_evidence_present: responseEvidencePresent,
    missing_evidence_fields: missingEvidenceFields,
  };
}

function runResultFindings(runResult: Record<string, unknown>): AiTopFinding[] {
  const candidates: unknown[] = [];
  const nuclei = asRecord(runResult.nuclei);
  const data = asRecord(runResult.data);
  const dataNuclei = asRecord(data.nuclei_results);
  for (const source of [nuclei, dataNuclei, asRecord(runResult.nuclei_results)]) {
    for (const key of ["findings", "Findings", "results", "Results", "items", "data", "Data"]) {
      candidates.push(...asList(source[key]));
    }
  }
  candidates.push(...asList(runResult.findings));
  return candidates
    .map((item) => findingFromRecord(item))
    .filter((item): item is AiTopFinding => item !== null);
}

function snapshotFindings(runState: RunStateSnapshot, runResult: Record<string, unknown>): AiTopFinding[] {
  const live = (Array.isArray(runState.findings) ? runState.findings : [])
    .map((finding) => findingFromRecord({
      name: finding.name,
      severity: finding.severity,
      "template-id": finding.templateId,
      "matched-at": finding.matchedAt,
      source: finding.source || "nuclei",
      tags: finding.tags,
      validation: finding.validation,
      operator_validation_required: finding.operatorValidationRequired,
      confidence: finding.confidence,
      verification_state: finding.verificationState,
      status_code: finding.statusCode,
      redirect: finding.redirect,
      fingerprint: finding.fingerprint,
      validation_evidence: finding.validationEvidence,
      response_evidence_present: finding.responseEvidencePresent,
      missing_evidence_fields: finding.missingEvidenceFields,
    }))
    .filter((item): item is AiTopFinding => item !== null);
  const fromRunResult = runResultFindings(runResult);
  const unique = new Map<string, AiTopFinding>();
  for (const finding of [...live, ...fromRunResult]) {
    const key = `${finding.source}|${finding.template_id || finding.title}|${finding.url || ""}`.toLowerCase();
    if (!unique.has(key)) unique.set(key, finding);
  }
  return Array.from(unique.values()).sort((a, b) => {
    const rank = (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9);
    if (rank !== 0) return rank;
    return a.title.localeCompare(b.title);
  });
}

function stageStatus(runState: RunStateSnapshot, runResult: Record<string, unknown>): Record<string, Record<string, unknown>> {
  const resultStages = asRecord(runResult.stages);
  const rows: Record<string, Record<string, unknown>> = {};
  for (const [name, stage] of Object.entries(resultStages)) {
    rows[name] = asRecord(stage);
  }
  for (const stage of Array.isArray(runState.stages) ? runState.stages : []) {
    rows[stage.name] = {
      ...(rows[stage.name] || {}),
      status: stage.status,
      metric: stage.metric,
      reason: stage.reason
    };
  }
  return rows;
}

function severityCounts(findings: AiTopFinding[], totalCount: number): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    const severity = normalizeSeverity(finding.severity);
    counts[severity] = (counts[severity] || 0) + 1;
  }
  const known = Object.values(counts).reduce((sum, value) => sum + value, 0);
  if (totalCount > known) counts.unknown = (counts.unknown || 0) + (totalCount - known);
  return counts;
}

function sourceHealthSummary(runResult: Record<string, unknown>): Record<string, unknown> {
  const osint = asRecord(runResult.osint);
  return {
    ...asRecord(osint.osint_source_health_summary),
    ...asRecord(osint.source_health),
    ...asRecord(asRecord(osint.summary).source_health)
  };
}

function lastErrors(logTail: string[]): string[] {
  return (Array.isArray(logTail) ? logTail : [])
    .filter((line) => /(error|failed|timeout|forbidden|interrupted|cancelled)/i.test(line))
    .slice(-8);
}

function partialNotes(runState: RunStateSnapshot, runResult: Record<string, unknown>, sourceHealth: Record<string, unknown>): string[] {
  const notes: string[] = [];
  const state = String(runState.runState || runResult.run_state || "").toLowerCase();
  if (["running", "in_progress", "active", "scanning", "started"].includes(state)) notes.push("Run is still running; report is not final.");
  if (["interrupted", "stopped", "cancelled", "canceled", "failed", "error"].includes(state) || runResult.interrupted_by_user === true) {
    notes.push("Run was interrupted or did not finish cleanly; report is partial.");
  }
  const coverage = String(sourceHealth.coverage_confidence || "").toLowerCase();
  if (coverage && coverage !== "high") notes.push(`Source coverage is ${coverage}; clean-result claims are not supported.`);
  for (const stage of Array.isArray(runState.stages) ? runState.stages : []) {
    if (["error", "failed", "skipped"].includes(stage.status.toLowerCase())) {
      notes.push(`${stage.name} stage status is ${stage.status}.`);
    }
  }
  return Array.from(new Set(notes)).slice(0, 10);
}

function runIdFromDir(runDir: string): string {
  return runDir.split(/[\\/]/).filter(Boolean).slice(-1)[0] || runDir;
}

function effectiveAiModel(config?: ScanConfig): string {
  const ai = config?.ai;
  return String(ai?.selectedModel || ai?.manualModelName || ai?.model || ai?.effectiveModel || "").trim();
}

export function buildAiRunContextSnapshot(currentAppState: CurrentAiAppState): AiRunContextSnapshot {
  const runState = currentAppState.runState;
  const runResult = asRecord(runState.currentRunResult);
  const meta = asRecord(runResult.meta);
  const summary = asRecord(runResult.summary);
  const runConfig = asRecord(runResult.run_config ?? runResult.config);
  const traffic = asRecord(runResult.traffic);
  const osint = asRecord(runResult.osint);
  const darkweb = asRecord(osint.darkweb_intelligence);
  const findings = snapshotFindings(runState, runResult);
  const stages = stageStatus(runState, runResult);
  const nucleiStage = asRecord(stages.nuclei);
  const toolsNuclei = asRecord(asRecord(runResult.tools).nuclei);
  const nucleiCount = maxCount(
    runState.metrics?.nucleiFindings,
    summary.nuclei_findings_count,
    nucleiStage.findings_count,
    toolsNuclei.findings_count,
    findings.filter((finding) => finding.source === "nuclei").length
  );
  const findingsCount = maxCount(summary.findings_count, summary.total_findings, nucleiCount, findings.length);
  const score = firstNumber(
    runState.risk?.score,
    nestedValue(runResult, ["report", "risk_score"]),
    nestedValue(runResult, ["decision", "risk_score"]),
    nestedValue(runResult, ["summary", "risk_score"]),
    nestedValue(runResult, ["risk", "score"]),
    runResult.risk_score
  );
  const sourceHealth = sourceHealthSummary(runResult);
  const runStateValue = runState.runState || asString(runResult.run_state, "");
  const normalizedRunState = runStateValue.toLowerCase();
  const isInterrupted = ["interrupted", "stopped", "cancelled", "canceled", "failed", "error"].includes(normalizedRunState) || runResult.interrupted_by_user === true;
  const isRunning = ["running", "in_progress", "active", "scanning", "started"].includes(normalizedRunState);
  const isCompleted = ["completed", "done", "finished", "historical_loaded"].includes(normalizedRunState) && !isInterrupted;

  return {
    ai_model: effectiveAiModel(currentAppState.config),
    ai_baseUrl: currentAppState.config?.ai?.baseUrl || "",
    ai_provider: currentAppState.config?.ai?.provider || "",
    target: runState.target || asString(meta.target ?? runResult.target ?? currentAppState.config?.target, ""),
    run_id: runIdFromDir(runState.currentRunDir),
    run_dir: runState.currentRunDir || "",
    report_path: runState.report?.path || "",
    run_state: runStateValue || "idle",
    is_running: isRunning,
    is_interrupted: isInterrupted,
    is_completed: isCompleted,
    profile: runState.profile || asString(runConfig.scan_profile ?? traffic.requested_profile ?? traffic.profile ?? currentAppState.config?.scanProfile, ""),
    mode: asString(runConfig.run_mode ?? meta.run_mode ?? currentAppState.config?.runMode, ""),
    risk_score: score,
    risk_band: riskBand(score, runState.risk?.label || ""),
    findings_count: findingsCount,
    nuclei_findings_count: nucleiCount,
    findings_by_severity: severityCounts(findings, findingsCount),
    top_findings: findings.slice(0, TOP_FINDINGS_LIMIT),
    tool_stage_status: stages,
    source_health_summary: sourceHealth,
    osint_summary: asRecord(osint.summary),
    darkweb_summary: asRecord(darkweb.summary),
    validation_notes: findings.length
      ? ["Nuclei template matches require operator validation.", ...findings.slice(0, 3).map((finding) => `${finding.title}: ${finding.validation || "operator_validation_required"}`)]
      : [],
    current_report_confidence: {
      risk_source: runState.risk?.source || "",
      decision_source: runState.decision?.source || "",
      coverage_confidence: sourceHealth.coverage_confidence || "",
      report_exists: Boolean(runState.report?.exists)
    },
    last_errors: lastErrors(runState.logTail || []),
    partial_coverage_notes: partialNotes(runState, runResult, sourceHealth),
    context_profile: currentAppState.contextProfile,
    request_id: currentAppState.requestId
  };
}

export function compareAiContextToVisibleState(
  context: AiRunContextSnapshot,
  runState: RunStateSnapshot
): AiContextConsistencyResult {
  const warnings: string[] = [];
  const visibleTarget = (runState.target || "").trim();
  if (visibleTarget && context.target.trim() !== visibleTarget) {
    warnings.push(`target mismatch: context=${context.target} visible=${visibleTarget}`);
  }
  const visibleRunState = (runState.runState || "").trim();
  if (visibleRunState && context.run_state !== visibleRunState) {
    warnings.push(`run_state mismatch: context=${context.run_state} visible=${visibleRunState}`);
  }
  if (runState.risk?.score !== null && runState.risk?.score !== undefined && context.risk_score !== runState.risk.score) {
    warnings.push(`risk_score mismatch: context=${context.risk_score} visible=${runState.risk.score}`);
  }
  if (context.nuclei_findings_count !== (runState.metrics?.nucleiFindings || 0)) {
    warnings.push(`nuclei count mismatch: context=${context.nuclei_findings_count} visible=${runState.metrics?.nucleiFindings || 0}`);
  }
  const visibleFindings = Array.isArray(runState.findings) ? runState.findings.length : 0;
  if (visibleFindings > 0 && visibleFindings <= TOP_FINDINGS_LIMIT && context.top_findings.length < visibleFindings) {
    warnings.push(`top_findings mismatch: context=${context.top_findings.length} visible=${visibleFindings}`);
  }
  return { ok: warnings.length === 0, warnings };
}
