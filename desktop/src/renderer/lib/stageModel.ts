import type { StageRow } from "../../shared/api";

export type StageStatus = "done" | "running" | "error" | "partial" | "interrupted" | "skipped" | "pending" | "unknown";
export function normalizeStageStatus(status: string): StageStatus {
  const value = status.toLowerCase();
  if (["done", "ok", "completed"].includes(value)) return "done";
  if (["running", "active"].includes(value)) return "running";
  if (["error", "failed", "timeout"].includes(value)) return "error";
  if (["skipped", "auto-skipped", "disabled"].includes(value)) return "skipped";
  if (["interrupted", "cancelled", "canceled"].includes(value)) return "interrupted";
  if (value === "partial") return "partial";
  if (["", "pending", "queued", "not_started"].includes(value)) return "pending";
  return "unknown";
}

export function summarizeStages(rows: StageRow[]) {
  const statuses = rows.map(row => normalizeStageStatus(row.status));
  const count = (status: StageStatus) => statuses.filter(value => value === status).length;
  const done = count("done"), skipped = count("skipped"), unknown = count("unknown"), total = rows.length - skipped - unknown;
  const status: StageStatus = !rows.length ? "pending"
    : count("running") ? "running" : count("error") ? "error"
    : count("interrupted") ? "interrupted" : count("partial") ? "partial"
    : skipped === rows.length ? "skipped" : unknown === rows.length ? "unknown" : unknown ? "unknown" : done === total ? "done"
    : done ? "partial" : count("unknown") ? "unknown" : "pending";
  return { done, skipped, unknown, total, status };
}
