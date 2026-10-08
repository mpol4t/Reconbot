export interface SqlmapRequest {
  runDir: string;
  url: string;
  parameter: string;
  method: "GET" | "POST";
  body: string;
  cookie: string;
  level: number;
  risk: number;
  duration: number;
  timeout: number;
  threads: number;
  delay: number;
  findingId?: string;
}
export interface SqlmapEvidence { parameter: string; place: string; type: string; title: string; payload: string; }
export type SqlmapStatus = "running" | "cancelled" | "timed_out" | "failed" | "detected" | "not_detected" | "inconclusive";
export interface SqlmapJob extends SqlmapRequest {
  jobId: string;
  jobDir: string;
  status: SqlmapStatus;
  startedAt: string;
  finishedAt?: string;
  evidence: SqlmapEvidence[];
  reportPath: string;
  message?: string;
}
export interface SqlmapSnapshot { installed: boolean; active: SqlmapJob | null; jobs: SqlmapJob[]; log: string; }

export function validateSqlmapRequest(input: SqlmapRequest, target: string): void {
  const url = new URL(input.url);
  const origin = new URL(target.includes("://") ? target : `http://${target}`);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash || /[\r\n\0]/.test(input.url)) throw new Error("Use an HTTP(S) URL without embedded credentials or fragments.");
  const port = (value: URL): string => value.port || (value.protocol === "https:" ? "443" : "80");
  if (url.hostname.toLowerCase() !== origin.hostname.toLowerCase() || port(url) !== port(origin)) throw new Error("The validation URL must belong to the selected scan target (same host and port).");
  if (!/^[A-Za-z0-9_][A-Za-z0-9_.\[\]-]{0,127}$/.test(input.parameter)) throw new Error("Enter one parameter name (for example id).");
  if (!['GET', 'POST'].includes(input.method)) throw new Error("Method must be GET or POST.");
  if (typeof input.body !== "string" || input.body.length > 65536 || input.body.includes('\0')) throw new Error("POST body is invalid or too large.");
  if (!(input.method === 'GET' ? url.searchParams : new URLSearchParams(input.body)).has(input.parameter)) throw new Error("The selected parameter must occur in the URL query or form-encoded POST body.");
  if (typeof input.cookie !== "string" || input.cookie.length > 16384 || /[\r\n\0]/.test(input.cookie)) throw new Error("Cookie must be a single header value.");
  for (const [key, low, high] of [['level', 1, 3], ['risk', 1, 2], ['duration', 10, 1800], ['timeout', 2, 60], ['threads', 1, 3]] as const) {
    if (!Number.isInteger(input[key]) || input[key] < low || input[key] > high) throw new Error(`${key} must be an integer between ${low} and ${high}.`);
  }
  if (!Number.isFinite(input.delay) || input.delay < 0 || input.delay > 5) throw new Error("Delay must be between 0 and 5 seconds.");
}
