import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { pythonExecutable } from "./pythonRuntime";
import { validateSqlmapRequest, type SqlmapRequest, type SqlmapJob, type SqlmapSnapshot } from "../shared/sqlmap";

function readJob(dir: string): SqlmapJob | null {
  try {
    const job = JSON.parse(fs.readFileSync(path.join(dir, 'result.json'), 'utf8')) as SqlmapJob;
    if (typeof job.status !== 'string' || !Array.isArray(job.evidence) || fs.realpathSync(job.jobDir) !== fs.realpathSync(dir)) return null;
    return { ...job, jobDir: fs.realpathSync(dir) };
  } catch { return null; }
}
function tail(file: string): string {
  try {
    const fd = fs.openSync(file, 'r');
    try { const size = fs.fstatSync(fd).size; const data = Buffer.alloc(Math.min(size, 65536)); fs.readSync(fd, data, 0, data.length, Math.max(0, size - data.length)); return data.toString('utf8'); }
    finally { fs.closeSync(fd); }
  } catch { return ''; }
}
export class SqlmapValidation {
  private child: ChildProcess | null = null;
  private jobDir = '';
  private scannerPid: number | null = null;
  private stopping = false;
  private completion: Promise<void> | null = null;
  private watchdog: ReturnType<typeof setTimeout> | undefined;
  readonly installed = spawnSync('sqlmap', ['--version'], { timeout: 5000, encoding: 'utf8' }).status === 0;
  constructor(private repoRoot: string) {}

  start(input: SqlmapRequest, runDir: string, target: string): { ok: boolean; message: string } {
    try {
      if (this.child) throw new Error('A SQLmap job is already running. Stop it or wait for completion.');
      if (!this.installed) throw new Error('SQLmap is not installed or is not on PATH. Install SQLmap and restart ReconBot.');
      if (!runDir || path.resolve(input.runDir) !== path.resolve(runDir)) throw new Error('Select the originating scan before starting validation.');
      validateSqlmapRequest(input, target);
      const run = fs.realpathSync(runDir);
      const root = path.join(run, 'validations', 'sqlmap');
      fs.mkdirSync(root, { recursive: true });
      if (fs.realpathSync(root) !== root) throw new Error('Validation output cannot be a symbolic link.');
      const jobId = `${new Date().toISOString().replace(/[:.]/g, '-')}-${randomUUID().slice(0, 8)}`;
      this.jobDir = path.join(root, jobId);
      fs.mkdirSync(this.jobDir, { mode: 0o700 });
      const request = { ...input, runDir: run, target };
      fs.writeFileSync(path.join(this.jobDir, 'request.json'), JSON.stringify(request, null, 2), { mode: 0o600 });
      const job: SqlmapJob = { ...request, jobId, jobDir: this.jobDir, status: 'running', startedAt: new Date().toISOString(), evidence: [], reportPath: path.join(this.jobDir, 'report.html') };
      fs.writeFileSync(path.join(this.jobDir, 'result.json'), JSON.stringify(job, null, 2), { mode: 0o600 });
      const dir = this.jobDir;
      const child = spawn(pythonExecutable(this.repoRoot), ['-u', '-m', 'reconbot.validation.sqlmap', '--job-dir', dir], { cwd: this.repoRoot, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, PYTHONUNBUFFERED: '1' } });
      this.child = child;
      this.stopping = false;
      this.scannerPid = null;
      let errors = '', partial = ''; 
      child.stdout?.on('data', data => {
        errors = (errors + data.toString()).slice(-8192);
        partial += data.toString();
        const lines = partial.split('\n'); partial = lines.pop()!.slice(-8192);
        for (const line of lines) {
          try { const event = JSON.parse(line); if (Number.isInteger(event.scannerPid) && event.scannerPid > 1) this.scannerPid = event.scannerPid; }
          catch { /* Backend diagnostics are retained as plain text. */ }
        }
      });
      child.stderr?.on('data', data => { errors = (errors + data.toString()).slice(-8192); });
      this.completion = new Promise(resolve => {
        let finished = false;
        const finish = (message?: string): void => {
          if (finished) return; finished = true;
          clearTimeout(this.watchdog);
          try {
            const result = readJob(dir);
            if (result?.status === 'running') fs.writeFileSync(path.join(dir, 'result.json'), JSON.stringify({ ...result, status: this.stopping ? 'cancelled' : 'failed', finishedAt: new Date().toISOString(), message: message || errors || 'Validation backend exited without final evidence.' }, null, 2));
          } catch { /* Shutdown still completes if the artifact disk is unavailable. */ } finally {
            if (this.child === child) { this.child = null; this.scannerPid = null; }
            resolve();
          }
        };
        child.once('error', error => finish(error.message));
        child.once('close', () => finish());
      });
      // Backend owns scanner groups and its own deadline. This is a second
      // deadline for a stalled backend, using graceful group cleanup.
      this.watchdog = setTimeout(() => { void this.stop(); }, input.duration * 1000 + 15000);
      return { ok: true, message: 'SQLmap validation started.' };
    } catch (error) { return { ok: false, message: error instanceof Error ? error.message : String(error) }; }
  }
  snapshot(runDir: string, jobId?: string): SqlmapSnapshot {
    let root = '';
    try { if (runDir) root = path.join(fs.realpathSync(runDir), 'validations', 'sqlmap'); } catch { /* Missing run. */ }
    let jobs: SqlmapJob[] = [];
    try { jobs = fs.readdirSync(root).sort().reverse().slice(0, 100).map(name => readJob(path.join(root, name))).filter((job): job is SqlmapJob => job !== null); }
    catch { /* No jobs for the selected run. */ }
    // Jobs that lost their owner across an app/crash restart are incomplete.
    jobs = jobs.map(job => job.status === 'running' && !(this.child && job.jobDir === this.jobDir) ? { ...job, status: 'inconclusive', message: 'The previous validation stopped without a final result.' } : job);
    const active = this.child ? readJob(this.jobDir) : null;
    return { installed: this.installed, active, jobs, log: tail(path.join(jobs.find(job => job.jobId === jobId)?.jobDir || active?.jobDir || jobs[0]?.jobDir || '', 'sqlmap.log')) };
  }
  async stop(): Promise<{ ok: boolean; message: string }> {
    if (!this.child) return { ok: true, message: 'No SQLmap validation is running.' };
    const child = this.child;
    if (!this.stopping) {
      this.stopping = true;
      let markerWritten = true;
      try { fs.writeFileSync(path.join(this.jobDir, 'cancel.request'), 'cancel', { mode: 0o600 }); } catch { markerWritten = false; }
      // Frozen Python installs handlers after its bootloader. An early marker
      // cancels before scanner launch, instead of interrupting that bootloader.
      if (this.scannerPid) child.kill('SIGINT');
      else if (!markerWritten) child.kill('SIGTERM');
    }
    // Normal exit cleans scanner groups in Python. If the wrapper itself stalls,
    // kill only the scanner PID reported by this owned child's stdout.
    const force = setTimeout(() => {
      if (this.child !== child) return;
      if (this.scannerPid && process.platform !== 'win32') {
        try { process.kill(-this.scannerPid, 'SIGKILL'); } catch { /* Already reaped. */ }
      }
      child.kill('SIGKILL');
    }, 8000);
    try { await this.completion; } finally { clearTimeout(force); }
    return { ok: true, message: 'SQLmap validation stopped.' };
  }
  async dispose(): Promise<void> { await this.stop(); }
}
