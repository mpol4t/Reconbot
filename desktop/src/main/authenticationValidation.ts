import fs from 'node:fs';
import path from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { pythonExecutable } from './pythonRuntime';
import { validateAuthenticationRequest, type AuthenticationJob, type AuthenticationRequest, type AuthenticationSnapshot } from '../shared/authentication';

function readJob(dir: string, summary = true): AuthenticationJob | null {
  try {
    const file = path.join(dir, summary && fs.existsSync(path.join(dir, 'summary.json')) ? 'summary.json' : 'result.json');
    if (fs.statSync(file).size > 16 * 1024 * 1024) return null;
    const value = JSON.parse(fs.readFileSync(file, 'utf8')) as AuthenticationJob;
    if (!Array.isArray(value.attempts) || typeof value.status !== 'string' || fs.realpathSync(value.jobDir) !== fs.realpathSync(dir)) return null;
    return { ...value, jobDir: fs.realpathSync(dir) };
  } catch { return null; }
}
function tail(file: string): string {
  try { const fd = fs.openSync(file, 'r'); try { const size = fs.fstatSync(fd).size, data = Buffer.alloc(Math.min(65536, size)); fs.readSync(fd, data, 0, data.length, Math.max(0, size - data.length)); return data.toString('utf8'); } finally { fs.closeSync(fd); } } catch { return ''; }
}
export class AuthenticationValidation {
  private child: ChildProcess | null = null;
  private dir = '';
  private ready = false;
  private stopping = false;
  private completion: Promise<void> | null = null;
  private watchdog: ReturnType<typeof setTimeout> | undefined;
  constructor(private readonly repoRoot: string) {}
  start(input: AuthenticationRequest, runDir: string, target: string): { ok: boolean; message: string } {
    try {
      if (this.child) throw new Error('An authentication test is already running.');
      if (!runDir || path.resolve(input.runDir) !== path.resolve(runDir)) throw new Error('Select the originating scan before starting validation.');
      validateAuthenticationRequest(input, target);
      for (const file of [input.passwordWordlist, ...(input.usernameSource === 'wordlist' ? [input.usernameWordlist] : [])]) {
        if (!path.isAbsolute(file) || !fs.statSync(file).isFile() || fs.statSync(file).size > 16 * 1024 * 1024) throw new Error('Choose readable absolute wordlist file paths, up to 16 MB.');
        fs.accessSync(file, fs.constants.R_OK);
      }
      const run = fs.realpathSync(runDir), root = path.join(run, 'validations', 'authentication');
      fs.mkdirSync(root, { recursive: true });
      if (fs.realpathSync(root) !== root) throw new Error('Validation output cannot be a symbolic link.');
      const jobId = `${new Date().toISOString().replace(/[:.]/g, '-')}-${randomUUID().slice(0, 8)}`;
      this.dir = path.join(root, jobId); fs.mkdirSync(this.dir, { mode: 0o700 });
      const request = { ...input, runDir: run, target };
      const job: AuthenticationJob = { ...request, jobId, jobDir: this.dir, reportPath: path.join(this.dir, 'report.html'), status: 'running', attempts: [], baselineRequests: 0, plannedAttempts: 0, startedAt: new Date().toISOString() };
      fs.writeFileSync(path.join(this.dir, 'request.json'), JSON.stringify(request, null, 2), { mode: 0o600 });
      fs.writeFileSync(path.join(this.dir, 'result.json'), JSON.stringify(job, null, 2), { mode: 0o600 });
      const dir = this.dir, child = spawn(pythonExecutable(this.repoRoot), ['-u', '-m', 'reconbot.validation.authentication', '--job-dir', dir], { cwd: this.repoRoot, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, PYTHONUNBUFFERED: '1' } });
      this.child = child; this.ready = false; this.stopping = false;
      let errors = '', partial = '';
      child.stdout?.on('data', data => {
        partial += data.toString(); const lines = partial.split('\n'); partial = lines.pop()!.slice(-8192);
        for (const line of lines) { try { if (JSON.parse(line).workerReady === true) this.ready = true; } catch { errors = (errors + line).slice(-8192); } }
      });
      child.stderr?.on('data', data => { errors = (errors + data.toString()).slice(-8192); });
      this.completion = new Promise(resolve => {
        let finished = false;
        const finish = (message?: string): void => {
          if (finished) return; finished = true; clearTimeout(this.watchdog);
          try {
            const result = readJob(dir, false);
            if (result?.status === 'running') {
              const final = { ...result, status: this.stopping ? 'cancelled' : 'failed', finishedAt: new Date().toISOString(), message: message || errors || 'Authentication backend exited without a final result.' };
              fs.writeFileSync(path.join(dir, 'result.json'), JSON.stringify(final, null, 2), { mode: 0o600 });
              fs.writeFileSync(path.join(dir, 'summary.json'), JSON.stringify({ ...final, attempts: [], attemptCount: final.attempts.length }), { mode: 0o600 });
              // A crash still leaves a readable diagnostic report and retained JSON.
              const esc = (text: string): string => text.replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]!));
              fs.writeFileSync(path.join(dir, 'report.html'), `<html><meta charset="utf-8"><h1>Authentication testing · ${final.status}</h1><p>${esc(final.message)}</p><p>Incomplete test; completed evidence is retained.</p><a href="result.json">Structured evidence</a></html>`);
            }
          } catch { /* Shutdown must complete even if artifact storage is unavailable. */ }
          finally { if (this.child === child) this.child = null; resolve(); }
        };
        child.once('error', error => finish(error.message)); child.once('close', () => finish());
      });
      this.watchdog = setTimeout(() => { void this.stop(); }, input.duration * 1000 + 15000);
      return { ok: true, message: 'Authentication testing started.' };
    } catch (error) { return { ok: false, message: error instanceof Error ? error.message : String(error) }; }
  }
  snapshot(runDir: string, jobId?: string, rejectedPage = 0): AuthenticationSnapshot {
    let jobs: AuthenticationJob[] = [];
    try {
      const root = path.join(fs.realpathSync(runDir), 'validations', 'authentication');
      jobs = fs.readdirSync(root).sort().reverse().slice(0, 100).map(name => readJob(path.join(root, name))).filter((job): job is AuthenticationJob => Boolean(job));
    } catch { /* No history. */ }
    jobs = jobs.map(job => job.status === 'running' && !(this.child && job.jobDir === this.dir) ? { ...job, status: 'inconclusive', message: 'The previous authentication test stopped without a final result.' } : job);
    const active = this.child ? readJob(this.dir) : null;
    const selected = jobs.find(job => job.jobId === jobId) || jobs[0];
    if (selected) {
      const details = readJob(selected.jobDir, false);
      if (details) {
        const rejected = details.attempts.filter(attempt => ['rejected', 'baseline_match'].includes(attempt.outcome));
        const rejectedPages = Math.max(1, Math.ceil(rejected.length / 50));
        const page = Number.isSafeInteger(rejectedPage) ? Math.max(0, Math.min(rejectedPage, rejectedPages - 1)) : 0;
        jobs = jobs.map(job => job.jobId === selected.jobId ? {
          ...job, attempts: details.attempts.slice(-100), attemptCount: details.attemptCount ?? details.attempts.length,
          acceptedAttempts: details.attempts.filter(attempt => attempt.outcome === 'accepted'),
          candidateAttempts: details.attempts.filter(attempt => attempt.outcome === 'candidate'),
          rejectedAttempts: rejected.slice(page * 50, (page + 1) * 50),
          otherAttempts: details.attempts.filter(attempt => !['accepted', 'candidate', 'rejected', 'baseline_match'].includes(attempt.outcome)).slice(-50),
          rejectedCount: rejected.length, rejectedPage: page, rejectedPages,
        } : { ...job, attempts: [] });
      }
    }
    return { active, jobs, log: tail(path.join(jobs.find(job => job.jobId === jobId)?.jobDir || active?.jobDir || jobs[0]?.jobDir || '', 'authentication.log')) };
  }
  async stop(): Promise<{ ok: boolean; message: string }> {
    if (!this.child) return { ok: true, message: 'No authentication test is running.' };
    const child = this.child;
    if (!this.stopping) {
      this.stopping = true;
      try { fs.writeFileSync(path.join(this.dir, 'cancel.request'), 'cancel', { mode: 0o600 }); if (this.ready) child.kill('SIGINT'); }
      catch { child.kill('SIGTERM'); }
    }
    const force = setTimeout(() => { if (this.child === child) child.kill('SIGKILL'); }, 8000);
    try { await this.completion; } finally { clearTimeout(force); }
    return { ok: true, message: 'Authentication testing stopped.' };
  }
  async dispose(): Promise<void> { await this.stop(); }
}
