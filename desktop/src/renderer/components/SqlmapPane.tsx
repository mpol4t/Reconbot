import { useEffect, useRef, useState } from "react";
import { Database, Play, Square, FileText, Terminal } from "lucide-react";
import { t } from "../lib/i18n";
import type { SqlmapRequest, SqlmapSnapshot } from "../../shared/sqlmap";
interface Props { runDir: string; target: string; active: boolean; seed: { url: string; findingId?: string; nonce: number } | null; }
const initial: Omit<SqlmapRequest, 'runDir'> = { url: '', parameter: '', method: 'GET', body: '', cookie: '', level: 1, risk: 1, duration: 180, timeout: 10, threads: 1, delay: 0.2 };
const statuses: Record<string, string> = { running: 'Running', detected: 'Injection detected', not_detected: 'Not detected within tested scope', inconclusive: 'Inconclusive', cancelled: 'Cancelled', timed_out: 'Time limit reached', failed: 'Failed' };
export default function SqlmapPane({ runDir, target, active, seed }: Props): JSX.Element {
  const [form, setForm] = useState(initial);
  const [snapshot, setSnapshot] = useState<SqlmapSnapshot>({ installed: false, active: null, jobs: [], log: '' });
  const [ready, setReady] = useState(false), [message, setMessage] = useState(''), [pending, setPending] = useState(false), [selected, setSelected] = useState(''), [follow, setFollow] = useState(true);
  const logRef = useRef<HTMLPreElement>(null);
  useEffect(() => { setForm({ ...initial, url: /^https?:\/\//i.test(target) ? target : target ? `http://${target}` : '' }); setSelected(''); setMessage(''); }, [runDir, target]);
  useEffect(() => {
    if (!seed) return;
    let parameter = '';
    try { parameter = new URL(seed.url).searchParams.keys().next().value || ''; } catch { /* Editable URL. */ }
    setForm(value => ({ ...value, url: seed.url, parameter, findingId: seed.findingId }));
  }, [seed]);
  useEffect(() => {
    if (!active) return;
    let stopped = false;
    const poll = async (): Promise<void> => {
      try { const value = await window.reconbot.readSqlmap(selected || undefined); if (!stopped) { setSnapshot(value); setReady(true); } }
      catch (error) { if (!stopped) setMessage(String(error)); }
    };
    void poll(); const timer = setInterval(() => { void poll(); }, 1200);
    return () => { stopped = true; clearInterval(timer); };
  }, [runDir, active, selected]);
  useEffect(() => { if (follow && logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, [snapshot.log, follow]);
  const change = <K extends keyof typeof form>(key: K, value: typeof form[K]): void => { setForm(previous => ({ ...previous, [key]: value })); };
  const action = async (stop = false): Promise<void> => {
    setPending(true);
    try {
      const result = stop ? await window.reconbot.stopSqlmap() : await window.reconbot.startSqlmap({ ...form, runDir });
      setMessage(result.message || ''); setSnapshot(await window.reconbot.readSqlmap()); setSelected('');
    } catch (error) { setMessage(String(error)); } finally { setPending(false); }
  };
  const job = snapshot.jobs.find(item => item.jobId === selected) || snapshot.jobs[0];
  return <section className="sqlmap-workspace">
    <header className="page-title"><div><span className="micro-label">{t('Validation')}</span><h1><Database size={25} /> SQLmap</h1></div><span className="results-count">{ready ? t(snapshot.installed ? 'SQLmap available' : 'SQLmap not installed') : t('Checking…')}</span></header>
    <p className="sqlmap-intro">{t('Test one selected parameter for SQL injection. Results are saved with this scan; its original score stays unchanged.')}</p>
    {!runDir && <p className="sqlmap-notice">{t('Select a scan from Artifacts before starting validation.')}</p>}
    {ready && !snapshot.installed && <p className="sqlmap-notice">{t('Install SQLmap on your system and restart ReconBot. macOS: brew install sqlmap · Debian/Ubuntu: sudo apt install sqlmap')}</p>}
    {snapshot.active && <div className="sqlmap-active"><span>{t('Running validation')} · <code>{snapshot.active.url}</code>{snapshot.active.runDir !== runDir && <strong>{t('This job belongs to another scan.')}</strong>}</span><button disabled={pending} onClick={() => { void action(true); }}><Square size={14} />{t('Stop SQLmap')}</button></div>}
    <div className="sqlmap-layout">
      <form className="sqlmap-form" onSubmit={event => { event.preventDefault(); void action(); }}>
        <label>{t('URL to validate')}<input type="url" required value={form.url} onChange={event => change('url', event.target.value)} placeholder="https://target.test/item?id=1" /></label>
        <div className="sqlmap-fields"><label>{t('Parameter')}<input required value={form.parameter} onChange={event => change('parameter', event.target.value)} placeholder="id" /></label><label>{t('Method')}<select value={form.method} onChange={event => change('method', event.target.value as 'GET' | 'POST')}><option>GET</option><option>POST</option></select></label></div>
        {form.method === 'POST' && <label>{t('Form-encoded POST body')}<textarea required value={form.body} onChange={event => change('body', event.target.value)} placeholder="id=1&search=example" /></label>}
        <details><summary>{t('Session and test settings')}</summary><label>Cookie<input value={form.cookie} onChange={event => change('cookie', event.target.value)} placeholder="session=…" /></label>
          <div className="sqlmap-fields">{([['level', 'Level', 1, 3, 1], ['risk', 'Risk', 1, 2, 1], ['duration', 'Time limit (seconds)', 10, 1800, 1], ['timeout', 'Request timeout (seconds)', 2, 60, 1], ['threads', 'Concurrent requests', 1, 3, 1], ['delay', 'Request delay (seconds)', 0, 5, 0.1]] as const).map(([key, label, min, max, step]) => <label key={key}>{t(label)}<input type="number" min={min} max={max} step={step} required value={form[key]} onChange={event => change(key, Number(event.target.value))} /></label>)}</div>
        </details>
        <p className="sqlmap-scope">{t('Detection only: boolean, error and UNION techniques. No database dump or shell. Level 1 / risk 1 is the default.')}</p>
        <button className="primary" type="submit" disabled={pending || !ready || !snapshot.installed || !runDir || Boolean(snapshot.active)}><Play size={15} />{t('Start SQLmap validation')}</button><p role="status" className="sqlmap-message">{t(message)}</p>
      </form>
      <div className="sqlmap-evidence"><header><h2>{t('Validation evidence')}</h2><span>{snapshot.jobs.length} {t('jobs')}</span></header>
        {!snapshot.jobs.length ? <p>{t('No SQLmap jobs for this scan yet.')}</p> : <><select aria-label={t('Validation history')} value={job?.jobId || ''} onChange={event => setSelected(event.target.value)}>{snapshot.jobs.map(item => <option key={item.jobId} value={item.jobId}>{item.startedAt.slice(0, 19)} · {t(statuses[item.status])} · {item.parameter}</option>)}</select>
        {job && <><h3 className={`sqlmap-status ${job.evidence.length ? 'detected' : ''}`}>{t(statuses[job.status])}</h3><code className="sqlmap-url">{job.url}</code><p>{job.method} · {job.parameter} · {t('Level')} {job.level} / {t('Risk')} {job.risk}</p>{job.message && <p role="status">{t(job.message)}</p>}{job.evidence.map((item, index) => <article key={index}><strong>{item.title}</strong><p>{item.parameter} ({item.place}) · {item.type}</p><span className="sqlmap-payload-label">Payload</span><pre aria-label="Payload">{item.payload}</pre></article>)}<p className="sqlmap-scope">{t('A negative result applies only to this parameter and tested techniques. Incomplete jobs cannot establish a clean result.')}</p>
          <div className="sqlmap-actions"><button disabled={job.status === 'running' || job.status === 'inconclusive' && !job.finishedAt} onClick={() => { void window.reconbot.openPath(job.reportPath).then(result => { if (!result.ok) setMessage(result.message || ''); }); }}><FileText size={14} />{t('Open validation report')}</button><button onClick={() => { void window.reconbot.openPath(job.jobDir); }}>{t('Open evidence folder')}</button></div>
        </>}</>}
      </div>
    </div>
    <section className="sqlmap-console"><header><h2><Terminal size={16} />{t('Live SQLmap output')}</h2><label><input type="checkbox" checked={follow} onChange={event => setFollow(event.target.checked)} />{t('Follow output')}</label></header><pre ref={logRef}>{snapshot.log || t('Output will appear when validation starts.')}</pre><small>{t('Shows the latest 64 KB of output. Complete logs are kept in the evidence folder.')}</small></section>
  </section>;
}
