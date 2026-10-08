import { useEffect, useRef, useState } from 'react';
import { KeyRound, Play, Square, FileText } from 'lucide-react';
import type { AuthenticationRequest, AuthenticationSnapshot } from '../../shared/authentication';
import WordlistField from './WordlistField';
import { t } from '../lib/i18n';

const initial: Omit<AuthenticationRequest, 'runDir'> = { url: '', mode: 'basic', usernameSource: 'single', username: '', usernameWordlist: '', passwordWordlist: '', usernameField: 'username', passwordField: 'password', extraBody: '', successMode: 'auto', successValue: '', failureValue: '', lockoutValue: 'account locked', maxAttempts: 50, duration: 180, timeout: 10, delay: 1 };
const statuses: Record<string, string> = { running: 'Running', accepted: 'Credentials accepted', candidate: 'Possible successful login — verification required', no_candidate: 'No candidate identified', not_accepted: 'Tested pairs rejected', attempt_limit: 'Attempt limit reached', blocked: 'Rate limit or lockout detected', inconclusive: 'Inconclusive', cancelled: 'Cancelled', timed_out: 'Time limit reached', failed: 'Failed' };
export default function AuthenticationPane({ runDir, target, active }: { runDir: string; target: string; active: boolean }): JSX.Element {
  const [form, setForm] = useState(initial), [state, setState] = useState<AuthenticationSnapshot>({ active: null, jobs: [], log: '' });
  const [message, setMessage] = useState(''), [pending, setPending] = useState(false), [selected, setSelected] = useState(''), [follow, setFollow] = useState(true);
  const [failedOpen, setFailedOpen] = useState(false), [failedPage, setFailedPage] = useState(0);
  const job = state.jobs.find(item => item.jobId === selected) || state.jobs[0];
  const log = useRef<HTMLPreElement>(null);
  useEffect(() => { setForm(previous => ({ ...previous, url: /^https?:\/\//i.test(target) ? target : target ? `http://${target}` : '' })); setSelected(''); setMessage(''); }, [runDir, target]);
  useEffect(() => {
    if (!active) return;
    let stopped = false;
    const poll = async (): Promise<void> => { try { const next = await window.reconbot.readAuthentication(selected || undefined, failedPage); if (!stopped) setState(next); } catch (error) { if (!stopped) setMessage(String(error)); } };
    void poll(); const timer = setInterval(() => { void poll(); }, 1200);
    return () => { stopped = true; clearInterval(timer); };
  }, [runDir, active, selected, failedPage]);
  useEffect(() => { setFailedOpen(false); setFailedPage(0); }, [runDir, selected, job?.jobId]);
  useEffect(() => { if (follow && log.current) log.current.scrollTop = log.current.scrollHeight; }, [state.log, follow]);
  const change = <K extends keyof typeof form>(key: K, value: typeof form[K]): void => setForm(previous => ({ ...previous, [key]: value }));
  const action = async (stop = false): Promise<void> => {
    setPending(true);
    try { const result = stop ? await window.reconbot.stopAuthentication() : await window.reconbot.startAuthentication({ ...form, runDir }); setMessage(result.message || ''); setState(await window.reconbot.readAuthentication()); setSelected(''); }
    catch (error) { setMessage(String(error)); } finally { setPending(false); }
  };
  const attemptCount = job?.attemptCount ?? job?.attempts.length ?? 0;
  const accepted = job?.acceptedAttempts ?? job?.attempts.filter(attempt => attempt.outcome === 'accepted') ?? [];
  const candidates = job?.candidateAttempts ?? job?.attempts.filter(attempt => attempt.outcome === 'candidate') ?? [];
  const rejected = job?.rejectedAttempts ?? job?.attempts.filter(attempt => ['rejected', 'baseline_match'].includes(attempt.outcome)) ?? [];
  const other = job?.otherAttempts ?? job?.attempts.filter(attempt => !['accepted', 'candidate', 'rejected', 'baseline_match'].includes(attempt.outcome)) ?? [];
  const automaticJob = job?.mode === 'form' && job?.successMode === 'auto';
  const rejectedCount = job?.rejectedCount ?? rejected.length;
  return <section className="sqlmap-workspace auth-workspace">
    <header className="page-title"><div><span className="micro-label">{t('Authentication')}</span><h1><KeyRound size={25} />{t('Authentication Testing')}</h1></div></header>
    <p className="sqlmap-intro">{t('Test selected credential lists against one login endpoint. The original scan score stays unchanged.')}</p>
    {!runDir && <p className="sqlmap-notice">{t('Select a scan from Artifacts before starting validation.')}</p>}
    {state.active && <div className="sqlmap-active"><span>{t('Running authentication test')} · <code>{state.active.url}</code>{state.active.runDir !== runDir && <strong>{t('This job belongs to another scan.')}</strong>}</span><button disabled={pending} onClick={() => { void action(true); }}><Square size={14} />{t('Stop authentication test')}</button></div>}
    <div className="sqlmap-layout">
      <form className="sqlmap-form" onSubmit={event => { event.preventDefault(); void action(); }}>
        <label>{t('Login URL')}<input type="url" required value={form.url} onChange={event => change('url', event.target.value)} /></label><p className="sqlmap-scope">{t(form.mode === 'form' ? 'Enter the exact form action URL, including its path and query. The scan target alone may not accept login requests.' : 'HTTP Basic uses the browser authentication challenge. For a page with username and password fields, choose Login form (POST).')}</p>
        <label>{t('Authentication method')}<select aria-label={t('Authentication method')} value={form.mode} onChange={event => change('mode', event.target.value as 'basic' | 'form')}><option value="basic">HTTP Basic</option><option value="form">{t('Login form (POST)')}</option></select></label>
        <label>{t('Username source')}<select aria-label={t('Username source')} value={form.usernameSource} onChange={event => change('usernameSource', event.target.value as 'single' | 'wordlist')}><option value="single">{t('Single username')}</option><option value="wordlist">{t('Username wordlist')}</option></select></label>
        {form.usernameSource === 'single' ? <label>{t('Username')}<input required value={form.username} onChange={event => change('username', event.target.value)} /></label> : <WordlistField slot="authUsers" label="Username wordlist" value={form.usernameWordlist} onChange={value => change('usernameWordlist', value)} />}
        <WordlistField slot="authPasswords" label="Password wordlist" value={form.passwordWordlist} onChange={value => change('passwordWordlist', value)} />
        <p className="sqlmap-scope">{t('UTF-8 wordlists: up to 16 MB and 10000 unique entries per file. Stops at the first accepted pair or comparison candidate.')}</p>
        {form.mode === 'form' && <div className="auth-form-criteria">
          <div className="sqlmap-fields"><label>{t('Username field name')}<input required value={form.usernameField} onChange={event => change('usernameField', event.target.value)} /></label><label>{t('Password field name')}<input required value={form.passwordField} onChange={event => change('passwordField', event.target.value)} /></label></div>
          <label>{t('Additional form values')}<input value={form.extraBody} onChange={event => change('extraBody', event.target.value)} placeholder="submit=Login" /></label><p className="sqlmap-scope">{t('Field names must match the HTML input name attributes. Add required fixed fields or the submit button as name=value pairs; they are not detected automatically.')}</p>
          <label>{t('Success criterion')}<select aria-label={t('Success criterion')} value={form.successMode} onChange={event => change('successMode', event.target.value as AuthenticationRequest['successMode'])}><option value="auto">{t('Automatic response comparison')}</option><option value="body">{t('Response contains text')}</option><option value="location">{t('Exact redirect address')}</option></select></label>
          {form.successMode === 'auto' ? <p className="sqlmap-notice">{t('No success text is needed. Stable incorrect-password responses are compared with each attempt. A repeatable difference is only a candidate; verify the login manually.')}</p> : <label>{t('Success value')}<input required value={form.successValue} onChange={event => change('successValue', event.target.value)} placeholder={form.successMode === 'body' ? 'Welcome back' : '/account'} /></label>}
          <label>{t('Failed login text')}{form.successMode === 'auto' && <small>{t('Optional in automatic mode')}</small>}<input required={form.successMode !== 'auto'} value={form.failureValue} onChange={event => change('failureValue', event.target.value)} placeholder="Invalid credentials" /></label>
          <p className="sqlmap-scope">{t('POST forms use URL-encoded fields and fixed extra values. Dynamic CSRF, JavaScript login, MFA and SSO flows are not supported in this version.')}</p>
        </div>}
        <details open><summary>{t('Attempt limits')}</summary><div className="sqlmap-fields">{([['maxAttempts', 'Maximum credential attempts', 1, 1000, 1], ['duration', 'Time limit (seconds)', 10, 1800, 1], ['timeout', 'Request timeout (seconds)', 2, 30, 1], ['delay', 'Request delay (seconds)', 0, 10, .1]] as const).map(([key, label, min, max, step]) => <label key={key}>{t(label)}<input type="number" required min={min} max={max} step={step} value={form[key]} onChange={event => change(key, Number(event.target.value))} /></label>)}</div><label>{t('Lockout text')}<input value={form.lockoutValue} onChange={event => change('lockoutValue', event.target.value)} /></label></details>
        <p className="sqlmap-scope">{t('Explicit criteria use one baseline; automatic forms use three reference requests per username and additional comparison checks. Stops on acceptance, a candidate, rate limiting, lockout or ambiguity. Redirects are not followed.')}</p>
        <button className="primary" type="submit" disabled={pending || !runDir || Boolean(state.active)}><Play size={15} />{t('Start authentication test')}</button><p role="status" className="sqlmap-message">{t(message)}</p>
      </form>
      <section className="sqlmap-evidence"><header><h2>{t('Authentication evidence')}</h2><span>{state.jobs.length} {t('jobs')}</span></header>
        {!job ? <p>{t('No authentication tests for this scan yet.')}</p> : <><select aria-label={t('Authentication history')} value={job.jobId} onChange={event => setSelected(event.target.value)}>{state.jobs.map(item => <option key={item.jobId} value={item.jobId}>{item.startedAt.slice(0, 19)} · {t(statuses[item.status])}</option>)}</select><h3 className={`sqlmap-status ${job.status === 'accepted' ? 'detected' : ''}`}>{t(statuses[job.status])}</h3><code className="sqlmap-url">{job.url}</code><p>{attemptCount} / {job.plannedAttempts} {t('credential pairs')} · {job.baselineRequests} {t('baseline requests')}{automaticJob && <> · {job.comparisonRequests ?? 0} {t('comparison requests')}</>}</p><p>{t(job.message || '')}</p>{job.diagnostic && <details><summary>{t('Technical details')}</summary><pre>{job.diagnostic}</pre></details>}{job.finishedAt && attemptCount === 0 && <p className="sqlmap-notice">{t('No wordlist pairs were tested. Check the result message and login settings before retrying.')}</p>}
          {accepted.map((attempt, index) => <section className="auth-success" key={index} aria-label={t('Accepted credentials')}><h3>{t('Accepted credentials')}</h3><span className="sqlmap-payload-label">{t('Username')}</span><pre aria-label={t('Username')}>{attempt.username || t('(empty username)')}</pre><span className="sqlmap-payload-label">{t('Password')}</span><pre aria-label={t('Password')}>{attempt.password || t('(empty password)')}</pre><p>HTTP {attempt.statusCode} · {t(attempt.detail)}</p></section>)}
          {candidates.map((attempt, index) => <section className="auth-candidate" key={index} aria-label={t('Possible successful login — verification required')}><h3>{t('Possible successful login — verification required')}</h3><p>{t('This is a response-comparison candidate, not accepted credentials. Verify the login manually.')}</p><span className="sqlmap-payload-label">{t('Username')}</span><pre aria-label={t('Username')}>{attempt.username || t('(empty username)')}</pre><span className="sqlmap-payload-label">{t('Password')}</span><pre aria-label={t('Password')}>{attempt.password || t('(empty password)')}</pre><p>HTTP {attempt.statusCode} · {t(attempt.detail)}</p></section>)}
          {other.length > 0 && <section className="auth-other-outcomes"><h3>{t('Other outcomes')}</h3>{other.map((attempt, index) => <article key={index}><strong>{attempt.username || t('(empty username)')} · HTTP {attempt.statusCode}</strong><span className="sqlmap-payload-label">{t('Password')}</span><pre aria-label={t('Password')}>{attempt.password || t('(empty password)')}</pre><p>{t(attempt.outcome)} · {t(attempt.detail)}</p></article>)}</section>}
          {rejectedCount > 0 && <section className="auth-failed-section"><button type="button" className="auth-failed-toggle" aria-expanded={failedOpen} aria-controls="auth-failed-list" onClick={() => setFailedOpen(value => !value)}>{t(automaticJob ? failedOpen ? 'Hide reference-matching attempts' : 'See reference-matching attempts' : failedOpen ? 'Hide failed attempts' : 'See failed attempts')}<span>{rejectedCount}</span></button>
            {failedOpen && <div id="auth-failed-list"><div className="auth-attempts">{rejected.map((attempt, index) => <article key={index}><strong>{attempt.username || t('(empty username)')} · HTTP {attempt.statusCode}</strong><span className="sqlmap-payload-label">{t('Password')}</span><pre aria-label={t('Password')}>{attempt.password || t('(empty password)')}</pre><p>{t(attempt.outcome)} · {t(attempt.detail)}</p></article>)}</div>
              {(job.rejectedPages ?? 1) > 1 && <nav className="auth-attempt-pages" aria-label={t('Failed attempts pages')}><button type="button" disabled={(job.rejectedPage ?? 0) === 0} onClick={() => setFailedPage((job.rejectedPage ?? 0) - 1)}>{t('Previous')}</button><span>{t('Page {page} of {pages}', { page: (job.rejectedPage ?? 0) + 1, pages: job.rejectedPages ?? 1 })}</span><button type="button" disabled={(job.rejectedPage ?? 0) >= (job.rejectedPages ?? 1) - 1} onClick={() => setFailedPage((job.rejectedPage ?? 0) + 1)}>{t('Next')}</button></nav>}
            </div>}
          </section>}
          <div className="sqlmap-actions"><button disabled={job.status === 'running' || !job.finishedAt} onClick={() => { void window.reconbot.openPath(job.reportPath).then(result => { if (!result.ok) setMessage(result.message || ''); }); }}><FileText size={14} />{t('Open authentication report')}</button><button onClick={() => { void window.reconbot.openPath(job.jobDir); }}>{t('Open evidence folder')}</button></div>
        </>}
      </section>
    </div>
    <section className="sqlmap-console"><header><h2>{t('Live authentication output')}</h2><label><input type="checkbox" checked={follow} onChange={event => setFollow(event.target.checked)} />{t('Follow output')}</label></header><pre ref={log}>{state.log || t('Output will appear when validation starts.')}</pre><small>{t('Shows the latest 64 KB of output. Complete logs are kept in the evidence folder.')}</small></section>
  </section>;
}
