"""Bounded SQLmap detection job with durable, run-associated evidence."""
from __future__ import annotations

import argparse
import html
import json
import os
from pathlib import Path
import re
import shutil
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit, parse_qs

from reconbot.runtime import processes


def atomic_json(path: Path, value: dict) -> None:
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    temp.chmod(0o600)
    os.replace(temp, path)


def validate_request(request: dict) -> dict:
    url = str(request.get('url', '')).strip()
    target = str(request.get('target', '')).strip()
    parsed, origin = urlsplit(url), urlsplit(target if '://' in target else 'http://' + target)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Use an HTTP(S) URL without embedded credentials or fragments.')
    if (parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == 'https' else 80)) != (origin.hostname.lower() if origin.hostname else '', origin.port or (443 if origin.scheme == 'https' else 80)):
        raise ValueError('The validation URL must belong to the selected scan target (same host and port).')
    if any(c in url for c in '\r\n\x00'):
        raise ValueError('Invalid URL characters.')
    parameter = str(request.get('parameter', '')).strip()
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.\[\]-]{0,127}', parameter):
        raise ValueError('Enter one parameter name (for example id).')
    method = request.get('method', 'GET')
    if method not in ('GET', 'POST'):
        raise ValueError('Method must be GET or POST.')
    body = str(request.get('body', ''))
    if len(body) > 65536 or '\x00' in body:
        raise ValueError('POST body is invalid or too large.')
    params = parse_qs(parsed.query if method == 'GET' else body, keep_blank_values=True)
    if parameter not in params:
        raise ValueError('The selected parameter must occur in the URL query or form-encoded POST body.')
    cookie = str(request.get('cookie', ''))
    if len(cookie) > 16384 or any(c in cookie for c in '\r\n\x00'):
        raise ValueError('Cookie must be a single header value.')
    result = {**request, 'url': url, 'parameter': parameter, 'method': method, 'body': body, 'cookie': cookie}
    for key, default, low, high in [('level', 1, 1, 3), ('risk', 1, 1, 2), ('duration', 180, 10, 1800), ('timeout', 10, 2, 60), ('threads', 1, 1, 3)]:
        value = request.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f'{key} must be an integer between {low} and {high}.')
        result[key] = value
    delay = request.get('delay', 0.2)
    if isinstance(delay, bool) or not isinstance(delay, (int, float)) or not 0 <= delay <= 5:
        raise ValueError('Delay must be between 0 and 5 seconds.')
    result['delay'] = delay
    return result


def build_command(request: dict, output: Path, executable: str) -> list[str]:
    command = [executable, '-u', request['url'], '-p', request['parameter'], '--batch', '--disable-coloring',
               '--output-dir', str(output), '--level', str(request['level']), '--risk', str(request['risk']),
               '--timeout', str(request['timeout']), '--retries', '0', '--threads', str(request['threads']),
               '--delay', str(request['delay']), '--param-filter', request['method'], '--technique', 'BEU', '--skip-waf', '--ignore-redirects', '-v', '1']
    # Detection only: no database enumeration, data extraction, shell or file access.
    if request['method'] == 'POST':
        command += ['--method', 'POST', '--data=' + request['body']]
    if request['cookie']:
        command += ['--cookie=' + request['cookie']]
    return command


def parse_evidence(raw: str, parameter: str, method: str | None = None) -> list[dict]:
    evidence = []
    for match in re.finditer(r'^Parameter:\s*(.+?)\s*\(([^)]+)\)\s*\n(.*?)(?=^Parameter:|^---|\Z)', raw, re.M | re.S):
        if match[1].strip() != parameter or (method is not None and match[2].strip() != method):
            continue
        for item in re.finditer(r'^\s+Type:\s*(.+)\n\s+Title:\s*(.+)\n\s+Payload:\s*(.+)', match[3], re.M):
            evidence.append({'parameter': parameter, 'place': match[2], 'type': item[1].strip(), 'title': item[2].strip(), 'payload': item[3].strip()})
    return evidence


def classify(raw: str, evidence: list, exit_code: int | None, interrupted: str | None) -> str:
    if interrupted:
        return interrupted
    if exit_code != 0:
        return 'failed'
    if evidence:
        return 'detected'
    no_match = 'all tested parameters do not appear to be injectable'
    errors = '\n'.join(line for line in raw.splitlines() if no_match not in line)
    if '[CRITICAL]' in errors or '[ERROR]' in errors:
        return 'failed'
    if no_match in raw and re.search(r'(?:\[\*\]\s*ending @|\[ending @)', raw):
        return 'not_detected'
    return 'inconclusive'


def write_report(job: Path, result: dict) -> None:
    esc = lambda value: html.escape(str(value))
    rows = ''.join(f'<article><h3>{esc(e["title"])}</h3><p>{esc(e["parameter"])} ({esc(e["place"])}) · {esc(e["type"])}</p><p class="payload-label">Payload</p><pre aria-label="Payload">{esc(e["payload"])}</pre></article>' for e in result['evidence'])
    text = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>ReconBot · SQLmap validation</title><style>body{{background:#11161c;color:#e4ebf2;font:16px system-ui;margin:0;padding:40px;max-width:1100px}}h1{{color:#5de0c9}}article{{border-top:1px solid #354450;padding:20px 0}}pre,code{{white-space:pre-wrap;overflow-wrap:anywhere;background:#1c242d;padding:12px;display:block}}dt{{color:#9bacbb}}dd{{margin:8px 0 20px}}a{{color:#5de0c9}}</style><h1>SQLmap validation</h1><p>Independent detection job · baseline scan score unchanged</p><dl><dt>Status</dt><dd>{esc(result['status'])}</dd><dt>URL</dt><dd><code>{esc(result['url'])}</code></dd><dt>Scope</dt><dd>{esc(result['method'])} parameter: {esc(result['parameter'])} · level {result['level']} / risk {result['risk']} · techniques BEU</dd><dt>Originating scan</dt><dd>{esc(result['runDir'])}</dd><dt>Finished</dt><dd>{esc(result.get('finishedAt', ''))}</dd><dt>Message</dt><dd>{esc(result.get('message', ''))}</dd></dl><p>A negative result applies only to this parameter and these techniques. Interrupted, failed and timed-out jobs are incomplete. Retained injection evidence still needs operator review.</p>{rows}<p><a href="sqlmap.log">Raw console log</a> · <a href="result.json">Structured evidence</a> · <a href="request.json">Exact request settings</a></p></html>'''
    temp = job / 'report.tmp'
    temp.write_text(text, encoding='utf-8')
    os.replace(temp, job / 'report.html')


def run_job(job: Path, executable: str | None = None) -> dict:
    job.chmod(0o700)
    request = validate_request(json.loads((job / 'request.json').read_text(encoding='utf-8')))
    result = {**request, 'jobId': job.name, 'jobDir': str(job), 'status': 'running', 'evidence': [], 'startedAt': datetime.now(timezone.utc).isoformat(), 'reportPath': str(job / 'report.html')}
    atomic_json(job / 'result.json', result)
    exit_code, interrupted = None, None
    try:
        if (job / 'cancel.request').exists():
            raise KeyboardInterrupt('Cancelled before SQLmap startup')
        executable = executable or shutil.which('sqlmap')
        if not executable:
            raise FileNotFoundError('SQLmap is not installed or is not on PATH. Install SQLmap and restart ReconBot.')
        command = build_command(request, job / 'raw', executable)
        result['command'] = command
        atomic_json(job / 'result.json', result)
        with processes.process_scope(), (job / 'sqlmap.log').open('w', encoding='utf-8') as log:
            proc = processes.Popen(command, stdout=log, stderr=processes.STDOUT, stdin=processes.DEVNULL)
            print(json.dumps({'scannerPid': proc.pid}), flush=True)
            deadline = time.monotonic() + request['duration']
            while proc.poll() is None:
                if (job / 'cancel.request').exists():
                    interrupted = 'cancelled'
                    break
                if time.monotonic() >= deadline:
                    interrupted = 'timed_out'
                    break
                time.sleep(0.1)
            exit_code = proc.poll()
    except KeyboardInterrupt:
        interrupted = 'cancelled'
    except Exception as exc:
        result['message'] = str(exc)
        interrupted = 'failed'
    raw = (job / 'sqlmap.log').read_text(encoding='utf-8', errors='replace') if (job / 'sqlmap.log').exists() else ''
    # Canonical per-target log contains complete injection-point blocks; console
    # is retained for completion/error classification, rather than invented proof.
    proof = '\n'.join(p.read_text(encoding='utf-8', errors='replace') for p in (job / 'raw').glob('*/log'))
    result['evidence'] = parse_evidence(proof, request['parameter'], request['method'])
    result.update(status=classify(raw, result['evidence'], exit_code, interrupted), exitCode=exit_code, finishedAt=datetime.now(timezone.utc).isoformat())
    write_report(job, result)
    atomic_json(job / 'result.json', result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--job-dir', required=True)
    args = parser.parse_args()
    try:
        result = run_job(Path(args.job_dir).resolve())
        print(json.dumps({'status': result['status'], 'jobId': result['jobId']}), flush=True)
    except Exception as exc:
        print(str(exc), flush=True)
        raise SystemExit(2)


if __name__ == '__main__':
    main()
