"""Explicit HTTP authentication wordlist tests with independent run evidence."""
from __future__ import annotations

import argparse
import html
import itertools
import json
import os
from pathlib import Path
import re
import signal
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit, urljoin, parse_qsl

import requests
from .sqlmap import atomic_json
from .authentication_compare import fingerprint, response_problem, http_issue


class DeadlineReached(Exception):
    pass


def persist(job: Path, result: dict) -> None:
    result['attemptCount'] = len(result['attempts'])
    atomic_json(job / 'result.json', result)
    atomic_json(job / 'summary.json', {**result, 'attempts': []})


def validate_request(value: dict) -> dict:
    result = dict(value)
    url, origin = urlsplit(str(value.get('url', ''))), urlsplit(str(value.get('target', '')))
    if not origin.scheme:
        origin = urlsplit('http://' + str(value.get('target', '')))
    if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.fragment or any(c in value['url'] for c in '\r\n\0'):
        raise ValueError('Use an HTTP(S) URL without embedded credentials or fragments.')
    key = lambda p: (p.hostname.lower() if p.hostname else '', p.port or (443 if p.scheme == 'https' else 80))
    if key(url) != key(origin):
        raise ValueError('The validation URL must belong to the selected scan target (same host and port).')
    if value.get('mode') not in ('basic', 'form') or value.get('usernameSource') not in ('single', 'wordlist'):
        raise ValueError('Invalid authentication method or username source.')
    for name in ('username', 'usernameWordlist', 'passwordWordlist', 'usernameField', 'passwordField', 'extraBody', 'successValue', 'failureValue', 'lockoutValue'):
        text = value.get(name)
        if not isinstance(text, str) or '\0' in text or len(text) > (16384 if name == 'extraBody' else 4096):
            raise ValueError('Invalid authentication input.')
    if not value['passwordWordlist'].strip() or not (value['username'] if value['usernameSource'] == 'single' else value['usernameWordlist'].strip()):
        raise ValueError('Choose a username and password wordlist.')
    if value['mode'] == 'basic' and value['usernameSource'] == 'single' and (':' in value['username'] or any(c in value['username'] for c in '\r\n')):
        raise ValueError('HTTP Basic usernames cannot contain colon or newline characters.')
    if value['mode'] == 'form':
        for name in ('usernameField', 'passwordField'):
            if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.\[\]-]{0,127}', value[name]):
                raise ValueError('Enter the exact username and password form field names.')
        if value['usernameField'] == value['passwordField']:
            raise ValueError('Username and password form fields must be different.')
        if any(name in (value['usernameField'], value['passwordField']) for name, _ in parse_qsl(value['extraBody'], keep_blank_values=True)):
            raise ValueError('Additional form values must not overwrite credential fields.')
        if value.get('successMode') not in ('auto', 'body', 'location'):
            raise ValueError('Choose automatic comparison or an explicit success criterion.')
        if value['successMode'] != 'auto' and (len(value['successValue'].strip()) < 3 or len(value['failureValue'].strip()) < 3):
            raise ValueError('Set explicit success and failure indicators for the login form.')
        if value['successMode'] == 'auto' and value['failureValue'] and len(value['failureValue'].strip()) < 3:
            raise ValueError('Optional failed login text must contain at least three characters.')
        if value['successMode'] == 'body' and value['successValue'] == value['failureValue']:
            raise ValueError('Success and failure indicators must be different.')
        if value['successMode'] == 'location':
            destination = urlsplit(urljoin(value['url'], value['successValue']))
            if (destination.scheme, key(destination)) != (url.scheme, key(url)) or destination.username or destination.password or destination.fragment:
                raise ValueError('The success redirect must be on the same origin.')
    for name, low, high in [('maxAttempts', 1, 1000), ('duration', 10, 1800), ('timeout', 2, 30)]:
        number = value.get(name)
        if type(number) is not int or not low <= number <= high:
            raise ValueError(f'{name} must be an integer between {low} and {high}.')
    delay = value.get('delay')
    if type(delay) not in (int, float) or not 0 <= delay <= 10:
        raise ValueError('Request delay must be between 0 and 10 seconds.')
    return result


def read_wordlist(file: str, basic_username: bool = False) -> list[str]:
    path = Path(file)
    if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('Wordlists must be readable UTF-8 files up to 16 MB.')
    values, seen = [], set()
    with path.open(encoding='utf-8-sig') as stream:
        for line in stream:
            value = line.rstrip('\r\n')
            if '\0' in value or len(value) > 4096 or basic_username and ':' in value:
                raise ValueError('A wordlist entry contains invalid characters or is too long.')
            if value not in seen:
                values.append(value); seen.add(value)
            if len(values) > 10000:
                raise ValueError('A wordlist can contain up to 10000 unique entries.')
    if not values:
        raise ValueError('The wordlist is empty.')
    return values


def request_response(config: dict, username: str | None, password: str | None) -> tuple[int, str, str, dict]:
    # Fresh sessions prevent a previously authenticated cookie from accepting
    # the next password. Ambient proxies/netrc credentials are not inherited.
    with requests.Session() as session:
        session.trust_env = False
        kwargs = {'timeout': config['timeout'], 'allow_redirects': False, 'stream': True}
        if config['mode'] == 'basic':
            response = session.get(config['url'], auth=(username, password) if username is not None else None, **kwargs)
        else:
            body = parse_qsl(config['extraBody'], keep_blank_values=True) + [(config['usernameField'], username), (config['passwordField'], password)]
            response = session.post(config['url'], data=body, **kwargs)
        with response:
            data = bytearray()
            for chunk in response.iter_content(4096):
                data.extend(chunk)
                if len(data) > 65536:
                    raise ValueError('Login response exceeded 64 KB; use a smaller explicit login endpoint.')
            text = bytes(data).decode(response.encoding or 'utf-8', errors='replace')
            return response.status_code, text, response.headers.get('Location', ''), {key.lower(): value for key, value in response.headers.items()}


def classify(config: dict, response: tuple) -> tuple[str, str]:
    code, text, location, headers = response
    if code == 429 or headers.get('retry-after') or config['lockoutValue'] and config['lockoutValue'].casefold() in text.casefold():
        return 'blocked', 'Rate limit or configured lockout indicator detected; stopped.'
    if config['mode'] == 'basic':
        if code == 401:
            return 'rejected', 'HTTP 401 challenge.'
        if 200 <= code < 300:
            return 'accepted', 'Successful HTTP response after a verified Basic challenge.'
        return 'inconclusive', http_issue(config['mode'], code) or 'The endpoint returned an unexpected HTTP response.'
    success = config['successValue'] in text if config['successMode'] == 'body' else 300 <= code < 400 and urljoin(config['url'], location) == urljoin(config['url'], config['successValue']) and bool(location)
    failure = config['failureValue'] in text
    if success and not failure and 200 <= code < 400:
        return 'accepted', 'The configured success indicator matched without the failure indicator.'
    if failure and not success and code not in (403, 500, 502, 503, 504):
        return 'rejected', 'The configured failure indicator matched.'
    return 'inconclusive', http_issue(config['mode'], code) or 'Success/failure indicators did not distinguish this response.'


def run_automatic(job, config, users, passwords, result, log, deadline, check_cancel):
    reference = None
    reference_user = None

    def fetch(username, password, kind):
        check_cancel()
        end = time.monotonic() + (config['delay'] if result['baselineRequests'] or result['attempts'] or result['comparisonRequests'] else 0)
        while time.monotonic() < end:
            check_cancel()
            if time.monotonic() >= deadline:
                raise DeadlineReached()
            time.sleep(min(.05, max(0, end - time.monotonic())))
        if time.monotonic() >= deadline:
            raise DeadlineReached()
        if kind:
            result[kind] += 1
        response = request_response(config, username, password)
        if kind is None:
            result['attempts'].append(dict(username=username, password=password, statusCode=response[0], outcome='inconclusive', detail='Form response is being checked; acceptance was not established.', responseEvidence=fingerprint(config, response, username, password), referenceEvidence=reference))
            persist(job, result)
        check_cancel()
        if time.monotonic() >= deadline:
            raise DeadlineReached()
        return response

    for username, password in itertools.islice(itertools.product(users, passwords), config['maxAttempts']):
        if reference_user != username:
            references = []
            for _ in range(3):
                wrong = 'reconbot_probe_' + uuid.uuid4().hex
                response = fetch(username, wrong, 'baselineRequests')
                problem = response_problem(config, response)
                if problem:
                    result.update(status=problem[0], message=problem[1])
                    return
                if config['failureValue'] and config['failureValue'] not in response[1]:
                    result.update(status='inconclusive', message='The optional failure indicator did not match the reference responses. No further attempts were sent.')
                    return
                references.append(fingerprint(config, response, username, wrong))
                persist(job, result)
            if references[0] != references[1] or references[0] != references[2]:
                result.update(status='inconclusive', message='Reference responses were unstable. Use an explicit success criterion for this form.')
                return
            reference, reference_user = references[0], username
            log.write('Three stable incorrect-password reference responses recorded for this username.\n'); log.flush()
        response = fetch(username, password, None)
        problem = response_problem(config, response)
        observed = fingerprint(config, response, username, password)
        if problem:
            outcome, detail = problem
        elif observed == reference:
            outcome, detail = 'baseline_match', 'Response matched the incorrect-password reference; acceptance was not established.'
        elif config['failureValue'] and config['failureValue'] in response[1]:
            outcome, detail = 'rejected', 'The configured failure indicator matched.'
        else:
            # Reproduce the difference, then ensure an incorrect-password
            # control still matches. All extra requests obey delay/deadline.
            repeat = fetch(username, password, 'comparisonRequests')
            problem = response_problem(config, repeat)
            if problem:
                outcome, detail = problem
            elif fingerprint(config, repeat, username, password) != observed:
                outcome, detail = 'inconclusive', 'The changed response did not repeat consistently; stopped.'
            else:
                wrong = 'reconbot_probe_' + uuid.uuid4().hex
                control = fetch(username, wrong, 'comparisonRequests')
                problem = response_problem(config, control)
                if problem:
                    outcome, detail = problem
                elif fingerprint(config, control, username, wrong) != reference:
                    outcome, detail = 'inconclusive', 'The incorrect-password control changed too; stopped without identifying a candidate.'
                else:
                    outcome, detail = 'candidate', 'A repeatable response difference was found. Manual login verification is required; acceptance was not established.'
        attempt = dict(username=username, password=password, statusCode=response[0], outcome=outcome, detail=detail, responseEvidence=observed, referenceEvidence=reference)
        result['attempts'][-1] = attempt
        log.write(json.dumps(attempt, ensure_ascii=False) + '\n'); log.flush()
        persist(job, result)
        if outcome not in ('baseline_match', 'rejected'):
            result.update(status=outcome, message=detail)
            return
    complete = len(result['attempts']) == result['plannedAttempts']
    result.update(status='no_candidate' if complete else 'attempt_limit', message='No candidate was identified in the tested pairs. Matching the reference does not independently verify rejection.' if complete else 'Attempt limit reached; remaining pairs were not tested.')


def write_report(job: Path, result: dict) -> None:
    esc = lambda value: html.escape(str(value))
    labels = {'accepted': 'Credentials accepted', 'candidate': 'Possible successful login — verification required', 'baseline_match': 'Matches incorrect-password response', 'rejected': 'Credentials rejected', 'inconclusive': 'Inconclusive', 'blocked': 'Rate limit or lockout detected'}
    def table(items):
        rows = ''.join('<tr>' + ''.join(f'<td>{esc(labels.get(item.get(key), item.get(key, "")) if key == "outcome" else item.get(key, ""))}</td>' for key in ('username', 'password', 'statusCode', 'outcome', 'detail')) + '</tr>' for item in items)
        return f'<table><thead><tr><th>Username</th><th>Password</th><th>HTTP status</th><th>Outcome</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table>'
    accepted = [item for item in result['attempts'] if item['outcome'] == 'accepted']
    candidates = [item for item in result['attempts'] if item['outcome'] == 'candidate']
    rejected = [item for item in result['attempts'] if item['outcome'] in ('rejected', 'baseline_match')]
    other = [item for item in result['attempts'] if item['outcome'] not in ('accepted', 'candidate', 'rejected', 'baseline_match')]
    success = f'<section class="accepted"><h2>Accepted credentials</h2>{table(accepted)}</section>' if accepted else ''
    candidate_section = f'<section class="candidate"><h2>Possible successful login — verification required</h2><p>This is a response-comparison candidate, not accepted credentials. Verify the login manually.</p>{table(candidates)}</section>' if candidates else ''
    failed_label = 'See reference-matching attempts' if result.get('successMode') == 'auto' and result['mode'] == 'form' else 'See failed attempts'
    failed = f'<details class="failed-attempts"><summary>{failed_label} ({len(rejected)})</summary>{table(rejected)}</details>' if rejected else ''
    outcomes = f'<section><h2>Other outcomes</h2>{table(other)}</section>' if other else ''
    text = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>ReconBot · Authentication testing</title><style>body{{background:#11161c;color:#e4ebf2;font:16px system-ui;margin:0;padding:40px}}h1,.accepted h2{{color:#5de0c9}}.candidate{{border-left:3px solid #dfb566;padding-left:20px;margin:24px 0}}.candidate h2{{color:#dfb566}}.accepted{{border-left:3px solid #5de0c9;padding-left:20px;margin:24px 0}}details{{margin:24px 0}}summary{{cursor:pointer;padding:16px 0;color:#9bacbb}}code,td{{overflow-wrap:anywhere;white-space:pre-wrap}}table{{border-collapse:collapse;width:100%;table-layout:fixed}}td,th{{border-bottom:1px solid #354450;padding:12px;text-align:left}}dt{{color:#9bacbb}}dd{{margin:8px 0 20px}}a{{color:#5de0c9}}@media(max-width:700px){{body{{padding:16px}}td,th{{padding:6px;font-size:12px}}}}</style><h1>Authentication testing</h1><p>Independent explicit test · original scan score unchanged</p>{success}{candidate_section}<dl><dt>Status</dt><dd>{esc(result['status'])}</dd><dt>URL</dt><dd><code>{esc(result['url'])}</code></dd><dt>Method</dt><dd>{esc(result['mode'])}</dd><dt>Message</dt><dd>{esc(result.get('message', ''))}</dd><dt>Credential attempts / planned pairs</dt><dd>{len(result['attempts'])} / {result['plannedAttempts']}</dd><dt>Baseline requests</dt><dd>{result['baselineRequests']}</dd><dt>Additional comparison requests</dt><dd>{result.get('comparisonRequests', 0)}</dd><dt>Originating scan</dt><dd>{esc(result['runDir'])}</dd></dl><p>Accepted means the configured endpoint and success criterion accepted this pair. It does not establish access to other services. A comparison candidate is not confirmed acceptance. Reference-matching responses do not independently prove rejection. A negative result applies only to the tested pairs. Limits, lockout, timeout and incomplete responses cannot establish that passwords are secure.</p>{outcomes}{failed}<p><a href="authentication.log">Full log</a> · <a href="result.json">Structured evidence</a> · <a href="request.json">Request settings</a></p></html>'''
    temporary = job / 'report.tmp'
    temporary.write_text(text, encoding='utf-8')
    os.replace(temporary, job / 'report.html')


def run_job(job: Path) -> dict:
    config = json.loads((job / 'request.json').read_text(encoding='utf-8'))
    result = {**config, 'jobId': job.name, 'jobDir': str(job), 'reportPath': str(job / 'report.html'), 'startedAt': datetime.now(timezone.utc).isoformat(), 'status': 'running', 'attempts': [], 'baselineRequests': 0, 'comparisonRequests': 0, 'plannedAttempts': 0}
    job.chmod(0o700)
    def check_cancel():
        if (job / 'cancel.request').exists():
            raise KeyboardInterrupt()
    try:
        check_cancel()
        config = validate_request(config)
        users = [config['username']] if config['usernameSource'] == 'single' else read_wordlist(config['usernameWordlist'], config['mode'] == 'basic')
        passwords = read_wordlist(config['passwordWordlist'])
        result['plannedAttempts'] = len(users) * len(passwords)
        persist(job, result)
        deadline = time.monotonic() + config['duration']
        with (job / 'authentication.log').open('w', encoding='utf-8') as log:
            log.write('Checking login failure baseline before wordlist attempts.\n'); log.flush()
            if config['mode'] == 'form' and config['successMode'] == 'auto':
                run_automatic(job, config, users, passwords, result, log, deadline, check_cancel)
            else:
                run_explicit(job, config, users, passwords, result, log, deadline, check_cancel)
    except KeyboardInterrupt:
        result.update(status='cancelled', message='Authentication testing cancelled; completed evidence retained.')
    except DeadlineReached:
        result.update(status='timed_out', message='Time limit reached; completed evidence retained.')
    except requests.exceptions.SSLError as error:
        result.update(status='failed', message='TLS connection failed. Check the server certificate and HTTPS endpoint.', diagnostic=str(error))
    except requests.exceptions.Timeout as error:
        result.update(status='failed', message='The login request timed out. Check server availability and the request timeout.', diagnostic=str(error))
    except requests.exceptions.ConnectionError as error:
        result.update(status='failed', message='Could not connect to the login endpoint. Start the server and check the host and port.', diagnostic=str(error))
    except Exception as error:
        result.update(status='failed', message=str(error))
    result['finishedAt'] = datetime.now(timezone.utc).isoformat()
    persist(job, result)
    write_report(job, result)
    return result


def run_explicit(job, config, users, passwords, result, log, deadline, check_cancel):
    check_cancel()
    result['baselineRequests'] = 1
    response = request_response(config, None if config['mode'] == 'basic' else 'reconbot_probe_' + uuid.uuid4().hex, None if config['mode'] == 'basic' else uuid.uuid4().hex)
    outcome, detail = classify(config, response)
    if outcome == 'blocked':
        result.update(status='blocked', message=detail)
    elif outcome != 'rejected' or config['mode'] == 'basic' and not re.search(r'\bBasic\b', response[3].get('www-authenticate', ''), re.I):
        result.update(status='inconclusive', message=http_issue(config['mode'], response[0]) or 'The endpoint did not establish an unambiguous failed-login baseline. No wordlist attempts were sent.')
    else:
        for username, password in itertools.islice(itertools.product(users, passwords), config['maxAttempts']):
            check_cancel()
            if time.monotonic() >= deadline:
                raise DeadlineReached()
            # Includes a delay after the baseline and between attempts.
            end = time.monotonic() + config['delay']
            while time.monotonic() < end:
                check_cancel()
                if time.monotonic() >= deadline: raise DeadlineReached()
                time.sleep(min(.05, max(0, end - time.monotonic())))
            code_response = request_response(config, username, password)
            outcome, detail = classify(config, code_response)
            result['attempts'].append({'username': username, 'password': password, 'statusCode': code_response[0], 'outcome': outcome, 'detail': detail})
            log.write(json.dumps(result['attempts'][-1], ensure_ascii=False) + '\n'); log.flush()
            persist(job, result)
            if outcome != 'rejected':
                result.update(status=outcome, message=detail)
                break
        else:
            complete = len(result['attempts']) == result['plannedAttempts']
            result.update(status='not_accepted' if complete else 'attempt_limit', message='All selected credential pairs were rejected.' if complete else 'Attempt limit reached; remaining pairs were not tested.')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job-dir', required=True)
    args = parser.parse_args()
    job = Path(args.job_dir).resolve()
    def interrupted(*_): raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    def expired(*_): raise DeadlineReached()
    signal.signal(signal.SIGALRM, expired)
    print(json.dumps({'workerReady': True}), flush=True)
    # Hard wall-clock deadline also bounds DNS, slow streaming and TLS reads.
    try:
        config = json.loads((job / 'request.json').read_text())
        duration = config.get('duration')
        if type(duration) is int and 10 <= duration <= 1800:
            signal.setitimer(signal.ITIMER_REAL, duration)
        run_job(job)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    main()
