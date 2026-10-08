import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
from urllib.parse import parse_qs
import uuid

import pytest

from reconbot.validation.authentication import DeadlineReached, run_job, validate_request


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        values = parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode(), keep_blank_values=True)
        username, password = values['username'][0], values['password'][0]
        probe = password.startswith('reconbot_probe_')
        valid = username == 'operator' and password == 'secret'
        self.server.requests_seen.append((self.path, username, password))
        count = len(self.server.requests_seen)
        code, body, headers = 200, 'Welcome operator' if valid else 'Invalid credentials', {}
        if self.path in ('/http404', '/http405', '/http400', '/http403', '/http503'):
            code, body = int(self.path[5:]), 'Endpoint error'
        elif self.path == '/same':
            body = 'Public page'
        elif self.path == '/reflect' and not valid:
            body += ' ' + username + ' ' + password
        elif self.path == '/enum' and username != 'operator':
            body = 'Unknown user'
        elif self.path == '/dynamic':
            body += ' ' + uuid.uuid4().hex
        elif self.path == '/drift' and count >= 5:
            body = 'Different page for everybody'
        elif self.path == '/nonrepeat' and valid and count % 2 == 0:
            body = 'Invalid credentials'
        elif self.path == '/error' and valid:
            code, body = 500, 'Server error'
        elif self.path == '/challenge' and valid:
            body = 'Please complete a CAPTCHA'
        elif self.path == '/rate' and not probe:
            code, body, headers = 429, 'Try later', {'Retry-After': '60'}
        elif self.path == '/lockout' and not probe:
            body = 'account locked'
        elif self.path == '/external' and valid:
            code, body, headers = 302, '', {'Location': 'https://outside.invalid/account'}
        elif self.path == '/redirect' and valid:
            code, body, headers = 302, '', {'Location': '/account'}
        elif self.path == '/blank':
            body = ''
        elif self.path == '/cookies':
            body, headers = 'Invalid credentials', {'Set-Cookie': 'token=' + uuid.uuid4().hex}
        data = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def site():
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.requests_seen = []
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def config(tmp_path, site, route='/normal'):
    passwords = tmp_path / 'passwords.txt'
    passwords.write_text('wrong-password\nsecret\n')
    users = tmp_path / 'users.txt'
    users.write_text('unknown-user\noperator\n')
    base = f'http://127.0.0.1:{site.server_port}'
    return dict(runDir=str(tmp_path), target=base, url=base + route, mode='form', usernameSource='single', username='operator', usernameWordlist=str(users), passwordWordlist=str(passwords), usernameField='username', passwordField='password', extraBody='', successMode='auto', successValue='', failureValue='', lockoutValue='account locked', maxAttempts=300, duration=10, timeout=2, delay=0)


def execute(tmp_path, value):
    folder = tmp_path / 'job'
    folder.mkdir()
    (folder / 'request.json').write_text(json.dumps(value))
    return run_job(folder)


@pytest.mark.parametrize('route', ['/normal', '/reflect', '/redirect', '/challenge'])
def test_repeatable_change_is_only_candidate_with_control_and_report(tmp_path, site, route):
    result = execute(tmp_path, config(tmp_path, site, route))
    assert result['status'] == 'candidate'
    assert result['baselineRequests'] == 3 and result['comparisonRequests'] == 2
    assert [item['outcome'] for item in result['attempts']] == ['baseline_match', 'candidate']
    assert result['attempts'][-1]['password'] == 'secret'
    assert len(site.requests_seen) == 7
    assert all(item[0] == route for item in site.requests_seen)  # redirects not followed
    report = (tmp_path / 'job/report.html').read_text()
    assert report.index('Possible successful login — verification required') < report.index('See reference-matching attempts')
    assert '<h2>Accepted credentials</h2>' not in report
    assert 'not accepted credentials' in report


@pytest.mark.parametrize('route', ['/same', '/cookies'])
def test_same_response_and_cookie_changes_never_prove_acceptance(tmp_path, site, route):
    result = execute(tmp_path, config(tmp_path, site, route))
    assert result['status'] == 'no_candidate'
    assert result['comparisonRequests'] == 0 and len(site.requests_seen) == 5
    assert all(item['outcome'] == 'baseline_match' for item in result['attempts'])


def test_reference_is_specific_to_each_username_not_account_enumeration(tmp_path, site):
    value = config(tmp_path, site, '/enum')
    value['usernameSource'] = 'wordlist'
    result = execute(tmp_path, value)
    assert result['status'] == 'candidate' and result['baselineRequests'] == 6
    assert len(result['attempts']) == 4
    assert [item['outcome'] for item in result['attempts']] == ['baseline_match'] * 3 + ['candidate']
    assert result['attempts'][-1]['username'] == 'operator'


@pytest.mark.parametrize('route,baseline,pairs', [('/dynamic', 3, 0), ('/blank', 1, 0), ('/drift', 3, 2), ('/nonrepeat', 3, 2), ('/error', 3, 2), ('/external', 3, 2)])
def test_unstable_error_and_external_redirects_are_inconclusive(tmp_path, site, route, baseline, pairs):
    result = execute(tmp_path, config(tmp_path, site, route))
    assert result['status'] == 'inconclusive'
    assert result['baselineRequests'] == baseline and len(result['attempts']) == pairs
    assert not any(item['outcome'] in ('accepted', 'candidate') for item in result['attempts'])


@pytest.mark.parametrize('route', ['/rate', '/lockout'])
def test_stop_conditions_apply_to_automatic_attempts(tmp_path, site, route):
    result = execute(tmp_path, config(tmp_path, site, route))
    assert result['status'] == 'blocked' and result['baselineRequests'] == 3
    assert len(result['attempts']) == 1 and len(site.requests_seen) == 4


def test_optional_failure_indicator_and_attempt_limit(tmp_path, site):
    value = config(tmp_path, site)
    value.update(failureValue='Invalid credentials', maxAttempts=1)
    result = execute(tmp_path, value)
    assert result['status'] == 'attempt_limit' and result['comparisonRequests'] == 0


def test_wrong_optional_indicator_stops_before_wordlist(tmp_path, site):
    value = config(tmp_path, site)
    value['failureValue'] = 'Not the actual failure'
    result = execute(tmp_path, value)
    assert result['status'] == 'inconclusive' and result['attempts'] == []


def test_long_wordlist_and_all_wrong_list_keep_candidate_distinct(tmp_path, site):
    value = config(tmp_path, site)
    Path(value['passwordWordlist']).write_text(''.join(f'wrong-{i}\n' for i in range(250)) + 'secret\n')
    result = execute(tmp_path, value)
    assert result['status'] == 'candidate' and len(result['attempts']) == 251
    assert result['baselineRequests'] == 3 and result['comparisonRequests'] == 2
    assert all(item['outcome'] == 'baseline_match' for item in result['attempts'][:-1])


def test_all_wrong_list_does_not_claim_independently_verified_rejection(tmp_path, site):
    value = config(tmp_path, site)
    Path(value['passwordWordlist']).write_text('wrong-first\nwrong-last\n')
    result = execute(tmp_path, value)
    assert result['status'] == 'no_candidate' and len(result['attempts']) == 2
    assert all(item['outcome'] == 'baseline_match' for item in result['attempts'])


def test_pending_changed_response_survives_deadline_during_comparison(tmp_path, site, monkeypatch):
    from reconbot.validation import authentication
    value = config(tmp_path, site)
    original = authentication.request_response
    def fetch(config, username, password):
        if len(site.requests_seen) == 5:
            raise DeadlineReached()
        return original(config, username, password)
    monkeypatch.setattr(authentication, 'request_response', fetch)
    result = execute(tmp_path, value)
    assert result['status'] == 'timed_out' and len(result['attempts']) == 2
    assert result['attempts'][-1]['password'] == 'secret'
    assert result['attempts'][-1]['outcome'] == 'inconclusive'


def test_automatic_blank_inputs_valid_but_explicit_inputs_still_required(tmp_path, site):
    value = config(tmp_path, site)
    assert validate_request(value)['successMode'] == 'auto'
    for change in [{'successMode': 'body'}, {'successMode': 'location'}, {'successMode': 'guess'}, {'failureValue': 'xx'}]:
        with pytest.raises(ValueError):
            validate_request({**value, **change})
    assert not site.requests_seen


@pytest.mark.parametrize('phase', ['trial', 'repeat', 'control'])
def test_cancellation_retains_completed_pair_without_candidate(tmp_path, site, monkeypatch, phase):
    from reconbot.validation import authentication
    value = config(tmp_path, site)
    original = authentication.request_response
    stop_after = {'trial': 5, 'repeat': 6, 'control': 7}[phase]
    def fetch(config, username, password):
        response = original(config, username, password)
        if len(site.requests_seen) == stop_after:
            (tmp_path / 'job/cancel.request').touch()
        return response
    monkeypatch.setattr(authentication, 'request_response', fetch)
    result = execute(tmp_path, value)
    assert result['status'] == 'cancelled' and len(result['attempts']) == 2
    assert result['attempts'][-1]['password'] == 'secret'
    assert result['attempts'][-1]['outcome'] == 'inconclusive'
    assert len(site.requests_seen) == stop_after


@pytest.mark.parametrize('phase', ['repeat', 'control'])
def test_rate_limit_in_comparison_never_becomes_candidate(tmp_path, site, monkeypatch, phase):
    from reconbot.validation import authentication
    value = config(tmp_path, site)
    original = authentication.request_response
    stop_before = {'repeat': 5, 'control': 6}[phase]
    def fetch(config, username, password):
        if len(site.requests_seen) == stop_before:
            return 429, 'Try later', '', {'retry-after': '60'}
        return original(config, username, password)
    monkeypatch.setattr(authentication, 'request_response', fetch)
    result = execute(tmp_path, value)
    assert result['status'] == 'blocked' and len(result['attempts']) == 2
    assert result['attempts'][-1]['outcome'] == 'blocked'
    assert not any(item['outcome'] in ('accepted', 'candidate') for item in result['attempts'])


@pytest.mark.parametrize('code,expected', [(404, 'Login URL was not found'), (405, 'does not accept POST'), (400, 'Check field names'), (403, 'Access was denied'), (503, 'Check server health')])
@pytest.mark.parametrize('mode', ['auto', 'body'])
def test_endpoint_errors_explain_setup_without_testing_wordlist(tmp_path, site, code, expected, mode):
    value = config(tmp_path, site, f'/http{code}')
    value.update(successMode=mode, successValue='Welcome operator' if mode == 'body' else '', failureValue='Invalid credentials' if mode == 'body' else '')
    result = execute(tmp_path, value)
    assert result['status'] == 'inconclusive' and result['attempts'] == []
    assert result['baselineRequests'] == 1 and len(site.requests_seen) == 1
    assert expected in result['message']
    assert expected in (tmp_path / 'job/report.html').read_text()


@pytest.mark.parametrize('error,expected', [('ConnectionError', 'Could not connect'), ('Timeout', 'request timed out'), ('SSLError', 'TLS connection failed')])
def test_network_errors_explain_next_step_without_guessing_outcome(tmp_path, site, monkeypatch, error, expected):
    from reconbot.validation import authentication
    def fail(*_):
        raise getattr(authentication.requests.exceptions, error)('internal diagnostic')
    monkeypatch.setattr(authentication, 'request_response', fail)
    result = execute(tmp_path, config(tmp_path, site))
    assert result['status'] == 'failed' and result['attempts'] == []
    assert expected in result['message'] and result['diagnostic'] == 'internal diagnostic'


def test_friendly_html_outcome_retains_structured_raw_code(tmp_path, site):
    result = execute(tmp_path, config(tmp_path, site))
    assert result['attempts'][0]['outcome'] == 'baseline_match'
    report = (tmp_path / 'job/report.html').read_text()
    assert 'Matches incorrect-password response' in report
    assert '<td>baseline_match</td>' not in report
