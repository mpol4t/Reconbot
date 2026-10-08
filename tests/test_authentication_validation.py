import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

import pytest

from reconbot.validation.authentication import run_job, validate_request, read_wordlist, write_report

spec = importlib.util.spec_from_file_location('auth_fixture', Path(__file__).parents[1] / 'desktop/scripts/authentication-local-fixture.py')
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)


@pytest.fixture
def server():
    value = fixture.LoginServer()
    thread = threading.Thread(target=value.serve_forever, daemon=True); thread.start()
    yield value
    value.shutdown(); value.server_close(); thread.join(timeout=2)


def request(tmp_path, server, **changes):
    password = tmp_path / 'passwords.txt'; password.write_text('wrong-password\n' + fixture.PASSWORD + '\n')
    users = tmp_path / 'users.txt'; users.write_text(fixture.USERNAME + '\n')
    base = f'http://127.0.0.1:{server.server_port}'
    return dict(runDir=str(tmp_path), target=base, url=base + '/basic', mode='basic', usernameSource='single', username=fixture.USERNAME, usernameWordlist=str(users), passwordWordlist=str(password), usernameField='username', passwordField='password', extraBody='', successMode='body', successValue='Welcome operator', failureValue='Invalid credentials', lockoutValue='account locked', maxAttempts=50, duration=10, timeout=2, delay=0, **changes)


def job(tmp_path, config, name='job'):
    folder = tmp_path / 'validations/authentication' / name; folder.mkdir(parents=True)
    (folder / 'request.json').write_text(json.dumps(config))
    return folder


@pytest.mark.parametrize('route,mode,success_mode,success_value', [('/basic','basic','body','Welcome operator'),('/form','form','body','Welcome operator'),('/form-redirect','form','location','/account')])
def test_real_loopback_authentication_and_exact_evidence(tmp_path, server, route, mode, success_mode, success_value):
    config = request(tmp_path, server); config.update(url=config['target'] + route, mode=mode, successMode=success_mode, successValue=success_value)
    folder = job(tmp_path, config)
    result = run_job(folder)
    assert result['status'] == 'accepted' and result['baselineRequests'] == 1
    assert [entry['outcome'] for entry in result['attempts']] == ['rejected', 'accepted']
    assert result['attempts'][-1]['password'] == fixture.PASSWORD
    assert (folder / 'report.html').exists()
    assert not any(entry[1] == '/account' for entry in server.requests_seen)
    assert len(server.requests_seen) == 3
    assert not (tmp_path / 'run_result.json').exists()


@pytest.mark.parametrize('route,mode,status,pairs', [('/public','basic','inconclusive',0),('/basic-rate-limit','basic','blocked',1),('/form-lockout','form','blocked',1),('/form-ambiguous','form','inconclusive',1),('/form-both','form','inconclusive',1),('/form-away','form','inconclusive',2)])
def test_uncertain_public_blocked_and_conflicting_responses_are_not_success(tmp_path, server, route, mode, status, pairs):
    config = request(tmp_path, server); config.update(url=config['target'] + route, mode=mode)
    result = run_job(job(tmp_path, config))
    assert result['status'] == status and len(result['attempts']) == pairs
    assert not any(entry[1] == '/account' for entry in server.requests_seen)


def test_attempt_limit_is_incomplete_and_exhausted_list_is_negative(tmp_path, server):
    config = request(tmp_path, server); config['maxAttempts'] = 1
    result = run_job(job(tmp_path, config, 'limited'))
    assert result['status'] == 'attempt_limit' and len(result['attempts']) == 1
    Path(config['passwordWordlist']).write_text('wrong-password\nanother-wrong\n')
    config['maxAttempts'] = 50
    result = run_job(job(tmp_path, config, 'exhausted'))
    assert result['status'] == 'not_accepted' and len(result['attempts']) == 2


def test_raw_wordlist_values_and_html_escaping(tmp_path, server):
    config = request(tmp_path, server); config['username'] = '<script>operator</script>'
    Path(config['passwordWordlist']).write_text(' secret & <value> \n')
    folder = job(tmp_path, config); result = run_job(folder)
    assert result['attempts'][0]['password'] == ' secret & <value> '
    report = (folder / 'report.html').read_text()
    assert '&lt;script&gt;operator&lt;/script&gt;' in report and '<script>operator' not in report
    assert ' secret &amp; &lt;value&gt; ' in report


def test_report_puts_accepted_credentials_first_and_collapses_only_rejections(tmp_path):
    attempts = [{'username': 'operator', 'password': f'wrong-{index}', 'statusCode': 401, 'outcome': 'rejected', 'detail': 'challenge'} for index in range(205)]
    attempts.append({'username': 'operator', 'password': 'correct <&> password', 'statusCode': 200, 'outcome': 'accepted', 'detail': 'criterion matched'})
    result = dict(attempts=attempts, status='accepted', url='http://127.0.0.1/basic', mode='basic', runDir=str(tmp_path), plannedAttempts=206, baselineRequests=1)
    write_report(tmp_path, result)
    report = (tmp_path / 'report.html').read_text()
    assert report.index('Accepted credentials') < report.index('See failed attempts (205)')
    assert report.index('correct &lt;&amp;&gt; password') < report.index('wrong-0')
    assert '<details class="failed-attempts"><summary>' in report
    assert 'wrong-204' in report and len(attempts) == 206
    result.update(status='inconclusive', attempts=[dict(attempts[0], outcome='inconclusive', detail='ambiguous response')])
    write_report(tmp_path, result)
    report = (tmp_path / 'report.html').read_text()
    assert '<h2>Other outcomes</h2>' in report
    assert '<summary>See failed attempts' not in report and '<h2>Accepted credentials' not in report


@pytest.mark.parametrize('changes', [{'url':'http://other.test/basic'}, {'url':'http://127.0.0.1:1/basic'}, {'url':'file:///etc/passwd'}, {'mode':'ssh'}, {'maxAttempts':True}, {'delay':float('nan')}, {'duration':0}, {'username':'a:b'}, {'mode':'form','successValue':''}, {'mode':'form','usernameField':'same','passwordField':'same'}, {'mode':'form','extraBody':'username=overwritten'}, {'mode':'form','successMode':'location','successValue':'http://other.test/account'}])
def test_scope_and_input_validation(tmp_path, server, changes):
    config = request(tmp_path, server); config.update(changes)
    with pytest.raises(ValueError): validate_request(config)
    assert server.requests_seen == []


def test_wordlist_duplicates_blanks_and_empty_file(tmp_path):
    file = tmp_path / 'list'; file.write_text('alpha\nalpha\n\n spaced \n')
    assert read_wordlist(str(file)) == ['alpha', '', ' spaced ']
    file.write_text('')
    with pytest.raises(ValueError): read_wordlist(str(file))


def test_cancellation_before_network_and_during_job(tmp_path, server):
    config = request(tmp_path, server)
    early = job(tmp_path, config, 'early'); (early / 'cancel.request').touch()
    assert run_job(early)['status'] == 'cancelled' and not server.requests_seen
    config['delay'] = 5
    folder = job(tmp_path, config, 'live')
    child = subprocess.Popen([sys.executable, '-m', 'reconbot.validation.authentication', '--job-dir', str(folder)], stdout=subprocess.PIPE)
    try:
        assert 'workerReady' in child.stdout.readline().decode()
        end = time.monotonic() + 5
        while not server.requests_seen and time.monotonic() < end: time.sleep(.05)
        child.send_signal(signal.SIGINT); child.communicate(timeout=5)
        result = json.loads((folder / 'result.json').read_text())
        assert result['status'] == 'cancelled' and result['attempts'] == []
        assert (folder / 'report.html').exists()
    finally:
        if child.poll() is None: child.kill(); child.wait()


def test_hard_deadline_interrupts_slow_http(tmp_path, server):
    config = request(tmp_path, server); config.update(url=config['target'] + '/slow', timeout=30)
    folder = job(tmp_path, config)
    start = time.monotonic()
    child = subprocess.run([sys.executable, '-m', 'reconbot.validation.authentication', '--job-dir', str(folder)], timeout=15, capture_output=True)
    assert child.returncode == 0 and time.monotonic() - start < 14
    assert json.loads((folder / 'result.json').read_text())['status'] == 'timed_out'
