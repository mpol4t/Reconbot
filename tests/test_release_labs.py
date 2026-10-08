"""Negative/positive contracts for the four manual release QA sites."""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest
import requests

from reconbot.validation.authentication import run_job

SCRIPT = Path(__file__).parents[1] / 'desktop/scripts/release-labs.py'
spec = importlib.util.spec_from_file_location('release_labs', SCRIPT)
labs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(labs)


@pytest.fixture
def sites():
    servers = [labs.LabServer(profile[0]) for profile in labs.PROFILES]
    threads = [threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True) for server in servers]
    for thread in threads:
        thread.start()
    yield {server.profile: f'http://127.0.0.1:{server.server_port}' for server in servers}
    for server, thread in zip(servers, threads):
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_exposure_profiles_and_no_wildcard_success(sites):
    expected = {'clean': [], 'medium': ['/.git/config', '/backup/', '/backup/config.json'], 'exposed': ['/.git/config', '/backup/', '/backup/config.json', '/.env', '/.env.bak', '/debug/vars', '/admin/dashboard'], 'validation': []}
    paths = ['/.git/config', '/backup/', '/backup/config.json', '/.env', '/.env.bak', '/debug/vars', '/admin/dashboard']
    for profile, base in sites.items():
        assert requests.get(base + '/health', timeout=2).json()['profile'] == profile
        for path in paths:
            assert requests.get(base + path, timeout=2).status_code == (200 if path in expected[profile] else 404)
        assert requests.get(base + '/no-such-route', timeout=2).status_code == 404
        assert requests.post(base + '/no-such-route', data=b'anything', timeout=2).status_code == 404
    response = requests.get(sites['clean'], timeout=2)
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert "default-src 'none'" in response.headers['Content-Security-Policy']
    assert requests.get(sites['medium'] + '/admin', timeout=2).status_code == 403


def test_real_sql_positive_and_negative_controls(sites):
    for profile, base in sites.items():
        for route in ['/item', '/clean']:
            injected = requests.get(base + route, params={'id': '1 OR 1=1'}, timeout=2).text
            assert ('product-20' in injected) == (profile == 'validation' and route == '/item')
            assert 'product-1' in requests.get(base + route, params={'id': '1'}, timeout=2).text
    base = sites['validation']
    response = requests.post(base + '/item', data={'id': "-1 UNION SELECT 99,'<script>alert(1)</script>'"}, timeout=2)
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in response.text
    assert '<script>alert(1)</script>' not in response.text
    response = requests.get(base + '/item', params={'id': '1; DROP TABLE products'}, timeout=2)
    assert 'SQLite error:' in response.text
    assert 'product-1' in requests.get(base + '/item?id=1', timeout=2).text


def test_scanner_malformed_bodies_and_head(sites):
    base = sites['validation']
    assert requests.post(base + '/item', data=b'\xff\x00\xfe', timeout=2).status_code == 400
    assert requests.post(base + '/item', data=b'x' * 65537, timeout=2).status_code == 413
    assert requests.post(base + '/item', data='&'.join(f'p{i}=1' for i in range(101)), timeout=2).status_code == 400
    assert requests.options(base, timeout=2).status_code == 405
    head = requests.head(base + '/login', timeout=2)
    assert head.status_code == 200 and head.content == b'' and int(head.headers['Content-Length']) > 100
    assert requests.get(base + '/health', timeout=2).status_code == 200


@pytest.mark.parametrize('path,mode,status', [('/basic', 'basic', 'accepted'), ('/login', 'form', 'accepted'), ('/login-redirect', 'form', 'accepted'), ('/basic-rate-limit', 'basic', 'blocked'), ('/login-lockout', 'form', 'blocked'), ('/login-ambiguous', 'form', 'inconclusive')])
def test_authentication_backend_against_new_labs(tmp_path, sites, path, mode, status):
    labs.write_assets(tmp_path, [8085, 8086, 8087, 8088])
    base = sites['validation']
    config = dict(runDir=str(tmp_path), target=base, url=base + path, mode=mode, usernameSource='single', username=labs.USERNAME, usernameWordlist=str(tmp_path / 'usernames.txt'), passwordWordlist=str(tmp_path / 'passwords.txt'), usernameField='username', passwordField='password', extraBody='', successMode='location' if path == '/login-redirect' else 'body', successValue='/account' if path == '/login-redirect' else 'Welcome operator', failureValue='Invalid credentials', lockoutValue='account locked', maxAttempts=50, duration=10, timeout=2, delay=0)
    folder = tmp_path / 'job'
    folder.mkdir()
    (folder / 'request.json').write_text(json.dumps(config))
    result = run_job(folder)
    assert result['status'] == status
    assert result['baselineRequests'] == 1
    if status == 'accepted':
        assert len(result['attempts']) == 3
        assert result['attempts'][-1]['password'] == labs.PASSWORD
    else:
        assert len(result['attempts']) == 1


def test_generated_wordlists_and_basic_pair(tmp_path, sites):
    labs.write_assets(tmp_path, [8085, 8086, 8087, 8088])
    words = (tmp_path / 'passwords-long.txt').read_text().splitlines()
    assert len(words) == len(set(words)) == 251 and words[-1] == labs.PASSWORD
    assert labs.PASSWORD not in (tmp_path / 'passwords-negative.txt').read_text().splitlines()
    base = sites['validation']
    assert requests.get(base + '/basic', timeout=2).status_code == 401
    assert requests.get(base + '/basic', auth=(labs.USERNAME, labs.PASSWORD), timeout=2).status_code == 200
    token = base64.b64encode(b'wrong:wrong').decode()
    assert requests.get(base + '/basic', headers={'Authorization': 'Basic ' + token}, timeout=2).status_code == 401


def test_port_conflict_and_owned_shutdown(tmp_path):
    # Reserve an ephemeral socket: an unsuccessful launch must leave it running.
    reserved = labs.LabServer('clean')
    try:
        failed = subprocess.run([sys.executable, str(SCRIPT), '--base-port', str(reserved.server_port), '--output-dir', str(tmp_path)], capture_output=True, text=True, timeout=5)
        assert failed.returncode == 1 and 'Cannot start lab suite' in failed.stderr
        assert not (tmp_path / 'server.pid').exists()
    finally:
        reserved.server_close()
    # Find four adjacent available ports without touching application-owned servers.
    servers = []
    for base in range(22000, 23000, 4):
        servers = []
        try:
            for i in range(4):
                servers.append(labs.LabServer('clean', base + i))
            break
        except OSError:
            for server in servers:
                server.server_close()
    assert len(servers) == 4
    for server in servers:
        server.server_close()
    child = subprocess.Popen([sys.executable, str(SCRIPT), '--base-port', str(base), '--output-dir', str(tmp_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 5
        while not (tmp_path / 'server.pid').exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(.05)
        assert (tmp_path / 'server.pid').exists()
        for offset in range(4):
            assert requests.get(f'http://127.0.0.1:{base + offset}/health', timeout=2).status_code == 200
        stop = subprocess.run([sys.executable, str(SCRIPT), '--stop', '--output-dir', str(tmp_path)], capture_output=True, timeout=5)
        assert stop.returncode == 0
        child.communicate(timeout=5)
        assert child.returncode == 0 and not (tmp_path / 'server.pid').exists()
        for offset in range(4):
            with pytest.raises(requests.ConnectionError):
                requests.get(f'http://127.0.0.1:{base + offset}/health', timeout=1)
    finally:
        if child.poll() is None:
            child.terminate()
            child.communicate(timeout=5)
