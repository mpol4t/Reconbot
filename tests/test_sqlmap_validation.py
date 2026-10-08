import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from reconbot.validation.sqlmap import validate_request, build_command, parse_evidence, classify, run_job, write_report
from reconbot.report.sections.sqlmap import render_sqlmap_validations


def request(**changes):
    return {'url': 'http://localhost:8082/item?id=1', 'target': 'http://localhost:8082', 'runDir': '/scan/run', 'parameter': 'id', 'method': 'GET', 'body': '', 'cookie': '', 'duration': 10, 'delay': 0, **changes}


@pytest.mark.parametrize('changes', [
    {'url': 'http://other.test:8082/item?id=1'}, {'url': 'http://localhost:9999/item?id=1'},
    {'url': 'file:///tmp/item?id=1'}, {'parameter': 'id --dump'}, {'parameter': '--os-shell', 'url': 'http://localhost:8082/item?--os-shell=1'}, {'parameter': 'unknown'},
    {'cookie': 'x=1\r\nInjected: 1'}, {'risk': 3}, {'duration': 0}, {'threads': True},
    {'delay': float('nan')}, {'method': 'DELETE'}, {'body': '\0'},
])
def test_invalid_requests(changes):
    with pytest.raises(ValueError):
        validate_request(request(**changes))


def test_command_exact_scope_and_no_shell(tmp_path):
    value = validate_request(request(url='http://localhost:8082/item?id=1%3B%24%28whoami%29', cookie='session=raw-secret'))
    command = build_command(value, tmp_path, 'sqlmap')
    assert command[command.index('-u') + 1] == value['url']
    assert command[command.index('-p') + 1] == 'id'
    assert command[command.index('--param-filter') + 1] == 'GET'
    assert '--cookie=session=raw-secret' in command
    assert command[command.index('--technique') + 1] == 'BEU'
    assert not {'--dump', '--os-shell', '--dbs', '--tamper'} & set(command)
    post = validate_request(request(method='POST', body='id=1&other=2'))
    assert build_command(post, tmp_path, 'sqlmap')[build_command(post, tmp_path, 'sqlmap').index('--param-filter') + 1] == 'POST'
    assert build_command(post, tmp_path, 'sqlmap')[-1] == '--data=' + post['body']
    cookie = validate_request(request(cookie='--os-shell'))
    assert '--cookie=--os-shell' in build_command(cookie, tmp_path, 'sqlmap')


PROOF = '''sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE
    Payload: id=1 AND 1=1

    Type: UNION query
    Title: Generic UNION query - 2 columns
    Payload: id=1 UNION SELECT NULL,NULL
---
back-end DBMS: SQLite
'''


def test_proof_and_classification():
    found = parse_evidence(PROOF, 'id')
    assert len(found) == 2 and found[1]['payload'] == 'id=1 UNION SELECT NULL,NULL'
    assert parse_evidence(PROOF, 'other') == []
    assert parse_evidence(PROOF, 'id', 'POST') == []
    assert parse_evidence('[INFO] testing id is injectable', 'id') == []
    assert classify('', found, 0, None) == 'detected'
    raw = '[WARNING] all tested parameters do not appear to be injectable\n[ending @ 12:00]'
    assert classify(raw, [], 0, None) == 'not_detected'
    assert classify(raw, [], 0, 'timed_out') == 'timed_out'
    assert classify(raw, [], 1, None) == 'failed'
    assert classify('[CRITICAL] connection failed\n' + raw, [], 0, None) == 'failed'
    assert classify('', [], 0, None) == 'inconclusive'
    assert classify('', found, None, 'cancelled') == 'cancelled'


def make_job(tmp_path, name='job'):
    job = tmp_path / 'validations' / 'sqlmap' / name
    job.mkdir(parents=True)
    (job / 'request.json').write_text(json.dumps(request(runDir=str(tmp_path))))
    return job


def test_failure_and_html_escaping(tmp_path):
    job = make_job(tmp_path)
    result = run_job(job, executable='/does/not/exist')
    assert result['status'] == 'failed' and result['evidence'] == []
    assert (job / 'report.html').exists()
    result['url'] = '<script>unsafe</script>'
    (job / 'result.json').write_text(json.dumps(result))
    section = render_sqlmap_validations(tmp_path)
    assert '&lt;script&gt;' in section and '<script>unsafe' not in section
    assert 'validations/sqlmap/job/report.html' in section
    result['evidence'] = [{'title': 'Test', 'parameter': 'id', 'place': 'GET', 'type': 'boolean-based blind', 'payload': 'id=1 AND 1<2'}]
    write_report(job, result)
    report = (job / 'report.html').read_text()
    assert '<p class="payload-label">Payload</p><pre aria-label="Payload">id=1 AND 1&lt;2</pre>' in report
    assert '&lt;script&gt;' in report and '<script>unsafe' not in report


def test_timeout_retains_evidence_and_reaps_children(tmp_path):
    job = make_job(tmp_path)
    fake = tmp_path / 'fake-sqlmap'
    fake.write_text('#!/usr/bin/env python3\nimport pathlib,sys,time,subprocess\noutput=pathlib.Path(sys.argv[sys.argv.index("--output-dir")+1])/"localhost"\noutput.mkdir(parents=True)\n(output/"log").write_text(' + repr(PROOF) + ')\nchild=subprocess.Popen([sys.executable,"-c","import time; time.sleep(300)"])\n(output/"pid").write_text(str(child.pid))\nprint("ready",flush=True)\ntime.sleep(300)\n')
    fake.chmod(0o755)
    result = run_job(job, executable=str(fake))
    assert result['status'] == 'timed_out' and len(result['evidence']) == 2
    pid = int((job / 'raw/localhost/pid').read_text())
    # A killed descendant may remain briefly as a zombie pending OS reaping.
    status = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True).stdout.strip()
    assert not status or status.startswith('Z')


def test_cancel_durable_result(tmp_path):
    job = make_job(tmp_path)
    # Use a Python-created shim on PATH; exercise the actual module entry.
    shim = tmp_path / 'sqlmap'
    shim.write_text('#!/usr/bin/env python3\nimport time\nprint("ready",flush=True)\ntime.sleep(300)\n')
    shim.chmod(0o755)
    env = {**os.environ, 'PATH': str(tmp_path) + os.pathsep + os.environ['PATH']}
    proc = subprocess.Popen([sys.executable, '-m', 'reconbot.validation.sqlmap', '--job-dir', str(job)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not (job / 'sqlmap.log').exists():
            time.sleep(.05)
        time.sleep(.1)
        proc.send_signal(signal.SIGINT)
        proc.communicate(timeout=8)
        result = json.loads((job / 'result.json').read_text())
        assert result['status'] == 'cancelled'
        assert (job / 'report.html').exists()
    finally:
        if proc.poll() is None:
            proc.kill(); proc.wait()


def test_main_report_includes_validation_without_rewriting_scan_state(tmp_path):
    from reconbot.report.builder import generate_report
    baseline = json.dumps({'meta': {'target': 'http://localhost:8082'}, 'run_state': 'interrupted', 'data': {}, 'stages': {}})
    (tmp_path / 'run_result.json').write_text(baseline)
    job = make_job(tmp_path)
    run_job(job, executable='/does/not/exist')
    generate_report({}, [], {}, {}, 'http://localhost:8082', '', output_dir=tmp_path, open_browser=False, quiet=True)
    report = (tmp_path / 'report.html').read_text()
    assert 'id="sqlmap-validations"' in report
    assert 'validations/sqlmap/job/report.html' in report
    assert (tmp_path / 'run_result.json').read_text() == baseline


def test_early_cancel_never_launches_sqlmap(tmp_path):
    job = make_job(tmp_path)
    (job / 'cancel.request').write_text('cancel')
    result = run_job(job, executable='/does/not/exist')
    assert result['status'] == 'cancelled'
    assert not (job / 'sqlmap.log').exists()
    assert (job / 'report.html').exists()
