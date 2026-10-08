import json
import os
import signal
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from reconbot.core.engine import RunConfig
from reconbot.core.nmap_scan import run_nmap
from reconbot.core.nuclei_scan import parse_nuclei_output
from reconbot.core.katana import run_katana
from reconbot.orchestration.cli_parser import build_parser
from reconbot.orchestration.runner import run_from_parsed_args
from reconbot.runtime.config import _load_yaml_config, _apply_config_defaults
from reconbot.runtime.output import _prepare_output_dirs, sync_latest
from reconbot.runtime.run_lifecycle import mark_terminal
from reconbot.runtime import processes


@pytest.mark.parametrize('rc,contents,status', [(0,'','Clean'),(1,'','Error'),(0,'  \n','Clean'),(1,' \n','Error'),(0,'broken','Error'),(0,'[]','Error')])
def test_nuclei_never_calls_failed_or_malformed_output_clean(tmp_path, rc, contents, status):
    output = tmp_path / 'nuclei.jsonl'
    output.write_text(contents)
    assert parse_nuclei_output(output, rc)['Status'] == status


def test_nuclei_preserves_partial_evidence(tmp_path):
    finding = {'template-id':'fixture', 'info':{'severity':'high'}, 'host':'http://example.test'}
    output = tmp_path / 'nuclei.jsonl'
    output.write_text(json.dumps(finding) + '\nbroken\n')
    parsed = parse_nuclei_output(output, 1)
    assert parsed['Status'] == 'Partial'
    assert parsed['Findings'] == [finding]


@pytest.mark.parametrize('timing', ['T0','T1','T2','T3','T4'])
def test_nmap_applies_operator_timing_ports_and_deadline(tmp_path, timing):
    with patch('reconbot.core.nmap_scan.subprocess.run') as run:
        run.return_value.returncode = 0
        run.return_value.stdout = ''
        run_nmap('127.0.0.1', timing=timing, top_ports=123, timeout_sec=9, run_dir=tmp_path)
        command = run.call_args.args[0]
        assert '-' + timing in command
        assert timing not in command
        assert command[command.index('--top-ports')+1] == '123'
        assert run.call_args.kwargs['timeout'] == 14


def test_deep_nmap_is_one_waited_xml_scan(tmp_path):
    with patch('reconbot.core.nmap_scan.subprocess.run') as run:
        run.return_value.returncode = 0
        run.return_value.stdout = ''
        _, xml = run_nmap('127.0.0.1', detailed=True, run_dir=tmp_path)
        assert '-p-' in run.call_args.args[0]
        assert '--top-ports' not in run.call_args.args[0]
        assert xml == tmp_path/'nmap.xml'
        assert run.call_count == 1


def test_ui_settings_become_runtime_fields_and_cli_wins(tmp_path):
    path = tmp_path/'config.yaml'
    path.write_text(json.dumps({'reconbot': {'tool_settings': {'katana': {'timeout': 17, 'maxDepth': 4, 'maxUrls': 25, 'rateLimit':3}, 'nuclei':{'timeout':12,'maxTemplates':50}, 'ipNmap':{'topPorts':250,'timeout':60}}}}))
    config = _load_yaml_config(str(path))
    args = _apply_config_defaults(build_parser().parse_args(['example.test','--katana-depth','2']), config)
    assert args.katana_depth == 2
    assert args.katana_timeout_sec == 17 and args.katana_max_urls == 25
    assert args.nuclei_timeout_sec == 12 and args.nuclei_pool_limit == 50
    assert args.nmap_top_ports == 250 and args.nmap_timeout_sec == 60


@pytest.mark.parametrize('field,value', [('katana_depth',{}),('katana_timeout_sec',-1),('nmap_top_ports',0),('nuclei_pool_limit',True),('nmap_enabled','false')])
def test_invalid_scan_settings_fail_before_any_scanner(field, value):
    with pytest.raises(ValueError):
        RunConfig(target='example.test',wordlist='',**{field:value})


def test_katana_stops_further_batches_at_retained_url_limit():
    with patch('reconbot.core.katana._run_katana_once', return_value=(0,'http://example.test/a\nhttp://example.test/b\n','')) as call:
        urls = run_katana(['http://example.test','http://second.test'], max_urls=1, auto_js_crawl=False, timeout_sec=7, rate_limit=3)
        assert len(urls) == 1 and call.call_count == 1
        assert call.call_args.kwargs['timeout_sec'] == 7
        assert call.call_args.kwargs['rate_limit'] == 3


def test_same_second_runs_and_latest_are_isolated(tmp_path):
    with patch('reconbot.runtime.output.datetime') as clock:
        clock.now.return_value = datetime(2026,9,20,12,0,0)
        a, latest, _ = _prepare_output_dirs(str(tmp_path))
        b, _, _ = _prepare_output_dirs(str(tmp_path))
    assert a != b
    for run, text in [(a,'a'),(b,'b')]:
        (run/'report.html').write_text(text)
        (run/'run_result.json').write_text(text)
        (run/'screenshots').mkdir()
        (run/'screenshots'/'one.png').write_bytes(b'fixture')
        sync_latest(run, latest)
    assert (latest/'report.html').read_text() == 'b'
    assert (latest/'run_result.json').read_text() == 'b'
    assert (latest/'screenshots'/'one.png').exists()
    assert (a/'report.html').read_text() == 'a'
    c, pointer, base = _prepare_output_dirs(str(latest))
    assert c.parent == tmp_path/'runs' and pointer == latest


def test_failure_and_interrupt_preserve_evidence_and_update_live_stages(tmp_path):
    (tmp_path/'run_result.json').write_text(json.dumps({'findings':[{'id':'saved'}]}))
    (tmp_path/'stages_live.json').write_text(json.dumps({'nmap':{'status':'running'},'katana':{'status':'pending'}}))
    mark_terminal(tmp_path,'example.test','interrupted','stop')
    result = json.loads((tmp_path/'run_result.json').read_text())
    assert result['findings'] == [{'id':'saved'}]
    assert result['run_state'] == 'interrupted'
    assert json.loads((tmp_path/'stages_live.json').read_text())['nmap']['status'] == 'interrupted'


def test_engine_exception_has_nonzero_exit_and_failed_artifact(tmp_path, monkeypatch):
    config = tmp_path/'config.yaml'
    config.write_text('reconbot:\n  gobuster_enabled: false\n  ffuf_enabled: false\n')
    args = build_parser().parse_args(['127.0.0.1','-c',str(config),'-o',str(tmp_path/'out')])
    monkeypatch.setenv('RECONBOT_SKIP_PREFLIGHT','1')
    with patch('reconbot.orchestration.runner.run_engine', side_effect=RuntimeError('fixture failure')):
        with pytest.raises(SystemExit) as error:
            run_from_parsed_args(args)
    assert error.value.code == 1
    assert json.loads((Path(args._run_dir)/'run_result.json').read_text())['run_state'] == 'failed'


def test_osint_only_does_not_require_active_scanners(tmp_path):
    config = tmp_path/'config.yaml'
    config.write_text('reconbot:\n  run_mode: osint_only\n')
    args = build_parser().parse_args(['example.test','-c',str(config),'-o',str(tmp_path/'out')])
    with patch('reconbot.orchestration.runner.preflight_check') as preflight, patch('reconbot.orchestration.runner.build_osint_enrichment', return_value={}), patch('reconbot.orchestration.runner.generate_report'):
        run_from_parsed_args(args)
        preflight.assert_not_called()


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process groups')
def test_process_scope_reaps_background_child_on_failure():
    with pytest.raises(RuntimeError):
        with processes.process_scope():
            child = processes.Popen([sys.executable,'-c','import time; time.sleep(60)'])
            raise RuntimeError('cancel fixture')
    assert child.poll() is not None
    with pytest.raises(ProcessLookupError):
        os.killpg(child.pid, 0)


@pytest.mark.skipif(os.name != 'posix', reason='POSIX signals')
def test_process_scope_handles_app_shutdown_signal():
    with pytest.raises(KeyboardInterrupt):
        with processes.process_scope():
            child = processes.Popen([sys.executable,'-c','import time; time.sleep(60)'])
            os.kill(os.getpid(), signal.SIGTERM)
    assert child.poll() is not None


def test_managed_timeout_cleans_process():
    with pytest.raises(processes.TimeoutExpired):
        with processes.process_scope():
            processes.run([sys.executable,'-c','import time; time.sleep(60)'],timeout=0.05)


def test_enrichment_rejects_wrong_run_before_network(tmp_path):
    from reconbot.orchestration.ip_enrichment import run_ip_enrichment
    (tmp_path/'run_result.json').write_text(json.dumps({'meta':{'target':'b.example'}}))
    with pytest.raises(ValueError, match='eşleşmiyor'):
        run_ip_enrichment({'run_dir':str(tmp_path),'original_target':'a.example','resolved_ip':'192.0.2.1'})
    assert not (tmp_path/'ip_enrichment.json').exists()


def test_timeout_retains_stdout_and_releases_registry():
    with processes.process_scope():
        with pytest.raises(processes.TimeoutExpired) as error:
            # Allow interpreter startup under load; the child still outlives
            # this deadline, exercising timeout output retention and cleanup.
            processes.run([sys.executable, '-c', 'import time; print("saved", flush=True); time.sleep(60)'], timeout=2, capture_output=True, text=True)
        assert 'saved' in error.value.output
        assert processes._owned.get() == []
        result = processes.run([sys.executable, '-c', 'print("complete")'], capture_output=True, text=True)
        assert result.stdout.strip() == 'complete'
        assert processes._owned.get() == []


def test_katana_preserves_partial_urls_and_reports_failed_batches():
    diagnostics = {}
    with patch('reconbot.core.katana._run_katana_once', side_effect=[(0,'http://a.test/x',''),(1,'http://b.test/partial','failed')]):
        urls = run_katana(['http://a.test','http://b.test'], auto_js_crawl=False, diagnostics=diagnostics)
    assert urls == ['http://a.test/x','http://b.test/partial']
    assert diagnostics['errors'] and diagnostics['successful_attempts'] == 1


@pytest.mark.parametrize('records,status', [({'a':{'returncode':0}},'done'),({'a':{'available':False,'error':'missing'}},'error'),({'a':{'returncode':0},'b':{'returncode':1}},'partial')])
def test_wrapper_error_records_affect_coverage(records, status):
    from reconbot.runtime.run_lifecycle import result_coverage_status
    assert result_coverage_status(records)[0] == status


def test_nuclei_completion_preserves_failed_discovery_state():
    from reconbot.runtime.state import _update_nuclei_stage
    result = _update_nuclei_stage({'stages':{'katana':{'status':'partial'}}}, {'Status':'Clean','Findings':[]}, None)
    assert result['run_state'] == 'incomplete'
    assert result['stages']['nuclei']['status'] == 'done'


@pytest.mark.parametrize('argv', [['generate-report'], ['generate-report','--run-dir','/nonexistent-fixture']])
def test_report_input_errors_have_failure_exit(argv):
    with pytest.raises(SystemExit) as error:
        run_from_parsed_args(build_parser().parse_args(argv))
    assert error.value.code == 1


def test_only_selected_scanners_are_required_for_ip_targets():
    from reconbot.runtime.scanner_settings import enabled_scanners
    config = RunConfig(target='127.0.0.1',wordlist='',nmap_enabled=False,katana_enabled=False,nuclei_enabled=False)
    active = enabled_scanners(config,'ip')
    assert not set(active).intersection({'nmap','katana','nuclei','subfinder','dnsx','httpx'})


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process groups')
def test_completed_parent_cannot_leave_scanner_grandchild(tmp_path):
    import subprocess as standard_subprocess
    pid_path = tmp_path/'grandchild.pid'
    leader = 'import subprocess,sys,time; p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); open(sys.argv[1],"w").write(str(p.pid)); time.sleep(.1)'
    with processes.process_scope():
        processes.run([sys.executable,'-c',leader,str(pid_path)],capture_output=True,text=True)
        assert processes._owned.get() == []
    state = standard_subprocess.run(['ps','-o','stat=','-p',pid_path.read_text()],capture_output=True,text=True).stdout.strip()
    assert not state or state.startswith('Z'), f'grandchild still active: {state}'


def test_ui_settings_reach_engine_without_silent_fallback(tmp_path, monkeypatch):
    config = tmp_path/'config.yaml'
    config.write_text(json.dumps({'reconbot':{'gobuster_enabled':False,'ffuf_enabled':False,'katana':{'auto_js':False},'tool_settings':{'katana':{'timeout':17,'maxUrls':25},'nuclei':{'timeout':12,'maxTemplates':50},'ipNmap':{'topPorts':250,'timeout':60}}}}))
    args = build_parser().parse_args(['127.0.0.1','-c',str(config),'-o',str(tmp_path/'out')])
    monkeypatch.setenv('RECONBOT_SKIP_PREFLIGHT','1')
    with patch('reconbot.orchestration.runner.run_engine',side_effect=RuntimeError('stop before external tools')) as engine:
        with pytest.raises(SystemExit):
            run_from_parsed_args(args)
    selected = engine.call_args.args[0]
    assert (selected.katana_timeout_sec,selected.katana_max_urls,selected.nuclei_timeout_sec,selected.nuclei_pool_limit,selected.nmap_top_ports,selected.nmap_timeout_sec) == (17,25,12,50,250,60)
    assert selected.katana_auto_js_crawl is False


def test_version_manifest_checks_only_enabled_tools_with_deadline():
    from reconbot.runtime.tool_metadata import runtime_metadata
    with patch('reconbot.runtime.tool_metadata.shutil.which', side_effect=lambda name: '/fixture/'+name), patch('reconbot.runtime.tool_metadata.processes.run') as run:
        run.return_value.returncode = 0
        run.return_value.stdout = 'fixture version 1'
        result = runtime_metadata(['nmap','checks'])
    assert set(result['tool_versions']) == {'nmap'}
    assert result['tool_versions']['nmap']['version'] == 'fixture version 1'
    assert run.call_args.kwargs['timeout'] == 2


@pytest.mark.parametrize('stored', [{'target':'b.example'}, {'summary':{}}])
def test_enrichment_cannot_use_request_as_run_identity(tmp_path, stored):
    from reconbot.orchestration.ip_enrichment import run_ip_enrichment
    (tmp_path/'run_result.json').write_text(json.dumps(stored))
    with pytest.raises(ValueError,match='eşleşmiyor'):
        run_ip_enrichment({'run_dir':str(tmp_path),'original_target':'a.example','resolved_ip':'192.0.2.1'})
