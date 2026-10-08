"""Regressions for the eight concrete findings in the October code review."""
import gzip
import io
import json
import signal
import threading
import time
from contextlib import ExitStack, redirect_stdout
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
import requests

from reconbot.ai import assistant
from reconbot.ai.action_guard import validate_action_plan
from reconbot.ai.answer_validator import validate_answer_integrity
from reconbot.ai.action_planner import extract_action_plan
from reconbot.ai.client import OpenAICompatibleClient, classify_http_400
from reconbot.ai.config import ai_config_from_mapping
from reconbot.ai.models import AIContext, ChatResponse
from reconbot.ai.context_builder import build_ai_context
from reconbot.ai.prompt_builder import build_messages
from reconbot.ai.redaction import redact_text, redact_for_prompt, redact_for_ui, redact_provider_error_payload
from reconbot.ai.request_planner import prepare_conversation_history
from reconbot.ai.request_planner import estimate_tokens_from_chars
from reconbot.ai.settings_actions import apply_settings_action
from reconbot.core import engine
from reconbot.core.dnsx_scan import run_dnsx
from reconbot.core.httpx_scan import run_httpx
from reconbot.core.subfinder_scan import run_subfinder
from reconbot.core.gobuster_scan import run_gobuster
from reconbot.core.ffuf_scan import run_ffuf
from reconbot.core import katana
from reconbot.core.web_checks import _bounded_response, run_web_checks
from reconbot.orchestration import gui_bootstrap as gui
from reconbot.orchestration.osint_core.domains import registered_domain
from reconbot.orchestration.osint_core.darkweb.manual_import import _match_item
from reconbot.orchestration.osint_core.darkweb.safety import safe_reference_url
from reconbot.runtime.scanner_result import ScannerItems, scanner_metadata
from reconbot.runtime.run_lifecycle import summarize_coverage


@pytest.mark.parametrize("secret_text", [
    'password=DEMO_SHORT_SECRET', '{"api_key":"DEMO_SHORT_SECRET"}',
    "{'password': 'DEMO_SHORT_SECRET'}", 'Authorization: Basic dXNlcjpwYXNz',
    'Authorization: Bearer tiny', '{"refresh_token":"DEMO_SHORT_SECRET"}',
    'Cookie: sessionid=DEMO_SHORT_SECRET',
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.fakeSignature123',
    '-----BEGIN PRIVATE KEY-----\nFAKE_TEST_KEY_ONLY\n-----END PRIVATE KEY-----',
    'AKIA0000000000000000', 'demo@example.test:DemoPassword123',
    'abcdefghijklmnopqrstuvwxyz1234567890',
    'alpha,beta,gamma,delta,epsilon', '/Users/example/test-run/reconbot.log',

])
def test_ai_content_preserves_latest_history_context_display_and_repair(secret_text):
    original = {'log': secret_text, 'token': secret_text, 'nested': [{'password': secret_text}]}
    context = AIContext(context=redact_for_prompt(original))
    history = [{'role': 'user', 'content': secret_text}, {'role': 'assistant', 'content': secret_text}]
    prepared, _, _ = prepare_conversation_history(history, secret_text)
    assert prepared == history
    messages = build_messages(context, secret_text, conversation_history=prepared)
    assert messages[-1].content == secret_text
    assert [row.content for row in messages if row.role == 'assistant'] == [secret_text]
    assert json.dumps(original, ensure_ascii=False, separators=(',', ':'), sort_keys=True) in messages[0].content
    assert redact_for_ui({'answer': secret_text})['answer'] == secret_text
    for mode in ("ai_prompt_redaction", "ui_display_redaction", "config_storage"):
        assert redact_text(secret_text, mode=mode) == secret_text
    repair = build_messages(context, secret_text, repair_failed_answer=secret_text,
                            repair_reason='integrity_failure', repair_artifact_evidence=[secret_text])
    assert repair[-1].content == secret_text
    assert secret_text in repair[0].content


def test_ai_structured_content_keeps_types_and_is_not_mutated():
    original = {1: ('password=demo', {'api_key': 'demo'}), 'session': ['demo']}
    for preserve in (redact_for_prompt, redact_for_ui):
        copied = preserve(original)
        assert copied == original
        copied['session'].append('changed')
        assert original['session'] == ['demo']


def test_provider_diagnostic_json_keeps_secret_fields_and_error_classification():
    payload = {'error': {'message': 'Context length exceeded; Authorization: Bearer demo',
                         'token': 'demo', 'code': 'context_length_exceeded'}}
    assert redact_provider_error_payload(json.dumps(payload)) == payload
    error = HTTPError('http://127.0.0.1:1234/v1/chat/completions', 400, 'bad request', {},
                      io.BytesIO(json.dumps(payload).encode()))
    with patch('urllib.request.urlopen', side_effect=error):
        client = OpenAICompatibleClient(ai_config_from_mapping({'enabled': True}))
        status, received, code = client._http_json('/chat/completions')
    assert (status, code) == ('http_error', 400)
    assert received == payload
    assert classify_http_400(received) == 'context_length_exceeded' 
    assert redact_provider_error_payload('password=demo') == 'password=demo'


def test_run_log_context_preserves_secrets(tmp_path):
    text = 'Authorization: Bearer DEMO_TOKEN password=DEMO_PASSWORD'
    (tmp_path / 'reconbot.log').write_text(text + '\n', encoding='utf-8')
    context = build_ai_context(str(tmp_path), profile='log_troubleshooting')
    assert text in context.context['log']['tail']


def test_ai_ipc_preserves_model_output_and_diagnostics():
    result = {'ok': True, 'answer': 'password=DEMO_PASSWORD',
              'endpoint_debug': {'rawProviderContent': 'Cookie: sessionid=DEMO_SESSION'},
              'action_plan': {'token': 'DEMO_TOKEN'}}
    output = io.StringIO()
    with patch('sys.stdin', io.StringIO('{}')), patch.object(assistant, 'dispatch', return_value=result), redirect_stdout(output):
        assert assistant.main() == 0
    assert json.loads(output.getvalue()) == result


@pytest.mark.parametrize('formatting', ['{}', '`{}`', '**{}**', '*{}*', '__{}__', '[Kanıt]({})', '**[Kanıt]({})**'])
def test_artifact_url_markdown_is_not_misclassified_as_invented(formatting):
    known='http://localhost:8082/eyoumail'
    findings=[{'url':known}]
    assert validate_answer_integrity(formatting.format(known),findings=findings,enforce_artifact_grounding=True).usable
    assert not validate_answer_integrity(formatting.format(known+'/invented'),findings=findings,enforce_artifact_grounding=True).usable


def test_literal_url_suffixes_are_not_removed_without_markdown_wrapper():
    known='http://localhost:8082/eyoumail'
    result=validate_answer_integrity(known+'_',findings=[{'url':known}],enforce_artifact_grounding=True)
    assert not result.usable
    wildcard='http://localhost:8082/items/*'
    assert validate_answer_integrity('**'+wildcard+'**',findings=[{'url':wildcard}],enforce_artifact_grounding=True).usable


def plan(path, value):
    return {'type':'settings_recommendation', 'requires_user_approval':True, 'risk_score_impact':0, 'changes':[{'path':path, 'proposed':value}]}


@pytest.mark.parametrize('path,value', [
    ('tool_settings.katana.maxDepth', {}), ('tool_settings.katana.maxDepth', True),
    ('tool_settings.katana.maxDepth', -1), ('tool_settings.katana.maxDepth', 1.5),
    ('tool_settings.katana.timeout', 3601), ('tool_settings.katana.enabled', 'false'),
    ('scan_profile', 'turbo'), ('tool_settings.nuclei.severityFilter', 'high,invalid'),
    ('tool_settings.osint.sources.wayback.retryCount', -1),
])
def test_approved_invalid_ai_values_leave_settings_intact(path, value):
    settings = {'tool_settings': {'katana': {'maxDepth': 3}}}
    result = apply_settings_action(settings, plan(path,value), approved=True)
    assert result['ok'] is False
    assert result['settings'] == settings


@pytest.mark.parametrize('impact', ['invalid', None, {}, [], True, 0.5])
def test_malformed_model_plan_is_rejected_without_parser_exception(impact):
    proposal = {**plan('scan_profile','fast'), 'risk_score_impact':impact}
    assert validate_action_plan(proposal,approved=True)[0] is False
    assert extract_action_plan(json.dumps(proposal)) is None


def test_ai_requires_actual_boolean_approval():
    result = assistant.apply_settings({'plan':plan('scan_profile','fast'), 'settings':{}, 'approved':'false'})
    assert result['ok'] is False


def test_backend_respects_disabled_approved_changes_toggle():
    result = assistant.apply_settings({'aiConfig':{'allowApprovedSettingsChanges':False}, 'plan':plan('scan_profile','fast'), 'settings':{}, 'approved':True})
    assert result['ok'] is False


def test_public_guard_cannot_accept_truthy_string_approval():
    assert validate_action_plan(plan('scan_profile','fast'),approved='false')[0] is False


def test_repair_provider_payload_fits_small_loaded_window():
    calls = []
    class Client:
        def __init__(self, config): pass
        def set_model_metadata(self, data): pass
        def chat(self, messages, **kwargs):
            calls.append((messages,kwargs))
            answer = ('Test açıklaması. '*200)+' [URL]' if len(calls)==1 else 'Bu veri doğrulanamadı.'
            return ChatResponse(ok=True, answer=answer, model='fixture', lm_request_sent=True, attempt_count=1)
    with patch.object(assistant, 'OpenAICompatibleClient', Client):
        result = assistant.chat({'question':'Bana bunu açıkla.', 'aiConfig':{'model':'fixture', 'maxOutputTokens':1000}, 'modelMetadata':{'loaded_context_length':2048}})
    assert result['ok'] and len(calls)==2
    for messages, kwargs in calls:
        input_tokens = sum(estimate_tokens_from_chars(len(m.content)+16) for m in messages)
        assert input_tokens + kwargs['max_tokens'] + 512 <= 2048
        assert messages[-1].content == 'Bana bunu açıkla.'
    assert result['answer_repair_request_plan']['estimatedInputTokens'] > 0
    assert result['answer_repair_request_plan']['estimatedTotalTokens'] + 512 <= 2048


@pytest.mark.parametrize('call,module,args', [
    (run_subfinder,'subfinder_scan',('example.test',)),
    (run_dnsx,'dnsx_scan',(['example.test'],)),
    (run_httpx,'httpx_scan',(['example.test'],)),
])
@pytest.mark.parametrize('stdout,status', [('', 'error'), ('child.example.test\n', 'partial')])
def test_discovery_nonzero_exit_never_becomes_clean(call,module,args,stdout,status):
    with patch(f'reconbot.core.{module}.subprocess.run', return_value=SimpleNamespace(returncode=1,stdout=stdout,stderr='controlled failure')):
        result=call(*args,rate_limit=10)
    assert scanner_metadata(result)['status']==status
    assert scanner_metadata(result)['returncode']==1
    if stdout: assert result==['child.example.test']


def test_unsupported_rate_limit_never_silently_runs_without_limit():
    with patch('reconbot.core.httpx_scan.subprocess.run',return_value=SimpleNamespace(returncode=1,stdout='',stderr='unknown flag: -rl')) as call:
        result=run_httpx(['example.test'],rate_limit=10)
    assert call.call_count==1 and scanner_metadata(result)['status']=='error'


def test_gobuster_keeps_partial_evidence(tmp_path):
    wordlist=tmp_path/'words';wordlist.write_text('admin\n')
    with patch('reconbot.core.gobuster_scan.subprocess.run',return_value=SimpleNamespace(returncode=1,stdout='/admin (Status: 200) [Size: 12]',stderr='failed later')):
        result=run_gobuster('http://example.test',str(wordlist),detect_wildcard=False)
    assert result[0]['path']=='/admin'
    assert scanner_metadata(result)['status']=='partial'


@pytest.mark.parametrize('contents', [None,'broken','{}','{"results":"broken"}'])
def test_ffuf_success_without_valid_output_is_error(tmp_path,contents):
    path=tmp_path/'ffuf.json'
    if contents is not None:path.write_text(contents)
    with patch('reconbot.core.ffuf_scan.subprocess.run',return_value=SimpleNamespace(returncode=0,stderr='')):
        result=run_ffuf(base_url='http://example.test',wordlist='fixture',output_json_path=path)
    assert scanner_metadata(result)['status']=='error'


def run_offline(config):
    with ExitStack() as stack:
        stack.enter_context(patch.object(engine,'runtime_metadata',return_value={}))
        stack.enter_context(patch.object(requests.Session,'request',side_effect=requests.ConnectionError('offline fixture')))
        stack.enter_context(patch.object(engine,'urlopen',side_effect=OSError('offline fixture')))
        stack.enter_context(patch.object(engine.socket,'getaddrinfo',return_value=[]))
        stack.enter_context(patch.object(engine,'_filter_soft_error_discovery',side_effect=lambda **kw:(kw['gobuster_results'],kw['ffuf_results'],{'suppressed_count':0,'suppressed':[],'baselines':{}})))
        with redirect_stdout(io.StringIO()):
            engine.run(config)
    return json.loads((Path(config.output_dir)/'run_result.json').read_text())


def config_for(tmp_path, **overrides):
    flags={name:False for name in ['nmap_enabled','subfinder_enabled','dnsx_enabled','httpx_enabled','katana_enabled','gobuster_enabled','checks_enabled','nuclei_enabled','wafw00f_enabled','whatweb_enabled']}
    flags.update(overrides)
    return engine.RunConfig(target='http://127.0.0.1:9/',wordlist='fixture',output_dir=str(tmp_path/'run'),verbose=False,**flags)


@pytest.mark.parametrize('findings,status',[([], 'error'),([{'url':'http://127.0.0.1:9/admin','status':200}], 'partial')])
def test_engine_ffuf_returned_errors_drive_stage_and_coverage(tmp_path,findings,status):
    with patch.object(engine,'run_ffuf',return_value={'returncode':1,'error':'controlled failure','findings':findings}):
        data=run_offline(config_for(tmp_path,ffuf_enabled=True))
    assert data['stages']['ffuf']['status']==status
    assert data['stages']['ffuf']['failed_base_url_count']==1
    assert 'ffuf' in summarize_coverage(data['stages'])['failed']


def test_engine_keeps_successful_dns_batches_when_later_batch_raises(tmp_path):
    config=config_for(tmp_path,subfinder_enabled=True,dnsx_enabled=True)
    config.target='example.test';config.dnsx_batch=1
    with patch.object(engine,'run_subfinder',return_value=['child.example.test']), patch.object(engine,'run_dnsx',side_effect=[['child.example.test'],RuntimeError('second batch failed')]):
        data=run_offline(config)
    assert data['stages']['dnsx']['status']=='partial'
    artifact=json.loads((Path(config.output_dir)/'dnsx.json').read_text())
    assert artifact['resolved_hosts']==['child.example.test']
    assert artifact['batches'][1]['status']=='error'


@pytest.mark.parametrize('checked,status',[(0,'error'),(1,'partial')])
def test_web_check_error_records_are_not_done(tmp_path,checked,status):
    with patch.object(engine,'run_web_checks',return_value={'checked_count':checked,'errors':[{'url':'http://fixture','error':'timeout'}]}), patch.object(engine,'build_auth_profile',return_value=engine._empty_auth_profile()):
        data=run_offline(config_for(tmp_path,checks_enabled=True))
    assert data['stages']['checks']['status']==status


@pytest.fixture
def local_http():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                if self.path=='/redirect':
                    self.send_response(302);self.send_header('Location','/large');self.send_header('Content-Length','0');self.end_headers();return
                self.send_response(200)
                if self.path=='/slow':
                    self.send_header('Content-Length','1000');self.end_headers()
                    for _ in range(1000):self.wfile.write(b'a');self.wfile.flush();time.sleep(0.02)
                    return
                body=b'a'*1_000_000
                if self.path=='/gzip':body=gzip.compress(body);self.send_header('Content-Encoding','gzip')
                self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            except (BrokenPipeError,ConnectionResetError):pass
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    yield f'http://127.0.0.1:{server.server_port}'
    server.shutdown();server.server_close()


@pytest.mark.parametrize('route',['/large','/gzip'])
def test_download_cap_applies_before_content_materialization(local_http,route):
    with requests.Session() as session:
        response,text=_bounded_response(session,local_http+route,timeout_sec=2,max_bytes=12345)
    assert len(text)==12345
    assert response._content is False and response.raw.closed


def test_trickling_body_has_total_deadline_and_restores_signal(local_http):
    before=signal.getsignal(signal.SIGALRM)
    started=time.monotonic()
    with requests.Session() as session,pytest.raises(requests.Timeout):
        _bounded_response(session,local_http+'/slow',timeout_sec=0.15,max_bytes=100000)
    assert time.monotonic()-started < 0.8
    assert signal.getsignal(signal.SIGALRM)==before
    assert signal.getitimer(signal.ITIMER_REAL)[0]==0


def test_web_redirect_setting_reaches_network(local_http):
    with requests.Session() as session:
        response,_=_bounded_response(session,local_http+'/redirect',timeout_sec=2,max_bytes=10,follow_redirects=False)
    assert response.status_code==302 and response.url.endswith('/redirect')
    assert run_web_checks([local_http+'/large'],max_body_bytes=10)['checked_count']==1


@pytest.mark.parametrize('host,domain',[
    ('portal.example.co.uk','example.co.uk'),('mail.example.com.tr','example.com.tr'),
    ('a.example.co.nz','example.co.nz'),('a.example.com.br','example.com.br'),
    ('a.alice.github.io','alice.github.io'),('b.bob.github.io','bob.github.io'),
    ('127.0.0.1',''),('::1',''),('https://[::1]/',''),('co.uk',''),
    ('https://portal.example.co.uk/evidence','example.co.uk'),
])
def test_psl_boundaries_are_shared_and_offline(host,domain):
    with patch.object(requests.Session,'request',side_effect=AssertionError('PSL must stay offline')):
        assert registered_domain(host)==domain
    if host=='portal.example.co.uk':
        assert safe_reference_url('https://'+host+'/evidence')[3]==domain
        assert _match_item({'domains':[host]},target_host='www.example.co.uk',registered_domain=domain,aliases=[])[0]=='registered_domain'


def post(server, payload, route='/api/run'):
    body=json.dumps(payload).encode()
    try:
        response=urlopen(Request(f'http://127.0.0.1:{server.server_port}'+route,data=body,headers={'Content-Type':'application/json'}),timeout=3)
    except HTTPError as exc:response=exc
    with response:return response.status,json.load(response)


def test_legacy_concurrent_start_is_reserved_and_retry_folder_unique(tmp_path):
    entered=threading.Event();release=threading.Event()
    class Proc:
        pid=12345
        stdout=io.StringIO('')
        finished=False
        def poll(self):return 0 if self.finished else None
        def wait(self):self.finished=True;return 0
        def terminate(self):self.finished=True
    def spawn(*args,**kwargs):entered.set();assert release.wait(2);return Proc()
    with patch.object(gui.subprocess,'Popen',side_effect=spawn) as calls:
        server,_=gui._start_gui_app_server(base_output_dir=str(tmp_path),port=0)
        try:
            payload={'target':'http://fixture.test','tools':{'gobuster':False,'ffuf':False}}
            with ThreadPoolExecutor(max_workers=1) as pool:
                first=pool.submit(post,server,payload)
                assert entered.wait(2)
                second=post(server,payload)
                assert second[0]==409 and calls.call_count==1
                release.set();first=first.result(timeout=3)
            assert first[0]==200
            third=post(server,payload)
            assert third[0]==200 and first[1]['request_dir']!=third[1]['request_dir']
        finally:release.set();server.shutdown();server.server_close()


def test_legacy_config_write_failure_releases_start_reservation(tmp_path):
    server,_=gui._start_gui_app_server(base_output_dir=str(tmp_path),port=0)
    payload={'target':'http://fixture.test','tools':{'gobuster':False,'ffuf':False}}
    try:
        with patch.object(gui,'_write_app_config',side_effect=OSError('fixture disk error')):
            assert post(server,payload)[0]==500
            assert post(server,payload)[0]==500  # not a stale 409 reservation
    finally:server.shutdown();server.server_close()


@pytest.mark.parametrize('stdout', [b'http://fixture.test/partial\n', 'http://fixture.test/partial\n'])
def test_katana_timeout_keeps_partial_evidence_and_diagnostics(stdout):
    diagnostics={}
    error=katana.subprocess.TimeoutExpired(['katana'],1,output=stdout,stderr=b'fixture stderr')
    with patch.object(katana.subprocess,'run',side_effect=error) as call:
        urls=katana.run_katana(['http://fixture.test'],auto_js_crawl=False,timeout_sec=1,diagnostics=diagnostics)
    assert urls==['http://fixture.test/partial']
    assert 'timeout (1s)' in diagnostics['errors'][0] and 'fixture stderr' in diagnostics['errors'][0]
    assert '-duc' in call.call_args.args[0]


def test_legacy_stop_during_start_terminates_reserved_process(tmp_path):
    entered=threading.Event();release=threading.Event();terminated=threading.Event()
    class Proc:
        pid=12345
        stdout=io.StringIO('')
        def poll(self):return 0 if terminated.is_set() else None
        def wait(self):return 0
        def terminate(self):terminated.set()
    def spawn(*args,**kwargs):entered.set();assert release.wait(2);return Proc()
    with patch.object(gui.subprocess,'Popen',side_effect=spawn):
        server,_=gui._start_gui_app_server(base_output_dir=str(tmp_path),port=0)
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                start=pool.submit(post,server,{'target':'http://fixture.test','tools':{'gobuster':False,'ffuf':False}})
                assert entered.wait(2)
                assert post(server,{},'/api/stop')[0]==200
                release.set();assert start.result(timeout=3)[0]==200
            assert terminated.wait(1)
        finally:release.set();server.shutdown();server.server_close()


def test_old_legacy_reader_cannot_adopt_or_log_into_new_run(tmp_path):
    release=threading.Event();old_done=threading.Event()
    old_run=tmp_path/'runs/old';new_run=tmp_path/'runs/new'
    class Proc:
        pid=12345
        def __init__(self,old):self.old=old;self.stdout=self.lines()
        def lines(self):
            if self.old:assert release.wait(3)
            yield f'[+] Output (run): {old_run if self.old else new_run}\n'
            yield 'OLD_READER_ONLY\n' if self.old else 'NEW_READER_ONLY\n'
        def poll(self):return 0 if self.old else None
        def wait(self):
            if self.old:old_done.set();return 3
            return 0
        def terminate(self):pass
    def state(server):
        with urlopen(f'http://127.0.0.1:{server.server_port}/api/state',timeout=2) as response:
            return json.load(response)['app']
    with patch.object(gui.subprocess,'Popen',side_effect=[Proc(True),Proc(False)]):
        server,_=gui._start_gui_app_server(base_output_dir=str(tmp_path),port=0)
        try:
            payload={'target':'http://fixture.test','tools':{'gobuster':False,'ffuf':False}}
            assert post(server,payload)[0]==200
            assert post(server,payload)[0]==200
            for _ in range(100):
                if state(server)['current_run_dir']==str(new_run):break
                time.sleep(0.01)
            assert state(server)['current_run_dir']==str(new_run)
            release.set();assert old_done.wait(1)
            current=state(server)
            assert current['current_run_dir']==str(new_run) and current['error']==''
            assert 'OLD_READER_ONLY' not in (new_run/'reconbot.log').read_text()
            assert 'OLD_READER_ONLY' in (old_run/'reconbot.log').read_text()
        finally:release.set();server.shutdown();server.server_close()
