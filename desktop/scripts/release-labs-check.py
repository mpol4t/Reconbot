"""Validate the release labs using installed scanners and ReconBot job backends."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import threading

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from reconbot.validation.authentication import run_job as auth_job
from reconbot.validation.sqlmap import run_job as sql_job

spec = importlib.util.spec_from_file_location('release_labs', Path(__file__).with_name('release-labs.py'))
labs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(labs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'desktop/build/release-labs-qa')
    parser.add_argument('--templates', type=Path, default=Path.home() / 'nuclei-templates')
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / 'summary.json').write_text('[]\n', encoding='utf-8')
    tools = {name: shutil.which(name) for name in ('sqlmap', 'nuclei', 'katana', 'gobuster', 'ffuf')}
    if not all(tools.values()):
        parser.error('Missing installed tool(s): ' + ', '.join(name for name, path in tools.items() if not path))
    templates = [args.templates / 'http/exposures' / name for name in ('configs/git-config.yaml', 'configs/laravel-env.yaml', 'configs/debug-vars.yaml', 'backups/backup-directory-listing.yaml')]
    if not all(path.is_file() for path in templates):
        parser.error('The four stock Nuclei exposure templates are required.')
    servers = [labs.LabServer(profile[0]) for profile in labs.PROFILES]
    threads = []
    summary = []

    def record(name, **values):
        summary.append({'check': name, **values})
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(summary[-1]), flush=True)

    def command(name, argv, timeout=60):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        (output / (name + '.log')).write_text(result.stdout + result.stderr, encoding='utf-8')
        if result.returncode:
            raise AssertionError(f'{name} failed ({result.returncode}); see its log.')

    try:
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
            thread.start()
            threads.append(thread)
        manifest = labs.write_assets(output / 'wordlists', [server.server_port for server in servers])
        bases = {site['profile']: site['url'] for site in manifest['sites']}
        wordlist = str(output / 'wordlists/discovery.txt')
        for profile, base in bases.items():
            crawl = output / (profile + '-katana.txt')
            crawl.unlink(missing_ok=True)
            command(profile + '-katana', [tools['katana'], '-u', base, '-d', '2', '-silent', '-duc', '-rl', '20', '-c', '2', '-p', '2', '-o', str(crawl)])
            urls = crawl.read_text().splitlines()
            assert any('/item?id=1' in url for url in urls), (profile, urls)
            record(profile + '-katana', urls=len(urls))
            gobuster = output / (profile + '-gobuster.txt')
            gobuster.unlink(missing_ok=True)
            command(profile + '-gobuster', [tools['gobuster'], 'dir', '-u', base, '-w', wordlist, '-t', '2', '-q', '-o', str(gobuster)])
            text = gobuster.read_text()
            assert 'missing-route' not in text and any(line.lstrip('/').startswith('about ') for line in text.splitlines()), text
            fuzz = output / (profile + '-ffuf.json')
            fuzz.unlink(missing_ok=True)
            command(profile + '-ffuf', [tools['ffuf'], '-u', base + '/FUZZ', '-w', wordlist, '-mc', '200,204,301,302,307,308,401,403,405', '-t', '2', '-rate', '20', '-noninteractive', '-of', 'json', '-o', str(fuzz)])
            matches = json.loads(fuzz.read_text())['results']
            assert not any('missing-route' in item['url'] for item in matches)
            assert any('/about' in item['url'] for item in matches)
            record(profile + '-discovery', gobuster=True, ffuf_matches=len(matches))
        targets = output / 'targets.txt'
        targets.write_text('\n'.join(bases.values()) + '\n')
        nuclei = output / 'nuclei.jsonl'
        nuclei.unlink(missing_ok=True)
        command('nuclei', [tools['nuclei'], '-l', str(targets), '-t', ','.join(str(path) for path in templates), '-duc', '-ni', '-dr', '-rl', '20', '-c', '2', '-bs', '2', '-timeout', '3', '-silent', '-jsonl', '-o', str(nuclei)], timeout=90)
        rows = [json.loads(line) for line in nuclei.read_text().splitlines() if line.strip()]
        for profile, base in bases.items():
            matches = [row for row in rows if row['matched-at'].startswith(base + '/')]
            ids = sorted({row['template-id'] for row in matches})
            expected = [] if profile in ('clean', 'validation') else ['backup-directory-listing', 'git-config'] if profile == 'medium' else ['backup-directory-listing', 'debug-vars', 'git-config', 'laravel-env']
            assert ids == expected, (profile, ids)
            record(profile + '-nuclei-selected-templates', templates=ids, matches=len(matches))
        base = bases['validation']
        for name, route, method, expected in [('sql-get', '/item?id=1', 'GET', 'detected'), ('sql-post', '/item', 'POST', 'detected'), ('sql-negative', '/clean?id=1', 'GET', 'not_detected')]:
            folder = output / name
            folder.mkdir(exist_ok=True)
            config = dict(runDir=str(output), target=base, url=base + route, parameter='id', method=method, body='id=1' if method == 'POST' else '', cookie='', duration=120, delay=0, level=1, risk=1, timeout=3, threads=1)
            (folder / 'request.json').write_text(json.dumps(config))
            result = sql_job(folder)
            record(name, status=result['status'], evidence=len(result['evidence']))
            assert result['status'] == expected, result
        cases = [('/basic', 'basic', 'passwords.txt', 'accepted', 3, 'single'), ('/login', 'form', 'passwords.txt', 'accepted', 3, 'single'), ('/login-redirect', 'form', 'passwords.txt', 'accepted', 3, 'single'), ('/basic', 'basic', 'passwords-long.txt', 'accepted', 251, 'single'), ('/basic', 'basic', 'passwords-negative.txt', 'not_accepted', 2, 'single'), ('/basic-rate-limit', 'basic', 'passwords.txt', 'blocked', 1, 'single'), ('/login-lockout', 'form', 'passwords.txt', 'blocked', 1, 'single'), ('/login-ambiguous', 'form', 'passwords.txt', 'inconclusive', 1, 'single'), ('/basic', 'basic', 'passwords.txt', 'accepted', 6, 'wordlist')]
        for i, (route, mode, passwords, expected, pairs, user_source) in enumerate(cases):
            folder = output / f'auth-{i}'
            folder.mkdir(exist_ok=True)
            config = dict(runDir=str(output), target=base, url=base + route, mode=mode, usernameSource=user_source, username=labs.USERNAME, usernameWordlist=str(output / 'wordlists/usernames.txt'), passwordWordlist=str(output / 'wordlists' / passwords), usernameField='username', passwordField='password', extraBody='', successMode='location' if route == '/login-redirect' else 'body', successValue='/account' if route == '/login-redirect' else 'Welcome operator', failureValue='Invalid credentials', lockoutValue='account locked', maxAttempts=300, duration=60, timeout=2, delay=0)
            (folder / 'request.json').write_text(json.dumps(config))
            result = auth_job(folder)
            record(f'auth-{i}', route=route, status=result['status'], pairs=len(result['attempts']))
            assert result['status'] == expected and len(result['attempts']) == pairs, result
            if expected == 'accepted':
                report = (folder / 'report.html').read_text()
                assert report.index('Accepted credentials') < report.index('See failed attempts')
        record('complete', passed=True, note='Targeted installed scanners and real job backends; GUI and full default Nuclei suite are separate tests.')
    finally:
        for server, thread in zip(servers, threads):
            server.shutdown()
            thread.join(timeout=2)
        for server in servers:
            server.server_close()


if __name__ == '__main__':
    main()
