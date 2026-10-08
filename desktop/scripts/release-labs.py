"""Four disposable loopback sites for ReconBot release QA. Python stdlib only."""
import argparse
import base64
import binascii
from contextlib import closing
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import sqlite3
import threading
from urllib.parse import parse_qs, urlsplit

USERNAME = 'operator'
PASSWORD = 'reconbot-demo-2026'
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / 'build/release-labs'
PROFILES = (
    ('clean', '01 / Protected', 'Negative controls: protected SQL queries and no exposed configuration.'),
    ('medium', '02 / Configuration exposure', 'Git configuration and a public backup listing. SQL remains protected.'),
    ('exposed', '03 / Multiple exposures', 'Synthetic environment, Git, debug, backup and unprotected admin data.'),
    ('validation', '04 / SQL & authentication', 'Vulnerable SQL, protected SQL, Basic and form login, and stop conditions.'),
)
STYLE = '''body{margin:0;background:#10161b;color:#edf4f6;font:17px/1.6 system-ui,sans-serif}
main{max-width:960px;margin:6vh auto;padding:24px}header{border-bottom:1px solid #31424b;padding-bottom:28px}
small{color:#69ddc8;letter-spacing:.12em}h1{font-size:clamp(30px,5vw,54px);line-height:1.1;margin:18px 0}
p{color:#aebec8}a{color:#80e4d0}ul{padding-left:24px}li{padding:7px 0}code{background:#23313b;padding:3px 8px}
form{max-width:440px}label{display:block;margin:18px 0 5px}input,button{box-sizing:border-box;width:100%;font:inherit;padding:12px;background:#1b2831;color:#fff;border:1px solid #425867;border-radius:6px}
button{margin-top:22px;background:#68ddc7;color:#10211d;font-weight:700}footer{margin-top:40px;color:#9fadb8;font-size:14px}'''


def page(title, body):
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{escape(title)} | ReconBot Lab</title><link rel="stylesheet" href="/assets/site.css">'
            f'</head><body><main><header><small>RECONBOT / LOCAL TEST LAB</small><h1>{escape(title)}</h1>'
            '</header>' + body + '<footer>Synthetic local data · No external services · '
            '<a href="/">Lab home</a></footer></main></body></html>')


class LabServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, profile, port=0):
        if profile not in {item[0] for item in PROFILES}:
            raise ValueError('Unknown lab profile')
        self.profile = profile
        self.request_count = 0
        self.counter_lock = threading.Lock()
        super().__init__(('127.0.0.1', port), LabHandler)


class LabHandler(BaseHTTPRequestHandler):
    server_version = 'ReconBotLab'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_):
        pass

    def send(self, status, body, content_type='text/html; charset=utf-8', headers=None):
        data = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        if self.server.profile == 'clean':
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
            self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.close_connection = True
        if self.command != 'HEAD':
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch()

    def do_OPTIONS(self):
        self.send(405, 'Method not supported', headers={'Allow': 'GET, HEAD, POST'})

    def dispatch(self):
        with self.server.counter_lock:
            self.server.request_count += 1
        try:
            if len(self.path) > 16384:
                return self.send(414, 'Request URI too long')
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=100)
            if self.headers.get('Transfer-Encoding'):
                return self.send(400, 'Transfer encoding not supported')
            raw_length = self.headers.get('Content-Length', '0')
            if not raw_length.isdecimal():
                return self.send(400, 'Invalid content length')
            size = int(raw_length)
            if size > 65536:
                return self.send(413, 'Request body too large')
            if self.command == 'POST':
                raw = self.rfile.read(size)
                if len(raw) != size:
                    return self.send(400, 'Incomplete body')
                query = parse_qs(raw.decode('utf-8'), keep_blank_values=True, max_num_fields=100)
            return self.route(parsed.path, query)
        except (UnicodeDecodeError, ValueError):
            return self.send(400, 'Malformed request')
        except (TimeoutError, ConnectionError):
            self.close_connection = True

    def route(self, route, query):
        profile = self.server.profile
        if self.command == 'POST' and route not in ('/item', '/clean', '/login', '/login-redirect', '/login-lockout', '/login-ambiguous'):
            return self.send(405 if route in ('/', '/about', '/docs', '/assets/site.css') else 404, 'Route does not accept POST')
        if route == '/assets/site.css':
            return self.send(200, STYLE, 'text/css; charset=utf-8')
        if route == '/health':
            return self.send(200, json.dumps({'profile': profile, 'status': 'ready'}), 'application/json')
        if route == '/':
            _, title, description = next(item for item in PROFILES if item[0] == profile)
            links = [('/about', 'About'), ('/docs', 'Documentation'), ('/item?id=1', 'Product 1'), ('/item?id=2', 'Product 2'), ('/clean?id=1', 'Protected SQL control')]
            if profile in ('medium', 'exposed'):
                links += [('/backup/', 'Backup inventory'), ('/admin', 'Admin access')]
            if profile == 'exposed':
                links += [('/admin/dashboard', 'Unprotected admin preview'), ('/debug/vars', 'Debug variables')]
            if profile == 'validation':
                links += [(path, label) for path, label in (('/basic', 'HTTP Basic login'), ('/login', 'Form login'), ('/login-redirect', 'Redirect login'), ('/basic-rate-limit', 'Rate-limit stop'), ('/login-lockout', 'Lockout stop'), ('/login-ambiguous', 'Ambiguous outcome'))]
            body = '<p>' + escape(description) + '</p><ul>' + ''.join(f'<li><a href="{escape(path, quote=True)}">{escape(label)}</a></li>' for path, label in links) + '</ul>'
            return self.send(200, page(title, body))
        if route in ('/about', '/docs'):
            return self.send(200, page('Lab documentation', '<p>All records and credentials in this site are fictional.</p><p>Unknown routes return HTTP 404. Finding a URL alone does not prove exploitation.</p>'))
        if route in ('/item', '/clean'):
            return self.items(query, vulnerable=profile == 'validation' and route == '/item')
        if profile in ('medium', 'exposed'):
            if route == '/.git/config':
                return self.send(200, '[core]\nrepositoryformatversion = 0\n[remote "origin"]\nurl = https://example.invalid/synthetic-lab.git\n', 'text/plain; charset=utf-8')
            if route in ('/backup', '/backup/'):
                return self.send(200, page('Index of /backup/', '<ul><li><a href="/backup/config.json">config.json</a></li></ul>'))
            if route == '/backup/config.json':
                return self.send(200, '{"database":"synthetic_lab","password":"FAKE-BACKUP-PASSWORD","fixture":true}', 'application/json')
            if route == '/admin':
                return self.send(403, page('Access denied', '<p>Protected page. A 403 response is not an authentication bypass.</p>'))
        if profile == 'exposed':
            if route in ('/.env', '/.env.bak'):
                return self.send(200, 'APP_NAME=ReconBotSyntheticLab\nAPP_ENV=local\nAPP_DEBUG=true\nDB_HOST=127.0.0.1\nDB_DATABASE=synthetic_lab\nDB_PASSWORD=FAKE-ENV-PASSWORD\n', 'text/plain; charset=utf-8')
            if route == '/debug/vars':
                return self.send(200, '{"cmdline":["synthetic-lab"],"memstats":{"Alloc":1024},"fixture":true}', 'application/json')
            if route == '/admin/dashboard':
                return self.send(200, page('Unprotected admin preview', '<p>Fictional internal account inventory exposed without login.</p><ul><li>qa-operator</li><li>qa-reviewer</li></ul>'))
        if profile == 'validation':
            if route in ('/basic', '/basic-rate-limit'):
                headers = {'WWW-Authenticate': 'Basic realm="ReconBot local lab"'}
                authorization = self.headers.get('Authorization', '')
                if not authorization:
                    return self.send(401, 'Invalid credentials', headers=headers)
                if route == '/basic-rate-limit':
                    return self.send(429, 'Rate limit reached', headers={'Retry-After': '60'})
                try:
                    scheme, token = authorization.split(' ', 1)
                    valid = scheme.lower() == 'basic' and base64.b64decode(token, validate=True).decode('utf-8') == USERNAME + ':' + PASSWORD
                except (ValueError, UnicodeDecodeError, binascii.Error):
                    valid = False
                return self.send(200 if valid else 401, 'Welcome operator' if valid else 'Invalid credentials', headers=None if valid else headers)
            if route in ('/login', '/login-redirect', '/login-lockout', '/login-ambiguous'):
                if self.command != 'POST':
                    return self.send(200, page('Form login', f'<form action="{route}" method="post"><label for="username">Username</label><input id="username" name="username" autocomplete="username"><label for="password">Password</label><input id="password" type="password" name="password" autocomplete="current-password"><button>Sign in</button></form>'))
                username, password = query.get('username', [''])[0], query.get('password', [''])[0]
                probe = username.startswith('reconbot_probe_')
                if route == '/login-lockout' and not probe:
                    return self.send(200, 'account locked')
                if route == '/login-ambiguous' and not probe:
                    return self.send(200, 'Please continue')
                if username == USERNAME and password == PASSWORD:
                    if route == '/login-redirect':
                        return self.send(302, '', headers={'Location': '/account'})
                    return self.send(200, 'Welcome operator')
                return self.send(200, 'Invalid credentials')
            if route == '/account':
                # A synthetic destination, not a real account/session implementation.
                return self.send(200, page('Redirect destination', '<p>Fictional page used only to test Location matching.</p>'))
        return self.send(404, page('Not found', '<p>This route does not exist.</p>'))

    def items(self, query, vulnerable):
        value = query.get('id', ['1'])[0]
        with closing(sqlite3.connect(':memory:')) as connection:
            connection.execute('CREATE TABLE products (id integer, name text)')
            connection.executemany('INSERT INTO products VALUES (?,?)', [(i, 'product-' + str(i)) for i in range(1, 21)])
            # Permit read-only queries against this request's disposable synthetic database.
            def authorize(action, arg1, arg2, *_):
                allowed = action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION)
                if action == sqlite3.SQLITE_FUNCTION and str(arg2).lower() in ('load_extension', 'readfile', 'writefile'):
                    allowed = False
                return sqlite3.SQLITE_OK if allowed else sqlite3.SQLITE_DENY
            connection.set_authorizer(authorize)
            try:
                rows = (connection.execute('SELECT id,name FROM products WHERE id=' + value) if vulnerable else connection.execute('SELECT id,name FROM products WHERE id=?', (value,))).fetchall()
                body = '<h2>Items</h2>' + ''.join('<p>' + escape(str(row)) + '</p>' for row in rows)
            except sqlite3.Error as exc:
                body = '<p>SQLite error: ' + escape(str(exc)) + '</p>' if vulnerable else '<p>No matching item.</p>'
        return self.send(200, page('Product catalog', body))


def write_assets(folder, ports):
    folder.mkdir(parents=True, exist_ok=True)
    values = {
        'discovery.txt': 'about\ndocs\nitem\nclean\nadmin\nadmin/dashboard\nbackup\nbackup/\nbackup/config.json\n.git/config\n.env\n.env.bak\ndebug/vars\nbasic\nbasic-rate-limit\nlogin\nlogin-redirect\nlogin-lockout\nlogin-ambiguous\naccount\nmissing-route\n',
        'usernames.txt': 'unknown-user\n' + USERNAME + '\n',
        'passwords.txt': 'wrong-password\nanother-wrong-password\n' + PASSWORD + '\n',
        'passwords-negative.txt': 'wrong-password\nanother-wrong-password\n',
        'passwords-long.txt': ''.join(f'wrong-{i:04d}\n' for i in range(1, 251)) + PASSWORD + '\n',
    }
    for name, content in values.items():
        (folder / name).write_text(content, encoding='utf-8')
    manifest = {'sites': [{'profile': item[0], 'url': f'http://127.0.0.1:{port}'} for item, port in zip(PROFILES, ports)], 'credentials': {'username': USERNAME, 'password': PASSWORD}, 'wordlists': {name: str(folder / name) for name in values}}
    (folder / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-port', type=int, default=8085)
    parser.add_argument('--output-dir', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--stop', action='store_true', help='Request shutdown of this lab suite only.')
    args = parser.parse_args()
    folder = args.output_dir.resolve()
    stop_file, pid_file = folder / 'stop.request', folder / 'server.pid'
    if args.stop:
        if not pid_file.exists():
            parser.exit(1, 'No running lab suite recorded.\n')
        stop_file.touch()
        print('Shutdown requested for the four release labs.', flush=True)
        return
    if not 1024 <= args.base_port <= 65532:
        parser.error('Choose a base port from 1024 to 65532.')
    servers, threads = [], []
    stopping = threading.Event()
    try:
        for offset, profile in enumerate(PROFILES):
            servers.append(LabServer(profile[0], args.base_port + offset))
        manifest = write_assets(folder, [server.server_port for server in servers])
        stop_file.unlink(missing_ok=True)
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .1}, daemon=True)
            thread.start()
            threads.append(thread)
        pid_file.write_text(str(os.getpid()), encoding='utf-8')
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stopping.set())
        print(json.dumps(manifest, indent=2), flush=True)
        print('Ready. Ctrl+C or the same script with --stop closes all four sites.', flush=True)
        while not stopping.wait(.25):
            if stop_file.exists():
                break
    except OSError as exc:
        parser.exit(1, f'Cannot start lab suite: {exc}. Existing servers were not changed.\n')
    finally:
        for server, thread in zip(servers, threads):
            server.shutdown()
            thread.join(timeout=2)
        for server in servers:
            server.server_close()
        if threads:
            pid_file.unlink(missing_ok=True)
            stop_file.unlink(missing_ok=True)
            print('All four release labs closed.', flush=True)


if __name__ == '__main__':
    main()
