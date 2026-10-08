"""Loopback-only synthetic Basic/form login fixture for manual and automated QA."""
import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import time
from urllib.parse import parse_qs, urlsplit

USERNAME = 'operator'
PASSWORD = 'reconbot-demo-2026'


class LoginServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, port=0):
        super().__init__(('127.0.0.1', port), LoginHandler)
        self.requests_seen = []


class LoginHandler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def send(self, status, body, headers=None):
        data = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        for name, value in (headers or {}).items(): self.send_header(name, value)
        self.end_headers()
        try: self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError): pass
    def do_GET(self):
        route = urlsplit(self.path).path
        header = self.headers.get('Authorization', '')
        self.server.requests_seen.append(('GET', route, header))
        if route == '/public' or route == '/account':
            return self.send(200, 'Public page')
        if route == '/slow':
            time.sleep(20)
            return self.send(401, 'Invalid credentials', {'www-authenticate': 'Basic realm="ReconBot demo"'})
        if route.startswith('/basic'):
            if not header:
                return self.send(401, 'Invalid credentials', {'www-authenticate': 'Basic realm="ReconBot demo"'})
            if route == '/basic-rate-limit':
                return self.send(429, 'Rate limit', {'retry-after': '60'})
            try: pair = base64.b64decode(header.split(' ', 1)[1]).decode('utf-8')
            except Exception: pair = ''
            return self.send(200 if pair == USERNAME + ':' + PASSWORD else 401, 'Welcome operator' if pair == USERNAME + ':' + PASSWORD else 'Invalid credentials', {'www-authenticate': 'Basic realm="ReconBot demo"'})
        return self.send(200, '<h1>ReconBot login fixture</h1><p>Basic: /basic · POST: /form · POST redirect: /form-redirect</p>')
    def do_POST(self):
        route = urlsplit(self.path).path
        size = int(self.headers.get('Content-Length', '0'))
        if size > 65536: return self.send(413, 'Too large')
        fields = parse_qs(self.rfile.read(size).decode('utf-8'), keep_blank_values=True)
        username, password = fields.get('username', [''])[0], fields.get('password', [''])[0]
        self.server.requests_seen.append(('POST', route, fields))
        probe = username.startswith('reconbot_probe_')
        valid = username == USERNAME and password == PASSWORD
        if route == '/form-lockout' and not probe: return self.send(200, 'ACCOUNT LOCKED')
        if route == '/form-ambiguous' and not probe: return self.send(200, 'Please continue')
        if route == '/form-both' and not probe: return self.send(200, 'Welcome operator · Invalid credentials')
        if valid and route == '/form-redirect': return self.send(302, '', {'Location': '/account'})
        if valid and route == '/form-away': return self.send(302, '', {'Location': 'http://outside.invalid/account'})
        return self.send(200, 'Welcome operator' if valid else 'Invalid credentials')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8084)
    parser.add_argument('--output-dir', default='desktop/build/authentication-demo')
    args = parser.parse_args()
    folder = Path(args.output_dir).resolve(); folder.mkdir(parents=True, exist_ok=True)
    users, passwords = folder / 'usernames.txt', folder / 'passwords.txt'
    # Only these fixture-owned demo files are created; existing files stay intact.
    if not users.exists(): users.write_text('unknown-user\n' + USERNAME + '\n')
    if not passwords.exists(): passwords.write_text('wrong-password\nanother-wrong-password\n' + PASSWORD + '\n')
    server = LoginServer(args.port)
    print(f'Target: http://127.0.0.1:{server.server_port}\nBasic login: /basic\nPOST form: /form\nFields: username, password\nSuccess text: Welcome operator\nFailure text: Invalid credentials\nUsername: {USERNAME}\nPassword: {PASSWORD}\nUsernames: {users}\nPasswords: {passwords}\nStop: Ctrl+C', flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()


if __name__ == '__main__': main()
