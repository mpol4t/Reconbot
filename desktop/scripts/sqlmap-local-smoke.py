"""Real SQLmap against disposable loopback SQLite fixtures; no external targets."""
import argparse
import json
from pathlib import Path
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from reconbot.validation.sqlmap import run_job

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self): self.respond(parse_qs(urlsplit(self.path).query, keep_blank_values=True))
    def do_POST(self): self.respond(parse_qs(self.rfile.read(int(self.headers.get('Content-Length', 0))).decode(), keep_blank_values=True))
    def respond(self, query):
        connection = sqlite3.connect(':memory:')
        connection.execute('CREATE TABLE users (id integer, name text)')
        connection.executemany('INSERT INTO users VALUES (?,?)', [(i, 'person-' + str(i)) for i in range(1,21)])
        value = query.get('id', ['1'])[0]
        try:
            if self.path.startswith('/clean'):
                rows = connection.execute('SELECT id,name FROM users WHERE id=?', (value,)).fetchall()
            else:
                rows = connection.execute('SELECT id,name FROM users WHERE id=' + value).fetchall()
            body = '<h1>Items</h1>' + ''.join('<p>' + str(row) + '</p>' for row in rows)
        except Exception as exc:
            body = 'SQLite error: ' + str(exc)
        finally: connection.close()
        data = ('<html><body>' + body + '</body></html>').encode()
        self.send_response(200); self.send_header('Content-Type','text/html'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', nargs='?', default='desktop/build/sqlmap-local-qa')
    parser.add_argument('--serve', action='store_true', help='Keep the fixture running for manual GUI testing; no scans are started.')
    parser.add_argument('--port', type=int, default=8083, help='Loopback port in --serve mode (default: 8083).')
    args = parser.parse_args()
    server = ThreadingHTTPServer(('127.0.0.1', args.port if args.serve else 0), Handler)
    url = f'http://127.0.0.1:{server.server_port}'
    if args.serve:
        print(f'Target: {url}\nVulnerable GET: {url}/item?id=1\nClean GET: {url}/clean?id=1\nPOST: {url}/item (body: id=1)\nStop: Ctrl+C', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    root = Path(args.output).resolve()
    root.mkdir(parents=True, exist_ok=True)
    try:
        results=[]
        for name, method in [('vulnerable','GET'),('clean','GET'),('post','POST')]:
            job=root / name;job.mkdir(exist_ok=True)
            request={'runDir':str(root),'target':url,'url':url + ('/clean' if name=='clean' else '/item') + ('?id=1' if method=='GET' else ''),'parameter':'id','method':method,'body':'id=1' if method=='POST' else '', 'cookie':'', 'duration':120,'delay':0,'level':1,'risk':1,'timeout':3,'threads':1}
            (job/'request.json').write_text(json.dumps(request))
            result=run_job(job);results.append({'name':name,'status':result['status'],'evidence':len(result['evidence'])});print(json.dumps(results[-1]),flush=True)
        (root/'summary.json').write_text(json.dumps(results,indent=2))
        assert [r['status'] for r in results]==['detected','not_detected','detected'],results
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
