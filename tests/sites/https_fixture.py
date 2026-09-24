"""Loopback TLS fixture. This module is never packaged with Shadow."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
from urllib.parse import parse_qs

FORM = '<form action="/session" method="post"><input id="username" name="username"><input id="password" name="password" type="password"><button id="submit" type="submit">Sign in</button></form>'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path == "/login":
            self.reply(200, FORM)
        elif self.path == "/items" and self.headers.get("Cookie") == "fixture_session=synthetic-http-only-canary":
            self.reply(200, '<main data-view="items"><h1>Saved items</h1><ul><li>Example report</li></ul></main>')
        else:
            self.reply(404, "")

    def do_POST(self):
        size = self.headers.get("Content-Length", "")
        if self.path != "/session" or not size.isdigit() or not 0 < int(size) <= 1024:
            self.reply(400, "")
            return
        values = parse_qs(self.rfile.read(int(size)).decode("utf-8"))
        if values != {"username": ["synthetic-user"], "password": ["synthetic-atomic-auth-canary"]}:
            self.reply(403, "")
            return
        self.server.submissions += 1
        self.reply(303, "", {"Location": "/items", "Set-Cookie": "fixture_session=synthetic-http-only-canary; Secure; HttpOnly; SameSite=Strict; Path=/"})

    def reply(self, status, body, headers=None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)


class Fixture(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, directory: Path):
        super().__init__(("127.0.0.1", 0), Handler)
        self.submissions = 0
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(directory / "cert.pem", directory / "key.pem")
        self.socket = context.wrap_socket(self.socket, server_side=True)

    def handle_error(self, *_):
        pass
