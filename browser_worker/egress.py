"""Browser-only loopback CONNECT proxy to the host's leased vsock gateway."""
from collections.abc import Callable
import ipaddress
import json
import re
import select
import socket
import socketserver
import struct
import threading

from .errors import BrowserFailure, Code
from .watchdog import WorkerLease


def authority_from_header(header: bytes) -> str:
    try:
        if len(header) > 8192 or not header.endswith(b"\r\n\r\n"):
            raise ValueError
        lines = header[:-4].decode("ascii").split("\r\n")
        method, authority, version = lines[0].split(" ")
        if method != "CONNECT" or version != "HTTP/1.1" or not authority.endswith(":443"):
            raise ValueError
        host = authority[:-4]
        labels = host.split(".")
        if len(host) > 253 or len(labels) < 2 or not any(c.isalpha() for c in labels[-1]):
            raise ValueError
        if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError
        seen = set()
        for line in lines[1:]:
            name, value = line.split(":", 1)
            name = name.lower()
            if name in seen or name not in {"host", "connection", "proxy-connection", "user-agent"}:
                raise ValueError
            seen.add(name)
            if name == "host" and value.strip() != authority:
                raise ValueError
            if any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise ValueError
        return host
    except (ValueError, UnicodeError):
        raise BrowserFailure(Code.INVALID_REQUEST) from None


def read_exact(channel, count):
    data = bytearray()
    while len(data) < count:
        piece = channel.recv(count - len(data))
        if not piece:
            raise BrowserFailure(Code.UNAVAILABLE)
        data.extend(piece)
    return bytes(data)


def host_tunnel(hostname: str) -> socket.socket:
    channel = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    try:
        channel.settimeout(5)
        channel.connect((socket.VMADDR_CID_HOST, 4053))
        data = json.dumps({"host": hostname, "port": 443}, separators=(",", ":")).encode()
        channel.sendall(struct.pack("!I", len(data)) + data)
        length = struct.unpack("!I", read_exact(channel, 4))[0]
        if not 0 < length <= 512 or json.loads(read_exact(channel, length)) != {"kind": "connected"}:
            raise BrowserFailure(Code.UNAVAILABLE)
        return channel
    except BaseException:
        channel.close()
        raise


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def handle_error(self, *_):
        pass

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class _Request(socketserver.BaseRequestHandler):
    def handle(self):
        lease, connect = self.server.lease, self.server.connect
        browser = self.request
        browser.settimeout(1)
        try:
            lease.check()
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                piece = browser.recv(1)
                if not piece or len(header) >= 8192:
                    return
                header.extend(piece)
                lease.check()
            hostname = authority_from_header(bytes(header))
            with connect(hostname) as host:
                lease.check()
                host.settimeout(0.2)
                browser.settimeout(0.2)
                browser.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                total = 0
                while True:
                    lease.check()
                    ready, _, _ = select.select([browser, host], [], [], 0.1)
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        total += len(data)
                        if total > 16 * 1024 * 1024:
                            return
                        lease.check()
                        (host if source is browser else browser).sendall(data)
        except (BrowserFailure, OSError, ValueError):
            pass


class ConnectProxy:
    def __init__(self, lease: WorkerLease, *, connect: Callable[[str], socket.socket] = host_tunnel):
        self._server = _Server(("127.0.0.1", 0), _Request)
        self._server.lease = lease
        self._server.connect = connect
        self._server.slots = threading.BoundedSemaphore(8)
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        self.port = self._server.server_address[1]

    def start(self):
        self._server.lease.check()
        self._thread.start()

    def close(self):
        self._server.lease.revoke()
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=1)
