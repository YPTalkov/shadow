"""Guest-only loopback HTTP bridge to the instance-bound host model channel."""

import json
import socket
import struct
from http.server import BaseHTTPRequestHandler, HTTPServer

MAX_FRAME = 4 * 1024 * 1024
MODEL_PORT = 4051


def read_exact(connection: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise ConnectionError("channel_closed")
        result.extend(chunk)
    return bytes(result)


def receive(connection: socket.socket) -> dict:
    count = struct.unpack("!I", read_exact(connection, 4))[0]
    if not 0 < count <= MAX_FRAME:
        raise ValueError("invalid_frame")
    value = json.loads(read_exact(connection, count))
    if not isinstance(value, dict):
        raise ValueError("invalid_frame")
    return value


def send(connection: socket.socket, value: dict) -> None:
    data = json.dumps(value, separators=(",", ":")).encode()
    if not 0 < len(data) <= MAX_FRAME:
        raise ValueError("invalid_frame")
    connection.sendall(struct.pack("!I", len(data)) + data)


class ModelBridge(HTTPServer):
    def __init__(self, port: int = 0):
        super().__init__(("127.0.0.1", port), ModelRequest)
        self.timeout = 1

    def handle_error(self, request, client_address):
        pass


class ModelRequest(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def do_POST(self):
        started = False
        self.close_connection = True
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if (
                self.path != "/v1/responses"
                or len(lengths) != 1
                or self.headers.get("Transfer-Encoding")
                or self.headers.get("Upgrade")
                or len(self.headers) > 24
            ):
                raise ValueError("invalid_request")
            length = int(lengths[0])
            if not 0 < length <= MAX_FRAME:
                raise ValueError("invalid_request")
            payload = self.rfile.read(length)
            if len(payload) != length:
                raise ValueError("invalid_request")
            body = json.loads(payload)
            headers = {}
            for name, value in self.headers.items():
                if name.lower() in ("host", "content-length", "connection", "accept-encoding"):
                    continue
                if name.lower() in headers:
                    raise ValueError("invalid_request")
                headers[name.lower()] = value
            with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as host:
                host.settimeout(180)
                host.connect((socket.VMADDR_CID_HOST, MODEL_PORT))
                send(host, {"method": "POST", "path": self.path, "headers": headers, "body": body})
                start = receive(host)
                if start != {"kind": "start", "status": 200}:
                    raise ValueError("relay_denied")
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.end_headers()
                started = True
                while True:
                    frame = receive(host)
                    if frame == {"kind": "end"}:
                        self.wfile.write(b"0\r\n\r\n")
                        break
                    if frame.get("kind") != "event" or not isinstance(frame.get("data"), str):
                        raise ValueError("invalid_response")
                    data = frame["data"].encode()
                    self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                    self.wfile.flush()
        except (OSError, ValueError, TypeError, ConnectionError):
            if not started:
                payload = b'{"error":{"code":"model_relay_unavailable"}}'
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)
