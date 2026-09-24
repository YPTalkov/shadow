"""Guest-only client: fixed host vsock port, no filesystem or TCP fallback."""

from collections.abc import Callable
import socket
import struct

from .protocol import AgentError, MAX_FRAME, RESPONSE_SCHEMA, accepts, decode, encode, request


def _read(connection: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise AgentError("transport_unavailable")
        result.extend(chunk)
    return bytes(result)


def exchange(data: bytes) -> bytes:
    if not hasattr(socket, "AF_VSOCK"):
        raise AgentError("transport_unavailable")
    try:
        with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect((2, 4050))
            connection.sendall(struct.pack("!I", len(data)) + data)
            length = struct.unpack("!I", _read(connection, 4))[0]
            if not 0 < length <= MAX_FRAME:
                raise AgentError("response_limit")
            return _read(connection, length)
    except OSError:
        raise AgentError("transport_unavailable") from None


class ShadowClient:
    def __init__(self, transport: Callable[[bytes], bytes] = exchange):
        self._transport = transport

    def call(self, operation: str, arguments: dict | None = None, *, request_id: str | None = None) -> dict:
        message = request(operation, {} if arguments is None else arguments, request_id)
        try:
            reply = decode(self._transport(encode(message)))
        except AgentError:
            raise
        except Exception:
            raise AgentError("transport_unavailable") from None
        if not accepts(reply, RESPONSE_SCHEMA):
            raise AgentError("unavailable")
        if "error" in reply:
            if not set(reply).issubset({"protocol_major", "request_id", "error"}) or reply.get("request_id", message["request_id"]) != message["request_id"]:
                raise AgentError("unavailable")
            error = reply["error"]
            raise AgentError(error.get("code", "unavailable") if isinstance(error, dict) else "unavailable")
        if set(reply) != {"protocol_major", "request_id", "result"} or reply["request_id"] != message["request_id"] or not isinstance(reply["result"], dict):
            raise AgentError("unavailable")
        return reply["result"]
