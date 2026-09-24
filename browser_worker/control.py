"""Bounded private browser messages; no socket path or listening endpoint."""
import asyncio
import json
import struct
import time

from .errors import BrowserFailure, Code

MAX_FRAME = 2 * 1024 * 1024


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _validate(value, depth=0):
    if depth > 8:
        raise ValueError
    if type(value) is dict:
        if len(value) > 32:
            raise ValueError
        for key, item in value.items():
            _validate(key, depth + 1)
            _validate(item, depth + 1)
    elif type(value) is list:
        if len(value) > 256:
            raise ValueError
        for item in value:
            _validate(item, depth + 1)
    elif type(value) is str:
        value.encode("utf-8", errors="strict")
    elif type(value) is int and not -(2**63) <= value < 2**63:
        raise ValueError
    elif value is not None and type(value) not in (bool, int):
        raise ValueError


def encode(value: dict) -> bytes:
    try:
        _validate(value)
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if not 0 < len(data) <= MAX_FRAME:
            raise ValueError
        return struct.pack("!I", len(data)) + data
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise BrowserFailure(Code.INVALID_REQUEST) from None


class Frames:
    def __init__(self):
        self.buffer = bytearray()
        self.partial_since = None

    def feed(self, data: bytes) -> list[dict]:
        try:
            self.buffer.extend(data)
            if len(self.buffer) > MAX_FRAME + 65540:
                raise ValueError
            values = []
            while len(self.buffer) >= 4:
                length = struct.unpack("!I", self.buffer[:4])[0]
                if not 0 < length <= MAX_FRAME:
                    raise ValueError
                if len(self.buffer) < length + 4:
                    break
                value = json.loads(self.buffer[4:length + 4], object_pairs_hook=_object)
                del self.buffer[:length + 4]
                if type(value) is not dict:
                    raise ValueError
                _validate(value)
                values.append(value)
            if self.buffer:
                self.partial_since = self.partial_since or time.monotonic()
            else:
                self.partial_since = None
            return values
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise BrowserFailure(Code.INVALID_REQUEST) from None

    def check_deadline(self):
        if self.partial_since is not None and time.monotonic() - self.partial_since > 3:
            raise BrowserFailure(Code.UNAVAILABLE)


def renew(lease, message):
    if set(message) != {"kind", "sequence", "ttl_ms"} or message["kind"] != "lease":
        raise BrowserFailure(Code.INVALID_REQUEST)
    lease.renew(sequence=message["sequence"], ttl_ms=message["ttl_ms"])


class ControlChannel:
    def __init__(self, reader, writer, lease):
        self.reader, self.writer, self.lease = reader, writer, lease
        self.queue = asyncio.Queue(maxsize=8)
        self.ready = asyncio.Event()
        self.receiver = asyncio.create_task(self._receive())

    async def _receive(self):
        frames = Frames()
        try:
            while True:
                data = await asyncio.wait_for(self.reader.read(65536), timeout=3)
                if not data:
                    raise BrowserFailure(Code.SESSION_CLOSED)
                for message in frames.feed(data):
                    if message.get("kind") == "lease":
                        renew(self.lease, message)
                        self.ready.set()
                    else:
                        self.lease.check()
                        self.queue.put_nowait(message)
                frames.check_deadline()
        except BaseException:
            self.lease.revoke()
            self.writer.close()
            # Wake an in-flight action. Its output gate checks the dead lease.
            while not self.queue.empty():
                self.queue.get_nowait()
            self.queue.put_nowait({"kind": "closed"})

    async def receive(self, timeout=20):
        message = await asyncio.wait_for(self.queue.get(), timeout=timeout)
        self.lease.check()
        return message

    async def send(self, value):
        self.lease.check()
        self.writer.write(encode(value))
        await asyncio.wait_for(self.writer.drain(), timeout=1)
        self.lease.check()

    async def close(self):
        self.lease.revoke()
        self.receiver.cancel()
        self.writer.close()
        await asyncio.gather(self.receiver, return_exceptions=True)
