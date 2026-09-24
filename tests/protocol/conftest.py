from pathlib import Path
import socket
import struct
import subprocess

import pytest


class NativeBridge:
    def __init__(self, *, approve=True):
        root = Path(__file__).resolve().parents[2]
        executable = root / ".build/debug/agent-api-probe"
        assert executable.exists(), "Build agent-api-probe before protocol qualification"
        self.connection, child = socket.socketpair()
        self.connection.settimeout(10)
        self.process = subprocess.Popen([str(executable)] + (["--synthetic-approve"] if approve else []), stdin=child, stdout=child, stderr=subprocess.PIPE)
        child.close()
        self.captured = []

    def read(self, length):
        data = bytearray()
        while len(data) < length:
            chunk = self.connection.recv(length - len(data))
            assert chunk, "native probe disconnected"
            data.extend(chunk)
        return bytes(data)

    def __call__(self, data):
        self.connection.sendall(struct.pack("!I", len(data)) + data)
        length = struct.unpack("!I", self.read(4))[0]
        assert 0 < length <= 65536
        result = self.read(length)
        self.captured.append(result)
        return result

    def close(self):
        self.connection.close()
        _, errors = self.process.communicate(timeout=5)
        assert self.process.returncode == 0 and errors == b""


@pytest.fixture
def native():
    bridge = NativeBridge()
    try:
        yield bridge
    finally:
        bridge.close()


@pytest.fixture
def denied_native():
    bridge = NativeBridge(approve=False)
    try:
        yield bridge
    finally:
        bridge.close()
