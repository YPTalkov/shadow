import json
import socket
import struct
import subprocess
import sys
import uuid

import pytest


class Worker:
    def __init__(self):
        self.channel, child = socket.socketpair()
        self.channel.settimeout(10)
        self.process = subprocess.Popen(
            [sys.executable, "-I", "-m", "vault_worker.ipc"],
            stdin=child, stdout=child, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        child.close()
        self.epoch = str(uuid.uuid4())
        self.sequence = 0
        self.anchor = None

    def receive(self):
        def exact(count):
            data = bytearray()
            while len(data) < count:
                part = self.channel.recv(count - len(data))
                if not part:
                    raise EOFError("worker_channel_closed")
                data.extend(part)
            return bytes(data)
        length = struct.unpack("!I", exact(4))[0]
        assert 0 < length <= 65536
        return json.loads(exact(length))

    def send(self, kind, payload):
        data = json.dumps({
            "protocol_major": 1, "channel_epoch": self.epoch,
            "sequence": self.sequence, "kind": kind, "payload": payload,
        }).encode()
        self.channel.sendall(struct.pack("!I", len(data)) + data)

    def call(self, kind, payload):
        self.send(kind, payload)
        while True:
            response = self.receive()
            assert response["channel_epoch"] == self.epoch
            assert response["sequence"] == self.sequence
            if response["kind"] == "anchor.read":
                self.send("anchor.result", {"digest": self.anchor})
            elif response["kind"] == "anchor.advance":
                assert response["payload"]["expected"] == self.anchor
                self.anchor = response["payload"]["digest"]
                self.send("anchor.result", {"digest": self.anchor})
            else:
                self.sequence += 1
                return response

    def close(self):
        self.channel.close()
        self.process.wait(timeout=5)
        diagnostics = self.process.stderr.read()
        assert diagnostics == b""


def test_private_worker_create_import_lock_and_anchor(tmp_path):
    source = tmp_path / "synthetic.csv"
    source.write_text(
        "Title,URL,Username,Password,Notes\n"
        "Synthetic,https://example.invalid,owner,synthetic-password-canary,synthetic-notes-canary\n"
    )
    worker = Worker()
    try:
        assert worker.call("initialize", {"vault_directory": str(tmp_path / "private")})["kind"] == "result"
        assert worker.call("vault.create", {"password": "synthetic-master-password"})["payload"]["state"] == "unlocked"
        assert len(worker.anchor) == 64
        old_anchor = worker.anchor
        headers = worker.call("csv.headers", {"path": str(source)})["payload"]["headers"]
        assert headers == ["Title", "URL", "Username", "Password", "Notes"]
        preview = worker.call("csv.preview", {
            "path": str(source),
            "mapping": {"title": "Title", "url": "URL", "username": "Username", "password": "Password", "notes": "Notes"},
        })
        assert preview["payload"]["accepted"] == 1
        assert "synthetic-password-canary" not in json.dumps(preview)
        assert "synthetic-notes-canary" not in json.dumps(preview)
        commit = worker.call("csv.commit", {"operation_id": str(uuid.uuid4()), "valid_rows_only": False})
        assert commit["payload"]["accepted"] == 1
        assert worker.anchor != old_anchor
        catalog = worker.call("owner.catalog", {})
        assert catalog["payload"]["items"][0]["title"] == "Synthetic"
        assert "synthetic-password-canary" not in json.dumps(catalog)
        assert "synthetic-notes-canary" not in json.dumps(catalog)
        assert worker.call("vault.reveal", {})["payload"]["code"] == "unsupported_operation"
        assert worker.call("vault.lock", {})["payload"]["state"] == "locked"
    finally:
        worker.close()


def test_worker_rejects_protocol_replay_and_wrong_password(tmp_path):
    worker = Worker()
    try:
        worker.call("initialize", {"vault_directory": str(tmp_path / "private")})
        worker.call("vault.create", {"password": "synthetic-master-password"})
        response = worker.call("vault.unlock", {"password": "wrong-password"})
        assert response["kind"] == "error"
        assert response["payload"]["code"] == "invalid_credentials"
        worker.sequence -= 1
        worker.send("owner.catalog", {})
        with pytest.raises(EOFError):
            worker.receive()
    finally:
        worker.close()
