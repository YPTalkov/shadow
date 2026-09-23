"""Inherited private channel for the native supervisor; no discoverable listener."""

from __future__ import annotations

import json
import os
from pathlib import Path
import resource
import struct
import sys
import uuid

from .catalog import Catalog
from .csv_import import CSVImportError, CSVMapping, SelectedCSV
from .store import VaultStore, VaultStoreError
from .editor import EditorHandoff

MAX_MESSAGE = 65_536
ERROR_CODES = {
    "unsafe_path", "writer_busy", "recovery_required", "already_exists",
    "storage_unavailable", "invalid_credentials", "invalid_vault",
    "unsupported_profile", "kdf_limit_exceeded", "external_modification",
    "unsafe_source", "source_unavailable", "source_changed", "limit_exceeded",
    "invalid_mapping", "invalid_rows", "invalid_csv", "preview_required",
    "invalid_request", "operation_conflict", "vault_unavailable", "vault_locked",
    "unsupported_operation",
    "editor_active", "editor_unavailable", "editor_changed",
}


class ProtocolError(Exception):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError
        result[key] = value
    return result


def read_message() -> dict:
    header = sys.stdin.buffer.read(4)
    if not header:
        raise EOFError
    if len(header) != 4:
        raise ProtocolError
    length = struct.unpack("!I", header)[0]
    if not 0 < length <= MAX_MESSAGE:
        raise ProtocolError
    data = sys.stdin.buffer.read(length)
    if len(data) != length:
        raise ProtocolError
    message = json.loads(data, object_pairs_hook=unique_object)
    if (
        not isinstance(message, dict)
        or set(message) != {"protocol_major", "channel_epoch", "sequence", "kind", "payload"}
        or type(message["protocol_major"]) is not int
        or message["protocol_major"] != 1
        or type(message["sequence"]) is not int
        or message["sequence"] < 0
        or not isinstance(message["kind"], str)
        or len(message["kind"]) > 64
        or not isinstance(message["payload"], dict)
        or len(message["payload"]) > 16
    ):
        raise ProtocolError
    if str(uuid.UUID(message["channel_epoch"])) != message["channel_epoch"]:
        raise ProtocolError
    return message


class Channel:
    def __init__(self):
        self.epoch: str | None = None
        self.sequence = 0

    def receive(self) -> dict:
        message = read_message()
        if self.epoch is None:
            self.epoch = message["channel_epoch"]
        if message["channel_epoch"] != self.epoch or message["sequence"] != self.sequence:
            raise ProtocolError
        return message

    def send(self, kind: str, payload: dict) -> None:
        data = json.dumps({
            "protocol_major": 1, "channel_epoch": self.epoch,
            "sequence": self.sequence, "kind": kind, "payload": payload,
        }, ensure_ascii=False, separators=(",", ":")).encode()
        if len(data) > MAX_MESSAGE:
            raise ProtocolError
        sys.stdout.buffer.write(struct.pack("!I", len(data)) + data)
        sys.stdout.buffer.flush()

    def anchor(self, kind: str, payload: dict) -> str | None:
        self.send(kind, payload)
        response = self.receive()
        if response["kind"] != "anchor.result" or set(response["payload"]) != {"digest"}:
            raise ProtocolError
        digest = response["payload"]["digest"]
        if digest is not None and (
            not isinstance(digest, str) or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise ProtocolError
        return digest


class NativeAnchor:
    def __init__(self, channel: Channel):
        self.channel = channel

    def read(self) -> str | None:
        return self.channel.anchor("anchor.read", {})

    def advance(self, digest: str) -> None:
        expected = self.read()
        if self.channel.anchor("anchor.advance", {"expected": expected, "digest": digest}) != digest:
            raise ProtocolError


class Worker:
    def __init__(self, channel: Channel):
        self.channel = channel
        self.store: VaultStore | None = None
        self.password: str | None = None
        self.selected: SelectedCSV | None = None
        self.stopping = False
        self.editor: EditorHandoff | None = None

    def close_selection(self) -> None:
        if self.selected:
            self.selected.close()
        self.selected = None

    def dispatch(self, kind: str, payload: dict) -> dict:
        if kind == "initialize":
            if self.store is not None or set(payload) != {"vault_directory"}:
                raise ProtocolError
            path = payload["vault_directory"]
            if not isinstance(path, str) or not Path(path).is_absolute() or len(path) > 4096:
                raise ProtocolError
            self.store = VaultStore(Path(path), NativeAnchor(self.channel))
            self.editor = EditorHandoff(self.store)
            return {"state": "locked"}
        if self.store is None:
            raise ProtocolError
        if kind == "editor.status":
            if payload:
                raise ProtocolError
            return self.editor.status()
        if kind == "editor.preview":
            if set(payload) != {"password"} or not isinstance(payload["password"], str) or not payload["password"]:
                raise ProtocolError
            self.close_selection()
            self.password = None
            result = self.editor.preview(payload["password"])
            self.password = payload["password"]
            return result
        if kind == "editor.cancel":
            if set(payload) != {"discard"} or type(payload["discard"]) is not bool:
                raise ProtocolError
            self.close_selection()
            self.password = None
            return self.editor.cancel(discard=payload["discard"])
        if kind in ("vault.create", "vault.unlock"):
            self.close_selection()
            self.password = None
            password = payload.get("password")
            if set(payload) != {"password"} or not isinstance(password, str) or not password:
                raise VaultStoreError("invalid_request")
            if kind == "vault.create":
                self.store.create(password)
            self.store.open(password)
            self.password = password
            return {"state": "unlocked"}
        if kind == "vault.lock":
            self.close_selection()
            self.password = None
            self.stopping = True
            return {"state": "locked"}
        if self.password is None:
            raise VaultStoreError("vault_locked")
        if kind == "editor.begin":
            if payload:
                raise ProtocolError
            self.close_selection()
            result = self.editor.begin(self.password)
            self.password = None
            return result
        if kind == "editor.commit":
            if set(payload) != {"review_id"} or not isinstance(payload["review_id"], str):
                raise ProtocolError
            result = self.editor.commit(self.password, payload["review_id"])
            self.password = None
            return result
        if kind == "csv.headers":
            if set(payload) != {"path"} or not isinstance(payload["path"], str):
                raise CSVImportError("invalid_request")
            with SelectedCSV(Path(payload["path"]), CSVMapping("", "", "", "")) as source:
                return {"headers": source.headers(), "plaintext_source_warning": True}
        if kind == "csv.preview":
            if set(payload) != {"path", "mapping"} or not isinstance(payload["path"], str) or not isinstance(payload["mapping"], dict):
                raise CSVImportError("invalid_request")
            mapping = CSVMapping(**payload["mapping"])
            if any(not isinstance(value, str) for value in mapping.required()):
                raise CSVImportError("invalid_mapping")
            self.close_selection()
            self.selected = SelectedCSV(Path(payload["path"]), mapping)
            return self.selected.preview().public()
        if kind == "csv.cancel":
            self.close_selection()
            return {"state": "cancelled"}
        if kind == "csv.commit":
            if self.selected is None:
                raise CSVImportError("preview_required")
            if set(payload) != {"operation_id", "valid_rows_only"} or type(payload["valid_rows_only"]) is not bool:
                raise CSVImportError("invalid_request")
            operation_id = payload["operation_id"]
            if not isinstance(operation_id, str) or str(uuid.UUID(operation_id)) != operation_id:
                raise CSVImportError("invalid_request")
            return self.selected.commit(self.store, self.password, operation_id=operation_id, valid_rows_only=payload["valid_rows_only"])
        if kind == "owner.catalog":
            if not set(payload).issubset({"offset"}):
                raise VaultStoreError("invalid_request")
            offset = payload.get("offset", 0)
            if type(offset) is not int or offset < 0:
                raise VaultStoreError("invalid_request")
            catalog = Catalog.from_vault(self.store.open(self.password))
            return catalog.owner_page(offset)
        raise VaultStoreError("unsupported_operation")


def main() -> None:
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    channel = Channel()
    worker = Worker(channel)
    try:
        while not worker.stopping:
            request = channel.receive()
            try:
                result = worker.dispatch(request["kind"], request["payload"])
            except (VaultStoreError, CSVImportError) as error:
                channel.send("error", {"code": error.code if error.code in ERROR_CODES else "worker_unavailable"})
            except ProtocolError:
                raise
            except Exception:
                channel.send("error", {"code": "worker_unavailable"})
            else:
                channel.send("result", result)
            channel.sequence += 1
    except Exception:
        pass
    finally:
        worker.close_selection()
        worker.password = None


if __name__ == "__main__":
    main()
