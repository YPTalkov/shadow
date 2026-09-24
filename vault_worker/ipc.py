"""Inherited private channel for the native supervisor; no discoverable listener."""

from __future__ import annotations

import json
import base64
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
from .ingest import IngestSession, SourceCapabilities, SourceEnrollment, IngestError
from .conflicts import resolve as resolve_conflict
from . import encrypted_metadata
from .credentials import resolve as resolve_credential
from .recovery import Restore
from .encrypted_files import durable_copy

MAX_MESSAGE = 2 * 1024 * 1024  # Private host channel; includes a bounded source frame.
ERROR_CODES = {
    "unsafe_path", "writer_busy", "recovery_required", "already_exists",
    "storage_unavailable", "invalid_credentials", "invalid_vault",
    "unsupported_profile", "kdf_limit_exceeded", "external_modification",
    "unsafe_source", "source_unavailable", "source_changed", "limit_exceeded",
    "invalid_mapping", "invalid_rows", "invalid_csv", "preview_required",
    "invalid_request", "operation_conflict", "vault_unavailable", "vault_locked",
    "unsupported_operation",
    "editor_active", "editor_unavailable", "editor_changed",
    "invalid_enrollment", "unsupported_version", "identity_mismatch", "sequence_mismatch",
    "invalid_record", "unsupported_message", "unstable_identity", "unsupported_credential",
    "contradictory_coverage", "unsupported_evidence", "batch_conflict", "generation_conflict",
    "ambiguous_identity", "contradictory_evidence", "unknown_group", "history_limit",
    "invalid_group_hierarchy", "stale_conflict", "unlinked_identity", "stale_credential",
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


class NativeSourceAuthority:
    def __init__(self, channel: Channel):
        self.channel = channel
        self.pending = []

    def _acknowledge(self, kind, payload):
        self.channel.send(kind, payload)
        response = self.channel.receive()
        if response["kind"] != "native.result" or response["payload"] != {"state": "accepted"}:
            raise ProtocolError

    def invalidate(self, accounts):
        for offset in range(0, len(accounts), 256):
            self._acknowledge("mutation.invalidate", {"accounts": accounts[offset:offset + 256]})

    def restrict(self, account, kind, event):
        self.pending.append({"account": account, "kind": kind, "event_id": event})
        if len(self.pending) == 256:
            self.flush()

    def flush(self):
        if self.pending:
            self._acknowledge("restriction.record", {"events": self.pending})
            self.pending = []


class Worker:
    def __init__(self, channel: Channel):
        self.channel = channel
        self.store: VaultStore | None = None
        self.password: str | None = None
        self.selected: SelectedCSV | None = None
        self.stopping = False
        self.editor: EditorHandoff | None = None
        self.restore: Restore | None = None
        self.sources: dict[str, IngestSession] = {}
        self.source_authority = NativeSourceAuthority(channel)
        self.catalog_snapshot = None

    def close_sources(self):
        for source in self.sources.values():
            source.abort()
        self.sources.clear()
        self.source_authority.pending = []

    def close_selection(self) -> None:
        if self.selected:
            self.selected.close()
        self.selected = None

    def dispatch(self, kind: str, payload: dict) -> dict:
        if kind != "owner.catalog":
            self.catalog_snapshot = None
        if kind == "initialize":
            if self.store is not None or set(payload) != {"vault_directory"}:
                raise ProtocolError
            path = payload["vault_directory"]
            if not isinstance(path, str) or not Path(path).is_absolute() or len(path) > 4096:
                raise ProtocolError
            self.store = VaultStore(Path(path), NativeAnchor(self.channel))
            self.editor = EditorHandoff(self.store)
            self.restore = Restore(self.store)
            return {"state": "locked"}
        if self.store is None:
            raise ProtocolError
        if kind == "recovery.preview":
            if set(payload) != {"path", "password"} or any(not isinstance(value, str) or not value for value in payload.values()):
                raise ProtocolError
            self.password = None
            self.close_sources()
            self.close_selection()
            return self.restore.preview(Path(payload["path"]), payload["password"])
        if kind == "recovery.commit":
            if set(payload) != {"review_id"} or not isinstance(payload["review_id"], str) or self.password is not None:
                raise ProtocolError
            return self.restore.commit(payload["review_id"], reconcile=lambda: self.source_authority._acknowledge("recovery.reconcile", {"review_id": payload["review_id"]}))
        if kind == "recovery.cancel":
            if payload:
                raise ProtocolError
            self.restore.cancel()
            return {"state": "locked"}
        if kind == "backup.create":
            if payload:
                raise ProtocolError
            return self.store.backup()
        if kind == "editor.status":
            if payload:
                raise ProtocolError
            return self.editor.status()
        if kind == "editor.preview":
            if set(payload) != {"password"} or not isinstance(payload["password"], str) or not payload["password"]:
                raise ProtocolError
            self.close_sources()
            self.close_selection()
            self.password = None
            result = self.editor.preview(payload["password"])
            self.password = payload["password"]
            return result
        if kind == "editor.cancel":
            if set(payload) != {"discard"} or type(payload["discard"]) is not bool:
                raise ProtocolError
            self.close_sources()
            self.close_selection()
            self.password = None
            return self.editor.cancel(discard=payload["discard"])
        if kind in ("vault.create", "vault.unlock"):
            self.restore.cancel()
            self.close_sources()
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
            self.restore.cancel()
            self.close_sources()
            self.close_selection()
            self.password = None
            self.stopping = True
            return {"state": "locked"}
        if self.password is None:
            raise VaultStoreError("vault_locked")
        if kind == "backup.export":
            if set(payload) != {"path"} or not isinstance(payload["path"], str) or not Path(payload["path"]).is_absolute():
                raise ProtocolError
            self.store.backup()
            with self.store._writer_lock():
                data = self.store._read_live()
                db = self.store._connect()
                try:
                    self.store._verify_current(db, data)
                    self.store._check_editor(db, None)
                    durable_copy(Path(payload["path"]), data)
                finally:
                    db.close()
            return {"state": "exported"}
        if kind == "credential.resolve":
            if set(payload) != {"entry_id", "expected_revision", "origin", "include_totp"}:
                raise VaultStoreError("invalid_request")
            return resolve_credential(self.store.open(self.password), **payload)
        if kind == "editor.begin":
            if payload:
                raise ProtocolError
            self.close_selection()
            self.close_sources()
            result = self.editor.begin(self.password)
            self.password = None
            return result
        if kind == "editor.commit":
            if set(payload) != {"review_id"} or not isinstance(payload["review_id"], str):
                raise ProtocolError
            result = self.editor.commit(self.password, payload["review_id"])
            self.password = None
            return result
        if kind == "source.configure":
            if set(payload) != {"instance", "label", "epoch", "capabilities", "digest_key"} or len(self.sources) >= 16:
                raise IngestError("invalid_enrollment")
            raw = payload["capabilities"]
            keys = {"stable_items", "stable_groups", "complete_scopes", "deletion_evidence", "distinguishes_access_loss", "totp", "collection_mode", "version"}
            if not isinstance(raw, dict) or set(raw) != keys or any(type(raw[key]) is not bool for key in ("stable_items", "stable_groups", "distinguishes_access_loss", "totp")):
                raise IngestError("invalid_enrollment")
            if type(raw["version"]) is not int or raw["version"] != 1 or raw["collection_mode"] not in {"unattended", "owner_unlock_required", "owner_interaction_required"}:
                raise IngestError("invalid_enrollment")
            if not isinstance(raw["complete_scopes"], list) or not set(raw["complete_scopes"]).issubset({"account", "group"}) or not isinstance(raw["deletion_evidence"], list) or not set(raw["deletion_evidence"]).issubset({"item_tombstone", "group_tombstone"}):
                raise IngestError("invalid_enrollment")
            if not isinstance(payload["label"], str) or not 0 < len(payload["label"].encode()) <= 256:
                raise IngestError("invalid_enrollment")
            raw["complete_scopes"] = frozenset(raw["complete_scopes"])
            raw["deletion_evidence"] = frozenset(raw["deletion_evidence"])
            enrollment = SourceEnrollment(payload["instance"], payload["label"], SourceCapabilities(**raw), base64.b64decode(payload["digest_key"], validate=True))
            self.sources[enrollment.instance] = IngestSession(self.store, self.password, enrollment, payload["epoch"], restrict=self.source_authority.restrict, invalidate=self.source_authority.invalidate, flush_restrictions=self.source_authority.flush)
            return {"state": "configured"}
        if kind == "source.frame":
            if set(payload) != {"instance", "frame"} or payload["instance"] not in self.sources:
                raise IngestError("invalid_enrollment")
            try:
                receipt = self.sources[payload["instance"]].feed(base64.b64decode(payload["frame"], validate=True))
                if receipt == {"state": "aborted"}:
                    return {"state": "aborted", "receipt": None}
                return {"state": "committed" if receipt and "receipt_ref" in receipt else "collecting", "receipt": receipt}
            finally:
                self.source_authority.pending = []
        if kind == "source.close":
            if set(payload) != {"instance"}:
                raise ProtocolError
            source = self.sources.pop(payload["instance"], None)
            if source:
                source.abort()
            return {"state": "closed"}
        if kind == "source.status":
            if set(payload) != {"instances"} or not isinstance(payload["instances"], list) or len(payload["instances"]) > 16 or any(not isinstance(value, str) or str(uuid.UUID(value)) != value for value in payload["instances"]):
                raise ProtocolError
            vault = self.store.open(self.password)
            values = vault.tree.find("Meta/CustomData")
            records = []
            if values is not None:
                for item in values.findall("Item"):
                    key = item.findtext("Key") or ""
                    if key.startswith("shadow.source."):
                        record = encrypted_metadata.get(vault.tree.find("Meta"), key)
                        if record["instance"] in payload["instances"]:
                            records.append({name: record[name] for name in ("instance", "label", "generation", "last_received")})
            return {"sources": records}
        if kind == "source.resolve_conflict":
            if set(payload) != {"entry_id", "expected_revision", "choice", "operation_id"} or type(payload["expected_revision"]) is not int:
                raise ProtocolError
            self.source_authority.invalidate([payload["entry_id"]])
            return resolve_conflict(self.store, self.password, **payload)
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
            if offset == 0 or self.catalog_snapshot is None:
                self.catalog_snapshot = Catalog.from_vault(self.store.open(self.password))
            return self.catalog_snapshot.owner_page(offset)
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
            except (VaultStoreError, CSVImportError, IngestError) as error:
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
        worker.close_sources()
        worker.password = None


if __name__ == "__main__":
    main()
