"""Owner-only restore of a reviewed encrypted snapshot. Never restores authority."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import sqlite3
import time
import uuid

from .catalog import Catalog
from .encrypted_files import durable_copy, read_file
from .ingest import source_record, set_source
from .profile import ManagedKDBXError, load_managed
from .store import VaultStore, VaultStoreError


class Restore:
    def __init__(self, store: VaultStore):
        self.store = store
        self.review = None

    def cancel(self):
        self.review = None

    def _snapshot(self) -> dict:
        result = {"anchor": self.store.anchor.read()}
        for name in ("vault.kdbx", "authority.sqlite", "authority.sqlite-journal", "authority.sqlite-wal", "authority.sqlite-shm"):
            path = self.store.private_dir / name
            try:
                data = read_file(path)
                result[name] = hashlib.sha256(data).hexdigest()
            except FileNotFoundError:
                result[name] = None
        return result

    def _check_editor(self):
        if not self.store.ledger_path.exists():
            return
        # Read-only: preview must not recover a hot journal or mutate a damaged
        # authority ledger. Preserve all such files verbatim during commit.
        db = None
        try:
            db = sqlite3.connect(self.store.ledger_path.as_uri() + "?mode=ro&immutable=1", uri=True)
            if db.execute("SELECT checkout_id FROM editor_handoff LIMIT 1").fetchone():
                raise VaultStoreError("editor_active")
        except sqlite3.DatabaseError:
            pass  # Explicit recovery may replace corrupt/missing bookkeeping.
        finally:
            if db is not None:
                db.close()

    def preview(self, path: Path, password: str) -> dict:
        self.cancel()
        try:
            self.store._ensure_dirs()
            with self.store._writer_lock():
                state = self._snapshot()
                self._check_editor()
                data = read_file(path, private=False)
                vault = load_managed(data, password)
                catalog = Catalog.from_vault(vault)
                mirrored = []
                for entry in vault.entries:
                    record = source_record(entry)
                    if record:
                        mirrored.append(str(entry.uuid))
                        record["presence"] = "unknown"
                        record["last_observed"] = None
                        set_source(entry, record)
                restored = data
                if mirrored:
                    output = io.BytesIO()
                    vault.save(output)
                    restored = output.getvalue()
                    load_managed(restored, password)
                token = str(uuid.uuid4())
                self.review = {"id": token, "data": data, "restored": restored, "state": state, "expires": time.monotonic() + 300}
                return {"review_id": token, "accounts": catalog.count, "mirrored_ids": mirrored}
        except ManagedKDBXError as error:
            raise VaultStoreError(error.code) from None
        except OSError:
            raise VaultStoreError("unsafe_path") from None

    def commit(self, review_id: str, *, reconcile, fault=lambda _: None) -> dict:
        review = self.review
        self.cancel()  # A failed or interrupted restore always needs a new review.
        if review is None or review["id"] != review_id or time.monotonic() >= review["expires"]:
            raise VaultStoreError("preview_required")
        try:
            with self.store._writer_lock():
                if self._snapshot() != review["state"]:
                    raise VaultStoreError("external_modification")
                self._check_editor()
                # Recovery evidence is deliberately outside automatic rotation.
                recovery = self.store.backup_dir / ("recovery-" + review_id)
                recovery.mkdir(mode=0o700)
                self.store._fsync_dir(self.store.backup_dir)
                for name, expected in review["state"].items():
                    if name != "anchor" and expected is not None:
                        data = read_file(self.store.private_dir / name)
                        if hashlib.sha256(data).hexdigest() != expected:
                            raise VaultStoreError("external_modification")
                        durable_copy(recovery / name, data)
                durable_copy(recovery / "selected.kdbx", review["data"])
                data = review["restored"]
                digest = hashlib.sha256(data).hexdigest()
                fault("after_backup")
                # Independent restrictions must be durable before any restored
                # generation can be made authoritative, including after a crash.
                reconcile()
                fault("after_restrictions")
                if self._snapshot() != review["state"]:
                    raise VaultStoreError("external_modification")
                candidate = self.store.private_dir / (".restore-" + review_id + ".kdbx")
                durable_copy(candidate, data)
                new_ledger = self.store.private_dir / (".restore-" + review_id + ".sqlite")
                fd = os.open(new_ledger, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                os.close(fd)
                db = sqlite3.connect(new_ledger)
                try:
                    db.execute("PRAGMA synchronous=FULL")
                    db.execute("CREATE TABLE vault_generation (id INTEGER PRIMARY KEY CHECK (id = 1), digest TEXT NOT NULL)")
                    db.execute("INSERT INTO vault_generation VALUES (1, ?)", (digest,))
                    db.commit()
                finally:
                    db.close()
                fault("after_prepare")
                # Remove old SQLite recovery sidecars only after preserving them.
                for suffix in ("-journal", "-wal", "-shm"):
                    path = Path(str(self.store.ledger_path) + suffix)
                    if review["state"][path.name] is not None:
                        path.unlink()
                os.replace(candidate, self.store.vault_path)
                fault("after_replace")
                self.store._fsync_dir(self.store.private_dir)
                os.replace(new_ledger, self.store.ledger_path)
                self.store._fsync_dir(self.store.private_dir)
                fault("after_ledger")
                self.store.anchor.advance(digest)
                fault("after_anchor")
                return {"state": "restored"}
        except VaultStoreError:
            raise
        except Exception:
            raise VaultStoreError("storage_unavailable") from None
