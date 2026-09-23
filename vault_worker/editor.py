"""Exclusive encrypted checkout and confirmed content reconciliation."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import stat
import uuid

from lxml import etree

from .profile import MAX_FILE_BYTES, ManagedKDBXError, load_managed
from .store import VaultStore, VaultStoreError


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class EditorHandoff:
    def __init__(self, store: VaultStore):
        self.store = store
        self.review: dict | None = None

    def _record(self, db):
        row = db.execute("SELECT checkout_id, baseline_digest FROM editor_handoff WHERE id = 1").fetchone()
        if row is not None:
            try:
                if str(uuid.UUID(row[0])) != row[0] or len(row[1]) != 64:
                    raise ValueError
            except Exception:
                raise VaultStoreError("editor_unavailable") from None
        return row

    def _directory(self, checkout_id: str) -> Path:
        return self.store.private_dir / "editor" / checkout_id

    def status(self) -> dict:
        if not self.store.private_dir.exists():
            return {"state": "none"}
        self.store._check_dir(self.store.private_dir)
        db = self.store._connect()
        try:
            row = self._record(db)
        finally:
            db.close()
        if row is None:
            return {"state": "none"}
        return {"state": "editing", "checkout_id": row[0], "checkout_path": str(self._directory(row[0]) / "checkout.kdbx")}

    def begin(self, password: str) -> dict:
        self.store._check_dir(self.store.private_dir)
        with self.store._writer_lock():
            db = self.store._connect()
            try:
                self.store._check_editor(db, None)
                data = self.store._read_live()
                baseline = self.store._verify_current(db, data)
                load_managed(data, password)
                parent = self.store.private_dir / "editor"
                if not parent.exists():
                    parent.mkdir(mode=0o700)
                    self.store._fsync_dir(parent.parent)
                self.store._check_dir(parent)
                checkout_id = str(uuid.uuid4())
                directory = self._directory(checkout_id)
                directory.mkdir(mode=0o700)
                self.store._fsync_dir(parent)
                self.store._write_exclusive(directory / "baseline.kdbx", data)
                self.store._write_exclusive(directory / "checkout.kdbx", data)
                with db:
                    db.execute("INSERT INTO editor_handoff VALUES (1, ?, ?)", (checkout_id, baseline))
            finally:
                db.close()
        return self.status()

    def _read_checkout(self, checkout_id: str) -> bytes:
        directory = self._directory(checkout_id)
        self.store._check_dir(directory.parent)
        self.store._check_dir(directory)
        try:
            fd = os.open(directory / "checkout.kdbx", os.O_RDONLY | os.O_NOFOLLOW)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077 or before.st_nlink != 1 or before.st_uid != os.getuid():
                    raise VaultStoreError("unsafe_path")
                if before.st_size > MAX_FILE_BYTES:
                    raise VaultStoreError("limit_exceeded")
                chunks, total = [], 0
                while total <= MAX_FILE_BYTES:
                    part = os.read(fd, min(1024 * 1024, MAX_FILE_BYTES + 1 - total))
                    if not part:
                        break
                    chunks.append(part)
                    total += len(part)
                after = os.fstat(fd)
                current = (directory / "checkout.kdbx").lstat()
                identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
                if identity(before) != identity(after) or identity(current) != identity(before):
                    raise VaultStoreError("editor_changed")
                if total > MAX_FILE_BYTES:
                    raise VaultStoreError("limit_exceeded")
                return b"".join(chunks)
            finally:
                os.close(fd)
        except VaultStoreError:
            raise
        except OSError:
            raise VaultStoreError("editor_unavailable") from None

    def preview(self, password: str) -> dict:
        db = self.store._connect()
        try:
            record = self._record(db)
            if record is None:
                raise VaultStoreError("editor_unavailable")
            checkout_id, baseline = record
            live = self.store._read_live()
            if self.store._verify_current(db, live) != baseline:
                raise VaultStoreError("recovery_required")
        finally:
            db.close()
        data = self._read_checkout(checkout_id)
        try:
            original = load_managed(live, password)
            edited = load_managed(data, password)
        except ManagedKDBXError as error:
            raise VaultStoreError(error.code) from None
        original_entries = {entry.uuid: entry for entry in original.entries}
        edited_entries = {entry.uuid: entry for entry in edited.entries}
        changed = set()
        protected_changes = 0
        for identity, entry in edited_entries.items():
            previous = original_entries.get(identity)
            policy = {key: value for key, value in (previous.custom_properties.items() if previous else []) if key.startswith("shadow.")}
            submitted_policy = {key: value for key, value in entry.custom_properties.items() if key.startswith("shadow.")}
            if submitted_policy != policy:
                protected_changes += 1
            for key in list(entry.custom_properties):
                if key.startswith("shadow."):
                    entry.delete_custom_property(key)
            for key, value in policy.items():
                entry.set_custom_property(key, value, protect=True)
            if previous is None:
                entry.set_custom_property("shadow.authority.kind", "local", protect=True)
                entry.set_custom_property("shadow.revision", "1", protect=True)
            elif self._content(previous) != self._content(entry):
                changed.add(identity)
                try:
                    revision = int(previous.get_custom_property("shadow.revision") or "1")
                    if not 1 <= revision < 2**63 - 1:
                        raise ValueError
                except ValueError:
                    raise VaultStoreError("recovery_required") from None
                entry.set_custom_property("shadow.revision", str(revision + 1), protect=True)
        # Vault/group custom metadata cannot introduce policy authority either.
        # Only entry-level shadow fields are consumed; preserve candidate groups,
        # history, ordinary custom fields and KeePass metadata as qualified XML.
        token = str(uuid.uuid4())
        snapshot = self._directory(checkout_id) / f"review-{token}.kdbx"
        self.store._write_exclusive(snapshot, data)
        self.review = {"token": token, "id": checkout_id, "baseline": baseline, "digest": digest(data), "vault": edited}
        return {
            "review_id": token,
            "added": len(edited_entries.keys() - original_entries.keys()),
            "changed": len(changed),
            "removed": len(original_entries.keys() - edited_entries.keys()),
            "groups_changed": self._groups(original) != self._groups(edited),
            "protected_metadata_restored": protected_changes,
        }

    @staticmethod
    def _content(entry) -> bytes:
        element = deepcopy(entry._element)
        for child in list(element):
            if child.tag == "History" or (child.tag == "String" and (child.findtext("Key") or "").startswith("shadow.")):
                element.remove(child)
            elif child.tag == "Times":
                for value in list(child):
                    if value.tag not in {"Expires", "ExpiryTime"}:
                        child.remove(value)
        ancestry = [(group.findtext("UUID"), group.findtext("Name")) for group in entry._element.iterancestors("Group")]
        return etree.tostring(element, method="c14n") + str(ancestry).encode()

    @staticmethod
    def _groups(vault) -> list:
        return [(str(group.uuid), group.name, str(group.parentgroup.uuid) if group.parentgroup else None) for group in vault.groups]

    def commit(self, password: str, review_id: str) -> dict:
        review = self.review
        if review is None or review["token"] != review_id:
            raise VaultStoreError("preview_required")
        def unchanged():
            if digest(self._read_checkout(review["id"])) != review["digest"]:
                raise VaultStoreError("editor_changed")
        unchanged()
        def merge(vault):
            # Keep the active header/KDF/master password. The validated XML is
            # reconciled above, then serialized through normal durable commits.
            vault.kdbx.body.payload.xml = deepcopy(review["vault"].tree)
        self.store.commit(password, merge, editor_id=review["id"], expected_digest=review["baseline"], pre_publish=unchanged)
        try:
            unchanged()
            late_change = False
        except VaultStoreError:
            late_change = True
        self._finish(review["id"])
        self.review = None
        return {"state": "applied", "checkout_retained": True, "late_change": late_change}

    def cancel(self, *, discard: bool) -> dict:
        status = self.status()
        if status["state"] != "editing":
            raise VaultStoreError("editor_unavailable")
        self._finish(status["checkout_id"])
        self.review = None
        if discard:
            # Explicitly discard only the checkout. Baseline/review snapshots
            # remain encrypted recovery evidence; no recursive deletion.
            (self._directory(status["checkout_id"]) / "checkout.kdbx").unlink(missing_ok=True)
        return {"state": "cancelled", "checkout_retained": not discard, "late_change": False}

    def _finish(self, checkout_id: str):
        with self.store._writer_lock():
            db = self.store._connect()
            try:
                self.store._check_editor(db, checkout_id)
                self.store._verify_current(db, self.store._read_live())
                with db:
                    db.execute("DELETE FROM editor_handoff WHERE id = 1 AND checkout_id = ?", (checkout_id,))
            finally:
                db.close()
