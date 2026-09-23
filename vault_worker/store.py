"""Host-private encrypted vault generations with fail-closed publication.

The anchor is supplied by the native supervisor. A test anchor exists only to
exercise the transaction; production must use the independent Keychain anchor.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import io
import os
from pathlib import Path
import secrets
import sqlite3
import stat
from typing import Callable, Protocol

from pykeepass import PyKeePass

from .profile import ManagedKDBXError, create_managed, load_managed


class VaultStoreError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class GenerationAnchor(Protocol):
    def read(self) -> str | None: ...
    def advance(self, digest: str) -> None: ...


class MemoryAnchor:
    """Test fixture; never suitable for production authority."""

    def __init__(self):
        self.value: str | None = None

    def read(self) -> str | None:
        return self.value

    def advance(self, digest: str) -> None:
        self.value = digest


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class VaultStore:
    def __init__(self, private_dir: Path, anchor: GenerationAnchor):
        self.private_dir = Path(private_dir)
        self.anchor = anchor
        self.vault_path = self.private_dir / "vault.kdbx"
        self.backup_dir = self.private_dir / "backups"
        self.ledger_path = self.private_dir / "authority.sqlite"
        self.lock_path = self.private_dir / "writer.lock"

    def _check_dir(self, path: Path) -> None:
        try:
            mode = path.lstat().st_mode
        except OSError:
            raise VaultStoreError("unsafe_path") from None
        if not stat.S_ISDIR(mode) or mode & 0o077:
            raise VaultStoreError("unsafe_path")

    def _ensure_dirs(self) -> None:
        if not self.private_dir.exists():
            self.private_dir.mkdir(mode=0o700, parents=False)
        self._check_dir(self.private_dir)
        if not self.backup_dir.exists():
            self.backup_dir.mkdir(mode=0o700)
        self._check_dir(self.backup_dir)

    @contextmanager
    def _writer_lock(self):
        flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
        try:
            fd = os.open(self.lock_path, flags, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise VaultStoreError("unsafe_path")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise VaultStoreError("writer_busy") from None
        except VaultStoreError:
            os.close(fd)
            raise
        except OSError:
            if "fd" in locals():
                os.close(fd)
            raise VaultStoreError("unsafe_path") from None
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read_live(self) -> bytes:
        try:
            identity = self.vault_path.lstat()
            if not stat.S_ISREG(identity.st_mode) or identity.st_mode & 0o077 or identity.st_nlink != 1:
                raise VaultStoreError("unsafe_path")
            fd = os.open(self.vault_path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != (identity.st_dev, identity.st_ino):
                    raise VaultStoreError("unsafe_path")
                data = os.read(fd, 128 * 1024 * 1024 + 1)
            finally:
                os.close(fd)
            return data
        except VaultStoreError:
            raise
        except OSError:
            raise VaultStoreError("unsafe_path") from None

    def _connect(self, *, create: bool = False) -> sqlite3.Connection:
        try:
            if self.ledger_path.is_symlink():
                raise VaultStoreError("unsafe_path")
            if self.ledger_path.exists():
                ledger_stat = self.ledger_path.lstat()
                if not stat.S_ISREG(ledger_stat.st_mode) or ledger_stat.st_mode & 0o077:
                    raise VaultStoreError("unsafe_path")
            elif not create:
                raise VaultStoreError("recovery_required")
            db = sqlite3.connect(self.ledger_path, timeout=0)
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE IF NOT EXISTS vault_generation (id INTEGER PRIMARY KEY CHECK (id = 1), digest TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS prepared_generation (id TEXT PRIMARY KEY, old_digest TEXT NOT NULL, new_digest TEXT NOT NULL)")
            db.commit()
            os.chmod(self.ledger_path, 0o600)
            return db
        except VaultStoreError:
            raise
        except (OSError, sqlite3.Error):
            raise VaultStoreError("storage_unavailable") from None

    def _expected_digest(self, db: sqlite3.Connection) -> str:
        row = db.execute("SELECT digest FROM vault_generation WHERE id = 1").fetchone()
        if row is None:
            raise VaultStoreError("recovery_required")
        return row[0]

    def _verify_current(self, db: sqlite3.Connection, data: bytes) -> str:
        expected = self._expected_digest(db)
        if _digest(data) != expected or self.anchor.read() != expected:
            raise VaultStoreError("recovery_required")
        return expected

    def create(self, password: str) -> None:
        try:
            self._ensure_dirs()
            with self._writer_lock():
                if self.vault_path.exists() or self.vault_path.is_symlink() or self.ledger_path.exists() or self.anchor.read() is not None:
                    raise VaultStoreError("already_exists")
                data = create_managed(password)
                digest = _digest(data)
                fd = os.open(self.vault_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                try:
                    self._write_all(fd, data)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                self._fsync_dir(self.private_dir)
                db = self._connect(create=True)
                try:
                    with db:
                        db.execute("INSERT INTO vault_generation(id, digest) VALUES (1, ?)", (digest,))
                finally:
                    db.close()
                self.anchor.advance(digest)
        except VaultStoreError:
            raise
        except (OSError, sqlite3.Error, ManagedKDBXError):
            raise VaultStoreError("storage_unavailable") from None

    def open(self, password: str) -> PyKeePass:
        self._check_dir(self.private_dir)
        data = self._read_live()
        db = self._connect()
        try:
            with db:
                self._verify_current(db, data)
                # Prepared writes that never replaced the live generation have no authority.
                db.execute("DELETE FROM prepared_generation")
        finally:
            db.close()
        try:
            return load_managed(data, password)
        except ManagedKDBXError as error:
            raise VaultStoreError(error.code) from None

    def commit(
        self,
        password: str,
        mutate: Callable[[PyKeePass], None],
        *,
        fault: Callable[[str], None] | None = None,
    ) -> None:
        fault = fault or (lambda _: None)
        self._check_dir(self.private_dir)
        self._check_dir(self.backup_dir)
        temp_path: Path | None = None
        try:
            with self._writer_lock():
                old_data = self._read_live()
                db = self._connect()
                try:
                    old_digest = self._verify_current(db, old_data)
                    vault = load_managed(old_data, password)
                    mutate(vault)
                    output = io.BytesIO()
                    vault.save(output)
                    new_data = output.getvalue()
                    load_managed(new_data, password)
                    new_digest = _digest(new_data)
                    self._write_exclusive(self.backup_dir / f"previous-{secrets.token_hex(16)}.kdbx", old_data)
                    fault("after_backup")
                    generation = secrets.token_hex(16)
                    with db:
                        db.execute("INSERT INTO prepared_generation VALUES (?, ?, ?)", (generation, old_digest, new_digest))
                    fault("after_prepare")
                    temp_path = self.private_dir / f".generation-{generation}.kdbx"
                    fd = os.open(temp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                    try:
                        self._write_all(fd, new_data)
                        fault("after_temp_write")
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    fault("after_temp_fsync")
                    if self._read_live() != old_data:
                        raise VaultStoreError("external_modification")
                    load_managed(temp_path.read_bytes(), password)
                    fault("after_validate")
                    os.replace(temp_path, self.vault_path)
                    temp_path = None
                    fault("after_replace")
                    self._fsync_dir(self.private_dir)
                    fault("after_dir_fsync")
                    with db:
                        db.execute("UPDATE vault_generation SET digest = ? WHERE id = 1", (new_digest,))
                        db.execute("DELETE FROM prepared_generation WHERE id = ?", (generation,))
                    fault("after_ledger")
                    self.anchor.advance(new_digest)
                    fault("after_anchor")
                finally:
                    db.close()
        except VaultStoreError:
            raise
        except Exception:
            raise VaultStoreError("storage_unavailable") from None
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short write")
            view = view[count:]

    @classmethod
    def _write_exclusive(cls, path: Path, data: bytes) -> None:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            cls._write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        cls._fsync_dir(path.parent)

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
