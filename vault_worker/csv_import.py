"""Owner-selected CSV preview and commit; never exposed as an agent tool."""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
import hashlib
import io
import os
from pathlib import Path
import stat
from urllib.parse import urlsplit

from .store import SkipMutation, VaultStore, VaultStoreError


MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_ROWS = 50_000
MAX_FIELD_BYTES = 64 * 1024


class CSVImportError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class CSVMapping:
    title: str
    url: str
    username: str
    password: str
    notes: str | None = None
    totp: str | None = None
    group: str | None = None

    def required(self) -> tuple[str, ...]:
        return self.title, self.url, self.username, self.password


@dataclass(frozen=True)
class ImportRow:
    title: str
    url: str
    username: str
    password: str = field(repr=False)
    notes: str = field(default="", repr=False)
    totp: str = field(default="", repr=False)
    group: str = ""


@dataclass(frozen=True)
class ImportPreview:
    accepted: int
    rejected: int
    rows: tuple[dict[str, str], ...]
    codes: tuple[str, ...]

    def public(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "rejected": self.rejected,
            "rows": list(self.rows),
            "codes": list(self.codes),
            "plaintext_source_warning": True,
        }


def _origin(url: str) -> str:
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        port = parsed.port
        return f"https://{host}" + (f":{port}" if port not in (None, 443) else "")
    except (ValueError, UnicodeError):
        raise CSVImportError("invalid_rows") from None


class SelectedCSV:
    def __init__(self, path: Path, mapping: CSVMapping):
        self.path = Path(path)
        self.mapping = mapping
        self._fd: int | None = None
        self._identity: tuple[int, int, int, int] | None = None
        self._digest: str | None = None
        self._rows: tuple[ImportRow, ...] | None = None
        self._preview: ImportPreview | None = None
        try:
            identity = self.path.lstat()
            if not stat.S_ISREG(identity.st_mode) or identity.st_size > MAX_FILE_BYTES:
                raise CSVImportError("unsafe_source")
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
            self._fd = fd
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (identity.st_dev, identity.st_ino):
                raise CSVImportError("unsafe_source")
            self._identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        except CSVImportError:
            self.close()
            raise
        except OSError:
            self.close()
            raise CSVImportError("unsafe_source") from None

    def __enter__(self) -> SelectedCSV:
        return self

    def __exit__(self, *_):
        self.close()

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        self._rows = None

    def _read(self) -> bytes:
        if self._fd is None:
            raise CSVImportError("source_unavailable")
        try:
            opened = os.fstat(self._fd)
            current = self.path.lstat()
            identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            if identity != self._identity or (current.st_dev, current.st_ino) != identity[:2]:
                raise CSVImportError("source_changed")
            if opened.st_size > MAX_FILE_BYTES:
                raise CSVImportError("limit_exceeded")
            os.lseek(self._fd, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(self._fd, min(1024 * 1024, MAX_FILE_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_FILE_BYTES:
                    raise CSVImportError("limit_exceeded")
            data = b"".join(chunks)
            if len(data) > MAX_FILE_BYTES:
                raise CSVImportError("limit_exceeded")
            return data
        except CSVImportError:
            raise
        except OSError:
            raise CSVImportError("source_unavailable") from None

    def preview(self) -> ImportPreview:
        data = self._read()
        self._digest = hashlib.sha256(data).hexdigest()
        try:
            text = data.decode("utf-8-sig", errors="strict")
            old_limit = csv.field_size_limit()
            csv.field_size_limit(MAX_FIELD_BYTES)
            try:
                records = csv.reader(io.StringIO(text, newline=""), strict=True)
                headers = next(records)
                mapped = [value for value in (self.mapping.title, self.mapping.url, self.mapping.username, self.mapping.password, self.mapping.notes, self.mapping.totp, self.mapping.group) if value is not None]
                if len(mapped) != len(set(mapped)):
                    raise CSVImportError("invalid_mapping")
                if len(headers) != len(set(headers)) or not set(self.mapping.required()).issubset(headers):
                    raise CSVImportError("invalid_mapping")
                for optional in (self.mapping.notes, self.mapping.totp, self.mapping.group):
                    if optional is not None and optional not in headers:
                        raise CSVImportError("invalid_mapping")
                fields = {name: headers.index(name) for name in headers}
                accepted: list[ImportRow] = []
                public: list[dict[str, str]] = []
                rejected = 0
                count = 0
                for record in records:
                    count += 1
                    if count > MAX_ROWS:
                        raise CSVImportError("limit_exceeded")
                    if len(record) != len(headers) or any(len(value.encode("utf-8")) > MAX_FIELD_BYTES for value in record):
                        rejected += 1
                        continue
                    get = lambda name: record[fields[name]] if name else ""
                    title = get(self.mapping.title)
                    url = get(self.mapping.url)
                    username = get(self.mapping.username)
                    password = get(self.mapping.password)
                    notes = get(self.mapping.notes)
                    totp = get(self.mapping.totp)
                    group = get(self.mapping.group)
                    try:
                        origin = _origin(url)
                        if not title or not password:
                            raise CSVImportError("invalid_rows")
                    except CSVImportError:
                        rejected += 1
                        continue
                    accepted.append(ImportRow(title, url, username, password, notes, totp, group))
                    if len(public) < 50:
                        public.append({"title": title[:256], "origin": origin, "username": username[:256], "group": group[:256]})
                self._rows = tuple(accepted)
                self._preview = ImportPreview(len(accepted), rejected, tuple(public), ("invalid_rows",) if rejected else ())
                return self._preview
            finally:
                csv.field_size_limit(old_limit)
        except CSVImportError:
            raise
        except (UnicodeError, csv.Error, StopIteration):
            raise CSVImportError("invalid_csv") from None

    def _verify_unchanged(self) -> None:
        data = self._read()
        if self._digest is None or hashlib.sha256(data).hexdigest() != self._digest:
            raise CSVImportError("source_changed")

    def commit(
        self,
        store: VaultStore,
        master_password: str,
        *,
        operation_id: str,
        valid_rows_only: bool = False,
    ) -> dict[str, int | bool]:
        if self._preview is None or self._rows is None:
            raise CSVImportError("preview_required")
        if not operation_id or len(operation_id) > 128:
            raise CSVImportError("invalid_request")
        if self._preview.rejected and not valid_rows_only:
            raise CSVImportError("invalid_rows")
        self._verify_unchanged()
        rows = self._rows
        digest = self._digest

        def mutate(vault):
            replay = [entry for entry in vault.entries if entry.get_custom_property("shadow.import.operation") == operation_id]
            if replay:
                if len(replay) != len(rows) or any(entry.get_custom_property("shadow.import.digest") != digest for entry in replay):
                    raise SkipMutation("operation_conflict")
                raise SkipMutation("replayed")
            root = vault.find_groups(name="Imports", first=True)
            if root is None:
                root = vault.add_group(vault.root_group, "Imports")
            groups = {"": root}
            for row in rows:
                if row.group not in groups:
                    groups[row.group] = vault.find_groups(name=row.group, group=root, first=True) or vault.add_group(root, row.group)
                entry = vault.add_entry(groups[row.group], row.title, row.username, row.password, url=row.url, notes=row.notes, otp=row.totp or None, force_creation=True)
                entry.set_custom_property("shadow.import.operation", operation_id, protect=True)
                entry.set_custom_property("shadow.import.digest", digest, protect=True)

        def pre_publish():
            try:
                self._verify_unchanged()
            except CSVImportError:
                raise VaultStoreError("source_changed") from None

        try:
            result = store.commit(master_password, mutate, pre_publish=pre_publish)
        except VaultStoreError as error:
            if error.code == "source_changed":
                raise CSVImportError("source_changed") from None
            raise CSVImportError("vault_unavailable") from None
        if result == "operation_conflict":
            raise CSVImportError("operation_conflict")
        return {"accepted": self._preview.accepted, "rejected": self._preview.rejected, "replayed": result == "replayed"}
