"""Encrypted-only previous and UTC daily copies. Call under the vault writer lock."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import time
from typing import Callable

from .encrypted_files import durable_copy, read_file, sync_directory

NAME = re.compile(r"(previous|daily-\d{4}-\d{2}-\d{2})-([0-9a-f]{64})\.kdbx\Z")


class Backups:
    def __init__(self, directory: Path, *, clock: Callable[[], float] = time.time):
        self.directory = directory
        self.clock = clock

    def _verified(self, path: Path) -> bytes:
        match = NAME.fullmatch(path.name)
        data = read_file(path)
        if match is None or hashlib.sha256(data).hexdigest() != match[2]:
            raise OSError("backup_mismatch")
        return data

    def preserve(self, data: bytes, *, previous: bool) -> Path:
        digest = hashlib.sha256(data).hexdigest()
        today = datetime.fromtimestamp(self.clock(), timezone.utc).date().isoformat()
        copies = list(self.directory.glob(f"daily-{today}-*.kdbx"))
        if not copies:
            daily = self.directory / f"daily-{today}-{digest}.kdbx"
            durable_copy(daily, data)
        else:
            for daily in copies:
                self._verified(daily)
        target = self.directory / f"previous-{digest}.kdbx" if previous else daily
        if previous:
            if target.exists() or target.is_symlink():
                if self._verified(target) != data:
                    raise OSError("backup_mismatch")
            else:
                durable_copy(target, data)
        return target

    def rotate(self, *, previous: Path | None = None, daily: Path | None = None) -> None:
        today = datetime.fromtimestamp(self.clock(), timezone.utc).date()
        managed = [path for path in self.directory.iterdir() if NAME.fullmatch(path.name)]
        # Never prune a sole copy, unrecognized legacy copy, or anything when
        # the protected generation is unavailable. Do not follow symlinks.
        protected = previous or daily
        if protected is None or protected not in managed or len(managed) < 2:
            return
        self._verified(protected)
        expired = []
        for path in managed:
            if path == protected:
                continue
            match = NAME.fullmatch(path.name)
            if match[1] == "previous":
                remove = previous is not None
            else:
                day = datetime.strptime(match[1][6:], "%Y-%m-%d").date()
                remove = (today - day).days >= 30
            if remove:
                self._verified(path)
                expired.append(path)
        for path in expired:
            path.unlink()
        sync_directory(self.directory)

    def status(self) -> dict:
        daily = sorted(path for path in self.directory.iterdir() if NAME.fullmatch(path.name) and path.name.startswith("daily-"))
        latest = daily[-1] if daily else None
        if latest:
            self._verified(latest)
        return {"last_day": latest.name[6:16] if latest else None, "daily_count": len(daily)}
