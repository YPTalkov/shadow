"""Bounded reads and durable copies of encrypted files; no key material."""

from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat

MAX_BYTES = 128 * 1024 * 1024


def read_file(path: Path, *, private: bool = True) -> bytes:
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_nlink != 1 or (private and before.st_mode & 0o077)
            or before.st_size > MAX_BYTES):
        raise OSError("unsafe_encrypted_file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if identity(os.fstat(fd)) != identity(before):
            raise OSError("encrypted_file_changed")
        chunks, total = [], 0
        while total <= MAX_BYTES:
            part = os.read(fd, min(1024 * 1024, MAX_BYTES + 1 - total))
            if not part:
                break
            chunks.append(part)
            total += len(part)
        if (total != before.st_size or identity(os.fstat(fd)) != identity(before)
                or identity(path.lstat()) != identity(before)):
            raise OSError("encrypted_file_changed")
        return b"".join(chunks)
    finally:
        os.close(fd)


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable_copy(path: Path, data: bytes) -> None:
    """Publish a fully flushed, verified copy without replacing any existing file."""
    temp = path.parent / (".copy-" + secrets.token_hex(16))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        try:
            view = memoryview(data)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("short_write")
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        if read_file(temp) != data:
            raise OSError("copy_mismatch")
        # Hard-link publication gives no-replace semantics. The temporary link
        # is removed before this file can be consumed through read_file.
        os.link(temp, path, follow_symlinks=False)
    finally:
        temp.unlink(missing_ok=True)
    sync_directory(path.parent)
