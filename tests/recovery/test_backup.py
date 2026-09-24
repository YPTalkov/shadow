from datetime import datetime, timedelta, timezone
import hashlib
import os

import pytest

from vault_worker.backups import Backups
from vault_worker.encrypted_files import durable_copy, read_file
from vault_worker.profile import create_managed, load_managed

MASTER = "synthetic-backup-master"


def test_rotation_keeps_previous_thirty_days_and_legacy_evidence(tmp_path):
    today = datetime(2026, 1, 1, tzinfo=timezone.utc)
    clock = [today]
    backups = Backups(tmp_path, clock=lambda: clock[0].timestamp())
    encrypted = create_managed(MASTER)
    legacy = tmp_path / "previous-legacy.kdbx"
    durable_copy(legacy, encrypted)
    previous = backups.preserve(encrypted, previous=True)
    for day in range(40):
        clock[0] = today + timedelta(days=day)
        daily = backups.preserve(encrypted, previous=False)
        backups.rotate(daily=daily)
    assert len(list(tmp_path.glob("daily-*.kdbx"))) == 30
    assert previous.exists() and legacy.exists()
    assert load_managed(read_file(previous), MASTER)
    assert backups.status() == {"last_day": "2026-02-09", "daily_count": 30}


def test_disk_full_leaves_verified_copy_and_no_partial_publication(tmp_path, monkeypatch):
    encrypted = create_managed(MASTER)
    backups = Backups(tmp_path)
    old = backups.preserve(encrypted, previous=True)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    def full(fd, data):
        raise OSError("synthetic_disk_full")
    monkeypatch.setattr(os, "write", full)
    with pytest.raises(OSError):
        backups.preserve(encrypted + b"new", previous=True)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before
    assert load_managed(read_file(old), MASTER)


def test_bad_copy_blocks_rotation_and_single_generation_is_never_deleted(tmp_path):
    encrypted = create_managed(MASTER)
    old = tmp_path / ("previous-" + hashlib.sha256(encrypted).hexdigest() + ".kdbx")
    durable_copy(old, encrypted)
    backups = Backups(tmp_path)
    backups.rotate(previous=old)
    assert old.exists()
    corrupt = tmp_path / ("daily-2000-01-01-" + "0" * 64 + ".kdbx")
    durable_copy(corrupt, b"corrupt")
    with pytest.raises(OSError):
        backups.rotate(previous=old)
    assert old.exists() and corrupt.exists()


def test_encrypted_file_rejects_symlink_and_hardlink(tmp_path):
    good = tmp_path / "good"
    durable_copy(good, b"encrypted-fixture")
    link = tmp_path / "link"
    link.symlink_to(good)
    with pytest.raises(OSError):
        read_file(link)
    link.unlink()
    os.link(good, link)
    with pytest.raises(OSError):
        read_file(good)
