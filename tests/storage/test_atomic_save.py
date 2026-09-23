from pathlib import Path

import pytest

from vault_worker.profile import load_managed
from vault_worker.store import MemoryAnchor, VaultStore, VaultStoreError


MASTER = "synthetic-master-password"


def test_create_commit_and_encrypted_previous_generation(tmp_path):
    anchor = MemoryAnchor()
    store = VaultStore(tmp_path / "private", anchor)
    store.create(MASTER)
    first = store.vault_path.read_bytes()
    assert store.vault_path.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "private").stat().st_mode & 0o777 == 0o700

    def add_entry(db):
        db.add_entry(db.root_group, "Synthetic", "owner@example.invalid", "synthetic-password")

    store.commit(MASTER, add_entry)
    assert store.vault_path.read_bytes() != first
    assert load_managed(store.vault_path.read_bytes(), MASTER).find_entries(title="Synthetic", first=True).password == "synthetic-password"
    assert any(path.read_bytes() == first for path in store.backup_dir.iterdir())


@pytest.mark.parametrize("stage", [
    "after_backup", "after_prepare", "after_temp_write", "after_temp_fsync", "after_validate",
    "after_replace", "after_dir_fsync", "after_ledger", "after_anchor",
])
def test_faults_never_make_empty_vault(tmp_path, stage):
    anchor = MemoryAnchor()
    store = VaultStore(tmp_path / "private", anchor)
    store.create(MASTER)
    before = store.vault_path.read_bytes()

    def fail(name):
        if name == stage:
            raise RuntimeError("synthetic failure")

    with pytest.raises(VaultStoreError):
        store.commit(MASTER, lambda db: db.add_entry(db.root_group, "Synthetic", "owner", "synthetic-password"), fault=fail)

    assert load_managed(store.vault_path.read_bytes(), MASTER)
    reopened = VaultStore(tmp_path / "private", anchor)
    if stage in {"after_replace", "after_dir_fsync", "after_ledger"}:
        with pytest.raises(VaultStoreError) as mismatch:
            reopened.open(MASTER)
        assert mismatch.value.code == "recovery_required"
    else:
        reopened.open(MASTER)
        if stage == "after_anchor":
            assert reopened.vault_path.read_bytes() != before
        else:
            assert reopened.vault_path.read_bytes() == before


def test_changed_file_and_symlink_are_rejected(tmp_path):
    anchor = MemoryAnchor()
    store = VaultStore(tmp_path / "private", anchor)
    store.create(MASTER)
    old = store.vault_path.read_bytes()
    store.vault_path.write_bytes(old + b"tampered")
    with pytest.raises(VaultStoreError) as changed:
        store.open(MASTER)
    assert changed.value.code == "recovery_required"

    path = tmp_path / "other"
    path.write_bytes(old)
    store.vault_path.unlink()
    store.vault_path.symlink_to(path)
    with pytest.raises(VaultStoreError) as symlink:
        store.open(MASTER)
    assert symlink.value.code == "unsafe_path"


def test_concurrent_writer_is_denied(tmp_path):
    store = VaultStore(tmp_path / "private", MemoryAnchor())
    store.create(MASTER)
    with store._writer_lock():
        with pytest.raises(VaultStoreError) as busy:
            store.commit(MASTER, lambda db: None)
    assert busy.value.code == "writer_busy"


def test_external_change_cannot_be_overwritten(tmp_path):
    store = VaultStore(tmp_path / "private", MemoryAnchor())
    store.create(MASTER)
    original = store.vault_path.read_bytes()

    def external_change(db):
        store.vault_path.write_bytes(original + b"external change")

    with pytest.raises(VaultStoreError) as changed:
        store.commit(MASTER, external_change)
    assert changed.value.code == "external_modification"
    assert store.vault_path.read_bytes() == original + b"external change"


def test_unexpected_mutator_error_has_fixed_code(tmp_path):
    store = VaultStore(tmp_path / "private", MemoryAnchor())
    store.create(MASTER)
    before = store.vault_path.read_bytes()

    def fail(db):
        raise ValueError("synthetic-password")

    with pytest.raises(VaultStoreError) as failed:
        store.commit(MASTER, fail)
    assert failed.value.code == "storage_unavailable"
    assert store.vault_path.read_bytes() == before
