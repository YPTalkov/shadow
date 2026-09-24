import pytest

from vault_worker.encrypted_files import durable_copy
from vault_worker.profile import load_managed
from vault_worker.recovery import Restore
from vault_worker.store import MemoryAnchor, VaultStore, VaultStoreError

MASTER = "synthetic-restore-master"


@pytest.fixture
def generations(tmp_path):
    anchor = MemoryAnchor()
    store = VaultStore(tmp_path / "private", anchor)
    store.create(MASTER)
    store.commit(MASTER, lambda db: db.add_entry(db.root_group, "Recovery fixture", "owner", "synthetic-recovery-canary"))
    selected = tmp_path / "selected.kdbx"
    durable_copy(selected, store.vault_path.read_bytes())
    store.commit(MASTER, lambda db: db.add_entry(db.root_group, "Later fixture", "owner", "synthetic-later-canary"))
    return store, selected


def test_restore_preserves_current_files_and_requires_fresh_unlock(generations):
    store, selected = generations
    original = store.vault_path.read_bytes()
    recovery = Restore(store)
    review = recovery.preview(selected, MASTER)
    assert review["accounts"] == 1 and review["mirrored_ids"] == []
    restrictions = []
    assert recovery.commit(review["review_id"], reconcile=lambda: restrictions.append("reconciled")) == {"state": "restored"}
    assert restrictions == ["reconciled"]
    assert len(store.open(MASTER).entries) == 1
    evidence = store.backup_dir / ("recovery-" + review["review_id"])
    assert (evidence / "vault.kdbx").read_bytes() == original
    assert (evidence / "selected.kdbx").read_bytes() == selected.read_bytes()
    with pytest.raises(VaultStoreError, match="preview_required"):
        recovery.commit(review["review_id"], reconcile=lambda: None)


@pytest.mark.parametrize("damage", ["missing", "corrupt", "rollback"])
def test_explicit_restore_recovers_missing_or_damaged_bookkeeping(generations, damage):
    store, selected = generations
    if damage == "missing":
        store.vault_path.unlink()
        store.ledger_path.unlink()
    elif damage == "corrupt":
        store.vault_path.write_bytes(b"truncated")
        store.ledger_path.write_bytes(b"not sqlite")
    else:
        store.vault_path.write_bytes(selected.read_bytes())
    recovery = Restore(store)
    review = recovery.preview(selected, MASTER)
    recovery.commit(review["review_id"], reconcile=lambda: None)
    assert len(store.open(MASTER).entries) == 1


@pytest.mark.parametrize("stage", ["after_backup", "after_restrictions", "after_prepare", "after_replace", "after_ledger", "after_anchor"])
def test_restore_crashes_preserve_both_encrypted_generations(generations, stage):
    store, selected = generations
    original = store.vault_path.read_bytes()
    recovery = Restore(store)
    review = recovery.preview(selected, MASTER)
    def fail(name):
        if name == stage:
            raise OSError("synthetic_disk_full_or_crash")
    with pytest.raises(VaultStoreError):
        recovery.commit(review["review_id"], reconcile=lambda: None, fault=fail)
    evidence = store.backup_dir / ("recovery-" + review["review_id"])
    assert (evidence / "vault.kdbx").read_bytes() == original
    assert len(load_managed((evidence / "selected.kdbx").read_bytes(), MASTER).entries) == 1
    if stage in {"after_replace", "after_ledger"}:
        with pytest.raises(VaultStoreError, match="recovery_required"):
            store.open(MASTER)
    else:
        assert len(store.open(MASTER).entries) == (1 if stage == "after_anchor" else 2)


def test_invalid_selection_never_changes_current_vault_or_retains_old_review(generations):
    store, selected = generations
    before = store.vault_path.read_bytes()
    recovery = Restore(store)
    recovery.preview(selected, MASTER)
    with pytest.raises(VaultStoreError, match="invalid_credentials"):
        recovery.preview(selected, "wrong-password")
    assert recovery.review is None
    selected.write_bytes(b"truncated")
    with pytest.raises(VaultStoreError):
        recovery.preview(selected, MASTER)
    assert store.vault_path.read_bytes() == before


def test_changed_live_file_and_restriction_failure_prevent_publication(generations):
    store, selected = generations
    recovery = Restore(store)
    review = recovery.preview(selected, MASTER)
    before = store.vault_path.read_bytes()
    def deny():
        raise OSError("history_unavailable")
    with pytest.raises(VaultStoreError):
        recovery.commit(review["review_id"], reconcile=deny)
    assert store.vault_path.read_bytes() == before
    review = recovery.preview(selected, MASTER)
    store.vault_path.write_bytes(before + b"changed")
    with pytest.raises(VaultStoreError, match="external_modification"):
        recovery.commit(review["review_id"], reconcile=lambda: None)
    assert store.vault_path.read_bytes() == before + b"changed"


def test_selection_is_frozen_and_restore_cannot_replay_editor_lease(generations):
    from vault_worker.editor import EditorHandoff
    store, selected = generations
    recovery = Restore(store)
    review = recovery.preview(selected, MASTER)
    selected.write_bytes(b"changed after review")
    recovery.commit(review["review_id"], reconcile=lambda: None)
    assert len(store.open(MASTER).entries) == 1
    EditorHandoff(store).begin(MASTER)
    with pytest.raises(VaultStoreError, match="editor_active"):
        recovery.preview(store.vault_path, MASTER)
