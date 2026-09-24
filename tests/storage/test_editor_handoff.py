import io
import shutil
import subprocess

import pytest

from vault_worker.editor import EditorHandoff
from vault_worker.profile import load_managed
from vault_worker.store import MemoryAnchor, VaultStore, VaultStoreError

MASTER = "synthetic-editor-master"


@pytest.fixture
def editing(tmp_path):
    anchor = MemoryAnchor()
    store = VaultStore(tmp_path / "private", anchor)
    store.create(MASTER)
    def add(db):
        entry = db.add_entry(db.root_group, "Synthetic", "owner", "synthetic-password", notes="synthetic-notes")
        entry.set_custom_property("shadow.source.instance", "synthetic-source", protect=True)
        entry.set_custom_property("shadow.revision", "4", protect=True)
        entry.set_custom_property("owner-field", "synthetic-custom", protect=True)
    store.commit(MASTER, add)
    editor = EditorHandoff(store)
    status = editor.begin(MASTER)
    from pathlib import Path
    return store, editor, Path(status["checkout_path"])


def save_checkout(path, mutate):
    db = load_managed(path.read_bytes(), MASTER)
    mutate(db)
    stream = io.BytesIO()
    db.save(stream)
    path.write_bytes(stream.getvalue())


def test_editor_gate_survives_worker_restart_and_blocks_writes(editing):
    store, editor, path = editing
    restarted = EditorHandoff(store)
    assert restarted.status() == editor.status()
    with pytest.raises(VaultStoreError, match="editor_active"):
        store.open(MASTER)
    with pytest.raises(VaultStoreError, match="editor_active"):
        store.commit(MASTER, lambda db: None)
    restarted.cancel(discard=False)
    assert path.exists()
    assert store.open(MASTER).entries[0].title == "Synthetic"


def test_reconciles_content_and_preserves_existing_authority_metadata(editing):
    store, editor, path = editing
    def mutate(db):
        entry = db.entries[0]
        entry.save_history()
        entry.title = "Edited"
        entry.password = "synthetic-edited-password"
        entry.set_custom_property("shadow.source.instance", "forged-source", protect=True)
        db.move_entry(entry, db.add_group(db.root_group, "Edited Group"))
        added = db.add_entry(db.root_group, "Added", "owner", "synthetic-new-password")
        added.set_custom_property("shadow.source.instance", "forged-source", protect=True)
    save_checkout(path, mutate)
    preview = editor.preview(MASTER)
    assert preview["added"] == 1 and preview["changed"] == 1 and preview["removed"] == 0
    assert preview["groups_changed"] and preview["protected_metadata_restored"] == 2
    result = editor.commit(MASTER, preview["review_id"])
    assert result == {"state": "applied", "checkout_retained": True, "late_change": False}
    updated = store.open(MASTER)
    entry = updated.find_entries(title="Edited", first=True)
    assert entry.password == "synthetic-edited-password" and entry.group.name == "Edited Group"
    assert entry.get_custom_property("shadow.source.instance") == "synthetic-source"
    assert entry.get_custom_property("shadow.revision") == "5"
    assert entry.get_custom_property("owner-field") == "synthetic-custom"
    assert entry.notes == "synthetic-notes" and entry.history[0].password == "synthetic-password"
    added = updated.find_entries(title="Added", first=True)
    assert added.get_custom_property("shadow.source.instance") is None
    assert added.get_custom_property("shadow.authority.kind") == "local"
    committed = store.vault_path.read_bytes()
    save_checkout(path, lambda db: setattr(db.entries[0], "password", "late-editor-password"))
    assert store.vault_path.read_bytes() == committed


def test_changed_or_missing_checkout_preserves_live_generation(editing):
    store, editor, path = editing
    original, anchor = store.vault_path.read_bytes(), store.anchor.read()
    preview = editor.preview(MASTER)
    save_checkout(path, lambda db: setattr(db.entries[0], "title", "Late edit"))
    with pytest.raises(VaultStoreError, match="editor_changed"):
        editor.commit(MASTER, preview["review_id"])
    assert store.vault_path.read_bytes() == original and store.anchor.read() == anchor
    path.unlink()
    with pytest.raises(VaultStoreError, match="editor_unavailable"):
        editor.preview(MASTER)
    assert editor.status()["state"] == "editing"


def test_master_password_change_is_refused_and_preserved(editing):
    store, editor, path = editing
    save_checkout(path, lambda db: setattr(db, "password", "synthetic-new-master"))
    edited = path.read_bytes()
    with pytest.raises(VaultStoreError, match="invalid_credentials"):
        editor.preview(MASTER)
    assert path.read_bytes() == edited and editor.status()["state"] == "editing"
    editor.cancel(discard=False)
    assert store.open(MASTER)


@pytest.mark.skipif(shutil.which("keepassxc-cli") is None, reason="KeePassXC is not installed")
def test_real_keepassxc_checkout_edit_and_reconciliation(editing):
    store, editor, path = editing
    result = subprocess.run(["keepassxc-cli", "edit", "-q", "-t", "KeePassXC Edited", str(path), "Synthetic"], input=MASTER + "\n", text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, "synthetic KeePassXC edit failed"
    preview = editor.preview(MASTER)
    assert preview["changed"] == 1
    editor.commit(MASTER, preview["review_id"])
    assert store.open(MASTER).find_entries(title="KeePassXC Edited", first=True).password == "synthetic-password"

