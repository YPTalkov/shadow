from dataclasses import replace
import json
import uuid

import pytest

from vault_worker.catalog import Catalog
from vault_worker.conflicts import resolve
from vault_worker.ingest import IngestError, IngestSession, bump, source_record
from fake_source import coverage, frames, group, item, run
from conftest import MASTER


@pytest.mark.parametrize("choice", ["keep_local", "accept_incoming", "keep_both"])
def test_owner_resolves_encrypted_conflict_without_silent_overwrite(source, choice):
    store, enrollment, epoch, consumer, _ = source
    run(consumer, frames(enrollment, epoch, [("group", group()), ("item", item()), ("coverage", coverage())]))
    def owner_edit(db):
        entry = db.entries[0]
        entry.password = "synthetic-owner-edited"
        bump(entry)
    store.commit(MASTER, owner_edit)
    receipt = run(consumer, frames(enrollment, epoch, [("item", item(password="synthetic-incoming")), ("coverage", coverage())], generation=1))
    entry = store.open(MASTER).entries[0]
    assert receipt["conflicted"] == 1 and entry.password == "synthetic-owner-edited"
    assert entry.get_custom_property("shadow.incoming.password") == "synthetic-incoming"
    assert source_record(entry)["conflicted"]
    public = json.dumps(Catalog.from_vault(store.open(MASTER)).owner_page(0))
    assert "synthetic-owner-edited" not in public and "synthetic-incoming" not in public
    operation = str(uuid.uuid4())
    revision = int(entry.get_custom_property("shadow.revision"))
    arguments = dict(entry_id=str(entry.uuid), expected_revision=revision, choice=choice, operation_id=operation)
    result = resolve(store, MASTER, **arguments)
    committed = store.vault_path.read_bytes()
    assert resolve(store, MASTER, **arguments) == result and store.vault_path.read_bytes() == committed
    entries = store.open(MASTER).entries
    mirror = next(value for value in entries if value.uuid == entry.uuid)
    assert not source_record(mirror)["conflicted"]
    assert mirror.password == ("synthetic-owner-edited" if choice == "keep_local" else "synthetic-incoming")
    assert int(mirror.get_custom_property("shadow.revision")) == revision + 1
    if choice == "keep_both":
        clone = next(value for value in entries if value.uuid != mirror.uuid)
        assert source_record(clone) is None and clone.password == "synthetic-owner-edited"
        assert clone.get_custom_property("shadow.local_origin")
    assert len(entries) == (2 if choice == "keep_both" else 1)


def test_identical_observation_does_not_increment_revision(source):
    store, enrollment, epoch, consumer, _ = source
    run(consumer, frames(enrollment, epoch, [("group", group()), ("item", item())]))
    before = store.open(MASTER).entries[0].get_custom_property("shadow.revision")
    run(consumer, frames(enrollment, epoch, [("item", item())], generation=1))
    assert store.open(MASTER).entries[0].get_custom_property("shadow.revision") == before


def test_unknown_identity_creates_candidates_without_name_matching(source):
    store, enrollment, epoch, _, restrictions = source
    enrollment = replace(enrollment, capabilities=replace(enrollment.capabilities, stable_items=False, complete_scopes=frozenset()))
    def restrict(account, kind, event): restrictions[event] = (account, kind)
    consumer = IngestSession(store, MASTER, enrollment, epoch, restrict=restrict)
    for generation in range(2):
        run(consumer, frames(enrollment, epoch, [("group", group()), ("item", item(None)), ("coverage", coverage("partial"))], generation=generation))
    entries = store.open(MASTER).entries
    assert len(entries) == 2 and entries[0].uuid != entries[1].uuid
    assert all(source_record(entry)["conflicted"] for entry in entries)
    selected = entries[0]
    revision = int(selected.get_custom_property("shadow.revision"))
    resolve(store, MASTER, entry_id=str(selected.uuid), expected_revision=revision, choice="keep_local", operation_id=str(uuid.uuid4()))
    reopened = store.open(MASTER)
    adopted = next(entry for entry in reopened.entries if source_record(entry) is None)
    archived = reopened.find_entries(uuid=selected.uuid, first=True)
    assert adopted.uuid != selected.uuid and adopted.password == "synthetic-source-password"
    assert source_record(archived)["archived"]
    assert int(archived.get_custom_property("shadow.revision")) > revision
    assert str(archived.uuid) not in json.dumps(Catalog.from_vault(reopened).owner_page(0))


def test_stale_conflict_revision_cannot_be_resolved(source):
    store, enrollment, epoch, consumer, _ = source
    run(consumer, frames(enrollment, epoch, [("group", group()), ("item", item())]))
    def owner_edit(db):
        db.entries[0].password = "synthetic-owner-edited"
        bump(db.entries[0])
    store.commit(MASTER, owner_edit)
    run(consumer, frames(enrollment, epoch, [("item", item(password="synthetic-incoming"))], generation=1))
    entry = store.open(MASTER).entries[0]
    before = store.vault_path.read_bytes()
    with pytest.raises(IngestError, match="stale_conflict"):
        resolve(store, MASTER, entry_id=str(entry.uuid), expected_revision=1, choice="accept_incoming", operation_id=str(uuid.uuid4()))
    assert store.vault_path.read_bytes() == before
