import json

import pytest

from vault_worker.ingest import IngestError, IngestSession, source_record
from vault_worker.editor import EditorHandoff
from fake_source import coverage, frames, group, item, run
from conftest import MASTER


def test_commit_retry_changed_replay_and_stale_generation(source):
    store, enrollment, epoch, consumer, restrictions = source
    events = [("group", group()), ("item", item()), ("coverage", coverage())]
    messages = frames(enrollment, epoch, events)
    receipt = run(consumer, messages)
    assert receipt["generation"] == 1 and receipt["accepted"] == 1
    assert "synthetic-source-password" not in json.dumps(receipt)
    first_generation = store.vault_path.read_bytes()
    assert run(consumer, messages) == receipt
    assert store.vault_path.read_bytes() == first_generation
    altered = [json.loads(value) for value in messages]
    altered[2]["payload"]["secret"]["password"] = "changed-synthetic-secret"
    with pytest.raises(IngestError, match="batch_conflict"):
        run(consumer, [json.dumps(value).encode() for value in altered])
    with pytest.raises(IngestError, match="generation_conflict"):
        run(consumer, frames(enrollment, epoch, events, generation=0))
    assert store.vault_path.read_bytes() == first_generation and not restrictions


@pytest.mark.parametrize("fault", ["version", "instance", "epoch", "unknown", "sequence", "secret", "oversize", "nested"])
def test_malformed_or_unauthenticated_frames_have_no_effect(source, fault):
    store, enrollment, epoch, consumer, _ = source
    before = store.vault_path.read_bytes()
    messages = frames(enrollment, epoch, [("group", group()), ("item", item())])
    data = json.loads(messages[0])
    if fault == "version": data["contract_major"] = 2
    if fault == "instance": data["source_instance_id"] = "wrong"
    if fault == "epoch": data["channel_epoch"] = "wrong"
    if fault == "unknown": data["approved"] = True
    if fault == "sequence": data["producer_sequence"] = 1
    if fault == "secret": data["payload"]["password"] = "synthetic-canary"
    if fault == "nested": data["payload"]["extra"] = [[[[[[[[[[[[[["deep"]]]]]]]]]]]]]]
    with pytest.raises(IngestError):
        consumer.feed(b"x" * (1024 * 1024 + 1) if fault == "oversize" else json.dumps(data).encode())
    assert store.vault_path.read_bytes() == before and consumer.stage is None


def test_interrupted_batch_and_editor_handoff_do_not_publish(source):
    store, enrollment, epoch, consumer, _ = source
    before = store.vault_path.read_bytes()
    messages = frames(enrollment, epoch, [("group", group()), ("item", item()), ("coverage", coverage())])
    run(consumer, messages[:-1])
    assert store.vault_path.read_bytes() == before
    consumer.abort()
    editor = EditorHandoff(store)
    editor.begin(MASTER)
    with pytest.raises(IngestError, match="vault_unavailable"):
        consumer.feed(messages[0])
    assert store.vault_path.read_bytes() == before


def test_concurrent_owner_write_is_not_overwritten(source):
    store, enrollment, epoch, consumer, _ = source
    messages = frames(enrollment, epoch, [("group", group()), ("item", item())])
    run(consumer, messages[:-1])
    store.commit(MASTER, lambda db: db.add_entry(db.root_group, "Owner change", "owner", "synthetic-local"))
    changed = store.vault_path.read_bytes()
    with pytest.raises(IngestError, match="external_modification"):
        consumer.feed(messages[-1])
    assert store.vault_path.read_bytes() == changed


def test_source_vault_roundtrips_unchanged_through_editor(source):
    store, enrollment, epoch, consumer, _ = source
    run(consumer, frames(enrollment, epoch, [("group", group()), ("item", item()), ("coverage", coverage())]))
    editor = EditorHandoff(store)
    editor.begin(MASTER)
    preview = editor.preview(MASTER)
    assert preview["changed"] == 0
    editor.commit(MASTER, preview["review_id"])
    assert source_record(store.open(MASTER).entries[0])["instance"] == enrollment.instance


def test_duplicate_names_distinct_ids_and_multiple_memberships(source):
    store, enrollment, epoch, consumer, _ = source
    receipt = run(consumer, frames(enrollment, epoch, [("group", group()), ("group", group("group-b")), ("item", item(groups=["group-b", "group-a"])), ("item", item("item-b")), ("coverage", coverage())]))
    assert receipt["accepted"] == 2
    entries = store.open(MASTER).entries
    assert len(entries) == 2 and entries[0].uuid != entries[1].uuid
    assert {source_record(entry)["item_id"] for entry in entries} == {"item-a", "item-b"}
    assert sorted(source_record(entries[0])["groups"]) == ["group-a", "group-b"]


def test_contradictory_coverage_and_unsupported_evidence_are_refused(source):
    store, enrollment, epoch, consumer, _ = source
    before = store.vault_path.read_bytes()
    with pytest.raises(IngestError, match="contradictory_coverage"):
        run(consumer, frames(enrollment, epoch, [("coverage", coverage()), ("coverage", coverage("partial", "group", "group-a"))]))
    with pytest.raises(IngestError, match="unsupported_evidence"):
        run(consumer, frames(enrollment, epoch, [("delete", {"target": "item", "id": "item-a", "source_revision": "revision_unknown", "observed_at": "2026-09-24T00:00:00Z", "evidence": "not_found_in_search"})]))
    assert store.vault_path.read_bytes() == before


def test_disk_full_and_batch_limit_leave_previous_generation(source, monkeypatch):
    store, enrollment, epoch, consumer, _ = source
    before = store.vault_path.read_bytes()
    messages = frames(enrollment, epoch, [("group", group()), ("item", item())])
    def disk_full(*args):
        raise OSError(28, "synthetic disk full")
    monkeypatch.setattr("os.write", disk_full)
    with pytest.raises(IngestError, match="storage_unavailable"):
        run(consumer, messages)
    assert store.vault_path.read_bytes() == before and store.open(MASTER)
    monkeypatch.setattr("vault_worker.ingest.MAX_BATCH", 100)
    with pytest.raises(IngestError, match="limit_exceeded"):
        run(consumer, messages)
    assert store.vault_path.read_bytes() == before
