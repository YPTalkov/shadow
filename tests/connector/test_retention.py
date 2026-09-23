import pytest

from vault_worker import encrypted_metadata as metadata
from vault_worker.ingest import source_record
from fake_source import NOW, coverage, frames, group, item, run
from conftest import MASTER


@pytest.mark.parametrize("state,presence,event_kind", [("complete", "deleted_at_source", "deletedAtSource"), ("partial", "present", None), ("unavailable", "present", None), ("access_lost", "access_lost", "accessLost")])
def test_coverage_retains_secret_with_distinct_presence(source, state, presence, event_kind):
    store, enrollment, epoch, consumer, restrictions = source
    run(consumer, frames(enrollment, epoch, [("group", group()), ("item", item()), ("coverage", coverage())]))
    previous = store.open(MASTER).entries[0]
    previous_id, observed = previous.uuid, source_record(previous)["last_observed"]
    receipt = run(consumer, frames(enrollment, epoch, [("coverage", coverage(state))], generation=1))
    entry = store.open(MASTER).entries[0]
    record = source_record(entry)
    assert entry.uuid == previous_id and entry.password == "synthetic-source-password"
    assert entry.notes == "synthetic-owner-notes" and record["presence"] == presence
    assert record["last_observed"] == observed
    assert receipt["retained"] == (1 if event_kind else 0)
    assert {value[1] for value in restrictions.values()} == ({event_kind} if event_kind else set())


def test_reappearance_does_not_clear_removal_restriction(source):
    store, enrollment, epoch, consumer, restrictions = source
    run(consumer, frames(enrollment, epoch, [("group", group()), ("item", item()), ("coverage", coverage())]))
    run(consumer, frames(enrollment, epoch, [("coverage", coverage())], generation=1))
    removed = source_record(store.open(MASTER).entries[0])["restriction_event"]
    run(consumer, frames(enrollment, epoch, [("item", item(password="synthetic-new-password")), ("coverage", coverage())], generation=2))
    entry = store.open(MASTER).entries[0]
    assert entry.password == "synthetic-new-password"
    assert source_record(entry)["presence"] == "present"
    assert source_record(entry)["restriction_event"] == removed and removed in restrictions
    assert entry.history[0].password == "synthetic-source-password"


def test_group_absence_is_uncertain_and_positive_move_is_not_deletion(source):
    store, enrollment, epoch, consumer, restrictions = source
    run(consumer, frames(enrollment, epoch, [("group", group()), ("group", group("group-b", "Second")), ("item", item())]))
    run(consumer, frames(enrollment, epoch, [("item", item(groups=["group-b"])), ("coverage", coverage("complete", "group", "group-a"))], generation=1))
    assert not restrictions
    entry = store.open(MASTER).entries[0]
    assert source_record(entry)["presence"] == "present" and entry.group.name == "Second"
    run(consumer, frames(enrollment, epoch, [("coverage", coverage("complete", "group", "group-b"))], generation=2))
    entry = store.open(MASTER).entries[0]
    assert source_record(entry)["presence"] == "unknown" and entry.password == "synthetic-source-password"
    assert {value[1] for value in restrictions.values()} == {"historyUnknown"}


def test_group_removal_preserves_group_and_entry(source):
    store, enrollment, epoch, consumer, _ = source
    run(consumer, frames(enrollment, epoch, [("group", group()), ("item", item())]))
    run(consumer, frames(enrollment, epoch, [("delete", {"target": "group", "id": "group-a", "source_revision": "revision_unknown", "observed_at": NOW, "evidence": "group_tombstone"})], generation=1))
    entry = store.open(MASTER).entries[0]
    assert entry.group.name == "Synthetic Group" and source_record(entry)["presence"] == "unknown"
    assert metadata.get(entry.group._element, "shadow.source")["removed_at"]
