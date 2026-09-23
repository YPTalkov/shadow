"""Reusable synthetic credential-source/v1 producer; no Apple integration."""

import json
import uuid

NOW = "2026-09-24T00:00:00+00:00"


def group(identity="group-a", name="Synthetic Group", parent=None):
    return {"id": identity, "parent_id": parent, "name": name, "relationship": "member", "observation": "present"}


def item(identity="item-a", password="synthetic-source-password", groups=None, title="Synthetic Account"):
    return {"id": identity, "source_revision": "revision_unknown", "title": title, "username": "owner@example.invalid", "urls": ["https://example.invalid/path?ignored=query"], "groups": ["group-a"] if groups is None else groups, "credential_kind": "password", "secret": {"password": password, "notes": "synthetic-owner-notes"}}


def coverage(state="complete", scope="account", identity="account"):
    basis = {"complete": "enumeration_complete", "partial": "enumeration_partial", "unavailable": "source_locked", "access_lost": "permission_denied"}[state]
    return {"scope": scope, "id": identity, "state": state, "basis": basis, "capability_version": 1}


def frames(enrollment, epoch, events, *, generation=0, batch=None, mode="snapshot"):
    batch = batch or str(uuid.uuid4())
    records = [("begin", {"previous_generation": generation, "started_at": NOW, "mode": mode})] + list(events)
    records.append(("commit", {"finished_at": NOW, "final_sequence": len(records), "coverage_count": sum(kind == "coverage" for kind, _ in events)}))
    return [json.dumps({"contract_major": 1, "source_instance_id": enrollment.instance, "channel_epoch": epoch, "producer_sequence": index, "kind": kind, "batch_id": batch, "payload": payload}, sort_keys=True).encode() for index, (kind, payload) in enumerate(records)]


def run(consumer, messages):
    result = None
    for message in messages:
        result = consumer.feed(message)
    return result
