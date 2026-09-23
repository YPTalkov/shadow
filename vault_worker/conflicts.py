"""Explicit owner reconciliation of encrypted source conflicts."""

from copy import deepcopy
import json
import uuid

from .ingest import IngestError, apply_fields, bump, entry_fields, save_version, set_source, source_record, version_fields
from .store import SkipMutation, VaultStore, VaultStoreError


def resolve(store: VaultStore, password: str, *, entry_id: str, expected_revision: int, choice: str, operation_id: str) -> dict:
    if choice not in {"keep_local", "accept_incoming", "keep_both"} or str(uuid.UUID(entry_id)) != entry_id or str(uuid.UUID(operation_id)) != operation_id:
        raise IngestError("invalid_request")
    result = {"state": "resolved", "created_local_copy": choice == "keep_both"}
    error = None

    def mutate(vault):
        nonlocal error
        try:
            entry = vault.find_entries(uuid=uuid.UUID(entry_id), first=True)
            if entry is None:
                raise IngestError("stale_conflict")
            marker = entry.get_custom_property("shadow.conflict.last_resolution")
            if marker:
                prior = json.loads(marker)
                if prior["operation_id"] == operation_id:
                    if prior["choice"] != choice or prior["revision"] != expected_revision:
                        raise IngestError("operation_conflict")
                    result.update(prior["result"])
                    raise SkipMutation("replayed")
            source = source_record(entry)
            if source is None or not source.get("conflicted") or int(entry.get_custom_property("shadow.revision") or "1") != expected_revision:
                raise IngestError("stale_conflict")
            incoming = version_fields(entry, "incoming")
            incoming_group = entry.get_custom_property("shadow.incoming.group")
            if source["item_id"] is None:
                if choice != "keep_local":
                    raise IngestError("unlinked_identity")
                _local_copy(vault, entry, source)
                source["conflicted"] = False
                source["archived"] = True
                set_source(entry, source)
                result["created_local_copy"] = True
            else:
                if choice == "keep_both":
                    _local_copy(vault, entry, source)
                if choice in {"accept_incoming", "keep_both"}:
                    entry.save_history()
                    apply_fields(entry, incoming)
                    target = vault.find_groups(uuid=uuid.UUID(incoming_group), first=True) if incoming_group else None
                    if target is None:
                        raise IngestError("stale_conflict")
                    vault.move_entry(entry, target)
                save_version(entry, "baseline", incoming)
                if incoming_group:
                    entry.set_custom_property("shadow.baseline.group", incoming_group, protect=True)
                source["conflicted"] = False
                source["diverged"] = choice == "keep_local"
                set_source(entry, source)
            for key in list(entry.custom_properties):
                if key.startswith("shadow.incoming.") or key == "shadow.conflict.reason":
                    entry.delete_custom_property(key)
            bump(entry)
            entry.set_custom_property("shadow.conflict.last_resolution", json.dumps({"operation_id": operation_id, "choice": choice, "revision": expected_revision, "result": result}, sort_keys=True), protect=True)
        except IngestError as caught:
            error = caught
            raise

    try:
        store.commit(password, mutate)
    except VaultStoreError:
        if error:
            raise error from None
        raise
    return result


def _local_copy(vault, entry, source):
    local = vault.find_groups(name="Local copies", first=True) or vault.add_group(vault.root_group, "Local copies")
    clone = vault.add_entry(local, entry.title, entry.username, entry.password, force_creation=True)
    apply_fields(clone, entry_fields(entry))
    for key, value in entry.custom_properties.items():
        if not key.startswith("shadow."):
            clone.set_custom_property(key, value, protect=True)
    history = entry._element.find("History")
    if history is not None:
        cloned_history = deepcopy(history)
        for previous in cloned_history.findall("Entry/UUID"):
            previous.text = clone._element.findtext("UUID")
        clone._element.append(cloned_history)
    _make_local(clone, source)
    clone.set_custom_property("shadow.revision", "1", protect=True)


def _make_local(entry, source):
    for key in list(entry.custom_properties):
        if key.startswith("shadow."):
            entry.delete_custom_property(key)
    entry.set_custom_property("shadow.authority.kind", "local", protect=True)
    entry.set_custom_property("shadow.local_origin", json.dumps({"instance": source["instance"], "item_id": source["item_id"], "restriction_event": source.get("restriction_event")}, sort_keys=True), protect=True)
