"""Private credential-source/v1 consumer. Never imported by guest tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import secrets
import uuid

from . import encrypted_metadata as metadata
from .store import SkipMutation, VaultStore, VaultStoreError

MAX_FRAME = 1024 * 1024
MAX_BATCH = 64 * 1024 * 1024
FIELDS = ("title", "username", "password", "notes", "totp", "urls")


class IngestError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class SourceCapabilities:
    stable_items: bool
    stable_groups: bool
    complete_scopes: frozenset[str]
    deletion_evidence: frozenset[str]
    distinguishes_access_loss: bool
    totp: bool = False
    collection_mode: str = "owner_interaction_required"
    version: int = 1


@dataclass(frozen=True)
class SourceEnrollment:
    instance: str
    label: str
    capabilities: SourceCapabilities
    digest_key: bytes = field(repr=False)


def exact(record: dict, required: set[str], optional: set[str] = frozenset()) -> None:
    if not isinstance(record, dict) or not required.issubset(record) or not set(record).issubset(required | optional):
        raise IngestError("invalid_record")


def text(value, *, empty=True, maximum=65536) -> str:
    if not isinstance(value, str) or (not empty and not value) or len(value.encode()) > maximum:
        raise IngestError("invalid_record")
    return value


def identity(value) -> str:
    return text(value, empty=False, maximum=256)


def timestamp(value) -> str:
    value = text(value, empty=False, maximum=64)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
    except ValueError:
        raise IngestError("invalid_record") from None
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IngestError("invalid_record")
        result[key] = value
    return result


def bounded(value, depth=0):
    if depth > 12:
        raise IngestError("limit_exceeded")
    if isinstance(value, str):
        text(value)
    elif isinstance(value, dict):
        if len(value) > 32:
            raise IngestError("limit_exceeded")
        for key, child in value.items():
            text(key, maximum=128)
            bounded(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > 10000:
            raise IngestError("limit_exceeded")
        for child in value:
            bounded(child, depth + 1)
    elif value is not None and type(value) not in {bool, int}:
        raise IngestError("invalid_record")


def source_record(entry) -> dict | None:
    value = entry.get_custom_property("shadow.source")
    return json.loads(value) if value else None


def set_source(entry, value: dict) -> None:
    entry.set_custom_property("shadow.source", json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")), protect=True)


def entry_fields(entry) -> dict:
    extra_urls = entry.get_custom_property("shadow.urls")
    urls = json.loads(extra_urls) if extra_urls else ([entry.url] if entry.url else [])
    if urls and entry.url != urls[0]:
        urls = [entry.url or ""] + urls[1:]
    return {"title": entry.title or "", "username": entry.username or "", "password": entry.password or "", "notes": entry.notes or "", "totp": entry.otp or "", "urls": urls}


def version_fields(entry, prefix: str) -> dict:
    result = {}
    for name in FIELDS:
        value = entry.get_custom_property(f"shadow.{prefix}.{name}") or ""
        result[name] = json.loads(value) if name == "urls" and value else ([] if name == "urls" else value)
    return result


def save_version(entry, prefix: str, fields: dict) -> None:
    for name in FIELDS:
        value = json.dumps(fields[name], ensure_ascii=False, separators=(",", ":")) if name == "urls" else fields[name]
        entry.set_custom_property(f"shadow.{prefix}.{name}", value, protect=True)


def apply_fields(entry, fields: dict) -> None:
    entry.title, entry.username, entry.password = fields["title"], fields["username"], fields["password"]
    entry.notes, entry.otp = fields["notes"], fields["totp"]
    entry.url = fields["urls"][0] if fields["urls"] else ""
    entry.set_custom_property("shadow.urls", json.dumps(fields["urls"], ensure_ascii=False, separators=(",", ":")), protect=True)


def bump(entry):
    revision = int(entry.get_custom_property("shadow.revision") or "1")
    if not 1 <= revision < 2**63 - 1:
        raise IngestError("invalid_record")
    entry.set_custom_property("shadow.revision", str(revision + 1), protect=True)


class IngestSession:
    def __init__(self, store: VaultStore, password: str, enrollment: SourceEnrollment, epoch: str, *, restrict, now=None):
        if str(uuid.UUID(enrollment.instance)) != enrollment.instance or str(uuid.UUID(epoch)) != epoch or len(enrollment.digest_key) != 32:
            raise IngestError("invalid_enrollment")
        self.store, self.password, self.enrollment, self.epoch = store, password, enrollment, epoch
        self.restrict = restrict
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.stage: dict | None = None

    def abort(self):
        self.stage = None

    def feed(self, data: bytes) -> dict | None:
        try:
            return self._feed(data)
        except IngestError:
            self.abort()
            raise
        except VaultStoreError as error:
            self.abort()
            code = "vault_unavailable" if error.code in {"editor_active", "vault_locked"} else error.code
            raise IngestError(code) from None
        except Exception:
            self.abort()
            raise IngestError("invalid_record") from None

    def _feed(self, data: bytes) -> dict | None:
        if not isinstance(data, bytes) or not 0 < len(data) <= MAX_FRAME:
            raise IngestError("limit_exceeded")
        message = json.loads(data, object_pairs_hook=unique_object, parse_constant=lambda _: (_ for _ in ()).throw(IngestError("invalid_record")))
        bounded(message)
        exact(message, {"contract_major", "source_instance_id", "channel_epoch", "producer_sequence", "kind", "batch_id", "payload"})
        if type(message["contract_major"]) is not int or message["contract_major"] != 1:
            raise IngestError("unsupported_version")
        if message["source_instance_id"] != self.enrollment.instance or message["channel_epoch"] != self.epoch:
            raise IngestError("identity_mismatch")
        batch, sequence, kind, payload = message["batch_id"], message["producer_sequence"], message["kind"], message["payload"]
        if str(uuid.UUID(batch)) != batch or type(sequence) is not int or not 0 <= sequence <= 100_000:
            raise IngestError("invalid_record")
        if kind == "begin":
            if self.stage is not None or sequence != 0:
                raise IngestError("sequence_mismatch")
            exact(payload, {"previous_generation", "started_at", "mode"})
            if type(payload["previous_generation"]) is not int or payload["previous_generation"] < 0 or payload["mode"] not in {"snapshot", "delta"}:
                raise IngestError("invalid_record")
            timestamp(payload["started_at"])
            self.store.open(self.password)
            self.stage = {"batch": batch, "next": 0, "bytes": 0, "digest": hmac.new(self.enrollment.digest_key, digestmod=hashlib.sha256), "begin": payload, "items": [], "groups": {}, "coverage": {}, "deletions": [], "identities": set(), "expected_digest": self.store.anchor.read()}
        stage = self.stage
        if stage is None or stage["batch"] != batch or stage["next"] != sequence:
            raise IngestError("sequence_mismatch")
        stage["next"] += 1
        stage["bytes"] += len(data)
        if stage["bytes"] > MAX_BATCH:
            raise IngestError("limit_exceeded")
        # Channel epochs authenticate transport but are not semantic batch data.
        semantic = {key: value for key, value in message.items() if key != "channel_epoch"}
        canonical = json.dumps(semantic, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        stage["digest"].update(len(canonical).to_bytes(8, "big") + canonical)
        if kind == "begin":
            return None
        if kind == "abort":
            exact(payload, set())
            self.abort()
            return {"state": "aborted"}
        if kind == "group":
            group = self._group(payload)
            if group["id"] in stage["groups"] or len(stage["groups"]) >= 10000:
                raise IngestError("invalid_record")
            stage["groups"][group["id"]] = group
        elif kind == "item":
            item = self._item(payload)
            if len(stage["items"]) >= 50000 or (item["id"] is not None and item["id"] in stage["identities"]):
                raise IngestError("invalid_record")
            if item["id"] is not None:
                stage["identities"].add(item["id"])
            stage["items"].append(item)
        elif kind == "coverage":
            coverage = self._coverage(payload)
            key = (coverage["scope"], coverage["id"])
            if key in stage["coverage"]:
                raise IngestError("contradictory_coverage")
            stage["coverage"][key] = coverage
        elif kind == "delete":
            exact(payload, {"target", "id", "source_revision", "observed_at", "evidence"})
            if payload["target"] not in {"item", "group"} or payload["evidence"] not in self.enrollment.capabilities.deletion_evidence or payload["evidence"] != payload["target"] + "_tombstone":
                raise IngestError("unsupported_evidence")
            if not self.enrollment.capabilities.stable_items or (payload["target"] == "group" and not self.enrollment.capabilities.stable_groups):
                raise IngestError("unsupported_evidence")
            identity(payload["id"])
            text(payload["source_revision"], maximum=256)
            timestamp(payload["observed_at"])
            stage["deletions"].append(payload)
        elif kind == "commit":
            exact(payload, {"finished_at", "final_sequence", "coverage_count"})
            timestamp(payload["finished_at"])
            if payload["final_sequence"] != sequence or type(payload["final_sequence"]) is not int or payload["coverage_count"] != len(stage["coverage"]) or type(payload["coverage_count"]) is not int:
                raise IngestError("invalid_record")
            receipt = self._commit(stage)
            self.abort()
            return receipt
        else:
            raise IngestError("unsupported_message")
        return None

    def _group(self, value):
        exact(value, {"id", "parent_id", "name", "relationship", "observation"})
        identity(value["id"])
        if value["parent_id"] is not None:
            identity(value["parent_id"])
        text(value["name"], empty=False, maximum=256)
        if value["relationship"] not in {"owner", "member", "unknown"} or value["observation"] not in {"present", "unavailable"}:
            raise IngestError("invalid_record")
        return value

    def _item(self, value):
        exact(value, {"id", "source_revision", "title", "username", "urls", "groups", "credential_kind", "secret"})
        caps = self.enrollment.capabilities
        if caps.stable_items:
            identity(value["id"])
        elif value["id"] is not None:
            raise IngestError("unstable_identity")
        text(value["source_revision"], empty=False, maximum=256)  # "revision_unknown" is explicit.
        text(value["title"], empty=False, maximum=256)
        text(value["username"])
        if not isinstance(value["urls"], list) or len(value["urls"]) > 16 or not isinstance(value["groups"], list) or len(value["groups"]) > 128:
            raise IngestError("invalid_record")
        for url in value["urls"]:
            text(url, maximum=2048)
        for group in value["groups"]:
            identity(group)
        if len(set(value["groups"])) != len(value["groups"]) or value["credential_kind"] != "password":
            raise IngestError("unsupported_credential")
        exact(value["secret"], {"password"}, {"notes", "totp"})
        text(value["secret"]["password"], empty=False)
        text(value["secret"].get("notes", ""))
        text(value["secret"].get("totp", ""))
        if value["secret"].get("totp") and not caps.totp:
            raise IngestError("unsupported_credential")
        return value

    def _coverage(self, value):
        exact(value, {"scope", "id", "state", "basis", "capability_version"})
        if value["scope"] not in {"account", "group"} or value["capability_version"] != self.enrollment.capabilities.version or type(value["capability_version"]) is not int:
            raise IngestError("invalid_record")
        identity(value["id"])
        if value["scope"] == "account" and value["id"] != "account":
            raise IngestError("invalid_record")
        bases = {"complete": {"enumeration_complete"}, "partial": {"enumeration_partial"}, "unavailable": {"source_locked", "source_unavailable"}, "access_lost": {"permission_denied"}}
        if value["state"] not in bases or value["basis"] not in bases[value["state"]]:
            raise IngestError("unsupported_evidence")
        caps = self.enrollment.capabilities
        if value["state"] == "complete" and (self.stage["begin"]["mode"] != "snapshot" or value["scope"] not in caps.complete_scopes or not caps.stable_items or (value["scope"] == "group" and not caps.stable_groups)):
            raise IngestError("unsupported_evidence")
        if value["state"] == "access_lost" and not caps.distinguishes_access_loss:
            raise IngestError("unsupported_evidence")
        return value

    def _commit(self, stage):
        enrollment, caps = self.enrollment, self.enrollment.capabilities
        host_time = self.now().isoformat()
        batch_key = "shadow.batch." + enrollment.instance + "." + stage["batch"]
        source_key = "shadow.source." + enrollment.instance
        batch_digest = stage["digest"].hexdigest()
        result = {}
        account_coverage = stage["coverage"].get(("account", "account"))
        if account_coverage and account_coverage["state"] == "complete" and any(value["state"] != "complete" for value in stage["coverage"].values()):
            raise IngestError("contradictory_coverage")
        if account_coverage and account_coverage["state"] == "access_lost" and stage["items"]:
            raise IngestError("contradictory_coverage")
        removed_groups = {event["id"] for event in stage["deletions"] if event["target"] == "group"}
        for item in stage["items"]:
            if any(group in removed_groups or stage["coverage"].get(("group", group), {}).get("state") == "access_lost" for group in item["groups"]):
                raise IngestError("contradictory_coverage")

        def mutate(vault):
            nonlocal result
            meta = vault.tree.find("Meta")
            prior = metadata.get(meta, batch_key)
            if prior is not None:
                if not hmac.compare_digest(prior["digest"], batch_digest):
                    raise IngestError("batch_conflict")
                result = prior["receipt"]
                raise SkipMutation("replayed")
            source = metadata.get(meta, source_key, {"generation": 0})
            if source["generation"] != stage["begin"]["previous_generation"]:
                raise IngestError("generation_conflict")
            all_groups = self._groups(vault, stage, host_time)
            known = {}
            mirrored = []
            for entry in vault.entries:
                record = source_record(entry)
                if record and record["instance"] == enrollment.instance:
                    mirrored.append((entry, record))
                    if record["item_id"] is not None:
                        if record["item_id"] in known:
                            raise IngestError("ambiguous_identity")
                        known[record["item_id"]] = (entry, record)
            accepted = conflicted = retained = 0
            warnings = set()
            deleted_items = {event["id"] for event in stage["deletions"] if event["target"] == "item"}
            if deleted_items & stage["identities"]:
                raise IngestError("contradictory_evidence")
            for item in stage["items"]:
                if any(group not in all_groups for group in item["groups"]):
                    raise IngestError("unknown_group")
                fields = {name: item[name] for name in ("title", "username", "urls")}
                fields.update({name: item["secret"].get(name, "") for name in ("password", "notes", "totp")})
                primary = all_groups[sorted(item["groups"])[0]] if item["groups"] else all_groups[None]
                prior_entry = known.get(item["id"]) if item["id"] is not None else None
                if prior_entry is None:
                    entry = vault.add_entry(primary, fields["title"], fields["username"], fields["password"], force_creation=True)
                    apply_fields(entry, fields)
                    save_version(entry, "baseline", fields)
                    entry.set_custom_property("shadow.revision", "1", protect=True)
                    entry.set_custom_property("shadow.authority.kind", "mirrored", protect=True)
                    record = {"instance": enrollment.instance, "item_id": item["id"], "presence": "present" if item["id"] else "unknown", "groups": [], "events": [], "diverged": False, "conflicted": item["id"] is None}
                    if item["id"] is None:
                        warnings.add("unlinked_candidates")
                        entry.set_custom_property("shadow.conflict.reason", "unlinked_identity", protect=True)
                        save_version(entry, "incoming", fields)
                        self._restriction(entry, record, "unknown", "unstable_identity", stage, host_time)
                        conflicted += 1
                else:
                    entry, record = prior_entry
                    current, baseline = entry_fields(entry), version_fields(entry, "baseline")
                    local_group_changed = str(entry.group.uuid) != entry.get_custom_property("shadow.baseline.group")
                    incoming_group_changed = sorted(item["groups"]) != sorted(record["groups"])
                    incompatible = (current != baseline and fields != baseline and current != fields) or (local_group_changed and incoming_group_changed)
                    if incompatible or record.get("conflicted"):
                        conflict_changed = not record.get("conflicted") or version_fields(entry, "incoming") != fields or entry.get_custom_property("shadow.incoming.group") != str(primary.uuid)
                        save_version(entry, "incoming", fields)
                        entry.set_custom_property("shadow.incoming.group", str(primary.uuid), protect=True)
                        entry.set_custom_property("shadow.conflict.reason", "owner_source_divergence", protect=True)
                        record["conflicted"] = True
                        if conflict_changed:
                            bump(entry)
                        conflicted += 1
                    else:
                        if current == baseline or current == fields:
                            if current != fields or (entry.group.uuid != primary.uuid and not local_group_changed):
                                entry.save_history()
                                apply_fields(entry, fields)
                                bump(entry)
                            save_version(entry, "baseline", fields)
                            if not local_group_changed:
                                vault.move_entry(entry, primary)
                        record["diverged"] = entry_fields(entry) != fields or local_group_changed
                        if record["presence"] != "present":
                            bump(entry)
                        record["presence"] = "present"
                previous_groups = record["groups"]
                if item["id"] is not None and record["presence"] != "present":
                    record["presence"] = "present"
                    bump(entry)
                if previous_groups != item["groups"]:
                    self._event(record, {"kind": "membership", "previous": previous_groups, "current": item["groups"], "observed_at": host_time})
                record.update({"groups": item["groups"], "source_revision": item["source_revision"], "last_observed": host_time})
                entry.set_custom_property("shadow.baseline.group", str(primary.uuid), protect=True)
                set_source(entry, record)
                accepted += 1
            for group_id in removed_groups:
                group = all_groups.get(group_id)
                if group is not None:
                    group_record = metadata.get(group._element, "shadow.source")
                    group_record["removed_at"] = host_time
                    metadata.put(group._element, "shadow.source", group_record)
            for entry, record in mirrored:
                if record["item_id"] in stage["identities"]:
                    continue
                presence = reason = None
                if record["item_id"] in deleted_items or (account_coverage and account_coverage["state"] == "complete" and record["item_id"] is not None):
                    presence, reason = "deleted_at_source", "complete_account_absence" if record["item_id"] not in deleted_items else "item_tombstone"
                elif account_coverage and account_coverage["state"] == "access_lost":
                    presence, reason = "access_lost", "account_permission_loss"
                else:
                    for group in record["groups"]:
                        coverage = stage["coverage"].get(("group", group))
                        if coverage and coverage["state"] == "access_lost":
                            presence, reason = "access_lost", "group_permission_loss"
                            break
                        if group in removed_groups or (coverage and coverage["state"] == "complete"):
                            presence, reason = "unknown", "group_absence_uncertain"
                if presence:
                    self._restriction(entry, record, presence, reason, stage, host_time)
                    set_source(entry, record)
                    retained += 1
            if any(coverage["state"] != "complete" for coverage in stage["coverage"].values()) or not stage["coverage"]:
                warnings.add("partial_coverage")
            result = {"batch_id": stage["batch"], "receipt_ref": secrets.token_hex(32), "generation": source["generation"] + 1, "accepted": accepted, "conflicted": conflicted, "retained": retained, "warnings": sorted(warnings)}
            metadata.put(meta, source_key, {"instance": enrollment.instance, "label": enrollment.label, "generation": result["generation"], "last_received": host_time, "coverage": list(stage["coverage"].values()), "capability_version": caps.version})
            metadata.put(meta, batch_key, {"digest": batch_digest, "receipt": result})

        error = None
        def checked_mutate(vault):
            nonlocal error
            try:
                mutate(vault)
            except IngestError as caught:
                error = caught
                raise
        try:
            self.store.commit(self.password, checked_mutate, expected_digest=stage["expected_digest"])
        except VaultStoreError:
            if error:
                raise error from None
            raise
        return result

    @staticmethod
    def _event(record, event):
        if len(record["events"]) >= 1000:
            raise IngestError("history_limit")
        record["events"].append(event)

    def _restriction(self, entry, record, presence, reason, stage, host_time):
        if record["presence"] != presence or not record.get("restriction_event"):
            event_id = str(uuid.uuid5(uuid.UUID(stage["batch"]), str(entry.uuid) + presence))
            kind = {"deleted_at_source": "deletedAtSource", "access_lost": "accessLost", "unknown": "historyUnknown"}[presence]
            self.restrict(str(entry.uuid), kind, event_id)
            record["restriction_event"] = event_id
            self._event(record, {"id": event_id, "kind": presence, "basis": reason, "observed_at": host_time, "groups": record["groups"]})
            entry.set_custom_property("shadow.retention.notice", "Retained local copy: " + presence + "; evidence: " + reason + "; observed: " + host_time, protect=True)
            bump(entry)
        record["presence"] = presence

    def _groups(self, vault, stage, host_time):
        source_id = self.enrollment.instance
        root = next((group for group in vault.groups if metadata.get(group._element, "shadow.source_root") == source_id), None)
        if root is None:
            sources = vault.find_groups(name="Sources", first=True) or vault.add_group(vault.root_group, "Sources")
            root = vault.add_group(sources, self.enrollment.label)
            metadata.put(root._element, "shadow.source_root", source_id)
        known = {None: root}
        if self.enrollment.capabilities.stable_groups:
            for group in vault.groups:
                record = metadata.get(group._element, "shadow.source")
                if record and record["instance"] == source_id:
                    if record["id"] in known:
                        raise IngestError("ambiguous_identity")
                    known[record["id"]] = group
        pending = dict(stage["groups"])
        for _ in range(33):
            if not pending:
                break
            progressed = False
            for group_id, info in list(pending.items()):
                if info["parent_id"] in pending or info["parent_id"] not in known:
                    continue
                parent = known[info["parent_id"]]
                if len(list(parent._element.iterancestors("Group"))) >= 32:
                    raise IngestError("invalid_group_hierarchy")
                group = known.get(group_id)
                if group is None:
                    group = vault.add_group(parent, info["name"])
                    history = []
                else:
                    previous = metadata.get(group._element, "shadow.source")
                    history = previous.get("history", [])
                    if group.name != info["name"] or group.parentgroup.uuid != parent.uuid:
                        if len(history) >= 1000:
                            raise IngestError("history_limit")
                        history.append({"name": group.name, "parent_id": previous.get("parent_id"), "observed_at": host_time})
                        group.name = info["name"]
                        vault.move_group(group, parent)
                known[group_id] = group
                metadata.put(group._element, "shadow.source", {"instance": source_id, **info, "stable": self.enrollment.capabilities.stable_groups, "history": history, "last_observed": host_time})
                del pending[group_id]
                progressed = True
            if not progressed:
                break
        if pending:
            raise IngestError("invalid_group_hierarchy")
        return known
