"""Selected credential delivery on the supervisor's inherited private channel.

Native authority must approve each call; this module only checks that the
encrypted entry still matches that approval. It never searches by display name.
"""
import uuid

from .catalog import _origin
from .ingest import source_record
from .store import VaultStoreError


def resolve(vault, *, entry_id, expected_revision, origin, include_totp):
    if (type(entry_id) is not str or type(expected_revision) is not int
            or not 1 <= expected_revision < 2**63 or type(include_totp) is not bool
            or type(origin) is not str or _origin(origin) != origin):
        raise VaultStoreError("invalid_request")
    try:
        identifier = uuid.UUID(entry_id)
        if str(identifier) != entry_id:
            raise ValueError
    except ValueError:
        raise VaultStoreError("invalid_request") from None
    matches = [entry for entry in vault.entries if entry.uuid == identifier]
    if len(matches) != 1:
        raise VaultStoreError("stale_credential")
    entry = matches[0]
    recycle = vault.recyclebin_group
    if recycle is not None and recycle._element in entry._element.iterancestors():
        raise VaultStoreError("stale_credential")
    source = source_record(entry)
    if source and (source.get("conflicted") or source.get("archived")):
        raise VaultStoreError("stale_credential")
    try:
        revision = int(entry.get_custom_property("shadow.revision") or "1")
    except ValueError:
        raise VaultStoreError("stale_credential") from None
    if revision != expected_revision or _origin(entry.url) != origin:
        raise VaultStoreError("stale_credential")
    result = {"username": entry.username or "", "password": entry.password or "", "totp": (entry.otp or None) if include_totp else None}
    if not result["password"] or any(value is not None and len(value.encode("utf-8")) > 65536 for value in result.values()):
        raise VaultStoreError("unsupported_credential")
    return result
