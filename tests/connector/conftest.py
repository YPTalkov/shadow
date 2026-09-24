from datetime import datetime, timezone
import secrets
import uuid

import pytest

from vault_worker.ingest import IngestSession, SourceCapabilities, SourceEnrollment
from vault_worker.store import MemoryAnchor, VaultStore

MASTER = "synthetic-connector-master"


@pytest.fixture
def source(tmp_path):
    store = VaultStore(tmp_path / "private", MemoryAnchor())
    store.create(MASTER)
    enrollment = SourceEnrollment(str(uuid.uuid4()), "Synthetic source", SourceCapabilities(True, True, frozenset({"account", "group"}), frozenset({"item_tombstone", "group_tombstone"}), True, totp=True), secrets.token_bytes(32))
    epoch = str(uuid.uuid4())
    restrictions = {}
    def restrict(account, kind, event):
        value = (account, kind)
        if event in restrictions:
            assert restrictions[event] == value
        restrictions[event] = value
    consumer = IngestSession(store, MASTER, enrollment, epoch, restrict=restrict, now=lambda: datetime(2026, 9, 24, tzinfo=timezone.utc))
    return store, enrollment, epoch, consumer, restrictions
