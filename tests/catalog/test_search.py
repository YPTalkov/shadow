import json
import hashlib

import pytest

from vault_worker.catalog import Catalog, CatalogError
from vault_worker.profile import create_managed, load_managed


MASTER = "synthetic-master-password"


def reference(account_id):
    # Deterministic test stand-in for the native 256-bit capability registry.
    return hashlib.sha256(account_id.encode()).hexdigest()


def sample_catalog():
    vault = load_managed(create_managed(MASTER), MASTER)
    group = vault.add_group(vault.root_group, "Synthetic Group")
    first = vault.add_entry(group, "Example", "Zoë@EXAMPLE.invalid", "password-canary", url="https://example.invalid/private?token=secret-canary", notes="notes-canary")
    first.set_custom_property("hidden", "custom-canary", protect=True)
    second = vault.add_entry(group, "Example", "Zoë@EXAMPLE.invalid", "other-password", url="https://example.invalid/other", force_creation=True)
    third = vault.add_entry(group, "Other", "owner@another.invalid", "third-password", url="https://another.invalid/")
    return Catalog.from_vault(vault), {str(first.uuid), str(second.uuid)}, str(third.uuid)


def test_search_is_scoped_and_excludes_secret_fields():
    catalog, duplicate_ids, third_id = sample_catalog()
    title = catalog.search("example", approved_ids=duplicate_ids, ref_factory=reference)
    assert {item["account_ref"] for item in title["items"]} == {reference(item_id) for item_id in duplicate_ids}
    assert all(item["origins"] == ["https://example.invalid"] for item in title["items"])
    assert {item["account_ref"] for item in catalog.search("zoë@example", approved_ids=duplicate_ids, ref_factory=reference)["items"]} == {reference(item_id) for item_id in duplicate_ids}
    assert {item["account_ref"] for item in catalog.search("another.invalid", approved_ids={third_id}, ref_factory=reference)["items"]} == {reference(third_id)}
    serialized = json.dumps(title)
    assert not any(item_id in serialized for item_id in duplicate_ids)
    for canary in ("password-canary", "secret-canary", "notes-canary", "custom-canary"):
        assert canary not in serialized


def test_cursor_scope_and_query_are_bound():
    catalog, duplicate_ids, _ = sample_catalog()
    first = catalog.search("example", approved_ids=duplicate_ids, ref_factory=reference, limit=1)
    assert len(first["items"]) == 1
    cursor = first["next_cursor"]
    assert cursor
    second = catalog.search("example", approved_ids=duplicate_ids, ref_factory=reference, limit=1, cursor=cursor)
    assert len(second["items"]) == 1
    assert second["items"][0]["account_ref"] != first["items"][0]["account_ref"]
    with pytest.raises(CatalogError) as wrong_scope:
        catalog.search("example", approved_ids=set(), ref_factory=reference, cursor=cursor)
    assert wrong_scope.value.code == "invalid_cursor"
    with pytest.raises(CatalogError) as wrong_query:
        catalog.search("other", approved_ids=duplicate_ids, ref_factory=reference, cursor=cursor)
    assert wrong_query.value.code == "invalid_cursor"


def test_limits_and_no_disclosure_scope():
    catalog, duplicate_ids, _ = sample_catalog()
    assert catalog.search("", approved_ids=set(), ref_factory=reference)["items"] == []
    with pytest.raises(CatalogError) as too_long:
        catalog.search("x" * 257, approved_ids=duplicate_ids, ref_factory=reference)
    assert too_long.value.code == "invalid_request"
    with pytest.raises(CatalogError) as too_large:
        catalog.search("example", approved_ids=duplicate_ids, ref_factory=reference, limit=51)
    assert too_large.value.code == "invalid_request"
