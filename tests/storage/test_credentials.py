import pytest

from vault_worker.credentials import resolve
from vault_worker.ingest import set_source
from vault_worker.profile import create_managed, load_managed
from vault_worker.store import VaultStoreError


@pytest.fixture
def selected():
    vault = load_managed(create_managed("synthetic-master"), "synthetic-master")
    entry = vault.add_entry(vault.root_group, "Synthetic", "owner", "synthetic-password-canary", url="https://example.invalid/login", otp="synthetic-totp-canary")
    vault.add_entry(vault.root_group, "Other", "other", "other-account-canary", url="https://example.invalid", force_creation=True)
    arguments = dict(entry_id=str(entry.uuid), expected_revision=1, origin="https://example.invalid", include_totp=False)
    return vault, entry, arguments


def test_only_selected_fields_and_explicit_totp_cross_private_channel(selected):
    vault, _, arguments = selected
    assert resolve(vault, **arguments) == {"username": "owner", "password": "synthetic-password-canary", "totp": None}
    assert resolve(vault, **(arguments | {"include_totp": True}))["totp"] == "synthetic-totp-canary"


@pytest.mark.parametrize("mutation", ["revision", "origin", "conflict", "archived", "recycle", "oversize"])
def test_private_resolution_rechecks_current_entry(selected, mutation):
    vault, entry, arguments = selected
    if mutation == "revision":
        entry.set_custom_property("shadow.revision", "2")
    elif mutation == "origin":
        entry.url = "https://other.invalid"
    elif mutation in {"conflict", "archived"}:
        set_source(entry, {"conflicted" if mutation == "conflict" else "archived": True})
    elif mutation == "recycle":
        vault.trash_entry(entry)
    else:
        entry.password = "a" * 65537
    with pytest.raises(VaultStoreError) as failure:
        resolve(vault, **arguments)
    assert failure.value.code == ("unsupported_credential" if mutation == "oversize" else "stale_credential")


def test_deleted_mirror_remains_resolvable_only_through_native_authority(selected):
    # Presence is not native authority. Retained use is approved outside this
    # module and bound to the independent restriction ledger by the supervisor.
    vault, entry, arguments = selected
    set_source(entry, {"presence": "deleted_at_source", "conflicted": False})
    assert resolve(vault, **arguments)["password"] == "synthetic-password-canary"
