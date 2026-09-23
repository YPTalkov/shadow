import base64
import json
from urllib.parse import quote

from vault_worker.catalog import Catalog
from vault_worker.csv_import import CSVMapping, SelectedCSV
from vault_worker.profile import create_managed, load_managed
from vault_worker.secret_guard import SecretGuard, REDACTED


def test_cross_account_and_encoded_canaries_are_withheld():
    vault = load_managed(create_managed("synthetic-master"), "synthetic-master")
    first = vault.add_entry(vault.root_group, "Normal", "owner", "sensitive!password")
    first.set_custom_property("token", "sensitive-token", protect=True)
    encoded = base64.b64encode(b"sensitive-token").decode()
    vault.add_entry(vault.root_group, "prefix " + quote("sensitive!password", safe=""), encoded, "another-secret", url="https://sensitive-token.invalid")
    page = Catalog.from_vault(vault).owner_page(0)
    serialized = json.dumps(page)
    assert "sensitive" not in serialized and encoded not in serialized
    hidden = [item for item in page["items"] if item["title"] == REDACTED][0]
    assert hidden["username"] == REDACTED and hidden["origins"] == []


def test_protected_metadata_and_recycle_bin_are_not_disclosed():
    vault = load_managed(create_managed("synthetic-master"), "synthetic-master")
    protected = vault.add_entry(vault.root_group, "private-title" * 1000, "private-user", "synthetic-password", url="https://private-origin.invalid/path")
    for key in ("Title", "UserName", "URL"):
        protected._element.find(f"String[Key='{key}']/Value").set("Protected", "True")
    trashed = vault.add_entry(vault.root_group, "Deleted", "owner", "synthetic-deleted")
    vault.trash_entry(trashed)
    items = Catalog.from_vault(vault).owner_page(0)["items"]
    assert len(items) == 1
    assert items[0]["title"] == REDACTED and items[0]["username"] == REDACTED and not items[0]["origins"]


def test_csv_preview_withholds_a_secret_repeated_in_another_rows_metadata(tmp_path):
    path = tmp_path / "synthetic.csv"
    path.write_text("Title,URL,Username,Password\nFirst,https://example.invalid,owner,secret-canary\nsecret-canary,https://example.invalid,owner,another-secret\n")
    with SelectedCSV(path, CSVMapping("Title", "URL", "Username", "Password")) as selected:
        preview = selected.preview().public()
    assert preview["accepted"] == 2
    assert "secret-canary" not in json.dumps(preview)


def test_guard_budget_overflow_suppresses_metadata(monkeypatch):
    monkeypatch.setattr("vault_worker.secret_guard.MAX_STATES", 16)
    guard = SecretGuard(["large-synthetic-canary"])
    assert guard.suppress_all and guard.project("ordinary metadata") == REDACTED
    assert guard.project("") == ""


def test_failure_links_find_overlapping_patterns():
    guard = SecretGuard(["bc", "abcd", "xyab"])
    assert guard.project("zabc") == REDACTED
    assert guard.project("safe") == "safe"


def test_encrypted_source_metadata_remains_visible_but_incoming_secrets_do_not():
    vault = load_managed(create_managed("synthetic-master"), "synthetic-master")
    entry = vault.add_entry(vault.root_group, "Source account", "owner", "current-password-canary")
    entry.set_custom_property("shadow.baseline.title", "Source account", protect=True)
    entry.set_custom_property("shadow.baseline.username", "owner", protect=True)
    entry.set_custom_property("shadow.incoming.password", "incoming-password-canary", protect=True)
    vault.add_entry(vault.root_group, "incoming-password-canary", "other", "different-password")
    items = Catalog.from_vault(vault).owner_page(0)["items"]
    assert any(item["title"] == "Source account" and item["username"] == "owner" for item in items)
    assert "incoming-password-canary" not in json.dumps(items)
