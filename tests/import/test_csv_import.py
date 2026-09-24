import json

import pytest

from vault_worker.csv_import import CSVImportError, CSVMapping, SelectedCSV
from vault_worker.store import MemoryAnchor, VaultStore


MASTER = "synthetic-master-password"
MAPPING = CSVMapping(title="Title", url="URL", username="Username", password="Password", notes="Notes", group="Group")


def test_duplicate_titles_remain_distinct_with_protected_values(tmp_path):
    source = tmp_path / "duplicates.csv"
    source.write_text("Title,URL,Username,Password,Notes,TOTP\n" +
                      "Same,https://example.invalid,same,synthetic-one,synthetic-notes,JBSWY3DPEHPK3PXP\n" +
                      "Same,https://example.invalid,same,synthetic-two,synthetic-notes,JBSWY3DPEHPK3PXP\n")
    store = VaultStore(tmp_path / "private", MemoryAnchor())
    store.create(MASTER)
    mapping = CSVMapping("Title", "URL", "Username", "Password", notes="Notes", totp="TOTP")
    with SelectedCSV(source, mapping) as selected:
        selected.preview()
        assert selected.commit(store, MASTER, operation_id="duplicate-batch")["accepted"] == 2
        assert selected.commit(store, MASTER, operation_id="duplicate-batch")["replayed"]
    entries = store.open(MASTER).entries
    assert len(entries) == 2 and len({entry.uuid for entry in entries}) == 2
    assert {entry.password for entry in entries} == {"synthetic-one", "synthetic-two"}
    for entry in entries:
        assert entry.notes == "synthetic-notes" and entry.otp == "JBSWY3DPEHPK3PXP"
        for key in ("Password", "otp", "shadow.import.operation", "shadow.import.digest"):
            assert entry._element.find(f"String[Key='{key}']/Value").get("Protected") == "True"


def test_unicode_preview_fits_a_bounded_metadata_response(tmp_path):
    source = tmp_path / "unicode.csv"
    label = "🧪" * 256
    source.write_text("Title,URL,Username,Password,Notes,Group\n" + (f"{label},https://example.invalid,{label},synthetic-canary,,{label}\n" * 50))
    with SelectedCSV(source, MAPPING) as selected:
        preview = selected.preview().public()
    assert preview["accepted"] == 50
    assert 0 < len(preview["rows"]) < 50
    assert len(json.dumps(preview, ensure_ascii=False).encode()) < 64 * 1024


def test_oversized_unicode_headers_are_rejected_before_owner_display(tmp_path):
    source = tmp_path / "headers.csv"
    source.write_text(",".join("🧪" * 250 + str(index) for index in range(128)) + "\n")
    with SelectedCSV(source, MAPPING) as selected, pytest.raises(CSVImportError):
        selected.headers()


def test_bom_multiline_unicode_and_idempotent_commit(tmp_path):
    source = tmp_path / "synthetic.csv"
    source.write_bytes(("\ufeffTitle,URL,Username,Password,Notes,Group,Unused\r\n"
                        '"Ex, ample",https://example.invalid/private?token=hidden,Zoë,"synthetic,password",'
                        '"line 1\nline 2",Personal,unmapped-canary\r\n'
                        'Formula,https://another.invalid/,owner,=NOT_EVALUATED,notes-canary,,x\r\n').encode())
    store = VaultStore(tmp_path / "private", MemoryAnchor())
    store.create(MASTER)

    with SelectedCSV(source, MAPPING) as selected:
        preview = selected.preview()
        assert preview.accepted == 2
        assert preview.rejected == 0
        assert preview.rows[0]["title"] == "Ex, ample"
        public = json.dumps(preview.public())
        for canary in ("synthetic,password", "line 1", "unmapped-canary", "notes-canary", "hidden"):
            assert canary not in public
        receipt = selected.commit(store, MASTER, operation_id="synthetic-batch-1")
        assert receipt == {"accepted": 2, "rejected": 0, "replayed": False}
        replay = selected.commit(store, MASTER, operation_id="synthetic-batch-1")
        assert replay["replayed"] is True

    vault = store.open(MASTER)
    assert len(vault.entries) == 2
    first = vault.find_entries(title="Ex, ample", first=True)
    assert first.password == "synthetic,password"
    assert first.notes == "line 1\nline 2"
    assert vault.find_entries(title="Formula", first=True).password == "=NOT_EVALUATED"


def test_invalid_row_aborts_unless_owner_selects_valid_only(tmp_path):
    source = tmp_path / "synthetic.csv"
    source.write_text("Title,URL,Username,Password\nGood,https://example.invalid,owner,synthetic-secret\nBad,not a url,owner,other-secret\n")
    store = VaultStore(tmp_path / "private", MemoryAnchor())
    store.create(MASTER)
    mapping = CSVMapping(title="Title", url="URL", username="Username", password="Password")
    with SelectedCSV(source, mapping) as selected:
        preview = selected.preview()
        assert (preview.accepted, preview.rejected) == (1, 1)
        with pytest.raises(CSVImportError) as abort:
            selected.commit(store, MASTER, operation_id="batch")
        assert abort.value.code == "invalid_rows"
        assert not store.open(MASTER).entries
        receipt = selected.commit(store, MASTER, operation_id="batch", valid_rows_only=True)
        assert receipt == {"accepted": 1, "rejected": 1, "replayed": False}
        assert len(store.open(MASTER).entries) == 1


def test_symlink_and_changed_file_are_rejected(tmp_path):
    source = tmp_path / "source.csv"
    source.write_text("Title,URL,Username,Password\nGood,https://example.invalid,owner,synthetic-secret\n")
    link = tmp_path / "link.csv"
    link.symlink_to(source)
    mapping = CSVMapping(title="Title", url="URL", username="Username", password="Password")
    with pytest.raises(CSVImportError) as symlink:
        SelectedCSV(link, mapping)
    assert symlink.value.code == "unsafe_source"
    store = VaultStore(tmp_path / "private", MemoryAnchor())
    store.create(MASTER)
    with SelectedCSV(source, mapping) as selected:
        selected.preview()
        source.write_text(source.read_text() + "Changed,https://example.invalid,other,new-secret\n")
        with pytest.raises(CSVImportError) as changed:
            selected.commit(store, MASTER, operation_id="batch")
        assert changed.value.code == "source_changed"
    assert not store.open(MASTER).entries


def test_secret_header_cannot_also_be_public_title(tmp_path):
    source = tmp_path / "synthetic.csv"
    source.write_text("Title,URL,Username,Password\nGood,https://example.invalid,owner,synthetic-secret\n")
    mapping = CSVMapping(title="Password", url="URL", username="Username", password="Password")
    with SelectedCSV(source, mapping) as selected:
        with pytest.raises(CSVImportError) as invalid:
            selected.preview()
    assert invalid.value.code == "invalid_mapping"
