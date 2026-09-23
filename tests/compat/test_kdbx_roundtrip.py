import io
import shutil
import subprocess

import pytest
from pykeepass import PyKeePass

from vault_worker.profile import ManagedKDBXError, create_managed, inspect_header, load_managed


MASTER = "synthetic-master-password"


def test_managed_profile_and_seed_rotation():
    original = create_managed(MASTER)
    header = inspect_header(original)
    assert header == {"version": (4, 0), "cipher": "aes256", "kdf": "argon2id", "memory": 128 * 1024 * 1024, "iterations": 3, "lanes": 2}

    vault = load_managed(original, MASTER)
    vault.add_entry(vault.root_group, "Synthetic", "owner@example.invalid", "synthetic-password")
    first_stream = io.BytesIO()
    vault.save(first_stream)
    first = first_stream.getvalue()
    second_stream = io.BytesIO()
    vault.save(second_stream)
    second = second_stream.getvalue()
    assert first != second
    assert load_managed(first, MASTER).find_entries(title="Synthetic", first=True).password == "synthetic-password"
    assert load_managed(second, MASTER).find_entries(title="Synthetic", first=True).password == "synthetic-password"


def test_wrong_password_and_corruption_return_fixed_codes():
    data = create_managed(MASTER)
    with pytest.raises(ManagedKDBXError) as wrong:
        load_managed(data, "wrong")
    assert wrong.value.code == "invalid_credentials"
    with pytest.raises(ManagedKDBXError) as corrupt:
        load_managed(data[:-50] + b"0" * 50, MASTER)
    assert corrupt.value.code == "invalid_vault"


def test_rejects_unmanaged_profile_before_decryption():
    from pykeepass import create_database

    buffer = io.BytesIO()
    create_database(buffer, password=MASTER)
    with pytest.raises(ManagedKDBXError) as unsupported:
        load_managed(buffer.getvalue(), MASTER)
    assert unsupported.value.code == "unsupported_profile"


def test_header_limits_precede_key_derivation():
    data = bytearray(create_managed(MASTER))
    # The header parser sees this as a hostile KDF request; no Argon2 call is allowed.
    header = PyKeePass(io.BytesIO(data), decrypt=False)
    header.kdbx.header.value.dynamic_header.kdf_parameters.data.dict["M"].value = 2 * 1024 * 1024 * 1024
    # The public inspector accepts parsed headers as well as raw bytes for this safety check.
    with pytest.raises(ManagedKDBXError) as excessive:
        inspect_header(header)
    assert excessive.value.code == "kdf_limit_exceeded"


@pytest.mark.skipif(shutil.which("keepassxc-cli") is None, reason="KeePassXC is not installed")
def test_keepassxc_edits_managed_database(tmp_path):
    path = tmp_path / "synthetic.kdbx"
    db = load_managed(create_managed(MASTER), MASTER)
    group = db.add_group(db.root_group, "Synthetic Group")
    entry = db.add_entry(group, "Before", "owner@example.invalid", "synthetic-password")
    entry.set_custom_property("shadow.fixture", "synthetic", protect=True)
    output = io.BytesIO()
    db.save(output)
    path.write_bytes(output.getvalue())

    edited = subprocess.run(
        ["keepassxc-cli", "edit", "-q", "-t", "After", str(path), "Synthetic Group/Before"],
        input=MASTER + "\n",
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert edited.returncode == 0, "KeePassXC edit failed"
    reopened = load_managed(path.read_bytes(), MASTER)
    updated = reopened.find_entries(title="After", first=True)
    assert updated is not None
    assert updated.group.name == "Synthetic Group"
    assert updated.password == "synthetic-password"
    assert updated.get_custom_property("shadow.fixture") == "synthetic"

    saved = io.BytesIO()
    reopened.save(saved)
    path.write_bytes(saved.getvalue())
    listed = subprocess.run(
        ["keepassxc-cli", "ls", "-q", "-R", str(path)],
        input=MASTER + "\n",
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert listed.returncode == 0, "KeePassXC reopen failed"
    assert "After" in listed.stdout
