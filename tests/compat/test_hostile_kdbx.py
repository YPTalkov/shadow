import io
import struct
import zlib

import pytest
from lxml import etree

from vault_worker import bounded_kdbx
from vault_worker.profile import ManagedKDBXError, create_managed, inspect_header, load_managed

MASTER = "synthetic-master-password"


def saved(db):
    stream = io.BytesIO()
    db.save(stream)
    return stream.getvalue()


def test_raw_header_never_invokes_key_derivation(monkeypatch):
    data = create_managed(MASTER)
    def forbidden(**kwargs):
        raise AssertionError("header inspection must not derive keys")
    monkeypatch.setattr("argon2.low_level.hash_secret_raw", forbidden)
    assert inspect_header(data)["memory"] == 128 * 1024 * 1024
    # Mutate the raw Argon2 memory parameter; HMAC need not be valid because the
    # resource limit must run before cryptographic processing of hostile input.
    needle = b"\x05\x01\x00\x00\x00M\x08\x00\x00\x00" + struct.pack("<Q", 128 * 1024 * 1024)
    assert data.count(needle) == 1
    hostile = data.replace(needle, needle[:-8] + struct.pack("<Q", 2**40))
    with pytest.raises(ManagedKDBXError, match="kdf_limit_exceeded"):
        load_managed(hostile, MASTER)


def test_duplicate_or_unknown_outer_fields_are_refused():
    data = create_managed(MASTER)
    kind, length = struct.unpack_from("<BI", data, 12)
    duplicated = data[:12] + data[12:17 + length] + data[12:]
    with pytest.raises(ManagedKDBXError, match="unsupported_profile"):
        inspect_header(duplicated)
    unknown = data[:12] + struct.pack("<BI", 12, 1) + b"x" + data[12:]
    with pytest.raises(ManagedKDBXError, match="unsupported_profile"):
        inspect_header(unknown)


def test_encrypted_compression_bomb_is_bounded(monkeypatch):
    db = load_managed(create_managed(MASTER), MASTER)
    db.add_entry(db.root_group, "Synthetic", "owner", "synthetic", notes="x" * 100_000)
    data = saved(db)
    monkeypatch.setattr(bounded_kdbx, "MAX_PAYLOAD", 16_384)
    with pytest.raises(ManagedKDBXError, match="limit_exceeded"):
        load_managed(data, MASTER)


def test_encrypted_doctype_is_refused_without_resolving_entities():
    db = load_managed(create_managed(MASTER), MASTER)
    xml = etree.tostring(db.tree).replace(b"<Generator>PyKeePass</Generator>", b"<Generator>&probe;</Generator>")
    xml = b'<!DOCTYPE KeePassFile [<!ENTITY probe SYSTEM "file:///nonexistent-shadow-synthetic">]>' + xml
    db.kdbx.body.payload.xml = etree.parse(io.BytesIO(xml), etree.XMLParser(resolve_entities=False, no_network=True))
    with pytest.raises(ManagedKDBXError, match="unsupported_profile"):
        load_managed(saved(db), MASTER)


@pytest.mark.parametrize("feature", ["attachment", "extension", "duplicate_uuid"])
def test_unsupported_content_and_duplicate_identity_are_refused(feature):
    db = load_managed(create_managed(MASTER), MASTER)
    entry = db.add_entry(db.root_group, "Synthetic", "owner", "synthetic")
    if feature == "attachment":
        entry.add_attachment(db.add_binary(b"synthetic attachment"), "synthetic.txt")
    elif feature == "extension":
        etree.SubElement(entry._element, "UnqualifiedExtension").text = "synthetic"
    else:
        second = db.add_entry(db.root_group, "Second", "owner", "synthetic")
        second.uuid = entry.uuid
    with pytest.raises(ManagedKDBXError) as error:
        load_managed(saved(db), MASTER)
    assert error.value.code == ("invalid_vault" if feature == "duplicate_uuid" else "unsupported_profile")


def test_gzip_trailing_data_and_xml_entities_are_refused():
    compressor = zlib.compressobj(wbits=31)
    compressed = compressor.compress(b"synthetic") + compressor.flush()
    decoder = bounded_kdbx.BoundedDecompressed(bounded_kdbx.GreedyBytes)
    with pytest.raises(bounded_kdbx.BoundedKDBXError, match="invalid_vault"):
        decoder._decode(compressed + b"trailing", None, None)

