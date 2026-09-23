"""Bounded parsing adapters around the pinned library's KDBX4 crypto pipeline.

No global monkey patches. Encryption, KDF, and HMAC remain PyKeePass 4.2.0's
implementation; only decompression, XML input, and feature admission change.
"""

from __future__ import annotations

import base64
import io
import struct
import zlib

from construct import Adapter, GreedyBytes, If, IfThenElse, Struct, Switch, this
from lxml import etree
from pykeepass.kdbx_parsing import KDBX
from pykeepass.kdbx_parsing import common, kdbx4

MAX_PAYLOAD = 64 * 1024 * 1024
MAX_XML_NODES = 2_000_000
MAX_FIELD = 128 * 1024  # Allows base64 of the importer's 64 KiB fields.


class BoundedKDBXError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def header_fields(data: bytes, offset: int, allowed: set[int], *, maximum: int) -> dict[int, bytes]:
    fields: dict[int, bytes] = {}
    start = offset
    while offset + 5 <= len(data) and offset - start <= maximum:
        kind, length = struct.unpack_from("<BI", data, offset)
        offset += 5
        if kind not in allowed or kind in fields:
            raise BoundedKDBXError("unsupported_profile")
        if length > maximum or offset + length > len(data) or offset + length - start > maximum:
            raise BoundedKDBXError("invalid_vault")
        fields[kind] = data[offset:offset + length]
        offset += length
        if kind == 0:
            return fields
    raise BoundedKDBXError("invalid_vault")


def validate_outer_header(data: bytes) -> None:
    if len(data) < 12 or data[:8] != b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5":
        raise BoundedKDBXError("invalid_vault")
    if data[8:12] != b"\x00\x00\x04\x00":
        raise BoundedKDBXError("unsupported_profile")
    fields = header_fields(data, 12, {0, 1, 2, 3, 4, 7, 11}, maximum=65536)
    if not {0, 2, 3, 4, 7, 11}.issubset(fields) or fields[0] != b"\r\n\r\n":
        raise BoundedKDBXError("invalid_vault")
    if fields[3] not in (b"\x00\x00\x00\x00", b"\x01\x00\x00\x00") or len(fields[4]) != 32 or len(fields[7]) != 16:
        raise BoundedKDBXError("unsupported_profile")
    variant = fields[11]
    if variant[:2] != b"\x00\x01":
        raise BoundedKDBXError("unsupported_profile")
    offset, names = 2, set()
    while offset < len(variant) and variant[offset] != 0:
        kind = variant[offset]
        offset += 1
        if offset + 4 > len(variant):
            raise BoundedKDBXError("invalid_vault")
        length = struct.unpack_from("<I", variant, offset)[0]
        offset += 4
        name = variant[offset:offset + length]
        offset += length
        if name in names or name not in {b"$UUID", b"V", b"I", b"M", b"P", b"S"} or kind not in {4, 5, 0x42}:
            raise BoundedKDBXError("unsupported_profile")
        names.add(name)
        if offset + 4 > len(variant):
            raise BoundedKDBXError("invalid_vault")
        length = struct.unpack_from("<I", variant, offset)[0]
        offset += 4 + length
    if offset != len(variant) - 1 or variant[offset:] != b"\0" or names != {b"$UUID", b"V", b"I", b"M", b"P", b"S"}:
        raise BoundedKDBXError("invalid_vault")


class BoundedDecompressed(common.Decompressed):
    def _decode(self, data, con, path):
        decoder = zlib.decompressobj(31)
        output = decoder.decompress(data, MAX_PAYLOAD + 1)
        if len(output) > MAX_PAYLOAD or decoder.unconsumed_tail:
            raise BoundedKDBXError("limit_exceeded")
        if not decoder.eof or decoder.unused_data:
            raise BoundedKDBXError("invalid_vault")
        return output


# Standard KDBX XML fields, with binary attachments and custom icon data excluded
# until qualified. See KeePassLib/Serialization/KdbxFile.cs, XML element constants.
XML_TAGS = frozenset("""
KeePassFile Meta Root Group Entry Generator HeaderHash SettingsChanged
DatabaseName DatabaseNameChanged DatabaseDescription DatabaseDescriptionChanged
DefaultUserName DefaultUserNameChanged MaintenanceHistoryDays Color MasterKeyChanged
MasterKeyChangeRec MasterKeyChangeForce MasterKeyChangeForceOnce RecycleBinEnabled
RecycleBinUUID RecycleBinChanged EntryTemplatesGroup EntryTemplatesGroupChanged
HistoryMaxItems HistoryMaxSize LastSelectedGroup LastTopVisibleGroup MemoryProtection
ProtectTitle ProtectUserName ProtectPassword ProtectURL ProtectNotes CustomIcons
AutoType History Name Notes UUID IconID ForegroundColor BackgroundColor OverrideURL
QualityCheck Times Tags CreationTime LastModificationTime LastAccessTime ExpiryTime
Expires UsageCount LocationChanged DefaultAutoTypeSequence EnableAutoType
EnableSearching String Key Value Enabled DataTransferObfuscation DefaultSequence
Association Window KeystrokeSequence IsExpanded LastTopVisibleEntry DeletedObjects
DeletedObject DeletionTime CustomData Item Binaries
""".split())


class BoundedXML(common.XML):
    def _decode(self, data, con, path):
        if len(data) > MAX_PAYLOAD:
            raise BoundedKDBXError("limit_exceeded")
        # Refuse alternate encodings and declarations before libxml sees them.
        text = data.decode("utf-8-sig", errors="strict")
        if "<!DOCTYPE" in text or "<!ENTITY" in text or "\x00" in text:
            raise BoundedKDBXError("unsupported_profile")
        parser = etree.XMLParser(remove_blank_text=True, resolve_entities=False, load_dtd=False, no_network=True, huge_tree=False)
        tree = etree.parse(io.BytesIO(data), parser)
        if tree.docinfo.doctype or tree.getroot().tag != "KeePassFile":
            raise BoundedKDBXError("unsupported_profile")
        entries = 0
        for count, element in enumerate(tree.iter(), start=1):
            if count > MAX_XML_NODES or len(element.text or "") > MAX_FIELD:
                raise BoundedKDBXError("limit_exceeded")
            if element.tag not in XML_TAGS or any(key != "Protected" for key in element.attrib):
                raise BoundedKDBXError("unsupported_profile")
            if element.attrib.get("Protected", "False") not in {"True", "False"}:
                raise BoundedKDBXError("invalid_vault")
            if element.tag == "Entry":
                entries += 1
                if entries > 100_000:  # Includes entry history.
                    raise BoundedKDBXError("limit_exceeded")
        return tree


class StrictUnprotect:
    def _decode(self, tree, con, path):
        cipher = self.get_cipher(self.protected_stream_key(con))
        for element in tree.xpath(self.protected_xpath):
            if element.text is not None:
                element.text = cipher.decrypt(base64.b64decode(element.text, validate=True)).decode("utf-8", errors="strict")
        return tree


class StrictSalsa20(StrictUnprotect, common.Salsa20Stream):
    pass


class StrictChaCha20(StrictUnprotect, common.ChaCha20Stream):
    pass


Inner = Struct(
    "inner_header" / kdbx4.InnerHeader,
    "xml" / Switch(this.inner_header.protected_stream_id.data, {
        "salsa20": StrictSalsa20(this.inner_header.protected_stream_key.data, BoundedXML(GreedyBytes)),
        "chacha20": StrictChaCha20(this.inner_header.protected_stream_key.data, BoundedXML(GreedyBytes)),
    }),
)


class BoundedPayload(Adapter):
    def _decode(self, data, con, path):
        if len(data) > MAX_PAYLOAD:
            raise BoundedKDBXError("limit_exceeded")
        fields = header_fields(data, 0, {0, 1, 2}, maximum=1024)
        if set(fields) != {0, 1, 2} or fields[0] or fields[1] not in (b"\x02\0\0\0", b"\x03\0\0\0") or len(fields[2]) not in {32, 64}:
            raise BoundedKDBXError("unsupported_profile")
        return Inner.parse(data, **con)


BoundedBody = Struct(
    *kdbx4.Body.subcons[:-1],
    "payload" / If(this._._.decrypt, BoundedPayload(IfThenElse(
        this._.header.value.dynamic_header.compression_flags.data.compression,
        BoundedDecompressed(kdbx4.DecryptedPayload), kdbx4.DecryptedPayload,
    ))),
)
BOUNDED_KDBX = Struct(KDBX.header, "body" / BoundedBody)
