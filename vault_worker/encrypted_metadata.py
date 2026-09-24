"""Small JSON records inside encrypted KDBX custom data."""

import json
from lxml import etree


def get(element, key: str, default=None):
    data = element.find("CustomData")
    if data is None:
        return default
    matches = [item for item in data.findall("Item") if item.findtext("Key") == key]
    if not matches:
        return default
    if len(matches) != 1:
        raise ValueError("invalid_metadata")
    return json.loads(matches[0].findtext("Value") or "null")


def put(element, key: str, value) -> None:
    data = element.find("CustomData")
    if data is None:
        data = etree.SubElement(element, "CustomData")
    for item in list(data):
        if item.findtext("Key") == key:
            data.remove(item)
    item = etree.SubElement(data, "Item")
    etree.SubElement(item, "Key").text = key
    etree.SubElement(item, "Value").text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def preserve_app_metadata(original, candidate) -> None:
    data = candidate.find("CustomData")
    if data is not None:
        for item in list(data):
            if (item.findtext("Key") or "").startswith("shadow."):
                data.remove(item)
    original_data = original.find("CustomData") if original is not None else None
    if original_data is not None:
        for item in original_data.findall("Item"):
            key = item.findtext("Key") or ""
            if key.startswith("shadow."):
                put(candidate, key, get(original, key))
