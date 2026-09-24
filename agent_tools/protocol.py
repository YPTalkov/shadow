"""Pinned schema and bounded JSON shared by every guest frontend."""

from importlib.resources import files
import json
import re
import uuid

MAX_FRAME = 65_536
SCHEMA = json.loads(files("agent_tools").joinpath("agent-api-v1.schema.json").read_text())
RESPONSE_SCHEMA = json.loads(files("agent_tools").joinpath("agent-result-v1.schema.json").read_text())
OPERATIONS = {choice["properties"]["operation"]["const"]: choice["properties"]["arguments"] for choice in SCHEMA["oneOf"]}
ERROR_CODES = frozenset({
    "invalid_request", "unsupported_version", "rate_limited", "invalid_cursor", "invalid_reference",
    "capability_unavailable", "response_limit", "unavailable", "account_consent_required",
    "vault_locked", "caller_unavailable", "catalog_consent_required", "unsupported_adapter",
    "stale_request", "invalid_scope", "request_conflict", "transport_unavailable",
})


class AgentError(Exception):
    def __init__(self, code: str):
        self.code = code if isinstance(code, str) and code in ERROR_CODES else "unavailable"
        super().__init__(self.code)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AgentError("invalid_request")
        result[key] = value
    return result


def _number(value):
    raise AgentError("invalid_request")


def decode(data: bytes, *, maximum=MAX_FRAME, depth_limit=8):
    if not isinstance(data, bytes) or not 0 < len(data) <= maximum:
        raise AgentError("invalid_request")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique, parse_float=_number, parse_constant=_number)
        pending = [(value, 0)]
        nodes = 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            if depth > depth_limit or nodes > 4096:
                raise AgentError("invalid_request")
            if isinstance(item, str):
                if len(item.encode("utf-8")) > 16_384:
                    raise AgentError("invalid_request")
            elif type(item) is int and not -(2**63) <= item < 2**63:
                raise AgentError("invalid_request")
            elif isinstance(item, dict):
                pending.extend((key, depth + 1) for key in item)
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise AgentError("invalid_request") from None


def encode(value) -> bytes:
    try:
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        if len(data) > MAX_FRAME:
            raise AgentError("response_limit")
        return data
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise AgentError("invalid_request") from None


def accepts(value, schema) -> bool:
    if "const" in schema and (type(value) is not type(schema["const"]) or value != schema["const"]):
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    if "oneOf" in schema and sum(accepts(value, child) for child in schema["oneOf"]) != 1:
        return False
    expected = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool, "null": type(None)}
    if "type" in schema and type(value) is not expected[schema["type"]]:
        return False
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and not set(value).issubset(properties):
            return False
        if not set(schema.get("required", [])).issubset(value):
            return False
        if any(not accepts(value[key], rule) for key, rule in properties.items() if key in value):
            return False
    if isinstance(value, list):
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", MAX_FRAME):
            return False
        if schema.get("uniqueItems") and any(value[index] in value[:index] for index in range(len(value))):
            return False
        if "items" in schema and any(not accepts(item, schema["items"]) for item in value):
            return False
    if isinstance(value, str):
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", MAX_FRAME):
            return False
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            return False
        if schema.get("format") == "uuid":
            try:
                if str(uuid.UUID(value)) != value:
                    return False
            except ValueError:
                return False
    if type(value) is int and not schema.get("minimum", -(2**63)) <= value <= schema.get("maximum", 2**63 - 1):
        return False
    return True


def request(operation: str, arguments: dict, request_id: str | None = None) -> dict:
    value = {"protocol_major": 1, "request_id": request_id or str(uuid.uuid4()), "operation": operation, "arguments": arguments}
    if not accepts(value, SCHEMA):
        raise AgentError("invalid_request")
    return decode(encode(value))
