import json
from pathlib import Path
import subprocess
import uuid

import pytest

from agent_tools.protocol import AgentError, SCHEMA, accepts, decode, encode, request
from agent_tools.client import ShadowClient


def test_embedded_contracts_match_the_authoritative_schema():
    root = Path(__file__).resolve().parents[2]
    subprocess.run(["python3", str(root / "scripts/sync-agent-contract.py"), "--check"], check=True)


@pytest.mark.parametrize("arguments", [
    {"limit": True}, {"limit": 51}, {"query": "a" * 257}, {"query": "🧪" * 257},
    {"cursor": "a" * 63}, {"cursor": "A" * 64}, {"password": "synthetic-error-canary"},
    {"query": {"script": "synthetic-error-canary"}},
])
def test_guest_and_native_reject_the_same_invalid_arguments(native, arguments):
    value = {"protocol_major": 1, "request_id": str(uuid.uuid4()), "operation": "catalog.search", "arguments": arguments}
    assert not accepts(value, SCHEMA)
    response = decode(native(encode(value)))
    assert response["error"]["code"] == "invalid_request"
    assert "synthetic-error-canary" not in json.dumps(response)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":1.0}', b'{"x":NaN}', b'{"x":"\\ud800"}', b'{"x":01}', b'{}{}', b'[' * 20 + b'0' + b']' * 20])
def test_bounded_json_rejects_ambiguous_encodings(raw, native):
    with pytest.raises(AgentError):
        decode(raw)
    response = decode(native(raw))
    assert response["error"]["code"] == "invalid_request"


def test_argument_variants_cannot_add_owner_or_browser_escape_hatches(native):
    cases = [
        ("access.request", {"kind": "catalog", "approve": True}),
        ("browser.navigate", {"session_ref": "a" * 64, "url": "https://example.invalid"}),
        ("browser.click", {"session_ref": "a" * 64, "selector": "input[type=password]"}),
        ("vault.secret", {"path": "/synthetic/canary"}),
        ("browser.observe", {"session_ref": "a" * 64, "view_id": "safe\n"}),
    ]
    for operation, arguments in cases:
        with pytest.raises(AgentError):
            request(operation, arguments)
        value = {"protocol_major": 1, "request_id": str(uuid.uuid4()), "operation": operation, "arguments": arguments}
        assert decode(native(encode(value)))["error"]["code"] == "invalid_request"


@pytest.mark.parametrize("payload", [
    {"result": {"password": "synthetic-response-canary"}},
    {"result": {"state": "ready", "capabilities": [], "debug": "synthetic-response-canary"}},
    {"error": {"code": "synthetic-response-canary"}},
])
def test_clients_reject_response_fields_outside_the_result_contract(payload):
    def malicious(data):
        return encode({"protocol_major": 1, "request_id": decode(data)["request_id"], **payload})
    with pytest.raises(AgentError, match="^unavailable$"):
        ShadowClient(malicious).call("vault.status")
