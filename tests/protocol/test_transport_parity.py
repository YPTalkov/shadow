import io
import json
import uuid

import pytest

from agent_tools import cli
from agent_tools.mcp_server import MCPServer
from agent_tools.protocol import AgentError, encode
from agent_tools.ptc import Shadow


class Frontend:
    def __init__(self, kind, transport):
        self.kind = kind
        self.client = Shadow(transport)
        self.server = MCPServer(self.client)
        self.number = 0
        initialized = self.server.handle(encode({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "synthetic", "version": "1"}}}))
        assert initialized["result"]["protocolVersion"] == "2025-06-18"
        assert self.server.handle(encode({"jsonrpc": "2.0", "method": "notifications/initialized"})) is None

    def call(self, operation, arguments=None, request_id=None):
        arguments = {} if arguments is None else arguments
        request_id = request_id or str(uuid.uuid4())
        if self.kind == "ptc":
            return self.client.call(operation, arguments, request_id=request_id)
        if self.kind == "cli":
            output = io.BytesIO()
            status = cli.main([operation, "--arguments", json.dumps(arguments), "--request-id", request_id], client=self.client, stdout=output)
            value = json.loads(output.getvalue())
            if status:
                raise AgentError(value["error"]["code"])
            return value["result"]
        self.number += 1
        value = self.server.handle(encode({"jsonrpc": "2.0", "id": self.number, "method": "tools/call", "params": {"name": "shadow_" + operation.replace(".", "_"), "arguments": {"request_id": request_id, "arguments": arguments}}}))
        result = value["result"]
        content = json.loads(result["content"][0]["text"])
        if result["isError"]:
            raise AgentError(content["error"]["code"])
        return content


@pytest.mark.parametrize("kind", ["cli", "mcp", "ptc"])
def test_native_discovery_and_separate_use_consent_across_frontends(native, kind):
    frontend = Frontend(kind, native)
    assert frontend.call("vault.status")["state"] == "catalog_consent_required"
    with pytest.raises(AgentError, match="catalog_consent_required"):
        frontend.call("catalog.search")
    request_id = str(uuid.uuid4())
    consent = frontend.call("access.request", {"kind": "catalog"}, request_id)
    assert consent["state"] == "pending_owner"
    approved = frontend.call("operation.get", {"operation_ref": consent["operation_ref"]})
    assert approved["state"] == "granted"
    assert frontend.call("access.request", {"kind": "catalog"}, request_id) == approved
    page = frontend.call("catalog.search", {"query": "Synthetic", "limit": 50})
    assert 0 < len(page["items"]) <= 50
    items = page["items"][:]
    while page["next_cursor"]:
        page = frontend.call("catalog.search", {"query": "Synthetic", "cursor": page["next_cursor"]})
        items.extend(page["items"])
    assert len(items) == 55
    account = items[0]["account_ref"]
    assert len(account) == 64 and "id" not in items[0]
    with pytest.raises(AgentError, match="account_consent_required"):
        frontend.call("auth.login", {"account_ref": account, "grant_ref": approved["grant_ref"], "adapter_id": "synthetic-v1"})
    use = frontend.call("access.request", {"kind": "account_use", "account_ref": account, "adapter_id": "synthetic-v1", "actions": ["login"]})
    granted = frontend.call("operation.get", {"operation_ref": use["operation_ref"]})
    assert granted["state"] == "granted"
    # Browser qualification is connected in U9; permission cannot invent it.
    with pytest.raises(AgentError, match="capability_unavailable"):
        frontend.call("auth.login", {"account_ref": account, "grant_ref": granted["grant_ref"], "adapter_id": "synthetic-v1"})
    assert b"Undisclosed canary" not in b"".join(native.captured)


@pytest.mark.parametrize("kind", ["cli", "mcp", "ptc"])
def test_denied_native_consent_cannot_be_bypassed(denied_native, kind):
    frontend = Frontend(kind, denied_native)
    pending = frontend.call("access.request", {"kind": "catalog"})
    assert frontend.call("operation.get", {"operation_ref": pending["operation_ref"]})["state"] == "denied"
    with pytest.raises(AgentError, match="catalog_consent_required"):
        frontend.call("catalog.search")
    with pytest.raises(AgentError, match="invalid_request"):
        frontend.call("access.request", {"kind": "catalog", "approve": True})


@pytest.mark.parametrize("kind", ["cli", "mcp", "ptc"])
def test_safe_views_have_identical_transport_projection(kind):
    view = {"view_id": "items", "document_ref": "a" * 64, "records": [{"fields": [{"name": "title", "value": "Example report"}], "actions": [{"id": "open", "element_ref": "b" * 64}]}]}

    def transport(data):
        request = json.loads(data)
        return encode({"protocol_major": 1, "request_id": request["request_id"], "result": view})

    frontend = Frontend(kind, transport)
    assert frontend.call("browser.observe", {"session_ref": "c" * 64, "view_id": "items"}) == view
    view["records"][0]["cookie"] = "synthetic-cookie-canary"
    with pytest.raises(AgentError):
        frontend.call("browser.observe", {"session_ref": "c" * 64, "view_id": "items"})
