import io
import json
import subprocess
import sys
import uuid

from agent_tools.mcp_server import MCPServer, main
from agent_tools.protocol import OPERATIONS, encode


def initialization():
    return {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "synthetic", "version": "1"}}}


def test_stdio_lifecycle_and_tool_schemas_do_not_depend_on_vault_data():
    messages = [initialization(), {"jsonrpc": "2.0", "method": "notifications/initialized"}, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": {"progressToken": 2}}}, {"jsonrpc": "2.0", "id": 3, "method": "ping"}]
    output = io.BytesIO()
    assert main(io.BytesIO(b"\n".join(encode(value) for value in messages) + b"\n"), output) == 0
    replies = [json.loads(line) for line in output.getvalue().splitlines()]
    assert len(replies) == 3
    tools = replies[1]["result"]["tools"]
    assert len(tools) == len(OPERATIONS)
    for tool in tools:
        operation = tool["name"].removeprefix("shadow_").replace("_", ".", 1)
        assert tool["inputSchema"]["properties"]["arguments"] == OPERATIONS[operation]


def test_malformed_mcp_inputs_return_fixed_errors_without_echo():
    server = MCPServer()
    before_init = server.handle(encode({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    assert before_init["error"]["message"] == "invalid_request"
    server.handle(encode(initialization()))
    server.handle(encode({"jsonrpc": "2.0", "method": "notifications/initialized"}))
    attack = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "shadow_access_request", "arguments": {"request_id": str(uuid.uuid4()), "arguments": {"kind": "catalog", "password": "synthetic-mcp-canary"}}}}
    response = server.handle(encode(attack))
    assert response["result"]["isError"]
    assert "synthetic-mcp-canary" not in json.dumps(response)
    assert main(io.BytesIO(b"x" * 65537), io.BytesIO()) == 1


def test_real_cli_and_mcp_processes_emit_no_debug_stderr():
    cli = subprocess.run([sys.executable, "-m", "agent_tools.cli", "vault.status", "--invalid=synthetic-stderr-canary"], capture_output=True, timeout=5)
    assert cli.returncode == 1 and cli.stderr == b""
    assert json.loads(cli.stdout) == {"error": {"code": "invalid_request"}}
    messages = [initialization(), {"jsonrpc": "2.0", "method": "notifications/initialized"}, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    mcp = subprocess.run([sys.executable, "-m", "agent_tools.mcp_server"], input=b"\n".join(encode(value) for value in messages) + b"\n", capture_output=True, timeout=5)
    assert mcp.returncode == 0 and mcp.stderr == b""
    assert len(mcp.stdout.splitlines()) == 2
