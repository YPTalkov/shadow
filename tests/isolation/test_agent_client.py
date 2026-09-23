"""Actual client protocol qualification with synthetic SSE and a harmless tool."""

import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


@pytest.mark.skipif(
    os.environ.get("SHADOW_CODEX_INTEGRATION") != "1",
    reason="Opt in to the installed Codex CLI protocol probe",
)
def test_codex_responses_stream_and_tool_result(tmp_path):
    executable = shutil.which("codex")
    assert executable, "The pinned Codex CLI must be installed"
    requests = []
    failures = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
            requests.append((self.path, dict(self.headers), body))
            tools = {t.get("name") for t in body.get("tools", [])}
            if len(requests) == 1:
                name = "exec_command" if "exec_command" in tools else "shell_command"
                if name not in tools:
                    failures.append("expected_shell_tool_missing")
                arguments = {"cmd": "printf shadow-tool-ok"} if name == "exec_command" else {"command": "printf shadow-tool-ok"}
                item = {
                    "type": "function_call", "id": "fc_synthetic",
                    "call_id": "call_synthetic", "name": name,
                    "arguments": json.dumps(arguments), "status": "completed",
                }
            else:
                item = {
                    "type": "message", "id": "msg_synthetic", "role": "assistant",
                    "status": "completed",
                    "content": [{"type": "output_text", "text": "shadow-client-ok", "annotations": []}],
                }
            response = {
                "id": f"resp_synthetic_{len(requests)}", "object": "response",
                "status": "completed", "output": [item],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            }
            events = [
                {"type": "response.created", "response": {**response, "status": "in_progress", "output": []}},
                {"type": "response.output_item.added", "output_index": 0, "item": item},
                {"type": "response.output_item.done", "output_index": 0, "item": item},
                {"type": "response.completed", "response": response},
            ]
            payload = "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = {
            "model": '"synthetic-model"',
            "model_provider": '"shadow"',
            "model_providers.shadow.name": '"Shadow synthetic relay"',
            "model_providers.shadow.base_url": f'"http://127.0.0.1:{server.server_port}/v1"',
            "model_providers.shadow.wire_api": '"responses"',
            "model_providers.shadow.requires_openai_auth": "false",
            "model_providers.shadow.supports_websockets": "false",
            "cli_auth_credentials_store": '"ephemeral"',
            "features.shell_snapshot": "false",
            "features.use_linux_sandbox_bwrap": "false",
        }
        command = [
            executable, "exec", "--ignore-user-config", "--ignore-rules",
            "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only",
            "--json", "-C", str(tmp_path),
        ]
        for key, value in config.items():
            command.extend(["-c", f"{key}={value}"])
        command.append("Run printf shadow-tool-ok once, then say shadow-client-ok.")
        result = subprocess.run(
            command, capture_output=True, timeout=45,
            env={"PATH": os.environ["PATH"], "LANG": "en_US.UTF-8"},
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    # Avoid printing provider inputs or raw diagnostics on assertion failures.
    assert result.returncode == 0, "Codex client exited unsuccessfully"
    assert not failures, "Codex tool contract changed"
    assert len(requests) == 2, "Expected a streamed tool call and tool result round trip"
    assert all(path == "/v1/responses" for path, _, _ in requests)
    assert all("authorization" not in {k.lower() for k in headers} for _, headers, _ in requests)
    assert any(
        item.get("type") == "function_call_output" and "shadow-tool-ok" in str(item.get("output"))
        for item in requests[1][2]["input"]
    ), "The executed tool output must reach the provider"
    assert b"shadow-client-ok" in result.stdout
