import json
import os
import subprocess
import threading
from guest_transport.model_bridge import ModelBridge

server = ModelBridge()
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
os.makedirs("/work", exist_ok=True)
config = {
    "model": '"synthetic-model"',
    "model_provider": '"shadow"',
    "model_providers.shadow.name": '"Shadow"',
    "model_providers.shadow.base_url": f'"http://127.0.0.1:{server.server_port}/v1"',
    "model_providers.shadow.wire_api": '"responses"',
    "model_providers.shadow.requires_openai_auth": "false",
    "model_providers.shadow.supports_websockets": "false",
    "cli_auth_credentials_store": '"ephemeral"',
    "features.shell_snapshot": "false",
    "mcp_servers.shadow.command": '"/usr/bin/python3"',
    "mcp_servers.shadow.args": '["-m", "agent_tools.mcp_server"]',
    "mcp_servers.shadow.env.PYTHONPATH": '"/"',
    "mcp_servers.shadow.required": "true",
    "mcp_servers.shadow.startup_timeout_sec": "10",
}
command = [
    "/usr/bin/codex", "exec", "--ignore-user-config", "--ignore-rules",
    "--ephemeral", "--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox",
    "--json", "-C", "/work",
]
for key, value in config.items():
    command.extend(["-c", f"{key}={value}"])
command.append("Run printf shadow-tool-ok once, call shadow vault status through MCP, then say shadow-client-ok.")
try:
    result = subprocess.run(
        command, capture_output=True, timeout=30,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SHELL": "/bin/sh", "LANG": "C.UTF-8"},
    )
    passed = result.returncode == 0 and b"shadow-client-ok" in result.stdout
    print("LINUX_CODEX_RELAY=" + ("pass" if passed else "fail"))
    # These diagnostics are from an entirely synthetic guest and endpoint.
    if not passed:
        print("CODEX_EXIT=" + str(result.returncode))
        print(result.stderr.decode(errors="replace")[-3000:])
        print(result.stdout.decode(errors="replace")[-6000:])
except subprocess.TimeoutExpired as error:
    print("LINUX_CODEX_RELAY=fail")
    print("CODEX_EXIT=timeout")
    print((error.stderr or b"").decode(errors="replace")[-3000:])
    print((error.stdout or b"").decode(errors="replace")[-6000:])
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
