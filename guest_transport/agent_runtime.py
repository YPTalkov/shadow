"""Ephemeral Codex task runner. The host remains the authority for both channels."""

import json
import os
import selectors
import signal
import socket
import subprocess
import threading
import time
from dataclasses import dataclass

from guest_transport.model_bridge import ModelBridge, receive, send

MODELS = {"gpt-6-sol", "gpt-6-luna", "gpt-6-astra"}


def continuous_time() -> float:
    return time.clock_gettime(time.CLOCK_BOOTTIME)


@dataclass(frozen=True)
class AgentJob:
    prompt: str
    model: str

    @classmethod
    def decode(cls, value: dict) -> "AgentJob":
        if (
            set(value) != {"kind", "protocol_major", "prompt", "model"}
            or value["kind"] != "task"
            or type(value["protocol_major"]) is not int
            or value["protocol_major"] != 1
            or not isinstance(value["prompt"], str)
            or not 0 < len(value["prompt"].encode()) <= 8192
            or value["model"] not in MODELS
        ):
            raise ValueError("invalid_task")
        return cls(value["prompt"], value["model"])


class RuntimeLease:
    def __init__(self, now: float):
        self.deadline = now + 10
        self.sequence = 0
        self.revoked = False
        self.lock = threading.Lock()

    def valid(self, now: float) -> bool:
        with self.lock:
            return not self.revoked and now < self.deadline

    def renew(self, value: dict, now: float) -> None:
        with self.lock:
            if (
                self.revoked or now >= self.deadline
                or set(value) != {"kind", "sequence", "ttl_ms"}
                or value["kind"] != "lease"
                or type(value["sequence"]) is not int
                or value["sequence"] <= self.sequence
                or type(value["ttl_ms"]) is not int
                or value["ttl_ms"] != 10000
            ):
                self.revoked = True
                raise ValueError("lease_closed")
            self.sequence = value["sequence"]
            self.deadline = now + 10


class OutputProjection:
    def __init__(self):
        self.total = 0
        self.messages = 0

    def line(self, data: bytes) -> dict | None:
        self.total += len(data)
        if len(data) > 65536 or self.total > 4 * 1024 * 1024:
            raise ValueError("output_limit")
        value = json.loads(data)
        if not isinstance(value, dict):
            raise ValueError("invalid_output")
        if value.get("type") in {"error", "turn.failed"}:
            return {"kind": "failed"}
        item = value.get("item")
        if value.get("type") != "item.completed" or not isinstance(item, dict) or item.get("type") != "agent_message":
            return None
        text = item.get("text")
        if not isinstance(text, str) or not 0 < len(text.encode()) <= 8192 or self.messages >= 32:
            raise ValueError("output_limit")
        self.messages += 1
        return {"kind": "message", "text": text}


def command(port: int, model: str) -> list[str]:
    if model not in MODELS or not 0 < port < 65536:
        raise ValueError("invalid_task")
    config = {
        "model": json.dumps(model),
        "model_provider": '"shadow"',
        "model_providers.shadow.name": '"Shadow"',
        "model_providers.shadow.base_url": f'"http://127.0.0.1:{port}/v1"',
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
    result = ["/usr/bin/codex", "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
              "--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox", "--json", "-C", "/work"]
    for key, value in config.items():
        result.extend(["-c", f"{key}={value}"])
    return result + ["-"]


def run_task(publish, job: AgentJob, lease: RuntimeLease, stopped: threading.Event) -> bool:
    os.makedirs("/work", mode=0o700, exist_ok=True)
    bridge = ModelBridge()
    threading.Thread(target=bridge.serve_forever, daemon=True).start()
    process = None
    try:
        process = subprocess.Popen(
            command(bridge.server_port, job.model), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=True, cwd="/work",
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SHELL": "/bin/sh", "LANG": "C.UTF-8", "HOME": "/root"},
        )
        process.stdin.write(job.prompt.encode())
        process.stdin.close()
        projection = OutputProjection()
        buffer = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while not stopped.is_set() and lease.valid(continuous_time()):
                if not selector.select(0.05):
                    continue
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    return not buffer and process.wait(timeout=2) == 0
                buffer.extend(chunk)
                while b"\n" in buffer:
                    line, _, remaining = buffer.partition(b"\n")
                    buffer = bytearray(remaining)
                    result = projection.line(line)
                    if result is not None:
                        if result["kind"] == "failed":
                            return False
                        publish(result)
                if len(buffer) > 65536:
                    raise ValueError("output_limit")
        return False
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
            process.stdout.close()
        bridge.shutdown()
        bridge.server_close()


def main() -> None:
    stopped = threading.Event()
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as host:
        host.settimeout(10)
        host.connect((socket.VMADDR_CID_HOST, 4050))
        send(host, {"kind": "runtime_ready", "protocol_major": 1})
        lease = RuntimeLease(continuous_time())
        job = AgentJob.decode(receive(host))
        lease.renew(receive(host), continuous_time())
        send_lock = threading.Lock()

        def publish(value):
            with send_lock:
                send(host, value)

        def watch():
            try:
                while not stopped.is_set():
                    update = receive(host)
                    lease.renew(update, continuous_time())
                    publish({"kind": "alive", "sequence": update["sequence"]})
            except (OSError, ValueError, TypeError):
                stopped.set()

        threading.Thread(target=watch, daemon=True).start()
        try:
            succeeded = run_task(publish, job, lease, stopped)
            if not stopped.is_set() and lease.valid(continuous_time()):
                publish({"kind": "finished", "succeeded": succeeded})
                # Let the host consume the final frame and revoke this boot before shutdown.
                stopped.wait(10)
        finally:
            stopped.set()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Production console and Python exceptions never carry task contents.
        raise SystemExit(1) from None
