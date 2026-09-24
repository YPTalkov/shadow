import json

import pytest

from guest_transport.agent_runtime import AgentJob, OutputProjection, RuntimeLease, command


def test_agent_job_accepts_only_native_bounded_task():
    job = AgentJob.decode({"kind": "task", "protocol_major": 1, "prompt": "Check status", "model": "gpt-6-sol"})
    assert job.prompt == "Check status"
    for change in ({"model": "https://attacker.test"}, {"prompt": "x" * 8193}, {"token": "secret"}, {"protocol_major": True}):
        with pytest.raises(ValueError):
            AgentJob.decode({"kind": "task", "protocol_major": 1, "prompt": "ok", "model": "gpt-6-sol", **change})


def test_codex_command_has_only_guest_bridge_and_ephemeral_auth():
    result = command(4242, "gpt-6-sol")
    assert result[-1] == "-"  # Owner task arrives through stdin, never process arguments.
    assert "--ephemeral" in result and "--ignore-user-config" in result
    assert 'model_providers.shadow.base_url="http://127.0.0.1:4242/v1"' in result
    assert 'cli_auth_credentials_store="ephemeral"' in result
    assert 'mcp_servers.shadow.command="/usr/bin/python3"' in result


def test_output_projects_only_bounded_agent_text_not_commands_or_provider_errors():
    output = OutputProjection()
    def project(value):
        return output.line(json.dumps(value).encode())
    assert project({"type": "item.completed", "item": {"type": "command_execution", "aggregated_output": "secret"}}) is None
    assert project({"type": "error", "message": "provider raw detail"}) == {"kind": "failed"}
    assert project({"type": "item.completed", "item": {"type": "agent_message", "text": "done"}}) == {"kind": "message", "text": "done"}
    with pytest.raises(ValueError):
        project({"type": "item.completed", "item": {"type": "agent_message", "text": "x" * 8193}})
    with pytest.raises(ValueError):
        output.line(b"x" * 65537)


def test_runtime_lease_never_revives_after_expiry_or_replay():
    lease = RuntimeLease(now=1)
    lease.renew({"kind": "lease", "sequence": 1, "ttl_ms": 10000}, now=2)
    assert lease.valid(now=11)
    with pytest.raises(ValueError):
        lease.renew({"kind": "lease", "sequence": 2, "ttl_ms": 10000}, now=12)
    assert not lease.valid(now=12)
    replay = RuntimeLease(now=1)
    replay.renew({"kind": "lease", "sequence": 1, "ttl_ms": 10000}, now=2)
    with pytest.raises(ValueError):
        replay.renew({"kind": "lease", "sequence": 1, "ttl_ms": 10000}, now=3)
    assert not replay.valid(now=3)
