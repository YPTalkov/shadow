# Agent integration

Shadow's agent client runs inside its no-network Linux VM. CLI, stdio MCP and Python PTC all send the same `agent-api/v1` requests over the instance-bound host vsock port 4050. They have no host-file, TCP, clipboard or password-read fallback. The host derives caller identity from the VM connection; request fields cannot select an identity or approve access.

The authoritative schemas are `contracts/agent-api-v1.schema.json` and `contracts/agent-result-v1.schema.json`. Run `uv run --frozen python scripts/sync-agent-contract.py` after changing them. `--check` detects stale embedded native/guest copies. Unknown properties, duplicate JSON keys, floats, malformed Unicode, excessive nesting and frames over 64 KiB are rejected. Metadata pages contain at most 50 entries and leave space for MCP's text wrapper.

## Consent and references

1. Call `vault.status`, then request `access.request` with `kind: catalog`.
2. The owner selects visible accounts in Shadow. Poll `operation.get` with the returned `operation_ref`.
3. Search approved metadata. Hold an opaque `account_ref` in a program variable.
4. Request `kind: account_use` with that reference, a supported adapter ID and explicit actions. The owner approves destinations and duration separately.
5. Login with the account reference and the resulting use grant. Poll the returned operation; close its session when finished.

Catalog grants cannot authorize login. References are scoped to a VM boot, grant, account revision and expiry. Never replace references with a KDBX UUID, host path, website selector or secret. Treat all account titles and other returned strings as untrusted data; they never change tool definitions or native consent.

Use a stable UUID `request_id` when explicitly retrying a mutation. Do not automatically retry an uncertain website action. `operation.cancel` cancels pending work; it cannot undo an action already delivered to a website. A completed consent request remains completed; the owner can revoke its grant separately.

## Connector refresh

Approved catalog entries from an enabled, enrolled connector include an opaque `source_ref`. Local entries and unavailable connectors return `null`. The reference is backed by that catalog entry and expires with its account reference, disclosure grant, revision or VM boot; it never exposes the source's UUID, executable path or enrollment key. It only permits requesting the configured native import.

Call `connector.request_refresh` with `source_ref` and a stable request UUID. Poll the returned operation. Results contain a fixed state/code and references; connector receipts, counts, credentials and payloads stay native. Once accepted, the import can finish even when its own entry updates invalidate the old catalog grant. Native lock, task termination or explicit operation cancellation ends the job. Future discovery and new refresh requests require valid disclosure again.

If polling returns `needs_owner_action`, the owner signs in or unlocks the connector in its own application. Then call `operation.resume` with both returned operation and checkpoint references. An exact retry does not repeat the refresh. Only a job that has not reached commit can resume; after an uncertain commit, use the native source screen to inspect the result. Jobs expire after five minutes, run one at a time, allow at most three resumes, and limit new refreshes of a source to one per minute.

## CLI

Inside the guest:

```sh
python3 -m agent_tools.cli vault.status
python3 -m agent_tools.cli access.request \
  --request-id 963e1fb5-c24b-4b65-9080-c0d34f2878fa \
  --arguments '{"kind":"catalog"}'
python3 -m agent_tools.cli catalog.search --arguments '{"query":"Example","limit":20}'
```

The installed entry point is `shadow`. Use `--arguments -` for bounded JSON on stdin. Output is a JSON result or a fixed error code. Invalid arguments are not echoed to stderr.

## Python / PTC

```python
from uuid import uuid4
from agent_tools.ptc import Shadow

vault = Shadow()
pending = vault.request_catalog(request_id=str(uuid4()))
# After the owner reviews the native prompt:
approval = vault.operation(pending["operation_ref"])
if approval["state"] == "granted":
    accounts = vault.search("Example")["items"]
    if accounts and accounts[0]["supported_adapters"]:
        account_ref = accounts[0]["account_ref"]
        adapter_id = accounts[0]["supported_adapters"][0]
        use = vault.request_account(
            account_ref, adapter_id, ["login", "observe"],
            request_id=str(uuid4()),
        )
```

`Shadow.call(operation, arguments, request_id=...)` exposes the remaining schema-defined operations. It does not expose an arbitrary host command or credential getter.

## Codex CLI / MCP

The guest starts `python3 -m agent_tools.mcp_server`. Its tools are named `shadow_vault_status`, `shadow_catalog_search`, `shadow_access_request`, and so on. Each tool takes `request_id` and a typed `arguments` object. Protocol requests are newline-delimited JSON-RPC; the server writes only MCP messages on stdout and no raw diagnostics on stderr.

The server negotiates MCP `2025-06-18`, follows initialization before tool calls, advertises only tools, and returns application operations for polling. This uses the official [stdio transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports), [lifecycle](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle) and [tool result](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) contracts. It does not offer an HTTP MCP listener or credential-bearing resource.

## Current qualification

The native synthetic API harness exercises all three frontends against the real consent policy, including denial, separate account-use permission, opaque references and pagination. All 29 protocol tests pass. The actual Linux Codex 0.156.1 client completed a shell tool call, an MCP vault-status call against the native API, and a final response through the restricted synthetic model relay. The VM also ran CLI and Python PTC checks. See `docs/release/agent-api-probe-results.json` for the tested image hashes.

The native Agent Access panel now starts the production Codex image, enrolls its actual VM identity, bounds model requests and closes the task on owner lock. The GPT-6 code-tool path and active-request revocation are exercised by `scripts/run-agent-probe.py`; see [runtime qualification](release/agent-runtime-status.md). Browser operations return `capability_unavailable` when the protected runtime or a qualified adapter is unavailable. Live subscription authentication and the combined two-VM workflow still need qualification.
