# Native Codex runtime qualification

The owner can select a model and a 30, 60 or 120-request ceiling, enter a task, and start or stop an isolated Codex VM from Agent Access. Each task gets a new native instance and boot identity. The guest has no NIC, host shares, graphics, saved state or console capture. Its writable home and workspace are in memory. Task completion, cancellation and vault lock close the VM, relay authority, pending requests and grants. Lock also clears displayed task output.

The supervisor imposes a 15-minute deadline, a 32 MiB cumulative model-input ceiling, a 4 MiB request limit and renewable 10-second model authority. Only the selected model is accepted. The guest receives the task through a private socket, sends it to Codex on stdin, and projects bounded assistant messages back to native plain text. Raw tool output and client/provider error messages are not displayed or logged by the runtime. Approved tool results still enter Codex's own in-memory conversation, as required for the task.

Model credentials remain in the host's Shadow-specific Keychain item. The relay fixes the upstream destination and authentication. It accepts local function/custom tool definitions, including namespaces, and rejects hosted tools and media/file URL fetches. No guest header can select another credential, account or destination.

## Client compatibility findings

Codex 0.156.1 selects Responses Lite for GPT-6: tool declarations and base instructions appear in `input`, accompanied by `x-openai-internal-codex-responses-lite: true`. Shadow supports this explicit form as well as the previously tested Responses form. The header is validated and reconstructed as a fixed literal. The ordinary form still requires an instructions string. This behavior was confirmed against the pinned [Codex source](https://github.com/openai/codex/blob/rust-v0.156.1/codex-rs/core/src/client.rs).

GPT-6's code tool also needs `codex-code-mode-host`, a separate release artifact. The image now contains both executable archives from 0.156.1. The helper archive's SHA-256 is `40198138b03798ffa8c0da4c827a8ca5896774ea104b7110c2a2c0c7560cbe94`, verified against the official release metadata. Its absence produced an actual guest tool failure; the completed code-tool/MCP probe is the regression proof.

## Verification

- 12 native test functions: malformed tasks, output bounds, renewable authority, request routing, Responses Lite, hosted-tool/fetch rejection and owner lock races.
- 42 Python checks across the new guest runner, image assembly and shared tool protocols.
- The actual Linux client executes a shell command and native Shadow MCP status call through GPT-6's code tool, then completes a response. A second task is held in an active model request; native lock removes the caller and pending consent. The old boot is rejected after unlock.
- The owner UI probe passes with the production image configured. Screenshots were inspected: task controls collapse when consent appears, leaving the full approval card and both decision buttons visible.

Commands:

```sh
bash scripts/test-swift.sh --filter 'agentRuntime|agentRelayHeartbeat|relay|codexClientMetadata|ownerLock'
uv run --frozen pytest tests/isolation/test_agent_runtime.py tests/isolation/test_browser_image.py tests/protocol -q
codesign --force --sign - --entitlements packaging/virtualization.entitlements .build/arm64-apple-macosx/debug/vm-boot-probe
uv run --frozen python scripts/run-agent-probe.py
.build/arm64-apple-macosx/debug/owner-ui-probe
```

The original executable and image hashes, host version and per-model results are recorded in `agent-runtime-results.json`; the packaged rerun is in `agent-package-results.json`. This is synthetic provider qualification. Two-VM authenticated tasks are covered by `two-vm-status.md`, and the local bundle by `package-status.md`. Live ChatGPT sign-in, physical OS lifecycle events and independent review remain release gates. Model availability for the owner's subscription has not been tested.
