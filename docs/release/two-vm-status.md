# Combined agent and browser qualification

The real Linux Codex 0.156.1 client completed a synthetic authenticated task through the production native agent supervisor, MCP service, private vault worker, protected browser VM and HTTPS fixture. A scripted provider drove the client; no live ChatGPT account was used.

The owner fixture approved catalog disclosure and credential use separately. Codex requested login, waited for completion, observed a bounded view, clicked an opaque action, extracted the report status, and closed the session. The fixture saw exactly one credential submission. Completion removed the caller and all grants.

A second run removed a mirrored credential from a complete source snapshot after successful login. The encrypted account retained its UUID and received a deletion restriction event. Existing grants closed before publication, and the client's subsequent browser read was denied. The agent then completed without reusing the session.

Both runs checked every model request for password, unlock and cookie canaries in plain text and base64. Captured synthetic console output contained no listed canaries. This scan covers these fixtures and encodings; it is not a general secrecy proof.

## Evidence

`two-vm-results.json` and `two-vm-source-results.json` record timestamps, executable and image hashes, host version and fixed result codes. Both passed on macOS 26.6.2 arm64.

```sh
uv run --frozen python scripts/run-browser-probe.py --agent
uv run --frozen python scripts/run-browser-probe.py --agent --interrupt source
```

The browser qualification image adds the private fixture CA and diagnostic bootstrap. The production image excludes those additions. These runs do not qualify a real site, live provider, or final installed bundle. U13/U14 retain those gates.

The later `packaged-two-vm-results.json` and `packaged-two-vm-source-results.json` rerun both flows using the sealed app's Python worker and agent image after the browser security updates and SDK startup repair. They record the app resource-inventory hash. The browser still uses its separate HTTPS qualification image; `production-browser-results.json` independently checks the exact bundled production image's boot and host-silence shutdown. These results do not close the live-provider, real-site or owner rehearsal gates.

The CE simplification rubrics were applied serially to this harness and wrapper, as required by the owner's tool mapping. No behavior-preserving rewrite was warranted: the scripted provider is diagnostic-only, its state machine makes each expected tool result explicit, and its bounds and authority checks remain visible. Existing scenario harnesses were reused; no production capture or bypass was added.
