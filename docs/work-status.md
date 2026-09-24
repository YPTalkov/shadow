# Implementation status

The acceptance target is the reviewed plan's G1–G6 release evidence, a packaged local application, and an owner rollout checkpoint. Publishing source is authorized by the owner's request to use `YPTalkov/shadow`. Real credential rollout still requires the plan's release gates.

| Unit | State | Evidence or remaining work |
|---|---|---|
| U1 | Partial | KDBX/KeePassXC interoperability, Swift builds and locked production images pass. Host Python and guest package scans are recorded; public browser fixes applied and unused vulnerable plugins removed. Residual advisories and native components still need review. |
| U2 | Partial | Both production profiles boot; real Linux root boundary attacks, cross-role socket denial, Linux Codex relay, HTTPS gateway and watchdog tests pass. Live provider and independent isolation qualification remain. |
| U3 | Implemented and tested | Native worker/Keychain create/import/reopen/rollback, hostile-file bounds and sealed packaged-worker qualification pass. |
| U4 | Implemented and tested | Catalog, references, authority and restriction ledger compose with native consent and both VMs; 10,000-entry search benchmark passes. |
| U5 | Partial | Descriptor-based preview/commit and packaged 5,000-row import pass in 1.05 seconds; manual owner walkthrough remains. |
| U6 | Partial | Packaged native import/edit/consent/recovery and actual two-VM sessions pass. Owner accessibility qualification remains. |
| U7 | Implemented and tested | Private signed producer, Keychain HMAC custody, refresh/removal, conflicts and editor conformance pass. Packaged two-VM source removal interrupts the active browser and retains encrypted data. Production connectors qualify separately. |
| U8 | Partial | Shared contracts, host ChatGPT sign-in, production VM controls and protected connector refresh jobs implemented. GPT-6 code tools, MCP, task teardown and active-request lock pass for all three selectable models. Connector discovery, receipts, cancellation/resume and signed native import pass; see `docs/release/agent-runtime-status.md` and `connector-job-status.md`. Combined two-VM login/read and source-removal interruption pass; live sign-in remains. |
| U9 | Implemented and tested | Production VM driver and owner runtime wiring, private credential delivery, independent leases, native-to-VM HTTPS login, idempotent retry, revocation and 12-second host suspension pass. |
| U10 | Partial | Schema-bound views, 18 hostile-view cases, 9 Chromium challenge cases, native TOTP/SSO, private owner input and two-minute expiry pass. Packaged UI states the synthetic-only scope. Owner-selected real-site adapter remains. |
| U11 | Partial | Synchronous lock/sleep/session handlers, idle expiry, worker-crash closure and bounded diagnostics pass, including packaged native UI export. Physical OS-event/installed-app crash rehearsal remains. |
| U12 | Partial | Encrypted retention, export, intact/lost-history restore, packaged native recovery and independent KeePassXC inspection pass. Owner disaster-recovery sign-off remains. |
| U13 | Partial | Packaged worker/agent two-VM task and source removal pass with no model canaries. Production browser boots without fixture exceptions and expires on host silence. Real-site, physical OS and independent attack qualification remain. |
| U14 | In progress | Sealed relocatable `dist/Shadow.app`, 16 tamper/installation checks, locked inventory, notices and CE review are complete. External adversarial CLI routes failed; independent security review and owner rollout approval remain open. |

## Chosen agent and model authentication

The owner selected Codex CLI and uses ChatGPT sign-in. Inspection of Marlen's source found its `openai-codex` provider delegates OAuth to pi-ai 0.85.0, refreshes the subscription token on the host, and sends authenticated streaming Responses requests to `https://chatgpt.com/backend-api/codex/responses` with a `chatgpt-account-id` header. Only source code was inspected; no Marlen credential store was opened.

Shadow keeps subscription authentication outside the guest and constrains its model relay to that endpoint. This refines KTD3's provider-key wording to support host-held OAuth credentials. Native device sign-in, Keychain custody and refresh are implemented and tested with synthetic responses; see `docs/release/model-auth-status.md`. The packaged production VM client passes with all three selectable models against synthetic provider responses. Live provider qualification remains required.

## Current checkpoint

See [release decision](release/go-no-go.md), [package evidence](release/package-status.md), [requirement evidence](release/security-evidence.md) and [CE review receipt](release/review-receipt.md). The plan is not complete, and no real-data rollout is approved. All remaining user decisions are recorded there; implementation does not require an API key.
