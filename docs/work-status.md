# Implementation status

The acceptance target is the reviewed plan's G1–G6 release evidence, a packaged local application, and an owner rollout checkpoint. Publishing source is authorized by the owner's request to use `YPTalkov/shadow`. Real credential rollout still requires the plan's release gates.

| Unit | State | Evidence or remaining work |
|---|---|---|
| U1 | Partial | KDBX interoperability and Swift builds pass; dependency audit and final image locks remain. |
| U2 | Partial | Both Linux profiles boot; root boundary probes, Linux Codex synthetic relay, and certificate-verified leased HTTPS pass. Browser-specific bypass tests, watchdogs, live sign-in and production images remain. |
| U3 | Partial | Native worker/Keychain create/import/reopen/rollback and bounded hostile-file tests pass. Full packaged resource/crash qualification remains. |
| U4 | Partial | Catalog, references, authority and restriction ledger tested; supervisor integration remains. |
| U5 | Partial | Descriptor-based CSV preview/commit and native three-account import pass; final manual owner walkthrough remains. |
| U6 | Partial | Native vault/import/editor/consent/revocation/source flows and full catalog scope pass. Actual VM/session integration and accessibility qualification remain. |
| U7 | Partial | Private consumer, native restriction publication, pinned executable enrollment, Keychain HMAC custody, refresh/removal, conflicts and source/editor conformance implemented. Browser-interruption and packaged qualification remain. |
| U8 | In progress | Shared contracts, host ChatGPT sign-in, production VM controls and protected connector refresh jobs implemented. GPT-6 code tools, MCP, task teardown and active-request lock pass for all three selectable models. Connector discovery, receipts, cancellation/resume and signed native import pass; see `docs/release/agent-runtime-status.md` and `connector-job-status.md`. Live sign-in and combined two-VM tasks remain. |
| U9 | Partial | Production VM driver, private credential delivery, root supervisor and renewable worker/egress leases implemented. Real native-vault-to-VM HTTPS login, idempotent retry, post-submit revocation and 12-second host suspension pass. Owner runtime wiring and full integrated attack matrix remain in U6/U13/U14. |
| U10 | Partial | Schema-bound views, 18 hostile-view cases, 9 Chromium challenge cases, native HTTPS TOTP/redirected SSO, actual private VM-view owner input, cancellation and measured two-minute expiry pass. See `docs/release/challenge-status.md`. Owner-selected site qualification and packaged capability display remain. |
| U11 | Partial | Synchronous lock/sleep/session handlers, continuous idle expiry, worker-crash closure, bounded seven-day diagnostics and owner-reviewed export implemented. 18 native tests, live VM worker-kill test and UI export pass. Physical OS-event and packaged crash/diagnostic rehearsal remains in U13/U14. |
| U12 | Partial | Encrypted previous/daily retention, export and reviewed restore implemented. 74 Python tests, 11 native test functions (six restore-history cases), native UI recovery and independent KeePassXC inspection pass. See `docs/release/recovery-status.md`; packaged/manual qualification remains. |
| U13 | Pending | Packaged cross-boundary security and end-to-end suite. |
| U14 | Pending | Packaging, independent review and owner rollout checkpoint. |

## Chosen agent and model authentication

The owner selected Codex CLI and uses ChatGPT sign-in. Inspection of Marlen's source found its `openai-codex` provider delegates OAuth to pi-ai 0.85.0, refreshes the subscription token on the host, and sends authenticated streaming Responses requests to `https://chatgpt.com/backend-api/codex/responses` with a `chatgpt-account-id` header. Only source code was inspected; no Marlen credential store was opened.

Shadow keeps subscription authentication outside the guest and constrains its model relay to that endpoint. This refines KTD3's provider-key wording to support host-held OAuth credentials. Native device sign-in, Keychain custody and refresh are implemented and tested with synthetic responses; see `docs/release/model-auth-status.md`. Live provider qualification and production VM client integration remain required before this integration is complete.
