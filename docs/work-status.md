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
| U8 | Partial | Shared request/result contracts, native API, CLI/MCP/PTC parity (29 tests), native authority tests and actual Linux Codex MCP pass. Protected jobs and production VM enrollment remain. |
| U9 | Partial | Production VM driver, private credential delivery, root supervisor and renewable worker/egress leases implemented. Real native-vault-to-VM HTTPS login, idempotent retry, post-submit revocation and 12-second host suspension pass. Owner runtime wiring and full integrated attack matrix remain in U6/U13/U14. |
| U10 | In progress | Native-to-VM list/detail/extract/navigation workflow and 18 hostile-view cases pass. Schemas, opaque document-bound links, cookie/credential projection and transport parity implemented. Owner challenges, SSO/TOTP and owner-selected site qualification remain. |
| U11 | Pending | Submit receipts recover unknown outcomes without replay; retained-grant retries recover status. Remaining: integrated lifecycle, independent monitors, challenge cancellation and audit. |
| U12 | Pending | Backup/restore and recovery UI. |
| U13 | Pending | Packaged cross-boundary security and end-to-end suite. |
| U14 | Pending | Packaging, independent review and owner rollout checkpoint. |

## Chosen agent and model authentication

The owner selected Codex CLI and uses ChatGPT sign-in. Inspection of Marlen's source found its `openai-codex` provider delegates OAuth to pi-ai 0.85.0, refreshes the subscription token on the host, and sends authenticated streaming Responses requests to `https://chatgpt.com/backend-api/codex/responses` with a `chatgpt-account-id` header. Only source code was inspected; no Marlen credential store was opened.

Shadow will keep subscription authentication outside the guest and constrain its model relay to that endpoint. This refines KTD3's provider-key wording to support host-held OAuth credentials. It does not change the isolation contract. Native sign-in/credential custody, token refresh, live provider qualification, and VM client qualification must all pass before this integration is complete.
