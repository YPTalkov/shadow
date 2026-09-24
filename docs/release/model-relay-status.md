# Codex subscription relay status

The owner uses ChatGPT sign-in. The native relay accepts only POST /v1/responses and fixes the HTTPS upstream to ChatGPT's Codex Responses endpoint. It injects a host-created subscription credential, rejects guest authentication/routing headers, checks a model allowlist, requires streaming with storage disabled, and canonicalizes the request JSON. The ephemeral URL session disables cookies, credentials, caches, proxies and redirects. Provider failures become fixed codes; SSE events are bounded and checked for literal or JSON-escaped credential reflection before forwarding.

The host-created lease binds instance and boot identity, has a monotonic expiry, and counts requests and cumulative input bytes. In-flight forwarding rechecks the lease; an independent 100 ms task cancels idle requests after revocation/expiry. These are request limits, not a verified monetary spending cap. Provider output is limited to 8 MiB per request.

On 2026-09-23, 12 native tests passed, including endpoint/authentication injection, routing attacks, unknown fields, expired credentials, boot mismatch, request limits, revocation, truncated SSE and reflected synthetic credentials. The first test run failed because the new ModelRelay target had no implementation, before production code was added.

The installed macOS Codex CLI 0.156.1 completed two Responses requests against a synthetic local SSE fixture: a harmless shell tool call followed by its output and a final message. It sent no authorization header. Command: SHADOW_CODEX_INTEGRATION=1 uv run --frozen pytest tests/isolation/test_agent_client.py.

The actual Linux client also completed this flow through the VM socket and native policy, as recorded in [isolation status](isolation-status.md). Its extra informational headers and client metadata are accepted and discarded before upstream forwarding. The native suite now has 14 passing tests.

This is the initial component evidence. Native sign-in, Keychain custody, refresh and synthetic streaming/cancellation tests are now covered by [model authentication](model-auth-status.md) and [agent runtime qualification](agent-runtime-status.md). Live subscription authentication remains open. No real credential store was read. Reflection checks are defense in depth and do not prove protection from a malicious model provider encoding a credential across output events.
