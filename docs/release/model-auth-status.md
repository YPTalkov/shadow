# Host ChatGPT sign-in

Development implementation, 2026-09-24. Live subscription qualification is pending; these results use synthetic provider responses and synthetic Keychain items.

Shadow's native Agent Access panel now offers ChatGPT device-code sign-in. The owner opens the fixed OpenAI sign-in page and enters the displayed code. Access and refresh tokens stay in a separate, device-only Keychain item scoped to Shadow's app identity. The guest receives neither a token nor a sign-in code. Locking clears a pending code; signing out also ends current vault access.

The installed Marlen dependency `@earendil-works/pi-ai` 0.85.0 supplies the protocol reference: `dist/auth/oauth/openai-codex.js` uses the public Codex client ID, device authorization endpoints, authorization-code exchange, account-ID claim and refresh endpoint. Only package source was inspected. No Marlen or Codex credential file was opened or imported.

OpenAI documents subscription sign-in and device-code authentication, including the need to enable device login in personal security settings or workspace permissions. See [OpenAI authentication](https://learn.chatgpt.com/docs/auth). Shadow's live account support and provider compatibility remain to be tested.

## Implemented controls

- Fixed HTTPS authentication endpoints, disabled redirects/cookies/cache/proxies, bounded responses and fixed errors. Provider response text never becomes a UI error or an agent result.
- Fifteen-minute continuous-time device flow; provider polling interval and slow-down responses respected. No guest operation can begin or finish the flow.
- Token response bounds, account-claim extraction, expiration checks and same-account refresh. Concurrent relay requests share one refresh, whose result is persisted before use.
- Sign-out/cancellation generations reject late token responses. Credential and prompt types redact normal string and reflection descriptions.
- The UI shows the device code only in the native owner panel. Opening the sign-in page requires an owner button press. No automatic clipboard copy or credential export is provided.

## Verification

`bash scripts/test-swift.sh --filter 'signOutDuring|simultaneousRelay|nativeSignIn|nativeModelTokens|codexDevice|codexOAuth|relay|ownerLock|ownerRestore'` — 16 tests passed.

Coverage includes request destinations and form encoding, malformed/duplicate fields, invalid polling intervals, provider failure redaction, token bounds and expiration, account switching, polling backoff, continuous expiry, late success after sign-out, refresh coalescing, real synthetic Keychain round-trip and synchronous removal of a cancelled UI code. The OAuth protocol and state-machine tests were added first and observed failing on the missing implementations.

The native owner UI probe passed after integration. Its Agent Access screen was visually inspected with the sign-in control alongside consent controls. A live device-code screen, live provider call and packaged artifact scan remain in U13/U14; no real sign-in was performed for this receipt.
