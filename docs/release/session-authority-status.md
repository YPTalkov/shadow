# Native session authority qualification

The native session coordinator serializes one protected browser session. It checks
the enrolled caller/boot, account revision, exact adapter credential origin and
native grant at each authentication stage and after private credential resolution.
Revocation closes the driver's authority synchronously before asynchronous teardown.

Private credential resolution reads the current encrypted generation and returns
only the selected entry's username/password and explicitly requested TOTP. It
rejects stale revisions/origins, ambiguous IDs, recycled/archived/conflicted entries
and oversized fields. Presence alone does not authorize a retained credential;
the native grant and independent restriction ledger still govern use.

The bounded SQLite journal holds opaque IDs, argument digests, timestamps, states
and fixed codes. It stores no credential payloads, metadata, browser state or
grants. Submit permission is acknowledged only after a FULL/fullfsync transaction.
Restart converts unfinished submitted work to `outcome_unknown`, and other
unfinished work to `cancelled`. Repeated requests recover status before resolving
expiring account references or claiming a retained-copy grant again. Receipts
expire after seven days; live sessions and authority are never restored.

Evidence (2026-09-24):

- `bash scripts/test-swift.sh --filter 'protectedSession|nativeWorkerUsesKeychain|operationJournal|publicAPI'`: 7 passed.
- Real native worker/Keychain/CSV/private resolver integration passed with synthetic credentials.
- Native service tests cover stage revocation before resolution, after resolution,
  after submit, retained approval retry, changed arguments and caller boot binding.
- Journal tests cover restart, terminal-state immutability, capacity/retention,
  private path permissions, symlinks and competing writers.

These service tests use a controlled browser driver. Production VM driver,
independent guest supervisor and renewable host egress integration remain in U9.
The earlier real Chromium VM evidence is recorded separately in
`browser-runtime-status.md`; it does not yet qualify this new end-to-end path.
