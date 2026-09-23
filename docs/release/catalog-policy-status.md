# Catalog and policy implementation status

The host-private catalog derives an allowlisted in-memory projection from an unlocked KDBX, strips URL paths/query values, searches title/site/Unicode username within an owner-approved ID scope, and returns only 256-bit reference strings supplied by the native registry. It does not expose entry UUIDs or secret fields. Native policy separates catalog disclosure from account use and binds use to the agent, VM boot, account revision, exact origin/action, expiry, and any retained restriction event. The reference registry invalidates tokens on lock or account change.

The native restriction ledger appends source deletion, access loss, stale mirror, and unknown-history events to a private SQLite file. Its independent Keychain hash chain refuses an ordinary rollback of that ledger. A source reappearance does not remove its event.

`uv run --frozen pytest tests/catalog`: 3 passed. `sh scripts/test-swift.sh`: 7 passed. These are component tests using synthetic data.

This unit is not complete: supervisor issuance and revocation are not wired to the public protocol, source provenance has not been populated from a connector, and active sessions are not yet closed by restriction events. The production runtime must never substitute the deterministic test reference factory for native random references. No real credential use is approved.
