# Catalog and policy implementation status

The host-private catalog derives an allowlisted in-memory projection from an unlocked KDBX, strips URL paths/query values, searches title/site/Unicode username within an owner-approved ID scope, and returns only 256-bit reference strings supplied by the native registry. It does not expose entry UUIDs or secret fields. Native policy separates catalog disclosure from account use and binds use to the agent, VM boot, account revision, exact origin/action, expiry, and any retained restriction event. The reference registry invalidates tokens on lock or account change.

The native restriction ledger appends source deletion, access loss, stale mirror, and unknown-history events to a private SQLite file. Its independent Keychain hash chain refuses an ordinary rollback of that ledger. A source reappearance does not remove its event.

`uv run --frozen pytest tests/catalog`: 3 passed. `sh scripts/test-swift.sh`: 7 passed. These are component tests using synthetic data.

The counts above describe the initial component checkpoint. Native issuance/revocation, connector provenance and active-session closure are now integrated and covered by the [combined VM tests](two-vm-status.md). The production runtime uses native random references. No real credential use is approved.

## Projection defense follow-up

Catalog and CSV preview now check allowlisted metadata against known protected values across entries/rows, including literal, URL-encoded and base64 forms. The in-memory matcher has a fixed memory/input budget and withholds all metadata if that budget is exceeded. Explicitly protected titles, usernames and URLs are withheld directly, including long values; entries under KeePassXC's recycle bin are omitted. Catalog groups now use their display path.

`uv run --frozen pytest tests/catalog tests/import tests/compat`: 27 passed. Cases include cross-account reflection, encoded reflection, protected metadata, recycled entries, CSV cross-row reflection, matcher overflow and overlapping patterns. This is defense in depth for typed projections; it does not authorize generic text/HTML output or prove every possible encoding safe. Full cross-boundary canary qualification remains in U13.
