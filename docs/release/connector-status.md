# Connector implementation status

The private Python consumer implements the pinned JSON wire profile in the source contract. Transactions use bounded trusted memory, a host-supplied HMAC key, authenticated enrollment/epoch parameters, source generations, and encrypted receipts/provenance. Success follows the ordinary anchored KDBX transaction. No producer can supply approval fields, clear restrictions or set host freshness.

Synthetic tests cover exact replay, changed batch replay, stale generations, malformed/oversized/unauthenticated frames, interrupted batches, concurrent owner writes, disk full, coverage contradictions, distinct source identities with duplicate labels, multiple memberships, scope loss, retained deletion, reappearance, and all conflict choices. The consumer's first run exposed PyKeePass's refusal of None in its TOTP setter; empty TOTP now uses the library's supported empty string.

Unlinked candidates stay blocked. Owner adoption creates a distinct local UUID and retains the archived encrypted candidate. Source conflict data and baseline fields stay encrypted and are included in known-secret projection checks. Native editor reconciliation preserves app-owned metadata at entry, group and vault level.

The native restriction service supports idempotent batches of up to 256 immutable events under a separate Keychain anchor. Missing expected history fails closed. The consumer currently receives a test restriction callback; native IPC wiring, source executable enrollment, native conflict/retained controls, stale-mirror event creation and production channel conformance are still under implementation. This is not a completed U7 or release approval.

Verification: `uv run --frozen pytest tests/connector tests/storage/test_editor_handoff.py tests/catalog` passed 40 tests. `sh scripts/test-swift.sh` passed 29 tests, including a 256-event native restriction batch, exact replay, identity reuse rejection and deleted-ledger detection.
