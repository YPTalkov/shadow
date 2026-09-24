# Connect a separate credential source

Shadow works with no connector installed. Apple collection stays in the separate Apple project. Shadow's private [credential-source/v1 contract](../contracts/credential-source-v1.md) is the integration authority.

The owner selects the connector application in **Sources & Retained Items**. Shadow validates its signed identity and capability manifest before enrollment. Enrollment pins its executable identity and creates a Shadow-specific Keychain HMAC key for that source. A changed executable requires fresh owner inspection; imported records alone cannot enroll a producer.

Refresh runs the pinned executable over inherited private IPC. The connector returns bounded begin/group/item/coverage/commit frames, stable identifiers and explicit coverage. No producer socket or secret import tool is exposed to an agent. Native restriction publication runs before the vault commit can make changed source state visible.

Complete absence evidence can mark a mirrored entry deleted; permission loss and incomplete evidence remain distinct. Every removal preserves the encrypted local entry and provenance. Owner edits and divergent producer updates require conflict review. Reappearance cannot erase an earlier restriction. Removing enrollment ends authority and retains imported entries.

Agents can request a refresh only through an opaque reference obtained from owner-approved catalog disclosure. Their request cannot choose a producer path, send secret payloads or approve source interaction. See [agent integration](../agent-integration.md) for bounded jobs and idempotent receipts.

Run conformance before changing either side:

```sh
uv run --frozen pytest tests/connector tests/protocol
bash scripts/test-swift.sh --filter 'nativeSource|enrolledExecutable|connector'
```

`source-fixture` and `scripts/make-source-fixture.py` create a synthetic signed producer for development. The fixture, its test credentials and diagnostic bypasses are excluded from `Shadow.app`.
