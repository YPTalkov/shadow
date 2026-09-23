# Storage implementation status

The host-private Python store creates an encrypted KDBX generation, keeps a previous encrypted file, validates a serialized replacement before publication, and fails closed when the live file, ledger digest, or supplied anchor disagree. Fault injection covers backup, prepare, temporary write/fsync, validation, replacement, directory fsync, ledger commit, and anchor advance. A separate Swift Keychain anchor has a synthetic create/update/stale-write test.

`uv run --frozen pytest tests/storage tests/compat`: 21 passed on 2026-09-23. `sh scripts/test-swift.sh`: 2 passed. These are component results with synthetic data.

This unit is not complete: the Swift supervisor is not yet connected to the private worker and Keychain anchor, writer startup/crash integration is untested, and hostile XML/attachment/compression limits are not established. The MemoryAnchor class is a test fixture and cannot authorize production operations. No real credentials are approved.
