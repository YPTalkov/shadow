# Storage implementation status

The host-private Python store creates an encrypted KDBX generation, keeps a previous encrypted file, validates a serialized replacement before publication, and fails closed when the live file, ledger digest, or supplied anchor disagree. Fault injection covers backup, prepare, temporary write/fsync, validation, replacement, directory fsync, ledger commit, and anchor advance. A separate Swift Keychain anchor has a synthetic create/update/stale-write test.

`uv run --frozen pytest tests/storage tests/compat`: 21 passed on 2026-09-23. `sh scripts/test-swift.sh`: 2 passed. These are component results with synthetic data.

The native PrivateVaultWorker client now launches the pinned-environment Python worker over an inherited socket pair. It supplies unlock material over that private channel, handles generation-anchor callbacks through the real macOS Keychain, and returns typed owner metadata. It uses no discoverable listener, credential argv/environment, or raw worker diagnostics. The worker disables core dumps, validates bounded epoch/sequence envelopes, rejects replay, and exits on channel loss. Native lock shuts down the channel and terminates the worker.

The integration test creates a synthetic vault, discovers CSV headers, previews/imports, observes the Keychain anchor change, locks, restarts and reopens the imported catalog. Replacing the encrypted file with an older generation requires recovery. The Python IPC test also checks wrong-password handling, unsupported reveal, replay rejection, and an empty diagnostic stream. On 2026-09-24, the native suite passed 20 tests; the affected Python storage/catalog/import suites passed 23 tests. Both new test suites failed before their implementations were added.

This unit is not complete: owner UI/lifecycle wiring, process crash qualification, editor/restore reconciliation, and hostile XML/attachment/compression limits remain. MemoryAnchor is used only by tests; the native client uses the Keychain anchor. No real credentials are approved.
