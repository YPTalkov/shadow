# Storage implementation status

The host-private Python store creates an encrypted KDBX generation, keeps a previous encrypted file, validates a serialized replacement before publication, and fails closed when the live file, ledger digest, or supplied anchor disagree. Fault injection covers backup, prepare, temporary write/fsync, validation, replacement, directory fsync, ledger commit, and anchor advance. A separate Swift Keychain anchor has a synthetic create/update/stale-write test.

`uv run --frozen pytest tests/storage tests/compat`: 21 passed on 2026-09-23. `sh scripts/test-swift.sh`: 2 passed. These are component results with synthetic data.

The native PrivateVaultWorker client now launches the pinned-environment Python worker over an inherited socket pair. It supplies unlock material over that private channel, handles generation-anchor callbacks through the real macOS Keychain, and returns typed owner metadata. It uses no discoverable listener, credential argv/environment, or raw worker diagnostics. The worker disables core dumps, validates bounded epoch/sequence envelopes, rejects replay, and exits on channel loss. Native lock shuts down the channel and terminates the worker.

The integration test creates a synthetic vault, discovers CSV headers, previews/imports, observes the Keychain anchor change, locks, restarts and reopens the imported catalog. Replacing the encrypted file with an older generation requires recovery. The Python IPC test also checks wrong-password handling, unsupported reveal, replay rejection, and an empty diagnostic stream. On 2026-09-24, the native suite passed 20 tests; the affected Python storage/catalog/import suites passed 23 tests. Both new test suites failed before their implementations were added.

The counts above describe the initial storage checkpoint. Owner UI/lifecycle wiring, worker-failure handling, editor/restore reconciliation and hostile XML/attachment/compression limits are now implemented and exercised; see [package qualification](package-status.md) and [recovery evidence](recovery-status.md). MemoryAnchor is used only by tests; the native client uses the Keychain anchor. Physical app-crash rehearsal and owner recovery sign-off remain open. No real credentials are approved.
# Bounded input follow-up

The read path now composes bounded decompression/XML adapters with PyKeePass's unchanged KDBX4 cryptographic pipeline. Header inspection parses only the header: the library's ordinary `decrypt=False` mode still invokes its KDF, so it is unsuitable for the resource-limit preflight. A raw-header regression test replaces Argon2 with a function that must never run during inspection.

Caps: 128 MiB encrypted file, 64 MiB decompressed payload, 128 Ki characters per XML field, 2 million XML nodes, 100,000 entries including history, 50,000 live entries and 10,000 groups. DTDs/entities, duplicate header keys/UUIDs, unknown outer fields/XML elements, attachments, custom icon data and unsupported inner streams are refused. Invalid protected field decoding fails instead of silently retaining unreadable values. Supported standard field names were checked against [KeePass's serializer declarations](https://github.com/dlech/KeePass2.x/blob/master/KeePassLib/Serialization/KdbxFile.cs).

`uv run --frozen pytest tests/compat`: 15 passed, including encrypted decompression/DTD/attachment fixtures and the installed KeePassXC round trip. The preceding storage/catalog/import compatibility run passed 30 tests. These are component tests; packaged hostile-input resource qualification remains part of U13.
