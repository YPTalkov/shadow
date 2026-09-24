# Encrypted recovery qualification

U12 development qualification, 2026-09-24. No real credentials were used. The final packaged rehearsal and independent review remain release gates.

## Implemented

- Verified encrypted copies before mutation; previous generation plus 30 UTC daily copies. Rotation preserves unrecognized legacy copies and recovery evidence. A failed copy prevents publication.
- Owner export with exclusive creation, and native restore preview with an immutable encrypted snapshot, a five-minute deadline and explicit review.
- Restore preserves current encrypted files and authority bookkeeping. It validates KDBX and bounds reads before publication, then reconciles independent restrictions through the inherited native channel.
- Valid newer deletion/access-loss events survive rollback. Missing, corrupt or rolled-back restriction history requires acknowledgment and a durable history-unknown event for every restored mirror before the new generation can become authoritative. Restored source observations are cleared; ordinary source grants cannot bypass retained-copy review.
- Restore closes grants, handles and sessions, remains locked after commit and requires fresh approval. Cancellation cannot publish a late preview.

## Evidence

| Check | Result |
|---|---|
| `uv run --frozen pytest tests/recovery tests/storage tests/connector -q` | 74 passed |
| `bash scripts/test-swift.sh --filter 'nativeRestore\|ownerRestore\|interruptedRestriction\|nativeSource\|ownerLock\|restrictionLedger\|nativeRestriction\|ownerLifecycle\|vaultWorkerCrash\|ownerIdle'` | 11 functions passed; restore function includes 6 history cases |
| `.build/arm64-apple-macosx/debug/owner-ui-probe` | Passed native import/source/editor/export/review/restore/reopen, uncertainty acknowledgment and diagnostics |
| Independent KeePassXC 2.7.12 inspection | Export decrypted and expected fixture entry listed with the vault worker closed; password delivered through a pipe |
| Native screen inspection | Reviewed ordinary and uncertain-history screens; confirmation disabled until acknowledgment |

The native history cases cover current deletion, current access loss, missing ledger, corrupt ledger, ledger rollback and a clean installation without the old Keychain anchors. A separate interruption test advances the restriction anchor before replacement and confirms the old ledger cannot become a trusted empty history. Owner integration verifies that an old account reference is rejected after restore and unlock.

Python fault injection covers backup, preparation, replacement, ledger and anchor boundaries, plus actual file-write failure injection. It proves recoverable encrypted generations and fail-closed mismatches; it does not substitute for packaged process-kill and physical power-loss rehearsal.

Local screenshots: `.build/evidence/owner-restore-review.jpg`, `owner-restore-uncertain.jpg`, `owner-diagnostics.jpg`. Binary digest and results: `recovery-results.json`. Owner instructions: `docs/operations/recovery.md`.

## Limits

Development runs used local APFS storage. Other export filesystems, packaged installation, accessibility walkthrough and physical OS/crash rehearsal remain in U13/U14. A whole-machine rollback that also restores the Keychain cannot be detected locally; the guide requires explicit recovery with a new app identity and uncertain mirror history. No full-vault rollout is authorized by these test results.
