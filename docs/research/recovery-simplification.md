# Recovery implementation review

Applied the CE reuse, quality and efficiency rubrics serially to the U12 changes after `4ab6663`, following the workspace's agent mapping. Settled KTD1–KTD10 boundaries remain in place.

- Reuse: one applied change delegates the store's directory flush to the identical encrypted-file helper. Existing private worker IPC, Keychain anchors and native owner controls carry recovery.
- Quality: one applied change removes an unused test import. Native review exposes counts and uncertainty; account identities stay in the private handshake. A separate Recovery view keeps the panel manageable.
- Efficiency: no behavior-preserving finding applied. Daily maintenance runs once per UTC day, and restriction recovery inserts the complete batch before anchor advancement.
- Two candidates skipped: combining normal append and recovery bootstrap could change transaction/anchor ordering; caching backup verification could remove a required integrity check. Neither tradeoff is justified as cleanup.

Behavior fixes were verified separately: fixed-size file reads, actual file-write fault injection, retained restriction projection, and cancellation while waiting for a previous worker to close. Existing atomic-save tests provided characterization; new recovery and native integration tests were added for the new transaction. This was not a test-first implementation claim.

Verification: 74 Python storage/recovery/connector tests; 11 Swift test functions with six restore-history cases; actual native UI export/restore and independent KeePassXC inspection. Swift build supplies compilation/type checking. No standalone Python lint/typecheck runner is configured. This record is not a final CE code-review or independent security-review receipt.
