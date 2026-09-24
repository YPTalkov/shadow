# CSV import implementation status

The host-private importer accepts a selected regular-file descriptor, strict UTF-8 CSV with optional BOM, explicit header mapping, a 20 MiB file cap, 50,000-row cap, and 64 KiB field cap. Preview returns only count, validation codes, and at most 50 metadata rows. Password, notes, TOTP, unmapped columns, and URL paths/query values remain outside the preview. Commit rechecks file identity/content, writes through the encrypted generation transaction, supports explicit valid-row-only selection, and records an encrypted operation ID for idempotent retry. It neither evaluates spreadsheet formulas nor deletes the source CSV.

`uv run --frozen pytest tests/import`: 4 passed with synthetic data on 2026-09-23.

The count above is the initial component checkpoint. Native file selection, mapping, secure unlock, confirmation and plaintext-source guidance are now wired and exercised by the packaged owner harness; see [package qualification](package-status.md). The owner's manual walkthrough remains open. No real CSV has been selected.
