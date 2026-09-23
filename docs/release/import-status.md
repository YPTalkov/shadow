# CSV import implementation status

The host-private importer accepts a selected regular-file descriptor, strict UTF-8 CSV with optional BOM, explicit header mapping, a 20 MiB file cap, 50,000-row cap, and 64 KiB field cap. Preview returns only count, validation codes, and at most 50 metadata rows. Password, notes, TOTP, unmapped columns, and URL paths/query values remain outside the preview. Commit rechecks file identity/content, writes through the encrypted generation transaction, supports explicit valid-row-only selection, and records an encrypted operation ID for idempotent retry. It neither evaluates spreadsheet formulas nor deletes the source CSV.

`uv run --frozen pytest tests/import`: 4 passed with synthetic data on 2026-09-23.

This is a component result, not a complete owner flow. The native file picker, mapping UI, secure unlock, and import confirmation are not wired yet. The app must display the plaintext-source and post-import cleanup guidance before any real import. No real CSV has been selected.
