# Recover an encrypted vault

This development build is qualified with synthetic credentials. The packaged release and independent security review are still required before real use.

## Know what to keep

Your files normally live in `~/Library/Application Support/Shadow/vault/`. Recovery → **Show vault folder** opens this location.

- `vault.kdbx` is the active encrypted vault.
- `backups/previous-*.kdbx` holds the generation before the last mutation.
- `backups/daily-YYYY-MM-DD-*.kdbx` holds the first verified generation copied on that UTC day. Shadow retains 30 days while it runs; it cannot make backups while the app is closed.
- `backups/recovery-*/` preserves the selected file and the files replaced by a restore. These recovery copies and older, unrecognized backup files are never automatically rotated.
- `restriction-recovery-*/` preserves damaged restriction bookkeeping replaced during explicit recovery. It contains identifiers and restriction events, never credentials.

Keep the master password separately. Shadow does not store it. Losing that password prevents decryption, including in KeePassXC. A backup remains encrypted with the password used when it was created.

## Export a copy

1. Unlock the vault and open Recovery.
2. Choose **Export encrypted copy…**, then choose a new filename on your backup destination. Existing files are preserved rather than replaced.
3. Check the copy in KeePassXC using its master password. Keep at least one verified copy away from the active disk. Shadow only copies to an external destination when you choose to export.

Automatic backups are local and contain only encrypted KDBX bytes. They cannot protect against loss of the entire disk. The app does not export an agent grant, unlock key or model sign-in with them.

## Restore through Shadow

1. Finish or cancel any editing checkout, and close KeePassXC.
2. Open Recovery → **Choose encrypted file…**. Select a local `.kdbx` copy and enter that file's master password.
3. Choose **Check and review restore**. This ends current agent sessions and grants. A wrong password, damaged file or unsupported encryption profile prevents publication.
4. Check the account counts. Shadow preserves current files and newer restriction events. Restored source observations become uncertain until refreshed; historical restrictions still require retained-copy approval.
5. If restriction history is missing, damaged or older than its independent checkpoint, read and acknowledge the uncertainty. Shadow will mark every restored mirrored entry as history unknown. It cannot reconstruct facts that are no longer available.
6. Choose **Restore reviewed snapshot**. The review expires after five minutes. The selected snapshot is frozen at review time; selecting another file requires another review.
7. Unlock with the selected file's password. Check the catalog and retained-item status, refresh trusted sources when appropriate, and approve each agent anew.

Restore never reinstates old approvals. Local accounts are unapproved; mirrored accounts carry preserved restrictions or history-unknown restrictions. An ordinary current-source grant cannot bypass retained-copy review.

If storage fills or power is lost, preserve all files. Reopen Recovery and select a verified encrypted copy again. A checkpoint mismatch deliberately blocks ordinary unlock; do not delete bookkeeping to bypass it. Recovery evidence contains both the selected snapshot and the previous files once the backup stage has completed. A failure before that stage leaves the current vault untouched.

## Recover without Shadow

1. Quit Shadow. Make another copy of a verified `.kdbx` file before editing it.
2. Open that copy with qualified KeePassXC 2.7.12. Enter the file's master password directly in KeePassXC.
3. Inspect the entries and recover the information you need there. This does not require the connector, Shadow's database or its Keychain entries.
4. To return to Shadow, use the reviewed restore procedure above. Editing or inspecting an exported copy never writes through to the active vault.

## Recover a whole system or move to a clean installation

A filesystem rollback that leaves the current Keychain intact is detected. A whole-machine rollback that also restores older Keychain state cannot be detected from that machine alone.

For a known whole-machine rollback or lost app identity:

1. Quit Shadow and preserve the entire old `~/Library/Application Support/Shadow/` folder, plus an independently verified encrypted KDBX copy.
2. Move the preserved app folder aside; keep it until recovery has been checked. Launch Shadow to create a fresh app identity. Do not copy old ledgers or approvals into the new folder.
3. Use Recovery to restore the verified KDBX copy. Acknowledge the missing history. All restored mirrored entries enter history-unknown retained-copy review, and all local accounts need new approval.
4. Re-enroll any trusted connectors and agents. Verify the recovered data independently in KeePassXC before considering cleanup of old copies.

The app never automatically deletes the last verified recovery generation, live retained credentials, or recovery evidence. Uninstalling the app should preserve its data folder and your exports.
