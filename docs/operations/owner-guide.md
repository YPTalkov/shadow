# Use Shadow

The current build is for synthetic credentials. Its two included website adapters serve the automated synthetic fixture; no real website is qualified yet.

## Create and import

1. Open Shadow. Enter and confirm a master password in the native secure fields. Keep it separately; Shadow does not save it.
2. Open **Import CSV** and select a local synthetic file. Map title, HTTPS website, username and password; map notes, TOTP and group only when present.
3. Review accepted/rejected counts and metadata. Resolve invalid rows or explicitly choose the valid subset, then import.
4. The original CSV remains plaintext. After checking the encrypted vault, manage that original file yourself. Shadow does not claim secure erasure from an SSD, snapshots or backups.

The owner catalog shows titles, usernames, HTTPS origins and groups. Notes, URL paths/query strings, passwords, TOTP and protected custom fields do not belong in agent metadata. Metadata copied from known protected values is withheld as additional protection.

## Connect ChatGPT and run a task

1. Unlock the vault and open **Agent Access**.
2. Choose **Sign in with ChatGPT**, open the fixed OpenAI sign-in page, and enter the displayed device code there yourself. Device-code login may need enabling in your ChatGPT security settings. Do not paste the code into a task or chat.
3. When Shadow says **ChatGPT connected**, select a model, set the request ceiling, and describe a task without credentials. Start it. The isolated task has a 15-minute maximum.
4. If the agent requests discovery, select the accounts it may see. This reveals bounded metadata and does not permit credential use.
5. A separate credential-use request names the account, destinations, actions and duration. Review each. A retained copy also requires its explicit one-session checkbox.
6. Use **Stop task**, **Revoke**, or **Lock vault** to end access. Completion closes that task's environment and permissions. Lock also clears its displayed output.

A useful live-model check, after signing in, is: “Run `printf shadow-ready`, call Shadow vault status, and report the fixed status. Do not request account access.” This needs no website credential. Successful subscription access is still a required owner-assisted qualification.

Agent output is untrusted text. It cannot approve a native request. Declining or ignoring a request grants nothing. Sign-out ends current access before removing Shadow's model credentials.

## Inspect and edit passwords

Choose **Open in KeePassXC…** from the vault. Shadow locks agent access and prepares an encrypted checkout. Enter the master password directly in KeePassXC. Save and close the editor, return to Shadow, enter the master password, and review the changes before applying. A failed, cancelled or abandoned edit preserves the managed vault. Do not edit the active `vault.kdbx` directly.

## Optional sources and retained accounts

Shadow works without any connector. The **Sources** panel can inspect and enroll a separately installed signed connector, refresh it, disable it, or remove its enrollment. Removing a source preserves imported encrypted accounts and ends old authority. Deletion, permission loss, uncertain history and conflicts remain visible; retention never implies agent permission. Refresh jobs requested by agents use the same enrolled native source and cannot supply a path, secret or producer payload.

## Back up and recover

Use **Recovery** to create/export an encrypted copy, choose an encrypted file for reviewed restore, show the vault folder, or review fixed diagnostics before export. Follow the [recovery guide](recovery.md) and check a backup independently in KeePassXC. Restoring never reinstates old grants.

The active directory is `~/Library/Application Support/Shadow/vault/`. Keep the master password and at least one verified encrypted copy separately from this disk.

## Security boundary and limits

Shadow supports its own isolated Codex VM. An unrestricted host agent with your filesystem access is outside this boundary. Model credentials stay in the native host; vault secrets pass only to the protected browser, whose website access is limited by a reviewed adapter and native approval. The agent receives approved metadata and bounded task results. The authenticated website necessarily receives its login secret.

Known-value filtering is additional protection, not proof against every encoding or a malicious website. No general DOM, browser screenshot, arbitrary JavaScript or raw browser error tool is exposed. Unsupported routes and challenges stop; they do not fall back to an unrestricted browser. Independent security review and a selected real site's qualification are required before real credentials.
