# Owner panel qualification

Development evidence on Apple Silicon macOS 26.6.2. Synthetic credentials only.

Implemented native create/unlock/lock, metadata catalog, CSV selection, column mapping, preview, valid-row-only consent, commit/cancel, and original plaintext reminder. Master-password fields clear on submission and lock. Closing the last window quits after worker shutdown. Session resignation, sleep, and idle handlers request lock; full screen-lock and crash qualification remain in U11.

`sh scripts/test-swift.sh`: 21 passed. The native model test locks during an unfinished unlock and verifies the late result cannot publish an unlocked state. A second panel cannot acquire the same owner's configuration lease.

`swift run owner-ui-probe`: passed. The probe runs a real AppKit/SwiftUI window with the private Python worker and a temporary Keychain anchor: create, three-row CSV preview, import, catalog, lock. Only synthetic temporary data is used and removed afterward. Local view captures are at `.build/evidence/owner-{import,vault,locked}.jpg`; import and locked views were inspected. These are rendered view captures, not OS screenshots or proof of mouse/VoiceOver operation. OS window capture was unavailable. An initial split-view capture omitted the sidebar; a fixed five-section sidebar now renders with the controls.

## Exclusive editor handoff

The native panel creates an encrypted checkout, locks its worker and reserves the writer lease. A durable SQLite handoff record blocks ordinary unlock/writes after a restart. It opens only the checkout in the qualified KeePassXC 2.7.12 application, verifying its Apple Developer ID signature and expected team. No master password is passed to the editor. Resume requires closing KeePassXC, re-entering the current vault password, reviewing counts, and explicitly applying or cancelling.

The worker takes a stable bounded snapshot, validates the managed format, reconciles changes and preserves app-owned provenance for existing UUIDs. Changed entries receive a new revision; new UUIDs become unapproved local entries. A changed checkout after preview is rejected. Apply uses the normal encrypted generation transaction and the active master password/KDF. Checkout master-password changes are explicitly unsupported and leave the copy preserved. Apply and cancel-with-preserve keep encrypted copies; late saves cannot modify the active file. Only explicit discard removes the checkout.

`uv run --frozen pytest tests/storage tests/compat`: 36 passed, including an actual KeePassXC CLI edit/reconcile, changed password/group/history, stale review, missing file, master-password change refusal, and restart. `sh scripts/test-swift.sh`: 22 passed, including the native reservation, Keychain, worker restart and confirmation path. The extended live AppKit probe passed begin → review → apply → reopen → lock; `.build/evidence/owner-editor-review.jpg` was visually inspected. The editor application launch/manual unlock and VoiceOver walkthrough still need final qualification.

## Native consent and revocation

Agent Access now shows pending requests and active permissions. Catalog approval starts with no accounts selected. Credential-use approval separately names the native caller, account, exact credential/resource origins, actions and expiry. Retained-copy consent is explicit and bound to the current removal event/revision and one session. Timeout, denial, revision change, caller boot change and revocation cannot grant access. Prompts are bounded and throttled; repeated request IDs retain their result and changed arguments fail.

`sh scripts/test-swift.sh`: 28 passed. The consent cases cover scope separation, stale prompts, timeout, monotonic expiry despite a wall-clock rollback, caller substitution, request replay, throttling, revocation, and retained session binding. `uv run --frozen pytest tests/catalog tests/import tests/storage/test_worker_ipc.py`: 14 passed after adding private entry revisions. The live UI probe rendered a catalog grant and separate pending use request; `.build/evidence/owner-consent.jpg` was inspected, and beginning editor handoff cleared both before worker teardown.

Sources and guided Recovery remain pending. Mirrored accounts are deliberately unavailable to this panel's authority coordinator until U7 connects their native restriction ledger. Actual VM enrollment/requests, session teardown callbacks, catalog scope pagination, and keyboard/VoiceOver qualification remain integration work. Currently runtime access is closed, so no active VM session can overlap editor handoff. This report does not mark U6 or the release complete.
