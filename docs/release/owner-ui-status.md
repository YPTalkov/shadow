# Owner panel qualification

Development evidence on Apple Silicon macOS 26.6.2. Synthetic credentials only.

Implemented native create/unlock/lock, metadata catalog, CSV selection, column mapping, preview, valid-row-only consent, commit/cancel, and original plaintext reminder. Master-password fields clear on submission and lock. Closing the last window quits after worker shutdown. Session resignation, sleep, and idle handlers request lock; full screen-lock and crash qualification remain in U11.

`sh scripts/test-swift.sh`: 21 passed. The native model test locks during an unfinished unlock and verifies the late result cannot publish an unlocked state. A second panel cannot acquire the same owner's configuration lease.

`swift run owner-ui-probe`: passed. The probe runs a real AppKit/SwiftUI window with the private Python worker and a temporary Keychain anchor: create, three-row CSV preview, import, catalog, lock. Only synthetic temporary data is used and removed afterward. Local view captures are at `.build/evidence/owner-{import,vault,locked}.jpg`; import and locked views were inspected. These are rendered view captures, not OS screenshots or proof of mouse/VoiceOver operation. OS window capture was unavailable. An initial split-view capture omitted the sidebar; a fixed five-section sidebar now renders with the controls.

Agent Access, Sources, and guided Recovery are explicit development states pending their implementation. KeePassXC handoff, native grant/revocation dialogs, retained-item approval, and final keyboard/VoiceOver walkthrough remain open. This report does not mark U6 or the release complete.
