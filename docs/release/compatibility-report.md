# Synthetic compatibility report

Date: 2026-09-23. Target: Apple Silicon macOS 26.6.2. This is a development qualification record, not a production release approval.

| Fixture | Outcome |
|---|---|
| managed-profile | KDBX 4.0, AES-256, Argon2id, 128 MiB, 3 iterations, 2 lanes passed |
| unchanged-save-twice | Distinct encrypted bytes; both reopened with the same synthetic content |
| wrong-password-corruption | Fixed error codes; no caller-visible library diagnostics |
| hostile-kdf-profile | Parsed header rejected an excessive memory request before decryption |
| keepassxc-edit-reopen | KeePassXC 2.7.12 edited title; PyKeePass 4.2.0 preserved group, password, and protected custom property; KeePassXC reopened the subsequent save |
| protocol-major | Public/private schema version 1 checked; guest package import scan passed |

`uv run --frozen pytest tests/compat`: 7 passed. `swift build`: passed. `swift test`: blocked because this machine's Command Line Tools installation does not provide the `Testing` or `XCTest` modules.

| Artifact | SHA-256 |
|---|---|
| `uv.lock` | `5c2af48d2484e036ec6e8ec8b176b532fbef2359792e045425e6d78e845acd2b` |
| KeePassXC 2.7.12 CLI executable | `a5b8a8662d54d82bbb77bc458836aec9bc7a1576280509dc858676aa5922a2d6` |
| installed PyKeePass 4.2.0 `pykeepass.py` | `6e1842c4893bcff13ecc8bbf47c727f6b37ae8ae3e505e91a2fe64e44a241726` |

Python: 3.12.13; Swift: 6.3.3. A final packaged dependency inventory, vulnerability review, VM image hashes, and full Swift test pass remain release requirements.
