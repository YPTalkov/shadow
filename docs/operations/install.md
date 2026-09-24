# Install the personal build

This build is for synthetic qualification on Apple Silicon macOS 26.6.2. It has a local ad-hoc signature, not a Developer ID signature or notarization. Independent security review, live model sign-in and real-site qualification remain open. Use test credentials only.

## Build

The build machine needs Swift 6.3.3, Python 3.12, uv, squashfs-tools and the image-building tools listed in [images/README.md](../../images/README.md). The app itself bundles Python and its VM images.

```sh
uv sync --frozen
uv run --frozen python -m images.fetch_probe
uv run --frozen python -m images.build_probe --profile agent
# Follow images/README.md to fetch and assemble the browser base first.
uv run --frozen python -m images.build_browser --runtime-only --profile runtime
uv run --frozen python scripts/build-local-app.py
uv run --frozen python scripts/qualify-local-app.py dist/Shadow.app
```

The result is `dist/Shadow.app`; `dist/build-receipt.json` records its executable and inventory hashes. Keep the receipt outside the app. Rebuilding changes the signed identity and requires qualification again. The build script only replaces its disposable `dist/Shadow.app`, never an installed copy or vault.

## Open or install

Open `dist/Shadow.app` locally, or copy it to `~/Applications/Shadow.app` while Shadow is closed. Keep the complete bundle intact. It can run outside the source checkout and does not use Homebrew or the development virtual environment.

To verify a copied bundle before opening it:

```sh
"$HOME/Applications/Shadow.app/Contents/MacOS/Shadow" --verify-installation
```

The fixed result must be `SHADOW_INSTALLATION=pass`. Startup verifies the local signature, exact resource inventory and qualified macOS/architecture. Modified, extra or missing resources and external interpreter links prevent protected operations. A macOS update deliberately requires a fresh qualification/build. Re-signing a changed resource without updating the inventory also fails.

Local signing detects changes relative to this build; it does not establish a publisher identity. Keep the trusted build receipt and source revision. This boundary does not defend against a compromised macOS administrator or an attacker allowed to replace the entire trusted application and its receipt.

## Upgrade, rollback and remove

Quit Shadow and export a verified encrypted backup before replacing the app. Preserve the previous bundle and receipt. If an update cannot open, restore the previous app, preserving the data folder. If storage history is inconsistent, use the [reviewed recovery procedure](recovery.md); do not delete a ledger to bypass a checkpoint.

To uninstall, quit and remove only the application bundle. Keep `~/Library/Application Support/Shadow/`, exported KDBX copies, and the master password. Uninstall does not erase the vault, backups or Keychain items. Public package distribution is not part of this personal build.
