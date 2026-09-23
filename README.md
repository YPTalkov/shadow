# Shadow credential vault

Standalone local credential vault for a protected agent runtime. The [implementation plan](docs/plans/2026-09-23-2139-feat-standalone-agent-credential-vault-plan.md) defines the release gates. The project is under implementation and is **not approved for real credentials**.

The vault will use an owner-held master password and a KDBX file that can be opened in KeePassXC. Agent operations will use opaque references and a separate protected browser runtime. The Apple Passwords connector is a separate project; the [source contract](docs/contracts/credential-source-v1.md) defines its optional ingestion seam.

Development requires macOS on Apple Silicon, Swift 6, Python 3.12, `uv`, and KeePassXC. Run `uv sync --frozen` and `uv run --frozen pytest` for Python checks, and `swift test` for the Swift package.

Do not import or enter real credentials until the release record explicitly passes every gate and the owner approves the selected accounts and site.
