# Shadow credential vault

Standalone local credential vault for an isolated Codex runtime on Apple Silicon macOS. A locally signed application and synthetic qualification tools are implemented. **Real credentials are not approved:** live ChatGPT sign-in, a selected real website and independent security review remain release gates.

Shadow stores credentials in an encrypted KDBX file recoverable with KeePassXC. Native controls manage import, separate discovery/use approvals, revocation, source retention, editing and recovery. Codex and the protected browser run in separate Linux VMs without host shares or network devices. ChatGPT sign-in stays in the host Keychain; approved website traffic passes through the native HTTPS gateway.

- [Build and install](docs/operations/install.md)
- [Owner guide](docs/operations/owner-guide.md) and [recovery](docs/operations/recovery.md)
- [Agent API, CLI, MCP and PTC](docs/agent-integration.md)
- [Optional connector integration](docs/operations/connector-integration.md)
- [Implementation status](docs/work-status.md) and [release plan](docs/plans/2026-09-23-2139-feat-standalone-agent-credential-vault-plan.md)
- [Release decision and outstanding checks](docs/release/go-no-go.md)

The Apple Passwords connector is a separate project. This app does not collect Apple passwords itself.

Development requires macOS on Apple Silicon, Swift 6, Python 3.12, `uv`, and KeePassXC. Run `uv sync --frozen` and `uv run --frozen pytest` for Python checks, and `sh scripts/test-swift.sh` for the Swift package.

Do not import or enter real credentials until the release record explicitly passes every gate and the owner approves the selected accounts and site.
