# Release decision: synthetic qualification only

The local implementation and relocatable application are available. The full project is **not production-ready**. G1–G6 and the owner's real-data rollout checkpoint remain required by the reviewed plan. Source publication is authorized; public binary distribution and real-vault import are not part of this checkpoint.

## Verified on the target Mac

- Encrypted CSV import, KeePassXC inspection/editing, separate native approvals, source retention and reviewed recovery.
- Real Codex CLI inside its production Linux image, with code tools and MCP, for all three offered models against a synthetic provider.
- Two-VM authenticated login/read and source-removal interruption, using the packaged worker and agent plus a separate HTTPS fixture browser image.
- Exact production browser boot and host-silence shutdown without the fixture CA or gateway exception.
- Sixteen installation, relocation and tamper checks against the sealed application.
- Packaged 5,000-row import in 1.05 seconds and 10,000-entry catalog search p95 of 3.43 ms; six protected-value reflection classes and persistent canary scans pass.

Each receipt describes its own image and harness identity. The qualification browser image is never bundled in the app. A passing synthetic provider or test-site receipt is not a live-provider or real-site result.

## Open gates

| Gate | Evidence still required | Next action |
|---|---|---|
| Live model access | Native ChatGPT device sign-in, refresh and a real streamed Codex task | Owner signs in through Shadow's Agent Access panel using a test vault; never paste the code or password into an agent prompt. |
| First production adapter | Owner-selected low-risk website and exact read-only task; adapter-specific destination, challenge and safe-output qualification | Owner names the site/task. Implement and qualify that adapter before asking for real account rollout. |
| OS and owner rehearsal | Installed-app physical lock, sleep/wake, quit/crash; accessibility and disaster recovery walkthrough | Run the [remaining qualification checklist](../operations/remaining-qualification.md) with the owner present. |
| Dependency/security review | Native and guest dependency assessment; independent isolation, IPC, egress, output, persistence and retention review | A reviewer independent of this implementation assesses the pinned source/package. CE self-review and canaries do not replace this. |
| Real-data rollout | All above evidence accepted and G1–G6 passed | Obtain separate owner approval for a small named subset and site. Full-vault import is a later decision. |

The CE review found no new concrete code defect in its serial local pass. External CLI review attempts produced no usable review: Claude authentication/model dispatch failed and Grok rejected the adapter's command option. This does not count as an independent security assessment.

## Failure and recovery

Stop the agent and lock Shadow if a fixed operation code is unexpected, a view becomes unsupported, or a resource/authority check fails. Preserve encrypted files and the build receipt. Export only the native reviewed diagnostic code/count report. Do not enable raw DOM, network, model-request or credential logging to diagnose real-account failures.

To roll back, quit the app and restore the previous complete bundle; preserve the data folder and Keychain history. Use [reviewed recovery](../operations/recovery.md) if storage history is inconsistent. Never delete the only encrypted copy or clear a restriction ledger to resume access.
