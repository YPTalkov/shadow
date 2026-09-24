# CE implementation review

- Run: `20260924-071758-a0230df5`, 2026-09-24.
- Skill: `ce-code-review`, full depth, `mode:agent`, against `origin/main`.
- Reviewed source: `1b50398bbe1630b624fb7691499be50420c97773` plus the staged packaging slice; 273 files in the selected scope.
- Receipt status: `complete`. Full-plan verdict: **Not ready**.
- Concrete code findings retained: 0. Caller-applied review fixes: 0.

Correctness, testing, maintainability, agent parity, security, performance, API contracts, reliability and Swift/UI rubrics were applied serially in the implementation context, following the owner's AGENTS tool mapping. This is self-review with shared context, not nine independent reviewers. The empty findings set required no finding-validator batch.

The external adversarial pass is degraded. Claude returned an OAuth refresh failure and rejected the configured model; the replacement Grok CLI rejected `--prompt-file`. Neither produced a usable review artifact or an attested serving model. Both managed jobs reached terminal state and their temporary job directories were removed. No external agreement is claimed.

The review traced native consent/revision/boot scope into protected sessions and durable submit receipts; worker publication and recovery anchors; lock/cancellation epochs; host OAuth custody; generated agent contracts; isolated-world authentication and safe views; image/resource verification; and the fidelity limits of the synthetic harnesses. No plan decision was reversed.

Outstanding requirements remain in the [release decision](go-no-go.md) and [requirement matrix](security-evidence.md). The independent security review, live provider/site, physical OS and owner accessibility/recovery checks are open. Publishing a draft source milestone does not approve real credentials.

The detailed machine-readable run is local at `/tmp/compound-engineering-501/ce-code-review/20260924-071758-a0230df5`; this durable receipt does not depend on that temporary directory surviving.

## Image maintenance follow-up

The subsequent dependency scan found two HIGH advisory matches in unused GStreamer components, public updates for 18 packages, and missing display-overlay inventory records. A repeat build exposed a case collision in kernel module extraction on macOS. These are separate findings discovered after the review scope above.

The follow-up applies correctness, security, reliability, testing and maintainability rubrics serially to the package lock, Debian reconciliation helper, archive-based module reader and CI interpreter setup. Reconciliation checks identities before publication, checks both replacement and retained dependencies, preserves shared files/directories, removes retired payloads and updates the scanner inventory. Module bytes remain archive data and the module archive is verified against the pinned release. No package script runs on the host. The CI change repairs an observed unavailable `setup-python` version by installing the same exact runtime through uv.

Twelve image tests cover archive traversal/links, usr-merge, package removal/upgrades, shared files, Pre-Depends, replacement dependencies, metadata identity and case-distinct module bytes. Actual image checks verify all 205 retired payloads absent, all 515 package dependency relations satisfied, case-distinct module hashes preserved, and all 37 Chromium scenarios passing. Advisory coverage and unresolved findings are explicit in the [dependency assessment](dependency-assessment.md). This follow-up is self-review; the independent review and full-plan verdict remain unchanged.

CI then exposed the older SDK's nonisolated generated `VZVirtualMachine.start()` method. The shared startup bridge now calls the callback API on `MainActor` and resumes only its completion result. A Swift/reliability pass checked actor ownership, error propagation and unchanged caller generation checks. The local build, 77 native tests and actual two-VM authenticated task pass with that bridge. Hosted CI separately checks compilation against its SDK; this does not broaden the qualified production OS tuple.

The next compiler pass required explicit `MainActor` isolation on both owner-operation closures and their deferred publication closures. The two private helper signatures now encode that existing ownership. Generation checks still precede publication, and all 77 native tests pass, including interrupted unlock/restore behavior. This is a compatibility repair, with no relaxed concurrency checking or `unchecked Sendable` conformance.
