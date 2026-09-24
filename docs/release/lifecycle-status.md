# Lifecycle and diagnostic qualification

U11 implementation evidence on macOS 26.6.2 (25G83), arm64. This is not the final packaged G5/G6 assessment.

## Authority closure

- Lock and cancel buttons, quit, screen/display sleep, system sleep/wake and user-session transitions revoke on the current MainActor turn. Worker and VM teardown follows asynchronously.
- The owner inactivity deadline uses `mach_continuous_time`, advances during sleep, and resets on local owner input. Pending consent expiry also runs while another owner panel is visible.
- Explicit weak-owner revocation subscriptions replace chained callbacks. Browser/egress authority closes before agent output channels. Session shutdown removes its subscription; dead owners are pruned.
- Unexpected vault-worker exit notifies the owner supervisor. Every protected browser checkpoint also checks worker liveness, independently of callback delivery. Expected worker shutdown does not report a crash.
- Browser VM failure and host suspension remain covered by the independent native/guest/egress deadlines and the prior native-session evidence.

## Diagnostics

The private receipt database now aggregates UTC-day counts from a closed `AuditCode` enum. No API accepts arbitrary event text. Reports contain only schema version, retention days, dates, codes and counts. Receipt reconciliation counts cancelled/ambiguous operations without replaying them.

Storage is bounded to 4 MiB with 4096-byte SQLite pages, secure deletion, seven-day pruning at startup and during active maintenance, and bounded counters. Reports reject unknown stored codes and are capped at 64 KiB. The native Recovery panel previews an immutable report before its owner-selected export; the exported bytes match the preview. There is no upload path.

Native core dumps are disabled before the owner application initializes, and the private Python worker already disables core dumps. Product code does not print raw errors, request bodies, browser content or connector stderr. OS-managed crash/diagnostic collection still requires the final packaged inspection.

## Verification

- Eighteen targeted Swift tests cover the notification bridge, synchronous locking, observer order/removal, grant expiry, worker SIGKILL versus intentional exit, continuous-clock inactivity, receipt recovery, diagnostic retention, unknown stored codes and oversized files.
- Actual encrypted-vault → HTTPS browser authentication → vault-worker SIGKILL → status/retry: no usable old session and exactly one credential submission. Exact VM hashes are in `lifecycle-worker-results.json`.
- `owner-ui-probe` passed import/source/editor/reopen/lock plus diagnostic preview and exact-byte export. `.build/evidence/owner-diagnostics.jpg` was visually inspected.
- Swift compilation and `git diff --check` pass. No Python source changed in this unit except the existing test runner's added worker-interruption option.

```sh
bash scripts/test-swift.sh --filter 'lifecycleNotification|diagnosticsReject|revocationObservers|ownerLifecycle|vaultWorkerCrash|diagnosticsRetain|ownerIdle|protected|ownerLock|consent|catalog|operationJournal'
uv run --frozen python scripts/run-browser-probe.py --interrupt worker
.build/arm64-apple-macosx/debug/owner-ui-probe
```

Resign `vm-boot-probe` with the virtualization entitlement after a Swift relink.

## OS qualification still required

Apple documents [workspace session transitions](https://developer.apple.com/documentation/appkit/nsworkspace/sessiondidresignactivenotification) as user switching and [CGSessionCopyCurrentDictionary](https://developer.apple.com/documentation/coregraphics/cgsessioncopycurrentdictionary%28%29) as window-server session information. They do not document the extra `com.apple.screenIsLocked` notification or `CGSSessionScreenIsLocked` key as stable public contracts. Shadow uses both extra signals alongside public sleep/session notifications and console-state checks.

Injected notification tests prove handler behavior, not OS emission. Physical screen lock, sleep/wake, app crash/reboot and OS diagnostic inspection remain in the packaged U13/U14 rehearsal for each supported OS. This run did not lock the owner's host or change its system-wide diagnostic settings.
