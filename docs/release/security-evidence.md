# Requirement evidence and outstanding gates

This matrix describes observed synthetic qualification. “Partial” means the named remaining evidence is required; it is not a passed guarantee. The [plan](../plans/2026-09-23-2139-feat-standalone-agent-credential-vault-plan.md) remains authoritative.

| Requirement | Observed evidence | Remaining qualification |
|---|---|---|
| R1 standalone | Native create/import/edit/recovery without Apple; combined two-VM task | Owner live-model and selected-site rehearsal |
| R2 portable storage | KDBX 4.0/AES-256/Argon2id; independent KeePassXC round trips and packaged read | Owner recovery sign-off |
| R3 import | Mapped CSV preview, descriptor stability, bounded hostile inputs; packaged import and sink scans | Owner walkthrough |
| R4 catalog | Scoped consent, references, pagination, metadata projection, 10,000-entry benchmark | Independent boundary review |
| R5 non-disclosure | Model/console/persistent canary checks; protected fields and hostile-view fixtures | Full independent secrecy assessment; real-site behavior |
| R6 isolation | Real Linux root attacks, no NIC/share/swap, cross-role socket denial, immutable disks; packaged agent checks | Independent isolation review and additional concurrent-instance attack assessment |
| R7 authority | Separate native discovery/use approvals, revision/boot/grant scope, retained-event approval | Owner approval rehearsal |
| R8 atomic auth | Native worker to protected browser over private IPC; one HTTPS submission, safe retries, TOTP and owner challenge | Selected real site |
| R9 post-login | Real Codex observes, clicks and extracts bounded report status inside protected browser | Selected real site's read-only task |
| R10 capabilities | Synthetic-only capability disclosure; fixed manifests; unsupported/drift failures | Owner-selected adapter and qualification |
| R11 retention | Source removal preserves encrypted entry, restricts authority before publication and interrupts active two-VM task | Independent source/persistence review |
| R12 uncertainty | Partial coverage/access loss/conflicts; reappearance and restore keep restrictions | Owner source-state walkthrough |
| R13 ingestion | Conformance, exact retry, stable IDs, conflicts, private signed producer and scoped refresh jobs | Production connector separately qualified by its project |
| R14 controls | Native UI screenshots and packaged-worker create/import/consent/edit/source/recovery rehearsal | Owner and accessibility walkthrough |
| R15 lifecycle | Lock, worker kill, 12-second host suspension, lease expiry, old-boot rejection, fixed receipts | Physical screen lock/sleep/wake/quit/crash rehearsal on installed app |
| R16 persistence | Fault-injected commit/recovery, encrypted previous/daily backups, restore and KeePassXC inspection | Owner disaster-recovery sign-off; physical power-loss evidence not claimed |
| R17 local path | Fixed host relay destination, no guest model credentials, native HTTPS allowlist, no cloud browser | Live provider and site qualification; independent network-path review |
| R18 parity | Shared schemas, CLI/MCP/PTC native harness, real Codex code-tool/MCP path | Final owner-selected task through each applicable surface |
| R19 connector | Versioned private contract, fake producer conformance, native identity/key custody, refresh jobs | Apple integration remains separate; not a standalone prerequisite |
| R20 release evidence | Installable sealed local bundle, exact hashes, automated receipts and explicit no-go | G1–G6 must all pass before real credentials |

## Acceptance examples

| Example | Result |
|---|---|
| AE1 standalone CSV/login/task | Synthetic native import plus real Codex two-VM task pass; live owner site pending |
| AE2 separate permission | Catalog permission does not authorize login; separate native use approval passes |
| AE3 source deletion | Encrypted retention and active-session interruption pass |
| AE4 source access loss/partial scan | Conformance and restriction tests pass; no inferred deletion from incomplete coverage |
| AE5 owner/source conflict | Conflict and editor reconciliation tests pass; native source-removal/editor rehearsal passes |
| AE6 malicious content | Hostile adapter/view/challenge fixtures and protected-value projections pass within their stated schemas |
| AE7 restore | Native intact/lost-history recovery and independent KeePassXC read pass; old grants stay invalid |
| AE8 hostile agent | Real root no-share/no-network/cross-role socket tests pass; independent attack review remains |

## Release decision

G1 format checks pass and the host Python advisory scan is clear; full dependency review remains partial. G2–G5 have the synthetic results above and the specified coverage limits. G6 remains open. No real credential rollout is approved, and no full-production secrecy claim is made.

Production logging has no raw credential/DOM/network capture mode. Diagnostic harnesses and synthetic fixtures are outside the application bundle. A clean canary scan proves only the tested values and sinks; it does not prove resistance to arbitrary transformed echoes or a compromised destination/kernel/administrator.
