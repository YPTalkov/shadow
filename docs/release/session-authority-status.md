# Native session authority qualification

The native session coordinator serializes one protected browser session. It checks
the enrolled caller/boot, account revision, exact adapter credential origin and
native grant at each authentication stage and after private credential resolution.
Revocation closes the driver's authority synchronously before asynchronous teardown.

Private credential resolution reads the current encrypted generation and returns
only the selected entry's username/password and explicitly requested TOTP. It
rejects stale revisions/origins, ambiguous IDs, recycled/archived/conflicted entries
and oversized fields. Presence alone does not authorize a retained credential;
the native grant and independent restriction ledger still govern use.

The bounded SQLite journal holds opaque IDs, argument digests, timestamps, states
and fixed codes. It stores no credential payloads, metadata, browser state or
grants. Submit permission is acknowledged only after a FULL/fullfsync transaction.
Restart converts unfinished submitted work to `outcome_unknown`, and other
unfinished work to `cancelled`. Repeated requests recover status before resolving
expiring account references or claiming a retained-copy grant again. Receipts
expire after seven days; live sessions and authority are never restored.

Evidence (2026-09-24):

- `bash scripts/test-swift.sh --filter 'protectedSession|nativeWorkerUsesKeychain|operationJournal|publicAPI'`: 7 passed.
- Real native worker/Keychain/CSV/private resolver integration passed with synthetic credentials.
- Native service tests cover stage revocation before resolution, after resolution,
  after submit, retained approval retry, changed arguments and caller boot binding.
- Journal tests cover restart, terminal-state immutability, capacity/retention,
  private path permissions, symlinks and competing writers.

## Real VM integration

The production driver now runs the same authority flow against the actual Linux
VM. Its instance-bound private channel carries only staged commands and selected
credentials; the agent has no route to it. The root guest supervisor and
unprivileged worker enforce their own leases. Native egress renews every two
seconds, cannot exceed ten seconds, and cannot revive after expiry. Native output
checks the continuous-clock lease before returning a usable session reference.

The qualification image adds only a synthetic CA bootstrap; production images
omit the fixture CA and probe entry points. Loopback routing exists only in the
diagnostic executable's fixed `app.shadow.test` mapping. Production destinations
continue to reject loopback/private addresses and `.test` names.

Verified on the real VM, with encrypted synthetic CSV input and native Keychain:

- Login succeeded through certificate-verified HTTPS; retry returned the prior
  session with exactly one website submission; close removed the usable session.
- Revocation after receipt of the POST, while the website withheld its response,
  yielded `outcome_unknown`; retry did not send another POST.
- Suspending the native process for 12 seconds invalidated the session before it
  could be returned on resume. This proves interruption handling at the public
  status boundary; it does not claim a measured guest process exit timestamp.
- Console scans found no synthetic credential/cookie canaries.

Commands: `scripts/run-browser-probe.py --session`, `--interrupt revoke`, and
`--interrupt suspend`, run through `uv run --frozen python` after signing the
diagnostic executable with the virtualization entitlement. Machine-readable
results are the adjacent `native-session-*-results.json` files.

Targeted checks after cleanup: 43 Python tests and 11 native tests passed. Python
compilation and Swift builds passed; no Python lint/typecheck runner is configured.
Those counts describe this component checkpoint. The native owner panel and
packaged runtime are now connected; see [package qualification](package-status.md).
Real-site qualification and independent attack assessment remain open.
