# Protected authentication challenge qualification

This is synthetic capability evidence for U10, not a production release approval.

## Implemented capability

- Packaged `synthetic-v1` and `synthetic-sso-v1` adapters share bounded list/detail projections. The SSO fixture starts on the resource origin, redirects to a separate credential origin, and returns to the resource origin over certificate-verified HTTPS.
- Native authority checks surround password and TOTP fill/submit, selected-entry resolution, verification, and output. TOTP is requested from the private vault worker only for a packaged adapter with a qualified challenge definition. RFC 6238 SHA1/SHA256/SHA512 vectors pass.
- A known OTP challenge without a stored seed produces `needs_owner_action`, an opaque checkpoint, and no session reference. The owner sees a native account/caller/origin header and a private `VZVirtualMachineView`. Agent operations cannot enter a code, inspect the view, or complete the checkpoint.
- Owner completion is one-shot and rechecks the live grant, account revision, and VM lease. The worker verifies the destination before opening observations. Owner cancellation, revocation, and expiry close browser authority synchronously.
- Isolated-world listeners retain bounded owner-entered OTP values in trusted memory for output filtering after navigation. Generated codes use the same protection. Seeds, codes, passwords and cookies never enter the agent contract.
- Unknown passkey/recovery layouts return a fixed `unsupported_challenge` code. Because the password submission already occurred, the durable operation state remains `outcome_unknown`; repeating the request does not resubmit.

## Verification

Commands use the checked-in fixture and private test gateway. No real account was accessed.

```sh
uv run --frozen pytest tests/browser tests/protocol
bash scripts/test-swift.sh --filter 'OwnerChallenge|protectedSession|protectedOwner|protectedTOTP|operationJournal|ownerModel'
uv run --frozen python -m images.build_browser --runtime-only --profile probe
uv run --frozen python scripts/run-browser-probe.py
uv run --frozen python -m images.build_browser --runtime-only --profile qualification
uv run --frozen python scripts/run-browser-probe.py --flow totp
uv run --frozen python scripts/run-browser-probe.py --flow sso
uv run --frozen python scripts/run-browser-probe.py --flow owner
uv run --frozen python scripts/run-browser-probe.py --flow unsupported
uv run --frozen python scripts/run-browser-probe.py --flow owner_cancel
uv run --frozen python scripts/run-browser-probe.py --flow owner_timeout
```

The native probe requires an ad-hoc signature with `packaging/virtualization.entitlements` after every relink. There is no configured Python lint/typecheck runner. Swift compilation checks native types.

Unit/contract results: **88 Python tests and 9 native tests pass**. Real Chromium scenarios exercise generated TOTP, owner completion, redirected SSO, cancellation, lease expiry, early completion, unsupported challenge, replaced input, and changed form action. The native HTTPS flows use encrypted CSV import, Keychain generation anchors, actual VM input devices, durable receipts, and list/detail navigation. Native owner input is automated through the actual private VM view with synthetic keyboard events, followed by the same native completion entry point used by Continue.

The actual timeout probe observed closure 119,989 ms after its first pending-status poll, with zero OTP submissions and no surviving checkpoint/session. It uses the production 120-second deadline and native two-second renewal loop, without shortening the timer for the test.

The checked-in result files identify the exact runtime image hashes for each execution. The image builder keeps the production manifest separate from diagnostic profiles. Qualification images contain the synthetic CA; production images exclude it.

## Failures found and corrected

1. The first implementation filtered generated codes but did not retain owner-entered codes after navigation. Isolated-world capture and reflection assertions now cover both paths.
2. Closing the worker lease before reporting an authentication failure discarded `unsupported_challenge`. Output is now sealed first; the private channel reports its fixed terminal code and waits at most five seconds for native teardown. The browser context is already destroyed. Native revocation and the root watchdog still terminate the VM.

## Remaining release gates

The owner-selected real site has not been qualified. Arbitrary recovery/passkey flows, selectors, JavaScript, screenshots, downloads and settings are unsupported. A known-value filter does not prove that arbitrary transformations of secrets are safe; the plan's R10 residual limits remain. Application enrollment, packaged two-VM tests and synthetic lifecycle/recovery checks are now recorded in [package qualification](package-status.md). Physical OS/owner rehearsal and independent security review remain required.
