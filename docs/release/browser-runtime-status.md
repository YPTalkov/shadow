# Protected browser runtime qualification

This is component evidence for U9. The owner application does not yet expose a working protected login. Native credential delivery, per-session command serialization, persistent operation receipts, safe observation adapters, challenges and production supervision remain in progress.

## Tested runtime

- Apple Virtualization browser device profile: two CPUs, 4 GiB RAM, no NIC or host share, read-only SquashFS disk, tmpfs for mutable state, private Virtio display and two USB input devices.
- Alpine Linux 6.12.110 kernel, with Ubuntu Noble userspace from the pinned official Playwright Python 1.63.0 ARM64 OCI manifest. Chromium 153.0.8010.12 runs headed as UID 1001 with its namespace sandbox enabled.
- Xorg and NSS tooling are selected from signature-verified Ubuntu indexes and recorded in `images/display-packages.lock.json`. Package maintainer scripts never run on the host. The selected package versions need the final dependency audit before release.
- The image assembler verifies hashes, retains guest links as archive metadata, applies whiteouts, rejects traversal and normalizes Debian `/usr` merge paths. It never extracts guest links onto the host filesystem.

The checked image hashes and result markers are in `browser-probe-results.json`. The synthetic probe boots, completes its checks and powers off in about six seconds on the development Mac. This is not a startup-time guarantee for the finished application.

## Authentication and output

The worker captures the document and exact form nodes inside a Chromium isolated world. Website scripts cannot replace that world's DOM prototypes or checkpoint. It rechecks document/frame identity, visibility, field purposes, form action, method and target before credential resolution, fill and submit. Native-authority callbacks bracket each phase. The observation gate remains closed until success and a fresh permitted document are verified.

Ten scenarios ran in actual Chromium: successful login, changed form action, injected frame, navigation, replaced password node, input-event mutation, submit-button mutation, lease revocation, failure after submit, and poisoned website DOM prototypes. Changed state prevents submission; failure after submission returns `outcome_unknown` and never retries.

A separate loopback HTTPS fixture exercised a real CONNECT tunnel over the browser VM socket, certificate validation, one password submission, an HTTP 303 redirect, a Secure/HttpOnly cookie and an authenticated page read. The fixture mapping exists only in `VMBootProbe`; the application gateway still rejects loopback and `.test` destinations. No certificate-error bypass flag is used. The fixture CA is installed only in the synthetic guest's NSS database.

The browser proxy rejects non-CONNECT requests, non-443 ports, IP literals, userinfo, conflicting Host headers, duplicate/authorization headers and excessive frames. It stops existing tunnels when its worker lease expires or is revoked. Production DNS pinning and host lease checks remain independent.

## Crash artifacts

A forced renderer crash with a synthetic password in memory produced no dump under guest writable directories. Merely passing `--disable-breakpad`, `--disable-crash-reporter` or `--crash-dumps-dir` did not satisfy this test. The runtime now puts Chromium's configuration/crash-report location on the read-only application mount; writable profile state remains on tmpfs. The kernel core limit is zero and its core handler discards input.

`--disable-crashpad-for-testing` caused repeated network-service FD-ownership crashes in this pinned browser, so it is not used. This finding needs preservation when changing browser versions. The ordinary flags and read-only artifact restriction must be requalified together.

The successful synthetic console contained none of the password, form or cookie canaries. This is a bounded test of known sinks, not the complete U13 leakage qualification.

## Reproduce

```sh
uv run --frozen python images/fetch_probe.py
uv run --frozen python images/build_probe.py
uv run --frozen python images/fetch_browser.py
uv run --frozen python -m images.fetch_display
uv run --frozen python scripts/prepare-browser-fixture.py
uv run --frozen python -m images.build_browser
swift build --product vm-boot-probe
codesign --force --sign - --entitlements packaging/virtualization.entitlements .build/arm64-apple-macosx/debug/vm-boot-probe
uv run --frozen python scripts/run-browser-probe.py
uv run --frozen pytest tests/browser tests/catalog/test_secret_guard.py tests/isolation/test_browser_image.py
```

Rebuild only the pinned application/initramfs with `python -m images.build_browser --runtime-only` after code changes. The full base build requires `mksquashfs`, `unsquashfs`, `zstd` and `ar`. Refreshing the display lock also requires `gpgv`; its selected dependencies and versions require review before accepting a new qualification.

## Implementation references

- [Playwright Linux image requirements](https://playwright.dev/python/docs/docker) and [browser version matching](https://playwright.dev/python/docs/browsers).
- [Chromium Linux certificate database](https://chromium.googlesource.com/chromium/src.git/+/refs/heads/main/docs/linux/cert_management.md): the M146+ default follows the XDG data directory.
- [Chromium crash reporting](https://www.chromium.org/developers/crash-reports/) and [crashpad switch declaration](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/chrome/common/chrome_switches.h).
