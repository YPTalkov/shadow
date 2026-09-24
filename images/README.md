# Synthetic VM qualification image

This developer probe boots Alpine 3.22.6 Linux 6.12.110 with Python 3.12.14 and Codex CLI 0.156.1 inside Apple's Virtualization framework. It contains synthetic fixtures only. The agent and browser profiles have no NIC or host shares, and their disk attachment is read-only. Mutable guest state lives in the initramfs. Console capture is specific to this synthetic probe and must not be enabled for a protected browser using credentials.

Install squashfs to obtain unsquashfs, then run:

    uv run --frozen python images/fetch_probe.py
    uv run --frozen python images/build_probe.py
    swift build --product vm-boot-probe
    codesign --force --sign - --entitlements packaging/virtualization.entitlements .build/arm64-apple-macosx/debug/vm-boot-probe
    uv run --frozen python scripts/run-vm-probe.py

Set SHADOW_LIVE_EGRESS=1 for the optional live HTTPS test to example.com. This sends a HEAD request without credentials and verifies the destination certificate inside the browser VM.

The fetcher verifies exact hashes for the official release archive, Codex executable archive, and Python's Alpine packages. The builder does not extract guest filesystem symlinks onto the host. It writes a CPIO archive and records kernel, initrd and disk hashes in .build/guest-cache/probe/manifest.json. The runner records bounded result fields in results.json; synthetic console output is kept beside it for diagnosis.

Alpine's kernel is an EFI zboot wrapper. The builder extracts its gzip payload using the offset and size defined by the [Linux zboot header](https://github.com/torvalds/linux/blob/v6.12/drivers/firmware/efi/libstub/zboot-header.S), yielding the ARM64 Image required by VZLinuxBootLoader.

The Codex fixture routes guest loopback HTTP through the guest's model-only vsock channel, validates the request with the host Codex relay policy, then streams a synthetic shell tool call and final result. No provider credentials are needed for this test. Live subscription sign-in, browser automation, independent watchdogs, leased HTTPS egress, attack scenarios beyond these probes, dependency audit and packaged production qualification remain separate gates.

The headed Chromium runtime uses a separate pinned Ubuntu image because Playwright does not support musl. Its image builder, real VM authentication checks and current limitations are documented in [browser runtime qualification](../docs/release/browser-runtime-status.md). Image qualification does not establish that the finished application package is ready.

## Browser package maintenance

`images.fetch_display` downloads both the display and security package locks. `--refresh-lock` refreshes only the display dependency selection; security updates require explicit review against the pinned Ubuntu indexes. Run `images.build_browser --profile probe` to rebuild the full filesystem after either lock changes, then rebuild the qualification and runtime profiles with `--runtime-only`.

The builder checks package identities, replaces dpkg inventory records, removes retired payloads, and refuses removal of a declared dependency or a shared file. It assembles a read-only filesystem without running Debian maintainer scripts. The resulting inventory marks these records `X-Shadow-Assembled`; it is not a general-purpose mutable dpkg installation.

Kernel module bytes are read directly from the verified SquashFS archive into CPIO. Linux names such as `xt_DSCP.ko` and `xt_dscp.ko` must remain distinct even when the build host uses a case-insensitive filesystem. Do not extract that archive to a normal macOS directory.

See the [dependency assessment](../docs/release/dependency-assessment.md) for scan coverage, remaining advisories and the release gate.

## Production Codex task image

After fetching the inputs, run `uv run --frozen python -m images.build_probe --profile agent`. This writes `.build/guest-cache/agent/manifest.json` and hash-pinned boot files. The agent profile contains the task runner rather than the synthetic boot scripts. Codex's matching `codex-code-mode-host` executable is included for GPT-6 code tools. Guest home and task files remain in memory; the native supervisor discards console output.

Run `uv run --frozen python scripts/run-agent-probe.py` with the signed probe executable above to test all selectable models using synthetic responses and the real Linux client. See [native runtime qualification](../docs/release/agent-runtime-status.md) for the limits and remaining live-provider gate.
