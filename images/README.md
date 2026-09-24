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

The headed Chromium runtime uses a separate pinned Ubuntu image because Playwright does not support musl. Its image builder, real VM authentication checks and current limitations are documented in [browser runtime qualification](../docs/release/browser-runtime-status.md). Both image builders produce synthetic qualification artifacts; neither is the finished production package.
