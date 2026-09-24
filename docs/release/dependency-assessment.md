# Dependency assessment — 2026-09-24

This is a partial package advisory assessment. It does not pass G1 or the independent security gate. The exact database timestamp, image identities, remaining advisory/package pairs and verification counts are in [guest-dependency-audit.json](guest-dependency-audit.json).

## Findings and repairs

Trivy 0.74.0 initially matched 612 package/advisory pairs against the browser's Ubuntu 24.04 inventory: two HIGH, 563 MEDIUM and 47 LOW. The inventory also omitted display packages overlaid by our builder. The builder now records those additions and upgrades using the verified packages' control metadata and file lists.

Eighteen packages had public updates. Their exact versions and hashes are pinned in [the security lock](../../images/security-packages.lock.json), using the same signed Ubuntu indexes as the display lock. Both unused GStreamer bad-plugin packages were removed because the Noble fix for [CVE-2025-3887](https://ubuntu.com/security/CVE-2025-3887) requires Ubuntu Pro. Removal includes their 205 payload files; none remain in the assembled image. No retained package declares a dependency on them.

The repaired image contains 515 Debian package records. The new scan matches 549 pairs across 151 advisory IDs: **zero CRITICAL/HIGH, 500 MEDIUM and 49 LOW**, with no public fix recorded by this database. These are scanner results, not severity overrides or an assertion that the remaining findings are harmless. The original and repaired totals are not directly comparable because the original inventory omitted overlaid display packages.

All Depends and Pre-Depends relations resolve in the assembled inventory, including versioned alternatives and Provides. The native VM passed all 37 Chromium scenarios after these library updates. The 19 agent APK declarations, independently read from hash-verified `.PKGINFO` files, have no advisory matches in the same database. The separate [host Python audit](host-dependency-audit.json) covers 11 pinned distributions.

A repeat build also found a case collision while extracting Linux kernel modules onto macOS. The builder now reads each module directly from SquashFS, preserving both names and verifying the module archive against the pinned Alpine release. The assembled ramdisk contains 908 kernel modules; the four payloads in the two discovered case pairs match their original hashes.

## Reproduce the browser scan

Use the official [Trivy 0.74.0 release](https://github.com/aquasecurity/trivy/releases/tag/v0.74.0). The macOS ARM archive SHA-256 and Trivy database metadata are in the receipt. No scanner is bundled with Shadow.

1. Build the browser image from its locks.
2. Use `unsquashfs -cat` to copy `var/lib/dpkg/status`, `var/lib/dpkg/available`, `etc/lsb-release`, `etc/debian_version` and `usr/lib/os-release` into a temporary metadata directory. Copy the last file to `etc/os-release` there to resolve the image's symlink. Do not extract the full Linux filesystem onto a case-insensitive volume.
3. Run `trivy rootfs --scanners vuln --disable-telemetry --list-all-pkgs --cache-dir <cache> --format json --output <report> <metadata-directory>`. Refresh the database for a new release assessment; `--skip-db-update` reproduces a retained database snapshot.
4. Require recognition of Ubuntu 24.04 and compare the scanner's package count with the actual dpkg inventory. An empty/unrecognized scan is a failure, not a clean result.

This uses Trivy's [root filesystem scanner](https://trivy.dev/docs/latest/references/configuration/cli/trivy_rootfs/) over package metadata only. The initial full extraction failed on case collisions, and no full-filesystem scan is claimed. The agent result uses a temporary APK inventory generated from the 19 locked archive declarations; it does not scan the complete boot ramdisk.

## Remaining release work

Review the 151 remaining advisory IDs against actual reachability, with special attention to libraries handling browser content, images, fonts and TLS. No blanket waiver is recorded. The worker's restricted egress, unprivileged Chromium sandbox and short lifetime are existing boundaries; they do not erase a vulnerable dependency.

The package scans do not assess the Alpine boot kernel/BusyBox, statically linked Codex and code-mode-host dependencies, Chromium's bundled components, Playwright's Node runtime, standalone host CPython's native dependencies, or Apple frameworks/firmware. Those need assessment alongside the independent isolation and persistence review. Use synthetic credentials until these release gates are accepted.
