# Local package qualification

`scripts/build-local-app.py` assembles `dist/Shadow.app` from the release Swift executable, standalone CPython 3.12.13, hashed host dependencies, the production agent image and the production browser image. It excludes diagnostic executables, fixture CAs, fixture producers, plaintext inputs, development environments and raw capture modes. The packaged Python contains only the storage worker and shared value guard from this project.

All Mach-O Python libraries are locally signed before the resource inventory is hashed. The native application has the virtualization entitlement and hardened-runtime flag. The final local ad-hoc signature seals that inventory; startup verifies both signature and complete file/link inventory, including unexpected import files. macOS 26.6.2 and arm64 are the qualified host tuple. No Developer ID identity is available on this machine, and this build is not notarized or publicly distributed.

## Results

- The actual executable verifies after relocation into a path with spaces, with a sanitized environment and no source-tree dependency.
- Sixteen package checks pass: modified worker, agent/browser image and adapter; re-signed changed resources; added Python startup code; external interpreter link; changed host qualification; restoration of the original files; and absence of runtime-written bytecode.
- The release owner UI harness uses the verified packaged interpreter for create/import, separately scoped consent, signed-source enrollment/refresh, encrypted editor checkout/review, backup/export, restore with intact and missing restriction history, and reviewed diagnostics. It passes and scans its persistent files for plaintext/base64 password and unlock canaries. Screenshots were checked for full consent visibility.
- The exact production browser image boots Chromium and its private display, then stops within the host-silence limit. It stopped after 3.43 seconds in the measured run: the worker's three-second silence bound fired before PID 1's independent ten-second maximum. No fixture CA or gateway exception was present in this run.
- The packaged agent image runs the real Codex client with all three selectable models against synthetic provider responses. Root attempts to reach the browser's ports, other host ports and direct public/private/link-local destinations fail; host shares, routes, swap and storage imports are absent, and the base disk refuses writes. Completion and native lock invalidate its caller and authority.
- The packaged interpreter and agent image also pass the combined authenticated task and source-removal interruption. Those HTTPS tests use the separate browser qualification image containing the fixture CA. This is explicitly not a production-site test.

The build receipt and individual result files carry artifact hashes. A harness executable is separate from the delivered app; the app itself has no test bypass switch. `--verify-installation` only checks its sealed resources and exits, before vault initialization.

## Storage performance and recovery

The initial 5,000-row packaged import exceeded its 30-second target at 31.28 seconds. Profiling attributed 30.0 seconds to PyKeePass's duplicate search: `add_entry` scans the group even with `force_creation=True`. The importer now uses the same pinned library's public `Entry` constructor and group append directly, preserving its deliberate duplicate retention. A characterization test covers distinct UUIDs, protected password/TOTP/import fields and idempotent retry. Import, storage and compatibility tests pass.

The corrected source run imported 5,000 entries in 1.23 seconds. Final packaged timings are in `storage-package-results.json`. The storage rehearsal independently reads the encrypted file with KeePassXC and checks password, master password, notes, TOTP seed, token and recovery-code reflection into metadata. It scans every persistent fixture file after removing the harness-owned plaintext input.

The Argon2id floor remains 128 MiB, three iterations, two lanes. The measured unlock is below one second on this Mac; no encryption or persistence checks were removed to meet the import target.

## Dependency review and limits

`dependencies.json` inside the app records host Python distributions, Alpine APK declarations and browser Debian package versions; exact image/wheel/package locks and upstream notices are included. pip-audit 2.10.1 reported no known advisories for all 11 pinned host Python dependencies on 2026-09-24. The [guest dependency assessment](dependency-assessment.md) records the subsequent browser updates/removals, 515-package inventory, 19-APK scan, remaining advisories and coverage gaps. These scans do not cover every bundled native or guest component or establish that an undisclosed vulnerability is absent.

The full production gates remain open for live ChatGPT sign-in, owner-selected real-site support, physical OS-event rehearsal and independent security review. Ad-hoc integrity checks are not publisher authentication and do not defend against replacement of the entire trusted application by a compromised host administrator. Use synthetic credentials only.
