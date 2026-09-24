# Third-party software in the personal build

This local bundle includes independently licensed components. It is not a public distribution artifact. Preserve their notices and review source-distribution obligations before distributing a build to anyone else. Shadow does not assign a new license to upstream software.

- The private storage worker uses PyKeePass 4.2.0 (GPL-3.0). Its license and dependency notices are retained in `python/lib/python3.12/site-packages/*dist-info/`. The complete host dependency inventory is `dependencies.json`.
- CPython 3.12.13 uses the Python Software Foundation license and bundled third-party licenses, in `python/lib/python3.12/LICENSE.txt`. The standalone build is pinned in `locks/python-runtime.lock.json`; upstream build metadata is maintained by [python-build-standalone](https://github.com/astral-sh/python-build-standalone).
- The Linux kernel and BusyBox in the Alpine boot image use GPL licenses. Alpine package versions, hashes and source URLs are in `locks/python-packages.lock.json` and the guest package inventory. Package license declarations are copied from the signed-release APK metadata. [Alpine package sources](https://gitlab.alpinelinux.org/alpine/aports) provide the corresponding recipes.
- Codex and its code-mode helper are pinned to 0.156.1, from [OpenAI's source release](https://github.com/openai/codex/tree/rust-v0.156.1), under Apache-2.0. The original LICENSE and NOTICE are included in `licenses/codex/`.
- The browser filesystem is the pinned Microsoft Playwright Python Noble image. Its operating-system package inventory and license locations are in `dependencies.json`; the original notices remain under `/usr/share/doc/` inside the read-only disk. Playwright is Apache-2.0. Chromium and its bundled components have their own licenses retained in the image. Exact OCI layers, Python wheels and added display packages are in `locks/`.

KeePassXC is an independently installed application, not bundled here. Its qualified identity is documented in the release evidence.

This inventory records upstream declarations. It does not claim a completed legal review or authorize public binary redistribution.
