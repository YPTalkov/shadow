# Compatibility qualification

Current qualification target: Apple Silicon macOS 26.6.2, Swift 6.3.3 Command Line Tools, Python 3.12.13, PyKeePass 4.2.0, KeePassXC 2.7.12, KDBX 4.0 with AES-256 and Argon2id.

New databases use 128 MiB Argon2id memory, three iterations, and two lanes. Inputs requesting over 1 GiB, 20 iterations, or eight lanes are refused before derivation. Other KDBX versions, ciphers, KDFs, attachments, and unqualified extensions are not approved for write-back. Compatibility tests use synthetic fixture values and report no secret data.

Run `uv sync --frozen --python /Users/ypt/.pyenv/versions/3.12.13/bin/python3` and `uv run --frozen pytest tests/compat`. The explicit local Python path is only a developer example; release packaging must pin its own interpreter and hashes. Run `swift build` for the native library. The installed Command Line Tools currently lack the `Testing` and `XCTest` modules required by `swift test`; native test qualification remains open until an Xcode toolchain is available.

This document records a target and current limitation, not a release pass. Version, package, executable, and fixture hashes belong in the release manifest after the packaged checks run.
