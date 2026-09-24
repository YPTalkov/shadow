"""Fetch exact synthetic-probe inputs. Hash mismatches never replace the cache."""

import hashlib
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".build/guest-cache"
FIXED = [
    {
        "filename": "alpine-netboot-3.22.6-aarch64.tar.gz",
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-netboot-3.22.6-aarch64.tar.gz",
        "sha256": "0a39889547d6fb1b0dc124f4baceadd08fef7a72708d5c92774a207f2bc41728",
    },
    {
        "filename": "codex-aarch64-unknown-linux-musl.tar.gz",
        "url": "https://github.com/openai/codex/releases/download/rust-v0.156.1/codex-aarch64-unknown-linux-musl.tar.gz",
        "sha256": "558e12aaa6dacb335ec47240bf9721db8a54746806d64f01185a403f44f79b72",
    },
    {
        "filename": "codex-code-mode-host-aarch64-unknown-linux-musl.tar.gz",
        "url": "https://github.com/openai/codex/releases/download/rust-v0.156.1/codex-code-mode-host-aarch64-unknown-linux-musl.tar.gz",
        "sha256": "40198138b03798ffa8c0da4c827a8ca5896774ea104b7110c2a2c0c7560cbe94",
    },
]


def main() -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    packages = json.loads((ROOT / "images/python-packages.lock.json").read_text())["packages"]
    for item in FIXED + packages:
        name = item["filename"]
        if Path(name).name != name:
            raise SystemExit("invalid_artifact_name")
        target = CACHE / name
        if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == item["sha256"]:
            continue
        temporary = target.with_suffix(target.suffix + ".download")
        try:
            with urllib.request.urlopen(item["url"], timeout=60) as source, temporary.open("wb") as output:
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)
            if hashlib.sha256(temporary.read_bytes()).hexdigest() != item["sha256"]:
                raise SystemExit("artifact_hash_mismatch")
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
    print("probe_inputs_verified")


if __name__ == "__main__":
    main()
