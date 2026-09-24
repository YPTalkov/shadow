"""Fetch pinned browser image layers and guest wheels; never execute them on the host."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shutil
import tomllib
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".build/guest-cache/browser"
REGISTRY = "https://mcr.microsoft.com/v2/playwright/python"
MANIFEST = "832286ebbc124bd50c914b27cf2f88fb88d4e261f84f578060191c4daa9c68ac"


def fetch(url: str, digest: str, name: str) -> Path:
    target = CACHE / name
    if target.exists():
        with target.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() == digest:
                return target
    temporary = target.with_suffix(".download")
    with urlopen(url, timeout=60) as source, temporary.open("wb") as output:
        shutil.copyfileobj(source, output, 1024 * 1024)
    with temporary.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != digest:
            temporary.unlink()
            raise ValueError("browser_artifact_hash_mismatch")
    temporary.replace(target)
    return target


def main() -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(fetch(f"{REGISTRY}/manifests/sha256:{MANIFEST}", MANIFEST, "manifest.json").read_bytes())
    artifacts = []
    for layer in manifest["layers"]:
        digest = layer["digest"].removeprefix("sha256:")
        artifacts.append((f"{REGISTRY}/blobs/sha256:{digest}", digest, digest + ".tar.gz"))
    packages = tomllib.loads((ROOT / "uv.lock").read_text())["package"]
    wheel_names = []
    for name in ("playwright", "greenlet", "pyee", "typing-extensions"):
        package = next(p for p in packages if p["name"] == name)
        wheels = [w for w in package["wheels"] if w["url"].endswith("-py3-none-any.whl") or
                  ("manylinux" in w["url"] and "aarch64" in w["url"] and
                   ("-cp312-cp312-" in w["url"] or "-py3-none-" in w["url"]))]
        if len(wheels) != 1:
            raise ValueError("guest_wheel_selection_failed")
        wheel = wheels[0]
        filename = wheel["url"].rsplit("/", 1)[1]
        artifacts.append((wheel["url"], wheel["hash"].removeprefix("sha256:"), filename))
        wheel_names.append(filename)
    with ThreadPoolExecutor(max_workers=3) as pool:
        for path in pool.map(lambda artifact: fetch(*artifact), artifacts):
            print("verified " + path.name, flush=True)
    lock = {"image": "mcr.microsoft.com/playwright/python:v1.63.0-noble", "manifest_sha256": MANIFEST,
            "layers": [layer["digest"].removeprefix("sha256:") + ".tar.gz" for layer in manifest["layers"]],
            "wheels": wheel_names, "artifacts": [{"url": url, "sha256": digest, "filename": name} for url, digest, name in artifacts]}
    (ROOT / "images/browser-image.lock.json").write_text(json.dumps(lock, indent=2) + "\n")


if __name__ == "__main__":
    main()
