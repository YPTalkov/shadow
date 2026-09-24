"""Resolve the small native display addition from signed Ubuntu package indexes.

Run once with --refresh-lock to refresh the reviewed pins. Normal fetching uses
only the committed artifact hashes. No package maintainer script runs on macOS.
"""
import argparse
import hashlib
import json
import lzma
import gzip
import shutil
import re
import subprocess
from urllib.request import urlopen

from images.build_browser import LayerSet
from images.fetch_browser import ROOT, CACHE, fetch

MIRROR = "https://ports.ubuntu.com/ubuntu-ports"
LOCK = ROOT / "images/display-packages.lock.json"


def fields(text):
    for block in text.split("\n\n"):
        result = {}
        key = None
        for line in block.splitlines():
            if line.startswith(" ") and key:
                result[key] += "\n" + line[1:]
            elif ":" in line:
                key, value = line.split(":", 1)
                result[key] = value.lstrip()
        if result:
            yield result


def refresh():
    image = json.loads((ROOT / "images/browser-image.lock.json").read_text())
    # Rebuild the metadata views from verified OCI objects before trusting the
    # image's Ubuntu archive keyring or installed dependency declarations.
    hashes = {artifact["filename"]: artifact["sha256"] for artifact in image["artifacts"]}
    for name in image["layers"]:
        with (CACHE / name).open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != hashes[name]:
                raise ValueError("browser_artifact_hash_mismatch")
        with gzip.open(CACHE / name, "rb") as source, (CACHE / name.removesuffix(".gz")).open("wb") as target:
            shutil.copyfileobj(source, target, 1024 * 1024)
    paths = [CACHE / name.removesuffix(".gz") for name in image["layers"]]
    with LayerSet(paths) as merged:
        archive, item = merged.entries["usr/share/keyrings/ubuntu-archive-keyring.gpg"]
        keyring = CACHE / "ubuntu-archive-keyring.gpg"
        keyring.write_bytes(archive.extractfile(item).read())
        archive, item = merged.entries["var/lib/dpkg/status"]
        installed = {p["Package"]: p for p in fields(archive.extractfile(item).read().decode())}
        for package in list(installed.values()):
            for provided in package.get("Provides", "").split(","):
                if provided.strip():
                    installed[re.split(r"[\s:(]", provided.strip(), maxsplit=1)[0]] = package
    packages = {}
    indexes = []
    for suite in ("noble", "noble-updates", "noble-security"):
        signed = CACHE / (suite + "-InRelease")
        with urlopen(f"{MIRROR}/dists/{suite}/InRelease", timeout=60) as source:
            signed.write_bytes(source.read(4 * 1024 * 1024))
        release = CACHE / (suite + "-Release")
        result = subprocess.run(["gpgv", "--keyring", str(keyring), "--output", "-", str(signed)], capture_output=True)
        if result.returncode:
            raise ValueError("ubuntu_release_signature_invalid")
        release.write_bytes(result.stdout)
        metadata = next(fields(release.read_text()))
        checksums = {parts[2]: parts[0] for line in metadata["SHA256"].splitlines() if len(parts := line.split()) == 3}
        for component in ("main", "universe"):
            name = f"{component}/binary-arm64/Packages.xz"
            digest = checksums[name]
            url = f"{MIRROR}/dists/{suite}/{component}/binary-arm64/by-hash/SHA256/{digest}"
            path = fetch(url, digest, f"{suite}-{component}-Packages.xz")
            indexes.append({"suite": suite, "component": component, "sha256": digest})
            for package in fields(lzma.decompress(path.read_bytes()).decode()):
                packages[package["Package"]] = package
    selected = {}
    available = set(installed)

    def select(name):
        if name in available:
            return
        if name not in packages:
            raise ValueError("missing_display_dependency:" + name)
        package = packages[name]
        selected[name] = package
        available.add(name)
        available.update(re.split(r"[\s:(]", value.strip(), maxsplit=1)[0] for value in package.get("Provides", "").split(",") if value.strip())
        for dependency in (package.get("Pre-Depends", "") + "," + package.get("Depends", "")).split(","):
            if not dependency.strip():
                continue
            alternatives = [re.split(r"[\s:(]", value.strip(), maxsplit=1)[0] for value in dependency.split("|")]
            existing = next((value for value in alternatives if value in available), None)
            if existing:
                continue
            choice = next((value for value in alternatives if value in packages), None)
            if choice is None:
                raise ValueError("missing_display_dependency:" + alternatives[0])
            select(choice)

    for name in ("xserver-xorg-core", "xserver-xorg-input-libinput", "libnss3-tools"):
        select(name)
    artifacts = [{"name": name, "version": value["Version"], "url": MIRROR + "/" + value["Filename"],
                  "sha256": value["SHA256"], "filename": value["Filename"].rsplit("/", 1)[1],
                  "depends": value.get("Depends", "")} for name, value in sorted(selected.items())]
    lock = {"image_manifest_sha256": image["manifest_sha256"], "indexes": indexes, "artifacts": artifacts}
    LOCK.write_text(json.dumps(lock, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh-lock", action="store_true")
    if parser.parse_args().refresh_lock:
        refresh()
    for lock in (LOCK, ROOT / "images/security-packages.lock.json"):
        for artifact in json.loads(lock.read_text())["artifacts"]:
            fetch(artifact["url"], artifact["sha256"], artifact["filename"])
            print("verified " + artifact["name"], flush=True)


if __name__ == "__main__":
    main()
