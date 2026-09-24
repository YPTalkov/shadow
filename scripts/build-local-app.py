"""Assemble a relocatable, sealed personal bundle from exact locked inputs."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".build/python-runtime"
APP = ROOT / "dist/Shadow.app"
MACHO = {bytes.fromhex(value) for value in ("cffaedfe", "cefaedfe", "feedfacf", "feedface", "cafebabe", "bebafeca")}


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, cwd=ROOT, **kwargs)


def download(url, target, expected):
    if target.is_file() and digest(target) == expected:
        return
    temporary = target.with_suffix(".download")
    try:
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output, 1024 * 1024)
        if digest(temporary) != expected:
            raise ValueError("runtime_hash_mismatch")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def copy_tree(source, target):
    shutil.copytree(source, target, symlinks=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def main():
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("Apple Silicon macOS is required")
    run("uv", "run", "--frozen", "python", "scripts/sync-agent-contract.py", "--check")
    run("uv", "run", "--frozen", "python", "scripts/sync-site-adapters.py", "--check")
    run("swift", "build", "-c", "release", "--product", "Shadow")
    CACHE.mkdir(parents=True, exist_ok=True)
    lock = json.loads((ROOT / "packaging/python-runtime.lock.json").read_text())
    archive = CACHE / "python.tar.gz"
    download(lock["url"], archive, lock["sha256"])
    if subprocess.run(["/usr/bin/pgrep", "-f", re.escape(str(APP / "Contents/MacOS/Shadow"))], stdout=subprocess.DEVNULL).returncode == 0:
        raise SystemExit("Close the build's Shadow application before rebuilding it")
    # Only this script's disposable build artifact is replaced. Installation is
    # an explicit copy, so rebuilding cannot overwrite a running installed app.
    if APP.exists():
        shutil.rmtree(APP)
    contents = APP / "Contents"
    resources = contents / "Resources"
    macos = contents / "MacOS"
    macos.mkdir(parents=True)
    resources.mkdir()
    with tarfile.open(archive) as source:
        source.extractall(resources, filter="data")
    python = resources / "python/bin/python3"
    site = resources / "python/lib/python3.12/site-packages"
    # No installer, headers, build archives or host command entry points ship.
    for entry in list(site.iterdir()):
        shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
    shutil.rmtree(resources / "python/include")
    for entry in (resources / "python/bin").iterdir():
        if entry.name not in {"python3", "python3.12"}:
            entry.unlink()
    for entry in (resources / "python/lib").rglob("*.a"):
        entry.unlink()
    requirements = CACHE / "requirements.txt"
    run("uv", "export", "--frozen", "--no-dev", "--no-emit-project", "--format", "requirements-txt", "--output-file", requirements, stdout=subprocess.DEVNULL)
    run("uv", "pip", "install", "--python", python, "--target", site, "--require-hashes", "--only-binary=:all:", "--no-deps", "-r", requirements)
    for module in ("vault_worker", "shadow_common"):
        copy_tree(ROOT / module, site / module)
    # The worker never writes bytecode into a sealed application.
    for directory in list(resources.rglob("__pycache__")):
        shutil.rmtree(directory)
    for profile, manifest_name, initrd in (("agent", "manifest.json", "initrd"), ("browser", "production-manifest.json", "initrd-runtime")):
        source = ROOT / ".build/guest-cache" / profile
        manifest = json.loads((source / manifest_name).read_text())
        if manifest["profile"] != ("agent" if profile == "agent" else "runtime"):
            raise ValueError("qualification_image_cannot_ship")
        destination = resources / profile
        destination.mkdir()
        for name, key in (("kernel", "kernel"), (initrd, "initrd"), ("disk", "disk")):
            if digest(source / name) != manifest["files"][key]:
                raise ValueError("image_hash_mismatch")
            shutil.copy2(source / name, destination / name)
        shutil.copy2(source / manifest_name, destination / manifest_name)
    shutil.copy2(ROOT / ".build/arm64-apple-macosx/release/Shadow", macos / "Shadow")
    locks = resources / "locks"
    locks.mkdir()
    for source in [ROOT / "uv.lock", ROOT / "packaging/python-runtime.lock.json", *sorted((ROOT / "images").glob("*.lock.json"))]:
        shutil.copy2(source, locks / source.name)
    shutil.copy2(requirements, locks / "host-requirements.txt")
    shutil.copy2(ROOT / "packaging/THIRD-PARTY-NOTICES.md", resources)
    (resources / "adapters").mkdir()
    for adapter in sorted((ROOT / "site_adapters").glob("*/manifest.json")):
        shutil.copy2(adapter, resources / "adapters" / (adapter.parent.name + ".json"))
    license_lock = json.loads((ROOT / "packaging/licenses.lock.json").read_text())
    for item in license_lock:
        target = resources / "licenses" / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        download(item["url"], target, item["sha256"])
    # Metadata is obtained from the packaged interpreter, not the build venv.
    metadata_code = 'import importlib.metadata as m,json; print(json.dumps([{"name":d.metadata["Name"],"version":d.version,"license":d.metadata.get("License-Expression") or d.metadata.get("License"),"license_files":d.metadata.get_all("License-File",[])} for d in m.distributions()]))'
    host = json.loads(run(python, "-I", "-B", "-c", metadata_code, capture_output=True).stdout)
    packages = []
    for item in json.loads((ROOT / "images/python-packages.lock.json").read_text())["packages"]:
        with tarfile.open(ROOT / ".build/guest-cache" / item["filename"]) as apk:
            metadata = apk.extractfile(".PKGINFO").read().decode()
        fields = dict(line.split(" = ", 1) for line in metadata.splitlines() if " = " in line and not line.startswith("#"))
        packages.append({key: fields.get(key) for key in ("pkgname", "pkgver", "license", "url", "origin")})
    status = run("unsquashfs", "-cat", resources / "browser/disk", "var/lib/dpkg/status", capture_output=True).stdout.decode()
    debian = []
    for stanza in status.split("\n\n"):
        fields = dict(line.split(": ", 1) for line in stanza.splitlines() if ": " in line and not line.startswith(" "))
        if fields.get("Status") == "install ok installed":
            debian.append({"name": fields["Package"], "version": fields["Version"], "source": fields.get("Source"), "notice": "/usr/share/doc/" + fields["Package"] + "/copyright"})
    dependencies = {"host_python": host, "agent_apk": packages, "browser_debian": debian, "python_runtime": lock,
                    "codex": "0.156.1", "playwright": "1.63.0", "browser_base": "Ubuntu Noble", "alpine_boot": "3.22.6"}
    (resources / "dependencies.json").write_text(json.dumps(dependencies, indent=2) + "\n")
    with (contents / "Info.plist").open("wb") as output:
        plistlib.dump({"CFBundleExecutable": "Shadow", "CFBundleIdentifier": "com.yptalkov.shadow", "CFBundleName": "Shadow", "CFBundlePackageType": "APPL", "CFBundleShortVersionString": "0.1.0", "CFBundleVersion": "1", "LSMinimumSystemVersion": "15.0", "NSHighResolutionCapable": True, "NSPrincipalClass": "NSApplication"}, output)
    # Sign every native Python extension/library before hashing the inventory.
    for path in sorted(resources.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as source:
            magic = source.read(4)
        if magic in MACHO:
            run("codesign", "--force", "--sign", "-", path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    files, links = {}, {}
    for path in sorted(resources.rglob("*")):
        name = path.relative_to(resources).as_posix()
        if path.is_symlink():
            if not path.resolve().is_relative_to(resources) or not path.exists():
                raise ValueError("external_runtime_link")
            links[name] = os.readlink(path)
        elif path.is_file():
            files[name] = digest(path)
    inventory = {"schema": 1, "macos": platform.mac_ver()[0], "architecture": platform.machine(), "files": files, "links": links}
    (resources / "installation.json").write_text(json.dumps(inventory, indent=2) + "\n")
    run("codesign", "--force", "--sign", "-", "--options", "runtime", "--entitlements", ROOT / "packaging/virtualization.entitlements", APP)
    run("codesign", "--verify", "--deep", "--strict", APP)
    run(macos / "Shadow", "--verify-installation")
    receipt = {"built_at": datetime.now(timezone.utc).isoformat(), "source_commit": run("git", "rev-parse", "HEAD", capture_output=True).stdout.decode().strip(),
               "source_dirty": bool(run("git", "status", "--porcelain", capture_output=True).stdout),
               "macos": inventory["macos"], "architecture": inventory["architecture"], "signing": "local-ad-hoc", "notarized": False,
               "executable_sha256": digest(macos / "Shadow"), "inventory_sha256": digest(resources / "installation.json"),
               "resource_files": len(files), "resource_links": len(links), "bytes": sum(path.stat().st_size for path in resources.rglob("*") if path.is_file() and not path.is_symlink())}
    (APP.parent / "build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("LOCAL_APP=pass")


if __name__ == "__main__":
    main()
