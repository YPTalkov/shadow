"""Assemble a read-only browser filesystem without host extraction or Docker."""
from contextlib import AbstractContextManager
import argparse
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tarfile
import zipfile

from images.build_probe import cpio_file, RELEASE, SHA256
from images.fetch_browser import CACHE, ROOT


def safe_name(name: str) -> str:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe_image_path")
    return str(path)


def canonical_debian_layer(source: Path, target: Path) -> None:
    # Ubuntu Noble uses /usr merge. dpkg follows these guest directory links;
    # archive overlay replacement would instead destroy the dynamic loader's
    # /lib link. Normalize package paths without following a host symlink.
    def canonical(name):
        name = safe_name(name)
        return "usr/" + name if name.split("/", 1)[0] in {"lib", "bin", "sbin"} else name

    with tarfile.open(source) as original, tarfile.open(target, "w") as normalized:
        for member in original:
            data = original.extractfile(member) if member.isfile() else None
            member.name = canonical(member.name)
            if member.islnk():
                member.linkname = canonical(member.linkname)
            normalized.addfile(member, data)
            if data is not None:
                data.close()


class LayerSet(AbstractContextManager):
    """Keep guest links as archive metadata, apply OCI replacement and whiteouts."""
    def __init__(self, paths: list[Path]):
        self.archives = []
        self.entries = {}
        try:
            for path in paths:
                archive = tarfile.open(path)
                self.archives.append(archive)
                additions = {}
                for item in archive:
                    name = safe_name(item.name)
                    if name == ".":
                        continue
                    parent = str(PurePosixPath(name).parent)
                    prefix = "" if parent == "." else parent + "/"
                    base = PurePosixPath(name).name
                    if base == ".wh..wh..opq":
                        self.entries = {n: v for n, v in self.entries.items() if not n.startswith(prefix)}
                    elif base.startswith(".wh."):
                        removed = prefix + base[4:]
                        self.entries = {n: v for n, v in self.entries.items() if n != removed and not n.startswith(removed + "/")}
                    else:
                        if not (item.isfile() or item.isdir() or item.issym() or item.islnk()):
                            raise ValueError("unsupported_image_member")
                        item.name = name
                        if item.islnk():
                            item.linkname = safe_name(item.linkname)
                        additions[name] = (archive, item)
                self.entries.update(additions)
            for name in self.entries:
                for parent in PurePosixPath(name).parents:
                    if str(parent) in self.entries and not self.entries[str(parent)][1].isdir():
                        raise ValueError("image_parent_is_not_directory")
        except BaseException:
            self.__exit__(None, None, None)
            raise

    @property
    def names(self) -> set[str]:
        return set(self.entries)

    def __exit__(self, *args):
        for archive in self.archives:
            archive.close()

    def write(self, output, additions: dict[str, tuple[bytes, int]] | None = None) -> None:
        additions = additions or {}
        with tarfile.open(fileobj=output, mode="w|", format=tarfile.PAX_FORMAT) as target:
            for name, (archive, original) in self.entries.items():
                if name in additions or name.startswith(("ms-playwright/firefox-", "ms-playwright/webkit-", "ms-playwright/chromium_headless_shell-")):
                    continue
                item = copy.copy(original)
                item.uid = item.gid = 0
                item.uname = item.gname = "root"
                item.mtime = 0
                item.pax_headers = {}
                # No setuid programs in the browser filesystem. Chromium uses
                # the kernel namespace sandbox as an unprivileged guest user.
                item.mode &= 0o777
                data = None
                if item.islnk():
                    seen = {name}
                    linked_archive, linked = archive, original
                    while linked.islnk():
                        if linked.linkname in seen or linked.linkname not in self.entries:
                            raise ValueError("invalid_image_hardlink")
                        seen.add(linked.linkname)
                        linked_archive, linked = self.entries[linked.linkname]
                    if not linked.isfile():
                        raise ValueError("invalid_image_hardlink")
                    item.type = tarfile.REGTYPE
                    item.size = linked.size
                    item.linkname = ""
                    data = linked_archive.extractfile(linked)
                elif item.isfile():
                    data = archive.extractfile(original)
                target.addfile(item, data)
                if data is not None:
                    data.close()
            for name, (data, mode) in additions.items():
                item = tarfile.TarInfo(safe_name(name))
                item.size, item.mode = len(data), mode
                target.addfile(item, io.BytesIO(data))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-only", action="store_true")
    parser.add_argument("--profile", choices=("probe", "runtime", "qualification"), default="probe")
    arguments = parser.parse_args()
    runtime_only = arguments.runtime_only
    lock = json.loads((ROOT / "images/browser-image.lock.json").read_text())
    for artifact in ([] if runtime_only else lock["artifacts"]):
        with (CACHE / artifact["filename"]).open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != artifact["sha256"]:
                raise ValueError("browser_artifact_hash_mismatch")
    paths = []
    for name in ([] if runtime_only else lock["layers"]):
        unpacked = CACHE / name.removesuffix(".gz")
        # Recreate from the verified compressed object on every build.
        with gzip.open(CACHE / name, "rb") as source, unpacked.open("wb") as target:
            shutil.copyfileobj(source, target, 1024 * 1024)
        paths.append(unpacked)
    display = json.loads((ROOT / "images/display-packages.lock.json").read_text())
    if display["image_manifest_sha256"] != lock["manifest_sha256"]:
        raise ValueError("display_base_mismatch")
    for artifact in ([] if runtime_only else display["artifacts"]):
        package = CACHE / artifact["filename"]
        with package.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != artifact["sha256"]:
                raise ValueError("display_artifact_hash_mismatch")
        # Read only the Debian data archive; maintainer scripts are never run.
        unpacked = CACHE / (artifact["name"] + "-data.tar")
        compressed = subprocess.check_output(["ar", "-p", str(package), "data.tar.zst"])
        with unpacked.open("wb") as output:
            subprocess.run(["zstd", "-d", "-c"], input=compressed, stdout=output, check=True)
        normalized = CACHE / (artifact["name"] + "-normalized.tar")
        canonical_debian_layer(unpacked, normalized)
        paths.append(normalized)
    additions = {}
    for wheel in ([] if runtime_only else lock["wheels"]):
        with zipfile.ZipFile(CACHE / wheel) as archive:
            for member in archive.infolist():
                if not member.is_dir():
                    name = "opt/shadow-deps/" + safe_name(member.filename)
                    additions[name] = (archive.read(member), 0o755 if member.filename.endswith("/node") else 0o644)
    # A directory to bind the separately pinned application ramdisk over.
    additions["opt/shadow/.base"] = (b"", 0o644)
    disk = CACHE / "disk"
    if runtime_only:
        previous = json.loads((CACHE / "runtime-manifest.json").read_text())
        with disk.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != previous["files"]["disk"]:
                raise ValueError("browser_base_image_changed")
    else:
        with LayerSet(paths) as merged:
            process = subprocess.Popen(["mksquashfs", "-", str(disk), "-tar", "-noappend", "-all-root", "-default-mode", "0755", "-default-uid", "0", "-default-gid", "0", "-comp", "gzip", "-processors", "2", "-no-progress", "-mkfs-time", "0"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL)
            try:
                merged.write(process.stdin, additions)
                process.stdin.close()
                if process.wait() != 0:
                    raise ValueError("browser_filesystem_build_failed")
            except BaseException:
                process.kill()
                process.wait()
                raise
    archive_path = ROOT / ".build/guest-cache" / RELEASE
    with archive_path.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != SHA256:
            raise ValueError("kernel_archive_hash_mismatch")
    with tarfile.open(archive_path) as archive:
        ramdisk = archive.extractfile("boot/initramfs-virt").read()
    modules = CACHE / "modules-root"
    subprocess.run(["unsquashfs", "-f", "-d", str(modules), str(ROOT / ".build/guest-cache/modloop-virt")], check=True, stdout=subprocess.DEVNULL)
    bootstrap = (ROOT / "images/browser-init.sh").read_bytes()
    if arguments.profile != "probe":
        entrypoint = b"-m browser_worker.supervisor" if arguments.profile == "runtime" else b"/opt/shadow/runtime_qualification.py"
        bootstrap = bootstrap.replace(b"/opt/shadow/boot_probe.py", entrypoint)
    overlay = bytearray(cpio_file("init", bootstrap, stat.S_IFREG | 0o755))
    payload = {"shadow/xorg.conf": (ROOT / "images/xorg.conf").read_bytes(),
               "shadow/crashes/.keep": b"",
               "shadow/config/chromium/Crash Reports/.keep": b""}
    if arguments.profile == "probe":
        payload.update({"shadow/browser_probe.py": (ROOT / "images/browser-probe.py").read_bytes(),
                        "shadow/boot_probe.py": (ROOT / "images/browser-boot-probe.py").read_bytes(),
                        "shadow/browser_scenarios.py": (ROOT / "tests/browser/guest_scenarios.py").read_bytes()})
        payload["shadow/guest_safe_views.py"] = (ROOT / "tests/browser/guest_safe_views.py").read_bytes()
        payload["shadow/guest_challenges.py"] = (ROOT / "tests/browser/guest_challenges.py").read_bytes()
    if arguments.profile == "qualification":
        payload["shadow/runtime_qualification.py"] = (ROOT / "images/browser-runtime-qualification.py").read_bytes()
    if arguments.profile != "runtime":
        payload["shadow/fixture-ca.pem"] = (CACHE / "fixture/cert.pem").read_bytes()
    for package in ("browser_worker", "guest_transport", "site_adapters", "shadow_common"):
        for path in sorted((ROOT / package).rglob("*")):
            if path.is_file() and path.suffix in {".py", ".json"}:
                payload["shadow/" + str(path.relative_to(ROOT))] = path.read_bytes()
    directories = {str(parent) for name in payload for parent in PurePosixPath(name).parents if str(parent) != "."}
    for name in sorted(directories):
        overlay += cpio_file(name, b"", stat.S_IFDIR | 0o755)
    for name, data in payload.items():
        overlay += cpio_file(name, data, stat.S_IFREG | 0o644)
    for path in sorted((modules / "modules").rglob("*")):
        name = "lib/" + str(path.relative_to(modules))
        overlay += cpio_file(name, b"" if path.is_dir() else path.read_bytes(), (stat.S_IFDIR | 0o755) if path.is_dir() else (stat.S_IFREG | 0o644))
    overlay += cpio_file("TRAILER!!!", b"", 0)
    initrd_name = "initrd" if arguments.profile == "probe" else "initrd-" + arguments.profile
    (CACHE / initrd_name).write_bytes(ramdisk + gzip.compress(overlay, compresslevel=6, mtime=0))
    shutil.copyfile(ROOT / ".build/guest-cache/probe/kernel", CACHE / "kernel")
    manifest = {"image": lock["image"], "profile": arguments.profile, "image_manifest_sha256": lock["manifest_sha256"], "files": {}}
    for name in ("kernel", "initrd", "disk"):
        with (CACHE / (initrd_name if name == "initrd" else name)).open("rb") as source:
            manifest["files"][name] = hashlib.file_digest(source, "sha256").hexdigest()
    manifest_name = "production-manifest.json" if arguments.profile == "runtime" else ("runtime-manifest.json" if arguments.profile == "probe" else "qualification-manifest.json")
    (CACHE / manifest_name).write_text(json.dumps(manifest, indent=2) + "\n")
    print("browser_image_built")


if __name__ == "__main__":
    main()
