"""Build a synthetic Linux boot probe from the pinned official Alpine archive."""

import gzip
import hashlib
import json
import stat
import struct
import subprocess
import tarfile
from pathlib import Path

RELEASE = "alpine-netboot-3.22.6-aarch64.tar.gz"
SHA256 = "0a39889547d6fb1b0dc124f4baceadd08fef7a72708d5c92774a207f2bc41728"
ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".build/guest-cache"
OUTPUT = CACHE / "probe"


def cpio_file(name: str, contents: bytes, mode: int) -> bytes:
    name_bytes = name.encode() + b"\0"
    fields = [1, mode, 0, 0, 1, 0, len(contents), 0, 0, 0, 0, len(name_bytes), 0]
    header = b"070701" + "".join(f"{field:08x}" for field in fields).encode()
    entry = header + name_bytes
    entry += b"\0" * (-len(entry) % 4)
    entry += contents
    return entry + b"\0" * (-len(contents) % 4)


def main() -> None:
    archive = CACHE / RELEASE
    with archive.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != SHA256:
            raise SystemExit("release_hash_mismatch")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        kernel = tar.extractfile("boot/vmlinuz-virt").read()
        ramdisk = tar.extractfile("boot/initramfs-virt").read()
        (CACHE / "modloop-virt").write_bytes(tar.extractfile("boot/modloop-virt").read())
    if kernel[:8] == b"MZ\0\0zimg" and kernel[24:29] == b"gzip\0":
        offset, size = struct.unpack_from("<II", kernel, 8)
        if offset + size > len(kernel):
            raise SystemExit("invalid_zboot_payload")
        kernel = gzip.decompress(kernel[offset : offset + size])
    elif kernel.startswith(b"\x1f\x8b"):
        kernel = gzip.decompress(kernel)
    init = (ROOT / "images/probe-init.sh").read_bytes()
    overlay = cpio_file("init", init, stat.S_IFREG | 0o755)
    overlay += cpio_file("probe-boundary.py", (ROOT / "images/probe-boundary.py").read_bytes(), stat.S_IFREG | 0o644)
    overlay += cpio_file("probe-codex.py", (ROOT / "images/probe-codex.py").read_bytes(), stat.S_IFREG | 0o644)
    overlay += cpio_file("probe-egress.py", (ROOT / "images/probe-egress.py").read_bytes(), stat.S_IFREG | 0o644)
    overlay += cpio_file("guest_transport", b"", stat.S_IFDIR | 0o755)
    for source in sorted((ROOT / "guest_transport").glob("*.py")):
        overlay += cpio_file("guest_transport/" + source.name, source.read_bytes(), stat.S_IFREG | 0o644)
    subprocess.run([
        "unsquashfs", "-d", str(CACHE / "modloop"), "-f", str(CACHE / "modloop-virt"),
        "modules/*/kernel/net/vmw_vsock/*",
    ], check=True, stdout=subprocess.DEVNULL)
    for file in sorted((CACHE / "modloop/modules").rglob("*")):
        name = "lib/" + str(file.relative_to(CACHE / "modloop"))
        if file.is_dir():
            overlay += cpio_file(name, b"", stat.S_IFDIR | 0o755)
        else:
            overlay += cpio_file(name, file.read_bytes(), stat.S_IFREG | 0o644)
    lock = json.loads((ROOT / "images/python-packages.lock.json").read_text())
    for package in lock["packages"]:
        package_file = CACHE / package["filename"]
        if hashlib.sha256(package_file.read_bytes()).hexdigest() != package["sha256"]:
            raise SystemExit("package_hash_mismatch")
        with tarfile.open(package_file, ignore_zeros=True) as tar:
            for member in tar:
                name = member.name.removeprefix("./")
                if name.startswith("."):
                    continue
                if name.startswith("/") or ".." in Path(name).parts:
                    raise SystemExit("unsafe_archive_member")
                if member.isdir():
                    contents, mode = b"", stat.S_IFDIR | member.mode
                elif member.issym():
                    contents, mode = member.linkname.encode(), stat.S_IFLNK | 0o777
                elif member.isfile() or member.islnk():
                    contents, mode = tar.extractfile(member).read(), stat.S_IFREG | member.mode
                else:
                    raise SystemExit("unsupported_archive_member")
                overlay += cpio_file(name, contents, mode)
    codex_archive = CACHE / "codex-aarch64-unknown-linux-musl.tar.gz"
    if hashlib.sha256(codex_archive.read_bytes()).hexdigest() != "558e12aaa6dacb335ec47240bf9721db8a54746806d64f01185a403f44f79b72":
        raise SystemExit("codex_hash_mismatch")
    with tarfile.open(codex_archive) as tar:
        codex = tar.extractfile("codex-aarch64-unknown-linux-musl").read()
    overlay += cpio_file("usr/bin/codex", codex, stat.S_IFREG | 0o755)
    overlay += cpio_file("TRAILER!!!", b"", 0)
    # Linux accepts concatenated compressed/uncompressed initramfs archives.
    ramdisk += gzip.compress(overlay, mtime=0)
    files = {"kernel": kernel, "initrd": ramdisk, "disk": bytes(4096)}
    manifest = {"release": RELEASE, "release_sha256": SHA256, "files": {}}
    for name, contents in files.items():
        (OUTPUT / name).write_bytes(contents)
        manifest["files"][name] = hashlib.sha256(contents).hexdigest()
    (OUTPUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("synthetic_probe_image_built")


if __name__ == "__main__":
    main()
