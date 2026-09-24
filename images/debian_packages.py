"""Keep the read-only image's package inventory aligned with its archive overlays."""
from dataclasses import dataclass
from pathlib import PurePosixPath
import re


@dataclass(frozen=True)
class DebianOverlay:
    name: str
    version: str
    control: bytes
    files: frozenset[str]


def paragraphs(data):
    return [block for block in data.decode().strip().split("\n\n") if block.strip()]


def field(block, key):
    match = re.search(r"^" + re.escape(key) + r": (.+)$", block, re.M)
    if match is None:
        raise ValueError("missing_package_field:" + key)
    return match.group(1)


def canonical_path(name):
    path = PurePosixPath(name.removeprefix("/"))
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe_package_file")
    value = str(path)
    return "usr/" + value if value.split("/", 1)[0] in {"lib", "bin", "sbin"} else value


def reconcile_packages(merged, overlays, removed):
    """Delete retired payloads, retain shared directories, and replace metadata.

    All contents come from hash-verified OCI/Debian archives. Guest symlinks
    remain archive objects; no guest path is followed on the build host.
    """
    def read(name):
        archive, item = merged.entries[name]
        if not item.isfile():
            raise ValueError("package_metadata_not_regular")
        return archive.extractfile(item).read()

    status = {field(block, "Package"): block for block in paragraphs(read("var/lib/dpkg/status"))}
    removed = set(removed)
    replacements = {p.name: p for p in overlays}
    if len(replacements) != len(overlays):
        raise ValueError("duplicate_package_overlay")
    if not removed <= status.keys() or removed & replacements.keys():
        raise ValueError("invalid_package_removal")
    replacement_status = {}
    for overlay in overlays:
        blocks = paragraphs(overlay.control)
        if len(blocks) != 1 or field(blocks[0], "Package") != overlay.name or field(blocks[0], "Version") != overlay.version:
            raise ValueError("package_control_mismatch")
        if re.search(r"^Status:", blocks[0], re.M):
            raise ValueError("unexpected_package_status")
        replacement_status[overlay.name] = blocks[0]
    ownership = {}
    for name in status:
        candidates = [p for p in merged.entries if re.fullmatch(r"var/lib/dpkg/info/" + re.escape(name) + r"(?::[^/]+)?\.list", p)]
        if len(candidates) != 1:
            raise ValueError("ambiguous_package_inventory:" + name)
        ownership[name] = {canonical_path(p) for p in read(candidates[0]).decode().splitlines()}
    for name, block in (status | replacement_status).items():
        if name not in removed:
            dependencies = set(re.findall(r"(?:^|[,|])\s*([a-z0-9][a-z0-9+.-]+)",
                                          ",".join(re.findall(r"^(?:Pre-Depends|Depends): (.+)$", block, re.M))))
            if dependencies & removed:
                raise ValueError("removed_package_still_required:" + name)
    for name in removed | replacements.keys():
        retained = replacements[name].files if name in replacements else frozenset()
        for path in ownership.get(name, set()) - retained:
            entry = merged.entries.get(path)
            if entry is None or entry[1].isdir():
                continue
            if any(path in paths for other, paths in ownership.items() if other != name and other not in removed):
                raise ValueError("package_file_shared:" + path)
            del merged.entries[path]
        for path in list(merged.entries):
            if re.fullmatch(r"var/lib/dpkg/info/" + re.escape(name) + r"(?::[^/]+)?\.[^/]+", path):
                del merged.entries[path]
        status.pop(name, None)
    additions = {}
    for overlay in overlays:
        block = replacement_status[overlay.name]
        status[overlay.name] = block + "\nStatus: install ok installed\nX-Shadow-Assembled: yes"
        listing = "\n".join("/" + p for p in sorted(overlay.files)) + "\n"
        additions["var/lib/dpkg/info/" + overlay.name + ".list"] = (listing.encode(), 0o644)
    additions["var/lib/dpkg/status"] = (("\n\n".join(status[name] for name in sorted(status)) + "\n").encode(), 0o644)
    return additions
