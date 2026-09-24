"""Image assembly never materializes guest symlinks on the host."""
import io
import tarfile

import pytest

from images.build_browser import LayerSet, canonical_debian_layer, squashfs_modules
from images.debian_packages import DebianOverlay, reconcile_packages


def layer(path, entries):
    with tarfile.open(path, "w") as archive:
        for name, value in entries:
            item = tarfile.TarInfo(name)
            if isinstance(value, tuple):
                item.type = tarfile.SYMTYPE
                item.linkname = value[0]
                archive.addfile(item)
            else:
                item.size = len(value)
                archive.addfile(item, io.BytesIO(value))
    return path


def test_layers_replace_and_whiteout_without_host_extraction(tmp_path):
    first = layer(tmp_path / "first.tar", [("a", b"old"), ("removed", b"old"), ("tree/old", b"old"), ("absolute", ("/etc/passwd",))])
    second = layer(tmp_path / "second.tar", [("a", b"new"), (".wh.removed", b""), ("tree/.wh..wh..opq", b""), ("tree/new", b"new")])
    with LayerSet([first, second]) as merged:
        assert merged.names == {"a", "tree/new", "absolute"}
        output = io.BytesIO()
        merged.write(output)
    with tarfile.open(fileobj=io.BytesIO(output.getvalue())) as archive:
        assert archive.extractfile("a").read() == b"new"
        assert archive.getmember("absolute").linkname == "/etc/passwd"
    assert not (tmp_path / "absolute").exists()


@pytest.mark.parametrize("name", ["../escape", "/escape", "a/../../escape"])
def test_layer_path_traversal_is_rejected(tmp_path, name):
    with pytest.raises(ValueError, match="unsafe_image_path"):
        with LayerSet([layer(tmp_path / "bad.tar", [(name, b"bad")])]):
            pass


def test_child_under_symlink_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="image_parent_is_not_directory"):
        with LayerSet([layer(tmp_path / "bad.tar", [("escape", ("/tmp",)), ("escape/file", b"bad")])]):
            pass


def test_debian_usr_merge_preserves_the_base_loader_symlink(tmp_path):
    base = layer(tmp_path / "base.tar", [("lib", ("usr/lib",)), ("usr/lib/loader", b"loader")])
    source = tmp_path / "deb.tar"
    with tarfile.open(source, "w") as archive:
        directory = tarfile.TarInfo("./lib")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        value = tarfile.TarInfo("./lib/udev/fixture")
        value.size = 4
        archive.addfile(value, io.BytesIO(b"data"))
    normalized = tmp_path / "normalized.tar"
    canonical_debian_layer(source, normalized)
    with LayerSet([base, normalized]) as merged:
        assert merged.entries["lib"][1].issym()
        assert "usr/lib/udev/fixture" in merged.names
        assert "usr/lib/loader" in merged.names


def test_kernel_module_case_is_preserved_without_host_extraction(monkeypatch, tmp_path):
    listing = "\n".join("-rw-r--r-- 0/0 5 2026-09-24 00:00 squashfs-root/modules/kernel/" + name for name in ("xt_DSCP.ko", "xt_dscp.ko"))

    def read(command, **kwargs):
        if "-lln" in command:
            return listing
        return b"UPPER" if command[-1].endswith("xt_DSCP.ko") else b"lower"

    monkeypatch.setattr("images.build_browser.subprocess.check_output", read)
    files = list(squashfs_modules(tmp_path / "modloop"))
    assert [(name, data) for name, data, _ in files] == [
        ("lib/modules/kernel/xt_DSCP.ko", b"UPPER"),
        ("lib/modules/kernel/xt_dscp.ko", b"lower"),
    ]
    assert not list(tmp_path.iterdir())


def test_package_removal_and_upgrade_preserve_other_files_and_inventory(tmp_path):
    status = b"Package: obsolete\nVersion: 1\n\nPackage: retained\nVersion: 1\n"
    base = layer(tmp_path / "base.tar", [
        ("var/lib/dpkg/status", status),
        ("var/lib/dpkg/info/obsolete:arm64.list", b"/usr/lib/unused.so\n"),
        ("var/lib/dpkg/info/retained:arm64.list", b"/usr/lib/old.so\n"),
        ("usr/lib/unused.so", b"vulnerable"), ("usr/lib/old.so", b"old"),
        ("usr/lib/unrelated.so", b"keep"),
    ])
    update = layer(tmp_path / "update.tar", [("usr/lib/new.so", b"patched")])
    overlay = DebianOverlay("retained", "2", b"Package: retained\nVersion: 2\nArchitecture: arm64\n", frozenset({"usr/lib/new.so"}))
    with LayerSet([base, update]) as merged:
        additions = reconcile_packages(merged, [overlay], ["obsolete"])
        output = io.BytesIO()
        merged.write(output, additions)
    with tarfile.open(fileobj=io.BytesIO(output.getvalue())) as archive:
        names = archive.getnames()
        assert "usr/lib/unused.so" not in names and "usr/lib/old.so" not in names
        assert "var/lib/dpkg/info/obsolete:arm64.list" not in names
        assert archive.extractfile("usr/lib/new.so").read() == b"patched"
        assert archive.extractfile("usr/lib/unrelated.so").read() == b"keep"
        status = archive.extractfile("var/lib/dpkg/status").read()
        assert b"obsolete" not in status and b"Version: 2" in status
        assert archive.extractfile("var/lib/dpkg/info/retained.list").read() == b"/usr/lib/new.so\n"


@pytest.mark.parametrize("dependency", ["Depends: obsolete (>= 1)", "Depends: other\nPre-Depends: obsolete"])
def test_required_or_untracked_package_cannot_be_removed(tmp_path, dependency):
    base = layer(tmp_path / "base.tar", [
        ("var/lib/dpkg/status", ("Package: obsolete\nVersion: 1\n\nPackage: consumer\nVersion: 1\n" + dependency + "\n").encode()),
        ("var/lib/dpkg/info/obsolete.list", b"/usr/lib/shared.so\n"),
        ("var/lib/dpkg/info/consumer.list", b"/usr/bin/consumer\n"),
        ("usr/lib/shared.so", b"library"),
    ])
    with LayerSet([base]) as merged:
        with pytest.raises(ValueError, match="removed_package_still_required"):
            reconcile_packages(merged, [], ["obsolete"])
        assert "usr/lib/shared.so" in merged.names
        with pytest.raises(ValueError, match="invalid_package_removal"):
            reconcile_packages(merged, [], ["unknown"])


def test_new_dependency_and_shared_files_prevent_removal(tmp_path):
    base = layer(tmp_path / "base.tar", [
        ("var/lib/dpkg/status", b"Package: obsolete\nVersion: 1\n\nPackage: consumer\nVersion: 1\n"),
        ("var/lib/dpkg/info/obsolete.list", b"/usr/lib/shared.so\n"),
        ("var/lib/dpkg/info/consumer.list", b"/usr/lib/shared.so\n"),
        ("usr/lib/shared.so", b"library"),
    ])
    overlay = DebianOverlay("consumer", "2", b"Package: consumer\nVersion: 2\nDepends: obsolete\n", frozenset({"usr/lib/shared.so"}))
    with LayerSet([base]) as merged:
        with pytest.raises(ValueError, match="removed_package_still_required"):
            reconcile_packages(merged, [overlay], ["obsolete"])
        with pytest.raises(ValueError, match="package_file_shared"):
            reconcile_packages(merged, [], ["obsolete"])
        assert "usr/lib/shared.so" in merged.names


def test_package_overlay_identity_and_inventory_paths_are_checked(tmp_path):
    base = layer(tmp_path / "base.tar", [
        ("var/lib/dpkg/status", b"Package: retained\nVersion: 1\n"),
        ("var/lib/dpkg/info/retained.list", b"/../escape\n"),
    ])
    with LayerSet([base]) as merged:
        with pytest.raises(ValueError, match="unsafe_package_file"):
            reconcile_packages(merged, [], [])
    clean = layer(tmp_path / "clean.tar", [
        ("var/lib/dpkg/status", b"Package: retained\nVersion: 1\n"),
        ("var/lib/dpkg/info/retained.list", b"/usr/lib/old.so\n"),
    ])
    with LayerSet([clean]) as merged:
        wrong = DebianOverlay("new", "2", b"Package: other\nVersion: 2\n", frozenset())
        with pytest.raises(ValueError, match="package_control_mismatch"):
            reconcile_packages(merged, [wrong], [])
