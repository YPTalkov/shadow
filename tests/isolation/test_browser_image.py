"""Image assembly never materializes guest symlinks on the host."""
import io
import tarfile

import pytest

from images.build_browser import LayerSet, canonical_debian_layer


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
