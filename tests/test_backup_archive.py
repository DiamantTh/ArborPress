from __future__ import annotations

import bz2
import importlib.util
import os
import tarfile
from pathlib import Path

import pytest

from arborpress.backups.archive import (
    DEFAULT_MEDIA_SEGMENT_SIZE,
    UnsafeArchiveEntryError,
    UnstableFileError,
    _partition_media,
    _stable_copy,
    create_component_archives,
    scan_tree,
)
from arborpress.backups.compression import (
    CompressionSettings,
    CompressionUnavailableError,
    open_compressed_reader,
    open_compressed_writer,
)


def test_bz2_profiles_and_custom_levels() -> None:
    assert CompressionSettings(profile="fast").effective_level == 1
    assert CompressionSettings().effective_level == 6
    assert CompressionSettings(profile="strong").effective_level == 9
    assert CompressionSettings(profile="custom", level=3).effective_level == 3
    assert CompressionSettings(backend="bz3", profile="fast").effective_block_size == 500_000
    assert CompressionSettings(backend="bz3").effective_block_size == 900_000
    assert CompressionSettings(backend="bz3", profile="strong").effective_block_size == 1_500_000
    assert CompressionSettings(backend="bz3", threads=4).effective_threads == 4
    assert (
        CompressionSettings(backend="bz3", profile="custom", level=4).effective_block_size
        == 800_000
    )
    with pytest.raises(ValueError, match="between 1 and 9"):
        CompressionSettings(profile="custom", level=10)
    with pytest.raises(ValueError, match="not parallel"):
        CompressionSettings(threads=2)


def test_bz3_uses_only_the_optional_python_library(tmp_path: Path) -> None:
    path = tmp_path / "stream.bz3"
    settings = CompressionSettings(backend="bz3", threads=2)
    if importlib.util.find_spec("bz3") is None:
        with pytest.raises(CompressionUnavailableError, match="backup-bz3"):
            with open_compressed_writer(path, settings):
                pass
        assert not path.exists()
        return
    with open_compressed_writer(path, settings) as stream:
        stream.write(b"python-library-only")
    with open_compressed_reader(path, "bz3") as stream:
        assert stream.read() == b"python-library-only"


def test_media_segment_partition_is_payload_based_and_keeps_oversize_file_whole(
    tmp_path: Path,
) -> None:
    root = tmp_path / "media"
    root.mkdir()
    for name, size in (("a", 6), ("b", 6), ("large", 20), ("c", 4)):
        (root / name).write_bytes(b"x" * size)
    entries = scan_tree(root)

    groups = _partition_media(entries, 10)

    assert [
        [entry.relative_path.name for entry in group if entry.kind == "file"] for group in groups
    ] == [["a"], ["b", "c"], ["large"]]
    assert DEFAULT_MEDIA_SEGMENT_SIZE == 2 * 1024**3


def test_archive_is_pax_tar_and_contains_stable_relative_files(tmp_path: Path) -> None:
    component = tmp_path / "instance" / "themes"
    long_directory = "d" * 80
    long_filename = "s" * 40 + ".css"
    (component / long_directory).mkdir(parents=True)
    (component / long_directory / long_filename).write_text(
        "body { color: red; }", encoding="utf-8"
    )
    paths = create_component_archives(
        root=component,
        destination=tmp_path / "set",
        component="themes",
        backup_id="20261018-120000",
        compression=CompressionSettings(),
        temporary_root=tmp_path / "tmp",
    )

    result = paths[0]
    assert result.file.archive_format == "tar-pax+bz2"
    assert result.file.uncompressed_size_bytes == len("body { color: red; }")
    with bz2.open(result.archive_path, "rb") as stream:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            members = list(archive)
    assert [member.name for member in members] == [
        long_directory,
        f"{long_directory}/{long_filename}",
    ]
    assert members[-1].pax_headers


def test_unsafe_symlink_is_rejected_without_dereferencing(tmp_path: Path) -> None:
    root = tmp_path / "themes"
    root.mkdir()
    outside = tmp_path / "secret"
    outside.write_text("private", encoding="utf-8")
    (root / "escape").symlink_to(outside)

    with pytest.raises(UnsafeArchiveEntryError, match="Absolute symlink|escapes"):
        scan_tree(root)


def test_safe_relative_symlink_is_preserved_without_following_it(tmp_path: Path) -> None:
    root = tmp_path / "themes"
    (root / "assets").mkdir(parents=True)
    (root / "assets" / "logo.txt").write_text("logo", encoding="utf-8")
    (root / "logo.txt").symlink_to("assets/logo.txt")

    result = create_component_archives(
        root=root,
        destination=tmp_path / "set",
        component="themes",
        backup_id="20261018-120000",
        compression=CompressionSettings(),
        temporary_root=tmp_path / "tmp",
    )[0]

    assert result.file.member_paths == ("assets", "assets/logo.txt", "logo.txt")
    with bz2.open(result.archive_path, "rb") as stream:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            members = list(archive)
    assert members[-1].issym()
    assert members[-1].linkname == "assets/logo.txt"


@pytest.mark.skipif(os.name != "posix", reason="FIFO metadata is POSIX-specific")
def test_special_files_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "plugins"
    root.mkdir()
    os.mkfifo(root / "pipe")

    with pytest.raises(UnsafeArchiveEntryError, match="special file"):
        scan_tree(root)


def test_stable_copy_stages_file_content_and_rejects_non_regular(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_bytes(b"stable data")
    staged, size = _stable_copy(
        source, temporary_root=tmp_path / "tmp", relative=Path("source.txt")
    )
    try:
        assert size == 11
        assert staged.read_bytes() == b"stable data"
    finally:
        staged.unlink()
    with pytest.raises(UnstableFileError, match="stable backup file"):
        _stable_copy(
            tmp_path / "missing",
            temporary_root=tmp_path / "tmp",
            relative=Path("missing"),
        )


def test_stable_copy_retries_after_detecting_a_concurrent_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.backups import archive as archive_module

    source = tmp_path / "source.txt"
    source.write_bytes(b"before")
    original_signature = archive_module._stat_signature
    signature_calls = 0

    def change_after_open(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
        nonlocal signature_calls
        signature_calls += 1
        if signature_calls == 2:
            source.write_bytes(b"changed while read")
        return original_signature(metadata)

    monkeypatch.setattr(archive_module, "_stat_signature", change_after_open)
    staged, size = _stable_copy(
        source, temporary_root=tmp_path / "tmp", relative=Path("source.txt")
    )
    try:
        assert staged.read_bytes() == b"changed while read"
        assert size == len(b"changed while read")
        assert signature_calls >= 6
    finally:
        staged.unlink()
