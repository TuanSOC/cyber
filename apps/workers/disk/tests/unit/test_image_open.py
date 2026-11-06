"""Image openers (M9 phase 2): the bounds-checked split-raw reader, the media-size cap (RT6) and
refused paths. The EWF opener needs pyewf and phase 4's E01 sets (`tests/engine`)."""

import os
from pathlib import Path

import pytest

from disk_worker.probe import image

posix = pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="Linux semantics")


def _segments(tmp_path: Path, parts: list[bytes]) -> list[Path]:
    paths = []
    for i, data in enumerate(parts):
        p = tmp_path / f"image.{i + 1:03d}"
        p.write_bytes(data)
        paths.append(p)
    return paths


@posix
def test_split_raw_reads_across_segment_boundaries(tmp_path: Path) -> None:
    reader = image.SegmentReader(_segments(tmp_path, [b"abc", b"", b"defg", b"h"]))
    try:
        assert reader.size == 8
        assert reader.read(0, 8) == b"abcdefgh"
        assert reader.read(2, 3) == b"cde"
        assert reader.read(6, 100) == b"gh"  # short at the end, never an error
        assert reader.read(8, 1) == b"" and reader.read(-1, 4) == b"" and reader.read(0, 0) == b""
    finally:
        reader.close()


@posix
def test_a_symlinked_or_special_segment_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "real"
    target.write_bytes(b"x")
    link = tmp_path / "image.raw"
    link.symlink_to(target)
    with pytest.raises(OSError):
        image.SegmentReader([link])
    with pytest.raises(image.ImageError):
        image.SegmentReader([tmp_path])  # a directory


@posix
def test_media_larger_than_the_cap_is_unsupported(tmp_path: Path) -> None:
    paths = _segments(tmp_path, [b"x" * 100])
    with pytest.raises(image.ImageError) as exc:
        image.open_image({"format": "raw", "paths": [str(p) for p in paths], "max_media": 99})
    assert exc.value.code == "unsupported_disk_format" and exc.value.reason == "media_size"


def test_relative_paths_and_unknown_formats_are_refused() -> None:
    with pytest.raises(image.ImageError):
        image.open_image({"format": "raw", "paths": ["image.raw"], "max_media": 10})
    with pytest.raises(image.ImageError):
        image.open_image({"format": "vmdk", "paths": ["/work/x/image.raw"], "max_media": 10})


def test_tsk_int_accepts_enums_and_ints() -> None:
    class Enum:
        value = 7

    assert image.tsk_int(5) == 5
    assert image.tsk_int(Enum()) == 7
