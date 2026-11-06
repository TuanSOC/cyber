"""Magic classes (probe) and the root's format check (M9 phase 2). Pure: runs anywhere."""

import pytest
from cyberlab_jobs.disk import ImageFormat

from disk_worker import formats
from disk_worker.probe.magic import magic_class


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (b"MZ\x90\x00", "pe"),
        (b"\x7fELF\x02", "elf"),
        (b"#!/bin/sh\n", "script"),
        (b"PK\x03\x04", "archive"),
        (b"\x1f\x8b\x08", "archive"),
        (b"%PDF-1.7", "document"),
        (b"hello", "other"),
        (b"", "empty"),
    ],
)
def test_magic_class(head: bytes, expected: str) -> None:
    assert magic_class(head, len(head)) == expected


def test_a_zero_size_file_is_empty() -> None:
    assert magic_class(b"MZ", 0) == "empty"


EWF = formats.EWF1 + b"\x01" * 100


@pytest.mark.parametrize(
    ("head", "reason"),
    [
        (b"\x1f\x8b\x08\x00", "gzip"),
        (b"BZh91AY", "bzip2"),
        (b"\xfd7zXZ\x00\x00", "xz"),
        (b"\x28\xb5\x2f\xfd", "zstd"),
        (b"PK\x03\x04", "zip"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"Rar!\x1a\x07\x00", "rar"),
        (b"KDMV\x01\x00", "vmdk"),
        (b"# Disk DescriptorFile\n", "vmdk"),
        (b"vhdxfile", "vhdx"),
        (b"QFI\xfb\x00", "qcow"),
        (b"AFF10\r\n", "aff"),
        (b"EVF2\r\n\x81\x00", "ewf2"),
        (b"LVF\x09\x0d\x0a\xff\x00", "lef"),
    ],
)
def test_refused_formats(head: bytes, reason: str) -> None:
    with pytest.raises(formats.UnsupportedFormat) as exc:
        formats.detect(head + b"\x00" * 64, b"\x00" * 512, 1)
    assert exc.value.reason == reason


def test_a_vhd_footer_is_refused() -> None:
    with pytest.raises(formats.UnsupportedFormat):
        formats.detect(b"\x00" * 4096, b"conectix" + b"\x00" * 504, 1)


def test_accepted_formats_and_segment_names() -> None:
    assert formats.detect(EWF, b"\x00" * 512, 3) == ImageFormat.EWF
    assert formats.detect(b"\xeb\x52\x90NTFS    ", b"", 1) == ImageFormat.RAW
    assert formats.detect(b"\x00" * 512, b"", 4) == ImageFormat.SPLIT_RAW
    assert formats.segment_name(ImageFormat.RAW, 0, 1) == "image.raw"
    assert formats.segment_name(ImageFormat.SPLIT_RAW, 1, 3) == "image.002"
    assert formats.segment_name(ImageFormat.EWF, 0, 2) == "image.E01"
    assert formats.segment_name(ImageFormat.EWF, 63, 64) == "image.E64"
