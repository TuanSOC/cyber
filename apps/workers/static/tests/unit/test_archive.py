"""Archive pre-check (RT2): zips ClamAV finds anywhere, zip64, nesting, fail-closed parsing.

ClamAV 1.4 behaviour this mirrors (measured in the image): a zip member above
--max-filesize is trimmed without an alert, also when the zip is prefixed, appended to a PE
or nested; zip64 members are not scanned; tar / gzip / bzip2 / xz raise their own
`Heuristics.Limits.Exceeded.*` alert (integration tests). No 7z / RAR writer exists in the
image (no 7z/rar binaries, no py7zr), so those containers are only recognised by their
magic and always reported as unchecked.

The check measures members by inflating them itself: headers that lie about the size, and
local headers with odd versions / name lengths (which ClamAV still extracts), are caught.
"""

import hashlib
import io
import zipfile
from pathlib import Path

import pytest

from samples import pe
from samples.generate import (
    PREFIX,
    ZIP_DATE,
    deflate_zeros,
    hidden_in_extra,
    large_member_zip,
    local_entry,
    lying_size_zip,
    nested_zip,
    odd_local_headers,
    raw_deflate,
    zip64_data_descriptor,
    zip_in_extra_field,
)
from static_worker.engines import clamav
from static_worker.probe import archive

MEMBER = 70 * 1024 * 1024
LOCAL = b"PK\x03\x04"


@pytest.fixture(scope="module")
def large() -> bytes:
    return large_member_zip()


def check(tmp_path: Path, data: bytes) -> archive.ArchiveCheck:
    path = tmp_path / "sample"
    path.write_bytes(data)
    result, digest = archive.check(path)
    assert digest == hashlib.sha256(data).hexdigest()
    return result


def flagged(result: archive.ArchiveCheck) -> bool:
    record = result.record("0" * 64)
    return clamav.exceeds_limits({k: v for k, v in record.items() if v is not None})


def small_zip(*members: tuple[str, bytes], stream: bool = False) -> bytes:
    buffer = io.BytesIO()
    target: io.BytesIO | io.RawIOBase = buffer
    if stream:  # write-only: data descriptors (flag bit 3), as streaming zippers do

        class Out(io.RawIOBase):
            def writable(self) -> bool:
                return True

            def write(self, data: bytes) -> int:  # type: ignore[override]
                return buffer.write(data)

        target = Out()
    with zipfile.ZipFile(target, "w") as z:
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            with z.open(info, "w") as f:
                f.write(data)
    return buffer.getvalue()


def benign_pe() -> bytes:
    return pe.build(pe.PeSpec(sections=[pe.Section(".text", b"\x90" * 64 + b"\xc3", pe.TEXT)]))


def test_plain_files_are_not_archives(tmp_path: Path) -> None:
    noise = [LOCAL + bytes(26), LOCAL + b"\x14\x00\x00\x00\x08\x00" + bytes(40)]
    for data in (b"", b"hello", benign_pe(), *noise):  # headers that yield no data: noise
        result = check(tmp_path, data)
        assert result.format == "none" and not flagged(result), (data[:8], result.reasons)


def test_small_zips_pass(tmp_path: Path) -> None:
    for stream in (False, True):
        data = small_zip(("a.txt", b"alpha" * 100), ("b.bin", bytes(5000)), stream=stream)
        result = check(tmp_path, data)
        assert result.format == "zip" and result.members == 2 and not flagged(result)
        assert result.reasons == []


def test_nested_small_zips_are_walked(tmp_path: Path) -> None:
    inner = small_zip(("deep.txt", b"x" * 1000), stream=True)
    result = check(tmp_path, nested_zip(nested_zip(inner)))
    assert result.depth == 3 and result.members == 3 and not flagged(result), result.reasons


def test_plain_large_member(tmp_path: Path, large: bytes) -> None:
    result = check(tmp_path, large)
    assert result.largest_member == MEMBER and flagged(result)


@pytest.mark.parametrize("kind", ["prefixed", "sfx", "nested_prefixed", "nested_sfx"])
def test_zip_found_anywhere(tmp_path: Path, large: bytes, kind: str) -> None:
    """ClamAV scans (and trims) these; the pre-check must see the large member too."""
    data = {
        "prefixed": PREFIX * 64 + large,
        "sfx": benign_pe() + large,
        "nested_prefixed": nested_zip(PREFIX * 16 + large),
        "nested_sfx": nested_zip(benign_pe() + large),
    }[kind]
    result = check(tmp_path, data)
    assert result.format == "zip" and result.largest_member == MEMBER, result
    assert flagged(result)


def test_zip64_members_are_unchecked(tmp_path: Path) -> None:
    """ClamAV skips zip64 members (with or without a data descriptor)."""
    result = check(tmp_path, zip64_data_descriptor())
    assert result.unchecked and "zip64" in result.reasons
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z, z.open("x.txt", "w", force_zip64=True) as f:
        f.write(b"seekable zip64")
    assert check(tmp_path, buffer.getvalue()).unchecked
    assert check(tmp_path, nested_zip(buffer.getvalue())).unchecked  # nested as well


def test_zip_content_outside_the_central_directory(tmp_path: Path) -> None:
    data = small_zip(("a.txt", b"alpha" * 100))
    local_only = data[: data.index(b"PK\x01\x02")]  # no central directory at all
    result = check(tmp_path, local_only)
    assert result.unchecked and "orphan_local_header" in result.reasons
    # A zip embedded in the middle of a file, followed by a second, valid one.
    hidden = small_zip(("hidden.bin", b"hidden data " * 50))
    embedded = PREFIX + hidden[: hidden.index(b"PK\x01\x02")] + PREFIX + data
    result = check(tmp_path, embedded)
    assert result.unchecked and "orphan_local_header" in result.reasons


def test_encrypted_and_broken_members(tmp_path: Path) -> None:
    data = bytearray(small_zip(("a.txt", b"alpha" * 100)))
    flags_at = data.index(b"PK\x01\x02") + 8  # central directory flag bits
    data[flags_at] |= 1
    data[6] |= 1  # local header flag bits
    assert check(tmp_path, bytes(data)).encrypted
    broken = bytearray(small_zip(("a.txt", bytes(range(256)) * 40)))
    broken[60:80] = b"\xff" * 20  # corrupt the deflate stream
    assert check(tmp_path, bytes(broken)).unchecked
    bzip2 = io.BytesIO()
    with zipfile.ZipFile(bzip2, "w", zipfile.ZIP_BZIP2) as z:
        z.writestr("a.txt", b"alpha" * 100)
    assert "method_12" in check(tmp_path, bzip2.getvalue()).reasons  # not measurable here


def test_7z_and_rar_are_never_assumed_complete(tmp_path: Path) -> None:
    for magic, name in ((archive.SEVENZ, "7z"), (archive.RAR, "rar")):
        result = check(tmp_path, magic + bytes(64))
        assert result.format == name and flagged(result)


def test_inflate_budget_and_depth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = nested_zip(nested_zip(small_zip(("a.txt", LOCAL + b" not a header"))))
    monkeypatch.setattr(archive, "MAX_DEPTH", 2)
    assert "depth" in check(tmp_path, data).reasons
    monkeypatch.setattr(archive, "MAX_DEPTH", 20)
    monkeypatch.setattr(archive, "INFLATE_BUDGET", 100)
    assert "inflate_budget" in check(tmp_path, data).reasons


@pytest.mark.parametrize("prefixed", [False, True])
def test_headers_lying_about_the_size(tmp_path: Path, prefixed: bool) -> None:
    """Declared 1024 bytes (local + central), real 2 MiB: ClamAV inflates the real stream."""
    real = small_zip(("m.bin", bytes(2 * 1024 * 1024) + b"marker"))
    prefix = PREFIX if prefixed else b""
    result = check(tmp_path, prefix + lying_size_zip(real, 1024))
    assert result.largest_member == 1024  # what the headers claim ...
    assert flagged(result) and "size_mismatch" in result.reasons  # ... is not trusted
    honest = check(tmp_path, prefix + real)
    assert not flagged(honest), honest.reasons


def test_stored_member_sizes_must_agree(tmp_path: Path) -> None:
    stored = io.BytesIO()
    with zipfile.ZipFile(stored, "w", zipfile.ZIP_STORED) as z:
        z.writestr("a.txt", b"alpha" * 100)
    assert not flagged(check(tmp_path, stored.getvalue()))
    assert "size_mismatch" in check(tmp_path, lying_size_zip(stored.getvalue(), 10)).reasons


@pytest.mark.parametrize("kind", ["nameless", "version_255", "long_name"])
def test_odd_local_headers_are_counted(tmp_path: Path, kind: str) -> None:
    """ClamAV extracts these (no central directory; nlen 0 / version 255 / 5000-byte name)."""
    result = check(tmp_path, odd_local_headers(mib=2)[kind])
    assert result.format == "zip" and "orphan_local_header" in result.reasons
    assert result.largest_member == 2 * 1024 * 1024 and flagged(result)


def test_orphan_is_measured_by_its_real_stream(tmp_path: Path) -> None:
    """A local header claiming 0 bytes whose deflate stream yields 1 MiB is still seen."""
    result = check(tmp_path, PREFIX + local_entry(deflate_zeros(1), 0))
    assert result.largest_member == 1024 * 1024 and flagged(result)


@pytest.mark.parametrize("prefixed", [False, True])
def test_entry_hidden_in_a_members_extra_field(tmp_path: Path, prefixed: bool) -> None:
    """Only a member's DATA is covered: a local entry in its name / extra field is an orphan."""
    payload = local_entry(raw_deflate(bytes(2 * 1024 * 1024) + b"marker"), 2 * 1024 * 1024 + 6)
    data = (PREFIX if prefixed else b"") + hidden_in_extra(payload)
    assert zipfile.ZipFile(io.BytesIO(data)).read("cover.txt") == b"cover member\n"
    result = check(tmp_path, data)
    assert "orphan_local_header" in result.reasons and flagged(result), result.reasons
    assert result.largest_member == 2 * 1024 * 1024 + 6
    big = zip_in_extra_field()  # the integration sample: < 64 KiB extra, 70 MiB inside
    assert len(big) < 64 * 1024 and flagged(check(tmp_path, big))
    assert not flagged(check(tmp_path, hidden_in_extra(b"no zip here")))


def test_member_cap_matches_clamav() -> None:
    assert archive.MAX_MEMBER_BYTES == clamav.MAX_FILESIZE
