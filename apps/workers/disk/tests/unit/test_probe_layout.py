"""`layout` and `verify` logic without TSK (M9 phase 2): partition bounds, the refusal
signatures read before any parser (RT15), the family order, the GPT type GUIDs, and the EWF
media-hash status (RT16 / RT17). Pure: runs anywhere."""

import struct
import uuid

from disk_worker.probe import layout, verify
from disk_worker.probe.layout import Part


class Bytes:
    sector_size = 512

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.size = len(data)

    def read(self, offset: int, length: int) -> bytes:
        return self.data[offset : offset + length] if offset >= 0 else b""

    def close(self) -> None:
        pass


def test_partitions_beyond_the_media_or_overlapping_are_errors() -> None:
    parts = [
        Part(0, 2048, 1000, None, None),
        Part(1, 2500, 1000, None, None),
        Part(2, 9000, 2000, None, None),
        Part(3, 4000, 0, None, None),
    ]
    assert layout.check_bounds(parts, media_sectors=10_000) == {
        1: "overlap",
        2: "beyond_media",
        3: "beyond_media",
    }


def _at(offset: int, magic: bytes, size: int = 40_000) -> Bytes:
    data = bytearray(size)
    data[offset : offset + len(magic)] = magic
    return Bytes(bytes(data))


def test_refusal_signatures() -> None:
    assert layout.refusal(_at(3, b"-FVE-FS-"), 0) == ("encrypted", "bitlocker")
    assert layout.refusal(_at(0, b"LUKS\xba\xbe"), 0) == ("encrypted", "luks")
    assert layout.refusal(_at(32, b"NXSB"), 0) == ("unsupported", "apfs")
    assert layout.refusal(_at(512, b"LABELONE"), 0) == ("unsupported", "lvm")
    assert layout.refusal(_at(1024, b"H+"), 0) == ("unsupported", "hfsplus")
    assert layout.refusal(_at(32769, b"CD001"), 0) == ("unsupported", "iso9660")
    assert layout.refusal(_at(3, b"NTFS    "), 0) is None
    # Relative to the partition's own offset.
    assert layout.refusal(_at(4096 + 32, b"NXSB"), 4096) == ("unsupported", "apfs")


def test_the_hinted_family_goes_first() -> None:
    assert layout.family_order(None) == ("ntfs", "fat", "ext")
    assert layout.family_order("ext") == ("ext", "ntfs", "fat")
    assert layout.family_order("fat") == ("fat", "ntfs", "ext")
    assert layout.family_order("apfs") == ("ntfs", "fat", "ext")


def _gpt(entries: list[tuple[str, int]], count: int = 128, size: int = 128) -> Bytes:
    data = bytearray(64 * 1024)
    header = bytearray(92)
    header[:8] = b"EFI PART"
    struct.pack_into("<QII", header, 72, 2, count, size)
    data[512 : 512 + 92] = header
    for i, (guid, first) in enumerate(entries):
        off = 1024 + i * size
        data[off : off + 16] = uuid.UUID(guid).bytes_le
        struct.pack_into("<Q", data, off + 32, first)
    return Bytes(bytes(data))


def test_gpt_type_guids_are_read_bounded() -> None:
    basic = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
    linux = "0fc63daf-8483-4772-8e79-3d69d8477de4"
    types = layout.gpt_types(_gpt([(basic, 2048), (linux, 4096)]), 512)
    assert types == {2048: basic, 4096: linux}
    assert layout.GPT_HINTS[types[2048]] == "ntfs" and layout.GPT_HINTS[types[4096]] == "ext"
    assert layout.gpt_types(_gpt([(basic, 2048)], count=100_000), 512) == {}
    assert layout.gpt_types(_gpt([(basic, 2048)], size=64), 512) == {}
    assert layout.gpt_types(Bytes(bytes(4096)), 512) == {}


class Handle:
    def __init__(self, md5: str | None, sha1: str | None) -> None:
        self.values = {"MD5": md5, "SHA1": sha1}

    def get_hash_value(self, name: str) -> str | None:
        return self.values[name]

    def get_header_value(self, name: str) -> str | None:
        return {"case_number": "C-1\x00\nx", "examiner_name": "é" * 300}.get(name)


def _verify(content: bytes, md5: str | None, sha1: str | None, deadline: float = 60.0) -> dict:
    return verify.verify(lambda o, n: content[o : o + n], len(content), Handle(md5, sha1), deadline)


def test_matched_mismatch_and_absent() -> None:
    import hashlib

    data = b"media" * 1000
    md5, sha1 = hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest()  # noqa: S324
    assert _verify(data, md5, sha1)["media_hash_status"] == "matched"
    assert _verify(data, md5, "0" * 40)["media_hash_status"] == "mismatch"
    assert _verify(data, md5.upper(), None)["media_hash_status"] == "matched"
    out = _verify(data, None, None)
    assert out["media_hash_status"] == "absent"
    assert out["media_sha256"] == hashlib.sha256(data).hexdigest()


def test_a_verify_past_its_deadline_is_not_verified() -> None:
    out = _verify(b"x" * (9 * 1024**2), "a" * 32, None, deadline=-1.0)
    assert out["media_hash_status"] == "not_verified" and out["media_sha256"] is None


def test_garbage_stored_values_count_as_absent() -> None:
    assert _verify(b"x", "not-a-hash", "zz")["media_hash_status"] == "absent"


def test_header_values_are_bounded_and_inert() -> None:
    meta = verify.header_values(Handle(None, None))
    assert meta["case_number"] == "C-1\\x0ax"
    assert len(meta["examiner_name"].encode()) <= 256
