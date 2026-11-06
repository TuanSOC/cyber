"""The synthetic disk image generator (M9 phase 4) without Docker or any image tool.

The pure-Python images (FAT12 / 16 / 32, MBR / GPT, split raw, the FAT32 route of
`ntfs_windows`) are parsed back here by an independent minimal FAT / MBR / GPT reader written
for this test (not the generator's code) and compared with their `ground_truth.json`; the
regf base hive, the EWF section patcher, the exFAT boot checksum, the ext staging and debugfs
script and the pure hostile mutations are checked structurally. The tool-built images are
checked in `tests/engine/test_diskgen_images.py` (dev / test image).
"""

import hashlib
import json
import os
import random
import struct
import uuid
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from samples.diskgen import (
    BASE_TIME,
    MAX_IMAGE_BYTES,
    ewf,
    fs_exfat,
    fs_ext,
    hives,
    images,
    layouts,
    mutate,
    trees,
)
from samples.diskgen import __main__ as cli
from samples.diskgen import ground_truth as gt
from samples.diskgen.images import Generator

PURE = ("fat_basic", "fat12", "fat16", "ntfs_windows", "split_raw")


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> dict[str, images.Built]:
    gen = Generator(tmp_path_factory.mktemp("diskgen"), ntfs_route="fat32")
    return {i: gen.build(i) for i in PURE}


# --- an independent minimal reader -------------------------------------------------------------


def _u16(b: bytes, off: int) -> int:
    return int(struct.unpack_from("<H", b, off)[0])


def _u32(b: bytes, off: int) -> int:
    return int(struct.unpack_from("<I", b, off)[0])


def _dos(date: int, time: int = 0, tenth: int = 0) -> int:
    dt = datetime(
        1980 + (date >> 9),
        (date >> 5) & 15,
        date & 31,
        time >> 11,
        (time >> 5) & 63,
        (time & 31) * 2,
        tzinfo=UTC,
    )
    return int(dt.timestamp()) + tenth // 100


class Fat:
    def __init__(self, vol: bytes) -> None:
        assert vol[510:512] == b"\x55\xaa"
        self.vol = vol
        self.bps, self.spc = _u16(vol, 11), vol[13]
        self.reserved, self.nfats, self.root_entries = _u16(vol, 14), vol[16], _u16(vol, 17)
        self.total = _u16(vol, 19) or _u32(vol, 32)
        self.fatsz = _u16(vol, 22) or _u32(vol, 36)
        root_secs = (self.root_entries * 32 + self.bps - 1) // self.bps
        self.root_off = (self.reserved + self.nfats * self.fatsz) * self.bps
        self.data_sec = self.reserved + self.nfats * self.fatsz + root_secs
        self.clusters = (self.total - self.data_sec) // self.spc
        self.bits = 12 if self.clusters < 4085 else 16 if self.clusters < 65525 else 32
        self.cb = self.bps * self.spc
        fat_off = self.reserved * self.bps
        self.fat_raw = vol[fat_off : fat_off + self.fatsz * self.bps]
        self.used: dict[int, str] = {}

    def next(self, n: int) -> int:
        if self.bits == 12:
            v = _u16(self.fat_raw, n * 3 // 2)
            return v >> 4 if n % 2 else v & 0xFFF
        if self.bits == 16:
            return _u16(self.fat_raw, 2 * n)
        return _u32(self.fat_raw, 4 * n) & 0x0FFFFFFF

    def eoc(self, v: int) -> bool:
        return v >= {12: 0xFF8, 16: 0xFFF8, 32: 0x0FFFFFF8}[self.bits]

    def chain(self, start: int, owner: str) -> list[int]:
        out: list[int] = []
        c = start
        while 2 <= c < self.clusters + 2:
            assert c not in self.used, f"cluster {c} cross-linked: {owner} / {self.used.get(c)}"
            self.used[c] = owner
            out.append(c)
            c = self.next(c)
        assert self.eoc(c), (owner, c)
        return out

    def read(self, clusters: list[int]) -> bytes:
        return b"".join(
            self.vol[(self.data_sec + (c - 2) * self.spc) * self.bps :][: self.cb] for c in clusters
        )

    def entries(self, raw: bytes) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        lfn: dict[int, str] = {}
        sums: set[int] = set()
        for i in range(0, len(raw), 32):
            e = raw[i : i + 32]
            if e[0] == 0:
                break
            if e[11] == 0x0F:
                units = struct.unpack_from("<5H", e, 1) + struct.unpack_from("<6H", e, 14)
                units += struct.unpack_from("<2H", e, 28)
                chars = b"".join(struct.pack("<H", u) for u in units if u not in (0, 0xFFFF))
                lfn[e[0] & 0x1F] = chars.decode("utf-16-le", "surrogatepass")
                sums.add(e[13])
                continue
            short = e[:11]
            checksum = 0
            for byte in short:
                checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 0xFF
            deleted = e[0] == 0xE5
            name = None
            if lfn and not deleted:
                assert sums == {checksum}, "long-name checksum"
                name = "".join(lfn[k] for k in sorted(lfn))
            lfn, sums = {}, set()
            base, ext = short[:8].rstrip(b" ").decode("latin-1"), short[8:].rstrip(b" ").decode()
            if name is None:
                name = base + ("." + ext if ext else "")
                if deleted:
                    name = "_" + name[1:]
            cluster = (_u16(e, 20) << 16) | _u16(e, 26)
            out.append(
                {
                    "name": name,
                    "dir": bool(e[11] & 0x10),
                    "cluster": cluster,
                    "size": _u32(e, 28),
                    "deleted": deleted,
                    "mtime": _dos(_u16(e, 24), _u16(e, 22)),
                    "crtime": _dos(_u16(e, 16), _u16(e, 14), e[13]),
                    "atime": _dos(_u16(e, 18)),
                }
            )
        return out

    def walk(self) -> dict[str, dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        if self.bits == 32:
            root = self.read(self.chain(_u32(self.vol, 44), "/"))
        else:
            root = self.vol[self.root_off : self.root_off + self.root_entries * 32]
        stack = [("", root, 0)]
        while stack:
            path, raw, here = stack.pop()
            for e in self.entries(raw):
                if e["name"] in (".", ".."):
                    want = here if e["name"] == "." else None
                    if want is not None:
                        assert e["cluster"] == want
                    continue
                full = f"{path}/{e['name']}"
                found[full] = e
                if e["deleted"]:
                    continue
                if e["dir"]:
                    clusters = self.chain(e["cluster"], full)
                    stack.append((full, self.read(clusters), e["cluster"]))
                else:
                    clusters = self.chain(e["cluster"], full) if e["size"] else []
                    assert e["cluster"] or not e["size"]
                    assert (len(clusters) - 1) * self.cb < e["size"] or not e["size"]
                    assert len(clusters) * self.cb >= e["size"]
                    e["data"] = self.read(clusters)[: e["size"]]
        return found

    def free(self) -> int:
        return sum(1 for n in range(2, self.clusters + 2) if self.next(n) == 0)


def _mbr(disk: bytes) -> list[tuple[int, int, int]]:
    assert disk[510:512] == b"\x55\xaa"
    out = []
    for i in range(4):
        e = disk[446 + 16 * i : 462 + 16 * i]
        if e[4]:
            out.append((e[4], _u32(e, 8), _u32(e, 12)))
    return out


def _gpt(disk: bytes) -> list[tuple[uuid.UUID, int, int]]:
    total = len(disk) // 512
    out = []
    for lba in (1, total - 1):
        h = disk[lba * 512 : lba * 512 + 92]
        assert h[:8] == b"EFI PART"
        crc = _u32(h, 16)
        assert zlib.crc32(h[:16] + b"\0\0\0\0" + h[20:92]) == crc
        array_lba, count, size = struct.unpack_from("<QII", h, 72)
        array = disk[array_lba * 512 : array_lba * 512 + count * size]
        assert zlib.crc32(array) == _u32(h, 88)
        assert struct.unpack_from("<QQ", h, 24) == ((lba, total - 1) if lba == 1 else (lba, 1))
        if lba == 1:
            for i in range(count):
                raw = array[i * size : (i + 1) * size]
                if raw[:16] != bytes(16):
                    first, last = struct.unpack_from("<QQ", raw, 32)
                    out.append((uuid.UUID(bytes_le=raw[:16]), first, last - first + 1))
    return out


# --- the pure images against their ground truth ----------------------------------------------


@pytest.mark.parametrize("image_id", ["fat_basic", "fat12", "fat16", "ntfs_windows"])
def test_fat_images_read_back_as_their_ground_truth(
    built: dict[str, images.Built], image_id: str
) -> None:
    b = built[image_id]
    truth = json.loads((b.directory / "ground_truth.json").read_text(encoding="utf-8"))
    assert truth == b.truth
    disk = b.raw.read_bytes()
    assert len(disk) <= MAX_IMAGE_BYTES
    (part,) = truth["partitions"]
    if truth["volume_system"] == "dos":
        assert _mbr(disk) == [
            (
                {"fat12": 0x01, "fat16": 0x06, "fat32": 0x0C}[part["fs_type"]],
                part["start_sector"],
                part["length_sectors"],
            )
        ]
    vol = disk[part["start_sector"] * 512 :][: part["length_sectors"] * 512]
    fat = Fat(vol)
    assert f"fat{fat.bits}" == part["fs_type"]
    for copy in range(1, fat.nfats):
        off = (fat.reserved + copy * fat.fatsz) * fat.bps
        assert vol[off : off + fat.fatsz * fat.bps] == fat.fat_raw, "FAT copies differ"
    if fat.bits == 32:
        assert vol[6 * 512 : 7 * 512] == vol[:512], "backup boot sector"
        info = vol[512:1024]
        assert (_u32(info, 0), _u32(info, 484), _u32(info, 508)) == (
            0x41615252,
            0x61417272,
            0xAA550000,
        )
        assert _u32(info, 488) == fat.free()
    found = fat.walk()
    for want in truth["files"]:
        got = found[want["path"]]
        assert got["deleted"] == want["deleted"], want["path"]
        assert got["dir"] == (want["type"] == "dir")
        if want["type"] == "reg":
            assert got["size"] == want["size"]
        if "sha256" in want:
            assert hashlib.sha256(got["data"]).hexdigest() == want["sha256"], want["path"]
        for key in ("mtime", "crtime", "atime"):
            assert got[key] == want["times"][key], (want["path"], key)
    assert {p for p in found} == {f["path"] for f in truth["files"]}


def test_fat_basic_has_long_names_a_deleted_entry_and_two_second_times(
    built: dict[str, images.Built],
) -> None:
    truth = built["fat_basic"].truth
    by_path = {f["path"]: f for f in truth["files"]}
    assert by_path["/_ELETED.TXT"]["deleted"] is True
    assert "/Documents/Reports/Quarterly report for the synthetic company 2026.txt" in by_path
    odd = trees.fat_basic().nodes["/Pictures/two-second.txt"].mtime
    assert odd % 2 == 1
    assert by_path["/Pictures/two-second.txt"]["times"]["mtime"] == odd - 1
    raw = built["fat_basic"].raw.read_bytes()
    assert raw.count(b"\xe5ELETED TXT") == 1  # the 0xE5 short entry, data left in place
    assert b"this file was deleted (0xE5 entry)" in raw


def test_windows_tree_on_fat32_records_the_route_and_its_gaps(
    built: dict[str, images.Built],
) -> None:
    truth = built["ntfs_windows"].truth
    assert truth["ntfs_route"] == "fat32"
    assert truth["partitions"][0]["os"] == "windows"
    assert any("Zone.Identifier" in g for g in truth["gaps"])
    assert any("backup.dat" in g for g in truth["gaps"])
    assert truth["never_collect_meta"] == []
    paths = {f["path"] for f in truth["files"]}
    assert "/Users/José/Documents/notes.txt" in paths
    assert "/Windows/System32/config/SAM" in paths
    classes = {f.get("never_collect") for f in truth["files"]} - {None}
    assert classes == {
        "hives",
        "plaintext_secret_configs",
        "memory_on_disk",
        "browser_secrets",
        "keys_and_tokens",
    }
    assert set(truth["hive_outcome"]) == {"SYSTEM", "SOFTWARE", "NTUSER.DAT"}
    assert not any(f["type"] == "disk_ads_executable" for f in truth["expected_findings"])


def test_split_raw_is_the_windows_image_in_8_mib_parts(built: dict[str, images.Built]) -> None:
    b = built["split_raw"]
    names = [p.name for p in b.segments]
    assert names == [f"image.{i:03d}" for i in range(1, len(names) + 1)]
    assert all(p.stat().st_size == images.SPLIT_PART for p in b.segments[:-1])
    joined = b"".join(p.read_bytes() for p in b.segments)
    assert joined == built["ntfs_windows"].raw.read_bytes()
    assert b.truth["format"] == "split_raw" and b.truth["segments"] == names
    assert not (b.directory / "image.raw").exists()


def test_ground_truth_has_what_the_engine_test_reads(built: dict[str, images.Built]) -> None:
    for b in built.values():
        t = b.truth
        assert t["format"] in ("raw", "split_raw", "ewf")
        assert [p.name for p in b.segments] == t["segments"]
        for p in t["partitions"]:
            assert {"index", "fs_type", "fs_status", "os"} <= set(p)
        for f in t["files"]:
            assert {"partition_index", "path"} <= set(f)
            assert f["path"].startswith("/")
        assert "synthetic" in t["note"]


def test_pure_images_are_byte_identical_across_runs(
    built: dict[str, images.Built], tmp_path: Path
) -> None:
    again = Generator(tmp_path, ntfs_route="fat32")
    for image_id in ("fat_basic", "fat12", "fat16", "ntfs_windows"):
        b = again.build(image_id)
        assert b.truth["media_sha256"] == built[image_id].truth["media_sha256"], image_id
        assert b.truth == built[image_id].truth


# --- partition tables ---------------------------------------------------------------------------


def test_gpt_headers_arrays_and_protective_mbr() -> None:
    parts = [
        layouts.Part(2048, 4096, gpt_type=layouts.GUID_LINUX_FS, guid=uuid.uuid4(), name="a"),
        layouts.Part(6144, 2048, gpt_type=layouts.GUID_HFS_PLUS, guid=uuid.uuid4(), name="b"),
    ]
    total = 8192 + 34
    head, tail = layouts.gpt(parts, total, uuid.UUID(int=7))
    disk = bytearray(total * 512)
    disk[: len(head)] = head
    disk[len(disk) - len(tail) :] = tail
    assert _mbr(bytes(disk)) == [(0xEE, 1, total - 1)]
    assert _gpt(bytes(disk)) == [
        (layouts.GUID_LINUX_FS, 2048, 4096),
        (layouts.GUID_HFS_PLUS, 6144, 2048),
    ]


def test_assemble_is_sparse_and_places_contents(tmp_path: Path) -> None:
    out = tmp_path / "disk.raw"
    layouts.assemble(out, 100, b"HEAD", [(10, b"TEN"), (50, b"FIFTY")], b"TAIL")
    data = out.read_bytes()
    assert len(data) == 100 * 512
    assert data[:4] == b"HEAD" and data[5120:5123] == b"TEN" and data[25600:25605] == b"FIFTY"
    assert data.endswith(b"TAIL")


# --- hives ----------------------------------------------------------------------------------------


def test_base_hive_is_a_valid_regf_with_one_root_key() -> None:
    hive = hives.base_hive("SYSTEM")
    assert len(hive) == 8192 and hive[:4] == b"regf" and hive[4096:4100] == b"hbin"
    xor = 0
    for i in range(0, 0x1FC, 4):
        xor ^= _u32(hive, i)
    assert _u32(hive, 0x1FC) == xor
    root = 4096 + _u32(hive, 36)
    assert hive[root + 4 : root + 6] == b"nk"
    assert _u16(hive, root + 6) & 0x04  # the hive's root key
    assert hive[root + 80 : root + 80 + _u16(hive, root + 76)] == b"SYSTEM"
    sk = 4096 + _u32(hive, root + 4 + 44)
    assert hive[sk + 4 : sk + 6] == b"sk"
    cells = hives.cells(hive)
    assert sum(abs(size) for _, size in cells) == 4096 - 0x20
    assert [size < 0 for _, size in cells] == [True, True, False]
    assert hives.normalize(hive, BASE_TIME) == hive


def test_hive_normalize_resets_key_times_and_recomputes_the_checksum() -> None:
    hive = hives.base_hive("SOFTWARE", BASE_TIME + 999)
    fixed = hives.normalize(hive, BASE_TIME)
    assert fixed != hive
    assert fixed == hives.base_hive("SOFTWARE", BASE_TIME)


def test_reg_inputs_and_userassist_data() -> None:
    assert hives.rot13(hives.TOOL) == r"P:\Hfref\nyvpr\NccQngn\Ybpny\Grzc\gbby.rkr"
    data = hives.userassist_data(3, BASE_TIME)
    assert len(data) == 72 and _u32(data, 4) == 3
    assert struct.unpack_from("<Q", data, 60)[0] == hives.filetime(BASE_TIME)
    prefix, text = hives.reg_text("SYSTEM") or ("", "")
    assert prefix == r"HKEY_LOCAL_MACHINE\SYSTEM" and "CyberLabUpdater" in text
    assert '"ImagePath"="C:\\\\Users\\\\alice' in text
    assert hives.reg_text("SAM") is None


# --- EWF patcher --------------------------------------------------------------------------------


def _segment(number: int = 1) -> bytes:
    """An EWF1-shaped section chain (our own bytes): volume, hash, digest, done."""
    volume = bytearray(ewf.VOLUME_DATA)
    struct.pack_into("<IIIQ", volume, 4, 10, 64, 512, 640)
    struct.pack_into("<I", volume, 1048, zlib.adler32(bytes(volume[:1048])))
    md5 = bytes(range(16))
    hash_data = md5 + bytes(16)
    hash_data += struct.pack("<I", zlib.adler32(hash_data))
    digest = md5 + bytes(range(20)) + bytes(40)
    digest += struct.pack("<I", zlib.adler32(digest))
    out = bytearray(ewf.SIGNATURE + b"\x01" + struct.pack("<H", number) + b"\x00\x00")
    for kind, data in ((b"volume", bytes(volume)), (b"hash", hash_data), (b"digest", digest)):
        start = len(out)
        size = ewf.DESCRIPTOR + len(data)
        out += ewf.descriptor(kind, start + size, size) + data
    out += ewf.descriptor(b"done", len(out), ewf.DESCRIPTOR)
    return bytes(out)


def test_ewf_md5_patch_keeps_every_checksum_valid() -> None:
    seg = _segment()
    assert [s.type for s in ewf.sections(seg)] == [b"volume", b"hash", b"digest", b"done"]
    assert ewf.stored_md5(seg) == bytes(range(16))
    wrong = bytes(16 * [0xAA])
    bad = ewf.patch_md5(seg, wrong)
    assert ewf.stored_md5(bad) == wrong
    for s in ewf.sections(bad):
        if s.type == b"hash":
            assert _u32(bad, s.data + 32) == zlib.adler32(bad[s.data : s.data + 32])
        if s.type == b"digest":
            assert bad[s.data : s.data + 16] == wrong
            assert _u32(bad, s.data + 76) == zlib.adler32(bad[s.data : s.data + 76])


def test_ewf_media_size_and_segment_number_lies() -> None:
    seg = _segment()
    lie = ewf.patch_media_sectors(seg, mutate.HUGE_MEDIA_SECTORS)
    vol = next(s for s in ewf.sections(lie) if s.type == b"volume")
    assert struct.unpack_from("<Q", lie, vol.data + 16)[0] == mutate.HUGE_MEDIA_SECTORS
    assert _u32(lie, vol.data + 1048) == zlib.adler32(lie[vol.data : vol.data + 1048])
    assert _u16(ewf.patch_segment_number(seg, 9), 9) == 9
    broken = bytearray(seg)
    broken[ewf.FILE_HEADER + 20] ^= 1
    with pytest.raises(ValueError, match="checksum"):
        list(ewf.sections(bytes(broken)))


# --- exFAT, ext staging, CRC32C ---------------------------------------------------------------


def test_exfat_serial_patch_recomputes_both_boot_checksums() -> None:
    image = bytearray(24 * 512)
    for base in (0, 12 * 512):
        image[base + 3 : base + 11] = b"EXFAT   "
        image[base + 108] = 9
        image[base + 510 : base + 512] = b"\x55\xaa"
    fs_exfat.patch_serial(image, 0xCAFEF00D)
    main, backup = bytes(image[: 12 * 512]), bytes(image[12 * 512 :])
    assert main == backup and _u32(main, 100) == 0xCAFEF00D
    value = _u32(main, 11 * 512)
    assert main[11 * 512 :] == struct.pack("<I", value) * 128
    flags = bytearray(main)
    flags[106] ^= 0xFF  # VolumeFlags and PercentInUse are outside the checksum
    flags[112] ^= 0xFF
    assert fs_exfat.boot_checksum(bytes(flags)) == value
    flags[100] ^= 1
    assert fs_exfat.boot_checksum(bytes(flags)) != value


def test_crc32c_known_vector() -> None:
    assert mutate.crc32c(b"123456789") == 0xE3069283


def test_ext_staging_keeps_the_hard_link_and_times(tmp_path: Path) -> None:
    tree = trees.linux()
    root = tmp_path / "root"
    fs_ext.stage(tree, root)
    shadow, old = root / "etc/shadow", root / "var/log/old.log"
    assert os.stat(shadow).st_ino == os.stat(old).st_ino
    assert os.stat(shadow).st_nlink == 2
    assert int(os.stat(root / "var/log/syslog").st_mtime) == tree.nodes["/var/log/syslog"].mtime
    assert (root / "tmp/.x/upd").read_bytes()[:4] == b"\x7fELF"
    script = fs_ext.debugfs_script(tree, crtime=True)
    assert (
        f'set_inode_field "/var/log/syslog" mtime @{tree.nodes["/var/log/syslog"].mtime}' in script
    )
    assert '"/var/log/old.log"' not in script  # one inode, set through /etc/shadow
    assert 'set_inode_field "/home/alice/.ssh/authorized_keys" uid 1000' in script
    assert "crtime" not in fs_ext.debugfs_script(tree, crtime=False)
    argv = fs_ext.mke2fs_argv("ext4", tmp_path / "x", 32 << 20, root, uuid.UUID(int=1), "l")
    assert argv[-1] == "32768k" and "-U" in argv and "-d" in argv
    assert any(a.startswith("hash_seed=") for a in argv)


def test_linux_ground_truth_marks_the_shadow_hard_link_never_collected() -> None:
    tree = trees.linux()
    files = {f["path"]: f for f in gt.files(tree, 0, "ext4")}
    assert files["/var/log/old.log"]["hard_linked"] and files["/etc/shadow"]["hard_linked"]
    assert files["/var/log/old.log"]["sha256"] == files["/etc/shadow"]["sha256"]
    assert gt.never_collect_meta(tree, 0) == [
        {"partition_index": 0, "path": "/var/log/old.log", "link_to": "/etc/shadow"}
    ]
    assert gt.os_of(tree) == ("linux", "Debian GNU/Linux 13 (trixie)")
    assert files["/etc/os-release"]["times"]["crtime"] is not None


# --- inert executables ----------------------------------------------------------------------------


def test_tiny_executables_are_well_formed_and_inert() -> None:
    pe = trees.tiny_pe("x")
    assert len(pe) == 1024 and pe[:2] == b"MZ"
    lfanew = _u32(pe, 0x3C)
    assert pe[lfanew : lfanew + 4] == b"PE\x00\x00" and _u16(pe, lfanew + 4) == 0x014C
    assert _u16(pe, lfanew + 24) == 0x010B
    elf = trees.tiny_elf("x")
    assert elf[:4] == b"\x7fELF" and elf[4] == 2 and _u16(elf, 18) == 0x3E
    entry = struct.unpack_from("<Q", elf, 24)[0] - 0x400000
    assert elf[entry : entry + 9] == b"\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05"  # exit(0)
    for blob in (pe, elf):
        assert b"EICAR" not in blob and b"UPX" not in blob


def test_utmp_records_are_384_bytes() -> None:
    raw = trees.utmp([(7, 1, "pts/0", "alice", "198.51.100.7", BASE_TIME)])
    assert len(raw) == 384 and _u16(raw, 0) == 7 and raw[44:49] == b"alice"
    assert _u32(raw, 340) == BASE_TIME


# --- hostile mode (pure mutations) --------------------------------------------------------------


def test_pure_mutations_are_deterministic(tmp_path: Path) -> None:
    gen = Generator(tmp_path / "a", ntfs_route="fat32")
    other = Generator(tmp_path / "b", ntfs_route="fat32")
    for name in mutate.PURE_PYTHON:
        one = mutate.run_one(gen, name, 5, tmp_path / "a" / "h" / name)
        two = mutate.run_one(other, name, 5, tmp_path / "b" / "h" / name)
        digest = [hashlib.sha256(p.read_bytes()).hexdigest() for p in one.segments]
        assert digest == [hashlib.sha256(p.read_bytes()).hexdigest() for p in two.segments], name
        assert one.expect == two.expect
        doc = json.loads((one.directory / "mutation.json").read_text(encoding="utf-8"))
        assert doc["mutation"] == name and not (one.directory / "ground_truth.json").exists()


def test_deep_tree_path_exceeds_4096_bytes(tmp_path: Path) -> None:
    case = mutate.run_one(Generator(tmp_path), "deep_tree", 1, tmp_path / "deep")
    assert case.expect["path_bytes_max"] > 4096
    found = Fat(case.segments[0].read_bytes()).walk()
    deepest = max(found, key=len)
    assert deepest.endswith("/leaf.txt") and deepest.count("/") == 65
    assert len(deepest.encode()) == case.expect["path_bytes_max"]


def test_fat_directory_cycle_points_at_an_ancestor(tmp_path: Path) -> None:
    case = mutate.run_one(Generator(tmp_path), "dir_cycle_fat", 1, tmp_path / "cycle")
    fat = Fat(case.segments[0].read_bytes())
    root = fat.entries(fat.vol[fat.root_off : fat.root_off + 512 * 32])
    a = next(e for e in root if e["name"] == "a")
    b = next(e for e in fat.entries(fat.read([a["cluster"]])) if e["name"] == "b")
    c = next(e for e in fat.entries(fat.read([b["cluster"]])) if e["name"] == "c")
    assert c["cluster"] == a["cluster"]


def test_hostile_fat_names_are_stored_raw(tmp_path: Path) -> None:
    case = mutate.run_one(Generator(tmp_path), "hostile_names_fat", 1, tmp_path / "names")
    fat = Fat(case.segments[0].read_bytes())
    names = {e["name"] for e in fat.entries(fat.vol[fat.root_off : fat.root_off + 512 * 32])}
    assert names == set(mutate.HOSTILE_NAMES)


def test_bad_partitions_overlap_and_run_beyond_the_media(tmp_path: Path) -> None:
    case = mutate.run_one(Generator(tmp_path), "bad_partitions", 3, tmp_path / "parts")
    disk = case.segments[0].read_bytes()
    (_, s0, n0), (_, s1, _), (_, s2, n2) = _mbr(disk)
    assert s0 < s1 < s0 + n0
    assert s2 + n2 > len(disk) // 512
    assert case.expect["partition_errors"] == {"1": "overlap", "2": "beyond_media"}


def test_refused_magic_cycles_through_the_container_formats(tmp_path: Path) -> None:
    seen: set[str] = set()
    for seed in range(40):
        case = mutate.run_one(Generator(tmp_path), "refused_magic", seed, tmp_path / f"m{seed}")
        name = case.expect["format_refused"]
        seen.add(name)
        data = case.segments[0].read_bytes()
        if name == "vhd":
            assert data[-512:-504] == b"conectix"
        else:
            assert data.startswith(dict(mutate.REFUSED)[name])
    assert seen == {n for n, _ in mutate.REFUSED}


def test_truncation_and_corruption_stay_reproducible_per_seed(tmp_path: Path) -> None:
    gen = Generator(tmp_path, ntfs_route="fat32")
    a = mutate.run_one(gen, "truncate", 1, tmp_path / "t1")
    b = mutate.run_one(gen, "truncate", 2, tmp_path / "t2")
    assert a.expect["truncated_at"] != b.expect["truncated_at"]
    assert a.segments[0].stat().st_size == a.expect["truncated_at"]
    c = mutate.run_one(gen, "corrupt_fat_boot", 1, tmp_path / "c1")
    assert all(11 <= off < 90 for off in c.expect["flipped_boot"])


def test_hostile_mode_lists_tool_cases_as_skipped_without_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("shutil.which", lambda _name: None)
    gen = Generator(tmp_path, ntfs_route="fat32")
    cases, skipped = mutate.hostile(gen, len(mutate.CATALOG), 7)
    assert [c.name for c in cases] == list(mutate.PURE_PYTHON)
    assert len(skipped) == len(mutate.CATALOG) - len(mutate.PURE_PYTHON)
    names = sorted(p.name for p in (tmp_path / "hostile").iterdir())
    assert len(names) == len(mutate.PURE_PYTHON)


# --- the CLI --------------------------------------------------------------------------------------


def test_cli_builds_the_selected_ids_and_writes_an_index(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["--out", str(tmp_path), "--only", "fat12", "--ntfs-route", "fat32"]) == 0
    index = json.loads((tmp_path / "index.json").read_text(encoding="utf-8"))
    assert index["images"] == {"fat12": "byte_exact"}
    assert (tmp_path / "fat12" / "ground_truth.json").is_file()
    assert cli.main(["--list"]) == 0
    assert "ewf_bad_hash\tewfacquirestream" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.main(["--out", str(tmp_path), "--only", "nope"])


def test_cli_fails_on_a_missing_tool_unless_told_to_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("shutil.which", lambda _name: None)
    assert cli.main(["--out", str(tmp_path), "--only", "ext2"]) == 1
    assert not (tmp_path / "ext2").exists()
    assert cli.main(["--out", str(tmp_path), "--only", "fat12,ext2", "--skip-missing"]) == 0
    index = json.loads((tmp_path / "index.json").read_text(encoding="utf-8"))
    assert set(index["images"]) == {"fat12"} and set(index["skipped"]) == {"ext2"}


def test_every_id_is_registered_with_its_tools() -> None:
    assert set(images.BUILDERS) == {
        "fat_basic",
        "fat12",
        "fat16",
        "exfat_basic",
        "ext4_linux",
        "ext2",
        "ext3",
        "ntfs_windows",
        "ntfs_flat",
        "multi_gpt",
        "split_raw",
        "ewf_single",
        "ewf_multi",
        "ewf_bad_hash",
    }
    assert set(images.NEEDS) | set(images.PURE_PYTHON) | {"ntfs_windows"} == set(images.BUILDERS)
    rng = random.Random(1)
    assert images.serial("a") == images.serial("a") != images.serial(str(rng.random()))


# --- cross-checks with the worker (only where its contract package is installed) ----------------


def test_expected_finding_methods_exist_in_the_detections() -> None:
    pytest.importorskip("cyberlab_jobs")
    from disk_worker.detections.base import METHOD_MAX, TEMPLATES  # noqa: PLC0415

    findings = images._windows_findings("libntfs") + [
        {"method": gt.M_EXEC, "type": "disk_exec_user_writable"},
        {"method": gt.M_PERSISTENCE, "type": "disk_persistence_cron_file"},
        {"method": gt.M_PERSISTENCE, "type": "disk_persistence_systemd_unit"},
        {"method": gt.M_PERSISTENCE, "type": "disk_persistence_cron_exec"},
    ]
    for f in findings:
        assert f["method"] in METHOD_MAX
        assert TEMPLATES[f["type"]][0] == f["method"]


def test_never_collect_classes_exist_in_the_contract() -> None:
    disk = pytest.importorskip("cyberlab_jobs.disk")
    classes = {n.never_collect for t in (trees.linux(), trees.windows()) for n in t.walk()}
    assert classes - {None} <= set(disk.NEVER_COLLECT_PATTERNS)


def test_refused_magic_matches_the_root_format_check() -> None:
    pytest.importorskip("cyberlab_jobs")
    from disk_worker import formats  # noqa: PLC0415

    for name, head in mutate.REFUSED:
        body = bytearray(4096)
        body[: len(head)] = head
        footer = b"conectix" + bytes(504) if name == "vhd" else bytes(512)
        with pytest.raises(formats.UnsupportedFormat) as exc:
            formats.detect(bytes(body), footer, 1)
        assert exc.value.reason == name
