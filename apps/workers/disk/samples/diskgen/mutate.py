"""Hostile mode (used by phases 2 and 13): deterministic mutations from (mutation, seed).

`hostile(gen, n, seed)` writes `n` cases to `<out>/hostile/<nn>_<name>/`, cycling through
`CATALOG` with seed `seed + i`; each case has its segments and a `mutation.json` (never a
`ground_truth.json`: the engine test's ground-truth comparison skips them). A case whose base
image needs a missing tool is listed as skipped, never faked.

Pure Python: deep tree, truncation, boot / FAT corruption, a FAT directory cycle, hostile FAT
names, overlapping / beyond-media partitions, refused container magic. Tools: the ext
superblock / directory cycle / huge directory / raw-byte names, the NTFS MFT corruption and
the EWF media size / segment number lies.
"""

import json
import os
import random
import shutil
import struct
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from samples.diskgen import MIB, SECTOR, ewf, fs_ext, fs_fat, layouts, tools, trees
from samples.diskgen.images import ALIGN, FAT32_SIZE, Generator, ident
from samples.diskgen.trees import Tree

# The claimed media size of `ewf_huge_media`: 64 TiB, above every DISK_MAX_MEDIA_BYTES (the
# contract caps it at 16 TiB).
HUGE_MEDIA_SECTORS = 64 * 1024**4 // SECTOR
HUGE_DIR_ENTRIES = 300_000


@dataclass
class Case:
    name: str
    seed: int
    directory: Path
    segments: list[Path]
    expect: dict[str, Any]
    base: str | None = None


# (segments, expectations, base image id or None)
Result = tuple[list[Path], dict[str, Any], str | None]
Mutation = Callable[[Generator, Path, random.Random], Result]


# --- CRC32C (ext4 metadata_csum) -------------------------------------------------------------


def _crc32c_table() -> list[int]:
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        table.append(c)
    return table


_CRC32C = _crc32c_table()


def crc32c(data: bytes, crc: int = 0) -> int:
    """Standard CRC-32C (Castagnoli): `crc32c(b"123456789") == 0xE3069283`."""
    crc ^= 0xFFFFFFFF
    for byte in data:
        crc = _CRC32C[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def ext_superblock_checksum(sb: bytes) -> int:
    """ext4 `s_checksum`: the kernel's crc32c(~0, sb[0:1020]) without the final inversion."""
    return crc32c(sb[:1020]) ^ 0xFFFFFFFF


# --- helpers -----------------------------------------------------------------------------------


def flip(data: bytearray, rng: random.Random, start: int, end: int, count: int) -> list[int]:
    """Seeded single-byte XOR flips within [start, end) only (metadata regions)."""
    offsets = sorted(rng.sample(range(start, min(end, len(data))), count))
    for off in offsets:
        data[off] ^= rng.randrange(1, 256)
    return offsets


def _copy_raw(gen: Generator, base: str, d: Path) -> Path:
    raw = d / "image.raw"
    shutil.copyfile(gen.build(base).raw, raw)
    return raw


def _fat_image(
    d: Path, tree: Tree, bits: int = 16, size: int = 16 * MIB, spc: int = 4
) -> tuple[Path, fs_fat.FatWriter]:
    data, writer = fs_fat.build(tree, bits, size, spc)
    raw = d / "image.raw"
    raw.write_bytes(data)
    return raw, writer


# --- pure Python mutations -------------------------------------------------------------------


def deep_tree(gen: Generator, d: Path, rng: random.Random) -> Result:
    """64 nested directories of 255-character names: a path above 4 096 bytes (RT13)."""
    tree = Tree("deep_tree")
    path = ""
    letters = "abcdefghijklmnopqrstuvwxyz"
    for level in range(64):
        filler = letters[rng.randrange(26)]
        path += "/" + f"d{level:02d}".ljust(255, filler)
        tree.dir(path, level)
    tree.file(path + "/leaf.txt", b"bottom of a 64-level tree\n", 64)
    raw, _ = _fat_image(d, tree, 32, FAT32_SIZE, 1)
    return [raw], {"path_bytes_max": len(path.encode()) + 9, "fs_type": "fat32"}, None


def truncate(gen: Generator, d: Path, rng: random.Random) -> Result:
    raw = _copy_raw(gen, "fat16", d)
    size = raw.stat().st_size
    cut = rng.randrange(SECTOR, size)
    with raw.open("r+b") as f:
        f.truncate(cut)
    return [raw], {"truncated_at": cut, "original_bytes": size}, "fat16"


def corrupt_fat_boot(gen: Generator, d: Path, rng: random.Random) -> Result:
    raw = _copy_raw(gen, "fat_basic", d)
    data = bytearray(raw.read_bytes())
    g = fs_fat.geometry(32, FAT32_SIZE, 1)
    boot = flip(data, rng, 11, 90, 6)  # the BPB
    fat = flip(data, rng, g.reserved * SECTOR, (g.reserved + g.fat_sectors) * SECTOR, 16)
    raw.write_bytes(bytes(data))
    return [raw], {"flipped_boot": boot, "flipped_fat": fat}, "fat_basic"


def dir_cycle_fat(gen: Generator, d: Path, rng: random.Random) -> Result:
    """/a/b/c's directory entry points at /a's first cluster: c → a → b → c ..."""
    tree = Tree("dir_cycle_fat")
    tree.file("/a/b/c/file.txt", b"inside the cycle\n", 0)
    tree.file(f"/a/b/note-{rng.randrange(1000):03d}.txt", b"note\n", 0)
    raw, writer = _fat_image(d, tree)
    data = bytearray(raw.read_bytes())
    entry = writer.placed["/a/b/c"].entry_offset
    target = writer.placed["/a"].cluster
    struct.pack_into("<H", data, entry + 20, target >> 16)
    struct.pack_into("<H", data, entry + 26, target & 0xFFFF)
    raw.write_bytes(bytes(data))
    return [raw], {"cycle": ["/a/b/c", "/a"], "fs_type": "fat16"}, None


HOSTILE_NAMES = (
    "pipe|name.txt",
    "new\nline.txt",
    "invoice‮txt.exe",
    "€" * 85,  # 255 bytes of UTF-8
    "lone-\ud800-surrogate.txt",  # invalid UTF-8 once TSK converts it
    "tab\tand\x01control.txt",
)


def hostile_names_fat(gen: Generator, d: Path, rng: random.Random) -> Result:
    tree = Tree("hostile_names_fat")
    names = list(HOSTILE_NAMES)
    rng.shuffle(names)
    for i, name in enumerate(names):
        tree.file(f"/{name}", f"hostile name {i}\n".encode(), i)
    raw, _ = _fat_image(d, tree)
    shown = [n.encode("unicode_escape").decode("ascii") for n in names]
    return [raw], {"names": shown, "fs_type": "fat16"}, None


def bad_partitions(gen: Generator, d: Path, rng: random.Random) -> Result:
    tree = trees.small("bad_partitions")
    data, _ = fs_fat.build(tree, 12, 4 * MIB, 4, hidden=ALIGN)
    first = layouts.Part(ALIGN, len(data) // SECTOR, mbr_type=layouts.MBR_FAT12)
    overlap_start = ALIGN + rng.randrange(1, first.sectors - 1)
    overlap = layouts.Part(overlap_start, 4096, mbr_type=layouts.MBR_LINUX)
    total = ALIGN + first.sectors + 4096
    beyond = layouts.Part(total - 100, 10_000, mbr_type=layouts.MBR_LINUX)
    raw = d / "image.raw"
    head = layouts.mbr([first, overlap, beyond], 0x0BAD0BAD)
    layouts.assemble(raw, total, head, [(ALIGN, data)])
    expect = {"partition_errors": {"1": "overlap", "2": "beyond_media"}, "ok": [0]}
    return [raw], expect, None


REFUSED = (
    ("gzip", b"\x1f\x8b\x08\x00" + bytes(6)),
    ("zip", b"PK\x03\x04" + bytes(26)),
    ("vmdk", b"KDMV" + struct.pack("<I", 1)),
    ("qcow", b"QFI\xfb" + struct.pack(">I", 3)),
    ("vhd", b""),  # footer only
)


def refused_magic(gen: Generator, d: Path, rng: random.Random) -> Result:
    """A container format the root's magic check must refuse (`disk_worker/formats.py`)."""
    name, head = REFUSED[rng.randrange(len(REFUSED))]
    body = bytearray(MIB)
    body[: len(head)] = head
    if name == "vhd":
        body[-512:-504] = b"conectix"
    raw = d / "image.raw"
    raw.write_bytes(bytes(body))
    return [raw], {"format_refused": name}, None


# --- tool mutations ----------------------------------------------------------------------------


def ext_huge_inodes(gen: Generator, d: Path, rng: random.Random) -> Result:
    """The ext4 superblock claims the largest inode table its block size allows (RT30)."""
    raw = _copy_raw(gen, "ext4_linux", d)
    data = bytearray(raw.read_bytes())
    sb = ALIGN * SECTOR + 1024
    if struct.unpack_from("<H", data, sb + 56)[0] != 0xEF53:
        raise ValueError("no ext superblock")
    block = 1024 << struct.unpack_from("<I", data, sb + 24)[0]
    blocks, per_group_blocks = (
        struct.unpack_from("<I", data, sb + 4)[0],
        struct.unpack_from("<I", data, sb + 32)[0],
    )
    groups = -(-blocks // per_group_blocks)
    per_group = block * 8 - rng.randrange(0, 8) * 8
    struct.pack_into("<I", data, sb + 40, per_group)
    struct.pack_into("<I", data, sb + 0, per_group * groups)
    if struct.unpack_from("<I", data, sb + 100)[0] & 0x400:  # metadata_csum
        checksum = ext_superblock_checksum(bytes(data[sb : sb + 1024]))
        struct.pack_into("<I", data, sb + 1020, checksum)
    raw.write_bytes(bytes(data))
    return [raw], {"inodes_claimed": per_group * groups}, "ext4_linux"


def corrupt_ext_superblock(gen: Generator, d: Path, rng: random.Random) -> Result:
    raw = _copy_raw(gen, "ext3", d)
    data = bytearray(raw.read_bytes())
    sb = ALIGN * SECTOR + 1024
    flipped = flip(data, rng, sb, sb + 1024, 8) + flip(data, rng, sb + 3072, sb + 3072 + 256, 4)
    raw.write_bytes(bytes(data))
    return [raw], {"flipped": flipped}, "ext3"


def corrupt_mft(gen: Generator, d: Path, rng: random.Random) -> Result:
    raw = _copy_raw(gen, "ntfs_flat", d)
    data = bytearray(raw.read_bytes())
    vbr = ALIGN * SECTOR
    if data[vbr + 3 : vbr + 11] != b"NTFS    ":
        raise ValueError("no NTFS boot sector")
    bps = struct.unpack_from("<H", data, vbr + 11)[0]
    cluster = bps * data[vbr + 13]
    mft = vbr + struct.unpack_from("<Q", data, vbr + 48)[0] * cluster
    flipped = flip(data, rng, mft, mft + 16 * 1024, 24)
    raw.write_bytes(bytes(data))
    return [raw], {"flipped": flipped, "mft_offset": mft}, "ntfs_flat"


def dir_cycle_ext(gen: Generator, d: Path, rng: random.Random) -> Result:
    tree = Tree("dir_cycle_ext")
    tree.file("/a/b/c/file.txt", b"inside the cycle\n", rng.randrange(100))
    fs = d / "fs.ext4"
    fs_ext.build(
        tree,
        fs,
        "ext4",
        8 * MIB,
        fs_uuid=ident("dir_cycle_ext", "fs"),
        label="cycle",
        extra_debugfs=['ln "/a" "/a/b/c/back"'],
    )
    raw = d / "image.raw"
    raw.write_bytes(fs.read_bytes())
    fs.unlink()
    return [raw], {"cycle": ["/a/b/c/back", "/a"], "fs_type": "ext4"}, None


def _stage_bytes(root: Path, names: list[bytes]) -> None:
    broot = os.fsencode(root)
    for i, name in enumerate(names):
        with open(os.path.join(broot, name), "wb") as f:
            f.write(f"file {i}\n".encode())


def _mke2fs_staged(d: Path, staging: Path, image_id: str, size: int, **kw: Any) -> Path:
    raw = d / "image.raw"
    argv = fs_ext.mke2fs_argv(
        "ext4", raw, size, staging, ident(image_id, "fs"), image_id[:16], **kw
    )
    tools.run(argv, timeout=600)
    return raw


def huge_dir(gen: Generator, d: Path, rng: random.Random) -> Result:
    tools.require("mke2fs")
    with tempfile.TemporaryDirectory(prefix="diskgen-hugedir-", dir=d) as tmp:
        staging = Path(tmp) / "root"
        big = staging / "big"
        big.mkdir(parents=True)
        salt = rng.randrange(1 << 30)
        names = [f"{salt:08x}{i:08x}".encode() for i in range(HUGE_DIR_ENTRIES)]
        _stage_bytes(big, names)
        # 16 groups of 1 024 blocks: 300 000 inodes fit the per-group limit (block size x 8).
        raw = _mke2fs_staged(
            d,
            staging,
            "huge_dir",
            64 * MIB,
            inodes=HUGE_DIR_ENTRIES + 64,
            inode_size=128,
            extra=["-g", "1024", "-O", "^has_journal"],
        )
    return [raw], {"directory": "/big", "entries": HUGE_DIR_ENTRIES, "fs_type": "ext4"}, None


def hostile_names_ext(gen: Generator, d: Path, rng: random.Random) -> Result:
    tools.require("mke2fs")
    names = [
        b"pipe|name.txt",
        b"new\nline.txt",
        "invoice‮txt.exe".encode(),
        "€".encode() * 85,
        b"bad-\xff\xfe-utf8.txt",
        b"\x01\x02control",
    ]
    rng.shuffle(names)
    with tempfile.TemporaryDirectory(prefix="diskgen-names-", dir=d) as tmp:
        staging = Path(tmp) / "root"
        staging.mkdir()
        _stage_bytes(staging, names)
        raw = _mke2fs_staged(d, staging, "hostile_names_ext", 8 * MIB)
    return [raw], {"names_hex": [n.hex() for n in names], "fs_type": "ext4"}, None


def ewf_huge_media(gen: Generator, d: Path, rng: random.Random) -> Result:
    base = gen.build("ewf_single")
    seg = d / "image.E01"
    sectors = HUGE_MEDIA_SECTORS + rng.randrange(1 << 20)
    seg.write_bytes(ewf.patch_media_sectors(base.segments[0].read_bytes(), sectors))
    return [seg], {"claimed_media_bytes": sectors * SECTOR}, "ewf_single"


def ewf_lying_segments(gen: Generator, d: Path, rng: random.Random) -> Result:
    base = gen.build("ewf_multi")
    out: list[Path] = []
    victim = rng.randrange(1, len(base.segments))
    lie = len(base.segments) + 1 + rng.randrange(20)
    for i, src in enumerate(base.segments):
        data = src.read_bytes()
        if i == victim:
            data = ewf.patch_segment_number(data, lie)
        dst = d / src.name
        dst.write_bytes(data)
        out.append(dst)
    return out, {"segment": victim + 1, "claims": lie}, "ewf_multi"


CATALOG: dict[str, Mutation] = {
    "deep_tree": deep_tree,
    "truncate": truncate,
    "corrupt_fat_boot": corrupt_fat_boot,
    "dir_cycle_fat": dir_cycle_fat,
    "hostile_names_fat": hostile_names_fat,
    "bad_partitions": bad_partitions,
    "refused_magic": refused_magic,
    "ext_huge_inodes": ext_huge_inodes,
    "corrupt_ext_superblock": corrupt_ext_superblock,
    "corrupt_mft": corrupt_mft,
    "dir_cycle_ext": dir_cycle_ext,
    "huge_dir": huge_dir,
    "hostile_names_ext": hostile_names_ext,
    "ewf_huge_media": ewf_huge_media,
    "ewf_lying_segments": ewf_lying_segments,
}
PURE_PYTHON = (
    "deep_tree",
    "truncate",
    "corrupt_fat_boot",
    "dir_cycle_fat",
    "hostile_names_fat",
    "bad_partitions",
    "refused_magic",
)


def run_one(gen: Generator, name: str, seed: int, directory: Path) -> Case:
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    rng = random.Random(f"{name}/{seed}")
    segments, expect, base = CATALOG[name](gen, directory, rng)
    case = Case(name, seed, directory, segments, expect, base)
    doc = {
        "mutation": name,
        "seed": seed,
        "base": base,
        "format": "ewf"
        if segments[0].suffix.startswith(".E")
        else ("raw" if len(segments) == 1 else "split_raw"),
        "segments": [p.name for p in segments],
        "expect": expect,
        "note": "hostile synthetic image: every outcome must be terminal (no hang, no crash)",
    }
    (directory / "mutation.json").write_text(
        json.dumps(doc, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    return case


def hostile(
    gen: Generator, n: int, seed: int, *, only_pure: bool = False
) -> tuple[list[Case], list[str]]:
    """`n` cases cycling through the catalog; (built cases, skipped reasons)."""
    names = list(PURE_PYTHON if only_pure else CATALOG)
    cases: list[Case] = []
    skipped: list[str] = []
    root = gen.out / "hostile"
    for i in range(n):
        name = names[i % len(names)]
        directory = root / f"{i:03d}_{name}"
        try:
            cases.append(run_one(gen, name, seed + i, directory))
        except tools.ToolMissing as exc:
            shutil.rmtree(directory, ignore_errors=True)
            skipped.append(f"{directory.name}: {exc}")
    return cases, skipped
