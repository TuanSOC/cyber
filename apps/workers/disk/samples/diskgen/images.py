"""The image set (plan phase 4 table): one builder per id, each writing `<out>/<id>/` with its
segments (`image.raw`, `image.001`..., `image.E01`...) and `ground_truth.json`.

Pure Python: `fat_basic`, `fat12`, `fat16`, `ntfs_windows` on the FAT32 route and `split_raw`
from it. Tools (dev / test target): `exfat_basic`, `ext4_linux`, `ext2`, `ext3`, `multi_gpt`,
`ntfs_flat`, `ntfs_windows` on the libntfs route and the `ewf_*` sets.
"""

import shutil
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from samples.diskgen import (
    BASE_TIME,
    MAX_IMAGE_BYTES,
    MIB,
    SECTOR,
    ewf,
    fs_exfat,
    fs_ext,
    fs_fat,
    fs_ntfs,
    hives,
    layouts,
    tools,
    trees,
)
from samples.diskgen import ground_truth as gt
from samples.diskgen.trees import Tree

NAMESPACE = uuid.UUID("5d1f0c3e-9a47-4b8e-bb21-7c0e4d9a6f12")
ALIGN = 2048  # first partition at 1 MiB
FAT32_SIZE = 36 * MIB  # >= 65525 clusters of 512 bytes
SPLIT_PART = 8 * MIB
EWF_SEGMENT = 4 * MIB
HIVE_TIME = BASE_TIME + 300
NTFS_ROUTES = ("auto", "libntfs", "fat32")


def ident(image_id: str, what: str) -> uuid.UUID:
    return uuid.uuid5(NAMESPACE, f"{image_id}/{what}")


def serial(image_id: str) -> int:
    return ident(image_id, "serial").int & 0xFFFFFFFF


@dataclass
class Built:
    image_id: str
    directory: Path
    segments: list[Path]
    truth: dict[str, Any]
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def raw(self) -> Path:
        return self.directory / "image.raw"


class Generator:
    def __init__(self, out: Path, ntfs_route: str = "auto") -> None:
        if ntfs_route not in NTFS_ROUTES:
            raise ValueError(ntfs_route)
        self.out = out
        self.ntfs_route = ntfs_route
        self.built: dict[str, Built] = {}

    def build(self, image_id: str) -> Built:
        if image_id in self.built:
            return self.built[image_id]
        builder = BUILDERS[image_id]
        directory = self.out / image_id
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True)
        try:
            built = builder(self, directory)
        except BaseException:
            shutil.rmtree(directory, ignore_errors=True)
            raise
        for seg in built.segments:
            if seg.stat().st_size > MAX_IMAGE_BYTES:
                raise ValueError(f"{seg} is above 64 MiB")
        gt.write(directory, built.truth)
        self.built[image_id] = built
        return built


# --- helpers ---------------------------------------------------------------------------------


def _fat_partition(
    tree: Tree, bits: int, size: int, spc: int, image_id: str, mbr_type: int
) -> tuple[bytes, fs_fat.FatWriter, layouts.Part]:
    data, writer = fs_fat.build(tree, bits, size, spc, hidden=ALIGN, volume_id=serial(image_id))
    part = layouts.Part(ALIGN, len(data) // SECTOR, mbr_type=mbr_type)
    return data, writer, part


def _mbr_image(
    directory: Path, image_id: str, parts: list[tuple[layouts.Part, Path | bytes]], total: int
) -> Path:
    raw = directory / "image.raw"
    head = layouts.mbr([p for p, _ in parts], serial(image_id))
    layouts.assemble(raw, total, head, [(p.start, c) for p, c in parts])
    return raw


def _total(*parts: layouts.Part, gpt: bool = False) -> int:
    end = max(p.start + p.sectors for p in parts)
    return end + (34 if gpt else 0)


# --- builders --------------------------------------------------------------------------------


def fat_basic(gen: Generator, d: Path) -> Built:
    tree = trees.fat_basic()
    data, writer = fs_fat.build(tree, 32, FAT32_SIZE, 1, volume_id=serial("fat_basic"))
    raw = d / "image.raw"
    raw.write_bytes(data)
    truth = gt.document(
        "fat_basic",
        "raw",
        [raw],
        "none",
        [gt.partition(0, 0, len(data) // SECTOR, "fat32")],
        gt.files(tree, 0, "fat", writer.placed),
        time_basis="local_unknown",
    )
    return Built("fat_basic", d, [raw], truth)


def _small_fat(image_id: str, bits: int, size: int, mbr_type: int) -> Callable[..., Built]:
    def build(gen: Generator, d: Path) -> Built:
        tree = trees.small(image_id)
        data, writer, part = _fat_partition(tree, bits, size, 4, image_id, mbr_type)
        raw = _mbr_image(d, image_id, [(part, data)], _total(part))
        truth = gt.document(
            image_id,
            "raw",
            [raw],
            "dos",
            [gt.partition(0, part.start, part.sectors, f"fat{bits}")],
            gt.files(tree, 0, "fat", writer.placed),
            time_basis="local_unknown",
        )
        return Built(image_id, d, [raw], truth)

    return build


def exfat_basic(gen: Generator, d: Path) -> Built:
    fs = d / "fs.exfat"
    fs_exfat.build(fs, 16 * MIB, label="CLEXFAT", serial=serial("exfat_basic"))
    part = layouts.Part(ALIGN, 16 * MIB // SECTOR, mbr_type=layouts.MBR_NTFS_EXFAT)
    raw = _mbr_image(d, "exfat_basic", [(part, fs)], _total(part))
    fs.unlink()
    truth = gt.document(
        "exfat_basic",
        "raw",
        [raw],
        "dos",
        [gt.partition(0, part.start, part.sectors, "exfat")],
        [],
        gaps=["exFAT stays empty: exfatprogs has no userspace copy tool (listing only)"],
    )
    return Built("exfat_basic", d, [raw], truth)


def _ext_fs(d: Path, image_id: str, tree: Tree, kind: str, size: int, **kw: Any) -> Path:
    fs = d / f"fs.{kind}"
    fs_ext.build(tree, fs, kind, size, fs_uuid=ident(image_id, kind), label=image_id[:16], **kw)
    return fs


def ext4_linux(gen: Generator, d: Path) -> Built:
    tree = trees.linux()
    size = 32 * MIB
    fs = _ext_fs(d, "ext4_linux", tree, "ext4", size)
    part = layouts.Part(
        ALIGN,
        size // SECTOR,
        gpt_type=layouts.GUID_LINUX_FS,
        guid=ident("ext4_linux", "part0"),
        name="linux",
    )
    total = _total(part, gpt=True)
    head, tail = layouts.gpt([part], total, ident("ext4_linux", "disk"))
    raw = d / "image.raw"
    layouts.assemble(raw, total, head, [(part.start, fs)], tail)
    fs.unlink()
    os_name = gt.os_of(tree)
    counts = trees.LINUX_COUNTS
    truth = gt.document(
        "ext4_linux",
        "raw",
        [raw],
        "gpt",
        [gt.partition(0, part.start, part.sectors, "ext4", os=os_name[0], os_name=os_name[1])],
        gt.files(tree, 0, "ext4"),
        never_collect_meta=gt.never_collect_meta(tree, 0),
        timezone="Europe/Paris",
        plaso_expected=[
            {
                "data_type": "syslog:*",
                "source": "/var/log/{syslog,auth.log}",
                "min_count": counts["syslog_lines"] - counts["ssh_accepted"],
            },
            {
                "data_type": "syslog:ssh:login",
                "source": "/var/log/auth.log",
                "count": counts["ssh_accepted"],
            },
            {"data_type": "linux:utmp:event", "source": "/var/log/wtmp", "count": counts["wtmp"]},
            {
                "data_type": "bash:history:command",
                "source": "/root/.bash_history",
                "count": counts["bash_root"],
            },
            {
                "data_type": "dpkg:line",
                "source": "/var/log/dpkg.log",
                "count": counts["dpkg_lines"],
            },
        ],
        collect_expected={
            "triage": [
                "/etc/os-release",
                "/etc/timezone",
                "/etc/passwd",
                "/var/log/syslog",
                "/var/log/auth.log",
                "/var/log/wtmp",
                "/var/log/dpkg.log",
                "/root/.bash_history",
                "/etc/cron.d/backup",
                "/etc/cron.d/updater",
                "/etc/systemd/system/cyberlab-agent.service",
                "/home/alice/.ssh/authorized_keys",
            ],
            "full_only": ["/var/log/auth.log.2.gz"],
            "dropped_compressed_content": ["/var/log/messages"],
            "never": [n.path for n in tree.walk() if n.never_collect],
        },
        expected_findings=[
            {"method": gt.M_EXEC, "type": "disk_exec_user_writable", "path": "/tmp/.x/upd"},  # noqa: S108
            {
                "method": gt.M_PERSISTENCE,
                "type": "disk_persistence_cron_file",
                "path": "/etc/cron.d/updater",
                "requires": ["timeline_window"],
            },
            {
                "method": gt.M_PERSISTENCE,
                "type": "disk_persistence_systemd_unit",
                "path": "/etc/systemd/system/cyberlab-agent.service",
                "requires": ["timeline_window"],
            },
            {
                "method": gt.M_PERSISTENCE,
                "type": "disk_persistence_cron_exec",
                "path": "/var/log/syslog",
                "requires": ["plaso"],
            },
        ],
        determinism="byte_exact (fixed UUID, hash seed and E2FSPROGS_FAKE_TIME; verify in Docker)",
    )
    return Built("ext4_linux", d, [raw], truth)


def _small_ext(image_id: str, kind: str, size: int) -> Callable[..., Built]:
    def build(gen: Generator, d: Path) -> Built:
        tree = trees.small(image_id)
        fs = _ext_fs(d, image_id, tree, kind, size)
        part = layouts.Part(ALIGN, size // SECTOR, mbr_type=layouts.MBR_LINUX)
        raw = _mbr_image(d, image_id, [(part, fs)], _total(part))
        fs.unlink()
        truth = gt.document(
            image_id,
            "raw",
            [raw],
            "dos",
            [gt.partition(0, part.start, part.sectors, kind)],
            gt.files(tree, 0, kind),
            determinism="byte_exact (fixed UUID, hash seed and fake time; verify in Docker)",
        )
        return Built(image_id, d, [raw], truth)

    return build


def windows_tree() -> tuple[Tree, dict[str, str]]:
    tree = trees.windows()
    outcome: dict[str, str] = {}
    for name, path in (
        ("SYSTEM", "/Windows/System32/config/SYSTEM"),
        ("SOFTWARE", "/Windows/System32/config/SOFTWARE"),
        ("NTUSER.DAT", "/Users/alice/NTUSER.DAT"),
    ):
        data, result = hives.build(name, HIVE_TIME)
        tree.nodes[path].data = data
        outcome[name] = result
    return tree, outcome


def _windows_findings(route: str) -> list[dict[str, Any]]:
    home = "/Users/alice"
    startup = f"{home}/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
    out: list[dict[str, Any]] = [
        {
            "method": gt.M_EXEC,
            "type": "disk_exec_user_writable",
            "path": f"{home}/AppData/Local/Temp/tool.exe",
        },
        {
            "method": gt.M_DOUBLE,
            "type": "disk_double_extension",
            "path": f"{home}/Downloads/invoice.pdf.exe",
        },
        {
            "method": gt.M_MISMATCH,
            "type": "disk_extension_mismatch",
            "path": f"{home}/Pictures/holiday.jpg",
        },
        {
            "method": gt.M_PERSISTENCE,
            "type": "disk_persistence_startup",
            "path": f"{startup}/sync.exe",
        },
        {
            "method": gt.M_PERSISTENCE,
            "type": "disk_persistence_run_key",
            "path": "/Windows/System32/config/SOFTWARE",
            "requires": ["hivex", "plaso"],
        },
        {
            "method": gt.M_PERSISTENCE,
            "type": "disk_persistence_service",
            "path": "/Windows/System32/config/SYSTEM",
            "requires": ["hivex", "plaso"],
        },
    ]
    if route == "libntfs":
        out.append(
            {
                "method": gt.M_ADS,
                "type": "disk_ads_executable",
                "path": f"{home}/Documents/report.txt",
                "stream": "payload",
            }
        )
    return out


def _try_libntfs(fs: Path, size: int, tree: Tree) -> bool:
    if not tools.have("mkntfs", "ntfscp", "ntfsinfo"):
        return False
    try:
        fs_ntfs.mkntfs(fs, size, label="WINDOWS", hidden_sectors=ALIGN)
        fs_ntfs.build_tree(fs, tree)
    except (tools.ToolFailed, OSError) as exc:
        print(f"ntfs_windows: libntfs route failed, using the FAT32 route ({exc})")
        fs.unlink(missing_ok=True)
        return False
    return True


def ntfs_windows(gen: Generator, d: Path) -> Built:
    tree, hive_outcome = windows_tree()
    size = 40 * MIB
    fs = d / "fs.ntfs"
    route = "fat32"
    if gen.ntfs_route in ("auto", "libntfs"):
        if _try_libntfs(fs, size, tree):
            route = "libntfs"
        elif gen.ntfs_route == "libntfs":
            raise tools.ToolFailed("the libntfs route was required and failed")
    if route == "libntfs":
        part = layouts.Part(ALIGN, size // SECTOR, mbr_type=layouts.MBR_NTFS_EXFAT)
        raw = _mbr_image(d, "ntfs_windows", [(part, fs)], _total(part))
        fs.unlink()
        fs_type, family, used = "ntfs", "ntfs", tree
        placed: dict[str, fs_fat.Placed] | None = None
        determinism = "exception: NTFS times and the mkntfs volume serial come from the tools"
    else:
        used = tree.without_ntfs_features()
        data, writer, part = _fat_partition(
            used, 32, FAT32_SIZE, 1, "ntfs_windows", layouts.MBR_FAT32_LBA
        )
        raw = _mbr_image(d, "ntfs_windows", [(part, data)], _total(part))
        fs_type, family, placed = "fat32", "fat", writer.placed
        determinism = "byte_exact"
    os_name = gt.os_of(used)
    truth = gt.document(
        "ntfs_windows",
        "raw",
        [raw],
        "dos",
        [gt.partition(0, part.start, part.sectors, fs_type, os=os_name[0])],
        gt.files(used, 0, family, placed),
        never_collect_meta=gt.never_collect_meta(used, 0),
        ntfs_route=route,
        hive_outcome=hive_outcome,
        gaps=used.gaps,
        expected_findings=_windows_findings(route),
        determinism=determinism,
    )
    if family == "fat":
        truth["time_basis"] = "local_unknown"
    return Built("ntfs_windows", d, [raw], truth)


def ntfs_flat(gen: Generator, d: Path) -> Built:
    """Route 3's NTFS-only features: the Windows tree's files in the root directory."""
    tree, _ = windows_tree()
    flat = Tree("ntfs_flat")
    for node in tree.walk():
        if node.is_dir or node.link_to is not None or f"/{node.name}" in flat.nodes:
            continue
        copy = flat.file(f"/{node.name}", node.data, streams=node.streams, never=node.never_collect)
        copy.mtime, copy.atime, copy.ctime, copy.crtime = (
            node.mtime,
            node.atime,
            node.ctime,
            node.crtime,
        )
    size = 16 * MIB
    fs = d / "fs.ntfs"
    fs_ntfs.mkntfs(fs, size, label="FLAT", hidden_sectors=ALIGN)
    fs_ntfs.copy_files(fs, flat, flat=True)
    part = layouts.Part(ALIGN, size // SECTOR, mbr_type=layouts.MBR_NTFS_EXFAT)
    raw = _mbr_image(d, "ntfs_flat", [(part, fs)], _total(part))
    fs.unlink()
    truth = gt.document(
        "ntfs_flat",
        "raw",
        [raw],
        "dos",
        [gt.partition(0, part.start, part.sectors, "ntfs")],
        gt.files(flat, 0, "ntfs"),
        expected_findings=[
            {
                "method": gt.M_ADS,
                "type": "disk_ads_executable",
                "path": "/report.txt",
                "stream": "payload",
            },
            {"method": gt.M_DOUBLE, "type": "disk_double_extension", "path": "/invoice.pdf.exe"},
            {"method": gt.M_MISMATCH, "type": "disk_extension_mismatch", "path": "/holiday.jpg"},
        ],
        gaps=["no deleted MFT entry: no userspace delete tool in ntfs-3g's Debian package"],
        determinism="exception: NTFS times and the mkntfs volume serial come from the tools",
    )
    return Built("ntfs_flat", d, [raw], truth)


def multi_gpt(gen: Generator, d: Path) -> Built:
    ext_tree, fat_tree = trees.small("multi_ext4"), trees.small("multi_fat")
    ext_size, fat_size, small = 16 * MIB, 16 * MIB, MIB
    ext_fs = _ext_fs(d, "multi_gpt", ext_tree, "ext4", ext_size)
    fat_start = ALIGN + ext_size // SECTOR
    fat_data, writer = fs_fat.build(
        fat_tree, 16, fat_size, 4, hidden=fat_start, volume_id=serial("multi_gpt")
    )
    hfs_start = fat_start + fat_size // SECTOR
    luks_start = hfs_start + small // SECTOR
    hfs = bytearray(small)
    hfs[1024:1028] = b"H+\x00\x04"  # an HFS+ volume header signature only
    luks = bytearray(small)
    luks[0:8] = b"LUKS\xba\xbe\x00\x02"  # a LUKS2 header signature only
    parts = [
        layouts.Part(
            ALIGN,
            ext_size // SECTOR,
            gpt_type=layouts.GUID_LINUX_FS,
            guid=ident("multi_gpt", "p0"),
            name="linux",
        ),
        layouts.Part(
            fat_start,
            fat_size // SECTOR,
            gpt_type=layouts.GUID_BASIC_DATA,
            guid=ident("multi_gpt", "p1"),
            name="data",
        ),
        layouts.Part(
            hfs_start,
            small // SECTOR,
            gpt_type=layouts.GUID_HFS_PLUS,
            guid=ident("multi_gpt", "p2"),
            name="mac",
        ),
        layouts.Part(
            luks_start,
            small // SECTOR,
            gpt_type=layouts.GUID_LINUX_LUKS,
            guid=ident("multi_gpt", "p3"),
            name="crypt",
        ),
    ]
    total = _total(*parts, gpt=True)
    head, tail = layouts.gpt(parts, total, ident("multi_gpt", "disk"))
    raw = d / "image.raw"
    contents: list[tuple[int, Path | bytes]] = [
        (parts[0].start, ext_fs),
        (parts[1].start, fat_data),
        (parts[2].start, bytes(hfs)),
        (parts[3].start, bytes(luks)),
    ]
    layouts.assemble(raw, total, head, contents, tail)
    ext_fs.unlink()
    truth = gt.document(
        "multi_gpt",
        "raw",
        [raw],
        "gpt",
        [
            gt.partition(0, parts[0].start, parts[0].sectors, "ext4"),
            gt.partition(1, parts[1].start, parts[1].sectors, "fat16"),
            gt.partition(
                2, parts[2].start, parts[2].sectors, None, fs_status="unsupported", reason="hfsplus"
            ),
            gt.partition(
                3, parts[3].start, parts[3].sectors, None, fs_status="encrypted", reason="luks"
            ),
        ],
        gt.files(ext_tree, 0, "ext4") + gt.files(fat_tree, 1, "fat", writer.placed),
        determinism="byte_exact (fixed UUID, hash seed and fake time; verify in Docker)",
    )
    return Built("multi_gpt", d, [raw], truth)


def split_raw(gen: Generator, d: Path) -> Built:
    base = gen.build("ntfs_windows")
    raw = d / "image.raw"
    shutil.copyfile(base.raw, raw)
    parts = layouts.split(raw, SPLIT_PART)
    truth = dict(base.truth)
    truth.update(
        id="split_raw",
        format="split_raw",
        segments=[p.name for p in parts],
        derived_from="ntfs_windows",
    )
    return Built("split_raw", d, parts, truth)


def _ewf(image_id: str, segment_bytes: int | None) -> Callable[..., Built]:
    def build(gen: Generator, d: Path) -> Built:
        base = gen.build("ntfs_windows")
        segments = ewf.acquire([base.raw], d / "image", segment_bytes=segment_bytes)
        truth = dict(base.truth)
        truth.update(
            id=image_id,
            format="ewf",
            segments=[p.name for p in segments],
            derived_from="ntfs_windows",
            media_hash_status="matched",
            ewf_case=ewf.CASE,
            determinism="exception: EWF header acquiry / system dates (media hash exact)",
        )
        return Built(image_id, d, segments, truth)

    return build


def ewf_bad_hash(gen: Generator, d: Path) -> Built:
    base = gen.build("ewf_single")
    src = base.segments[0]
    data = src.read_bytes()
    stored = ewf.stored_md5(data) or bytes(16)
    wrong = bytes(b ^ 0xFF for b in stored)
    seg = d / "image.E01"
    seg.write_bytes(ewf.patch_md5(data, wrong))
    truth = dict(base.truth)
    truth.update(
        id="ewf_bad_hash",
        segments=[seg.name],
        derived_from="ewf_single",
        media_hash_status="mismatch",
        stored_md5_patched=wrong.hex(),
    )
    return Built("ewf_bad_hash", d, [seg], truth)


BUILDERS: dict[str, Callable[[Generator, Path], Built]] = {
    "fat_basic": fat_basic,
    "fat12": _small_fat("fat12", 12, 4 * MIB, layouts.MBR_FAT12),
    "fat16": _small_fat("fat16", 16, 16 * MIB, layouts.MBR_FAT16),
    "exfat_basic": exfat_basic,
    "ext4_linux": ext4_linux,
    "ext2": _small_ext("ext2", "ext2", 8 * MIB),
    "ext3": _small_ext("ext3", "ext3", 16 * MIB),
    "ntfs_windows": ntfs_windows,
    "ntfs_flat": ntfs_flat,
    "multi_gpt": multi_gpt,
    "split_raw": split_raw,
    "ewf_single": _ewf("ewf_single", None),
    "ewf_multi": _ewf("ewf_multi", EWF_SEGMENT),
    "ewf_bad_hash": ewf_bad_hash,
}
PURE_PYTHON = ("fat_basic", "fat12", "fat16", "split_raw")
# Tools each id needs (beyond Python); ntfs_windows falls back to the pure FAT32 route.
NEEDS: dict[str, tuple[str, ...]] = {
    "exfat_basic": ("mkfs.exfat",),
    "ext4_linux": ("mke2fs", "debugfs"),
    "ext2": ("mke2fs", "debugfs"),
    "ext3": ("mke2fs", "debugfs"),
    "ntfs_flat": ("mkntfs", "ntfscp"),
    "multi_gpt": ("mke2fs", "debugfs"),
    "ewf_single": ("ewfacquirestream",),
    "ewf_multi": ("ewfacquirestream",),
    "ewf_bad_hash": ("ewfacquirestream",),
}
