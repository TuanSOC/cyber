"""The thin pytsk3 layer (probe side): explicit file-system families, entries and reads.

Everything that touches a pytsk3 object lives here, behind plain dataclasses, so the walker,
`collect` and `extract` logic is testable with fakes on any host.

File systems are opened only with an **explicit family** (`TSK_FS_TYPE_NTFS`,
`TSK_FS_TYPE_FAT_DETECT` = FAT12/16/32 then exFAT, `TSK_FS_TYPE_EXT_DETECT`): a family's
DETECT value reaches only that family's openers (red team, TSK `fs_open.c`), so APFS, HFS+,
ISO 9660, UFS, YAFFS and the rest are never offered hostile bytes. The constant names are
looked up with `getattr`: a pytsk3 build without one fails the open (`engine_unavailable`)
instead of silently falling back to autodetection.
"""

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from disk_worker.probe.image import tsk_int

FAMILY_CONSTANTS: dict[str, str] = {
    "ntfs": "TSK_FS_TYPE_NTFS",
    "fat": "TSK_FS_TYPE_FAT_DETECT",
    "ext": "TSK_FS_TYPE_EXT_DETECT",
}
FTYPE_NAMES: dict[str, str] = {
    "TSK_FS_TYPE_NTFS": "ntfs",
    "TSK_FS_TYPE_FAT12": "fat12",
    "TSK_FS_TYPE_FAT16": "fat16",
    "TSK_FS_TYPE_FAT32": "fat32",
    "TSK_FS_TYPE_EXFAT": "exfat",
    "TSK_FS_TYPE_EXT2": "ext2",
    "TSK_FS_TYPE_EXT3": "ext3",
    "TSK_FS_TYPE_EXT4": "ext4",
}
FAMILY_OF: dict[str, str] = {
    "ntfs": "ntfs",
    "fat12": "fat",
    "fat16": "fat",
    "fat32": "fat",
    "exfat": "fat",
    "ext2": "ext",
    "ext3": "ext",
    "ext4": "ext",
}
TIME_FIELDS = ("mtime", "atime", "ctime", "crtime")
# FAT keeps no $OrphanFiles-only virtual set: TSK adds $MBR, $FAT1, $FAT2 and $OrphanFiles as
# the last four inode numbers of a FAT file system (never real entries).
FAT_VIRTUAL_NAMES = frozenset({b"$MBR", b"$FAT1", b"$FAT2"})


class EngineMissing(RuntimeError):
    """A pytsk3 constant the probe needs does not exist in this build."""


def _pytsk3() -> Any:
    import pytsk3  # noqa: PLC0415 - imported only inside the probe

    return pytsk3


def const(name: str) -> Any:
    value = getattr(_pytsk3(), name, None)
    if value is None:
        raise EngineMissing(name)
    return value


def open_fs(img: Any, offset: int, family: str) -> Any:
    """`FS_Info(img, offset=…, type=<explicit family>)` (raises IOError when it is not one)."""
    return _pytsk3().FS_Info(img, offset=offset, type=const(FAMILY_CONSTANTS[family]))


def fs_type_name(fs: Any) -> str | None:
    """The contract's `FsType` value of an opened file system (None: outside the list)."""
    ftype = tsk_int(fs.info.ftype)
    for const_name, value in FTYPE_NAMES.items():
        c = getattr(_pytsk3(), const_name, None)
        if c is not None and tsk_int(c) == ftype:
            return value
    return None


@dataclass
class Meta:
    addr: int
    seq: int | None
    type: str  # reg | dir | lnk | other
    allocated: bool
    size: int | None
    mode: int | None
    uid: int | None
    gid: int | None
    nlink: int
    times: dict[str, tuple[int, int] | None] = field(default_factory=dict)


@dataclass
class RawEntry:
    name: bytes
    meta_addr: int
    meta_seq: int | None
    name_allocated: bool
    name_type: str
    meta: Meta | None
    handle: Any = None  # the pytsk3 File (reads go through `Fs`)


@dataclass(frozen=True)
class Stream:
    name: bytes
    attr_type: int
    attr_id: int
    size: int


def _type(value: Any, prefix: str) -> str:
    v = tsk_int(value)
    for short in ("REG", "DIR", "LNK"):
        c = getattr(_pytsk3(), f"{prefix}_{short}", None)
        if c is not None and tsk_int(c) == v:
            return short.lower()
    return "other"


def _flag(value: Any, name: str) -> bool:
    c = getattr(_pytsk3(), name, None)
    return c is not None and bool(tsk_int(value) & tsk_int(c))


def _opt_int(obj: Any, name: str) -> int | None:
    value = getattr(obj, name, None)
    if value is None:
        return None
    try:
        return tsk_int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _meta(meta: Any) -> Meta | None:
    if meta is None:
        return None
    times: dict[str, tuple[int, int] | None] = {}
    for t in TIME_FIELDS:
        seconds = _opt_int(meta, t)
        nanos = _opt_int(meta, f"{t}_nano") or 0
        times[t] = None if not seconds else (seconds, nanos if 0 <= nanos < 10**9 else 0)
    return Meta(
        addr=tsk_int(meta.addr),
        seq=_opt_int(meta, "seq"),
        type=_type(meta.type, "TSK_FS_META_TYPE"),
        allocated=_flag(meta.flags, "TSK_FS_META_FLAG_ALLOC"),
        size=_opt_int(meta, "size"),
        mode=_opt_int(meta, "mode"),
        uid=_opt_int(meta, "uid"),
        gid=_opt_int(meta, "gid"),
        nlink=_opt_int(meta, "nlink") or 0,
        times=times,
    )


def _name_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", "surrogateescape")
    return b""


def entry(f: Any) -> RawEntry:
    name = f.info.name
    return RawEntry(
        name=_name_bytes(name.name),
        meta_addr=tsk_int(name.meta_addr),
        meta_seq=_opt_int(name, "meta_seq"),
        name_allocated=not _flag(name.flags, "TSK_FS_NAME_FLAG_UNALLOC"),
        name_type=_type(name.type, "TSK_FS_NAME_TYPE"),
        meta=_meta(getattr(f.info, "meta", None)),
        handle=f,
    )


class Fs:
    """One opened file system (`fs_type` from the contract's list)."""

    def __init__(self, img: Any, offset: int, family: str) -> None:
        self.fs = open_fs(img, offset, family)
        fs_type = fs_type_name(self.fs)
        if fs_type is None or FAMILY_OF[fs_type] != family:
            raise OSError("the family opener returned another file system type")
        self.fs_type = fs_type
        self.family = family
        info = self.fs.info
        self.root_addr = tsk_int(info.root_inum)
        self.last_addr = tsk_int(info.last_inum)
        self.block_size = tsk_int(info.block_size)
        self.block_count = tsk_int(info.block_count)
        self.inode_count = tsk_int(getattr(info, "inum_count", 0) or 0)

    @property
    def case_insensitive(self) -> bool:
        return self.family in ("ntfs", "fat")

    @property
    def orphan_addr(self) -> int:
        return self.last_addr  # TSK's virtual `$OrphanFiles` directory

    def is_virtual(self, e: RawEntry) -> bool:
        """TSK's virtual FAT files ($MBR, $FAT1, $FAT2): not entries of the image."""
        return (
            self.family == "fat"
            and e.meta_addr > self.last_addr - 4
            and e.name in FAT_VIRTUAL_NAMES
        )

    def list_dir(self, addr: int) -> Iterator[RawEntry]:
        directory = self.fs.open_dir(inode=addr)
        for f in directory:
            yield entry(f)

    def open_meta(self, addr: int) -> RawEntry:
        f = self.fs.open_meta(inode=addr)
        e = entry(f)
        return e

    def open_path(self, path: str) -> RawEntry | None:
        try:
            return entry(self.fs.open(path))
        except (OSError, RuntimeError, ValueError):
            return None

    def streams(self, e: RawEntry, limit: int) -> list[Stream]:
        """Named NTFS `$DATA` streams of an entry (the unnamed default one excluded)."""
        if self.family != "ntfs" or e.handle is None:
            return []
        data = tsk_int(const("TSK_FS_ATTR_TYPE_NTFS_DATA"))
        out: list[Stream] = []
        for attr in e.handle:
            info = attr.info
            if tsk_int(info.type) != data:
                continue
            name = _name_bytes(getattr(info, "name", None))
            if not name or name == b"$Data":
                continue
            out.append(Stream(name, data, tsk_int(info.id), max(0, tsk_int(info.size))))
            if len(out) >= limit:
                break
        return out

    @staticmethod
    def read(e: RawEntry, offset: int, length: int, stream: Stream | None = None) -> bytes:
        if e.handle is None or length <= 0:
            return b""
        if stream is None:
            return bytes(e.handle.read_random(offset, length))
        return bytes(e.handle.read_random(offset, length, stream.attr_type, stream.attr_id))


__all__ = [
    "FAMILY_CONSTANTS",
    "FAMILY_OF",
    "FTYPE_NAMES",
    "EngineMissing",
    "Fs",
    "Meta",
    "RawEntry",
    "Stream",
    "const",
    "entry",
    "fs_type_name",
    "open_fs",
]
