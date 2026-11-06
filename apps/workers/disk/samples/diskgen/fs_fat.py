"""A pure-Python FAT12 / FAT16 / FAT32 writer (no mkfs, no mtools, no mount).

Layout as the Microsoft FAT specification describes it: boot sector + BPB (FAT32 also FSInfo
at sector 1 and the backup boot region at sector 6), two FAT copies, the fixed root directory
(FAT12 / 16) and the cluster heap. The FAT type follows from the cluster count (< 4085 FAT12,
< 65525 FAT16, else FAT32), which is how TSK, mtools and fsck.fat decide it too.

Directory entries: an 8.3 short entry for every name, preceded by long-name (VFAT) entries
whenever the name is not an upper-case 8.3 name. Deleted nodes are written and then deleted
the way DOS does it: every entry's first byte becomes 0xE5 and the cluster chain is freed,
the data clusters keep their bytes. Files are contiguous and allocated in tree order.

Times are stored as given (FAT keeps wall-clock time without a zone): modification time at a
2-second resolution, creation time at 10 ms, access as a date only (`quantize`).
"""

import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime

from samples.diskgen.trees import Node, Tree

SECTOR = 512
ATTR_DIR = 0x10
ATTR_ARCHIVE = 0x20
ATTR_LFN = 0x0F
DELETED = 0xE5
SHORT_CHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()-@^_`{}~")
EOC = {12: 0xFFF, 16: 0xFFFF, 32: 0x0FFFFFFF}


@dataclass(frozen=True)
class Geometry:
    bits: int
    total_sectors: int
    spc: int
    reserved: int
    fat_sectors: int
    root_entries: int
    clusters: int

    @property
    def root_sectors(self) -> int:
        return self.root_entries * 32 // SECTOR

    @property
    def root_offset(self) -> int:
        return (self.reserved + 2 * self.fat_sectors) * SECTOR

    @property
    def data_offset(self) -> int:
        return self.root_offset + self.root_sectors * SECTOR

    @property
    def cluster_bytes(self) -> int:
        return self.spc * SECTOR

    def cluster_offset(self, cluster: int) -> int:
        return self.data_offset + (cluster - 2) * self.cluster_bytes


def fat_type(clusters: int) -> int:
    return 12 if clusters < 4085 else 16 if clusters < 65525 else 32


def geometry(bits: int, size: int, spc: int) -> Geometry:
    total = size // SECTOR
    reserved = 32 if bits == 32 else 1
    root_entries = 0 if bits == 32 else 512
    root_sectors = root_entries * 32 // SECTOR
    fat = 1
    while True:
        clusters = (total - reserved - 2 * fat - root_sectors) // spc
        if clusters <= 0:
            raise ValueError("volume too small")
        if ((clusters + 2) * bits + 7) // 8 <= fat * SECTOR:
            break
        fat += 1
    if fat_type(clusters) != bits:
        raise ValueError(f"{size} bytes at {spc} sectors/cluster is FAT{fat_type(clusters)}")
    return Geometry(bits, total, spc, reserved, fat, root_entries, clusters)


# --- names -----------------------------------------------------------------------------------


def is_short(name: str) -> bool:
    """An upper-case 8.3 name that needs no long-name entries."""
    if name in (".", "..") or name.count(".") > 1 or name.startswith("."):
        return False
    base, _, ext = name.partition(".")
    if not 1 <= len(base) <= 8 or len(ext) > 3 or (name.endswith(".") and not ext):
        return False
    return all(ord(c) < 128 and ord(c) in SHORT_CHARS for c in base + ext)


def pack_short(name: str) -> bytes:
    base, _, ext = name.partition(".")
    return base.encode("ascii").ljust(8, b" ") + ext.encode("ascii").ljust(3, b" ")


def _clean(text: str) -> str:
    out = []
    for ch in text.upper():
        if ch in " .":
            continue
        out.append(ch if ord(ch) < 128 and ord(ch) in SHORT_CHARS else "_")
    return "".join(out)


def short_alias(name: str, taken: set[bytes]) -> bytes:
    """The Windows-style numeric-tail alias (`QUARTE~1.TXT`) unique within `taken`."""
    stem, dot, ext = name.lstrip(". ").rpartition(".")
    if not dot:
        stem, ext = ext, ""
    base, suffix = _clean(stem) or "_", _clean(ext)[:3]
    for n in range(1, 1_000_000):
        tail = f"~{n}"
        packed = pack_short(f"{base[: 8 - len(tail)]}{tail}" + (f".{suffix}" if suffix else ""))
        if packed not in taken:
            return packed
    raise ValueError("no free short alias")


def short_display(packed: bytes) -> str:
    """How TSK shows an 8.3 entry with no long name (`NAME.EXT`)."""
    base = packed[:8].rstrip(b" ").decode("latin-1")
    ext = packed[8:].rstrip(b" ").decode("latin-1")
    return f"{base}.{ext}" if ext else base


def lfn_checksum(packed: bytes) -> int:
    value = 0
    for byte in packed:
        value = (((value & 1) << 7) + (value >> 1) + byte) & 0xFF
    return value


def utf16_units(name: str) -> list[int]:
    raw = name.encode("utf-16-le", "surrogatepass")
    return [v for (v,) in struct.iter_unpack("<H", raw)]


def lfn_entries(units: list[int], checksum: int) -> list[bytes]:
    """The long-name entries in on-disk order (last part first, flagged 0x40)."""
    if not 1 <= len(units) <= 255:
        raise ValueError("long names hold 1..255 UTF-16 units")
    count = (len(units) + 12) // 13
    padded = units + ([0] if len(units) % 13 else [])
    padded += [0xFFFF] * (count * 13 - len(padded))
    out = []
    for seq in range(count, 0, -1):
        part = padded[(seq - 1) * 13 : seq * 13]
        entry = bytearray(32)
        entry[0] = seq | (0x40 if seq == count else 0)
        struct.pack_into("<5H", entry, 1, *part[0:5])
        entry[11], entry[12], entry[13] = ATTR_LFN, 0, checksum
        struct.pack_into("<6H", entry, 14, *part[5:11])
        struct.pack_into("<2H", entry, 28, *part[11:13])
        out.append(bytes(entry))
    return out


# --- times -----------------------------------------------------------------------------------


def dos_datetime(epoch: int) -> tuple[int, int, int]:
    """(date, time, creation tenths) of a wall-clock time given as epoch seconds."""
    dt = datetime.fromtimestamp(epoch, UTC)
    if not 1980 <= dt.year <= 2107:
        raise ValueError("FAT dates cover 1980..2107")
    date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    time = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return date, time, (dt.second % 2) * 100


def quantize(node: Node) -> dict[str, int | None]:
    """The times a FAT entry keeps of `node` (what a reader gets back)."""
    day = node.atime - node.atime % 86400
    return {
        "mtime": node.mtime - node.mtime % 2,
        "atime": day,
        "ctime": None,
        "crtime": node.crtime,
    }


# --- the writer ------------------------------------------------------------------------------


@dataclass
class Placed:
    """Where a node landed: its first cluster and the absolute offset of its short entry."""

    cluster: int
    entry_offset: int = -1
    short: bytes = b""
    display: str = ""
    clusters: list[int] = field(default_factory=list)


class FatWriter:
    def __init__(
        self,
        bits: int,
        size: int,
        spc: int,
        *,
        hidden: int = 0,
        volume_id: int = 0x1234ABCD,
        oem: bytes = b"CYBERLAB",
    ) -> None:
        self.g = geometry(bits, size, spc)
        self.hidden = hidden
        self.volume_id = volume_id
        self.oem = oem.ljust(8, b" ")[:8]
        self.buf = bytearray(self.g.total_sectors * SECTOR)
        self.fat = [0] * (self.g.clusters + 2)
        self.next = 2
        self.placed: dict[str, Placed] = {}

    # -- clusters --

    def alloc(self, nbytes: int, *, minimum: int = 0) -> list[int]:
        count = max(minimum, -(-nbytes // self.g.cluster_bytes))
        if self.next + count > self.g.clusters + 2:
            raise ValueError("volume full")
        run = list(range(self.next, self.next + count))
        self.next += count
        for a, b in zip(run, run[1:], strict=False):
            self.fat[a] = b
        if run:
            self.fat[run[-1]] = EOC[self.g.bits]
        return run

    def put(self, clusters: list[int], data: bytes) -> None:
        cb = self.g.cluster_bytes
        for i, cluster in enumerate(clusters):
            chunk = data[i * cb : (i + 1) * cb]
            off = self.g.cluster_offset(cluster)
            self.buf[off : off + len(chunk)] = chunk

    # -- entries --

    @staticmethod
    def short_entry(packed: bytes, attr: int, cluster: int, size: int, node: Node) -> bytes:
        wdate, wtime, _ = dos_datetime(node.mtime)
        cdate, ctime, tenth = dos_datetime(node.crtime)
        adate, _, _ = dos_datetime(node.atime)
        return struct.pack(
            "<11sBBBHHHHHHHI",
            packed,
            attr,
            0,
            tenth,
            ctime,
            cdate,
            adate,
            cluster >> 16,
            wtime,
            wdate,
            cluster & 0xFFFF,
            size,
        )

    def _names(self, children: list[Node]) -> dict[str, tuple[bytes, list[bytes]]]:
        taken: set[bytes] = set()
        out: dict[str, tuple[bytes, list[bytes]]] = {}
        for child in children:
            if is_short(child.name) and pack_short(child.name) not in taken:
                packed, lfn = pack_short(child.name), []
            else:
                packed = short_alias(child.name, taken)
                lfn = lfn_entries(utf16_units(child.name), lfn_checksum(packed))
            taken.add(packed)
            out[child.path] = (packed, lfn)
        return out

    def build(self, tree: Tree) -> bytes:
        dirs = ["/"] + [n.path for n in tree.walk() if n.is_dir]
        kids = {d: tree.children(d) for d in dirs}
        names = {d: self._names(kids[d]) for d in dirs}

        def entry_count(d: str) -> int:
            own = 0 if d == "/" else 2
            return own + sum(1 + len(lfn) for _, lfn in names[d].values())

        # Clusters in tree order (the FAT32 root first, at cluster 2).
        if self.g.bits == 32:
            root = self.alloc(entry_count("/") * 32, minimum=1)
            self.placed["/"] = Placed(root[0], clusters=root)
        else:
            if entry_count("/") > self.g.root_entries:
                raise ValueError("too many root entries")
            self.placed["/"] = Placed(0)
        for node in tree.walk():
            if node.is_dir:
                run = self.alloc(entry_count(node.path) * 32, minimum=1)
            else:
                run = self.alloc(len(node.data))
                self.put(run, node.data)
            self.placed[node.path] = Placed(run[0] if run else 0, clusters=run)

        for d in dirs:
            self._write_dir(d, kids[d], names[d], tree)
        for node in tree.walk():
            if node.deleted:
                for cluster in self.placed[node.path].clusters:
                    self.fat[cluster] = 0
        self._write_metadata()
        return bytes(self.buf)

    def _write_dir(
        self,
        d: str,
        children: list[Node],
        names: dict[str, tuple[bytes, list[bytes]]],
        tree: Tree,
    ) -> None:
        entries: list[bytes] = []
        here = self.placed[d]
        if d != "/":
            node = tree.nodes[d]
            parent = tree.nodes[d].parent
            up = 0 if parent == "/" else self.placed[parent].cluster
            entries.append(self.short_entry(b".          ", ATTR_DIR, here.cluster, 0, node))
            entries.append(self.short_entry(b"..         ", ATTR_DIR, up, 0, node))
        offsets: dict[str, int] = {}
        for child in children:
            packed, lfn = names[child.path]
            attr = ATTR_DIR if child.is_dir else ATTR_ARCHIVE
            size = 0 if child.is_dir else len(child.data)
            short = self.short_entry(packed, attr, self.placed[child.path].cluster, size, child)
            group = [*lfn, short]
            if child.deleted:
                group = [bytes([DELETED]) + e[1:] for e in group]
            entries.extend(group)
            offsets[child.path] = len(entries) - 1
            placed = self.placed[child.path]
            placed.short = packed
            if child.deleted:
                placed.display = "_" + short_display(packed)[1:]
            else:
                placed.display = child.name
        blob = b"".join(entries)
        if d == "/" and self.g.bits != 32:
            self.buf[self.g.root_offset : self.g.root_offset + len(blob)] = blob
            base = [self.g.root_offset + i * 32 for i in range(len(entries))]
        else:
            self.put(here.clusters, blob)
            per = self.g.cluster_bytes // 32
            base = [
                self.g.cluster_offset(here.clusters[i // per]) + (i % per) * 32
                for i in range(len(entries))
            ]
        for path, index in offsets.items():
            self.placed[path].entry_offset = base[index]

    # -- boot sector, FSInfo, FATs --

    def free_clusters(self) -> int:
        return sum(1 for v in self.fat[2:] if v == 0)

    def boot_sector(self) -> bytes:
        g = self.g
        b = bytearray(SECTOR)
        b[0:3] = b"\xeb\x58\x90" if g.bits == 32 else b"\xeb\x3c\x90"
        b[3:11] = self.oem
        total16 = g.total_sectors if g.total_sectors < 0x10000 and g.bits != 32 else 0
        total32 = 0 if total16 else g.total_sectors
        struct.pack_into(
            "<HBHBHHBHHHII",
            b,
            11,
            SECTOR,
            g.spc,
            g.reserved,
            2,
            g.root_entries,
            total16,
            0xF8,
            0 if g.bits == 32 else g.fat_sectors,
            63,
            255,
            self.hidden,
            total32,
        )
        if g.bits == 32:
            struct.pack_into("<IHHIHH", b, 36, g.fat_sectors, 0, 0, 2, 1, 6)
            ext = 64
        else:
            ext = 36
        struct.pack_into("<BBBI", b, ext, 0x80, 0, 0x29, self.volume_id)
        b[ext + 7 : ext + 18] = b"NO NAME    "
        b[ext + 18 : ext + 26] = f"FAT{g.bits}".encode().ljust(8, b" ")
        b[510:512] = b"\x55\xaa"
        return bytes(b)

    def fsinfo(self) -> bytes:
        b = bytearray(SECTOR)
        free = [i for i in range(2, self.g.clusters + 2) if self.fat[i] == 0]
        struct.pack_into("<I", b, 0, 0x41615252)
        struct.pack_into("<III", b, 484, 0x61417272, len(free), free[0] if free else 0xFFFFFFFF)
        struct.pack_into("<I", b, 508, 0xAA550000)
        return bytes(b)

    def fat_bytes(self) -> bytes:
        g = self.g
        table = list(self.fat)
        table[0] = {12: 0xFF8, 16: 0xFFF8, 32: 0x0FFFFFF8}[g.bits]
        table[1] = EOC[g.bits]
        out = bytearray(g.fat_sectors * SECTOR)
        if g.bits == 12:
            for n, value in enumerate(table):
                off = n * 3 // 2
                if n % 2 == 0:
                    out[off] = value & 0xFF
                    out[off + 1] = (out[off + 1] & 0xF0) | (value >> 8)
                else:
                    out[off] = (out[off] & 0x0F) | ((value & 0x0F) << 4)
                    out[off + 1] = value >> 4
        else:
            fmt = "<H" if g.bits == 16 else "<I"
            width = g.bits // 8
            for n, value in enumerate(table):
                struct.pack_into(fmt, out, n * width, value)
        return bytes(out)

    def _write_metadata(self) -> None:
        g = self.g
        boot = self.boot_sector()
        self.buf[0:SECTOR] = boot
        if g.bits == 32:
            info = self.fsinfo()
            self.buf[SECTOR : 2 * SECTOR] = info
            self.buf[6 * SECTOR : 7 * SECTOR] = boot
            self.buf[7 * SECTOR : 8 * SECTOR] = info
        fat = self.fat_bytes()
        for copy in range(2):
            off = (g.reserved + copy * g.fat_sectors) * SECTOR
            self.buf[off : off + len(fat)] = fat


def build(
    tree: Tree, bits: int, size: int, spc: int, *, hidden: int = 0, volume_id: int = 0x1234ABCD
) -> tuple[bytes, FatWriter]:
    writer = FatWriter(bits, size, spc, hidden=hidden, volume_id=volume_id)
    return writer.build(tree), writer
