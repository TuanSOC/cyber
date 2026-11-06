"""The iterative walker (M9 phase 2) over a fake file system. Pure: runs anywhere.

Covers directory cycles, a 300 000-entry directory, the depth cap, every name of a hard-linked
inode (RT7), deleted / orphan / reallocated flags, NTFS named streams, the hashing order
(executables first, then the rest in walk order within the budget), long paths (RT13) and the
row cap.
"""

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass, field

from disk_worker.probe.tsk import Meta, RawEntry, Stream
from disk_worker.probe.walk import MAX_DEPTH, WalkArgs, Walker
from tests.unit.phase2_helpers import ListWriter

ROOT = 2
ORPHANS = 10**9


def meta(
    addr: int,
    kind: str = "reg",
    size: int = 0,
    alloc: bool = True,
    nlink: int = 1,
    seq: int | None = 1,
) -> Meta:
    return Meta(
        addr=addr,
        seq=seq,
        type=kind,
        allocated=alloc,
        size=size,
        mode=0o644,
        uid=0,
        gid=0,
        nlink=nlink,
        times={"mtime": (1_700_000_000, 5), "crtime": None},
    )


def ent(
    name: bytes, m: Meta | None, *, alloc: bool = True, kind: str | None = None, seq: int | None = 1
) -> RawEntry:
    return RawEntry(
        name=name,
        meta_addr=m.addr if m else 0,
        meta_seq=seq,
        name_allocated=alloc,
        name_type=kind or (m.type if m else "reg"),
        meta=m,
    )


@dataclass
class FakeFs:
    family: str = "ext"
    root_addr: int = ROOT
    orphan_addr: int = ORPHANS
    dirs: dict[int, list[RawEntry]] = field(default_factory=dict)
    content: dict[tuple[int, bytes | None], bytes] = field(default_factory=dict)
    named_streams: dict[int, list[Stream]] = field(default_factory=dict)
    listed: list[int] = field(default_factory=list)
    by_addr: dict[int, RawEntry] = field(default_factory=dict)

    def list_dir(self, addr: int) -> Iterator[RawEntry]:
        self.listed.append(addr)
        if addr not in self.dirs:
            raise OSError("not a directory")
        yield from self.dirs[addr]

    def is_virtual(self, e: RawEntry) -> bool:
        return False

    def streams(self, e: RawEntry, limit: int) -> list[Stream]:
        return self.named_streams.get(e.meta_addr, [])[:limit]

    def open_meta(self, addr: int) -> RawEntry:
        if not self.by_addr:
            for entries in self.dirs.values():
                for e in entries:
                    if e.meta is not None:
                        self.by_addr.setdefault(e.meta_addr, e)
        if addr not in self.by_addr:
            raise OSError("no such inode")
        return self.by_addr[addr]

    def read(self, e: RawEntry, offset: int, length: int, stream: Stream | None = None) -> bytes:
        data = self.content.get((e.meta_addr, stream.name if stream else None), b"")
        return data[offset : offset + length]


def walk(fs: FakeFs, **kw: int) -> tuple[list[dict], dict[int, dict], Walker]:
    args = WalkArgs(
        max_rows=kw.pop("max_rows", 10**7),
        max_bytes=10**12,
        hash_max_file_bytes=kw.pop("hash_max", 10**6),
        hash_budget_bytes=kw.pop("budget", 10**9),
        **kw,
    )
    files, hashes = ListWriter(args.max_rows), ListWriter()
    w = Walker(fs, args, files)  # type: ignore[arg-type]
    w.run()
    w.hash_pending(hashes)  # type: ignore[arg-type]
    return files.items, {h["n"]: h for h in hashes.items}, w


def test_a_directory_cycle_ends() -> None:
    fs = FakeFs()
    fs.dirs[ROOT] = [ent(b"a", meta(10, "dir"))]
    fs.dirs[10] = [ent(b"loop", meta(ROOT, "dir")), ent(b"self", meta(10, "dir"))]
    rows, _, w = walk(fs)
    assert [r["path"] for r in rows] == ["/a", "/a/loop", "/a/self"]
    assert w.stats.loops >= 1
    assert fs.listed.count(10) == 1


def test_a_300000_entry_directory_is_capped_per_directory() -> None:
    fs = FakeFs()
    fs.dirs[ROOT] = [ent(f"f{i}".encode(), meta(100 + i)) for i in range(300_000)]
    rows, _, w = walk(fs, max_dir_entries=200_000, hash_max=0)
    assert len(rows) == 200_000
    assert w.stats.dir_capped == 1


def test_the_depth_cap() -> None:
    fs = FakeFs()
    parent = ROOT
    for depth in range(MAX_DEPTH + 5):
        fs.dirs[parent] = [ent(b"d", meta(1000 + depth, "dir"))]
        parent = 1000 + depth
    fs.dirs[parent] = []
    rows, _, w = walk(fs)
    assert w.stats.depth_capped == 1
    assert max(r["path"].count("/") for r in rows) == MAX_DEPTH + 1


def test_every_name_of_a_hard_linked_inode_is_a_row() -> None:
    fs = FakeFs()
    shadow = meta(50, size=4, nlink=2)
    fs.dirs[ROOT] = [ent(b"etc", meta(10, "dir")), ent(b"var", meta(11, "dir"))]
    fs.dirs[10] = [ent(b"shadow", shadow)]
    fs.dirs[11] = [ent(b"auth.log", shadow)]
    fs.content[(50, None)] = b"root"
    rows, _, _ = walk(fs)
    linked = [r for r in rows if r["meta_addr"] == 50]
    assert sorted(r["path"] for r in linked) == ["/etc/shadow", "/var/auth.log"]
    assert all(r["hard_linked"] for r in linked)
    assert {r["parent_addr"] for r in linked} == {10, 11}


def test_deleted_orphan_and_reallocated_flags() -> None:
    fs = FakeFs(family="ntfs")
    fs.dirs[ROOT] = [
        ent(b"gone.txt", meta(20, alloc=False), alloc=False),
        ent(b"reused.txt", meta(21, seq=7), alloc=False, seq=6),
        ent(b"$OrphanFiles", meta(ORPHANS, "dir")),
    ]
    fs.dirs[ORPHANS] = [ent(b"OrphanFile-30", meta(30, alloc=False), alloc=False)]
    fs.content[(21, None)] = b"secret"
    rows, _, _ = walk(fs)
    by = {r["name"]: r for r in rows}
    assert "$OrphanFiles" not in by
    assert by["gone.txt"]["deleted"] and by["gone.txt"]["hash_status"] == "not_allocated"
    assert by["reused.txt"]["deleted"] and by["reused.txt"]["reallocated"]
    assert by["reused.txt"]["magic"] is None  # never read
    assert by["OrphanFile-30"]["orphan"] and by["OrphanFile-30"]["path"] == (
        "/$OrphanFiles/OrphanFile-30"
    )


def test_named_streams_are_rows_of_their_own() -> None:
    fs = FakeFs(family="ntfs")
    fs.dirs[ROOT] = [ent(b"setup.exe", meta(40, size=2))]
    fs.content[(40, None)] = b"MZ"
    fs.content[(40, b"Zone.Identifier")] = b"[ZoneTransfer]"
    fs.content[(40, b"evil")] = b"MZ\x90\x00"
    fs.named_streams[40] = [Stream(b"Zone.Identifier", 128, 3, 14), Stream(b"evil", 128, 4, 4)]
    rows, _, _ = walk(fs)
    assert [(r["stream"], r["magic"]) for r in rows] == [
        (None, "pe"),
        ("Zone.Identifier", "other"),
        ("evil", "pe"),
    ]
    assert all(r["path"] == "/setup.exe" for r in rows)


def test_streams_are_capped_per_file() -> None:
    fs = FakeFs(family="ntfs")
    fs.dirs[ROOT] = [ent(b"f", meta(40, size=1))]
    fs.named_streams[40] = [Stream(f"s{i}".encode(), 128, i, 1) for i in range(40)]
    rows, _, _ = walk(fs, max_streams=16)
    assert len(rows) == 17


def test_executables_are_hashed_first_and_the_rest_within_the_budget() -> None:
    fs = FakeFs()
    fs.dirs[ROOT] = [
        ent(b"a.txt", meta(60, size=6)),
        ent(b"b.txt", meta(61, size=6)),
        ent(b"tool.exe", meta(62, size=6)),
    ]
    fs.content[(60, None)] = b"aaaaaa"
    fs.content[(61, None)] = b"bbbbbb"
    fs.content[(62, None)] = b"MZxxxx"
    rows, hashes, _ = walk(fs, budget=12)
    by = {r["name"]: r for r in rows}
    assert by["tool.exe"]["hash_status"] == "hashed"
    assert by["tool.exe"]["sha256"] == hashlib.sha256(b"MZxxxx").hexdigest()
    assert by["a.txt"]["hash_status"] == "pending" and by["b.txt"]["hash_status"] == "pending"
    assert hashes[by["a.txt"]["n"]]["hash_status"] == "hashed"
    assert hashes[by["b.txt"]["n"]]["hash_status"] == "budget"


def test_too_large_files_and_directories_are_not_hashed() -> None:
    fs = FakeFs()
    fs.dirs[ROOT] = [ent(b"big.bin", meta(70, size=100)), ent(b"d", meta(71, "dir"))]
    fs.dirs[71] = []
    fs.content[(70, None)] = b"x" * 100
    rows, _, _ = walk(fs, hash_max=10)
    by = {r["name"]: r for r in rows}
    assert by["big.bin"]["hash_status"] == "too_large"
    assert by["d"]["hash_status"] == "not_regular"


def test_a_short_read_is_a_hash_error_not_a_crash() -> None:
    fs = FakeFs()
    fs.dirs[ROOT] = [ent(b"x.exe", meta(80, size=10))]
    fs.content[(80, None)] = b"MZ"  # metadata says 10 bytes
    rows, _, w = walk(fs)
    assert rows[0]["hash_status"] == "error" and w.stats.read_errors == 1


def test_long_paths_are_truncated_and_flagged_never_bad_rows() -> None:
    fs = FakeFs()
    parent = ROOT
    name = ("é" * 120).encode()  # 240 bytes per level
    for depth in range(40):
        fs.dirs[parent] = [ent(name, meta(2000 + depth, "dir"))]
        parent = 2000 + depth
    fs.dirs[parent] = [ent(b"leaf.txt", meta(3000))]
    rows, _, _ = walk(fs, hash_max=0)
    leaf = rows[-1]
    assert leaf["name"] == "leaf.txt" and leaf["path_truncated"]
    assert len(leaf["path"].encode()) <= 4096


def test_hostile_names_are_escaped() -> None:
    fs = FakeFs()
    fs.dirs[ROOT] = [ent(b"a|b\nc", meta(90)), ent(b"\xff\xfe", meta(91))]
    rows, _, _ = walk(fs, hash_max=0)
    assert rows[0]["name"] == "a|b\\x0ac" and "\n" not in rows[0]["path"]
    assert rows[1]["name_lossy"]


def test_the_row_cap_stops_the_walk_with_truncated() -> None:
    fs = FakeFs()
    fs.dirs[ROOT] = [ent(f"f{i}".encode(), meta(100 + i)) for i in range(50)]
    rows, _, w = walk(fs, max_rows=10, hash_max=0)
    assert len(rows) == 10
    assert w.stats.truncated and w.stats.reason == "files_cap"


def test_an_unreadable_directory_is_counted_and_skipped() -> None:
    fs = FakeFs()
    fs.dirs[ROOT] = [ent(b"broken", meta(5, "dir")), ent(b"ok.txt", meta(6))]
    rows, _, w = walk(fs, hash_max=0)
    assert [r["name"] for r in rows] == ["broken", "ok.txt"]
    assert w.stats.dir_errors == 1


def test_the_soft_deadline_stops_the_walk() -> None:
    fs = FakeFs()
    fs.dirs[ROOT] = [ent(f"f{i}".encode(), meta(100 + i)) for i in range(1000)]
    ticks = iter([0.0] + [1000.0] * 10**4)
    args = WalkArgs(max_rows=10**6, max_bytes=10**12, deadline_s=100)
    w = Walker(fs, args, ListWriter(), clock=lambda: next(ticks))  # type: ignore[arg-type]
    stats = w.run()
    assert stats.truncated and stats.reason == "deadline"
