"""The synthetic image generator (M8 phase 4), without Volatility: the physical layout, our own
page-table walk to every kernel structure, the circular `tasks` list, the ISF against
Volatility's schema (when `jsonschema` and the installed schemas are there), the LiME / ELF
wrappers, the scenarios, and determinism of the generator and of the fuzz helpers.

    scripts/lane-test.sh 4 --service memory-worker-test pytest -q tests/unit/test_memgen.py
"""

import base64
import hashlib
import json
import lzma
import random
import struct
from pathlib import Path

import pytest

from samples.memgen import (
    BANNER,
    MAX_IMAGE_BYTES,
    SCENARIOS,
    UNKNOWN_BANNER,
    LayoutFull,
    Proc,
    Scenario,
    build,
    image_bytes,
    isf,
    isf_xz,
    mutate,
    scenario,
    wrappers,
)
from samples.memgen import kernel as k
from samples.memgen.__main__ import main as memgen_main
from samples.memgen.image import MemoryImage
from samples.memgen.scenarios import EXITED_PARENT, WIDE_COUNT


def translate(phys: bytes, dtb: int, va: int) -> int:
    """A 4-level x86-64 walk (2 MiB pages at the PD level) over the physical bytes."""
    table = dtb
    for level in (4, 3, 2, 1):
        index = (va >> (12 + 9 * (level - 1))) & 0x1FF
        entry = int(struct.unpack_from("<Q", phys, table + index * 8)[0])
        assert entry & k.PRESENT, f"not present at level {level}"
        if level == 2 and entry & k.PSE:
            return (entry & 0x000FFFFFFFE00000) | (va & 0x1FFFFF)
        table = entry & 0x000FFFFFFFFFF000
    return table | (va & 0xFFF)


def field(img: MemoryImage, at: int, struct_name: str, member: str) -> int:
    offset, desc = k.resolve(struct_name, member)
    if desc["kind"] == "struct":  # kuid_t / kgid_t: the single `val`
        (inner,) = k.STRUCTS[desc["name"]].fields.values()
        desc = inner[1]
    _, size, signed = k.BASE_TYPES[desc["name"]] if desc["kind"] == "base" else ("", 8, False)
    fmt = {4: "<i" if signed else "<I", 8: "<q" if signed else "<Q"}[size]
    return int(struct.unpack_from(fmt, img.phys, at + offset)[0])


def comm(img: MemoryImage, at: int) -> str:
    offset, _ = k.resolve("task_struct", "comm")
    return bytes(img.phys[at + offset : at + offset + k.COMM_LEN]).split(b"\0")[0].decode()


@pytest.fixture(scope="module")
def benign() -> MemoryImage:
    return build(scenario("linux_benign"))


def test_every_symbol_translates_through_init_top_pgt(benign: MemoryImage) -> None:
    doc = isf()
    dtb = doc["symbols"]["init_top_pgt"]["address"] - k.KERNEL_MAP
    assert dtb == k.PML4 != 0  # Volatility refuses a DTB of 0
    for name, symbol in doc["symbols"].items():
        phys = translate(bytes(benign.phys), dtb, symbol["address"])
        assert phys == symbol["address"] - k.KERNEL_MAP, name
    raw_banner = bytes(benign.phys[k.BANNER_AT : k.BANNER_AT + len(BANNER) + 2])
    assert raw_banner == k.banner_bytes(BANNER)
    assert bytes(benign.phys).count(b"Linux version") == 1


def test_find_aslr_facts_hold_for_init_task(benign: MemoryImage) -> None:
    """What Volatility's Linux stacker checks on the `swapper/0` hit (shifts of 0)."""
    signature = b"swapper/0" + b"\0" * 6
    hits, at = [], benign.phys.find(signature)
    while at >= 0:
        hits.append(at)
        at = benign.phys.find(signature, at + 1)
    comm_off = k.resolve("task_struct", "comm")[0]
    assert hits == [k.TASKS + comm_off]
    assert field(benign, k.TASKS, "task_struct", "pid") == 0
    assert field(benign, k.TASKS, "task_struct", "files") == k.kva(k.INIT_FILES)
    nxt = field(benign, k.TASKS, "task_struct", "tasks.next")
    prev = field(benign, k.TASKS, "task_struct", "tasks.prev")
    assert nxt != prev


def test_the_tasks_list_is_circular_in_scenario_order(benign: MemoryImage) -> None:
    off = k.resolve("task_struct", "tasks")[0]
    at, seen = k.TASKS, []
    for _ in range(len(benign.order) + 1):
        seen.append(field(benign, at, "task_struct", "pid"))
        at = field(benign, at, "task_struct", "tasks.next") - k.KERNEL_MAP - off
        if at == k.TASKS:
            break
    assert seen == [0, *(p.pid for p in benign.scenario.procs)]


def test_processes_carry_parent_cred_mm_and_argv(benign: MemoryImage) -> None:
    dtb = k.USER_PML4
    for proc in benign.scenario.procs:
        at = benign.tasks[proc.pid]
        assert comm(benign, at) == proc.comm[:15]
        parent = field(benign, at, "task_struct", "real_parent") - k.KERNEL_MAP
        assert field(benign, parent, "task_struct", "tgid") == proc.ppid
        cred = field(benign, at, "task_struct", "cred") - k.KERNEL_MAP
        assert field(benign, cred, "cred", "uid") == proc.uid
        assert field(benign, cred, "cred", "egid") == proc.gid
        flags = field(benign, at, "task_struct", "flags")
        mm = field(benign, at, "task_struct", "mm")
        assert bool(flags & k.PF_KTHREAD) == proc.kthread == (mm == 0)
        if mm:
            assert field(benign, at, "task_struct", "active_mm") == mm
            mm -= k.KERNEL_MAP
            pgd = field(benign, mm, "mm_struct", "pgd") - k.KERNEL_MAP
            assert pgd == dtb
            start = field(benign, mm, "mm_struct", "arg_start")
            end = field(benign, mm, "mm_struct", "arg_end")
            argv = bytes(benign.phys[translate(bytes(benign.phys), dtb, start) :][: end - start])
            assert argv.split(b"\0")[:-1] == [a.encode() for a in proc.args]


def test_scenarios() -> None:
    assert set(SCENARIOS) == {"linux_benign", "linux_orphan_and_dup", "linux_wide",
                              "symbols_missing"}  # fmt: skip
    benign = scenario("linux_benign")
    assert 25 <= len(benign.procs) <= 40
    orphan = build(scenario("linux_orphan_and_dup"))
    assert list(orphan.exited) == [EXITED_PARENT]
    names = [p.comm for p in orphan.scenario.procs]
    assert names.count("systemd") == 2
    wide = scenario("linux_wide")
    assert len(wide.procs) == WIDE_COUNT == len({p.pid for p in wide.procs})
    missing = scenario("symbols_missing")
    assert missing.banner == UNKNOWN_BANNER != BANNER and missing.procs == benign.procs


def test_the_layout_refuses_what_does_not_fit() -> None:
    with pytest.raises(LayoutFull):
        build(Scenario("dup", (Proc(5, 0, "a"), Proc(5, 0, "b"))))
    with pytest.raises(LayoutFull):
        build(Scenario("many", tuple(Proc(i, 0, "x") for i in range(1, 20_000))))
    with pytest.raises(LayoutFull):
        build(scenario("linux_benign"), size=8 * 1024**2)


def test_the_isf_document() -> None:
    doc = isf()
    assert doc["metadata"]["producer"] == {"name": "cyberlab-memgen", "version": "0.1.0"}
    assert doc["metadata"]["format"] == k.ISF_FORMAT and "linux" in doc["metadata"]
    raw_banner = doc["symbols"]["linux_banner"]["constant_data"]
    assert base64.b64decode(raw_banner) == (BANNER + "\n\0").encode()
    required = {"file", "list_head", "hlist_head", "mm_struct", "super_block", "task_struct",
                "vm_area_struct", "qstr", "dentry", "fs_struct", "files_struct", "kobject",
                "cred", "inode", "idr", "address_space", "page", "vfsmount", "net", "socket",
                "sock", "inet_sock", "unix_sock"}  # fmt: skip
    assert required <= set(doc["user_types"])
    for name in ("init_task", "init_mm", "init_files", "init_top_pgt", "linux_banner"):
        assert name in doc["symbols"]
    assert json.loads(lzma.decompress(isf_xz())) == doc
    assert isf_xz() == isf_xz()  # deterministic


def test_the_isf_validates_against_volatility_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    from memory_worker.symbols.import_isf import ImportRefused, volatility_schema_dir

    try:
        schemas = volatility_schema_dir()
    except ImportRefused:
        pytest.skip("volatility3 is not installed here")
    schema = json.loads((schemas / f"schema-{k.ISF_FORMAT}.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(isf())
    jsonschema.Draft202012Validator(schema).validate(isf(UNKNOWN_BANNER))


def _lime_ranges(data: bytes) -> list[tuple[int, int, int]]:
    found, at = [], 0
    while at < len(data):
        magic, version, start, end, _ = wrappers.LIME_HEADER.unpack_from(data, at)
        assert (magic, version) == (wrappers.LIME_MAGIC, 1)
        found.append((start, end, at + wrappers.LIME_HEADER.size))
        at += wrappers.LIME_HEADER.size + end - start + 1
    return found


def test_lime_and_elf_hold_the_same_physical_bytes(benign: MemoryImage) -> None:
    lime = wrappers.lime(benign)
    ranges = _lime_ranges(lime)
    assert [(s, e + 1) for s, e, _ in ranges] == benign.ranges
    for start, end, at in ranges:
        assert lime[at : at + end - start + 1] == benign.phys[start : end + 1]
    elf = wrappers.elf(benign)
    header = wrappers.ELF_HEADER.unpack_from(elf, 0)
    assert header[0] == b"\x7fELF" and header[1] == 2 and header[7] == wrappers.ET_CORE
    phoff, phnum = header[11], header[16]
    assert phnum == len(benign.ranges)
    for i, (start, end) in enumerate(benign.ranges):
        p = wrappers.ELF_PHDR.unpack_from(elf, phoff + i * wrappers.ELF_PHDR.size)
        p_type, _, offset, _, paddr, filesz, memsz, _ = p
        assert (p_type, paddr, filesz, memsz) == (wrappers.PT_LOAD, start, end - start,
                                                  end - start)  # fmt: skip
        assert elf[offset : offset + filesz] == benign.phys[start:end]
    hole = benign.phys[k.HOLE[0] : k.HOLE[1]]
    assert hole == bytes(len(hole))  # nothing lives in what the wrappers leave out
    with pytest.raises(ValueError):
        wrappers.wrap(benign, "vmem")


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_images_are_deterministic_and_small(name: str) -> None:
    for fmt in wrappers.FORMATS:
        data = image_bytes(name, fmt)
        assert len(data) <= MAX_IMAGE_BYTES
        assert hashlib.sha256(data).digest() == hashlib.sha256(image_bytes(name, fmt)).digest()


def test_the_seed_changes_only_the_free_memory() -> None:
    one = build(scenario("linux_benign"))
    other = build(Scenario("linux_benign", one.scenario.procs, seed=99))
    assert one.phys[: k.NOISE] == other.phys[: k.NOISE]
    assert one.phys[k.NOISE : k.NOISE_END] != other.phys[k.NOISE : k.NOISE_END]


def test_fuzz_helpers_are_seeded_and_cover_every_family() -> None:
    first = list(mutate.mutants(seed=7, count=len(mutate.FAMILIES)))
    assert [m.family for m in first] == list(mutate.FAMILIES)
    again = list(mutate.mutants(seed=7, count=len(mutate.FAMILIES)))
    assert [hashlib.sha256(m.data).digest() for m in first] == [
        hashlib.sha256(m.data).digest() for m in again
    ]
    other = {m.family: m.data for m in mutate.mutants(seed=8, count=len(mutate.FAMILIES))}
    changed = [m.family for m in first if m.data != other[m.family]]
    assert set(changed) == set(mutate.FAMILIES) - {"zero_length"}
    benign = image_bytes("linux_benign")
    for m in first:
        assert m.fmt in wrappers.FORMATS and len(m.data) <= MAX_IMAGE_BYTES
        assert m.data != benign, m.name


def test_structure_mutations_damage_what_they_name() -> None:
    def rng() -> random.Random:
        return random.Random(3)

    assert mutate.zero_length(rng()) == b""
    assert 0 < len(mutate.truncate(rng())) < k.IMAGE_BYTES
    comm_off = k.resolve("task_struct", "comm")[0]
    data = mutate.huge_comm(rng())
    hit = [pid for pid, at in build(scenario("linux_benign")).tasks.items()
           if b"\0" not in data[at + comm_off : at + comm_off + k.COMM_LEN]]  # fmt: skip
    assert len(hit) == 4
    head = wrappers.LIME_HEADER.unpack_from(mutate.lime_lying(rng()), 0)
    assert head[3] + 1 > k.IMAGE_BYTES
    assert wrappers.LIME_HEADER.unpack_from(mutate.lime_huge(rng()), 0)[3] > 1 << 63
    ranges = _lime_header_starts(mutate.lime_overlap(rng()))
    assert ranges != sorted(ranges)


def _lime_header_starts(data: bytes) -> list[int]:
    starts, at = [], 0
    while at + wrappers.LIME_HEADER.size <= len(data):
        _, _, start, end, _ = wrappers.LIME_HEADER.unpack_from(data, at)
        starts.append(start)
        at += wrappers.LIME_HEADER.size + end - start + 1
    return starts


def test_the_command_line(tmp_path: Path) -> None:
    out = tmp_path / "img.lime"
    isf_out = tmp_path / "x.json.xz"
    assert memgen_main(["--scenario", "linux_orphan_and_dup", "--format", "lime",
                        "--out", str(out), "--isf-out", str(isf_out)]) == 0  # fmt: skip
    assert out.read_bytes() == image_bytes("linux_orphan_and_dup", "lime")
    assert isf_out.read_bytes() == isf_xz()
    with pytest.raises(SystemExit):
        memgen_main([])
