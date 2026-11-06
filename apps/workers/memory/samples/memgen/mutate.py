"""Seeded mutations of the synthetic images for fuzz-lite (M8 phases 4 and 11).

Every helper is deterministic for a given `random.Random` (the same seed gives the same bytes)
and returns a new byte string; nothing is written to disk here. Structure-level mutations
patch the built `MemoryImage` (so Volatility still stacks and walks into the damage);
container-level ones damage the raw / LiME / ELF bytes.

Families:
- `truncate`, `zero_length`, `corrupt_pages` (random pages overwritten, page tables and
  task area included);
- `cyclic_tasks` (a `tasks` loop that never returns to init_task), `self_parent`,
  `huge_comm` (16 non-NUL, non-ASCII bytes), `huge_args` (`arg_end` far past `arg_start`),
  `invalid_pointers` (non-canonical / unmapped `tasks`, `mm`, `cred`, `real_parent`),
  `page_table_loop` (a PD entry that points back at the PML4);
- `lime_lying` (a range longer than the file), `lime_overlap` (ranges out of order),
  `lime_huge` (an end near 2**64), `elf_lying` (a PT_LOAD beyond the file).
"""

from __future__ import annotations

import random
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from samples.memgen import kernel as k
from samples.memgen.image import MemoryImage, build
from samples.memgen.scenarios import scenario
from samples.memgen.wrappers import ELF_HEADER, ELF_PHDR, elf, lime, lime_header, raw

BASE_SCENARIO = "linux_benign"


@dataclass(frozen=True)
class Mutant:
    name: str  # "<family>#<n>"
    family: str
    fmt: str  # the container the bytes claim to be: raw / lime / elf
    data: bytes


def _image() -> MemoryImage:
    return build(scenario(BASE_SCENARIO))


def _pids(img: MemoryImage, rng: random.Random, n: int) -> list[int]:
    listed = [pid for pid in img.order if pid]
    return rng.sample(listed, min(n, len(listed)))


def truncate(rng: random.Random) -> bytes:
    data = raw(_image())
    return data[: rng.randrange(1, len(data))]


def zero_length(rng: random.Random) -> bytes:
    del rng
    return b""


def corrupt_pages(rng: random.Random, pages: int = 8) -> bytes:
    data = bytearray(raw(_image()))
    # Half the hits land where the kernel structures live (tables, banner, tasks, creds).
    hot = list(range(k.PML4 // k.PAGE, k.ARGS_END // k.PAGE))
    every = range(len(data) // k.PAGE)
    for i in range(pages):
        page = rng.choice(hot) if i % 2 == 0 else rng.choice(every)
        data[page * k.PAGE : (page + 1) * k.PAGE] = rng.randbytes(k.PAGE)
    return bytes(data)


def cyclic_tasks(rng: random.Random) -> bytes:
    img = _image()
    listed = [pid for pid in img.order if pid]
    i, j = sorted(rng.sample(range(len(listed)), 2))
    off = k.resolve("task_struct", "tasks")[0]
    # The later task points forward to an earlier one: the walk never reaches init_task.
    img.set(listed[j], "tasks.next", k.kva(img.tasks[listed[i]] + off))
    img.set(listed[i], "tasks.prev", k.kva(img.tasks[listed[j]] + off))
    return raw(img)


def self_parent(rng: random.Random) -> bytes:
    img = _image()
    for pid in _pids(img, rng, 3):
        img.set(pid, "real_parent", k.kva(img.tasks[pid]))
        img.set(pid, "parent", k.kva(img.tasks[pid]))
    return raw(img)


def huge_comm(rng: random.Random) -> bytes:
    img = _image()
    for pid in _pids(img, rng, 4):
        img.set(pid, "comm", bytes(rng.randrange(0x80, 0x100) for _ in range(k.COMM_LEN)))
    return raw(img)


def huge_args(rng: random.Random) -> bytes:
    img = _image()
    for pid in _pids(img, rng, 4):
        mm = img.u64(img.tasks[pid] + k.resolve("task_struct", "mm")[0])
        if mm:
            at = mm - k.KERNEL_MAP
            start = img.u64(at + k.resolve("mm_struct", "arg_start")[0])
            img.put(at, "mm_struct", "arg_end", start + rng.choice([4097, 1 << 20, 1 << 40]))
    return raw(img)


def invalid_pointers(rng: random.Random) -> bytes:
    img = _image()
    members = ["tasks.next", "tasks.prev", "mm", "active_mm", "cred", "real_parent", "files"]
    for pid in _pids(img, rng, 6):
        value = rng.choice([
            rng.getrandbits(64),  # mostly non-canonical
            k.KERNEL_MAP + len(img.phys) + rng.randrange(0, 1 << 30),  # canonical, unmapped
            0x4141414141414141,
            1,
        ])  # fmt: skip
        img.set(pid, rng.choice(members), value)
    return raw(img)


def page_table_loop(rng: random.Random) -> bytes:
    img = _image()
    index = rng.randrange(8, 512)
    struct.pack_into("<Q", img.phys, k.KERNEL_PD + index * 8, k.PML4 | k.PRESENT | k.WRITABLE)
    struct.pack_into("<Q", img.phys, k.USER_PD + 8, k.USER_PML4 | k.PRESENT | k.WRITABLE)
    return raw(img)


def lime_lying(rng: random.Random) -> bytes:
    img = _image()
    data = bytearray(lime(img))
    # The first range claims far more bytes than follow it.
    end = rng.choice([len(data) * 4, 1 << 40, len(img.phys) + k.PAGE])
    data[: len(lime_header(0, 0))] = lime_header(0, end)
    return bytes(data)


def lime_overlap(rng: random.Random) -> bytes:
    img = _image()
    low, high = img.ranges
    back = rng.randrange(1, low[1] // k.PAGE) * k.PAGE
    return lime(img, [high, (low[0], low[1]), (high[0] - back, high[0])])


def lime_huge(rng: random.Random) -> bytes:
    img = _image()
    data = bytearray(lime(img))
    data[:32] = lime_header(0, (1 << 64) - 1 - rng.randrange(0, 1 << 16))
    return bytes(data)


def elf_lying(rng: random.Random) -> bytes:
    img = _image()
    data = bytearray(elf(img))
    # The second PT_LOAD claims data past the end of the file (or a huge memsz).
    at = ELF_HEADER.size + ELF_PHDR.size
    fields = list(ELF_PHDR.unpack_from(data, at))
    if rng.random() < 0.5:
        fields[2] = len(data) + rng.randrange(1, 1 << 30)  # p_offset beyond the file
    else:
        fields[5] = fields[6] = 1 << 46  # p_filesz / p_memsz huge
    ELF_PHDR.pack_into(data, at, *fields)
    return bytes(data)


FAMILIES: dict[str, tuple[str, Callable[[random.Random], bytes]]] = {
    "truncate": ("raw", truncate),
    "zero_length": ("raw", zero_length),
    "corrupt_pages": ("raw", corrupt_pages),
    "cyclic_tasks": ("raw", cyclic_tasks),
    "self_parent": ("raw", self_parent),
    "huge_comm": ("raw", huge_comm),
    "huge_args": ("raw", huge_args),
    "invalid_pointers": ("raw", invalid_pointers),
    "page_table_loop": ("raw", page_table_loop),
    "lime_lying": ("lime", lime_lying),
    "lime_overlap": ("lime", lime_overlap),
    "lime_huge": ("lime", lime_huge),
    "elf_lying": ("elf", elf_lying),
}


def mutants(seed: int, count: int = 50) -> Iterator[Mutant]:
    """`count` mutants, round-robin over the families (each family seeded from `seed`), so
    every family appears once `count >= len(FAMILIES)`. Lazy: one 16 MiB image at a time."""
    names = list(FAMILIES)
    for n in range(count):
        family = names[n % len(names)]
        fmt, helper = FAMILIES[family]
        rng = random.Random(f"{seed}:{n}:{family}")
        yield Mutant(name=f"{family}#{n}", family=family, fmt=fmt, data=helper(rng))


__all__ = ["FAMILIES", "Mutant", "mutants"]
