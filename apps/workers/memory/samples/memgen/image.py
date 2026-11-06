"""Build the physical memory of one synthetic Linux x86-64 machine from a scenario (M8 phase 4).

`build(scenario) -> MemoryImage`: a flat 16 MiB physical map holding the page tables, the
banner, `init_task` and one `task_struct` per process (in the scenario's order on the circular
`tasks` list), their `mm_struct`s, creds and argv strings, plus seeded noise as "free memory".
A process whose `ppid` names no process of the scenario gets an *exited* parent: a
`task_struct` with that pid that is not on the list (what a real image shows after the parent
exited). Everything is deterministic: the same scenario (and seed) gives the same bytes.

`MemoryImage.set(pid, member, value)` patches one member afterwards (the fuzz helpers use it).
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field

from samples.memgen import kernel as k


@dataclass(frozen=True)
class Proc:
    pid: int
    ppid: int  # 0: a child of init_task (the swapper); a pid outside the scenario: exited
    comm: str
    uid: int = 0
    gid: int = 0
    args: tuple[str, ...] = ()  # argv; a user process without one shows an empty command
    kthread: bool = False
    start_s: int = 0  # seconds after boot


@dataclass(frozen=True)
class Scenario:
    name: str
    procs: tuple[Proc, ...]
    banner: str = k.BANNER
    seed: int = 0


class LayoutFull(ValueError):
    """The scenario does not fit the fixed physical layout."""


@dataclass
class MemoryImage:
    scenario: Scenario
    phys: bytearray
    tasks: dict[int, int] = field(default_factory=dict)  # pid -> task_struct (on the list)
    exited: dict[int, int] = field(default_factory=dict)  # exited parents (not on the list)
    order: list[int] = field(default_factory=list)  # list order (init_task first)

    @property
    def ranges(self) -> list[tuple[int, int]]:
        """Physical ranges a LiME / ELF capture holds (end exclusive): all but the hole."""
        return [(0, k.HOLE[0]), (k.HOLE[1], len(self.phys))]

    def task_at(self, pid: int) -> int:
        return self.tasks[pid] if pid in self.tasks else self.exited[pid]

    def put(self, phys: int, struct_name: str, member: str, value: int | bytes) -> None:
        offset, desc = k.resolve(struct_name, member)
        data = k.encode(desc, value)
        self.phys[phys + offset : phys + offset + len(data)] = data

    def set(self, pid: int, member: str, value: int | bytes) -> None:
        """Patch one `task_struct` member of a process (dotted path, e.g. `tasks.next`)."""
        self.put(self.task_at(pid), "task_struct", member, value)

    def u64(self, phys: int) -> int:
        return int(struct.unpack_from("<Q", self.phys, phys)[0])


def _entry(table: int, index: int, value: int, phys: bytearray) -> None:
    struct.pack_into("<Q", phys, table + index * 8, value)


def _index(va: int, level: int) -> int:
    """Page-table index of `va` at level 4 (PML4) .. 2 (PD)."""
    return (va >> (12 + 9 * (level - 1))) & 0x1FF


def _page_tables(phys: bytearray) -> None:
    rw = k.PRESENT | k.WRITABLE
    # Kernel: PML4[511] -> PDPT[510] -> PD of 2 MiB pages mapping all physical memory at
    # KERNEL_MAP (0xffffffff80000000 + physical).
    _entry(k.PML4, _index(k.KERNEL_MAP, 4), k.KERNEL_PDPT | rw, phys)
    _entry(k.KERNEL_PDPT, _index(k.KERNEL_MAP, 3), k.KERNEL_PD | rw, phys)
    for i in range(len(phys) // k.LARGE_PAGE):
        _entry(k.KERNEL_PD, i, (i * k.LARGE_PAGE) | rw | k.PSE, phys)
    # The user address space every process shares: the kernel half, plus the argv region
    # (read-only, user) at USER_ARGS_VA.
    user = k.PRESENT | k.USER
    _entry(k.USER_PML4, _index(k.KERNEL_MAP, 4), k.KERNEL_PDPT | rw, phys)
    _entry(k.USER_PML4, _index(k.USER_ARGS_VA, 4), k.USER_PDPT | rw | k.USER, phys)
    _entry(k.USER_PDPT, _index(k.USER_ARGS_VA, 3), k.USER_PD | rw | k.USER, phys)
    _entry(k.USER_PD, _index(k.USER_ARGS_VA, 2), k.ARGS | user | k.PSE, phys)


def _comm(name: str) -> bytes:
    return name.encode("ascii", "replace")[: k.COMM_LEN - 1]


def build(scenario: Scenario, size: int = k.IMAGE_BYTES) -> MemoryImage:
    if size < k.NOISE_END or size % k.LARGE_PAGE:
        raise LayoutFull("the image must cover the layout in whole 2 MiB pages")
    phys = bytearray(size)
    img = MemoryImage(scenario=scenario, phys=phys)
    _page_tables(phys)
    raw_banner = k.banner_bytes(scenario.banner)
    phys[k.BANNER_AT : k.BANNER_AT + len(raw_banner)] = raw_banner

    img.put(k.INIT_MM, "mm_struct", "pgd", k.kva(k.PML4))
    img.put(k.INIT_FILES, "files_struct", "count", 1)
    img.put(k.INIT_CRED, "cred", "usage", 1)

    # Slots: init_task, then the listed processes, then the exited parents.
    pids = [p.pid for p in scenario.procs]
    if len(set(pids)) != len(pids) or 0 in pids:
        raise LayoutFull("pids must be unique and non-zero")
    exited = sorted({p.ppid for p in scenario.procs if p.ppid and p.ppid not in pids})
    slots = 1 + len(pids) + len(exited)
    if k.TASKS + slots * k.TASK_SIZE > k.TASKS_END:
        raise LayoutFull("too many processes for the task area")
    img.tasks = {pid: k.TASKS + (i + 1) * k.TASK_SIZE for i, pid in enumerate(pids)}
    base = k.TASKS + (len(pids) + 1) * k.TASK_SIZE
    img.exited = {pid: base + i * k.TASK_SIZE for i, pid in enumerate(exited)}

    init = k.TASKS
    _task(img, init, pid=0, comm=b"swapper/0", flags=k.PF_KTHREAD, parent=init, mm=0,
          active_mm=k.INIT_MM, cred=k.INIT_CRED, start_ns=0)  # fmt: skip
    for pid, at in img.exited.items():
        _task(img, at, pid=pid, comm=b"(exited)", flags=0, parent=init, mm=0,
              active_mm=k.INIT_MM, cred=k.INIT_CRED, start_ns=0)  # fmt: skip

    mm_at, cred_at, args_at = k.MMS, k.CREDS, k.ARGS
    for proc in scenario.procs:
        parent = init if proc.ppid == 0 else img.task_at(proc.ppid)
        cred = k.INIT_CRED
        if proc.uid or proc.gid or not proc.kthread:
            if cred_at + k.CRED_SIZE > k.CREDS_END:
                raise LayoutFull("too many creds")
            cred = cred_at
            cred_at += k.CRED_SIZE
            img.put(cred, "cred", "usage", 1)
            for member in ("uid", "suid", "euid", "fsuid"):
                img.put(cred, "cred", member, proc.uid)
            for member in ("gid", "sgid", "egid", "fsgid"):
                img.put(cred, "cred", member, proc.gid)
        mm = 0
        if not proc.kthread:
            if mm_at + k.MM_SIZE > k.MMS_END:
                raise LayoutFull("too many mm_structs")
            mm = mm_at
            mm_at += k.MM_SIZE
            argv = b"".join(a.encode("utf-8") + b"\x00" for a in proc.args)
            if args_at + len(argv) > k.ARGS_END:
                raise LayoutFull("the argv area is full")
            phys[args_at : args_at + len(argv)] = argv
            start = k.USER_ARGS_VA + (args_at - k.ARGS)
            img.put(mm, "mm_struct", "pgd", k.kva(k.USER_PML4))
            img.put(mm, "mm_struct", "arg_start", start)
            img.put(mm, "mm_struct", "arg_end", start + len(argv))
            img.put(mm, "mm_struct", "env_start", start + len(argv))
            img.put(mm, "mm_struct", "env_end", start + len(argv))
            args_at += (len(argv) + 15) & ~15
        _task(img, img.tasks[proc.pid], pid=proc.pid, comm=_comm(proc.comm),
              flags=k.PF_KTHREAD if proc.kthread else 0, parent=parent, mm=mm,
              active_mm=mm or k.INIT_MM, cred=cred,
              start_ns=proc.start_s * 1_000_000_000)  # fmt: skip

    img.order = [0, *pids]
    _link(img, [init, *(img.tasks[pid] for pid in pids)])
    rng = random.Random(scenario.seed)
    phys[k.NOISE : k.NOISE_END] = rng.randbytes(k.NOISE_END - k.NOISE)
    return img


def _task(img: MemoryImage, at: int, *, pid: int, comm: bytes, flags: int, parent: int,
          mm: int, active_mm: int, cred: int, start_ns: int) -> None:  # fmt: skip
    put = img.put
    put(at, "task_struct", "pid", pid)
    put(at, "task_struct", "tgid", pid)
    put(at, "task_struct", "flags", flags)
    put(at, "task_struct", "comm", comm)
    put(at, "task_struct", "real_parent", k.kva(parent))
    put(at, "task_struct", "parent", k.kva(parent))
    put(at, "task_struct", "mm", k.kva(mm) if mm else 0)
    put(at, "task_struct", "active_mm", k.kva(active_mm))
    put(at, "task_struct", "cred", k.kva(cred))
    put(at, "task_struct", "real_cred", k.kva(cred))
    put(at, "task_struct", "files", k.kva(k.INIT_FILES))
    put(at, "task_struct", "start_time", start_ns)
    put(at, "task_struct", "start_boottime", start_ns)
    # A task off the list points at itself (an empty list_head), as the kernel leaves it.
    own = k.kva(at + k.resolve("task_struct", "tasks")[0])
    put(at, "task_struct", "tasks.next", own)
    put(at, "task_struct", "tasks.prev", own)


def _link(img: MemoryImage, chain: list[int]) -> None:
    """The circular `tasks` list in this order (init_task first)."""
    off = k.resolve("task_struct", "tasks")[0]
    n = len(chain)
    for i, at in enumerate(chain):
        img.put(at, "task_struct", "tasks.next", k.kva(chain[(i + 1) % n] + off))
        img.put(at, "task_struct", "tasks.prev", k.kva(chain[(i - 1) % n] + off))


__all__ = ["LayoutFull", "MemoryImage", "Proc", "Scenario", "build"]
