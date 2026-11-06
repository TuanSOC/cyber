"""The synthetic kernel: our own type layouts, the ISF that describes them and the physical
memory that holds them (M8 phase 4). Pure stdlib; nothing here comes from a real kernel, a
real image or Volatility (only the ISF *format* is Volatility's public schema).

What Volatility 3 (2.28.2) needs to run `linux.pslist` on an image (phase-4 notes):

- `LinuxIntelStacker` scans the physical layer for the ISF's `linux_banner.constant_data`,
  then (`find_aslr`) for `swapper/0` + NULs: the hit's `task_struct` must have pid 0, `files`
  = `&init_files` (virtual shift) and its physical offset gives the physical shift (both 0
  here); `active_mm`, `tasks` are read on the way. The DTB is `init_top_pgt` (x86-64 4-level)
  translated with `virtual - 0xffffffff80000000`.
- `LinuxKernelIntermedSymbols` requires these user types to exist (any layout): file,
  list_head, hlist_head, mm_struct, super_block, task_struct, vm_area_struct, qstr, dentry,
  fs_struct, files_struct, kobject, cred, inode, idr, address_space, page, vfsmount, net,
  socket, sock, inet_sock, unix_sock.
- `linux.pslist` walks `init_task.tasks` both ways (init_task itself is the sentinel, never
  listed), and per task reads pid, tgid, comm, real_parent->tgid, mm / active_mm (a user task
  is valid only when they are equal), cred->{uid,gid,euid,egid}.val and flags (PF_KTHREAD).
- `linux.psaux` (cheap, so done): `mm->pgd` (a process layer), `mm->arg_start` / `arg_end`
  read through that layer; kernel threads (no mm) print `[comm]`.

Physical layout (one flat map; kernel virtual = `KERNEL_MAP` + physical, KASLR 0):

    0x001000  init_top_pgt (PML4)   0x002000 kernel PDPT   0x003000 kernel PD (2 MiB pages)
    0x004000  user PML4 (shared)    0x005000 user PDPT     0x006000 user PD (argv region)
    0x010000  linux_banner          0x011000 init_mm / init_files / init_cred
    0x100000  init_task, then every task_struct (0x100 each)
    0x400000  mm_structs            0x500000 creds          0x600000 argv strings (2 MiB)
    0x800000  seeded noise (free memory)

The 640 KiB..1 MiB "hole" holds nothing, so the LiME / ELF wrappers can leave it out.
"""

from __future__ import annotations

import base64
import json
import lzma
import struct
from dataclasses import dataclass, field
from typing import Any

PAGE = 0x1000
LARGE_PAGE = 0x200000
KERNEL_MAP = 0xFFFFFFFF80000000  # __START_KERNEL_map
IMAGE_BYTES = 16 * 1024**2
PF_KTHREAD = 0x00200000
ISF_FORMAT = "6.2.0"
PRODUCER = {"name": "cyberlab-memgen", "version": "0.1.0"}
ISF_NAME = "cyberlab-synthetic-6.1.0.json.xz"

# Physical layout.
PML4 = 0x1000
KERNEL_PDPT = 0x2000
KERNEL_PD = 0x3000
USER_PML4 = 0x4000
USER_PDPT = 0x5000
USER_PD = 0x6000
BANNER_AT = 0x10000
INIT_MM = 0x11000
INIT_FILES = 0x11100
INIT_CRED = 0x11200
TASKS = 0x100000
TASKS_END = 0x400000
MMS = 0x400000
MMS_END = 0x500000
CREDS = 0x500000
CREDS_END = 0x600000
ARGS = 0x600000
ARGS_END = 0x800000
NOISE = 0x800000
NOISE_END = 0xC00000
HOLE = (0xA0000, 0x100000)  # nothing lives here: LiME / ELF ranges skip it
# The argv region as user processes see it (one shared user address space).
USER_ARGS_VA = 0x00007FFD00000000

# Page-table entry bits.
PRESENT, WRITABLE, USER, PSE = 0x1, 0x2, 0x4, 0x80


def kva(phys: int) -> int:
    """The kernel virtual address of a physical offset (no KASLR)."""
    return KERNEL_MAP + phys


# --- types --------------------------------------------------------------------------------

TypeDesc = dict[str, Any]


def base(name: str) -> TypeDesc:
    return {"kind": "base", "name": name}


def ptr(sub: TypeDesc) -> TypeDesc:
    return {"kind": "pointer", "subtype": sub}


def ref(name: str) -> TypeDesc:
    return {"kind": "struct", "name": name}


def array(count: int, sub: TypeDesc) -> TypeDesc:
    return {"kind": "array", "count": count, "subtype": sub}


# name -> (kind, size, signed)
BASE_TYPES: dict[str, tuple[str, int, bool]] = {
    "char": ("char", 1, True),
    "unsigned char": ("char", 1, False),
    "short int": ("int", 2, True),
    "short unsigned int": ("int", 2, False),
    "int": ("int", 4, True),
    "unsigned int": ("int", 4, False),
    "long int": ("int", 8, True),
    "long unsigned int": ("int", 8, False),
    "long long int": ("int", 8, True),
    "long long unsigned int": ("int", 8, False),
    "_Bool": ("bool", 1, False),
    "void": ("void", 0, False),
    "pointer": ("int", 8, False),
}

ULONG = base("long unsigned int")
U64 = base("long long unsigned int")
UINT = base("unsigned int")
INT = base("int")
CHAR = base("char")

Fields = dict[str, tuple[int, TypeDesc]]


@dataclass(frozen=True)
class Struct:
    size: int
    fields: Fields = field(default_factory=dict)


TASK_SIZE = 0x100
MM_SIZE = 0x80
CRED_SIZE = 0x40
COMM_LEN = 16

STRUCTS: dict[str, Struct] = {
    "list_head": Struct(
        16, {"next": (0, ptr(ref("list_head"))), "prev": (8, ptr(ref("list_head")))}
    ),
    "kuid_t": Struct(4, {"val": (0, UINT)}),
    "kgid_t": Struct(4, {"val": (0, UINT)}),
    "pgd_t": Struct(8, {"pgd": (0, ULONG)}),
    "task_struct": Struct(
        TASK_SIZE,
        {
            "__state": (0x00, UINT),
            "flags": (0x04, UINT),
            "tasks": (0x10, ref("list_head")),
            "pid": (0x20, INT),
            "tgid": (0x24, INT),
            "real_parent": (0x28, ptr(ref("task_struct"))),
            "parent": (0x30, ptr(ref("task_struct"))),
            "mm": (0x38, ptr(ref("mm_struct"))),
            "active_mm": (0x40, ptr(ref("mm_struct"))),
            "real_cred": (0x48, ptr(ref("cred"))),
            "cred": (0x50, ptr(ref("cred"))),
            "files": (0x58, ptr(ref("files_struct"))),
            "start_time": (0x60, U64),
            "start_boottime": (0x68, U64),
            "comm": (0x70, array(COMM_LEN, CHAR)),
        },
    ),
    "mm_struct": Struct(
        MM_SIZE,
        {
            "pgd": (0x00, ptr(ref("pgd_t"))),
            "start_code": (0x08, ULONG),
            "end_code": (0x10, ULONG),
            "start_data": (0x18, ULONG),
            "end_data": (0x20, ULONG),
            "start_brk": (0x28, ULONG),
            "brk": (0x30, ULONG),
            "start_stack": (0x38, ULONG),
            "arg_start": (0x40, ULONG),
            "arg_end": (0x48, ULONG),
            "env_start": (0x50, ULONG),
            "env_end": (0x58, ULONG),
        },
    ),
    "cred": Struct(
        CRED_SIZE,
        {
            "usage": (0x00, INT),
            "uid": (0x04, ref("kuid_t")),
            "gid": (0x08, ref("kgid_t")),
            "suid": (0x0C, ref("kuid_t")),
            "sgid": (0x10, ref("kgid_t")),
            "euid": (0x14, ref("kuid_t")),
            "egid": (0x18, ref("kgid_t")),
            "fsuid": (0x1C, ref("kuid_t")),
            "fsgid": (0x20, ref("kgid_t")),
        },
    ),
    "files_struct": Struct(0x40, {"count": (0x00, INT)}),
}
# Types Volatility's Linux symbol class insists on; nothing in this image uses them.
PLACEHOLDER_TYPES = (
    "file", "hlist_head", "super_block", "vm_area_struct", "qstr", "dentry", "fs_struct",
    "kobject", "inode", "idr", "address_space", "page", "vfsmount", "net", "socket", "sock",
    "inet_sock", "unix_sock",
)  # fmt: skip
for _name in PLACEHOLDER_TYPES:
    STRUCTS[_name] = Struct(8)

_FORMATS = {(1, True): "<b", (1, False): "<B", (2, True): "<h", (2, False): "<H",
            (4, True): "<i", (4, False): "<I", (8, True): "<q", (8, False): "<Q"}  # fmt: skip


def resolve(struct_name: str, path: str) -> tuple[int, TypeDesc]:
    """Offset and type of a (dotted) member path, e.g. `task_struct`, `tasks.next`."""
    offset = 0
    current = struct_name
    desc: TypeDesc = ref(struct_name)
    for part in path.split("."):
        member_offset, desc = STRUCTS[current].fields[part]
        offset += member_offset
        if desc["kind"] == "struct":
            current = desc["name"]
    return offset, desc


def encode(desc: TypeDesc, value: int | bytes) -> bytes:
    """Bytes of one value of a pointer, base or char-array type (or a one-field struct)."""
    kind = desc["kind"]
    if kind == "pointer":
        return struct.pack("<Q", int(value) & 0xFFFFFFFFFFFFFFFF)
    if kind == "base":
        _, size, signed = BASE_TYPES[desc["name"]]
        return struct.pack(_FORMATS[(size, signed)], int(value))
    if kind == "array":
        raw = bytes(value) if isinstance(value, (bytes, bytearray)) else str(value).encode()
        return raw[: desc["count"]].ljust(desc["count"], b"\x00")
    if kind == "struct":  # kuid_t / kgid_t: the single `val`
        (inner,) = STRUCTS[desc["name"]].fields.values()
        return encode(inner[1], value)
    raise ValueError(f"cannot encode a {kind}")


# --- the banner and the ISF ----------------------------------------------------------------

BANNER = (
    "Linux version 6.1.0-cyberlab-synthetic (memgen@cyberlab.invalid) (gcc (CyberLab "
    "synthetic) 12.2.0, GNU ld 2.40) #1 SMP PREEMPT_DYNAMIC Thu Jan 1 00:00:00 UTC 2026"
)
# The symbols-missing variant: the same image with a banner no store ever holds an ISF for.
UNKNOWN_BANNER = (
    "Linux version 6.1.0-cyberlab-unknown (memgen@cyberlab.invalid) (gcc (CyberLab "
    "synthetic) 12.2.0, GNU ld 2.40) #1 SMP PREEMPT_DYNAMIC Thu Jan 1 00:00:00 UTC 2026"
)


def banner_bytes(banner: str) -> bytes:
    """`linux_banner` as the kernel stores it: the text, a newline, a NUL."""
    return banner.encode("ascii") + b"\n\x00"


def symbol_table() -> dict[str, tuple[int, TypeDesc]]:
    """Symbol -> (physical offset, type), without the banner (sized per banner)."""
    return {
        "init_top_pgt": (PML4, array(512, ref("pgd_t"))),
        "init_task": (TASKS, ref("task_struct")),
        "init_mm": (INIT_MM, ref("mm_struct")),
        "init_files": (INIT_FILES, ref("files_struct")),
        "init_cred": (INIT_CRED, ref("cred")),
    }


def isf(banner: str = BANNER) -> dict[str, Any]:
    """Our ISF for the synthetic kernel (Volatility's schema 6.2.0)."""
    raw = banner_bytes(banner)
    symbols: dict[str, Any] = {
        "linux_banner": {
            "address": kva(BANNER_AT),
            "type": array(len(raw), CHAR),
            "constant_data": base64.b64encode(raw).decode("ascii"),
        }
    }
    for name, (phys, desc) in symbol_table().items():
        symbols[name] = {"address": kva(phys), "type": desc}
    return {
        "metadata": {
            "format": ISF_FORMAT,
            "producer": dict(PRODUCER),
            "linux": {"symbols": [], "types": []},
        },
        "base_types": {
            name: {"kind": kind, "size": size, "signed": signed, "endian": "little"}
            for name, (kind, size, signed) in BASE_TYPES.items()
        },
        "user_types": {
            name: {
                "kind": "struct",
                "size": s.size,
                "fields": {f: {"offset": off, "type": desc} for f, (off, desc) in s.fields.items()},
            }
            for name, s in STRUCTS.items()
        },
        "enums": {},
        "symbols": symbols,
    }


def isf_json(banner: str = BANNER) -> bytes:
    return json.dumps(isf(banner), sort_keys=True, separators=(",", ":")).encode("ascii")


def isf_xz(banner: str = BANNER) -> bytes:
    """The ISF as `.json.xz` (deterministic: same banner, same bytes)."""
    return lzma.compress(isf_json(banner), format=lzma.FORMAT_XZ, preset=6)


__all__ = [
    "BANNER",
    "IMAGE_BYTES",
    "ISF_NAME",
    "KERNEL_MAP",
    "PF_KTHREAD",
    "STRUCTS",
    "UNKNOWN_BANNER",
    "banner_bytes",
    "encode",
    "isf",
    "isf_json",
    "isf_xz",
    "kva",
    "resolve",
]
