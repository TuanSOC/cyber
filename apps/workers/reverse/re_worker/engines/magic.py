"""Root's magic check (M10 phase 2): which loader, or which diagnostic, from header bytes only.

Root never parses the sample beyond this: a bounded read of the first `HEADER_BYTES` (plus,
for ELF, the program headers inside that window) through `struct`, the M3 rule. The probe
never chooses the loader: root passes `pe` / `elf` on its command line.

- `MZ` + an in-bounds `PE\\0\\0` -> `PeLoader`; a non-empty CLR data directory (index 14)
  -> diagnostic `unsupported_managed_code`; a machine other than i386 / amd64 -> diagnostic
  `unsupported_architecture`.
- `\\x7fELF`, little-endian, `e_type` EXEC / DYN -> `ElfLoader`; a machine other than
  EM_386 / EM_X86_64 (or x32: EM_X86_64 in a 32-bit class) -> `unsupported_architecture`;
  REL / CORE / big-endian -> `unsupported_format`.
- Anything else -> `unsupported_format` (a `JobFailed`, no stream).

`preferred_base` is the file's own base (RT8): PE `ImageBase`; ELF the lowest `PT_LOAD`
`p_vaddr`, page-aligned (0 when there is none).
"""

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cyberlab_jobs.reverse import FileFormat, ReArch

HEADER_BYTES = 64 * 1024
MAX_PE_OFFSET = HEADER_BYTES - 512
MAX_PHNUM = 512
PAGE_MASK = ~0xFFF
PT_LOAD = 1
CLR_DIRECTORY = 14
PE_MACHINES: dict[int, tuple[ReArch, str]] = {0x14C: ("x86", "i386"), 0x8664: ("x86_64", "AMD64")}
PE_MACHINE_NAMES = {0x1C0: "ARM", 0x1C4: "ARMNT", 0xAA64: "ARM64", 0x200: "IA64", 0x5064: "RISCV64"}
ELF_MACHINES: dict[int, tuple[ReArch, str]] = {3: ("x86", "EM_386"), 62: ("x86_64", "EM_X86_64")}
ELF_MACHINE_NAMES = {8: "EM_MIPS", 20: "EM_PPC", 21: "EM_PPC64", 40: "EM_ARM", 183: "EM_AARCH64"}
ET_EXEC, ET_DYN = 2, 3
Loader = Literal["pe", "elf"]
Diagnostic = Literal["unsupported_architecture", "unsupported_managed_code"]


class UnsupportedFormat(ValueError):
    """Neither a PE nor a loadable little-endian ELF (`unsupported_format`)."""


@dataclass(frozen=True)
class SampleFacts:
    format: FileFormat
    arch: ReArch
    machine: str
    bits: Literal[32, 64]
    endianness: Literal["little", "big"]
    preferred_base: int
    diagnostic: Diagnostic | None = None

    @property
    def loader(self) -> Loader:
        return self.format


def _u16(data: bytes, off: int, fmt: str = "<H") -> int:
    if off < 0 or off + 2 > len(data):
        raise UnsupportedFormat("header out of bounds")
    return int(struct.unpack_from(fmt, data, off)[0])


def _u32(data: bytes, off: int, fmt: str = "<I") -> int:
    if off < 0 or off + 4 > len(data):
        raise UnsupportedFormat("header out of bounds")
    return int(struct.unpack_from(fmt, data, off)[0])


def _u64(data: bytes, off: int, fmt: str = "<Q") -> int:
    if off < 0 or off + 8 > len(data):
        raise UnsupportedFormat("header out of bounds")
    return int(struct.unpack_from(fmt, data, off)[0])


def _pe(data: bytes) -> SampleFacts:
    e_lfanew = _u32(data, 0x3C)
    if not 0x40 <= e_lfanew <= MAX_PE_OFFSET or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise UnsupportedFormat("no PE signature")
    machine = _u16(data, e_lfanew + 4)
    opt_size = _u16(data, e_lfanew + 20)
    opt = e_lfanew + 24
    magic = _u16(data, opt)
    if magic == 0x10B:
        bits: Literal[32, 64] = 32
        image_base = _u32(data, opt + 28)
        count_off, dirs_off = opt + 92, opt + 96
    elif magic == 0x20B:
        bits = 64
        image_base = _u64(data, opt + 24)
        count_off, dirs_off = opt + 108, opt + 112
    else:
        raise UnsupportedFormat("unknown optional header")
    known = PE_MACHINES.get(machine)
    if known is None:
        name = PE_MACHINE_NAMES.get(machine, f"0x{machine:04x}")
        return SampleFacts(
            "pe", "other", name, bits, "little", image_base, "unsupported_architecture"
        )
    arch, name = known
    clr_size = 0
    count = _u32(data, count_off) if count_off + 4 <= opt + opt_size else 0
    clr = dirs_off + CLR_DIRECTORY * 8
    if count > CLR_DIRECTORY and clr + 8 <= min(len(data), opt + opt_size):
        clr_rva, clr_size = struct.unpack_from("<II", data, clr)
        clr_size = clr_size if clr_rva else 0
    diagnostic: Diagnostic | None = "unsupported_managed_code" if clr_size else None
    return SampleFacts("pe", arch, name, bits, "little", image_base, diagnostic)


def _elf_base(data: bytes, bits: int) -> int:
    if bits == 64:
        phoff, phentsize, phnum = _u64(data, 32), _u16(data, 54), _u16(data, 56)
        minimum = 56
    else:
        phoff, phentsize, phnum = _u32(data, 28), _u16(data, 42), _u16(data, 44)
        minimum = 32
    if phnum == 0 or phentsize < minimum or phnum > MAX_PHNUM:
        return 0
    lowest: int | None = None
    for i in range(phnum):
        entry = phoff + i * phentsize
        if entry + phentsize > len(data):
            break  # program headers beyond the window: what was read decides
        if _u32(data, entry) != PT_LOAD:
            continue
        vaddr = _u64(data, entry + 16) if bits == 64 else _u32(data, entry + 8)
        lowest = vaddr if lowest is None else min(lowest, vaddr)
    return (lowest & PAGE_MASK) if lowest is not None else 0


def _elf(data: bytes) -> SampleFacts:
    if len(data) < 64:
        raise UnsupportedFormat("truncated ELF header")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2):
        raise UnsupportedFormat("unknown ELF class")
    if ei_data != 1:
        raise UnsupportedFormat("big-endian or unknown ELF data encoding")
    bits: Literal[32, 64] = 64 if ei_class == 2 else 32
    e_type, e_machine = _u16(data, 16), _u16(data, 18)
    if e_type not in (ET_EXEC, ET_DYN):
        raise UnsupportedFormat("not an executable or shared object")
    base = _elf_base(data, bits)
    known = ELF_MACHINES.get(e_machine)
    if known is None or (known[0] == "x86_64") != (bits == 64):
        name = ELF_MACHINE_NAMES.get(e_machine, f"e_machine {e_machine}")
        if known is not None:
            name = "EM_X86_64 (x32)" if bits == 32 else "EM_386 (64-bit class)"
        return SampleFacts("elf", "other", name, bits, "little", base, "unsupported_architecture")
    arch, name = known
    return SampleFacts("elf", arch, name, bits, "little", base)


def inspect_bytes(data: bytes) -> SampleFacts:
    """Facts from the first bytes of a sample (pure; `UnsupportedFormat` otherwise)."""
    if data[:2] == b"MZ":
        return _pe(data)
    if data[:4] == b"\x7fELF":
        return _elf(data)
    raise UnsupportedFormat("neither PE nor ELF")


def inspect(path: Path) -> SampleFacts:
    with open(path, "rb") as f:
        return inspect_bytes(f.read(HEADER_BYTES))


__all__ = ["HEADER_BYTES", "SampleFacts", "UnsupportedFormat", "inspect", "inspect_bytes"]
