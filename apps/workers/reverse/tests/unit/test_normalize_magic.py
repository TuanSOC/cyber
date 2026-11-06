"""Root's magic check (pure Python): the loader root chooses, the diagnostics, the file's
preferred base (RT8), and refusals of everything else, from header bytes only."""

import pytest

from re_worker.engines.magic import UnsupportedFormat, inspect_bytes
from tests.stage_helpers import elf_header, pe_header


def test_pe_x64_and_x86() -> None:
    facts = inspect_bytes(pe_header())
    assert (facts.format, facts.loader, facts.arch, facts.bits) == ("pe", "pe", "x86_64", 64)
    assert facts.preferred_base == 0x140000000 and facts.diagnostic is None
    x86 = inspect_bytes(pe_header(machine=0x14C, pe32_plus=False, image_base=0x400000))
    assert (x86.arch, x86.bits, x86.machine, x86.preferred_base) == ("x86", 32, "i386", 0x400000)


def test_pe_managed_and_foreign_machines_are_diagnostics() -> None:
    assert inspect_bytes(pe_header(clr=True)).diagnostic == "unsupported_managed_code"
    arm = inspect_bytes(pe_header(machine=0xAA64))
    assert (arm.arch, arm.machine, arm.diagnostic) == ("other", "ARM64", "unsupported_architecture")


def test_elf_bases_and_machines() -> None:
    pie = inspect_bytes(elf_header(loads=(0x0, 0x3DB8)))
    assert (pie.format, pie.arch, pie.preferred_base) == ("elf", "x86_64", 0)
    exe = inspect_bytes(elf_header(e_type=2, loads=(0x401000, 0x400040)))
    assert exe.preferred_base == 0x400000  # lowest PT_LOAD, page-aligned
    x86 = inspect_bytes(elf_header(machine=3, elf64=False, loads=(0x8048000,)))
    assert (x86.arch, x86.bits, x86.preferred_base) == ("x86", 32, 0x8048000)
    arm = inspect_bytes(elf_header(machine=183))
    assert (arm.arch, arm.diagnostic) == ("other", "unsupported_architecture")
    x32 = inspect_bytes(elf_header(machine=62, elf64=False))
    assert x32.diagnostic == "unsupported_architecture"


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x00" * 64,
        b"PK\x03\x04" + b"\0" * 100,
        b"MZ" + b"\0" * 62,  # e_lfanew 0
        pe_header()[:0x90],  # truncated optional header
        elf_header(e_type=1),  # REL object
        elf_header(e_type=4),  # core dump
        elf_header(big_endian=True),
        b"\x7fELF\x03" + b"\0" * 80,  # unknown class
    ],
)
def test_everything_else_is_unsupported(data: bytes) -> None:
    with pytest.raises(UnsupportedFormat):
        inspect_bytes(data)


def test_hostile_header_fields_stay_in_bounds() -> None:
    import struct

    data = bytearray(pe_header())
    struct.pack_into("<I", data, 0x3C, 0xFFFFFFF0)  # e_lfanew far outside
    with pytest.raises(UnsupportedFormat):
        inspect_bytes(bytes(data))
    huge = bytearray(elf_header())
    struct.pack_into("<H", huge, 56, 0xFFFF)  # e_phnum beyond the cap: no base, no crash
    assert inspect_bytes(bytes(huge)).preferred_base == 0
