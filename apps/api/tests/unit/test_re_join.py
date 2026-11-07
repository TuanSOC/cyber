"""M10 phase 7: the capa -> function join on file virtual addresses (RT8). Pure.

Hand-made cases for the three base conventions (PE, ELF non-PIE, ELF PIE rebased by Ghidra):
they prove the arithmetic and the interval search, not what the engines report; the real
capa + real Ghidra check on the `injector` and `elf_net` builds is phase 12's.
"""

import uuid

import pytest

from app.modules.reverse_engineering.join import (
    ADDRESS_LIMIT,
    BodyIndex,
    SourceCapability,
    capa_file_va,
    capa_file_vas,
    join,
    parse_locations,
)

CAP_A = uuid.UUID(int=1)
CAP_B = uuid.UUID(int=2)


def _index(*functions: tuple[int, list[tuple[int, int]]]) -> BodyIndex:
    """(entry, [(start RVA, end RVA), ...]) per function."""
    return BodyIndex((start, end, entry) for entry, body in functions for start, end in body)


def test_pe_capa_and_ghidra_agree_on_the_image_base() -> None:
    """PE: both engines load at ImageBase; file VA = VA."""
    base = 0x140000000
    index = _index((base + 0x11E0, [(0x11E0, 0x1320)]), (base + 0x1320, [(0x1320, 0x1440)]))
    caps = [
        SourceCapability(CAP_A, (base + 0x1280, base + 0x12A0)),
        SourceCapability(CAP_B, (base + 0x1400, base + 0x9000)),
    ]
    result = join(caps, capa_base=base, preferred_base=base, index=index)
    assert [(link.capability_id, link.function_entry, link.file_va) for link in result.links] == [
        (CAP_A, base + 0x11E0, base + 0x1280),  # two locations, one link (the lowest)
        (CAP_B, base + 0x1320, base + 0x1400),
    ]
    assert (result.linked, result.unlocated, result.capabilities) == (3, 1, 2)


def test_elf_non_pie_uses_the_lowest_pt_load() -> None:
    """ELF EXEC: the file's own base is the lowest PT_LOAD (0x400000); a capa base reported
    as that same address gives file VA = location."""
    preferred = 0x400000
    index = _index((0x401100, [(0x1100, 0x1180)]))
    caps = [SourceCapability(CAP_A, (0x401120,))]
    result = join(caps, capa_base=0x400000, preferred_base=preferred, index=index)
    assert [(link.function_entry, link.file_va) for link in result.links] == [(0x401100, 0x401120)]


def test_elf_pie_rebased_by_both_engines_still_links() -> None:
    """ELF DYN: the file says base 0; Ghidra rebases to 0x100000 (its entries are
    0x100000 + RVA) and capa to its own base (here 0x200000): both normalize to file VAs."""
    ghidra_base, capa_base, preferred = 0x100000, 0x200000, 0
    entry = ghidra_base + 0x1140
    index = _index((entry, [(0x1140, 0x11C0)]))
    caps = [SourceCapability(CAP_A, (capa_base + 0x1150, capa_base + 0x11C0))]
    result = join(caps, capa_base=capa_base, preferred_base=preferred, index=index)
    assert [(link.function_entry, link.file_va) for link in result.links] == [(entry, 0x1150)]
    assert (result.linked, result.unlocated) == (1, 1)  # 0x11c0 is the (exclusive) end


def test_overlapping_and_split_bodies() -> None:
    """A location in two overlapping functions links to both; a split body (two chunks)
    contains addresses in either chunk only."""
    index = _index(
        (0x1000, [(0x1000, 0x1100), (0x3000, 0x3040)]),
        (0x1080, [(0x1080, 0x1200)]),
        (0x5000, [(0x5000, 0x5010)]),
    )
    assert index.containing(0x1090) == [0x1000, 0x1080]
    assert index.containing(0x3020) == [0x1000]
    assert index.containing(0x2000) == []
    assert index.containing(0x1200) == []  # half-open
    assert index.containing(0x0) == [] and len(index) == 4
    caps = [SourceCapability(CAP_A, (0x1090, 0x3020, 0x2000))]
    result = join(caps, capa_base=0, preferred_base=0, index=index)
    assert {(link.function_entry, link.file_va) for link in result.links} == {
        (0x1000, 0x1090),
        (0x1080, 0x1090),
    }
    assert (result.linked, result.unlocated) == (2, 1)


def test_a_long_body_shadowing_later_ranges_is_still_found() -> None:
    """The running maximum end keeps a long early range reachable behind many short ones."""
    functions = [(0x10, [(0x10, 0x10000)])] + [(a, [(a, a + 8)]) for a in range(0x100, 0x900, 16)]
    index = _index(*functions)
    assert index.containing(0x8F8) == [0x10]
    assert index.containing(0x104) == [0x10, 0x100]


def test_nothing_links_without_a_capa_base_or_outside_64_bits() -> None:
    index = _index((0x1000, [(0x1000, 0x2000)]))
    caps = [SourceCapability(CAP_A, (0x1100,))]
    result = join(caps, capa_base=None, preferred_base=0, index=index)
    assert (result.links, result.linked, result.unlocated) == ((), 0, 1)
    low = join(caps, capa_base=0x2000, preferred_base=0, index=index)  # 0x1100 - 0x2000 < 0
    assert (low.linked, low.unlocated) == (0, 1)
    empty = join([], capa_base=0, preferred_base=0, index=BodyIndex([]))
    assert (empty.links, empty.linked, empty.unlocated, empty.capabilities) == ((), 0, 0, 0)


def test_capa_file_vas_for_the_job_message() -> None:
    assert capa_file_va(0x140001280, 0x140000000, 0x140000000) == 0x140001280
    assert capa_file_va(0x201150, 0x200000, 0) == 0x1150
    assert capa_file_va(0x10, 0x20, 0) is None
    assert capa_file_va(ADDRESS_LIMIT - 1, 0, 1) is None
    assert capa_file_vas([0x30, 0x10, 0x30, 0x5], 0x8, 0) == [0x8, 0x28]
    assert capa_file_vas([0x10], None, 0) == []
    assert capa_file_vas(range(1000), 0, 0, limit=512) == list(range(512))


@pytest.mark.parametrize(
    ("stored", "parsed"),
    [
        (["5368713856", "5368713888"], [5368713856, 5368713888]),
        (["18446744073709551615"], [2**64 - 1]),
        (["18446744073709551616", "-1", "0x10", 7, None, "１２"], []),
        ("nope", []),
        (None, []),
    ],
)
def test_stored_locations_are_parsed_defensively(stored: object, parsed: list[int]) -> None:
    assert parse_locations(stored) == parsed
