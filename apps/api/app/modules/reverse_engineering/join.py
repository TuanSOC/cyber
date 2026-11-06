"""Link capa capabilities to RE functions on file virtual addresses (M10 phase 7, RT8). Pure.

capa (vivisect) and Ghidra may load the same file at different bases (Ghidra rebases an ELF
PIE, e.g. to 0x100000; vivisect has its own conventions), so neither side's virtual
addresses are compared directly. Both are normalized to **file virtual addresses**, the
addresses the file itself declares, with `preferred_base` = the file's own base (PE
`ImageBase`; ELF lowest `PT_LOAD` `p_vaddr`, page-aligned):

    capa:   file_va = location - (capa_base - preferred_base)
    Ghidra: file_va = va - (image_base - preferred_base)   (a body RVA r: preferred_base + r)

A capability links to every function whose body ranges (half-open RVA ranges) contain one
of its locations; a location no body contains is counted as unlocated. Several locations of
one capability inside one function give one link (the lowest file VA).
"""

import bisect
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

ADDRESS_LIMIT = 2**64
MAX_CAPA_FILE_VAS = 512  # = re.v1 MAX_CAPA_FILE_VAS (the job message's hint list)


def capa_file_va(location: int, capa_base: int, preferred_base: int) -> int | None:
    """A capa location as a file virtual address, or None when it falls outside 64 bits."""
    value = location - (capa_base - preferred_base)
    return value if 0 <= value < ADDRESS_LIMIT else None


def capa_file_vas(
    locations: Iterable[int],
    capa_base: int | None,
    preferred_base: int,
    *,
    limit: int = MAX_CAPA_FILE_VAS,
) -> list[int]:
    """Every location as a file VA (sorted, unique, the lowest `limit`); none without a base
    (a static job from before M10, or capa reported none)."""
    if capa_base is None:
        return []
    found = {
        va for loc in locations if (va := capa_file_va(loc, capa_base, preferred_base)) is not None
    }
    return sorted(found)[:limit]


def parse_locations(value: object) -> list[int]:
    """`malware_capabilities.locations` (decimal strings, checked by 0018) as integers; an
    unexpected element is skipped, never trusted."""
    if not isinstance(value, list):
        return []
    out = []
    for item in value:
        if isinstance(item, str) and item.isascii() and item.isdigit() and len(item) <= 20:
            number = int(item)
            if number < ADDRESS_LIMIT:
                out.append(number)
    return out


class BodyIndex:
    """Interval lookup over the functions' body ranges (RVAs), built in O(n log n): the ranges
    sorted by start, with the running maximum end, so a query walks back only over ranges
    that can still contain the address."""

    def __init__(self, ranges: Iterable[tuple[int, int, int]]) -> None:
        """`ranges`: (start RVA, end RVA, function entry), half-open, start < end."""
        ordered = sorted(r for r in ranges if r[0] < r[1])
        self._starts = [r[0] for r in ordered]
        self._ranges = ordered
        self._max_end: list[int] = []
        top = -1
        for _, end, _ in ordered:
            top = max(top, end)
            self._max_end.append(top)

    def __len__(self) -> int:
        return len(self._ranges)

    def containing(self, rva: int) -> list[int]:
        """Entries of every function whose body contains `rva` (sorted, unique)."""
        found: set[int] = set()
        i = bisect.bisect_right(self._starts, rva) - 1
        while i >= 0 and self._max_end[i] > rva:
            start, end, entry = self._ranges[i]
            if start <= rva < end:
                found.add(entry)
            i -= 1
        return sorted(found)


@dataclass(frozen=True)
class SourceCapability:
    """A capability of the source static job and its capa locations."""

    id: uuid.UUID
    locations: tuple[int, ...]


@dataclass(frozen=True)
class Link:
    capability_id: uuid.UUID
    function_entry: int
    file_va: int


@dataclass(frozen=True)
class JoinResult:
    links: tuple[Link, ...]
    linked: int  # locations inside at least one function body
    unlocated: int  # locations no body contains (or outside 64 bits, or no capa base)

    @property
    def capabilities(self) -> int:
        return len({link.capability_id for link in self.links})


def join(
    capabilities: Sequence[SourceCapability],
    *,
    capa_base: int | None,
    preferred_base: int,
    index: BodyIndex,
) -> JoinResult:
    """The capability -> function links of one RE job (see the module docstring)."""
    links: dict[tuple[uuid.UUID, int], int] = {}
    linked = unlocated = 0
    for capability in capabilities:
        for location in capability.locations:
            file_va = (
                None if capa_base is None else capa_file_va(location, capa_base, preferred_base)
            )
            rva = None if file_va is None else file_va - preferred_base
            entries = index.containing(rva) if rva is not None and rva >= 0 else []
            if not entries or file_va is None:
                unlocated += 1
                continue
            linked += 1
            for entry in entries:
                key = (capability.id, entry)
                links[key] = min(links.get(key, file_va), file_va)
    ordered = sorted(links.items(), key=lambda kv: (str(kv[0][0]), kv[0][1]))
    return JoinResult(
        links=tuple(Link(cap_id, entry, file_va) for (cap_id, entry), file_va in ordered),
        linked=linked,
        unlocated=unlocated,
    )
