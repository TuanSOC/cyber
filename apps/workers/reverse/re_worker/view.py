"""`ReView`: the immutable in-memory view of one program's validated records (M10 phase 1,
IMPLEMENTED and FROZEN; consumed by phase 2's pipeline, phase 3's radare2 engine and phase 5's
priority and detections).

Built once in O(n log n) from records that already passed the `re.v1` contract and
`StreamChecker` (so every reference names a known function, import or string):
- functions by entry; body-range interval lookup by RVA and by file virtual address (RT8:
  `file_va = va - (image_base - preferred_base)`, so `rva = file_va - preferred_base`);
- callers / callees adjacency (entry -> sorted entries) with call-site counts;
- imports -> calling functions and functions -> imports called;
- strings -> referencing functions and functions -> strings referenced.
Lookups return sorted tuples (deterministic: phase 5's priority and findings depend on it).

`DetectionOutput` is what `detections.run(view, limits)` returns.
"""

import bisect
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from cyberlab_jobs.results import FindingRecord, IocRecord
from cyberlab_jobs.reverse import (
    ReCallEdgeRecord,
    ReDecompiledRecord,
    ReFunctionRecord,
    ReImportRecord,
    ReImportRefRecord,
    ReProgramRecord,
    ReStringRecord,
    ReStringRefRecord,
)


def _freeze(source: Mapping[int, set[int]]) -> Mapping[int, tuple[int, ...]]:
    return MappingProxyType({key: tuple(sorted(values)) for key, values in source.items()})


@dataclass(frozen=True)
class ReView:
    program: ReProgramRecord
    functions: Mapping[int, ReFunctionRecord]
    imports: Mapping[int, ReImportRecord]
    strings: Mapping[int, ReStringRecord]
    decompiled: Mapping[int, ReDecompiledRecord]
    edge_sites: Mapping[tuple[int, int], int]
    _callers: Mapping[int, tuple[int, ...]]
    _callees: Mapping[int, tuple[int, ...]]
    _import_callers: Mapping[int, tuple[int, ...]]
    _imports_called: Mapping[int, tuple[int, ...]]
    _string_referrers: Mapping[int, tuple[int, ...]]
    _strings_referenced: Mapping[int, tuple[int, ...]]
    # Body ranges sorted by start: (start, end, entry), plus the running maximum of `end`.
    _starts: tuple[int, ...]
    _ranges: tuple[tuple[int, int, int], ...]
    _max_end: tuple[int, ...]

    @classmethod
    def build(
        cls,
        program: ReProgramRecord,
        functions: Iterable[ReFunctionRecord],
        edges: Iterable[ReCallEdgeRecord] = (),
        imports: Iterable[ReImportRecord] = (),
        import_refs: Iterable[ReImportRefRecord] = (),
        strings: Iterable[ReStringRecord] = (),
        string_refs: Iterable[ReStringRefRecord] = (),
        decompiled: Iterable[ReDecompiledRecord] = (),
    ) -> "ReView":
        by_entry = {f.entry: f for f in functions}
        callers: dict[int, set[int]] = defaultdict(set)
        callees: dict[int, set[int]] = defaultdict(set)
        sites: dict[tuple[int, int], int] = {}
        for edge in edges:
            callees[edge.caller].add(edge.callee)
            callers[edge.callee].add(edge.caller)
            sites[(edge.caller, edge.callee)] = edge.sites
        import_callers: dict[int, set[int]] = defaultdict(set)
        imports_called: dict[int, set[int]] = defaultdict(set)
        for ref in import_refs:
            import_callers[ref.import_index].add(ref.function_entry)
            imports_called[ref.function_entry].add(ref.import_index)
        referrers: dict[int, set[int]] = defaultdict(set)
        referenced: dict[int, set[int]] = defaultdict(set)
        for sref in string_refs:
            referrers[sref.string_index].add(sref.function_entry)
            referenced[sref.function_entry].add(sref.string_index)
        ranges = sorted((r.start, r.end, f.entry) for f in by_entry.values() for r in f.body)
        max_end: list[int] = []
        running = -1
        for _, end, _ in ranges:
            running = max(running, end)
            max_end.append(running)
        return cls(
            program=program,
            functions=MappingProxyType(dict(sorted(by_entry.items()))),
            imports=MappingProxyType({i.index: i for i in sorted(imports, key=lambda i: i.index)}),
            strings=MappingProxyType({s.index: s for s in sorted(strings, key=lambda s: s.index)}),
            decompiled=MappingProxyType({d.function_entry: d for d in decompiled}),
            edge_sites=MappingProxyType(sites),
            _callers=_freeze(callers),
            _callees=_freeze(callees),
            _import_callers=_freeze(import_callers),
            _imports_called=_freeze(imports_called),
            _string_referrers=_freeze(referrers),
            _strings_referenced=_freeze(referenced),
            _starts=tuple(r[0] for r in ranges),
            _ranges=tuple(ranges),
            _max_end=tuple(max_end),
        )

    # --- graph ----------------------------------------------------------------------------

    def callers(self, entry: int) -> tuple[int, ...]:
        return self._callers.get(entry, ())

    def callees(self, entry: int) -> tuple[int, ...]:
        return self._callees.get(entry, ())

    def import_callers(self, import_index: int) -> tuple[int, ...]:
        return self._import_callers.get(import_index, ())

    def imports_called(self, entry: int) -> tuple[int, ...]:
        return self._imports_called.get(entry, ())

    def string_referrers(self, string_index: int) -> tuple[int, ...]:
        return self._string_referrers.get(string_index, ())

    def strings_referenced(self, entry: int) -> tuple[int, ...]:
        return self._strings_referenced.get(entry, ())

    def import_names_called(self, entry: int) -> frozenset[str]:
        """Names of the imports a function calls (ordinal-only imports are `#<n>`)."""
        names = set()
        for index in self.imports_called(entry):
            imp = self.imports[index]
            names.add(imp.name if imp.name is not None else f"#{imp.ordinal}")
        return frozenset(names)

    # --- addresses ------------------------------------------------------------------------

    def functions_at_rva(self, rva: int) -> tuple[int, ...]:
        """Entries of every function whose body contains `rva` (overlapping chunks happen)."""
        found: set[int] = set()
        i = bisect.bisect_right(self._starts, rva) - 1
        while i >= 0 and self._max_end[i] > rva:
            start, end, entry = self._ranges[i]
            if start <= rva < end:
                found.add(entry)
            i -= 1
        return tuple(sorted(found))

    def functions_at_va(self, va: int) -> tuple[int, ...]:
        return self.functions_at_rva(va - self.program.image_base)

    def functions_at_file_va(self, file_va: int) -> tuple[int, ...]:
        """RT8: capa locations arrive as file virtual addresses."""
        return self.functions_at_rva(file_va - self.program.preferred_base)


@dataclass
class DetectionOutput:
    """Phase 5's `detections.run(view, limits)` result (findings cite their function in
    `attributes.function_entry`; IOCs come only from strings referenced by code)."""

    findings: list[FindingRecord] = field(default_factory=list)
    iocs: list[IocRecord] = field(default_factory=list)
    truncated: bool = False
