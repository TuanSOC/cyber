"""Stage rows -> validated `re.v1` records (root side, pure Python; M10 phases 2 and 3).

The `analyze` stage (Ghidra) and the radare2 reducer emit the same row shapes, one JSON
object per line:

    {"kind": "program_facts", ...}   once (`ProgramFacts`)
    {"kind": "function", ...}        `ReFunctionRecord` fields (callers / callees /
                                     priority_rank are root's, any value is replaced)
    {"kind": "call_edge" | "import" | "import_ref" | "string" | "string_ref", ...}

Every row is validated alone against the contract model (per-record error isolation: a
hostile line is counted, never fatal). Then the cross-record rules the ingest will check are
made true here, so the stream can never be refused for them: one record per key, references
only to kept functions / imports / strings, `rva = entry - image_base`, caller / callee
counts recomputed from the kept edges, and root's caps (`ReLimits`) applied whatever the
probe claims (`capped`). Program facts the root knows better (format, arch, bits, the file's
preferred base, sha256, size) come from root's magic check and the job, never the probe.
"""

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

from cyberlab_jobs.base import Strict
from cyberlab_jobs.results import Text64
from cyberlab_jobs.reverse import (
    Address,
    AnalysisStatus,
    ReCallEdgeRecord,
    ReFunctionRecord,
    ReImportRecord,
    ReImportRefRecord,
    ReLimits,
    ReProgramRecord,
    ReStringRecord,
    ReStringRefRecord,
    Text32,
)
from pydantic import BaseModel, ValidationError

from re_worker.engines.magic import SampleFacts

KINDS = ("function", "call_edge", "import", "import_ref", "string", "string_ref")
ROOT_FIELDS = ("callers", "callees", "priority_rank")


class ProgramFacts(Strict):
    """What only the engine knows about the loaded program."""

    kind: Literal["program_facts"] = "program_facts"
    language_id: Text64 | None = None
    compiler_spec: Text32 | None = None
    image_base: Address
    entry: Address | None = None
    analysis_status: AnalysisStatus = "complete"


MODELS: dict[str, type[BaseModel]] = {
    "program_facts": ProgramFacts,
    "function": ReFunctionRecord,
    "call_edge": ReCallEdgeRecord,
    "import": ReImportRecord,
    "import_ref": ReImportRefRecord,
    "string": ReStringRecord,
    "string_ref": ReStringRefRecord,
}


@dataclass
class Analysis:
    facts: ProgramFacts | None = None
    functions: list[ReFunctionRecord] = field(default_factory=list)
    edges: list[ReCallEdgeRecord] = field(default_factory=list)
    imports: list[ReImportRecord] = field(default_factory=list)
    import_refs: list[ReImportRefRecord] = field(default_factory=list)
    strings: list[ReStringRecord] = field(default_factory=list)
    string_refs: list[ReStringRefRecord] = field(default_factory=list)
    invalid: Counter[str] = field(default_factory=Counter)  # rows refused by the contract
    dropped: Counter[str] = field(default_factory=Counter)  # duplicates, dangling refs, rva
    capped: set[str] = field(default_factory=set)  # kinds root cut at its cap

    def counts(self) -> dict[str, int]:
        return {
            "functions": len(self.functions),
            "call_edges": len(self.edges),
            "imports": len(self.imports),
            "import_refs": len(self.import_refs),
            "strings": len(self.strings),
            "string_refs": len(self.string_refs),
        }


def caps(limits: ReLimits) -> dict[str, int]:
    """Root's per-kind caps (also passed to the probe, which stops at the same values)."""
    return {
        "function": limits.max_functions,
        "call_edge": limits.max_call_edges,
        "import": limits.max_imports,
        "import_ref": limits.max_import_refs,
        "string": limits.max_strings,
        "string_ref": limits.max_string_refs,
    }


def probe_caps(limits: ReLimits) -> dict[str, int]:
    """The caps as probe flags (`--max-functions N`, ...)."""
    names = {
        "function": "functions",
        "call_edge": "call-edges",
        "import": "imports",
        "import_ref": "import-refs",
        "string": "strings",
        "string_ref": "string-refs",
    }
    return {names[kind]: n for kind, n in caps(limits).items()}


def max_rows(limits: ReLimits) -> int:
    """Rows root reads from one stage at most: every cap plus the facts and a margin for
    invalid lines (each counted, none kept)."""
    return sum(caps(limits).values()) + 1 + 10_000


def _validate(kind: str, row: dict[str, Any], analysis: Analysis) -> BaseModel | None:
    model = MODELS.get(kind)
    if model is None:
        analysis.invalid["unknown_kind"] += 1
        return None
    if kind == "function":
        row = {k: v for k, v in row.items() if k not in ROOT_FIELDS}
    try:
        return model.model_validate(row)
    except (ValidationError, ValueError, TypeError):
        analysis.invalid[kind] += 1
        return None


def _collect(rows: Iterable[dict[str, Any]], limits: ReLimits, analysis: Analysis) -> None:
    cap = caps(limits)
    raw: dict[str, list[BaseModel]] = defaultdict(list)
    for row in rows:
        kind = row.get("kind")
        if not isinstance(kind, str):
            analysis.invalid["unknown_kind"] += 1
            continue
        record = _validate(kind, row, analysis)
        if record is None:
            continue
        if isinstance(record, ProgramFacts):
            if analysis.facts is None:
                analysis.facts = record
            else:
                analysis.dropped["program_facts"] += 1
            continue
        if len(raw[kind]) >= cap[kind]:
            analysis.capped.add(kind)
            continue
        raw[kind].append(record)
    _resolve(raw, analysis)


def _resolve(raw: dict[str, list[BaseModel]], analysis: Analysis) -> None:
    if analysis.facts is None:
        return
    base = analysis.facts.image_base
    functions: dict[int, ReFunctionRecord] = {}
    for f in raw["function"]:
        assert isinstance(f, ReFunctionRecord)  # noqa: S101 - _validate's model
        if f.entry in functions or f.entry < base:
            analysis.dropped["function"] += 1
            continue
        functions[f.entry] = f.model_copy(update={"rva": f.entry - base})

    edges: dict[tuple[int, int], ReCallEdgeRecord] = {}
    for e in raw["call_edge"]:
        assert isinstance(e, ReCallEdgeRecord)  # noqa: S101
        key = (e.caller, e.callee)
        if e.caller not in functions or e.callee not in functions or key in edges:
            analysis.dropped["call_edge"] += 1
            continue
        edges[key] = e

    imports: dict[int, ReImportRecord] = {}
    for i in raw["import"]:
        assert isinstance(i, ReImportRecord)  # noqa: S101
        if i.index in imports:
            analysis.dropped["import"] += 1
            continue
        imports[i.index] = i

    import_refs: dict[tuple[int, int], ReImportRefRecord] = {}
    for r in raw["import_ref"]:
        assert isinstance(r, ReImportRefRecord)  # noqa: S101
        key = (r.import_index, r.function_entry)
        known = r.import_index in imports and r.function_entry in functions
        if not known or key in import_refs:
            analysis.dropped["import_ref"] += 1
            continue
        import_refs[key] = r

    strings: dict[int, ReStringRecord] = {}
    for s in raw["string"]:
        assert isinstance(s, ReStringRecord)  # noqa: S101
        if s.index in strings:
            analysis.dropped["string"] += 1
            continue
        strings[s.index] = s

    string_refs: dict[tuple[int, int], ReStringRefRecord] = {}
    for sr in raw["string_ref"]:
        assert isinstance(sr, ReStringRefRecord)  # noqa: S101
        key = (sr.string_index, sr.function_entry)
        known = sr.string_index in strings and sr.function_entry in functions
        if not known or key in string_refs:
            analysis.dropped["string_ref"] += 1
            continue
        string_refs[key] = sr

    callers: Counter[int] = Counter()
    callees: Counter[int] = Counter()
    for caller, callee in edges:
        callees[caller] += 1
        callers[callee] += 1
    analysis.functions = [
        f.model_copy(update={"callers": callers[f.entry], "callees": callees[f.entry]})
        for f in sorted(functions.values(), key=lambda f: f.entry)
    ]
    analysis.edges = [edges[k] for k in sorted(edges)]
    analysis.imports = [imports[k] for k in sorted(imports)]
    analysis.import_refs = [import_refs[k] for k in sorted(import_refs)]
    analysis.strings = [strings[k] for k in sorted(strings)]
    analysis.string_refs = [string_refs[k] for k in sorted(string_refs)]


def normalize_analysis(rows: Iterable[dict[str, Any]], limits: ReLimits) -> Analysis:
    analysis = Analysis()
    _collect(rows, limits, analysis)
    return analysis


def program_record(
    sample: SampleFacts,
    facts: ProgramFacts,
    *,
    sha256: str,
    size_bytes: int,
    analysis_status: AnalysisStatus,
    counts: dict[str, int],
) -> ReProgramRecord:
    """The program line: root's facts from the magic check and the job, the engine's facts
    about the loaded program. An entry the engine reports below its image base is dropped."""
    entry = facts.entry if facts.entry is not None and facts.entry >= facts.image_base else None
    return ReProgramRecord(
        format=sample.format,
        arch=sample.arch,
        machine=sample.machine[:64],
        bits=sample.bits,
        endianness=sample.endianness,
        language_id=facts.language_id,
        compiler_spec=facts.compiler_spec,
        image_base=facts.image_base,
        preferred_base=sample.preferred_base,
        entry=entry,
        sha256=sha256,
        size_bytes=size_bytes,
        analysis_status=analysis_status,
        counts=dict(list(counts.items())[:32]),
    )


def diagnostic_program(sample: SampleFacts, *, sha256: str, size_bytes: int) -> ReProgramRecord:
    """The program line of a diagnostic stream: nothing was loaded (`not_run`)."""
    return ReProgramRecord(
        format=sample.format,
        arch=sample.arch,
        machine=sample.machine[:64],
        bits=sample.bits,
        endianness=sample.endianness,
        image_base=sample.preferred_base,
        preferred_base=sample.preferred_base,
        sha256=sha256,
        size_bytes=size_bytes,
        analysis_status="not_run",
    )


__all__ = [
    "KINDS",
    "MODELS",
    "Analysis",
    "ProgramFacts",
    "caps",
    "diagnostic_program",
    "max_rows",
    "normalize_analysis",
    "probe_caps",
    "program_record",
]
