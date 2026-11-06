"""Stage rows -> `re.v1` records and the whole stream (pure Python): the fixture rows of the
`analyze` stage normalize into records the contract's own `StreamChecker` accepts; root
recomputes rva / callers / callees and drops what the ingest would refuse."""

import gzip
import json
from pathlib import Path
from typing import Any

from cyberlab_jobs.reverse import (
    RE_LINE_ADAPTER,
    CodeKind,
    ReEngine,
    validate_stream,
)

from re_worker.engines import EngineOutput
from re_worker.engines.magic import inspect_bytes
from re_worker.normalize.decompiled import normalize_decompiled
from re_worker.normalize.records import (
    diagnostic_program,
    max_rows,
    normalize_analysis,
    probe_caps,
    program_record,
)
from re_worker.result import engine_for, write_diagnostic, write_result
from re_worker.view import DetectionOutput
from tests.stage_helpers import LIMITS, SHA, decompiled_entries, elf_header, job, pe_header, rows


def _analysis(case: str = "pe_full"):  # type: ignore[no-untyped-def]
    return normalize_analysis(rows(case, "analyze"), LIMITS)


def test_pe_rows_normalize_completely() -> None:
    analysis = _analysis()
    assert analysis.facts is not None and analysis.facts.image_base == 0x140000000
    assert analysis.counts() == {
        "functions": 31,
        "call_edges": 17,
        "imports": 8,
        "import_refs": 8,
        "strings": 7,
        "string_refs": 7,
    }
    assert not analysis.invalid and not analysis.dropped and not analysis.capped
    main = next(f for f in analysis.functions if f.name == "main")
    assert (main.callers, main.callees, main.priority_rank) == (1, 6, None)
    assert all(f.rva == f.entry - 0x140000000 for f in analysis.functions)


def test_probe_values_root_owns_are_replaced() -> None:
    lines = rows("pe_full", "analyze")
    for line in lines:
        if line["kind"] == "function":
            line["callers"], line["callees"], line["priority_rank"] = 999, 999, 7
            line["rva"] = 12345
    analysis = normalize_analysis(lines, LIMITS)
    assert not analysis.invalid
    assert all(f.priority_rank is None for f in analysis.functions)
    assert max(f.callers for f in analysis.functions) < 999
    assert analysis.facts is not None
    base = analysis.facts.image_base
    assert all(f.rva == f.entry - base for f in analysis.functions)


def test_caps_cut_and_dangling_references_drop() -> None:
    limits = LIMITS.model_copy(update={"max_functions": 5, "max_strings": 2})
    analysis = normalize_analysis(rows("pe_full", "analyze"), limits)
    assert len(analysis.functions) == 5 and {"function", "string"} <= analysis.capped
    kept = {f.entry for f in analysis.functions}
    assert all(e.caller in kept and e.callee in kept for e in analysis.edges)
    assert all(r.function_entry in kept for r in analysis.import_refs)
    assert len(analysis.strings) == 2
    assert all(r.string_index in {s.index for s in analysis.strings} for r in analysis.string_refs)
    assert analysis.dropped["call_edge"] > 0


def test_no_program_facts_means_nothing_usable() -> None:
    lines = [r for r in rows("pe_full", "analyze") if r["kind"] != "program_facts"]
    analysis = normalize_analysis(lines, LIMITS)
    assert analysis.facts is None and analysis.functions == []


def test_probe_flags_and_row_bound() -> None:
    assert probe_caps(LIMITS)["call-edges"] == LIMITS.max_call_edges
    assert max_rows(LIMITS) > sum(probe_caps(LIMITS).values())


def _output(case: str, fmt: str, header: bytes):  # type: ignore[no-untyped-def]
    analysis = _analysis(case)
    sample = inspect_bytes(header)
    assert analysis.facts is not None
    program = program_record(
        sample,
        analysis.facts,
        sha256=SHA,
        size_bytes=1024,
        analysis_status="complete",
        counts=analysis.counts(),
    )
    listed = list(decompiled_entries(case))
    found = normalize_decompiled(
        rows(case, "decompile"), listed, LIMITS, CodeKind.PSEUDO_C, out_of_time=False
    )
    return EngineOutput(
        program=program,
        functions=analysis.functions,
        edges=analysis.edges,
        imports=analysis.imports,
        import_refs=analysis.import_refs,
        strings=analysis.strings,
        string_refs=analysis.string_refs,
        decompiled=found.records,
        tool_versions={"replay": "hand-written"},
    ), listed


def _read(path: Path) -> list[object]:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [RE_LINE_ADAPTER.validate_python(json.loads(line)) for line in f]


def test_the_written_stream_passes_the_contract(tmp_path: Path) -> None:
    for case, fmt, header in (("pe_full", "pe", pe_header()), ("elf_full", "elf", elf_header())):
        output, listed = _output(case, fmt, header)
        the_job = job(file_format=fmt, decompile=tuple(listed))
        engine, kind = engine_for(the_job.profile, "replay")
        path = write_result(
            tmp_path / f"{case}.ndjson.gz", the_job, engine, kind, output, DetectionOutput()
        )
        lines = _read(path)
        validate_stream(lines, job_id=the_job.job_id, limits=LIMITS)  # type: ignore[arg-type]
        assert lines[0].engine == ReEngine.REPLAY  # type: ignore[attr-defined]
        assert sum(1 for line in lines if getattr(line, "kind", "") == "decompiled") == len(listed)


def test_diagnostic_stream(tmp_path: Path) -> None:
    sample = inspect_bytes(pe_header(machine=0xAA64))
    the_job = job()
    program = diagnostic_program(sample, sha256=SHA, size_bytes=1024)
    path = write_diagnostic(tmp_path / "d.ndjson.gz", the_job, program, tool_versions={"g": "1"})
    lines = _read(path)
    assert [getattr(line, "kind", "") for line in lines] == ["header", "program", "trailer"]
    validate_stream(lines, job_id=the_job.job_id, diagnostic=True)  # type: ignore[arg-type]
    program: Any = lines[1]
    assert program.arch == "other" and program.analysis_status == "not_run"
    assert lines[0].engine == ReEngine.GHIDRA  # type: ignore[attr-defined]
