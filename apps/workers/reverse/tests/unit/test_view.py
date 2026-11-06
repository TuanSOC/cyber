"""`ReView` (M10 phase 1, implemented): adjacency, import / string links and the body-range
lookups by RVA, VA and file virtual address (RT8), over the frozen contract fixtures."""

from pathlib import Path
from typing import Any

from cyberlab_jobs.reverse import (
    RE_LINE_ADAPTER,
    BodyRange,
    ReCallEdgeRecord,
    ReDecompiledRecord,
    ReFunctionRecord,
    ReImportRecord,
    ReImportRefRecord,
    ReProgramRecord,
    ReStringRecord,
    ReStringRefRecord,
)

from re_worker.view import ReView
from tests.conftest import CONTRACT_FIXTURES


def _view(path: Path) -> ReView:
    lines = [RE_LINE_ADAPTER.validate_json(raw) for raw in path.read_bytes().splitlines()]

    def of(kind: type[Any]) -> list[Any]:
        return [line for line in lines if isinstance(line, kind)]

    (program,) = of(ReProgramRecord)
    return ReView.build(
        program,
        of(ReFunctionRecord),
        of(ReCallEdgeRecord),
        of(ReImportRecord),
        of(ReImportRefRecord),
        of(ReStringRecord),
        of(ReStringRefRecord),
        of(ReDecompiledRecord),
    )


def _entry(view: ReView, name: str) -> int:
    return next(e for e, f in view.functions.items() if f.name == name)


def test_pe_adjacency_and_links() -> None:
    view = _view(CONTRACT_FIXTURES / "pe_full.ndjson")
    main = _entry(view, "main")
    inject = _entry(view, "inject_remote")
    assert inject in view.callees(main) and main in view.callers(inject)
    decode = _entry(view, "decode_config")
    assert decode in view.callees(decode)  # recursion
    assert view.import_names_called(inject) == {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    }
    assert "#4" in view.import_names_called(_entry(view, "beacon"))
    resolve = _entry(view, "resolve_apis")
    values = {view.strings[i].value for i in view.strings_referenced(resolve)}
    assert {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"} <= values
    url = next(i for i, s in view.strings.items() if s.value.startswith("http://"))
    assert view.string_referrers(url) == (_entry(view, "beacon"),)
    assert view.callers(0) == () and view.callees(0) == ()
    assert len(view.decompiled) == 6


def test_body_lookup_by_rva_va_and_file_va() -> None:
    view = _view(CONTRACT_FIXTURES / "pe_full.ndjson")
    inject = _entry(view, "inject_remote")
    rva = view.functions[inject].rva
    assert view.functions_at_rva(rva) == (inject,)
    assert view.functions_at_rva(rva + 0x10) == (inject,)
    assert view.functions_at_va(inject + 4) == (inject,)
    # PE: the file's base is the engine's base, so a file VA is the VA.
    assert view.functions_at_file_va(inject) == (inject,)
    assert view.functions_at_rva(0) == ()


def test_elf_pie_file_va_join() -> None:
    """RT8: Ghidra rebased the PIE to 0x100000, the file's own base is 0."""
    view = _view(CONTRACT_FIXTURES / "elf_full.ndjson")
    main = _entry(view, "main")
    file_va = view.program.to_file_va(main)
    assert file_va == main - 0x100000
    assert view.functions_at_file_va(file_va + 8) == (main,)
    assert view.functions_at_file_va(main) == ()  # an engine VA is not a file VA


def test_overlapping_bodies_return_every_owner() -> None:
    program = ReProgramRecord(
        format="pe",
        arch="x86",
        bits=32,
        endianness="little",
        image_base=0x400000,
        preferred_base=0x400000,
        sha256="e" * 64,
        size_bytes=1,
        analysis_status="complete",
    )

    def fn(entry: int, *ranges: tuple[int, int]) -> ReFunctionRecord:
        return ReFunctionRecord(
            entry=entry,
            rva=entry - 0x400000,
            name=f"f{entry:x}",
            name_source="generated",
            size=0x100,
            body=[BodyRange(start=a, end=b) for a, b in ranges],
        )

    a = fn(0x401000, (0x1000, 0x1100), (0x3000, 0x3010))  # a shared chunk far away
    b = fn(0x402000, (0x2000, 0x2100), (0x3000, 0x3010))
    c = fn(0x401050, (0x1050, 0x1060))  # nested in a
    view = ReView.build(program, [a, b, c])
    assert view.functions_at_rva(0x3008) == (0x401000, 0x402000)
    assert view.functions_at_rva(0x1055) == (0x401000, 0x401050)
    assert view.functions_at_rva(0x1100) == ()  # half-open
    assert view.functions_at_rva(0x2050) == (0x402000,)
