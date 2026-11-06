"""The radare2 reducer (pure Python; RT9): bounded split at the marker lines, strict JSON per
section, and the rows it writes normalize into the same records as the Ghidra stage."""

import io
import json
from typing import Any

from re_worker.normalize.records import normalize_analysis
from re_worker.probe.out import RowWriter
from re_worker.probe.r2 import import_key, name_source, parse, reduce, split
from tests.stage_helpers import LIMITS, STAGE_ROWS

PE_OUT = STAGE_ROWS / "r2" / "pe.r2.out"
KINDS = ("function", "call_edge", "import", "import_ref", "string", "string_ref")
CAPS = dict.fromkeys(KINDS, 100)


def _reduce(
    data: bytes, caps: dict[str, int] = CAPS
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    stream = io.StringIO()
    status: dict[str, Any] = {}
    writer = RowWriter(stream, caps)
    reduce(split(io.BytesIO(data)), writer, status)
    return [json.loads(line) for line in stream.getvalue().splitlines()], status


def test_split_keeps_the_four_sections_in_order() -> None:
    sections = split(io.BytesIO(PE_OUT.read_bytes()))
    assert sections.ended and set(sections.raw) == {"info", "functions", "imports", "strings"}
    assert sections.errors == []
    assert parse(sections.raw["functions"])[0]["name"] == "entry0"  # after the warning line


def test_reduced_rows_normalize_like_the_ghidra_stage() -> None:
    rows, status = _reduce(PE_OUT.read_bytes())
    analysis = normalize_analysis(rows, LIMITS)
    assert not analysis.invalid and not analysis.dropped
    assert analysis.facts is not None and analysis.facts.image_base == 0x400000
    assert analysis.facts.entry == 0x401000
    names = {f.entry: f for f in analysis.functions}
    assert names[0x401000].name_source == "export"
    assert names[0x401080].name_source == "symbol"
    assert names[0x401100].name_source == "generated"  # the 5.x `offset` spelling
    assert names[0x401100].body[0].end - names[0x401100].body[0].start == 48  # insane maxaddr
    thunk = names[0x401200]
    assert thunk.name_source == "import" and thunk.is_thunk and thunk.is_external
    edges = {(e.caller, e.callee): e.sites for e in analysis.edges}
    assert edges == {
        (0x401000, 0x401080): 1,
        (0x401080, 0x401100): 2,
        (0x401080, 0x401200): 1,
        (0x401100, 0x401100): 1,
    }
    imports = {i.index: i for i in analysis.imports}
    assert imports[2].name is None and imports[2].ordinal == 4
    refs = {(imports[r.import_index].name, r.function_entry) for r in analysis.import_refs}
    assert refs == {
        ("VirtualAlloc", 0x401080),
        ("puts", 0x401080),  # through the sym.imp thunk
        ("GetProcAddress", 0x401100),
    }
    strings = {s.index: s for s in analysis.strings}
    assert len(strings) == 5  # "abc" is too short
    assert any(s.value == "\n===CYBERLAB:end===\n" for s in strings.values())  # not a marker
    assert {s.encoding for s in strings.values()} == {"ascii", "utf16le"}
    referenced = {(strings[r.string_index].value, r.function_entry) for r in analysis.string_refs}
    assert ("http://203.0.113.7/a", 0x401080) in referenced
    assert ("LoadLibraryA", 0x401100) in referenced
    assert status["engine_errors"] == [] and status["truncated"] == {}


def test_missing_invalid_and_oversize_sections_are_recorded() -> None:
    data = PE_OUT.read_bytes()
    no_end = data.replace(b"===CYBERLAB:end===\n", b"")
    _, status = _reduce(no_end)
    assert status["truncated"] == {"r2_output": True}
    broken = data.replace(b'[{"vaddr"', b'[{"vaddr": NaN, "x"', 1)
    rows, status = _reduce(broken)
    assert "radare_strings_failed" in status["engine_errors"]
    assert any(r["kind"] == "function" for r in rows)
    sections = split(io.BytesIO(data), max_section=200)
    assert "radare_functions_too_large" in sections.errors and "functions" not in sections.raw
    repeated = data.replace(b"===CYBERLAB:imports===", b"===CYBERLAB:info===", 1)
    sections = split(io.BytesIO(repeated))
    assert "radare_marker_unexpected" in sections.errors


def test_garbage_output_still_gives_facts_or_nothing() -> None:
    rows, status = _reduce(b"\x00\xff garbage\n" * 10)
    assert {e for e in status["engine_errors"]} >= {"radare_info_failed", "radare_functions_failed"}
    assert [r["kind"] for r in rows] == ["program_facts"]
    assert status["truncated"] == {"r2_output": True}


def test_caps_stop_the_reducer() -> None:
    rows, status = _reduce(PE_OUT.read_bytes(), {**CAPS, "function": 2, "string": 1})
    assert sum(r["kind"] == "function" for r in rows) == 2
    assert status["truncated"] == {"function": True, "string": True}


def test_names() -> None:
    assert name_source("sym.imp.KERNEL32.dll_VirtualAlloc", "fcn") == "import"
    assert name_source("fcn.00401000", "fcn") == "generated"
    assert name_source("dbg.parse_config", "fcn") == "debug"
    assert name_source("entry0", "fcn") == "export"
    assert name_source("sym.main", "sym") == "symbol"
    assert import_key("sym.imp.KERNEL32.dll_VirtualAlloc", "KERNEL32.dll") == "virtualalloc"
    assert import_key("sym.imp.puts") == "puts"


def test_fixture_is_ascii_text() -> None:
    assert PE_OUT.read_bytes().isascii()
