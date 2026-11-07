"""Every cap stops its exporter and sets its flag (pure Python): the probe's writer, its text
bounds, and the error-name token of the status."""

import io
import json

from re_worker.probe.main import error_name
from re_worker.probe.mapping import name_source, ordinal_of, string_encoding
from re_worker.probe.out import RowWriter, dumps, optional_text, text


def test_writer_stops_each_kind_at_its_cap() -> None:
    stream = io.StringIO()
    writer = RowWriter(stream, {"function": 2, "string": 0})
    assert writer.emit("function", {"entry": 1}) and writer.emit("function", {"entry": 2})
    assert not writer.emit("function", {"entry": 3})
    assert not writer.emit("string", {"index": 0})
    assert writer.emit("program_facts", {"image_base": 0})  # uncapped kinds pass
    assert writer.truncated == {"function": True, "string": True}
    assert writer.counts == {"function": 2, "program_facts": 1}
    rows = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert [r["kind"] for r in rows] == ["function", "function", "program_facts"]


def test_rows_are_ascii_json_without_nan() -> None:
    line = dumps({"name": "‮中", "n": 1})
    assert line.isascii() and json.loads(line)["name"] == "‮中"
    try:
        dumps({"x": float("nan")})
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("NaN must not be written")


def test_text_removes_nul_and_lone_surrogates_and_cuts() -> None:
    assert text("a\x00b", 255) == "ab"
    assert text("x\ud800y", 255) == "x�y"
    assert text("\U0001f600" * 3, 2) == "\U0001f600" * 2
    assert text("z" * 1000, 255) == "z" * 255
    assert optional_text(None, 8) is None and optional_text("\x00", 8) is None


def test_error_names_are_status_tokens() -> None:
    class Java(Exception):
        pass

    Java.__name__ = "java.lang.OutOfMemoryError"
    assert error_name(Java()) == "OutOfMemoryError"
    Weird = type("1 bad-name", (Exception,), {})
    assert error_name(Weird()) == "Error"


def test_engine_value_mappings() -> None:
    assert name_source("DEFAULT", is_export=False, imports_external=False, is_fid=False) == (
        "generated"
    )
    assert name_source("IMPORTED", is_export=True, imports_external=False, is_fid=False) == (
        "export"
    )
    assert name_source("ANALYSIS", is_export=False, imports_external=True, is_fid=True) == "import"
    assert name_source("ANALYSIS", is_export=False, imports_external=False, is_fid=True) == (
        "fid_library"
    )
    assert name_source("USER_DEFINED", is_export=False, imports_external=False, is_fid=False) == (
        "symbol"
    )
    assert string_encoding("unicode", "abc", big_endian=False) == "utf16le"
    assert string_encoding("TerminatedUnicode", "abc", big_endian=True) == "utf16be"
    assert string_encoding("unicode32", "abc", big_endian=False) == "utf32"
    assert string_encoding("string", "café", big_endian=False) == "utf8"
    assert string_encoding("TerminatedCString", "plain", big_endian=False) == "ascii"
    assert ordinal_of("Ordinal_4") == 4 and ordinal_of("Ordinal_70000") is None
    assert ordinal_of("VirtualAlloc") is None
