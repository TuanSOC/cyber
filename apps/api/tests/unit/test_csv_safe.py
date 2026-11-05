"""`app/core/csv_safe.py` (M6 phase 1, RT19): formula cells, RFC 4180, streaming."""

import csv
import io

import pytest

from app.core.csv_safe import CHUNK_ROWS, csv_safe, write_csv


@pytest.mark.parametrize(
    "cell",
    [
        "=1+1",
        "+cmd",
        "-2+3",
        "@SUM(A1)",
        "\t=x",
        "\r=x",
        '  =HYPERLINK("http://x")',
        " =1",
        "　@x",
        "＝1+1",
        "＋1",
        "－1",
        "＠x",
        "\n=1",
    ],
)
def test_formula_cells_are_prefixed(cell: str) -> None:
    assert csv_safe(cell) == "'" + cell.replace("\x00", "")


@pytest.mark.parametrize("cell", ["", "plain", "10.0.0.1", "a=b", "x@y.example", "1-2", " text"])
def test_ordinary_cells_are_unchanged(cell: str) -> None:
    assert csv_safe(cell) == cell


def test_nul_is_removed_and_none_is_empty() -> None:
    assert csv_safe("a\x00b") == "ab"
    assert csv_safe("\x00=1") == "'=1"
    assert csv_safe(None) == ""
    assert csv_safe(42) == "42"


def _parse(chunks: list[bytes]) -> list[list[str]]:
    text = b"".join(chunks).decode("utf-8")
    return list(csv.reader(io.StringIO(text, newline="")))


def test_rfc4180_quoting_and_crlf() -> None:
    chunks = list(write_csv([["a,b", 'say "hi"', "line\nbreak"], ["=1", "ok", ""]]))
    raw = b"".join(chunks)
    assert raw.endswith(b"\r\n")
    assert b'"a,b","say ""hi""","line\nbreak"\r\n' in raw
    assert _parse(chunks) == [["a,b", 'say "hi"', "line\nbreak"], ["'=1", "ok", ""]]


def test_header_comment_is_a_single_first_line() -> None:
    chunks = list(write_csv([["x"]], header_comment="# TLP:AMBER CASE-00012\nexported"))
    first, rest = b"".join(chunks).split(b"\r\n", 1)
    assert first == b"# TLP:AMBER CASE-00012 exported"
    assert rest == b"x\r\n"


def test_streams_in_chunks() -> None:
    rows = [[str(i)] for i in range(CHUNK_ROWS * 2 + 3)]
    chunks = list(write_csv(rows))
    assert len(chunks) == 3
    assert [r[0] for r in _parse(chunks)] == [str(i) for i in range(CHUNK_ROWS * 2 + 3)]


def test_utf8_output() -> None:
    assert b"".join(write_csv([["Tiếng Việt", "＝"]])) == "Tiếng Việt,'＝\r\n".encode()
