"""Formula-injection-safe CSV (M6, FROZEN; shared by the IOC collection and timeline
exports).

- `csv_safe(cell)`: a cell whose first non-whitespace character (`str.isspace`) is `=`, `+`,
  `-`, `@`, TAB or CR, or one of their look-alikes (full-width `＝` `＋` `－` `＠`, small
  `﹢` `﹣` `﹦` `﹫`, the minus sign `−`), is prefixed with `'` so spreadsheet software shows
  it as text (RT19). NUL characters are removed.
- `write_csv(rows, header_comment)`: RFC 4180 (CRLF line ends, minimal quoting, `"`
  doubled), every cell through `csv_safe`, streamed as UTF-8 byte chunks. The optional
  header comment (`# TLP:AMBER CASE-00012 exported ...`) is the first record: one cell on
  one line (line breaks become spaces), quoted like any other cell when it holds a
  separator or a quote, so user text in it (a collection name) cannot add columns.
"""

import csv
import io
from collections.abc import Iterable, Iterator, Sequence
from typing import Any

DANGEROUS_LEADS = frozenset(
    "=+-@\t\r"
    "＝＋－＠"  # full-width = + - @
    "﹢﹣﹦﹫"  # small + - = @
    "−"  # minus sign
)
CHUNK_ROWS = 500


def _first_significant(text: str) -> str | None:
    """The first character that is not whitespace (`str.isspace`); TAB and CR count as
    significant because they are formula leads themselves."""
    for char in text:
        if char in "\t\r" or not char.isspace():
            return char
    return None


def csv_safe(cell: object) -> str:
    text = "" if cell is None else str(cell)
    text = text.replace("\x00", "")
    if _first_significant(text) in DANGEROUS_LEADS:
        return "'" + text
    return text


def _line(writer_buffer: io.StringIO, writer: Any, row: Sequence[object]) -> str:
    writer.writerow([csv_safe(cell) for cell in row])
    value = writer_buffer.getvalue()
    writer_buffer.seek(0)
    writer_buffer.truncate()
    return value


def write_csv(
    rows: Iterable[Sequence[object]], header_comment: str | None = None
) -> Iterator[bytes]:
    """Yield the CSV as UTF-8 chunks (about `CHUNK_ROWS` rows each)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    if header_comment is not None:
        # One cell on one line, quoted when it holds a separator or a quote (user text such
        # as a collection name cannot add columns), and formula-safe like any other cell.
        comment = " ".join(header_comment.replace("\x00", "").splitlines())
        yield _line(buffer, writer, [comment]).encode("utf-8")
    pending: list[str] = []
    for row in rows:
        pending.append(_line(buffer, writer, row))
        if len(pending) >= CHUNK_ROWS:
            yield "".join(pending).encode("utf-8")
            pending.clear()
    if pending:
        yield "".join(pending).encode("utf-8")
