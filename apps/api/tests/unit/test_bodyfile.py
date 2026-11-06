"""The TSK body file of the disk interop export (M9 phase 8): 11 fields per line, names that
cannot add a field or a line (`|` -> `\\x7c`, newline -> `\\x0a`, `\\` escaped so the round
trip is exact), the inode format, TSK's mode string, epoch times, deleted names."""

from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest

from app.modules.disk_forensics.exports_interop import (
    BODYFILE_FIELDS,
    bodyfile_inode,
    bodyfile_line,
    escape_field,
    mode_string,
    parse_bodyfile_line,
    unescape_field,
)

WHEN = datetime(2026, 10, 1, 8, 0, 0, tzinfo=UTC)


def _row(**fields: Any) -> SimpleNamespace:
    row: dict[str, Any] = {
        "partition_index": 1,
        "meta_addr": Decimal(65),
        "meta_seq": 1,
        "stream": None,
        "path": "Windows/notepad.exe",
        "type": "reg",
        "flags": 1,
        "size": 4096,
        "mode": 0o100644,
        "uid": 0,
        "gid": 0,
        "md5": "0" * 31 + "1",
        "atime": WHEN,
        "mtime": WHEN,
        "ctime": WHEN,
        "crtime": WHEN,
    }
    row.update(fields)
    return SimpleNamespace(**row)


def test_a_regular_entry() -> None:
    line = bodyfile_line(_row())
    assert line.endswith("\n") and line.count("\n") == 1
    epoch = str(int(WHEN.timestamp()))
    assert parse_bodyfile_line(line) == [
        "0" * 31 + "1",
        "/p1/Windows/notepad.exe",
        "65-1",
        "r/rrw-r--r--",
        "0",
        "0",
        "4096",
        epoch,
        epoch,
        epoch,
        epoch,
    ]


@pytest.mark.parametrize(
    "name",
    [
        "a|b",
        "line\nbreak",
        "cr\rlf",
        "tab\there",
        "back\\slash",
        "literal \\x7c text",
        "|||",
        "\x00nul",
        "del\x7f",
        "üñíçødé 名前",
    ],
)
def test_hostile_names_round_trip_on_one_line(name: str) -> None:
    line = bodyfile_line(_row(path=name, stream=name))
    assert line.count("\n") == 1 and "\r" not in line
    fields = line.rstrip("\n").split("|")
    assert len(fields) == BODYFILE_FIELDS
    parsed = parse_bodyfile_line(line)
    assert parsed[1] == f"/p1/{name}:{name}"
    assert unescape_field(fields[2].split("-", 2)[2]) == name  # the stream in the inode


def test_escapes_are_lowercase_hex() -> None:
    assert escape_field("a|b\nc\\d") == "a\\x7cb\\x0ac\\x5cd"
    assert unescape_field(escape_field("x\\x7cy")) == "x\\x7cy"


def test_inode_formats() -> None:
    assert bodyfile_inode(Decimal(2**64 - 1), None, None) == str(2**64 - 1)
    assert bodyfile_inode(Decimal(366), 1, "payload") == "366-1-payload"
    assert bodyfile_inode(12, None, "ads") == "12-ads"


def test_unknown_values_are_zero_and_deleted_names_are_marked() -> None:
    row = _row(md5=None, size=None, uid=None, gid=None, mode=None, flags=2, atime=None)
    fields = parse_bodyfile_line(bodyfile_line(row))
    assert fields[0] == "0"
    assert fields[1] == "/p1/Windows/notepad.exe (deleted)"
    assert fields[3:8] == ["r/r---------", "0", "0", "0", "0"]
    realloc = parse_bodyfile_line(bodyfile_line(_row(flags=1 | 8)))
    assert realloc[1].endswith(" (deleted-realloc)")


def test_named_stream() -> None:
    fields = parse_bodyfile_line(bodyfile_line(_row(stream="Zone.Identifier")))
    assert fields[1] == "/p1/Windows/notepad.exe:Zone.Identifier"
    assert fields[2] == "65-1-Zone.Identifier"


@pytest.mark.parametrize(
    ("file_type", "mode", "expected"),
    [
        ("reg", 0o100755, "r/rrwxr-xr-x"),
        ("dir", 0o040750, "d/drwxr-x---"),
        ("lnk", 0o120777, "l/lrwxrwxrwx"),
        ("other", 0o000644, "-/-rw-r--r--"),
        ("reg", None, "r/r---------"),
        ("reg", 0o104755, "r/rrwsr-xr-x"),
        ("reg", 0o102644, "r/rrw-r-Sr--"),
        ("dir", 0o041777, "d/drwxrwxrwt"),
        ("dir", 0o041776, "d/drwxrwxrwT"),
    ],
)
def test_mode_strings(file_type: str, mode: int | None, expected: str) -> None:
    assert mode_string(file_type, mode) == expected


def test_parser_rejects_a_wrong_field_count() -> None:
    with pytest.raises(ValueError, match="11 fields"):
        parse_bodyfile_line("a|b|c\n")
