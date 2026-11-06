"""The probe's row encoder and streaming visitor (pure Python; the Volatility value classes
are stand-ins): bounded values, absent values as null + `_unreadable`, tree rows with
`_parent`, the cap stopping the grid with a `_truncated` marker."""

import io
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from memory_worker.probe.encode import (
    MAX_DISASM,
    MAX_HEX_BYTES,
    MAX_TEXT,
    CapReached,
    Encoder,
    RowWriter,
    VolTypes,
)


class Absent:
    pass


class Unreadable(Absent):
    pass


@dataclass
class LayerData:
    data: bytes
    fail: bool = False


@dataclass
class Disassembly:
    text: str


class Hex(int):
    pass


class HexBytes(bytes):
    pass


def _read(value: Any, n: int) -> bytes:
    if value.fail:
        raise OSError("page not present")
    return bytes(value.data[: n * 4])  # a sloppy reader: the encoder cuts again


TYPES = VolTypes(
    absent=Absent,
    layer_data=LayerData,
    disassembly=Disassembly,
    read_layer=_read,
    disassemble=lambda value, n: value.text,
)
ENC = Encoder(TYPES)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, True),
        (Hex(0xFFFF_F806_7280_0000), 0xFFFF_F806_7280_0000),
        (5, 5),
        (1.5, 1.5),
        (datetime(2026, 11, 1, 8, 0, tzinfo=UTC), "2026-11-01T08:00:00+00:00"),
        (
            datetime(2026, 11, 1, 10, 0, tzinfo=timezone(timedelta(hours=2))),
            "2026-11-01T08:00:00+00:00",
        ),  # noqa: E501
        (datetime(2026, 11, 1, 8, 0), "2026-11-01T08:00:00+00:00"),  # naive: UTC
        (b"MZ\x90\x00", "4d5a9000"),
        (HexBytes(bytes(range(200))), bytes(range(MAX_HEX_BYTES)).hex()),
        (LayerData(b"\xcc" * 500), "cc" * MAX_HEX_BYTES),
        ("svc\x00host.exe", "svchost.exe"),
        ("\ud800bad", "?bad"),
    ],
)
def test_values(value: object, expected: object) -> None:
    assert ENC.value(value) == expected


def test_text_and_disassembly_are_cut() -> None:
    assert ENC.value("A" * 10_000) == "A" * MAX_TEXT
    assert len(str(ENC.value(Disassembly("nop\n" * 1000)))) == MAX_DISASM


def test_absent_and_unencodable_values_become_null_and_unreadable() -> None:
    row = ENC.row(
        ["PID", "ExitTime", "Hexdump", "Ratio", "Name"],
        [4, Unreadable(), LayerData(b"", fail=True), math.nan, None],
        None,
    )
    assert row == {
        "PID": 4,
        "ExitTime": None,
        "Hexdump": None,
        "Ratio": None,
        "Name": None,
        "_unreadable": ["ExitTime", "Hexdump", "Ratio", "Name"],
    }
    assert json.dumps(row, allow_nan=False)


@dataclass
class Node:
    values: list[object]
    parent: "Node | None" = None


def test_rows_stream_with_parent_indexes_and_stop_at_the_cap() -> None:
    out = io.StringIO()
    writer = RowWriter(out, ["Type", "Name"], 3, ENC)
    hive = Node(["Key", None])
    writer(hive, None)
    writer(Node(["Value", "a.exe"], hive), None)
    writer(Node(["Value", "b.exe"], hive), None)
    with pytest.raises(CapReached):
        writer(Node(["Value", "c.exe"], hive), None)
    writer.cap()
    rows = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [r.get("_parent") for r in rows[:3]] == [None, 0, 0]
    assert rows[-1] == {"_truncated": True}
    assert writer.rows == 3 and writer.truncated


def test_a_value_raising_in_str_never_stops_the_row() -> None:
    class Hostile:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    assert ENC.row(["X", "Y"], [Hostile(), 1], 2) == {
        "X": None,
        "Y": 1,
        "_parent": 2,
        "_unreadable": ["X"],
    }
