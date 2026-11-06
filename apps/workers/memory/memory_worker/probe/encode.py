"""Row encoder and streaming TreeGrid visitor of the probe (tool uid side; M8 phase 2).

Volatility's JSON renderers buffer the whole grid (research §5), so the probe walks the grid
with its own visitor: one JSON object per row, written as it is produced, stopping the grid
at the row cap (`CapReached`, caught by the probe, which then writes `{"_truncated": true}`).

Values (the contract bounds are applied again by root, this is the first cut):
- bool as bool, int (and `format_hints.Hex`) as int, finite floats as floats;
- `datetime` as ISO 8601 UTC;
- `bytes` / `HexBytes` / `LayerData` as lowercase hex of at most `MAX_HEX_BYTES` bytes;
- `Disassembly` as capstone text of at most `MAX_DISASM` characters;
- `str` cut to `MAX_TEXT` characters, NUL removed, lone surrogates replaced;
- absent values (`NotApplicableValue`, `UnreadableValue`, ...) as null, the column listed in
  the row's `_unreadable` marker.

Tree plugins: a child row carries `_parent`, the 0-based index of its parent row in the file.
The Volatility classes are injected (`VolTypes`) so this module imports no Volatility code.
"""

import json
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, TextIO

MAX_TEXT = 4096
MAX_HEX_BYTES = 64
MAX_DISASM = 1024
MAX_DISASM_INPUT = 256  # bytes handed to the disassembler
PARENT = "_parent"
UNREADABLE = "_unreadable"
TRUNCATED = "_truncated"


class CapReached(Exception):
    """Raised by the visitor at the row cap: stops `grid.populate`."""


class Unencodable(Exception):
    pass


@dataclass(frozen=True)
class VolTypes:
    absent: type  # interfaces.renderers.BaseAbsentValue
    layer_data: type  # renderers.LayerData
    disassembly: type  # renderers.Disassembly
    read_layer: Callable[[Any, int], bytes]  # (LayerData value, at most n bytes) -> bytes
    disassemble: Callable[[Any, int], str]  # (Disassembly value, max input bytes) -> text


def text(value: str, limit: int = MAX_TEXT) -> str:
    clean = value.replace("\x00", "")[:limit]
    return clean.encode("utf-8", "replace").decode("utf-8")


def iso(value: datetime) -> str:
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat()


class Encoder:
    def __init__(self, types: VolTypes) -> None:
        self.types = types

    def value(self, value: object) -> object:
        """JSON-safe value, or raises `Unencodable` (the column becomes null + unreadable)."""
        t = self.types
        if value is None or isinstance(value, t.absent):
            raise Unencodable
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return int(value)
        if isinstance(value, float):
            if not math.isfinite(value):
                raise Unencodable
            return value
        if isinstance(value, datetime):
            try:
                return iso(value)
            except (OverflowError, ValueError) as exc:
                raise Unencodable from exc
        if isinstance(value, bytes | bytearray | memoryview):
            return bytes(value[:MAX_HEX_BYTES]).hex()
        if isinstance(value, t.layer_data):
            return self._guarded(lambda: t.read_layer(value, MAX_HEX_BYTES)[:MAX_HEX_BYTES].hex())
        if isinstance(value, t.disassembly):
            return self._guarded(lambda: text(t.disassemble(value, MAX_DISASM_INPUT), MAX_DISASM))
        if isinstance(value, str):
            return text(value)
        return self._guarded(lambda: text(str(value)))

    @staticmethod
    def _guarded(produce: Callable[[], object]) -> object:
        try:
            return produce()
        except Exception as exc:  # noqa: BLE001 - a bad value never stops the row
            raise Unencodable from exc

    def row(
        self, columns: Sequence[str], values: Sequence[object], parent: int | None
    ) -> dict[str, object]:
        out: dict[str, object] = {}
        unreadable: list[str] = []
        for column, value in zip(columns, values, strict=False):
            try:
                out[column] = self.value(value)
            except Unencodable:
                out[column] = None
                unreadable.append(column)
        if parent is not None:
            out[PARENT] = parent
        if unreadable:
            out[UNREADABLE] = unreadable
        return out


class RowWriter:
    """The `grid.populate` visitor: streams rows to `out`, at most `max_rows`."""

    def __init__(
        self, out: TextIO, columns: Sequence[str], max_rows: int, encoder: Encoder
    ) -> None:
        self.out = out
        self.columns = list(columns)
        self.max_rows = max_rows
        self.encoder = encoder
        self.rows = 0
        self.truncated = False
        self._index: dict[int, int] = {}

    def __call__(self, node: Any, accumulator: Any) -> Any:
        if self.rows >= self.max_rows:
            raise CapReached
        parent = getattr(node, "parent", None)
        parent_index = self._index.get(id(parent)) if parent is not None else None
        row = self.encoder.row(self.columns, list(node.values), parent_index)
        self.out.write(json.dumps(row, ensure_ascii=True, allow_nan=False) + "\n")
        self._index[id(node)] = self.rows
        self.rows += 1
        return accumulator

    def cap(self) -> None:
        self.truncated = True
        self.out.write(json.dumps({TRUNCATED: True}) + "\n")


__all__ = [
    "MAX_DISASM",
    "MAX_HEX_BYTES",
    "MAX_TEXT",
    "PARENT",
    "TRUNCATED",
    "UNREADABLE",
    "CapReached",
    "Encoder",
    "RowWriter",
    "Unencodable",
    "VolTypes",
    "iso",
    "text",
]
