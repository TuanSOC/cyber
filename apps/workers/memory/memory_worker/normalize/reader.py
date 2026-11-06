"""Bounded reads of probe output (root side; pure Python over an open binary file).

The engine opens the files through the worker kit (`sandbox.open_output`: dir_fd,
O_NOFOLLOW, regular files only); everything here only sees the file object, so a probe can
at worst produce bounded, typed garbage:
- a line is at most `MAX_LINE_BYTES` (a longer one is skipped in bounded chunks, never held);
- a file is at most `MAX_FILE_BYTES` and `max_rows` rows (root's own cap, whatever the probe
  claims); beyond either the run counts as truncated;
- NaN / Infinity, invalid JSON, non-objects and over-deep nesting skip one line;
- the probe's `{"_truncated": true}` marker ends the rows: nothing after it is read, and a
  `{"_truncated": false}` written after the real cap changes nothing.

`status.json` is read whole up to `MAX_STATUS_BYTES` and validated (`ProbeStatus`); anything
else makes it `None` (the plugin then counts as failed).
"""

import json
import re
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Annotated, Any, BinaryIO, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
)

MAX_LINE_BYTES = 64 * 1024
MAX_FILE_BYTES = 512 * 1024**2  # = the probe's RLIMIT_FSIZE
MAX_STATUS_BYTES = 64 * 1024
TRUNCATED = "_truncated"
NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _no_constants(value: str) -> Any:
    raise ValueError(f"non-finite number {value}")


def loads(raw: bytes) -> Any:
    return json.loads(raw, parse_constant=_no_constants)


@dataclass
class RowStats:
    lines: int = 0
    rows: int = 0
    skipped: int = 0  # lines that were not a usable JSON object
    truncated: bool = False  # the probe's marker, root's row cap or the byte cap


def read_rows(f: BinaryIO | None, max_rows: int, stats: RowStats) -> Iterator[dict[str, Any]]:
    if f is None:
        return
    total = 0
    while raw := f.readline(MAX_LINE_BYTES + 1):
        total += len(raw)
        if total > MAX_FILE_BYTES:
            stats.truncated = True
            return
        stats.lines += 1
        if len(raw) > MAX_LINE_BYTES and not raw.endswith(b"\n"):
            stats.skipped += 1
            while (more := f.readline(MAX_LINE_BYTES)) and not more.endswith(b"\n"):
                total += len(more)
                if total > MAX_FILE_BYTES:
                    stats.truncated = True
                    return
            total += len(more)
            continue
        try:
            item = loads(raw)
        except (ValueError, RecursionError):
            stats.skipped += 1
            continue
        if not isinstance(item, dict):
            stats.skipped += 1
            continue
        if TRUNCATED in item:
            if item[TRUNCATED] is True:
                stats.truncated = True
            return
        if stats.rows >= max_rows:
            stats.truncated = True
            return
        stats.rows += 1
        yield item


class RowSource:
    """The rows of one plugin run, read lazily when the normalizer iterates them (once).
    `opener` opens the rows file (the engine passes the kit's `sandbox.open_output`); a
    missing or non-regular file yields nothing. `done` receives root's counts."""

    def __init__(
        self,
        opener: Callable[[], AbstractContextManager[BinaryIO]],
        max_rows: int,
        done: Callable[[RowStats], None],
    ) -> None:
        self.opener = opener
        self.max_rows = max_rows
        self.done = done

    def __iter__(self) -> Iterator[dict[str, Any]]:
        stats = RowStats()
        try:
            with self.opener() as f:
                yield from read_rows(f, self.max_rows, stats)
        except (OSError, ValueError):
            pass  # no rows file (the outcome already says why) or not a regular file
        finally:
            self.done(stats)


ShortStr = Annotated[StrictStr, Field(max_length=1024)]
Name = Annotated[StrictStr, Field(pattern=NAME.pattern)]
Count = Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]


class ProbeStatus(BaseModel):
    """`status.json` of one probe run (untrusted; unknown keys ignored)."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    status: Literal["ok", "failed", "unsupported"]
    error: Name | None = None
    rows: Count = 0
    truncated: StrictBool = False
    audit: Annotated[dict[Name, Count], Field(max_length=16)] = {}
    offline: StrictBool | None = None
    remote_isf_url: ShortStr | None = None
    symbol_paths: Annotated[list[ShortStr], Field(max_length=4)] = []
    isf: Annotated[list[ShortStr], Field(max_length=8)] = []
    layers: Annotated[list[Name], Field(max_length=8)] = []
    columns: Annotated[list[Annotated[StrictStr, Field(max_length=64)]], Field(max_length=64)] = []
    identify: dict[str, Any] | None = None

    def offline_verified(self, symbols_dir: str) -> bool:
        """The probe ran offline with exactly the store + the two built-in symbol dirs."""
        paths = self.symbol_paths
        return (
            self.offline is True
            and self.remote_isf_url is None
            and len(paths) == 3
            and paths[0] == symbols_dir
            and paths[1].endswith("/volatility3/symbols")
            and paths[2].endswith("/volatility3/framework/symbols")
        )


def read_status(f: BinaryIO | None) -> ProbeStatus | None:
    if f is None:
        return None
    data = f.read(MAX_STATUS_BYTES + 1)
    if len(data) > MAX_STATUS_BYTES:
        return None
    try:
        return ProbeStatus.model_validate(loads(data))
    except (ValueError, RecursionError, ValidationError):
        return None


__all__ = [
    "MAX_FILE_BYTES",
    "MAX_LINE_BYTES",
    "MAX_STATUS_BYTES",
    "ProbeStatus",
    "RowSource",
    "RowStats",
    "loads",
    "read_rows",
    "read_status",
]
