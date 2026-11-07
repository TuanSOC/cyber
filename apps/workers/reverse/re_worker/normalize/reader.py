"""Bounded reads of stage output (root side; pure Python over an open binary file).

The engines open the files through the worker kit (`sandbox.open_output`: dir fd,
O_NOFOLLOW, regular files only); this module only sees the file object, so a stage process
can at worst produce bounded, typed garbage (the M8 reader):
- a line is at most `MAX_LINE_BYTES` (a longer one is skipped in bounded chunks, never held;
  512 KiB: one 64 KiB code text JSON-escaped with `ensure_ascii` fits);
- a file is at most `MAX_FILE_BYTES` and `max_rows` rows (root's own cap, whatever the probe
  claims); beyond either the stage counts as truncated;
- NaN / Infinity, invalid JSON or UTF-8, duplicate keys, non-objects and over-deep nesting
  skip one line (counted);
- the probe's `{"_truncated": true}` marker ends the rows.

`status.json` is read whole up to `MAX_STATUS_BYTES` and validated (`StageStatus`, unknown
keys ignored); anything else makes it `None` (root then concludes from what it measured).
"""

import json
from collections.abc import Iterator
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

MAX_LINE_BYTES = 512 * 1024
MAX_FILE_BYTES = 1024**3  # = a JVM stage's RLIMIT_FSIZE
MAX_STATUS_BYTES = 64 * 1024
MAX_DEPTH = 8
TRUNCATED = "_truncated"
NAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]{0,63}$"
AUDIT_KEY_PATTERN = r"^[a-z_][a-z0-9_:.\-]{0,63}$"


class _Duplicate(ValueError):
    pass


def _no_constants(value: str) -> Any:
    raise ValueError(f"non-finite number {value}")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _Duplicate(key)
        out[key] = value
    return out


def _check(value: Any, level: int = 0) -> None:
    """Bounded nesting, and no lone surrogate in any string (a `\\ud800` escape decodes to
    one; it is not UTF-8 and would break the ingest's text columns)."""
    if level > MAX_DEPTH:
        raise ValueError("nested too deeply")
    if isinstance(value, str):
        value.encode("utf-8")  # UnicodeEncodeError is a ValueError
    elif isinstance(value, dict):
        for key, item in value.items():
            key.encode("utf-8")
            _check(item, level + 1)
    elif isinstance(value, list):
        for item in value:
            _check(item, level + 1)


def loads(raw: bytes) -> Any:
    """Strict JSON: UTF-8 only, no NaN / Infinity, no duplicate keys, no lone surrogates,
    bounded nesting."""
    text = raw.decode("utf-8")  # UnicodeDecodeError is a ValueError
    value = json.loads(text, parse_constant=_no_constants, object_pairs_hook=_no_duplicates)
    _check(value)
    return value


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


Name = Annotated[StrictStr, Field(pattern=NAME_PATTERN)]
AuditKey = Annotated[StrictStr, Field(pattern=AUDIT_KEY_PATTERN)]
Arg = Annotated[StrictStr, Field(max_length=512)]
Path255 = Annotated[StrictStr, Field(max_length=255)]
Count = Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]


class StageStatus(BaseModel):
    """`status.json` of one stage process (untrusted; unknown keys ignored). Root uses it
    only for what it cannot measure itself, and checks every claim it can (the JVM
    arguments against the expected list, the children against the allow-list)."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    status: Literal["ok", "failed"]
    error: Name | None = None  # an exception class name, never a message
    error_code: Name | None = None  # a stage-level code (`re_parse_failed`, ...)
    reason: Name | None = None  # why, as a fixed token (`loader_option`, ...)
    jvm_started: StrictBool = False
    jvm_args: Annotated[list[Arg], Field(max_length=64)] = []
    audit: Annotated[dict[AuditKey, Count], Field(max_length=16)] = {}
    analysis_status: Literal["complete", "timeout", "failed", "not_run"] | None = None
    truncated: Annotated[dict[Name, StrictBool], Field(max_length=32)] = {}
    counts: Annotated[dict[Name, Count], Field(max_length=32)] = {}
    children: Annotated[list[Path255], Field(max_length=32)] = []
    decompiler_limited: Count = 0  # prlimit applied to a decompiler child (RT4)
    decompiler_restarts: Count = 0
    unknown_options: Annotated[list[Arg], Field(max_length=32)] = []
    engine_errors: Annotated[list[Name], Field(max_length=32)] = []  # the radare2 reducer
    loader_options: Annotated[list[Arg], Field(max_length=64)] = []


def read_status(f: BinaryIO | None) -> StageStatus | None:
    if f is None:
        return None
    data = f.read(MAX_STATUS_BYTES + 1)
    if len(data) > MAX_STATUS_BYTES:
        return None
    try:
        return StageStatus.model_validate(loads(data))
    except (ValueError, RecursionError, ValidationError):
        return None


__all__ = [
    "MAX_FILE_BYTES",
    "MAX_LINE_BYTES",
    "MAX_STATUS_BYTES",
    "RowStats",
    "StageStatus",
    "loads",
    "read_rows",
    "read_status",
]
