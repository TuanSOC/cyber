"""Bounded reads of probe output (root side; pure Python over an open binary file).

The analyzer opens the files through the worker kit (`sandbox.open_output`: dir_fd,
O_NOFOLLOW, regular files only) or, for sealed stage dirs, the same way; everything here sees
only the file object, so a probe can at worst produce bounded, typed garbage:
- a line is at most `max_line_bytes` (a longer one is skipped in bounded chunks, never held);
- a file is at most `max_bytes` and `max_rows` rows (root's own caps, whatever the probe
  claims); beyond either the read counts as truncated;
- NaN / Infinity, invalid JSON, non-objects and over-deep nesting count as bad lines.
"""

import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, BinaryIO

MAX_LINE_BYTES = 64 * 1024
MAX_STATUS_BYTES = 64 * 1024


def _no_constants(value: str) -> Any:
    raise ValueError(f"non-finite number {value}")


def loads(raw: bytes) -> Any:
    return json.loads(raw, parse_constant=_no_constants)


@dataclass
class ReadStats:
    lines: int = 0
    rows: int = 0
    bad: int = 0  # unusable lines + rows that failed validation (the caller adds those)
    truncated: bool = False

    def bad_ratio(self) -> float:
        return self.bad / self.lines if self.lines else 0.0


def read_jsonl(
    f: BinaryIO | None,
    stats: ReadStats,
    *,
    max_rows: int,
    max_bytes: int,
    max_line_bytes: int = MAX_LINE_BYTES,
) -> Iterator[dict[str, Any]]:
    if f is None:
        return
    total = 0
    while raw := f.readline(max_line_bytes + 1):
        total += len(raw)
        if total > max_bytes or stats.rows >= max_rows:
            stats.truncated = True
            return
        stats.lines += 1
        if len(raw) > max_line_bytes and not raw.endswith(b"\n"):
            stats.bad += 1
            while (more := f.readline(max_line_bytes)) and not more.endswith(b"\n"):
                total += len(more)
                if total > max_bytes:
                    stats.truncated = True
                    return
            total += len(more)
            continue
        try:
            item = loads(raw)
        except (ValueError, RecursionError):
            stats.bad += 1
            continue
        if not isinstance(item, dict):
            stats.bad += 1
            continue
        stats.rows += 1
        yield item


def read_status(f: BinaryIO | None) -> dict[str, Any] | None:
    if f is None:
        return None
    raw = f.read(MAX_STATUS_BYTES + 1)
    if len(raw) > MAX_STATUS_BYTES:
        return None
    try:
        value = loads(raw)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


__all__ = ["MAX_LINE_BYTES", "ReadStats", "loads", "read_jsonl", "read_status"]
