"""Turning tool output (derived from attacker-controlled packets) into records.

The root process reads these files, so every read is bounded: per line (a single giant line
is skipped in chunks, never loaded), per file (bytes and lines), and every conversion error
skips one record instead of failing the job. Sources report what they capped or skipped.
"""

import contextlib
import ipaddress
import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any, BinaryIO

from cyberlab_worker import sandbox

log = logging.getLogger(__name__)

MAX_LINE_BYTES = 1024 * 1024
MAX_FILE_BYTES = 1024**3
NUL = chr(0)
# Accepted timestamp window (1970 .. 2100): anything else is a parser artefact.
MIN_EPOCH, MAX_EPOCH = 0.0, 4_102_444_800.0
# One record that fails to convert is skipped, never fatal.
RECORD_ERRORS = (ValueError, OverflowError, TypeError, RecursionError)


class JsonLines:
    """Bounded JSON-lines reader over one tool output file."""

    def __init__(self, dirs: sandbox.JobDirs, name: str, *, max_lines: int) -> None:
        self.dirs = dirs
        self.name = name
        self.max_lines = max_lines
        self.lines = 0
        self.skipped = 0
        self.capped = False

    def __iter__(self) -> Iterator[dict[str, Any]]:
        with contextlib.ExitStack() as stack:
            try:
                f = stack.enter_context(sandbox.open_output(self.dirs, self.name))
            except (OSError, ValueError):  # missing (engine produced nothing) or not a file
                return
            yield from self._read(f)

    def _read(self, f: BinaryIO) -> Iterator[dict[str, Any]]:
        total = 0
        while raw := f.readline(MAX_LINE_BYTES + 1):
            total += len(raw)
            if total > MAX_FILE_BYTES or self.lines >= self.max_lines:
                self.capped = True
                return
            if len(raw) > MAX_LINE_BYTES and not raw.endswith(b"\n"):
                # Oversized line: skip it in bounded chunks, never hold it in memory.
                self.skipped += 1
                while (more := f.readline(MAX_LINE_BYTES)) and not more.endswith(b"\n"):
                    total += len(more)
                    if total > MAX_FILE_BYTES:
                        self.capped = True
                        return
                continue
            self.lines += 1
            try:
                item = json.loads(raw)
            except (ValueError, RecursionError):
                self.skipped += 1
                continue
            if isinstance(item, dict):
                yield item
            else:
                self.skipped += 1


def clip(value: object, limit: int) -> str | None:
    """Tool text: str only, NUL removed, lone surrogates replaced, length-capped."""
    if not isinstance(value, str):
        return None
    text = value.replace(NUL, "")[:limit]
    return text.encode("utf-8", "replace").decode("utf-8")


def clip_list(value: object, limit: int, items: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [text for v in value[:items] if (text := clip(v, limit)) is not None]


def ip(value: object) -> str | None:
    """Plain IPv4/IPv6 only (no IPv6 zone/scope id: unbounded text in the address)."""
    if not isinstance(value, str) or "%" in value or len(value) > 45:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def port(value: object) -> int | None:
    return value if isinstance(value, int) and 0 <= value <= 65535 else None


def count(value: object) -> int:
    return value if isinstance(value, int) and 0 <= value < 2**63 else 0


def opt_count(value: object) -> int | None:
    return value if isinstance(value, int) and 0 <= value < 2**63 else None


def seconds(value: object) -> float | None:
    if isinstance(value, int | float) and 0 <= value < 10**9:
        return float(value)
    return None


def epoch(value: object) -> datetime | None:
    if isinstance(value, int | float) and MIN_EPOCH <= value < MAX_EPOCH:
        return datetime.fromtimestamp(float(value), UTC)
    return None


def iso(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        return epoch(parsed.timestamp())
    except RECORD_ERRORS:
        return None
