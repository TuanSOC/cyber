"""The probe's bounded output (tool uid; pure Python, unit-tested on any host).

`RowWriter` writes one compact ASCII JSON object per line (`ensure_ascii`, no NaN) to the
private stdout handle and stops each kind at its cap (the same values root applies, plus a
`truncated` flag per kind for the status). Every string the engine hands over passes `text`:
NUL removed, lone surrogates replaced (Java strings may hold them), cut to its contract
length. Root re-validates everything; this only keeps honest output inside the bounds.
"""

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any, TextIO

STATUS = "status.json"


class StageFailure(Exception):  # noqa: N818 - a stage outcome with a contract code
    """The stage refuses to go on: `code` is an `RE_ERROR_CODES` value, `reason` a token."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


def text(value: object, limit: int) -> str:
    s = str(value).replace("\x00", "")
    s = s.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
    return s[:limit]


def optional_text(value: object, limit: int) -> str | None:
    if value is None:
        return None
    s = text(value, limit)
    return s or None


def dumps(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


class RowWriter:
    def __init__(self, stream: TextIO, caps: dict[str, int]) -> None:
        self.stream = stream
        self.caps = dict(caps)
        self.counts: Counter[str] = Counter()
        self.truncated: dict[str, bool] = {}

    def full(self, kind: str) -> bool:
        cap = self.caps.get(kind)
        return cap is not None and self.counts[kind] >= cap

    def emit(self, kind: str, fields: dict[str, Any]) -> bool:
        """Write one row; False (and the kind's truncated flag) once its cap is reached."""
        if self.full(kind):
            self.truncated[kind] = True
            return False
        self.stream.write(dumps({"kind": kind, **fields}) + "\n")
        self.counts[kind] += 1
        return True

    def finish(self) -> None:
        self.stream.flush()


def write_status(out: Path, status: dict[str, Any]) -> None:
    """`status.json` in the out dir: created once (O_EXCL | O_NOFOLLOW, relative to it)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    dir_fd = os.open(out, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        fd = os.open(STATUS, flags, 0o600, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(json.dumps(status, ensure_ascii=True, allow_nan=False, default=str) + "\n")


__all__ = [
    "STATUS",
    "RowWriter",
    "StageFailure",
    "dumps",
    "optional_text",
    "text",
    "write_status",
]
