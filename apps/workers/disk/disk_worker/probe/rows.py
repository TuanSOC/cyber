"""Bounded probe output: JSONL rows with a row and byte cap, and the one `status.json`.

Every file is created by the probe in its own out dir with `O_CREAT | O_EXCL | O_NOFOLLOW`
relative to the out dir's descriptor, so nothing planted (a symlink, an earlier file) can
redirect a write. Values are ASCII JSON (`ensure_ascii`), one object per line.
"""

import json
import os
from pathlib import Path
from types import TracebackType
from typing import IO, Any, Self

STATUS = "status.json"


def create(out: Path, name: str, mode: int = 0o600) -> IO[bytes]:
    if "/" in name or name in ("", ".", ".."):
        raise ValueError("output names are single path components")
    dir_fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(name, flags, mode, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    return os.fdopen(fd, "wb")


def dumps(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()


class RowWriter:
    """JSONL with caps: past `max_rows` or `max_bytes` nothing more is written and
    `truncated` is set (the caller stops its walk on `full`)."""

    def __init__(self, out: Path, name: str, *, max_rows: int, max_bytes: int) -> None:
        self._file = create(out, name)
        self.max_rows = max_rows
        self.max_bytes = max_bytes
        self.rows = 0
        self.bytes = 0
        self.truncated = False

    @property
    def full(self) -> bool:
        return self.truncated

    def write(self, row: dict[str, Any]) -> bool:
        if self.truncated:
            return False
        line = dumps(row) + b"\n"
        if self.rows >= self.max_rows or self.bytes + len(line) > self.max_bytes:
            self.truncated = True
            return False
        self._file.write(line)
        self.rows += 1
        self.bytes += len(line)
        return True

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def write_status(out: Path, status: dict[str, Any]) -> None:
    with create(out, STATUS) as f:
        f.write(dumps(status) + b"\n")


def read_args(path: Path, max_bytes: int = 64 * 1024**2) -> dict[str, Any]:
    """The root-written stage arguments (`input/<stage>.json`): a regular file, no symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        raw = f.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("stage arguments too large")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("stage arguments are an object")
    return value


__all__ = ["STATUS", "RowWriter", "create", "dumps", "read_args", "write_status"]
