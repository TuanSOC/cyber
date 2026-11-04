"""Framing of an analyzer's result stream, shared by every result schema.

A result is gzip NDJSON: the header is line 1, the trailer the last line (line count + sha256
of every byte before it), so a truncated or spliced stream is detectable before anything is
written. `check_framing()` enforces the framing and the stream-wide caps (inflated size, line
count, line length, termination) and hands each header/body line to the schema's checker;
`body_lines()` re-reads an already validated stream for the database writes.
"""

import gzip
import hashlib
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path

from cyberlab_jobs.results import ResultTrailer
from pydantic import ValidationError

# The largest legitimate line of any schema is far below this.
MAX_LINE_BYTES = 1024**2


class InvalidResult(Exception):
    """The stream is refused; `reason` is a short code for logs and tests."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def read_lines(path: Path, max_decompressed: int) -> Iterator[bytes]:
    """Every line of the gzip file, refusing zip bombs, over-long and unterminated lines."""
    total = 0
    try:
        with gzip.open(path, "rb") as stream:
            while line := stream.readline(MAX_LINE_BYTES + 1):
                total += len(line)
                if total > max_decompressed:
                    raise InvalidResult("decompressed_too_large")
                if len(line) > MAX_LINE_BYTES:
                    raise InvalidResult("line_too_long")
                if not line.endswith(b"\n"):
                    raise InvalidResult("unterminated_line")
                yield line
    except (OSError, EOFError, zlib.error) as exc:  # not gzip, truncated, corrupt
        raise InvalidResult("bad_gzip") from exc


def ioc_key(ioc_type: str, value: str) -> tuple[str, bytes]:
    """Duplicate key of an IOC: exactly what the unique index compares (job, type, md5(value)).

    Postgres md5(text) hashes the UTF-8 bytes (the database encoding), as this does, so the
    validator refuses everything the index would and nothing it would accept.
    """
    return ioc_type, hashlib.md5(value.encode(), usedforsecurity=False).digest()


def check_framing(
    path: Path,
    *,
    max_decompressed: int,
    max_lines: int,
    first: Callable[[bytes], None],
    middle: Callable[[bytes], None],
) -> None:
    """Blocking. Feeds line 1 to `first` and every body line to `middle` (both raise
    InvalidResult), then checks the trailer's line count and sha256."""
    digest = hashlib.sha256()
    lines = 0
    pending: bytes | None = None  # the trailer is only known to be last at end of stream
    for seen, line in enumerate(read_lines(path, max_decompressed), start=1):
        if seen > max_lines:
            raise InvalidResult("too_many_lines")
        if pending is not None:
            digest.update(pending)
            lines += 1
            if lines == 1:
                first(pending)
            else:
                middle(pending)
        pending = line
    if lines == 0 or pending is None:
        raise InvalidResult("missing_header")
    try:
        trailer = ResultTrailer.model_validate_json(pending)
    except ValidationError as exc:
        raise InvalidResult("invalid_trailer") from exc
    if trailer.line_count != lines:
        raise InvalidResult("trailer_count_mismatch")
    if trailer.sha256 != digest.hexdigest():
        raise InvalidResult("trailer_hash_mismatch")


def body_lines(path: Path, max_decompressed: int) -> Iterator[bytes]:
    """Every line between the header and the trailer of an already validated stream."""
    pending: bytes | None = None
    for index, line in enumerate(read_lines(path, max_decompressed)):
        if pending is not None:
            yield pending
        pending = line if index > 0 else None
