import gzip
import hashlib
from pathlib import Path
from types import TracebackType
from typing import Self

from cyberlab_jobs.results import ResultTrailer
from pydantic import BaseModel


class ResultWriter:
    """gzip NDJSON writer; the trailer carries the line count and sha256 of all prior bytes."""

    def __init__(self, path: Path) -> None:
        self._file = gzip.open(path, "wb", compresslevel=6)
        self._digest = hashlib.sha256()
        self._lines = 0

    def write(self, record: BaseModel) -> None:
        line = record.model_dump_json().encode() + b"\n"
        self._digest.update(line)
        self._file.write(line)
        self._lines += 1

    def close(self) -> None:
        trailer = ResultTrailer(line_count=self._lines, sha256=self._digest.hexdigest())
        self._file.write(trailer.model_dump_json().encode() + b"\n")
        self._file.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if exc_type is None:
            self.close()
        else:
            self._file.close()
