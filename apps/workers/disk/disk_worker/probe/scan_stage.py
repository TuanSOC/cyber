"""`scan` stage shell (probe side; phase 5 owns the YARA logic in `probe/scan_yara.py`).

Root writes the candidates (natural keys, sizes, the partition each lives on) into the stage
arguments; this shell opens the image and the needed file systems through the same openers as
the walk and hands phase 5's scanner one `ScanItem` at a time. A candidate whose entry is not
an allocated regular file (or whose NTFS sequence changed) reads as `None`.

Interface used (phase 5 implements it in `disk_worker.probe.scan_yara`):

    scan(rule_dirs: list[Path], items: Iterator[ScanItem], emit: Callable[[dict], bool],
         deadline: float) -> dict[str, int]

`emit` is the bounded JSONL writer of `out/hits.jsonl` (False once the cap is hit); the
returned counts go into `status.json` (`counts`).
"""

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from disk_worker.probe import collect
from disk_worker.probe.tsk import Fs


@dataclass(frozen=True)
class ScanItem:
    partition_index: int
    meta_addr: int
    meta_seq: int | None
    stream: str | None
    size: int
    read: Callable[[], bytes | None]

    def key(self) -> dict[str, Any]:
        return {
            "partition_index": self.partition_index,
            "meta_addr": self.meta_addr,
            "meta_seq": self.meta_seq,
            "stream": self.stream,
        }


def items(img: Any, args: dict[str, Any]) -> Iterator[ScanItem]:
    filesystems: dict[int, Fs | None] = {}
    max_file = int(args["max_file_bytes"])
    for c in args["candidates"]:
        index = int(c["partition_index"])
        if index not in filesystems:
            part = args["partitions"].get(str(index))
            try:
                filesystems[index] = (
                    Fs(img, int(part["offset"]), str(part["family"])) if part else None
                )
            except (OSError, RuntimeError):
                filesystems[index] = None
        fs = filesystems[index]
        yield ScanItem(
            partition_index=index,
            meta_addr=int(c["meta_addr"]),
            meta_seq=c.get("meta_seq"),
            stream=c.get("stream"),
            size=int(c["size"]),
            read=_reader(fs, c, max_file),
        )


def _reader(fs: Fs | None, c: dict[str, Any], max_file: int) -> Callable[[], bytes | None]:
    def read() -> bytes | None:
        if fs is None:
            return None
        try:
            e, stream, size = collect.resolve(
                fs, int(c["meta_addr"]), c.get("meta_seq"), c.get("stream")
            )
        except (collect.Refused, OSError, RuntimeError, ValueError):
            return None
        if size > max_file:
            return None
        data = bytearray()
        while len(data) < size:
            chunk = fs.read(e, len(data), min(collect.CHUNK, size - len(data)), stream)
            if not chunk:
                return None
            data += chunk
        return bytes(data)

    return read


def run(img: Any, args: dict[str, Any], emit: Callable[[dict[str, Any]], bool]) -> dict[str, int]:
    from disk_worker.probe import scan_yara  # noqa: PLC0415 - phase 5's module

    deadline = time.monotonic() + float(args["deadline_s"])
    rule_dirs = [Path(p) for p in args["rule_dirs"]]
    counts = scan_yara.scan(rule_dirs, items(img, args), emit, deadline)
    return {str(k)[:64]: int(v) for k, v in dict(counts).items()}


__all__ = ["ScanItem", "items", "run"]
