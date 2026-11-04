"""`facts` mode: hashes, entropy, libmagic type, ssdeep (ppdeep; slow, last).

The archive pre-check is its own probe mode (`archive`), run in its own process and out dir
before this one: libmagic, parsing the same hostile bytes here, cannot touch its output.
"""

import hashlib
import sys
from collections import Counter
from pathlib import Path

from static_worker.probe.common import emit, entropy_of, error, text

CHUNK = 1024 * 1024


def run(sample: Path, *, ssdeep_max_bytes: int) -> None:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()  # noqa: S324 - IDs
    counts: Counter[int] = Counter()
    size = 0
    with open(sample, "rb") as f:
        while chunk := f.read(CHUNK):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            counts.update(chunk)
    record: dict[str, object] = {
        "kind": "facts",
        "size": size,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "entropy": entropy_of(counts, size),
        "file_type": None,
        "mime": None,
    }
    try:
        import magic

        record["file_type"] = text(magic.from_file(str(sample)), 255)
        record["mime"] = text(magic.from_file(str(sample), mime=True), 128)
    except Exception as exc:  # one fact failing never hides the others
        error("libmagic_failed", type(exc).__name__)
    emit(record)
    sys.stdout.flush()
    # Last: ppdeep is pure Python (~0.2 MiB/s); a timeout here loses only the fuzzy hash.
    if size <= ssdeep_max_bytes:
        try:
            import ppdeep

            emit({"kind": "ssdeep", "value": text(ppdeep.hash(sample.read_bytes()), 128)})
        except Exception as exc:
            error("ssdeep_failed", type(exc).__name__)
