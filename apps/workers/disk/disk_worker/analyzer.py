"""The disk analysis of one job (M9 phase 1 stub; phase 2 owns the body, never the signature).

`analyze(job, dirs, config) -> Path`: download and verify the segments, then the stages (verify,
layout, walk, collect, scan, timeline), detections and the `disk.v1` stream; returns the gzip
NDJSON to upload. Raises `DiagnosticResult` (a diagnostic stream to upload with its error code)
or `JobFailed`. Phase 1: always `JobFailed("not_implemented")` after `started` was sent.
"""

from pathlib import Path

from cyberlab_jobs.disk import DIAGNOSTIC_ERROR_CODES, DiskJobV1
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from disk_worker.config import Config


class DiagnosticResult(JobFailed):
    """No file system could be opened (or the format was refused after the layout): `path` is
    the diagnostic stream (header, at most the partitions, trailer) to upload, then report
    failed / `code` with its version id."""

    def __init__(self, code: str, path: Path) -> None:
        if code not in DIAGNOSTIC_ERROR_CODES:
            raise ValueError(f"{code} is not a diagnostic error code")
        super().__init__(code)
        self.path = path


def analyze(job: DiskJobV1, dirs: sandbox.JobDirs, config: Config) -> Path:
    raise JobFailed("not_implemented", "disk analysis lands with M9 phase 2")
