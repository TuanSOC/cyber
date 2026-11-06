"""The `disk.v1` / `disk-export.v1` job messages (M9 phase 1 entry points; phase 7 owns
`build_disk_message`, phase 10 `build_export_message`; neither changes the signature).

`build_disk_message(job, segments, settings) -> DiskJobV1`: one presigned GET per segment (the
exact evidence version, expiring with the queue TTL plus the job timeout), the profile, the
OS hint, `DiskLimits` from settings and the job deadline (RT5). No image cache key (RT1).
Blocking (MinIO): called from the dispatch worker thread.
"""

from typing import Any

from cyberlab_jobs.disk import DiskExportJobV1, DiskJobV1

from app.core.config import Settings


def build_disk_message(job: Any, segments: list[Any], settings: Settings) -> DiskJobV1:
    """`job`: the dispatch input of the disk job; `segments`: its ordered segment rows."""
    raise NotImplementedError("disk dispatch lands with M9 phase 7")


def build_export_message(
    job: Any, source_job: Any, segments: list[Any], exports: list[Any], settings: Settings
) -> DiskExportJobV1:
    """One presigned POST per exported file plus one for the result stream (phase 10)."""
    raise NotImplementedError("disk file export dispatch lands with M9 phase 10")
