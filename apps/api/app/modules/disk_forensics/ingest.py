"""Trusted ingest of a `disk.v1` result (M9 phase 1 entry points; phase 7 owns the bodies).

Run by the disk ingest worker (task `disk.ingest`, queue `ingest_disk`; RT9): validate the
whole stream (pass 1), then one transaction (pass 2): `disk_images`, `disk_partitions`,
`disk_files`, `disk_events`, `analysis_findings`, `iocs`, `analysis_timeline`, custody and the
in-org known-hash join. A diagnostic stream (`no_supported_filesystem`,
`unsupported_disk_format`) stores the image and the partitions and fails the job.
"""

from pathlib import Path
from typing import Any

from cyberlab_jobs import IngestMessageV1


async def ingest_disk(job: Any, msg: IngestMessageV1, path: Path) -> None:
    raise NotImplementedError("disk ingest lands with M9 phase 7")


async def ingest_disk_diagnostic(job: Any, msg: IngestMessageV1, path: Path) -> None:
    raise NotImplementedError("disk diagnostic ingest lands with M9 phase 7")
