"""Trusted ingest of a `disk-export.v1` result (M9 phase 1 entry point; phase 10 owns it):
marks each `disk_exports` row `ready` (object key, exact version id, size, the untrusted
worker sha256) or `failed`."""

from pathlib import Path
from typing import Any

from cyberlab_jobs import IngestMessageV1


async def ingest_disk_export(job: Any, msg: IngestMessageV1, path: Path) -> None:
    raise NotImplementedError("disk export ingest lands with M9 phase 10")
