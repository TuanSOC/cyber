"""The ingest hand-off of a disk result (M9 phase 1 entry point; phase 7 owns the body, RT9).

`hand_off(job, msg) -> None`: called by the shared ingest worker for a disk `finished` event,
after it validated the event: moves the job deadline by `DISK_INGEST_TIMEOUT_S` and sends the
task `disk.ingest` to the queue `ingest_disk`, so the long transaction runs on the dedicated
disk ingest worker and never delays the shared ingest queue (reaper, correlation, other
analyzers).
"""

from typing import Any

from cyberlab_jobs import IngestMessageV1


async def hand_off(job: Any, msg: IngestMessageV1) -> None:
    raise NotImplementedError("the disk ingest hand-off lands with M9 phase 7")
