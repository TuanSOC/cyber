"""The ingest hand-off of a disk result (M9 phase 7, RT9).

`hand_off(job, msg) -> None`: called by the shared ingest worker (solo; it also runs the
reaper and the M7 correlation tick) for a disk report that carries a result, after it
authenticated the report (token, org from our own index). It never reads the stream:

1. under the job lock (taken with SKIP LOCKED: a disk ingest in progress holds the job row
   through its foreign keys, and this worker must never wait for it), a still-active job's
   deadline becomes now + `DISK_INGEST_TIMEOUT_S`;
2. after that commits, the report goes to the queue `ingest_disk` as the task `disk.ingest`,
   which the dedicated disk ingest worker consumes alone.

A busy job row or a failed publish raises `HandOffBusy` (a ConnectionError: the `ingest.event`
task retries it with backoff). Redelivery is safe: `disk.ingest` re-authenticates, and its
guarded transition makes a second ingest of the same job a no-op.
"""

import logging
from datetime import timedelta
from typing import Any

import anyio
from cyberlab_jobs import DISK_INGEST, IngestMessageV1, Queues
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.core.threads import broker_limiter
from app.modules.analysis import lifecycle
from app.modules.analysis.models import ACTIVE, AnalysisJob, AnalysisJobIndex

log = logging.getLogger(__name__)

PUBLISH_TIMEOUT_S = 15


class HandOffBusy(ConnectionError):
    """The job row is locked (an ingest runs) or the broker refused the publish: retry."""


def _publish_sync(message: dict[str, Any]) -> None:
    from app.workers.celery_app import celery_app

    settings = get_settings()
    celery_app.send_task(
        DISK_INGEST,
        kwargs={"message": message},
        queue=Queues(settings.queue_prefix).ingest_disk,
        retry=True,
        retry_policy={"max_retries": 1, "interval_start": 0, "interval_step": 0.5},
    )


async def publish(message: dict[str, Any]) -> None:
    """Send `disk.ingest` (tests replace this to run the disk ingest in-process)."""
    with anyio.fail_after(PUBLISH_TIMEOUT_S):
        await anyio.to_thread.run_sync(
            _publish_sync, message, limiter=broker_limiter(), abandon_on_cancel=True
        )


async def move_deadline(job: AnalysisJob) -> bool:
    """The job's deadline becomes now + DISK_INGEST_TIMEOUT_S. False when the job is no
    longer active (nothing to hand off); raises HandOffBusy when its row is locked."""
    settings = get_settings()
    async with tenant_session(job.organization_id, None) as session:
        locked = await session.scalar(
            select(AnalysisJob)
            .where(AnalysisJob.id == job.id, AnalysisJob.organization_id == job.organization_id)
            .with_for_update(skip_locked=True)
        )
        if locked is None:
            raise HandOffBusy(f"analysis job {job.id} is locked")
        if locked.status not in ACTIVE:
            return False
        index = await session.scalar(
            select(AnalysisJobIndex)
            .where(AnalysisJobIndex.job_id == job.id)
            .with_for_update()
        )
        if index is None:  # pragma: no cover - written with the job
            return False
        index.deadline_at = lifecycle.now() + timedelta(seconds=settings.disk_ingest_timeout_s)
    return True


async def hand_off(job: Any, msg: IngestMessageV1) -> None:
    if not await move_deadline(job):
        return
    try:
        await publish(msg.model_dump(mode="json"))
    except Exception as exc:
        log.warning("disk ingest hand-off of analysis job %s not sent: %s", job.id, exc)
        raise HandOffBusy(f"disk ingest hand-off of analysis job {job.id} not sent") from exc
    log.info("analysis job %s handed off to the disk ingest worker", job.id)
