"""Trusted handling of analyzer messages.

Nothing in a message is trusted beyond what it can prove: the job is located through the
non-tenant index (the org in the message must match), the per-job token must hash to the
stored digest, and only state-valid transitions apply.
"""

import hashlib
import hmac
import logging
from datetime import timedelta
from typing import Any

import anyio
import urllib3
from cyberlab_jobs import IngestEvent, IngestMessageV1, Outcome
from minio.error import S3Error
from pydantic import ValidationError
from sqlalchemy.exc import InterfaceError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.core.threads import evidence_io_limiter
from app.modules.analysis import lifecycle
from app.modules.analysis import repository as repo
from app.modules.analysis.dispatch import result_key
from app.modules.analysis.models import AnalysisJob, AnalysisJobIndex, AnalysisStatus
from app.modules.audit import service as audit
from app.modules.evidence.models import CustodyAction, EvidenceCustodyEvent

log = logging.getLogger(__name__)

# Time the worker gets after reporting `started` before the reaper fails the job.
RUNNING_GRACE_S = 120


def _token_ok(job: AnalysisJob, token: str) -> bool:
    digest = hashlib.sha256(token.encode()).hexdigest()
    return hmac.compare_digest(digest, job.ingest_token_sha256)


async def _result_exists(job: AnalysisJob, version_id: str) -> bool:
    bucket = get_settings().results_bucket
    key = result_key(job.organization_id, job.id)

    def stat() -> bool:
        try:
            get_minio().stat_object(bucket, key, version_id=version_id)
        except S3Error as exc:
            if exc.code in {"NoSuchKey", "NoSuchVersion", "InvalidArgument", "BadRequest"}:
                return False
            raise
        return True

    return await anyio.to_thread.run_sync(stat, limiter=evidence_io_limiter())


def _audit(session: AsyncSession, job: AnalysisJob, action: str, **details: Any) -> None:
    audit.record(
        session,
        action=action,
        org_id=job.organization_id,
        actor_id=None,
        target_type="analysis_job",
        target_id=job.id,
        details={"evidence_id": str(job.evidence_id), **details},
    )


async def _apply(
    session: AsyncSession, job: AnalysisJob, msg: IngestMessageV1, result_ok: bool
) -> None:
    settings = get_settings()
    if msg.event == IngestEvent.STARTED:
        if await lifecycle.transition(
            session,
            job,
            AnalysisStatus.RUNNING,
            allowed_from=(AnalysisStatus.QUEUED,),
            deadline_at=lifecycle.now()
            + timedelta(seconds=settings.analysis_timeout_s + RUNNING_GRACE_S),
        ):
            job.worker_version = msg.worker_version
        return

    active = (AnalysisStatus.QUEUED, AnalysisStatus.RUNNING)
    if msg.outcome == Outcome.SUCCEEDED:
        if not result_ok:
            await _fail(session, job, "invalid_result")
            return
        if await lifecycle.transition(session, job, AnalysisStatus.SUCCEEDED, allowed_from=active):
            job.result_version_id = msg.result_version_id
            job.worker_version = msg.worker_version
            session.add(
                EvidenceCustodyEvent(
                    organization_id=job.organization_id,
                    evidence_id=job.evidence_id,
                    action=CustodyAction.ANALYZED,
                    # The requester is accountable for the run; the worker acted for them.
                    actor_id=job.requested_by,
                    details={"job_id": str(job.id), "system": True, "worker": msg.worker_version},
                )
            )
            _audit(session, job, "analysis.succeeded", worker=msg.worker_version)
        return

    await _fail(session, job, msg.error_code or "analyzer_failed")


async def _fail(session: AsyncSession, job: AnalysisJob, code: str) -> None:
    if await lifecycle.transition(
        session,
        job,
        AnalysisStatus.FAILED,
        allowed_from=(AnalysisStatus.QUEUED, AnalysisStatus.RUNNING),
        error_code=code,
    ):
        _audit(session, job, "analysis.failed", error_code=code)


# Worth retrying (the task redelivers): infrastructure hiccups, never logic errors.
TRANSIENT_ERRORS: tuple[type[BaseException], ...] = (
    OperationalError,
    InterfaceError,
    ConnectionError,
    TimeoutError,
    urllib3.exceptions.HTTPError,
)


async def _authenticated_job(msg: IngestMessageV1) -> AnalysisJob | None:
    """The job a message may act on, or None (dropped). Takes no row locks."""
    async with tenant_session(None, None) as session:
        index = await session.get(AnalysisJobIndex, msg.job_id)
        org_id = index.organization_id if index else None
    if org_id is None or org_id != msg.organization_id:
        log.warning("dropping ingest message for unknown job %s", msg.job_id)
        return None
    # The org comes from our own index row, never from the message alone.
    async with tenant_session(org_id, None) as session:
        job = await session.get(AnalysisJob, msg.job_id)
    if job is None:
        return None
    if not _token_ok(job, msg.ingest_token):
        log.warning("dropping ingest message with a bad token for job %s", job.id)
        return None
    return job


async def handle_event(raw: dict[str, Any]) -> None:
    try:
        msg = IngestMessageV1.model_validate(raw)
    except ValidationError:
        log.warning("dropping invalid ingest message")
        return

    job = await _authenticated_job(msg)
    if job is None:
        return
    org_id = job.organization_id
    try:
        # Object-store I/O happens before the row lock is taken.
        result_ok = bool(
            msg.outcome == Outcome.SUCCEEDED
            and msg.result_version_id
            and await _result_exists(job, msg.result_version_id)
        )
        async with tenant_session(org_id, None) as session:
            locked = await repo.get_for_update(session, org_id, msg.job_id)
            if locked is not None:
                await _apply(session, locked, msg, result_ok)
    except TRANSIENT_ERRORS:
        raise
    except Exception:
        # A permanent failure must not be retried into silence: record it on the job.
        log.exception("ingest failed for analysis job %s", msg.job_id)
        async with tenant_session(org_id, None) as session:
            locked = await repo.get_for_update(session, org_id, msg.job_id)
            if locked is not None:
                await _fail(session, locked, "ingest_error")
