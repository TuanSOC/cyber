"""M9 phase 7: the disk deadlines and the reaper.

Queued: the queue TTL. Started: ANALYSIS_DISK_TIMEOUT_S + the M2 grace. Handed off: the
hand-off time + DISK_INGEST_TIMEOUT_S; past it the job is `timed_out` whether the reaper or the
late ingest itself notices, and the late ingest writes nothing. A job row its ingest holds is
skipped by the reaper, never waited for.
"""

from datetime import timedelta

from sqlalchemy import select, update

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import lifecycle
from app.modules.analysis.models import AnalysisJob, AnalysisJobIndex
from app.workers import ingest, reaper
from tests import disk_results as dr
from tests.analysis_helpers import SentJobs
from tests.disk_results import HandOffs
from tests.disk_results import handoffs as handoffs  # noqa: F401 (fixture)
from tests.disk_results import sent as sent  # noqa: F401 (fixture)


async def _expire(job_id: object) -> None:
    async with tenant_session(None, None) as session:
        await session.execute(
            update(AnalysisJobIndex)
            .where(AnalysisJobIndex.job_id == job_id)
            .values(deadline_at=lifecycle.now() - timedelta(seconds=1))
        )


async def test_a_disk_job_never_started_is_reaped(sent: SentJobs) -> None:
    _, _, item = await dr.queued_job(sent)
    index = await dr.index_of_job(item.job_id)
    ttl = timedelta(seconds=get_settings().analysis_queue_ttl_s)
    assert abs(index.deadline_at - (lifecycle.now() + ttl)) < timedelta(minutes=1)
    await _expire(item.job_id)
    assert await reaper.reap() >= 1
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "never_started")


async def test_a_started_disk_job_gets_the_disk_deadline(sent: SentJobs) -> None:
    _, _, item = await dr.queued_job(sent)
    before = lifecycle.now()
    await ingest.handle_event(dr.started(item))
    index = await dr.index_of_job(item.job_id)
    assert index.status == "running"
    budget = timedelta(seconds=get_settings().analysis_disk_timeout_s + ingest.RUNNING_GRACE_S)
    assert before + budget <= index.deadline_at <= lifecycle.now() + budget
    await _expire(item.job_id)
    assert await reaper.reap() >= 1
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "timed_out")


async def test_a_handed_off_job_reaped_before_its_ingest_writes_nothing(
    sent: SentJobs, handoffs: HandOffs
) -> None:
    _, _, item = await dr.queued_job(sent)
    await ingest.handle_event(dr.started(item))
    version = dr.put_result(item.organization_id, item.job_id, dr.framed(dr.retargeted(item)))
    await ingest.handle_event(dr.finished(item, version))
    await _expire(item.job_id)
    assert await reaper.reap() >= 1
    await ingest.handle_disk_ingest(handoffs[-1])  # the disk ingest worker, too late
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "timed_out")
    assert await dr.row_counts(item.organization_id, item.job_id) == dr.EMPTY


async def test_an_ingest_past_its_deadline_rolls_back_and_times_out(
    sent: SentJobs, handoffs: HandOffs
) -> None:
    """The reaper skipped the job (its ingest held the row): the ingest fails it itself."""
    _, _, item = await dr.queued_job(sent)
    await ingest.handle_event(dr.started(item))
    version = dr.put_result(item.organization_id, item.job_id, dr.framed(dr.retargeted(item)))
    await ingest.handle_event(dr.finished(item, version))
    await _expire(item.job_id)
    await ingest.handle_disk_ingest(handoffs[-1])
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "timed_out")
    assert await dr.row_counts(item.organization_id, item.job_id) == dr.EMPTY


async def test_the_reaper_skips_a_disk_job_its_ingest_holds(sent: SentJobs) -> None:
    _, _, item = await dr.queued_job(sent)
    await _expire(item.job_id)
    async with tenant_session(item.organization_id, None) as holder:
        await holder.execute(
            select(AnalysisJob.id)
            .where(AnalysisJob.id == item.job_id)
            .with_for_update(key_share=True)
        )
        assert await reaper.reap() == 0  # returns at once: skipped, not waited for
    assert (await dr.job_of(item)).status == "queued"
    assert await reaper.reap() >= 1  # the next tick, once the row is free
    assert (await dr.job_of(item)).status == "failed"
