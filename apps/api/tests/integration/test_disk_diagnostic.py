"""M9 phase 7: the diagnostic stream of a failed disk job (`no_supported_filesystem` /
`unsupported_disk_format`): the image and partitions are stored, the job fails with the
worker's code, on the disk ingest worker; anything else in it writes nothing."""

import pytest

from tests import disk_results as dr
from tests.analysis_helpers import SentJobs
from tests.disk_results import HandOffs
from tests.disk_results import handoffs as handoffs  # noqa: F401 (fixture)
from tests.disk_results import sent as sent  # noqa: F401 (fixture)

DIAGNOSTIC_TABLES = {**dr.EMPTY, "disk_images": 1, "disk_partitions": 2}


@pytest.mark.parametrize("code", ["no_supported_filesystem", "unsupported_disk_format"])
async def test_a_diagnostic_stores_the_layout_and_fails_the_job(
    sent: SentJobs, handoffs: HandOffs, code: str
) -> None:
    _, _, item = await dr.queued_job(sent)
    data = dr.framed(dr.retargeted(item, dr.DIAGNOSTIC))
    message = await dr.deliver(item, data, handoffs, outcome="failed", error_code=code)
    assert len(handoffs) == 1  # read by the disk ingest worker, not the shared one
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("failed", code)
    assert job.result_version_id == message["result_version_id"]
    assert job.summary["counts"]["partitions"] == 2
    assert job.summary["engine_errors"] == ["no_supported_filesystem"]
    assert await dr.row_counts(item.organization_id, item.job_id) == DIAGNOSTIC_TABLES
    [partition] = await dr.rows(
        item.organization_id,
        'SELECT fs_status, error_code FROM disk_partitions WHERE job_id = :job AND "index" = 0',
        job=item.job_id,
    )
    assert partition.fs_status == "encrypted"
    assert partition.error_code == "unsupported_disk_format"


async def test_a_diagnostic_with_records_writes_nothing(
    sent: SentJobs, handoffs: HandOffs
) -> None:
    _, _, item = await dr.queued_job(sent)
    objs = dr.retargeted(item, dr.DIAGNOSTIC)
    windows = dr.parsed(dr.WINDOWS)
    objs.append(windows[dr.index_of(windows, "file")])
    await dr.deliver(
        item, dr.framed(objs), handoffs, outcome="failed", error_code="no_supported_filesystem"
    )
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")
    assert await dr.row_counts(item.organization_id, item.job_id) == dr.EMPTY


async def test_a_failed_report_with_another_code_is_refused_unread(
    sent: SentJobs, handoffs: HandOffs
) -> None:
    _, _, item = await dr.queued_job(sent)
    data = dr.framed(dr.retargeted(item, dr.DIAGNOSTIC))
    await dr.deliver(item, data, handoffs, outcome="failed", error_code="walk_memory")
    assert handoffs == []
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")
    assert await dr.row_counts(item.organization_id, item.job_id) == dr.EMPTY


async def test_a_failed_report_without_a_result_fails_the_job(
    sent: SentJobs, handoffs: HandOffs
) -> None:
    from app.workers import ingest

    _, _, item = await dr.queued_job(sent)
    await ingest.handle_event(dr.finished(item, None, outcome="failed", error_code="walk_memory"))
    assert handoffs == []
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "walk_memory")
