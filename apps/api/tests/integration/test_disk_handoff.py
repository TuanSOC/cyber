"""M9 phase 7 (RT9): the shared ingest worker only validates a disk report and hands it off.

It never downloads or reads the stream, moves the deadline by DISK_INGEST_TIMEOUT_S under the
job lock (never waiting for a disk ingest that holds it), and publishes `disk.ingest` to the
disk ingest worker's own queue; other analyzers' results keep ingesting meanwhile.
"""

from datetime import timedelta
from typing import Any

import pytest
from cyberlab_jobs import DISK_INGEST
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import lifecycle
from app.modules.analysis.models import AnalysisJob
from app.modules.disk_forensics import handoff
from app.workers import ingest
from tests import disk_results as dr
from tests import pcap_results as pr
from tests.analysis_helpers import SentJobs, new_case, tiny_pcap, upload
from tests.disk_results import HandOffs
from tests.disk_results import handoffs as handoffs  # noqa: F401 (fixture)
from tests.disk_results import sent as sent  # noqa: F401 (fixture)


async def test_the_shared_worker_hands_off_without_reading(
    sent: SentJobs, handoffs: HandOffs, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def no_download(*_: Any) -> None:
        raise AssertionError("the shared ingest worker must not download a disk result")

    monkeypatch.setattr(ingest, "_download_result", no_download)
    _, _, item = await dr.queued_job(sent)
    await ingest.handle_event(dr.started(item))
    version = dr.put_result(item.organization_id, item.job_id, dr.framed(dr.retargeted(item)))
    before = lifecycle.now()
    message = dr.finished(item, version)
    await ingest.handle_event(message)

    assert handoffs == [message | {"schema_version": "ingest.v1", "error_code": None}]
    job = await dr.job_of(item)
    assert job.status == "running"  # still active: the disk ingest worker finishes it
    index = await dr.index_of_job(item.job_id)
    budget = timedelta(seconds=get_settings().disk_ingest_timeout_s)
    assert before + budget <= index.deadline_at <= lifecycle.now() + budget


async def test_the_hand_off_publishes_disk_ingest_on_its_queue(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.workers.celery_app import celery_app

    calls: list[tuple[str, dict[str, Any]]] = []

    def capture(name: str, **kwargs: Any) -> None:
        calls.append((name, kwargs))

    monkeypatch.setattr(celery_app, "send_task", capture)
    _, _, item = await dr.queued_job(sent)
    version = dr.put_result(item.organization_id, item.job_id, dr.framed(dr.retargeted(item)))
    await ingest.handle_event(dr.finished(item, version))
    [(name, kwargs)] = calls
    settings = get_settings()
    assert name == DISK_INGEST
    assert kwargs["queue"] == f"{settings.queue_prefix}ingest_disk"
    assert kwargs["kwargs"]["message"]["result_version_id"] == version


async def test_a_failed_publish_is_retried_by_the_ingest_task(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(_: dict[str, Any]) -> None:
        raise OSError("broker down")

    monkeypatch.setattr(handoff, "publish", broken)
    _, _, item = await dr.queued_job(sent)
    version = dr.put_result(item.organization_id, item.job_id, dr.framed(dr.retargeted(item)))
    with pytest.raises(handoff.HandOffBusy):
        await ingest.handle_event(dr.finished(item, version))
    assert isinstance(handoff.HandOffBusy(), ingest.TRANSIENT_ERRORS)
    assert (await dr.job_of(item)).status == "queued"  # never failed `ingest_error`


async def test_a_job_held_by_its_ingest_is_never_waited_for(
    sent: SentJobs, handoffs: HandOffs
) -> None:
    """A disk ingest holds the job row (its rows' foreign keys take KEY SHARE)."""
    _, _, item = await dr.queued_job(sent)
    job = await dr.job_of(item)
    async with tenant_session(item.organization_id, None) as holder:
        await holder.execute(
            select(AnalysisJob.id)
            .where(AnalysisJob.id == item.job_id)
            .with_for_update(key_share=True)
        )
        with pytest.raises(handoff.HandOffBusy):
            await handoff.move_deadline(job)
    assert handoffs == []


async def test_other_results_ingest_while_a_disk_result_waits(
    sent: SentJobs, handoffs: HandOffs
) -> None:
    """The shared queue keeps serving: a pcap result is ingested while the disk one is handed
    off (and not yet ingested by the disk ingest worker)."""
    reg, _, disk_item = await dr.queued_job(sent)
    disk_version = dr.put_result(
        disk_item.organization_id, disk_item.job_id, dr.framed(dr.retargeted(disk_item))
    )
    await ingest.handle_event(dr.finished(disk_item, disk_version))
    assert len(handoffs) == 1

    capture = await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap(), "x.pcap")
    pcap_item = next(i for i in sent if str(i.evidence_id) == capture["id"])
    await pr.deliver(pcap_item, pr.stream(pcap_item.job_id))
    async with tenant_session(reg.org_id, None) as session:
        pcap_job = await session.get(AnalysisJob, pcap_item.job_id)
    assert pcap_job is not None
    assert pcap_job.status == "succeeded", pcap_job.error_code
    assert (await dr.job_of(disk_item)).status == "queued"
    # Then the disk ingest worker takes its turn.
    await ingest.handle_disk_ingest(handoffs[0])
    assert (await dr.job_of(disk_item)).status == "succeeded"
