"""M9 phase 7: the trusted ingest of a `disk.v1` success on the disk ingest worker, all rows or
none (RT9: `handle_event` only hands the report off; `handle_disk_ingest` writes it).

Each hostile stream must fail the job `invalid_result` and leave every result table empty.
"""

import uuid
from typing import Any

import pytest
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.disk_forensics import stream
from app.modules.disk_forensics.models import DiskImage
from app.modules.pcap_analysis.models import AnalysisFinding
from tests import disk_results as dr
from tests.analysis_helpers import SentJobs
from tests.disk_results import HandOffs
from tests.disk_results import handoffs as handoffs  # noqa: F401 (fixture)
from tests.disk_results import sent as sent  # noqa: F401 (fixture)
from tests.pcap_results import encode


async def _audits(org_id: uuid.UUID, action: str) -> list[AuditLog]:
    async with tenant_session(org_id, None) as session:
        rows = await session.execute(select(AuditLog).where(AuditLog.action == action))
        return list(rows.scalars())


async def test_a_disk_result_is_written_in_one_transaction(
    sent: SentJobs, handoffs: HandOffs
) -> None:
    reg, ids, item = await dr.queued_job(sent, segments=2)
    message = await dr.deliver(item, dr.framed(dr.retargeted(item)), handoffs)
    assert len(handoffs) == 1
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("succeeded", None)
    assert job.result_version_id == message["result_version_id"]
    assert job.worker_version == dr.WORKER
    assert await dr.row_counts(reg.org_id, item.job_id) == dr.WINDOWS_TABLES

    summary = job.summary
    assert summary["schema_version"] == "disk.v1"
    assert (summary["profile"], summary["engine"], summary["timeline_engine"]) == (
        "triage",
        "tsk",
        "replay",
    )
    # The trusted identity is ours (segment count and total size); the media hash is the
    # worker's (RT17).
    assert summary["image"]["segments"] == 2
    assert summary["image"]["size_bytes"] == sum(s.size_bytes for s in item.segments)
    assert summary["image"]["format"] == "split_raw"
    counts = summary["counts"]
    assert (counts["files"], counts["events"], counts["findings"]) == (306, 8, 3)
    assert (counts["unresolved_finding_refs"], counts["unresolved_event_files"]) == (2, 1)
    assert summary["known_hash_join"] == "ok" and counts["known_hash_findings"] == 0

    # `analyzed` custody on every segment, the job's audit entry once.
    for ordinal, evidence_id in enumerate(ids):
        custody = (
            await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/custody")
        ).json()["items"]
        [analyzed] = [e for e in custody if e["action"] == "analyzed"]
        assert analyzed["details"]["job_id"] == str(item.job_id)
        if ordinal:
            assert analyzed["details"]["ordinal"] == ordinal
    [succeeded] = await _audits(reg.org_id, "analysis.succeeded")
    assert succeeded.details is not None and succeeded.details["counts"]["files"] == 306

    image = await dr.scalar(reg.org_id, select(DiskImage).where(DiskImage.job_id == item.job_id))
    assert (image.format, image.segments, int(image.media_size)) == ("split_raw", 2, 67108864)
    assert image.media_hash_status is None and len(image.stages) == 6


async def test_refs_resolve_to_row_ids(sent: SentJobs, handoffs: HandOffs) -> None:
    _, _, item = await dr.queued_job(sent)
    objs = dr.retargeted(item)
    exe = objs[dr.index_of(objs, "file", path="Windows/System32/sys000.dll")]
    ref = stream.file_ref(exe["partition_index"], exe["meta_addr"], exe["meta_seq"], None)
    event_i = dr.index_of(objs, "event", ordinal=0)
    objs[event_i] = {
        **objs[event_i],
        "file": {"partition_index": 1, "meta_addr": exe["meta_addr"], "meta_seq": 1},
    }
    finding_i = dr.index_of(objs, "finding")
    objs[finding_i] = {**objs[finding_i], "evidence_refs": [ref, "event:0", "event:404"]}
    await dr.deliver(item, dr.framed(objs), handoffs)
    job = await dr.job_of(item)
    assert job.status == "succeeded", job.error_code

    [file_row] = await dr.rows(
        item.organization_id,
        "SELECT id, ext, meta_addr FROM disk_files WHERE job_id = :job AND path = :path",
        job=item.job_id,
        path=exe["path"],
    )
    assert (file_row.ext, int(file_row.meta_addr)) == ("dll", 67)
    [event] = await dr.rows(
        item.organization_id,
        "SELECT id, file_id FROM disk_events WHERE job_id = :job AND ordinal = 0",
        job=item.job_id,
    )
    assert event.file_id == file_row.id
    refs = await dr.scalar(
        item.organization_id,
        select(AnalysisFinding.evidence_refs).where(
            AnalysisFinding.job_id == item.job_id,
            AnalysisFinding.finding_id == uuid.UUID(objs[finding_i]["finding_id"]),
        ),
    )
    assert refs == [f"file:{file_row.id}", f"event:{event.id}"]
    [timeline] = await dr.rows(
        item.organization_id,
        "SELECT ref FROM analysis_timeline WHERE job_id = :job AND event = 'logon'",
        job=item.job_id,
    )
    assert timeline.ref == f"event:{event.id}"


def _splice(objs: list[dict[str, Any]], case: str) -> list[dict[str, Any]]:
    file_i = dr.index_of(objs, "file")
    if case == "duplicate_file":
        objs.insert(file_i + 1, dict(objs[file_i]))
    elif case == "segments_mismatch":
        objs[0]["image"]["segments"] = 3
        objs[0]["image"]["format"] = "split_raw"
    elif case == "wrong_job":
        objs[0]["job_id"] = str(uuid.uuid4())
    elif case == "nul_path":
        objs[file_i]["path"] = "Windows/sys\u0000tem.dll"
    elif case == "unknown_partition":
        objs[file_i]["partition_index"] = 99
    elif case == "out_of_order":
        objs.append(dict(objs[file_i]) | {"meta_addr": 777_777, "name": "late"})
    return objs


@pytest.mark.parametrize(
    "case",
    [
        "duplicate_file",
        "segments_mismatch",
        "wrong_job",
        "nul_path",
        "unknown_partition",
        "out_of_order",
    ],
)
async def test_a_hostile_stream_writes_nothing(
    sent: SentJobs, handoffs: HandOffs, case: str
) -> None:
    _, _, item = await dr.queued_job(sent)
    await dr.deliver(item, dr.framed(_splice(dr.retargeted(item), case)), handoffs)
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")
    assert job.result_version_id is None and job.summary == {}
    assert await dr.row_counts(item.organization_id, item.job_id) == dr.EMPTY


async def test_a_spliced_or_truncated_stream_writes_nothing(
    sent: SentJobs, handoffs: HandOffs
) -> None:
    _, _, item = await dr.queued_job(sent)
    lines = [dr.dumps(o) for o in dr.retargeted(item)]
    # The trailer counts one line less than the stream holds.
    data = encode(lines, trailer={"line_count": 2})
    await dr.deliver(item, data, handoffs)
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")
    assert await dr.row_counts(item.organization_id, item.job_id) == dr.EMPTY


async def test_a_redelivered_ingest_is_a_no_op(sent: SentJobs, handoffs: HandOffs) -> None:
    from app.workers import ingest

    _, _, item = await dr.queued_job(sent)
    await dr.deliver(item, dr.framed(dr.retargeted(item)), handoffs)
    assert (await dr.job_of(item)).status == "succeeded"
    # Broker redelivery of the hand-off: re-authenticated, then the job is final.
    await ingest.handle_disk_ingest(handoffs[-1])
    assert await dr.row_counts(item.organization_id, item.job_id) == dr.WINDOWS_TABLES


async def test_a_disk_report_with_a_bad_token_is_dropped(
    sent: SentJobs, handoffs: HandOffs
) -> None:
    from app.workers import ingest

    _, _, item = await dr.queued_job(sent)
    version = dr.put_result(item.organization_id, item.job_id, dr.framed(dr.retargeted(item)))
    forged = dr.finished(item, version) | {"ingest_token": "x" * 43}
    await ingest.handle_event(forged)
    await ingest.handle_disk_ingest(forged)
    assert handoffs == []
    assert (await dr.job_of(item)).status == "queued"
    assert await dr.row_counts(item.organization_id, item.job_id) == dr.EMPTY
