"""M9 phase 10: the trusted ingest of a `disk-export.v1` result (on the disk ingest worker, RT9).

Each export becomes `ready` (the API-derived key, the exact version, the size, the worker's
sha256 stored as untrusted) or `failed` (the worker's code, or `invalid_result` when the stored
object is missing or not the reported size); the job succeeds when one file is ready. A hostile
stream fails the job `invalid_result` and every pending export with it; a worker failure (no
result) fails the job and its exports with the worker's code.
"""

import uuid
from typing import Any

from app.modules.analysis.dispatch import DispatchInput
from app.modules.disk_forensics.dispatch import export_key
from tests import disk_export_helpers as dx
from tests import disk_results as dr
from tests.disk_export_helpers import Captured
from tests.disk_export_helpers import exports as exports  # noqa: F401 (fixture)
from tests.disk_results import HandOffs
from tests.disk_results import handoffs as handoffs  # noqa: F401 (fixture)
from tests.disk_results import sent as sent  # noqa: F401 (fixture)
from tests.pcap_results import encode


async def _requested(exports: Captured, n: int = 2) -> tuple[dx.Source, DispatchInput, list[str]]:
    src = await dx.source_job()
    org = src.reg.org_id
    paths = [dx.UPDATER, "Windows/System32/sys000.dll"][:n]
    ids = [await dx.file_id(org, src.job_id, p) for p in paths]
    response = await dx.request(src.reg, src.job_id, ids)
    assert response.status_code == 202, response.text
    return src, exports.last[0], [i["id"] for i in response.json()["items"]]


async def test_ready_and_failed_files_in_one_succeeded_job(
    exports: Captured, handoffs: HandOffs, sent: Any
) -> None:
    src, item, [good, refused] = await _requested(exports)
    version = dx.put_export(item, good, dx.CONTENT)
    await dx.deliver_export(item, [dx.ok(good), dx.failed(refused)], handoffs)
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("succeeded", None)
    assert job.summary["counts"] == {"exports": 2, "ready": 1, "failed": 1, "bytes": 1024}
    row = await dx.export_row(src.reg.org_id, good)
    assert (row.state, row.size, row.object_version_id) == ("ready", 1024, version)
    assert row.object_key == export_key(item.job_id, good)
    assert row.worker_sha256 == dx.ok(good)["sha256"]
    other = await dx.export_row(src.reg.org_id, refused)
    assert (other.state, other.error_code, other.object_key) == (
        "failed",
        "disk_export_not_allowed",
        None,
    )


async def test_a_missing_or_resized_object_fails_its_file(
    exports: Captured, handoffs: HandOffs, sent: Any
) -> None:
    src, item, [missing, resized] = await _requested(exports)
    dx.put_export(item, resized, dx.CONTENT + b"x")  # one byte more than reported
    await dx.deliver_export(item, [dx.ok(missing), dx.ok(resized)], handoffs)
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")  # no file was ready
    for export_id in (missing, resized):
        row = await dx.export_row(src.reg.org_id, export_id)
        assert (row.state, row.error_code) == ("failed", "invalid_result")


async def test_all_files_refused_fail_the_job_with_their_code(
    exports: Captured, handoffs: HandOffs, sent: Any
) -> None:
    _, item, ids = await _requested(exports)
    await dx.deliver_export(item, [dx.failed(i) for i in ids], handoffs)
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "disk_export_not_allowed")
    assert job.summary["failed_codes"] == {"disk_export_not_allowed": 2}


async def test_hostile_streams_fail_the_job_and_every_export(
    exports: Captured, handoffs: HandOffs, sent: Any
) -> None:
    for files in (
        lambda ids: [dx.ok(ids[0])],  # an export missing from the report
        lambda ids: [dx.ok(ids[0]), dx.ok(ids[1]), dx.ok(uuid.uuid4())],  # an unknown one
        lambda ids: [dx.ok(ids[0]), dx.ok(ids[0])],  # one twice
    ):
        src, item, ids = await _requested(exports)
        for export_id in ids:
            dx.put_export(item, export_id, dx.CONTENT)
        await dx.deliver_export(item, files(ids), handoffs)
        job = await dr.job_of(item)
        assert (job.status, job.error_code) == ("failed", "invalid_result")
        for export_id in ids:
            row = await dx.export_row(src.reg.org_id, export_id)
            assert (row.state, row.error_code) == ("failed", "invalid_result")


async def test_a_disk_v1_stream_is_not_an_export_result(
    exports: Captured, handoffs: HandOffs, sent: Any
) -> None:
    src, item, ids = await _requested(exports, 1)
    data = encode([dr.dumps(o) for o in dr.retarget(dr.parsed(), item.job_id)])
    await dr.deliver(item, data, handoffs)
    assert (await dr.job_of(item)).error_code == "invalid_result"
    assert (await dx.export_row(src.reg.org_id, ids[0])).state == "failed"


async def test_a_worker_failure_fails_the_pending_exports(
    exports: Captured, handoffs: HandOffs, sent: Any
) -> None:
    from app.workers import ingest

    src, item, ids = await _requested(exports, 1)
    await ingest.handle_event(
        dr.finished(item, None, outcome="failed", error_code="integrity_mismatch")
    )
    job = await dr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "integrity_mismatch")
    row = await dx.export_row(src.reg.org_id, ids[0])
    assert (row.state, row.error_code) == ("failed", "integrity_mismatch")
