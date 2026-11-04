"""End to end through the real broker and the real (test) pcap-worker container.

The worker consumes `test.pcap`, fetches evidence by presigned URL, runs its tools as the
unprivileged uid and reports on `test.ingest`; these tests feed those reports to the real
ingest handler.
"""

import dataclasses
import gzip
from collections.abc import Iterator

import pytest
from cyberlab_jobs.results import RECORD_ADAPTER, ResultHeader, ResultTrailer

from app.core.clients import get_minio
from app.core.config import get_settings
from app.modules.analysis import dispatch
from tests.analysis_helpers import (
    jobs_for,
    new_case,
    purge_test_queues,
    run_ingest_until,
    tiny_pcap,
    upload,
)
from tests.factories import csrf, register

FINAL = {"succeeded", "failed"}


@pytest.fixture(autouse=True)
def _clean_queues() -> Iterator[None]:
    purge_test_queues()
    yield
    purge_test_queues()


async def test_worker_analyzes_an_uploaded_capture() -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    [job] = await jobs_for(reg.client, reg.org_id, evidence["id"])

    seen = await run_ingest_until(job["id"], FINAL)
    [job] = await jobs_for(reg.client, reg.org_id, evidence["id"])
    assert job["status"] == "succeeded", seen
    assert seen == ["started:None:None", "finished:succeeded:None"]

    # The result object (the version ingest recorded) is a valid pcap.v1 stream.
    key = dispatch.result_key(reg.org_id, job["id"])
    response = get_minio().get_object(get_settings().results_bucket, key)
    try:
        lines = gzip.decompress(response.read()).splitlines()
    finally:
        response.close()
        response.release_conn()
    header = ResultHeader.model_validate_json(lines[0])
    assert str(header.job_id) == job["id"] and header.capture_format == "pcap"
    assert {"zeek", "tshark", "suricata", "rules_sha256"} <= set(header.tool_versions)
    stats = RECORD_ADAPTER.validate_json(lines[1])
    assert stats.kind == "stats" and stats.packets == 3
    assert ResultTrailer.model_validate_json(lines[-1]).line_count == len(lines) - 1


async def _manual_job(
    monkeypatch: pytest.MonkeyPatch, content: bytes
) -> tuple[str, dispatch.DispatchInput, object]:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), content)
    captured: list[dispatch.DispatchInput] = []

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    response = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}/analyses",
        json={"analyzer": "pcap"},
        headers=csrf(reg.client),
    )
    assert response.status_code == 201, response.text
    monkeypatch.undo()
    return response.json()["id"], captured[0], reg


async def test_hash_mismatch_is_refused_before_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    job_id, item, reg = await _manual_job(monkeypatch, b"not a capture, never auto-analyzed")
    await dispatch.send(dataclasses.replace(item, sha256="0" * 64))

    seen = await run_ingest_until(job_id, FINAL)
    assert seen[-1] == "finished:failed:integrity_mismatch"


async def test_compressed_capture_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    job_id, item, _ = await _manual_job(monkeypatch, gzip.compress(tiny_pcap()))
    await dispatch.send(item)

    seen = await run_ingest_until(job_id, FINAL)
    assert seen[-1] == "finished:failed:unsupported_capture_format"


async def test_size_mismatch_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    job_id, item, _ = await _manual_job(monkeypatch, b"seven b")
    await dispatch.send(dataclasses.replace(item, size_bytes=3))

    seen = await run_ingest_until(job_id, FINAL)
    assert seen[-1] == "finished:failed:integrity_mismatch"
