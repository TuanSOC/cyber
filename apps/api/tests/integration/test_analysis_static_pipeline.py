"""End to end through the real broker and the real (test) static-worker container.

The worker consumes `test.static`, fetches the sample by presigned URL, runs its engines as
the unprivileged uid and reports on `test.ingest`; these tests feed those reports to the
real ingest handler and read the results back through the API.
"""

import gzip
from collections.abc import Iterator

import pytest
from cyberlab_jobs.static import STATIC_LINE_ADAPTER, StaticResultHeader

from app.core.clients import get_minio
from app.core.config import get_settings
from app.modules.analysis import dispatch
from tests.analysis_helpers import (
    jobs_for,
    new_case,
    pe_bytes,
    purge_test_queues,
    run_ingest_until,
    upload,
)
from tests.factories import register

FINAL = {"succeeded", "failed"}
# ClamAV loads its database per scan (15-20 s); the full profile adds capa and FLOSS.
TIMEOUT_S = 300.0


@pytest.fixture(autouse=True)
def _clean_queues() -> Iterator[None]:
    purge_test_queues()
    yield
    purge_test_queues()


def _result_lines(org_id: object, job_id: str) -> list[bytes]:
    response = get_minio().get_object(
        get_settings().results_bucket, dispatch.result_key(org_id, job_id)
    )
    try:
        return gzip.decompress(response.read()).splitlines()
    finally:
        response.close()
        response.release_conn()


@pytest.mark.parametrize(
    ("content", "profile", "file_format"),
    [(b"plain notes, nothing to see\n", "av", "other"), (pe_bytes(), "full", "pe")],
    ids=["av-profile", "full-profile"],
)
async def test_worker_analyzes_an_uploaded_sample(
    content: bytes, profile: str, file_format: str
) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), content, "sample.bin")
    [job] = await jobs_for(reg.client, reg.org_id, evidence["id"])
    assert (job["analyzer"], job["profile"]) == ("static", profile)

    seen = await run_ingest_until(job["id"], FINAL, timeout_s=TIMEOUT_S)
    [job] = await jobs_for(reg.client, reg.org_id, evidence["id"])
    assert job["status"] == "succeeded", seen
    assert seen == ["started:None:None", "finished:succeeded:None"]

    lines = _result_lines(reg.org_id, job["id"])
    header = StaticResultHeader.model_validate_json(lines[0])
    assert str(header.job_id) == job["id"] and header.file_format == file_format
    assert any(name.startswith("clamav") for name in header.tool_versions), header
    records = [STATIC_LINE_ADAPTER.validate_json(line) for line in lines[1:-1]]
    [sample] = [r for r in records if r.kind == "sample"]
    assert sample.sha256 == evidence["hashes"]["sha256"] and sample.size == len(content)

    base = f"/api/v1/orgs/{reg.org_id}/analyses/{job['id']}"
    report = await reg.client.get(f"{base}/report")
    assert report.status_code == 200, report.text
    assert report.json()["evidence"]["hashes"]["sha256"] == evidence["hashes"]["sha256"]
