"""Synthetic `memory.v1` result streams for the M8 phase-6 ingest tests.

The phase-1 fixtures (`packages/py-jobs/tests/fixtures/memory/`, hand-written, labelled
synthetic) carry fixed job ids and a placeholder image identity. `lines()` reads one without
its trailer and retargets it to a job and its evidence record, so tests can splice in hostile
lines; `pcap_results.encode()` appends a matching trailer and gzips (same framing).
"""

import hashlib
import json
import uuid
from typing import Any

from cyberlab_jobs import IngestMessageV1
from httpx import Response
from sqlalchemy import select, text

from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch
from app.modules.analysis.models import AnalysisJob
from app.modules.evidence.models import Evidence, EvidenceHash, HashAlgorithm
from app.workers import ingest
from tests.analysis_helpers import new_case
from tests.factories import Registered, csrf, register
from tests.memory_helpers import FIXTURES
from tests.pcap_results import encode, put_result

WORKER = "memory-worker/test"
WINDOWS = "windows_triage.ndjson"
LINUX = "linux_triage.ndjson"
DIAGNOSTIC = "symbols_missing.ndjson"
# Fixture job ids (the header of each file names its own).
FIXTURE_JOBS = {
    WINDOWS: uuid.UUID("6a1f0c1e-8d6b-4c55-9d9e-0d1b6f5a1001"),
    LINUX: uuid.UUID("6a1f0c1e-8d6b-4c55-9d9e-0d1b6f5a1002"),
    DIAGNOSTIC: uuid.UUID("6a1f0c1e-8d6b-4c55-9d9e-0d1b6f5a1003"),
}
FIXTURE_SIZE = 67_108_864
FIXTURE_SHA256 = "b" * 64
# Rows the Windows fixture writes per table.
WINDOWS_TABLES = {
    "memory_images": 1,
    "memory_processes": 40,
    "memory_connections": 3,
    "memory_injections": 1,
    "memory_artifacts": 6,
    "analysis_findings": 2,
    "iocs": 2,
    "analysis_timeline": 4,
}
WINDOWS_COUNTS = {
    "processes": 40,
    "connections": 3,
    "injections": 1,
    "artifacts": 6,
    "findings": 2,
    "iocs": 2,
    "timeline": 4,
    "orphan_refs": 0,
}


def dumps(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode() + b"\n"


def parsed(name: str = WINDOWS) -> list[dict[str, Any]]:
    """The fixture's lines as dicts, trailer dropped."""
    raw = (FIXTURES / name).read_bytes().splitlines()
    objs = [json.loads(line) for line in raw]
    assert objs[-1]["kind"] == "trailer"
    return objs[:-1]


def retarget(
    objs: list[dict[str, Any]], job_id: uuid.UUID | str, *, size: int, sha256: str
) -> list[dict[str, Any]]:
    out = []
    for obj in objs:
        obj = dict(obj)
        if obj["kind"] == "header":
            obj["job_id"] = str(job_id)
        elif obj["kind"] == "image":
            obj["size_bytes"], obj["sha256"] = size, sha256
        out.append(obj)
    return out


def lines(job_id: uuid.UUID | str, *, size: int, sha256: str, name: str = WINDOWS) -> list[bytes]:
    return [dumps(o) for o in retarget(parsed(name), job_id, size=size, sha256=sha256)]


def stream(job_id: uuid.UUID | str, *, size: int, sha256: str, name: str = WINDOWS) -> bytes:
    return encode(lines(job_id, size=size, sha256=sha256, name=name))


def index_of(objs: list[dict[str, Any]], kind: str, **match: Any) -> int:
    return next(
        i
        for i, o in enumerate(objs)
        if o["kind"] == kind and all(o.get(k) == v for k, v in match.items())
    )


async def evidence_identity(org_id: uuid.UUID, job_id: uuid.UUID) -> tuple[int, str]:
    """(size, sha256) of the stored evidence record of a job."""
    async with tenant_session(org_id, None) as session:
        job = await session.get(AnalysisJob, job_id)
        assert job is not None
        evidence = await session.get(Evidence, job.evidence_id)
        assert evidence is not None
        sha256 = await session.scalar(
            select(EvidenceHash.value).where(
                EvidenceHash.evidence_id == job.evidence_id,
                EvidenceHash.algorithm == HashAlgorithm.SHA256,
            )
        )
    assert sha256 is not None
    return evidence.size_bytes, sha256


def finished(
    item: dispatch.DispatchInput,
    version_id: str,
    *,
    outcome: str = "succeeded",
    error_code: str | None = None,
) -> dict[str, Any]:
    message: dict[str, Any] = {
        "job_id": str(item.job_id),
        "organization_id": str(item.organization_id),
        "ingest_token": item.ingest_token,
        "event": "finished",
        "outcome": outcome,
        "result_version_id": version_id,
        "worker_version": WORKER,
    }
    if error_code is not None:
        message["error_code"] = error_code
    return message


async def deliver(
    item: dispatch.DispatchInput,
    data: bytes,
    *,
    outcome: str = "succeeded",
    error_code: str | None = None,
) -> dict[str, Any]:
    """Upload a result for the job and hand ingest the analyzer's report."""
    version = put_result(item.organization_id, item.job_id, data)
    message = finished(item, version, outcome=outcome, error_code=error_code)
    await ingest.handle_event(message)
    return message


async def seed_results(org_id: uuid.UUID, job_id: uuid.UUID, name: str = WINDOWS) -> None:
    """Ingest a full memory result for a job whose token the test does not know."""
    size, sha256 = await evidence_identity(org_id, job_id)
    version_id = put_result(org_id, job_id, stream(job_id, size=size, sha256=sha256, name=name))
    async with tenant_session(org_id, None) as session:
        job = await session.get(AnalysisJob, job_id)
    assert job is not None
    message = IngestMessageV1(
        job_id=job_id,
        organization_id=org_id,
        ingest_token="t" * 43,
        event="finished",
        outcome="succeeded",
        result_version_id=version_id,
        worker_version=WORKER,
    )
    await ingest.ingest_success(job, message)
    async with tenant_session(org_id, None) as session:
        job = await session.get(AnalysisJob, job_id)
    assert job is not None and job.status == "succeeded", job and job.error_code


# --- API flow: a `kind=memory` upload and its memory job ---------------------------------

# A tiny stand-in "image" (zeros: no magic, never analyzed for real here).
IMAGE = b"\x00" * 4096
IMAGE_SHA256 = hashlib.sha256(IMAGE).hexdigest()
TABLES = tuple(WINDOWS_TABLES)


async def upload_memory(
    reg: Registered,
    case_id: str,
    content: bytes = IMAGE,
    filename: str = "host.raw",
    *,
    kind: str | None = "memory",
) -> Response:
    params = {"filename": filename}
    if kind is not None:
        params["kind"] = kind
    return await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}/evidence",
        params=params,
        content=content,
        headers={"Content-Type": "application/octet-stream", **csrf(reg.client)},
    )


async def run_memory(reg: Registered, evidence_id: str, **body: Any) -> Response:
    return await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/analyses",
        json={"analyzer": "memory", **body},
        headers=csrf(reg.client),
    )


async def queued_job(
    sent: list[dispatch.DispatchInput], **body: Any
) -> tuple[Registered, str, dispatch.DispatchInput]:
    """A new org with a `kind=memory` upload of IMAGE and a queued memory job on it
    (dispatch captured in `sent`)."""
    reg = await register()
    response = await upload_memory(reg, await new_case(reg))
    assert response.status_code == 201, response.text
    evidence_id = str(response.json()["id"])
    run = await run_memory(reg, evidence_id, **body)
    assert run.status_code == 201, run.text
    item = sent[-1]
    assert item.analyzer == "memory" and str(item.job_id) == run.json()["id"]
    return reg, evidence_id, item


def image_stream(
    item: dispatch.DispatchInput,
    name: str = WINDOWS,
    objs: list[dict[str, Any]] | None = None,
) -> bytes:
    """The fixture (or `objs`, already retargeted) framed for the job of `item`."""
    if objs is None:
        objs = retarget(parsed(name), item.job_id, size=len(IMAGE), sha256=IMAGE_SHA256)
    return encode([dumps(o) for o in objs])


def retargeted(item: dispatch.DispatchInput, name: str = WINDOWS) -> list[dict[str, Any]]:
    return retarget(parsed(name), item.job_id, size=len(IMAGE), sha256=IMAGE_SHA256)


async def job_of(item: dispatch.DispatchInput) -> AnalysisJob:
    async with tenant_session(item.organization_id, None) as session:
        job = await session.get(AnalysisJob, item.job_id)
    assert job is not None
    return job


async def row_counts(org_id: uuid.UUID, job_id: uuid.UUID) -> dict[str, int]:
    """Rows per result table for one job."""
    out: dict[str, int] = {}
    async with tenant_session(org_id, None) as session:
        for table in TABLES:
            out[table] = int(
                await session.scalar(
                    text(f"SELECT count(*) FROM {table} WHERE job_id = :job"), {"job": job_id}
                )
                or 0
            )
    return out
