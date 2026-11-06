"""Synthetic `disk.v1` results and the API flow of a disk job, for the M9 phase-7 tests.

The phase-1 fixtures (`packages/py-jobs/tests/fixtures/disk/`, hand-written, labelled
synthetic) carry fixed job ids. `retargeted()` reads one without its trailer and points it at a
job and its segment count, so tests can splice in hostile lines; `pcap_results.encode()`
appends a matching trailer and gzips (same framing).

`deliver()` runs both halves of RT9 in-process: the shared worker's `handle_event` (which
only hands the report off; `handoff.publish` is captured by the `handoffs` fixture) and the
disk ingest worker's `handle_disk_ingest` on the captured message.
"""

import json
import uuid
from typing import Any

import pytest
from httpx import Response
from sqlalchemy import text

from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch
from app.modules.analysis.models import AnalysisJob, AnalysisJobIndex
from app.modules.disk_forensics import handoff
from app.workers import ingest
from tests.analysis_helpers import SentJobs, new_case
from tests.disk_helpers import FIXTURES
from tests.factories import Registered, csrf, register
from tests.pcap_results import encode, put_result

WORKER = "disk-worker/test"
WINDOWS = "windows_triage.ndjson"
LINUX = "linux_triage.ndjson"
DIAGNOSTIC = "no_supported_filesystem.ndjson"
# A tiny stand-in segment (zeros: no magic, never analyzed for real here).
SEGMENT = b"\x00" * 4096
TABLES = (
    "disk_images",
    "disk_partitions",
    "disk_files",
    "disk_events",
    "analysis_findings",
    "iocs",
    "analysis_timeline",
)
EMPTY = dict.fromkeys(TABLES, 0)
# Rows the Windows fixture writes per table (no known-hash match in a fresh org).
WINDOWS_TABLES = {
    "disk_images": 1,
    "disk_partitions": 2,
    "disk_files": 306,
    "disk_events": 8,
    "analysis_findings": 3,
    "iocs": 3,
    "analysis_timeline": 4,
}


class HandOffs(list[dict[str, Any]]):
    """`disk.ingest` messages captured instead of published."""


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


@pytest.fixture
def handoffs(monkeypatch: pytest.MonkeyPatch) -> HandOffs:
    captured = HandOffs()

    async def capture(message: dict[str, Any]) -> None:
        captured.append(message)

    monkeypatch.setattr(handoff, "publish", capture)
    return captured


def dumps(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def parsed(name: str = WINDOWS) -> list[dict[str, Any]]:
    """The fixture's lines as dicts, trailer dropped."""
    objs = [json.loads(line) for line in (FIXTURES / name).read_bytes().splitlines()]
    assert objs[-1]["kind"] == "trailer"
    return objs[:-1]


def retarget(
    objs: list[dict[str, Any]], job_id: uuid.UUID | str, *, segments: int = 1
) -> list[dict[str, Any]]:
    out = []
    for obj in objs:
        obj = json.loads(json.dumps(obj))
        if obj["kind"] == "header":
            obj["job_id"] = str(job_id)
            obj["image"]["segments"] = segments
            if segments > 1 and obj["image"]["format"] == "raw":
                obj["image"]["format"] = "split_raw"
        out.append(obj)
    return out


def retargeted(item: dispatch.DispatchInput, name: str = WINDOWS) -> list[dict[str, Any]]:
    return retarget(parsed(name), item.job_id, segments=len(item.segments))


def framed(objs: list[dict[str, Any]]) -> bytes:
    return encode([dumps(o) for o in objs])


def index_of(objs: list[dict[str, Any]], kind: str, **match: Any) -> int:
    return next(
        i
        for i, o in enumerate(objs)
        if o["kind"] == kind and all(o.get(k) == v for k, v in match.items())
    )


# --- API flow ---------------------------------------------------------------------------------


async def upload_disk(
    reg: Registered,
    case_id: str,
    content: bytes = SEGMENT,
    filename: str = "host.E01",
    *,
    kind: str | None = "disk",
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


async def upload_segments(reg: Registered, case_id: str, n: int) -> list[str]:
    ids = []
    for i in range(n):
        # Distinct bytes per segment (a real set never repeats a segment's content).
        response = await upload_disk(
            reg, case_id, SEGMENT + bytes([i + 1]), filename=f"host.E{i + 1:02d}"
        )
        assert response.status_code == 201, response.text
        ids.append(str(response.json()["id"]))
    return ids


async def run_disk(
    reg: Registered, evidence_id: str, segments: list[str] | None = None, **body: Any
) -> Response:
    return await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/analyses",
        json={"analyzer": "disk", "segments": segments or [evidence_id], **body},
        headers=csrf(reg.client),
    )


async def queued_job(
    sent: SentJobs, segments: int = 1, **body: Any
) -> tuple[Registered, list[str], dispatch.DispatchInput]:
    """A new org with `segments` `kind=disk` uploads in one case and a queued disk job over
    them (dispatch captured in `sent`)."""
    reg = await register()
    ids = await upload_segments(reg, await new_case(reg), segments)
    run = await run_disk(reg, ids[0], ids, **body)
    assert run.status_code == 201, run.text
    item = sent[-1]
    assert item.analyzer == "disk" and str(item.job_id) == run.json()["id"]
    return reg, ids, item


def finished(
    item: dispatch.DispatchInput,
    version_id: str | None,
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


def started(item: dispatch.DispatchInput) -> dict[str, Any]:
    return {
        "job_id": str(item.job_id),
        "organization_id": str(item.organization_id),
        "ingest_token": item.ingest_token,
        "event": "started",
        "worker_version": WORKER,
    }


async def deliver(
    item: dispatch.DispatchInput,
    data: bytes,
    handoffs: HandOffs,
    *,
    outcome: str = "succeeded",
    error_code: str | None = None,
) -> dict[str, Any]:
    """Upload a result, report it to the shared worker, then run the handed-off disk ingest."""
    version = put_result(item.organization_id, item.job_id, data)
    message = finished(item, version, outcome=outcome, error_code=error_code)
    before = len(handoffs)
    await ingest.handle_event(message)
    for handed in handoffs[before:]:
        await ingest.handle_disk_ingest(handed)
    return message


async def job_of(item: dispatch.DispatchInput) -> AnalysisJob:
    async with tenant_session(item.organization_id, None) as session:
        job = await session.get(AnalysisJob, item.job_id)
    assert job is not None
    return job


async def index_of_job(job_id: uuid.UUID) -> AnalysisJobIndex:
    async with tenant_session(None, None) as session:
        index = await session.get(AnalysisJobIndex, job_id)
    assert index is not None
    return index


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


async def rows(org_id: uuid.UUID, sql: str, **params: Any) -> list[Any]:
    async with tenant_session(org_id, None) as session:
        return list((await session.execute(text(sql), params)).all())


async def scalar(org_id: uuid.UUID, stmt: Any) -> Any:
    async with tenant_session(org_id, None) as session:
        return await session.scalar(stmt)

