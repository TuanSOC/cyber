"""Helpers of the M9 phase-10 file-export tests (request, ingest, promote, TTL, custody, IDOR).

- `source_job(...)`: a new org with `segments` real uploads (`kind=disk` by default: restricted,
  AI / TI excluded; the API's own hashes) in one case, and a succeeded disk job over them with
  the phase-1 Windows fixture's listing (`seed_disk_job`);
- `exports` fixture: `export_service.send_export` captured (no broker);
- `worker_report(...)` / `deliver_export(...)`: what the disk worker does: the exported objects
  under `exports/<job>/<export_id>` in the results bucket, then the `disk-export.v1` stream
  through both ingest halves (`tests.disk_results.deliver`);
- `ready_export(...)`: request one file, deliver it `ok`: a `ready` export.
"""

import hashlib
import io
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

import pytest
from httpx import Response
from sqlalchemy import select

from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis.dispatch import DispatchInput
from app.modules.disk_forensics import export_service
from app.modules.disk_forensics.dispatch import export_key
from app.modules.disk_forensics.models import DiskExport, DiskFile
from tests import disk_results as dr
from tests.analysis_helpers import new_case
from tests.disk_helpers import seed_disk_job
from tests.factories import Registered, csrf, register
from tests.integration.seed import Tenant
from tests.pcap_results import encode

# windows_triage.ndjson (partition 1, NTFS): an allocated executable, a named stream, the SAM
# hive, a deleted file, an orphan, a directory.
UPDATER = "Users/alice/AppData/Local/Temp/updater.exe"
NOTES = "Users/alice/Documents/notes.txt"  # with the named stream `payload`
SAM = "Windows/System32/config/SAM"
DELETED = "Users/alice/Downloads/old_tool.exe"
ORPHAN = "$OrphanFiles/OrphanFile-9999"
CONTENT = b"MZ" + b"\x90" * 1022  # what the "worker" exports


@dataclass
class Source:
    reg: Registered
    t: Tenant
    job_id: uuid.UUID
    segments: list[uuid.UUID]
    case_id: str


@dataclass
class Captured:
    calls: list[tuple[DispatchInput, uuid.UUID, list[Any]]] = field(default_factory=list)

    @property
    def last(self) -> tuple[DispatchInput, uuid.UUID, list[Any]]:
        return self.calls[-1]


@pytest.fixture
def exports(monkeypatch: pytest.MonkeyPatch) -> Captured:
    captured = Captured()

    async def capture(item: DispatchInput, source_job_id: uuid.UUID, planned: list[Any]) -> None:
        captured.calls.append((item, source_job_id, planned))

    monkeypatch.setattr(export_service, "send_export", capture)
    return captured


async def source_job(*, segments: int = 1, kind: str | None = "disk") -> Source:
    reg = await register()
    case_id = await new_case(reg)
    ids = []
    for i in range(segments):
        response = await dr.upload_disk(
            reg, case_id, dr.SEGMENT + bytes([i + 1]), f"host.E{i + 1:02d}", kind=kind
        )
        assert response.status_code == 201, response.text
        ids.append(uuid.UUID(response.json()["id"]))
    t = Tenant(reg.org_id, reg.user_id, uuid.UUID(case_id))
    job_id = await seed_disk_job(t, ids)
    return Source(reg, t, job_id, ids, case_id)


async def file_id(
    org_id: uuid.UUID, job_id: uuid.UUID, path: str, stream: str | None = None
) -> uuid.UUID:
    async with tenant_session(org_id, None) as s:
        found = await s.scalar(
            select(DiskFile.id).where(
                DiskFile.organization_id == org_id,
                DiskFile.job_id == job_id,
                DiskFile.path == path,
                DiskFile.stream.is_(None) if stream is None else DiskFile.stream == stream,
            )
        )
    assert found is not None, path
    return found


async def request(reg: Registered, job_id: uuid.UUID, file_ids: list[uuid.UUID]) -> Response:
    return await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/analyses/{job_id}/disk/file-exports",
        json={"file_ids": [str(f) for f in file_ids]},
        headers=csrf(reg.client),
    )


async def promote(reg: Registered, export_id: uuid.UUID | str) -> Response:
    return await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/disk-exports/{export_id}/promote", headers=csrf(reg.client)
    )


async def export_row(org_id: uuid.UUID, export_id: uuid.UUID | str) -> DiskExport:
    async with tenant_session(org_id, None) as s:
        row = await s.get(DiskExport, uuid.UUID(str(export_id)))
    assert row is not None
    return row


def put_export(item: DispatchInput, export_id: uuid.UUID | str, data: bytes) -> str:
    stored = get_minio().put_object(
        get_settings().results_bucket,
        export_key(item.job_id, export_id),
        io.BytesIO(data),
        len(data),
    )
    return str(stored.version_id)


def ok(export_id: uuid.UUID | str, data: bytes = CONTENT, **over: Any) -> dict[str, Any]:
    return {
        "export_id": str(export_id),
        "status": "ok",
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        **over,
    }


def failed(export_id: uuid.UUID | str, code: str = "disk_export_not_allowed") -> dict[str, Any]:
    return {"export_id": str(export_id), "status": "failed", "error_code": code}


def stream(job_id: uuid.UUID, files: list[dict[str, Any]]) -> bytes:
    header = {
        "kind": "header",
        "schema_version": "disk-export.v1",
        "job_id": str(job_id),
        "tool_versions": {"pytsk3": "test"},
        "files": files,
    }
    return encode([json.dumps(header).encode() + b"\n"])


async def deliver_export(
    item: DispatchInput, files: list[dict[str, Any]], handoffs: dr.HandOffs
) -> dict[str, Any]:
    return await dr.deliver(item, stream(item.job_id, files), handoffs)


async def ready_export(
    exports: Captured,
    handoffs: dr.HandOffs,
    *,
    kind: str | None = "disk",
    segments: int = 1,
    data: bytes = CONTENT,
) -> tuple[Source, DispatchInput, str]:
    """A `ready` export of `UPDATER` whose stored object is `data`."""
    src = await source_job(segments=segments, kind=kind)
    response = await request(
        src.reg, src.job_id, [await file_id(src.reg.org_id, src.job_id, UPDATER)]
    )
    assert response.status_code == 202, response.text
    export_id = response.json()["items"][0]["id"]
    item = exports.last[0]
    put_export(item, export_id, data)
    await deliver_export(item, [ok(export_id, data)], handoffs)
    assert (await export_row(src.reg.org_id, export_id)).state == "ready"
    return src, item, export_id
