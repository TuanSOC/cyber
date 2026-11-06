"""File exports to derived evidence (M9 phase 1 stubs on the frozen paths; phase 10 implements
them).

- `POST /analyses/{job}/disk/file-exports` `{file_ids}` (evidence.write; RT29): 1..20 listed,
  allocated regular files (≤ DISK_EXPORT_MAX_BYTES, no name of the inode on the never-collected
  list, RT7) become an `extract` job; distinct from the interop `GET …/disk/exports/*`.
- `GET /disk-exports/{id}` (evidence.read).
- `POST /disk-exports/{id}/promote` (evidence.write): streams the object through the evidence
  upload pipeline (re-hashed, sniffed, quota, object lock) into derived evidence that inherits
  the restriction (source `derived`) and gets its normal static job.

Until phase 10 every route answers `501 not_implemented`.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.modules.disk_forensics.schemas import DiskExportList, DiskExportOut, ExportRequestIn

router = APIRouter(prefix="/orgs/{org_id}", tags=["disk-forensics"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
EvidenceWrite = Annotated[
    OrgContext, Depends(require(Permission.EVIDENCE_WRITE), scope="function")
]


@router.post(
    "/analyses/{job_id}/disk/file-exports", response_model=DiskExportList, status_code=202
)
async def request_file_exports(
    job_id: uuid.UUID, body: ExportRequestIn, ctx: EvidenceWrite
) -> DiskExportList:
    raise not_implemented()


@router.get("/disk-exports/{export_id}", response_model=DiskExportOut)
async def get_disk_export(export_id: uuid.UUID, ctx: EvidenceRead) -> DiskExportOut:
    raise not_implemented()


@router.post("/disk-exports/{export_id}/promote", response_model=DiskExportOut)
async def promote_disk_export(export_id: uuid.UUID, ctx: EvidenceWrite) -> DiskExportOut:
    raise not_implemented()
