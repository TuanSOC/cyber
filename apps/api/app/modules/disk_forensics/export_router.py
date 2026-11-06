"""File exports to derived evidence (M9 phase 10 on the phase-1 frozen paths and schemas).

- `POST /analyses/{job}/disk/file-exports` `{file_ids}` (evidence.write; RT29): 1..20 listed,
  allocated regular files (or named streams) of a succeeded disk `triage` / `full` job, each
  at most DISK_EXPORT_MAX_BYTES, no name of the inode on the never-collected list (RT7),
  become ONE `extract` job (the image is downloaded and re-verified again: no cache, RT1);
  `202` with the `pending` exports. Distinct from the interop `GET …/disk/exports/*`.
- `GET /analyses/{job}/disk/file-exports` (evidence.read): the exports requested from that
  analysis, newest first (the job page's exports tab).
- `GET /disk-exports/{id}` (evidence.read): state, size, the worker's sha256 (untrusted,
  display only) and, once promoted, the evidence id (whose hashes are the API's own).
- `POST /disk-exports/{id}/promote` (evidence.write): streams the exact object version through
  the evidence pipeline (re-hashed by the API, sniffed, quota, object lock) into derived
  evidence of the source case that inherits the restriction (source `derived`) and the share
  flags, then gets its normal automatic static job.

Every route answers 404 for an unknown or foreign job, file or export (`export_service`).
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.core import rate_limit
from app.core.deps import CurrentUserDep
from app.core.rbac import OrgContext, Permission, require
from app.modules.disk_forensics import export_service
from app.modules.disk_forensics.schemas import DiskExportList, DiskExportOut, ExportRequestIn

router = APIRouter(prefix="/orgs/{org_id}", tags=["disk-forensics"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
# Export requests per user and 10 minutes (each one re-downloads the whole image).
EXPORT_REQUESTS_PER_10MIN = 10


@router.post("/analyses/{job_id}/disk/file-exports", response_model=DiskExportList, status_code=202)
async def request_file_exports(
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    body: ExportRequestIn,
    user: CurrentUserDep,
    request: Request,
) -> DiskExportList:
    await rate_limit.hit(f"disk:export:{user.id}", EXPORT_REQUESTS_PER_10MIN, 600)
    return await export_service.request_exports(org_id, user, job_id, body.file_ids, request)


@router.get("/analyses/{job_id}/disk/file-exports", response_model=DiskExportList)
async def list_file_exports(job_id: uuid.UUID, ctx: EvidenceRead) -> DiskExportList:
    """The file exports requested from this disk analysis (newest first, at most
    `LIST_MAX`); 404 for an unknown or foreign job, another analyzer or an `extract` job."""
    return await export_service.list_exports(ctx, job_id)


@router.get("/disk-exports/{export_id}", response_model=DiskExportOut)
async def get_disk_export(export_id: uuid.UUID, ctx: EvidenceRead) -> DiskExportOut:
    return await export_service.get_export(ctx, export_id)


@router.post("/disk-exports/{export_id}/promote", response_model=DiskExportOut)
async def promote_disk_export(
    org_id: uuid.UUID, export_id: uuid.UUID, user: CurrentUserDep, request: Request
) -> DiskExportOut:
    return await export_service.promote(org_id, user, export_id, request)
