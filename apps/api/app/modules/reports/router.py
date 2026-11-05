"""Report draft, finalize, version and citation routes (M6). Frozen in phase 1 as
`501 not_implemented` stubs with their final paths, permissions and models; phase 3 fills
the bodies. Rate limits (phase 3): preview 30 and finalize 10 per user per 10 minutes."""

import uuid
from typing import Annotated

from cyberlab_jobs.report import ReportSnapshot
from fastapi import APIRouter, Depends, Path, Query, Request, status
from fastapi.responses import Response

from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.modules.reports.schemas import (
    CitedByOut,
    CitedKind,
    RefId,
    ReportCreate,
    ReportDetail,
    ReportFinalize,
    ReportOut,
    ReportPage,
    ReportPreviewOut,
    ReportSignatureOut,
    ReportStatus,
    ReportUpdate,
    ReportVersionDetail,
    ReportVersionList,
    ReportVersionSummary,
)

router = APIRouter(prefix="/orgs/{org_id}", tags=["reports"])

InvRead = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_READ), scope="function")]
InvWrite = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_WRITE), scope="function")]
EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
Cursor = Annotated[str | None, Query(max_length=512)]
Version = Annotated[int, Path(ge=1, le=100_000)]


@router.get("/reports", response_model=ReportPage)
async def list_reports(
    ctx: InvRead,
    investigation_id: uuid.UUID | None = None,
    status_: Annotated[ReportStatus | None, Query(alias="status")] = None,
    cursor: Cursor = None,
) -> ReportPage:
    """The org-wide list (latest version, TLP, updated)."""
    raise not_implemented()


@router.get("/investigations/{investigation_id}/reports", response_model=ReportPage)
async def list_case_reports(
    investigation_id: uuid.UUID, ctx: InvRead, cursor: Cursor = None
) -> ReportPage:
    raise not_implemented()


@router.post(
    "/investigations/{investigation_id}/reports",
    response_model=ReportOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_report(
    investigation_id: uuid.UUID, body: ReportCreate, ctx: InvWrite, request: Request
) -> ReportOut:
    """TLP defaults to the case TLP; below it needs `org.update` + the acknowledgement;
    `409 investigation_archived`."""
    raise not_implemented()


@router.get("/reports/{report_id}", response_model=ReportDetail)
async def get_report(report_id: uuid.UUID, ctx: InvRead) -> ReportDetail:
    raise not_implemented()


@router.patch("/reports/{report_id}", response_model=ReportDetail)
async def update_report(
    report_id: uuid.UUID, body: ReportUpdate, ctx: InvWrite, request: Request
) -> ReportDetail:
    """`409 stale_draft`; `422 selection_out_of_scope`."""
    raise not_implemented()


@router.post("/reports/{report_id}/discard", response_model=ReportDetail)
async def discard_report(report_id: uuid.UUID, ctx: InvWrite, request: Request) -> ReportDetail:
    """Only without versions (`409 report_has_versions`)."""
    raise not_implemented()


@router.post("/reports/{report_id}/preview", response_model=ReportPreviewOut)
async def preview_report(report_id: uuid.UUID, ctx: InvWrite) -> ReportPreviewOut:
    """The snapshot built in memory with its size and render units against the budget;
    nothing stored, nothing audited."""
    raise not_implemented()


@router.post(
    "/reports/{report_id}/finalize",
    response_model=ReportVersionSummary,
    status_code=status.HTTP_201_CREATED,
)
async def finalize_report(
    report_id: uuid.UUID, body: ReportFinalize, ctx: InvWrite, request: Request
) -> ReportVersionSummary:
    """Freeze the draft into a signed version (PDF render queued): `422 report_too_large`,
    `422 report_too_large_to_render` (RT1), `409 tlp_below_case` (RT7),
    `422 external_review_required` (RT8), `422 distribution_required`, `409 stale_draft`."""
    raise not_implemented()


@router.get("/reports/{report_id}/versions", response_model=ReportVersionList)
async def list_versions(report_id: uuid.UUID, ctx: InvRead) -> ReportVersionList:
    raise not_implemented()


@router.get("/reports/{report_id}/versions/{version}", response_model=ReportVersionDetail)
async def get_version(report_id: uuid.UUID, version: Version, ctx: InvRead) -> ReportVersionDetail:
    """Manifest, `signature_valid`, `snapshot_ok` (re-hashed), counts, renders."""
    raise not_implemented()


@router.get("/reports/{report_id}/versions/{version}/content", response_model=ReportSnapshot)
async def get_version_content(
    report_id: uuid.UUID, version: Version, ctx: EvidenceRead
) -> ReportSnapshot:
    """The stored snapshot for the viewer (inline, `no-store`), re-hashed (`409
    integrity_failed`); not audited per view (RT11)."""
    raise not_implemented()


@router.get(
    "/reports/{report_id}/versions/{version}/snapshot",
    response_class=Response,
    responses={200: {"content": {"application/json": {}}}},
)
async def download_snapshot(
    report_id: uuid.UUID, version: Version, ctx: EvidenceRead, request: Request
) -> Response:
    """The canonical JSON exactly as stored, as an attachment; audited
    `report.snapshot_downloaded`."""
    raise not_implemented()


@router.get(
    "/reports/{report_id}/versions/{version}/signature", response_model=ReportSignatureOut
)
async def get_signature(
    report_id: uuid.UUID, version: Version, ctx: InvRead
) -> ReportSignatureOut:
    """`{manifest, signature, kid, alg}` served as `.sig.json`."""
    raise not_implemented()


@router.get("/cited-by", response_model=CitedByOut)
async def get_cited_by(
    ctx: EvidenceRead,
    kind: CitedKind,
    ref_id: RefId,
    job_id: uuid.UUID | None = None,
) -> CitedByOut:
    """AI outputs (verified citations) and report versions that cite one row."""
    raise not_implemented()
