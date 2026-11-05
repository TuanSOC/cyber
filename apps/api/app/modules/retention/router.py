"""Retention policy, preview, runs and legal hold routes (M7). Paths, permissions and models
are frozen in phase 1; every body answers `501 not_implemented` until phase 3 lands.

- the policy: `org.read` to read, `org.update` to change (lowering a value or turning
  `enforce` on waits for `RETENTION_POLICY_DELAY_DAYS`, RT1; enforce needs
  `acknowledge_destruction`); audited `retention.policy_changed`;
- the preview: `org.update`, read-only, through the shared selector `retention/select.py`;
- runs: `audit.read` to list, `org.update` to request a manual run (mode from the DB only);
- legal holds: `investigation.read` to list, `org.update` to place or release (released once;
  the S3 mirror is the retention worker's, published as `retention.sync_holds`, RT5).
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status

from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.modules.retention.schemas import (
    LegalHoldCreate,
    LegalHoldOut,
    LegalHoldPage,
    LegalHoldRelease,
    RetentionPolicyIn,
    RetentionPolicyOut,
    RetentionPreviewIn,
    RetentionPreviewOut,
    RetentionRunCreate,
    RetentionRunDetail,
    RetentionRunOut,
    RetentionRunPage,
)

router = APIRouter(prefix="/orgs/{org_id}", tags=["retention"])

OrgRead = Annotated[OrgContext, Depends(require(Permission.ORG_READ), scope="function")]
OrgUpdate = Annotated[OrgContext, Depends(require(Permission.ORG_UPDATE), scope="function")]
AuditRead = Annotated[OrgContext, Depends(require(Permission.AUDIT_READ), scope="function")]
InvRead = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_READ), scope="function")]


@router.get("/retention/policy", response_model=RetentionPolicyOut)
async def get_policy(ctx: OrgRead) -> RetentionPolicyOut:
    """The effective policy, pending changes and their effective times (no row: keep
    everything forever, enforce off)."""
    raise not_implemented()


@router.put("/retention/policy", response_model=RetentionPolicyOut)
async def put_policy(
    body: RetentionPolicyIn, ctx: OrgUpdate, request: Request
) -> RetentionPolicyOut:
    """`422 policy_floor`, `422 retention_acknowledgement_required`; writes
    `retention_policy_index` in the same transaction (RT3)."""
    raise not_implemented()


@router.post("/retention/preview", response_model=RetentionPreviewOut)
async def preview(body: RetentionPreviewIn, ctx: OrgUpdate) -> RetentionPreviewOut:
    """What a run would select now (counts, bytes, a bounded sample). Writes nothing."""
    raise not_implemented()


@router.get("/retention/runs", response_model=RetentionRunPage)
async def list_runs(ctx: AuditRead, page: PageParamsDep) -> RetentionRunPage:
    raise not_implemented()


@router.get("/retention/runs/{retention_run_id}", response_model=RetentionRunDetail)
async def get_run(retention_run_id: uuid.UUID, ctx: AuditRead) -> RetentionRunDetail:
    raise not_implemented()


@router.post(
    "/retention/runs", response_model=RetentionRunOut, status_code=status.HTTP_202_ACCEPTED
)
async def create_run(body: RetentionRunCreate, ctx: OrgUpdate, request: Request) -> RetentionRunOut:
    """Queue a manual run (`retention.run_org`); one run per org at a time (`409`)."""
    raise not_implemented()


@router.get("/legal-holds", response_model=LegalHoldPage)
async def list_holds(
    ctx: InvRead,
    page: PageParamsDep,
    investigation_id: Annotated[uuid.UUID | None, Query()] = None,
    active_only: Annotated[bool, Query()] = False,
) -> LegalHoldPage:
    raise not_implemented()


@router.post("/legal-holds", response_model=LegalHoldOut, status_code=status.HTTP_201_CREATED)
async def place_hold(body: LegalHoldCreate, ctx: OrgUpdate, request: Request) -> LegalHoldOut:
    """Audited `legal_hold.placed`; answers `s3_sync: pending` (RT5)."""
    raise not_implemented()


@router.post("/legal-holds/{hold_id}/release", response_model=LegalHoldOut)
async def release_hold(
    hold_id: uuid.UUID, body: LegalHoldRelease, ctx: OrgUpdate, request: Request
) -> LegalHoldOut:
    """Released once (`409`); keeps protecting until the delay passed (RT1). Audited
    `legal_hold.released`."""
    raise not_implemented()
