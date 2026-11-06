"""Evidence metadata, custody chain and archiving (transfers: uploads.py / transfer.py)."""

import uuid
from typing import Any, Literal

from starlette.requests import HTTPConnection

from app.core.client_ip import client_ip, user_agent
from app.core.errors import Conflict, EvidencePurged, NotFound
from app.core.pagination import PageParams
from app.core.rbac import OrgContext
from app.modules.audit import service as audit
from app.modules.evidence import repository as repo
from app.modules.evidence.models import CustodyAction, EvidenceCustodyEvent, EvidenceStatus
from app.modules.evidence.schemas import CustodyEventOut, CustodyPage, EvidenceOut, EvidencePage
from app.modules.investigations.models import InvestigationStatus

# M8: the stored `memory_sensitivity.state` as the `EvidenceOut` literal.
_SENSITIVITY: dict[str, Literal["restricted", "released"]] = {
    "restricted": "restricted",
    "released": "released",
}


def to_out(row: repo.EvidenceRow) -> EvidenceOut:
    e = row.evidence
    return EvidenceOut(
        id=e.id,
        investigation_id=e.investigation_id,
        original_filename=e.original_filename,
        detected_mime=e.detected_mime,
        detected_description=e.detected_description,
        size_bytes=e.size_bytes,
        status=e.status,
        description=e.description,
        uploaded_by=e.uploaded_by,
        uploaded_by_name=row.uploaded_by_name,
        uploaded_at=e.uploaded_at,
        hashes=row.hashes,
        ai_excluded=row.ai_excluded,
        ti_excluded=row.ti_excluded,
        purged_at=row.purged_at,
        purged_by_run_id=row.purge_run_id,
        legal_hold=row.legal_hold,
        declared_type=e.declared_type,
        type_mismatch=e.type_mismatch,
        memory_sensitivity=_SENSITIVITY.get(row.memory_sensitivity or ""),
    )


def record_event(
    ctx: OrgContext,
    *,
    evidence_id: uuid.UUID,
    action: CustodyAction | None,
    audit_action: str,
    request: HTTPConnection,
    custody_details: dict[str, Any] | None = None,
    audit_details: dict[str, Any] | None = None,
) -> None:
    """Custody event (if any) + audit row in the caller's transaction."""
    if action is not None:
        ctx.session.add(
            EvidenceCustodyEvent(
                organization_id=ctx.org_id,
                evidence_id=evidence_id,
                action=action,
                actor_id=ctx.user.id,
                ip=client_ip(request),
                user_agent=user_agent(request),
                details=custody_details or {},
            )
        )
    audit.record(
        ctx.session,
        action=audit_action,
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="evidence",
        target_id=evidence_id,
        details=audit_details,
        request=request,
    )


async def ensure_open_investigation(ctx: OrgContext, investigation_id: uuid.UUID) -> None:
    """Archived investigations are read-only; holds FOR SHARE until the transaction ends."""
    investigation = await repo.get_investigation(
        ctx.session, ctx.org_id, investigation_id, for_share=True
    )
    if investigation is None:
        raise NotFound()
    if investigation.status == InvestigationStatus.ARCHIVED:
        raise Conflict("Archived investigations are read-only", code="investigation_archived")


async def get_row(
    ctx: OrgContext, evidence_id: uuid.UUID, *, for_update: bool = False
) -> repo.EvidenceRow:
    row = await repo.get_row(ctx.session, ctx.org_id, evidence_id, for_update=for_update)
    if row is None:
        raise NotFound()
    return row


async def list_for_investigation(
    ctx: OrgContext, investigation_id: uuid.UUID, page: PageParams
) -> EvidencePage:
    if await repo.get_investigation(ctx.session, ctx.org_id, investigation_id) is None:
        raise NotFound()
    rows, total = await repo.list_for_investigation(ctx.session, ctx.org_id, investigation_id, page)
    return EvidencePage(items=[to_out(r) for r in rows], total=total)


def ensure_not_purged(row: repo.EvidenceRow) -> None:
    """`410 evidence_purged` once retention purged the bytes (after the org check, so other
    orgs' evidence still answers 404)."""
    if row.purged_at is not None:
        raise EvidencePurged(
            extra={
                "purged_at": row.purged_at.isoformat(),
                "run_id": str(row.purge_run_id) if row.purge_run_id else None,
            }
        )


async def get_evidence(ctx: OrgContext, evidence_id: uuid.UUID) -> EvidenceOut:
    return to_out(await get_row(ctx, evidence_id))


async def custody(ctx: OrgContext, evidence_id: uuid.UUID, page: PageParams) -> CustodyPage:
    await get_row(ctx, evidence_id)
    events, total = await repo.list_custody(ctx.session, ctx.org_id, evidence_id, page)
    return CustodyPage(
        items=[
            CustodyEventOut(
                id=event.id,
                action=event.action,
                actor_id=event.actor_id,
                actor_name=name,
                occurred_at=event.occurred_at,
                ip=event.ip,
                user_agent=event.user_agent,
                details=event.details,
            )
            for event, name in events
        ],
        total=total,
    )


async def archive(ctx: OrgContext, evidence_id: uuid.UUID, request: HTTPConnection) -> EvidenceOut:
    row = await get_row(ctx, evidence_id, for_update=True)
    await ensure_open_investigation(ctx, row.evidence.investigation_id)
    if row.evidence.status == EvidenceStatus.ARCHIVED:
        raise Conflict("Evidence is already archived", code="evidence_archived")
    row.evidence.status = EvidenceStatus.ARCHIVED
    record_event(
        ctx,
        evidence_id=evidence_id,
        action=CustodyAction.ARCHIVED,
        audit_action="evidence.archived",
        request=request,
    )
    await ctx.session.flush()
    out = to_out(row)
    await ctx.session.commit()
    return out
