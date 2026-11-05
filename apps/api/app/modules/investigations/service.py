import uuid
from typing import Any

from starlette.requests import HTTPConnection

from app.core.errors import Conflict, NotFound
from app.core.pagination import PageParams
from app.core.rbac import OrgContext
from app.core.stubs import not_implemented
from app.modules.audit import service as audit
from app.modules.investigations import policy
from app.modules.investigations import repository as repo
from app.modules.investigations.models import Investigation, InvestigationStatus
from app.modules.investigations.schemas import (
    InvestigationCreate,
    InvestigationOut,
    InvestigationPage,
    InvestigationUpdate,
    SharePolicyOut,
    case_ref,
)

# The M6 update fields (TLP, share-policy flags, status reasons): their rules land in
# phase 2; until then a request that sets one answers 501 instead of bypassing them.
M6_UPDATE_FIELDS = frozenset(
    {"tlp", "ai_excluded", "ti_excluded", "status_reason", "acknowledge_tlp_downgrade"}
)

S = InvestigationStatus
# Allowed status changes. `archived` is terminal in M1.
TRANSITIONS: dict[InvestigationStatus, frozenset[InvestigationStatus]] = {
    S.OPEN: frozenset({S.IN_PROGRESS, S.CLOSED}),
    S.IN_PROGRESS: frozenset({S.CLOSED}),
    S.CLOSED: frozenset({S.IN_PROGRESS, S.ARCHIVED}),
    S.ARCHIVED: frozenset(),
}


def _to_out(row: repo.Row) -> InvestigationOut:
    inv = row.investigation
    return InvestigationOut(
        id=inv.id,
        case_number=inv.case_number,
        case_ref=case_ref(inv.case_number),
        title=inv.title,
        description=inv.description,
        status=inv.status,
        allowed_transitions=sorted(TRANSITIONS[inv.status]),
        severity=inv.severity,
        created_by=inv.created_by,
        created_by_name=row.created_by_name,
        evidence_count=row.evidence_count,
        created_at=inv.created_at,
        updated_at=inv.updated_at,
        tlp=inv.tlp,
        ai_excluded=inv.ai_excluded,
        ti_excluded=inv.ti_excluded,
        share_policy=_share_policy(inv),
    )


def _share_policy(inv: Investigation) -> SharePolicyOut:
    case = policy.case_policy(inv.tlp, inv.ai_excluded, inv.ti_excluded)
    return SharePolicyOut(
        ai_blocked=case.ai_blocked, ti_blocked=case.ti_blocked, reasons=case.reasons
    )


async def list_investigations(
    ctx: OrgContext, filters: repo.Filters, page: PageParams
) -> InvestigationPage:
    rows, total = await repo.list_investigations(ctx.session, ctx.org_id, filters, page)
    return InvestigationPage(items=[_to_out(r) for r in rows], total=total)


async def get_investigation(ctx: OrgContext, investigation_id: uuid.UUID) -> InvestigationOut:
    row = await repo.get_row(ctx.session, ctx.org_id, investigation_id)
    if row is None:
        raise NotFound()
    return _to_out(row)


async def create_investigation(
    ctx: OrgContext, data: InvestigationCreate, request: HTTPConnection
) -> InvestigationOut:
    investigation = Investigation(
        organization_id=ctx.org_id,
        case_number=await repo.next_case_number(ctx.session, ctx.org_id),
        title=data.title,
        description=data.description,
        severity=data.severity,
        created_by=ctx.user.id,
    )
    ctx.session.add(investigation)
    await ctx.session.flush()
    audit.record(
        ctx.session,
        action="investigation.created",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="investigation",
        target_id=investigation.id,
        details={"case_ref": case_ref(investigation.case_number), "title": data.title},
        request=request,
    )
    out = _to_out(repo.Row(investigation, ctx.user.display_name, 0))
    await ctx.session.commit()
    return out


async def update_investigation(
    ctx: OrgContext, investigation_id: uuid.UUID, data: InvestigationUpdate, request: HTTPConnection
) -> InvestigationOut:
    row = await repo.get_row(ctx.session, ctx.org_id, investigation_id, for_update=True)
    if row is None:
        raise NotFound()
    if data.model_fields_set & M6_UPDATE_FIELDS:
        raise not_implemented()
    inv = row.investigation
    if inv.status == S.ARCHIVED:
        raise Conflict("Archived investigations are read-only", code="investigation_archived")

    changes: dict[str, Any] = {}
    for field in sorted(data.model_fields_set):
        new = getattr(data, field)
        old = getattr(inv, field)
        if new != old:
            changes[field] = {"from": old, "to": new}
    if "status" in changes and data.status not in TRANSITIONS[inv.status]:
        raise Conflict(
            f"Cannot change status from {inv.status.value} to {data.status}",
            code="invalid_transition",
        )
    if not changes:
        return _to_out(row)

    for field, change in changes.items():
        setattr(inv, field, change["to"])
    audit.record(
        ctx.session,
        action="investigation.updated",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="investigation",
        target_id=inv.id,
        # Long free text is not copied into the audit trail, only the fact it changed.
        details={
            "case_ref": case_ref(inv.case_number),
            "changes": {
                k: ({"changed": True} if k == "description" else v) for k, v in changes.items()
            },
        },
        request=request,
    )
    await ctx.session.flush()
    out = _to_out(row)
    await ctx.session.commit()
    return out
