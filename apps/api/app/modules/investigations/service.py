import uuid
from typing import Any

from starlette.requests import HTTPConnection

from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.core.pagination import PageParams
from app.core.rbac import OrgContext, Permission
from app.modules.audit import service as audit
from app.modules.investigations import policy
from app.modules.investigations import repository as repo
from app.modules.investigations.models import (
    Investigation,
    InvestigationStatus,
    InvestigationStatusEvent,
)
from app.modules.investigations.schemas import (
    InvestigationCreate,
    InvestigationOut,
    InvestigationPage,
    InvestigationUpdate,
    SharePolicyOut,
    StatusEventOut,
    StatusEventPage,
    case_ref,
)
from app.modules.notes import paging

# Request-only fields (M6): never copied onto the row.
_CONTROL_FIELDS = frozenset({"status_reason", "acknowledge_tlp_downgrade"})
# Share-policy flags: turning one off needs `integrations.manage`, turning it on does not.
_EXCLUSION_FLAGS = ("ai_excluded", "ti_excluded")

S = InvestigationStatus
# Allowed status changes. `archived` is terminal in M1.
TRANSITIONS: dict[InvestigationStatus, frozenset[InvestigationStatus]] = {
    S.OPEN: frozenset({S.IN_PROGRESS, S.CLOSED}),
    S.IN_PROGRESS: frozenset({S.CLOSED}),
    S.CLOSED: frozenset({S.IN_PROGRESS, S.ARCHIVED}),
    S.ARCHIVED: frozenset(),
}


class StatusReasonRequired(AppError):
    status_code = 422
    code = "status_reason_required"
    message = "Closing, reopening or archiving a case needs a status reason"


class TlpDowngradeNotAcknowledged(AppError):
    status_code = 422
    code = "tlp_downgrade_not_acknowledged"
    message = "Lowering the TLP of a case needs acknowledge_tlp_downgrade"


def requires_reason(old: InvestigationStatus, new: InvestigationStatus) -> bool:
    """Closing, archiving and reopening (closed -> in_progress) need a reason (M6)."""
    return new in (S.CLOSED, S.ARCHIVED) or (old == S.CLOSED and new == S.IN_PROGRESS)


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
        legal_hold=row.legal_hold,
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


def can(ctx: OrgContext, permission: Permission) -> bool:
    """Whether the caller also holds `permission` (beyond the route's own): the role's
    permissions, or role ∩ scopes for an API key (M11 RT1)."""
    return permission in ctx.permissions


def _changes(inv: Investigation, data: InvestigationUpdate) -> dict[str, Any]:
    changes: dict[str, Any] = {}
    for field in sorted(data.model_fields_set - _CONTROL_FIELDS):
        new = getattr(data, field)
        old = getattr(inv, field)
        if new != old:
            changes[field] = {"from": old, "to": new}
    return changes


def _check_rules(
    ctx: OrgContext, inv: Investigation, data: InvestigationUpdate, changes: dict[str, Any]
) -> None:
    """The status transition and its reason, the TLP downgrade rule and the exclusion-flag
    rule (M6)."""
    if "status" in changes:
        new_status = InvestigationStatus(changes["status"]["to"])
        if new_status not in TRANSITIONS[inv.status]:
            raise Conflict(
                f"Cannot change status from {inv.status.value} to {new_status.value}",
                code="invalid_transition",
            )
        if requires_reason(inv.status, new_status) and data.status_reason is None:
            raise StatusReasonRequired()
    if "tlp" in changes and policy.is_downgrade(changes["tlp"]["to"], inv.tlp):
        if not can(ctx, Permission.ORG_UPDATE):
            raise Forbidden(
                "Lowering the TLP of a case needs the org.update permission",
                code="tlp_downgrade_forbidden",
            )
        if data.acknowledge_tlp_downgrade is not True:
            raise TlpDowngradeNotAcknowledged()
    for flag in _EXCLUSION_FLAGS:
        turned_off = flag in changes and not changes[flag]["to"]
        if turned_off and not can(ctx, Permission.INTEGRATIONS_MANAGE):
            raise Forbidden("Turning a share-policy exclusion off needs integrations.manage")


def _plain(value: Any) -> Any:
    return value.value if isinstance(value, InvestigationStatus) else value


def _audit_details(
    inv: Investigation, data: InvestigationUpdate, changes: dict[str, Any]
) -> dict[str, Any]:
    """The diff without free text: the description and the status reason are never copied,
    only that the description changed and whether a reason was given."""
    details: dict[str, Any] = {
        "case_ref": case_ref(inv.case_number),
        "changes": {
            field: (
                {"changed": True}
                if field == "description"
                else {"from": _plain(change["from"]), "to": _plain(change["to"])}
            )
            for field, change in changes.items()
        },
    }
    if "tlp" in changes:
        details["tlp_from"] = str(changes["tlp"]["from"])
        details["tlp_to"] = str(changes["tlp"]["to"])
        details["tlp_downgrade"] = policy.is_downgrade(changes["tlp"]["to"], changes["tlp"]["from"])
    if "status" in changes:
        details["status_from"] = _plain(changes["status"]["from"])
        details["status_to"] = _plain(changes["status"]["to"])
        details["has_reason"] = data.status_reason is not None
    for flag in _EXCLUSION_FLAGS:
        if flag in changes:
            details[flag] = bool(changes[flag]["to"])
    return details


async def update_investigation(
    ctx: OrgContext, investigation_id: uuid.UUID, data: InvestigationUpdate, request: HTTPConnection
) -> InvestigationOut:
    row = await repo.get_row(ctx.session, ctx.org_id, investigation_id, for_update=True)
    if row is None:
        raise NotFound()
    inv = row.investigation
    if inv.status == S.ARCHIVED:
        raise Conflict("Archived investigations are read-only", code="investigation_archived")

    changes = _changes(inv, data)
    _check_rules(ctx, inv, data, changes)
    if not changes:
        return _to_out(row)

    old_status = inv.status
    details = _audit_details(inv, data, changes)
    for field, change in changes.items():
        value = change["to"]
        setattr(inv, field, str(value) if field == "tlp" else value)
    if "status" in changes:
        # Exactly one history row per status change, in the transaction of the update.
        ctx.session.add(
            InvestigationStatusEvent(
                organization_id=ctx.org_id,
                investigation_id=inv.id,
                from_status=old_status.value,
                to_status=InvestigationStatus(changes["status"]["to"]).value,
                reason=data.status_reason,
                actor_id=ctx.user.id,
            )
        )
    audit.record(
        ctx.session,
        action="investigation.updated",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="investigation",
        target_id=inv.id,
        details=details,
        request=request,
    )
    await ctx.session.flush()
    out = _to_out(row)
    await ctx.session.commit()
    return out


async def list_status_events(
    ctx: OrgContext, investigation_id: uuid.UUID, *, cursor: str | None, limit: int
) -> StatusEventPage:
    """The case's status history, newest first (cursor-paged)."""
    if await repo.get_row(ctx.session, ctx.org_id, investigation_id) is None:
        raise NotFound()
    before = paging.decode(cursor) if cursor else None
    rows = await repo.list_status_events(
        ctx.session, ctx.org_id, investigation_id, limit=limit + 1, before=before
    )
    page = rows[:limit]
    items = [
        StatusEventOut(
            id=event.id,
            from_status=InvestigationStatus(event.from_status) if event.from_status else None,
            to_status=InvestigationStatus(event.to_status),
            reason=event.reason,
            actor_id=event.actor_id,
            actor_name=name,
            occurred_at=event.occurred_at,
        )
        for event, name in page
    ]
    next_cursor = None
    if len(rows) > limit:
        last = page[-1][0]
        next_cursor = paging.encode(last.occurred_at, last.id)
    return StatusEventPage(items=items, next_cursor=next_cursor)
