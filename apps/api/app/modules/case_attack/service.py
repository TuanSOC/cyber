"""Analyst ATT&CK mappings of a case (M6 phase 5).

Every row comes from an analyst request: suggestions (`suggest.py`) are never written here.
The technique must be in the v20 index and neither revoked nor deprecated (`422
invalid_technique`); one row per (case, technique) (`409 mapping_exists`); sources are
re-checked in the case scope (`422 ref_out_of_scope`). An archived case is read-only
(`409 investigation_archived`). Writes are audited in the same transaction.
"""

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from starlette.requests import HTTPConnection

from app.core.errors import AppError, Conflict, NotFound
from app.core.rbac import OrgContext
from app.modules.attack.index import INDEX_VERSION
from app.modules.attack.schemas import MITRE_NOTICE
from app.modules.audit import service as audit
from app.modules.case_attack import labels, sources
from app.modules.case_attack.models import CaseAttackMapping
from app.modules.case_attack.schemas import (
    AttackMappingCreate,
    AttackMappingOut,
    AttackMappingUpdate,
    CaseAttackOut,
    MatrixTactic,
)
from app.modules.investigations.models import Investigation, InvestigationStatus
from app.modules.investigations.schemas import case_ref
from app.modules.users.models import User

MATRIX_STATUSES = frozenset({"confirmed", "suspected"})


class InvalidTechnique(AppError):
    status_code = 422
    code = "invalid_technique"
    message = "Unknown, revoked or deprecated ATT&CK technique (pinned index v20)"


class MappingExists(AppError):
    status_code = 409
    code = "mapping_exists"
    message = "This technique is already mapped on the case"


def _archived() -> Conflict:
    return Conflict("Archived investigations are read-only", code="investigation_archived")


async def get_investigation(
    ctx: OrgContext, investigation_id: uuid.UUID, *, lock: bool = False
) -> Investigation:
    stmt = select(Investigation).where(
        Investigation.id == investigation_id, Investigation.organization_id == ctx.org_id
    )
    if lock:  # a concurrent archive waits for this write (FOR SHARE)
        stmt = stmt.with_for_update(read=True)
    found = await ctx.session.scalar(stmt)
    if found is None:
        raise NotFound()
    return found


async def _outs(ctx: OrgContext, rows: Sequence[CaseAttackMapping]) -> list[AttackMappingOut]:
    if not rows:
        return []
    user_ids = {r.updated_by for r in rows}
    users = await ctx.session.execute(
        select(User.id, User.display_name).where(User.id.in_(user_ids))
    )
    names = {user_id: name for user_id, name in users}
    refs = [(str(s.get("kind")), str(s.get("ref_id"))) for r in rows for s in r.sources]
    found = await sources.resolve(ctx.session, ctx.org_id, rows[0].investigation_id, refs)
    return [
        AttackMappingOut(
            id=r.id,
            investigation_id=r.investigation_id,
            technique_id=r.technique_id,
            label=labels.technique_label(r.technique_id),
            status=r.status,  # CHECK-constrained MappingStatus
            rationale=r.rationale,
            sources=[sources.descriptor(ctx.org_id, s, found) for s in r.sources],
            created_by=r.created_by,
            updated_by=r.updated_by,
            updated_by_name=names.get(r.updated_by, ""),
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in rows
    ]


def matrix(mappings: Sequence[AttackMappingOut]) -> list[MatrixTactic]:
    """Every tactic of the index in v20 order, with its confirmed and suspected techniques
    (rejected ones excluded; a technique with several tactics is under each)."""
    by_tactic: dict[str, list[AttackMappingOut]] = {}
    for m in sorted(mappings, key=lambda m: m.technique_id):
        if m.status not in MATRIX_STATUSES:
            continue
        entry = labels.entry(m.technique_id)
        for shortname in entry.tactics if entry is not None else ():
            by_tactic.setdefault(shortname, []).append(m)
    return [
        MatrixTactic(tactic=labels.tactic_name(s), techniques=by_tactic.get(s, []))
        for s in labels.tactic_shortnames()
    ]


async def get_case_attack(ctx: OrgContext, investigation_id: uuid.UUID) -> CaseAttackOut:
    await get_investigation(ctx, investigation_id)
    rows = (
        await ctx.session.scalars(
            select(CaseAttackMapping)
            .where(
                CaseAttackMapping.organization_id == ctx.org_id,
                CaseAttackMapping.investigation_id == investigation_id,
            )
            .order_by(CaseAttackMapping.technique_id)
        )
    ).all()
    mappings = await _outs(ctx, rows)
    return CaseAttackOut(
        mappings=mappings,
        matrix=matrix(mappings),
        index_version=INDEX_VERSION,
        notice=MITRE_NOTICE,
    )


async def create_mapping(
    ctx: OrgContext,
    investigation_id: uuid.UUID,
    body: AttackMappingCreate,
    request: HTTPConnection,
) -> AttackMappingOut:
    inv = await get_investigation(ctx, investigation_id, lock=True)
    if inv.status == InvestigationStatus.ARCHIVED:
        raise _archived()
    if not labels.is_mappable(body.technique_id):
        raise InvalidTechnique()
    existing = await ctx.session.scalar(
        select(CaseAttackMapping.id).where(
            CaseAttackMapping.organization_id == ctx.org_id,
            CaseAttackMapping.investigation_id == investigation_id,
            CaseAttackMapping.technique_id == body.technique_id,
        )
    )
    if existing is not None:
        raise MappingExists()
    stored = await sources.check(ctx.session, ctx.org_id, investigation_id, body.sources)
    mapping = CaseAttackMapping(
        organization_id=ctx.org_id,
        investigation_id=investigation_id,
        technique_id=body.technique_id,
        status=body.status,
        rationale=body.rationale,
        sources=stored,
        created_by=ctx.user.id,
        updated_by=ctx.user.id,
    )
    ctx.session.add(mapping)
    try:
        await ctx.session.flush()
    except IntegrityError:  # a concurrent request mapped the same technique
        raise MappingExists() from None
    audit.record(
        ctx.session,
        action="case_attack.mapped",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="case_attack_mapping",
        target_id=mapping.id,
        details={
            "case_ref": case_ref(inv.case_number),
            "investigation_id": str(investigation_id),
            "technique_id": body.technique_id,
            "status": body.status,
            "sources": len(stored),
        },
        request=request,
    )
    [out] = await _outs(ctx, [mapping])
    await ctx.session.commit()
    return out


async def update_mapping(
    ctx: OrgContext,
    mapping_id: uuid.UUID,
    body: AttackMappingUpdate,
    request: HTTPConnection,
) -> AttackMappingOut:
    mapping = await ctx.session.scalar(
        select(CaseAttackMapping)
        .where(CaseAttackMapping.id == mapping_id, CaseAttackMapping.organization_id == ctx.org_id)
        .with_for_update()
    )
    if mapping is None:
        raise NotFound()
    inv = await get_investigation(ctx, mapping.investigation_id, lock=True)
    if inv.status == InvestigationStatus.ARCHIVED:
        raise _archived()

    changes: dict[str, Any] = {}
    fields = body.model_fields_set
    if "status" in fields and body.status is not None and body.status != mapping.status:
        changes["status"] = {"from": mapping.status, "to": body.status}
    if "rationale" in fields and body.rationale is not None and body.rationale != mapping.rationale:
        changes["rationale"] = {"changed": True}
    stored: list[dict[str, Any]] | None = None
    if "sources" in fields and body.sources is not None:
        stored = await sources.check(ctx.session, ctx.org_id, inv.id, body.sources)
        if stored != mapping.sources:
            changes["sources"] = {"from": len(mapping.sources), "to": len(stored)}
    if not changes:
        [out] = await _outs(ctx, [mapping])
        return out

    if "status" in changes and body.status is not None:
        mapping.status = body.status
    if "rationale" in changes and body.rationale is not None:
        mapping.rationale = body.rationale
    if "sources" in changes and stored is not None:
        mapping.sources = stored
    mapping.updated_by = ctx.user.id
    audit.record(
        ctx.session,
        action="case_attack.updated",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="case_attack_mapping",
        target_id=mapping.id,
        details={
            "case_ref": case_ref(inv.case_number),
            "investigation_id": str(inv.id),
            "technique_id": mapping.technique_id,
            "changes": changes,
        },
        request=request,
    )
    await ctx.session.flush()
    await ctx.session.refresh(mapping)
    [out] = await _outs(ctx, [mapping])
    await ctx.session.commit()
    return out
