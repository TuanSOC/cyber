import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import PageParams
from app.modules.evidence.models import Evidence, EvidenceCustodyEvent, EvidenceHash
from app.modules.investigations.models import EvidenceSharePolicy, Investigation
from app.modules.users.models import User


@dataclass(frozen=True)
class EvidenceRow:
    evidence: Evidence
    uploaded_by_name: str
    hashes: dict[str, str]
    # M6: the evidence's share-policy flags (no `evidence_share_policies` row = both off).
    ai_excluded: bool = False
    ti_excluded: bool = False


async def get_investigation(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    *,
    for_share: bool = False,
) -> Investigation | None:
    stmt = select(Investigation).where(
        Investigation.id == investigation_id, Investigation.organization_id == org_id
    )
    if for_share:
        # Blocks a concurrent status change (e.g. archiving) until this transaction ends.
        stmt = stmt.with_for_update(read=True)
    return (await session.execute(stmt)).scalar_one_or_none()


async def _hashes(
    session: AsyncSession, evidence_ids: list[uuid.UUID]
) -> dict[uuid.UUID, dict[str, str]]:
    out: dict[uuid.UUID, dict[str, str]] = {eid: {} for eid in evidence_ids}
    if evidence_ids:
        stmt = select(EvidenceHash).where(EvidenceHash.evidence_id.in_(evidence_ids))
        for h in (await session.execute(stmt)).scalars():
            out[h.evidence_id][h.algorithm.value] = h.value
    return out


async def _flags(
    session: AsyncSession, org_id: uuid.UUID, evidence_ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[bool, bool]]:
    if not evidence_ids:
        return {}
    p = EvidenceSharePolicy
    rows = await session.execute(
        select(p.evidence_id, p.ai_excluded, p.ti_excluded).where(
            p.organization_id == org_id, p.evidence_id.in_(evidence_ids)
        )
    )
    return {evidence_id: (ai, ti) for evidence_id, ai, ti in rows.all()}


async def list_for_investigation(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID, page: PageParams
) -> tuple[list[EvidenceRow], int]:
    where = (Evidence.organization_id == org_id, Evidence.investigation_id == investigation_id)
    total = (await session.execute(select(func.count()).where(*where))).scalar_one()
    stmt = (
        select(Evidence, User.display_name)
        .join(User, User.id == Evidence.uploaded_by)
        .where(*where)
        .order_by(Evidence.uploaded_at.desc(), Evidence.id.desc())
        .limit(page.limit)
        .offset(page.offset)
    )
    rows = (await session.execute(stmt)).all()
    ids = [e.id for e, _ in rows]
    hashes = await _hashes(session, ids)
    flags = await _flags(session, org_id, ids)
    return [
        EvidenceRow(e, name, hashes[e.id], *flags.get(e.id, (False, False))) for e, name in rows
    ], total


async def get_row(
    session: AsyncSession, org_id: uuid.UUID, evidence_id: uuid.UUID, *, for_update: bool = False
) -> EvidenceRow | None:
    stmt = (
        select(Evidence, User.display_name)
        .join(User, User.id == Evidence.uploaded_by)
        .where(Evidence.id == evidence_id, Evidence.organization_id == org_id)
    )
    if for_update:
        stmt = stmt.with_for_update(of=Evidence)
    row = (await session.execute(stmt)).one_or_none()
    if row is None:
        return None
    evidence, name = row
    hashes = (await _hashes(session, [evidence.id]))[evidence.id]
    flags = (await _flags(session, org_id, [evidence.id])).get(evidence.id, (False, False))
    return EvidenceRow(evidence, name, hashes, *flags)


async def lock_evidence_for_policy(
    session: AsyncSession, org_id: uuid.UUID, evidence_id: uuid.UUID
) -> Evidence | None:
    """FOR NO KEY UPDATE on the evidence row (never updated here): serializes share-policy
    writes of one evidence without blocking inserts that reference it (KEY SHARE)."""
    stmt = (
        select(Evidence)
        .where(Evidence.id == evidence_id, Evidence.organization_id == org_id)
        .with_for_update(key_share=True)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def get_share_policy(
    session: AsyncSession, org_id: uuid.UUID, evidence_id: uuid.UUID, *, fresh: bool = False
) -> EvidenceSharePolicy | None:
    stmt = select(EvidenceSharePolicy).where(
        EvidenceSharePolicy.organization_id == org_id,
        EvidenceSharePolicy.evidence_id == evidence_id,
    )
    if fresh:
        stmt = stmt.execution_options(populate_existing=True)
    return await session.scalar(stmt)


async def list_custody(
    session: AsyncSession, org_id: uuid.UUID, evidence_id: uuid.UUID, page: PageParams
) -> tuple[list[tuple[EvidenceCustodyEvent, str]], int]:
    where = (
        EvidenceCustodyEvent.organization_id == org_id,
        EvidenceCustodyEvent.evidence_id == evidence_id,
    )
    total = (await session.execute(select(func.count()).where(*where))).scalar_one()
    stmt = (
        select(EvidenceCustodyEvent, User.display_name)
        .join(User, User.id == EvidenceCustodyEvent.actor_id)
        .where(*where)
        .order_by(EvidenceCustodyEvent.occurred_at, EvidenceCustodyEvent.id)
        .limit(page.limit)
        .offset(page.offset)
    )
    return [(event, name) for event, name in (await session.execute(stmt)).all()], total
