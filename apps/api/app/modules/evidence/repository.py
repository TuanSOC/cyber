import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import PageParams
from app.modules.evidence.models import Evidence, EvidenceCustodyEvent, EvidenceHash
from app.modules.investigations.models import Investigation
from app.modules.users.models import User


@dataclass(frozen=True)
class EvidenceRow:
    evidence: Evidence
    uploaded_by_name: str
    hashes: dict[str, str]


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
    hashes = await _hashes(session, [e.id for e, _ in rows])
    return [EvidenceRow(e, name, hashes[e.id]) for e, name in rows], total


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
    return EvidenceRow(evidence, name, (await _hashes(session, [evidence.id]))[evidence.id])


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
