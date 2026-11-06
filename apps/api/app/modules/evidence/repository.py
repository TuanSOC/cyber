import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import PageParams
from app.modules.evidence.models import Evidence, EvidenceCustodyEvent, EvidenceHash
from app.modules.investigations.models import EvidenceSharePolicy, Investigation
from app.modules.memory_analysis.models import MemorySensitivity
from app.modules.retention.holds import active_holds
from app.modules.retention.models import EvidencePurge
from app.modules.users.models import User


@dataclass(frozen=True)
class EvidenceRow:
    evidence: Evidence
    uploaded_by_name: str
    hashes: dict[str, str]
    # M6: the evidence's share-policy flags (no `evidence_share_policies` row = both off).
    ai_excluded: bool = False
    ti_excluded: bool = False
    # M7: the retention tombstone (bytes purged; hashes and custody remain) and whether a
    # legal hold (case or org, active or released less than the delay ago) covers it.
    purged_at: datetime | None = None
    purge_run_id: uuid.UUID | None = None
    legal_hold: bool = False
    # M8: `restricted` / `released` when the evidence is a memory image (`memory_sensitivity`).
    memory_sensitivity: str | None = None
    # M9 (RT2): `(state, source)` of the evidence's `memory_sensitivity` row, any source.
    sensitivity: tuple[str, str] | None = None


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


async def memory_sensitivity_states(
    session: AsyncSession, org_id: uuid.UUID, evidence_ids: list[uuid.UUID]
) -> dict[uuid.UUID, str]:
    """`{evidence_id: "restricted" | "released"}` of the given evidence that have a row (M8)."""
    if not evidence_ids:
        return {}
    m = MemorySensitivity
    rows = await session.execute(
        select(m.evidence_id, m.state).where(
            m.organization_id == org_id, m.evidence_id.in_(evidence_ids)
        )
    )
    return {evidence_id: str(state) for evidence_id, state in rows.all()}


async def sensitivity_states(
    session: AsyncSession, org_id: uuid.UUID, evidence_ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[str, str]]:
    """`{evidence_id: (state, source)}` of the given evidence that have a row (M9, RT2)."""
    if not evidence_ids:
        return {}
    m = MemorySensitivity
    rows = await session.execute(
        select(m.evidence_id, m.state, m.source).where(
            m.organization_id == org_id, m.evidence_id.in_(evidence_ids)
        )
    )
    return {evidence_id: (str(state), str(source)) for evidence_id, state, source in rows.all()}


async def _purges(
    session: AsyncSession, org_id: uuid.UUID, evidence_ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[datetime, uuid.UUID]]:
    if not evidence_ids:
        return {}
    p = EvidencePurge
    rows = await session.execute(
        select(p.evidence_id, p.purged_at, p.run_id).where(
            p.organization_id == org_id, p.evidence_id.in_(evidence_ids)
        )
    )
    return {evidence_id: (at, run_id) for evidence_id, at, run_id in rows.all()}


def _memory_state(found: tuple[str, str] | None) -> str | None:
    return found[0] if found is not None and found[1] == "memory" else None


async def _rows(
    session: AsyncSession, org_id: uuid.UUID, rows: list[tuple[Evidence, str]]
) -> list[EvidenceRow]:
    ids = [e.id for e, _ in rows]
    hashes = await _hashes(session, ids)
    flags = await _flags(session, org_id, ids)
    purges = await _purges(session, org_id, ids)
    sensitivity = await sensitivity_states(session, org_id, ids)
    holds = await active_holds(session, org_id, now=datetime.now(UTC)) if ids else None
    out = []
    for e, name in rows:
        purged_at, run_id = purges.get(e.id, (None, None))
        out.append(
            EvidenceRow(
                e,
                name,
                hashes[e.id],
                *flags.get(e.id, (False, False)),
                purged_at=purged_at,
                purge_run_id=run_id,
                legal_hold=holds is not None and holds.covers(e.investigation_id),
                # M8's field keeps its meaning: memory images only (M9, RT2).
                memory_sensitivity=_memory_state(sensitivity.get(e.id)),
                sensitivity=sensitivity.get(e.id),
            )
        )
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
    rows = [(e, name) for e, name in (await session.execute(stmt)).all()]
    return await _rows(session, org_id, rows), total


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
    return (await _rows(session, org_id, [(evidence, name)]))[0]


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
