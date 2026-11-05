"""Retention queries of the API (RLS-bound app role, explicit org filters as well)."""

import uuid
from datetime import datetime

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import PageParams
from app.modules.investigations.models import Investigation
from app.modules.retention.holds import protecting
from app.modules.retention.models import (
    LegalHold,
    OrgRetentionPolicy,
    RetentionPolicyIndex,
    RetentionRun,
    RetentionRunItem,
)
from app.modules.users.models import User

RUN_ITEMS_SHOWN = 100


async def lock_org(session: AsyncSession, org_id: uuid.UUID) -> None:
    """Serialize policy changes and run requests of one org (transaction advisory lock; the
    retention worker takes the same key for its run bookkeeping)."""
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
        {"k": f"retention:{org_id}"},
    )


async def get_policy(
    session: AsyncSession, org_id: uuid.UUID, *, for_update: bool = False
) -> OrgRetentionPolicy | None:
    stmt = select(OrgRetentionPolicy).where(OrgRetentionPolicy.organization_id == org_id)
    if for_update:
        stmt = stmt.with_for_update()
    return (
        await session.execute(stmt.execution_options(populate_existing=True))
    ).scalar_one_or_none()


async def ensure_policy(
    session: AsyncSession, org_id: uuid.UUID, user_id: uuid.UUID
) -> OrgRetentionPolicy:
    """The org's policy row, created empty (keep everything, enforce off) if missing."""
    await session.execute(
        insert(OrgRetentionPolicy)
        .values(organization_id=org_id, updated_by=user_id)
        .on_conflict_do_nothing(index_elements=["organization_id"])
    )
    row = await get_policy(session, org_id, for_update=True)
    if row is None:  # pragma: no cover - inserted above (or by a concurrent PUT)
        raise RuntimeError("retention policy row vanished")
    return row


async def touch_index(session: AsyncSession, org_id: uuid.UUID) -> None:
    """The sweep's org list (RT3), in the transaction of every policy PUT."""
    stmt = insert(RetentionPolicyIndex).values(organization_id=org_id)
    await session.execute(
        stmt.on_conflict_do_update(
            index_elements=["organization_id"], set_={"updated_at": func.now()}
        )
    )


# --- legal holds -------------------------------------------------------------------------------


async def list_holds(
    session: AsyncSession,
    org_id: uuid.UUID,
    page: PageParams,
    *,
    investigation_id: uuid.UUID | None,
    active_only: bool,
    now: datetime,
) -> tuple[list[tuple[LegalHold, str, int | None]], int]:
    where = [LegalHold.organization_id == org_id]
    if investigation_id is not None:
        where.append(LegalHold.investigation_id == investigation_id)
    if active_only:
        where.append(protecting(now))
    total = (await session.execute(select(func.count()).where(*where))).scalar_one()
    stmt = (
        select(LegalHold, User.display_name, Investigation.case_number)
        .join(User, User.id == LegalHold.placed_by)
        .outerjoin(Investigation, Investigation.id == LegalHold.investigation_id)
        .where(*where)
        .order_by(LegalHold.placed_at.desc(), LegalHold.id.desc())
        .limit(page.limit)
        .offset(page.offset)
    )
    return [(h, name, number) for h, name, number in (await session.execute(stmt)).all()], total


async def get_hold(
    session: AsyncSession, org_id: uuid.UUID, hold_id: uuid.UUID, *, for_update: bool = False
) -> tuple[LegalHold, str, int | None] | None:
    stmt = (
        select(LegalHold, User.display_name, Investigation.case_number)
        .join(User, User.id == LegalHold.placed_by)
        .outerjoin(Investigation, Investigation.id == LegalHold.investigation_id)
        .where(LegalHold.id == hold_id, LegalHold.organization_id == org_id)
    )
    if for_update:
        stmt = stmt.with_for_update(of=LegalHold)
    row = (await session.execute(stmt)).one_or_none()
    return (row[0], row[1], row[2]) if row else None


async def case_number(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID
) -> int | None:
    stmt = select(Investigation.case_number).where(
        Investigation.id == investigation_id, Investigation.organization_id == org_id
    )
    return (await session.execute(stmt)).scalar_one_or_none()


# --- runs ------------------------------------------------------------------------------------


async def active_run(session: AsyncSession, org_id: uuid.UUID) -> RetentionRun | None:
    stmt = (
        select(RetentionRun)
        .where(
            RetentionRun.organization_id == org_id,
            RetentionRun.status.in_(("queued", "running")),
        )
        .order_by(RetentionRun.created_at.desc())
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def list_runs(
    session: AsyncSession, org_id: uuid.UUID, page: PageParams
) -> tuple[list[RetentionRun], int]:
    where = (RetentionRun.organization_id == org_id,)
    total = (await session.execute(select(func.count()).where(*where))).scalar_one()
    stmt = (
        select(RetentionRun)
        .where(*where)
        .order_by(RetentionRun.created_at.desc(), RetentionRun.id.desc())
        .limit(page.limit)
        .offset(page.offset)
    )
    return list((await session.execute(stmt)).scalars()), total


async def get_run(
    session: AsyncSession, org_id: uuid.UUID, run_id: uuid.UUID
) -> RetentionRun | None:
    stmt = select(RetentionRun).where(
        RetentionRun.id == run_id, RetentionRun.organization_id == org_id
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def run_items(
    session: AsyncSession,
    org_id: uuid.UUID,
    run_id: uuid.UUID,
    *,
    limit: int = RUN_ITEMS_SHOWN,
    offset: int = 0,
    outcome: str | None = None,
) -> tuple[list[RetentionRunItem], int, dict[str, int]]:
    """One page of the run's items (optionally of one outcome) and the run's item count per
    outcome."""
    where = (RetentionRunItem.organization_id == org_id, RetentionRunItem.run_id == run_id)
    by_outcome = {
        str(o): int(n)
        for o, n in (
            await session.execute(
                select(RetentionRunItem.outcome, func.count())
                .where(*where)
                .group_by(RetentionRunItem.outcome)
            )
        ).all()
    }
    filtered = (*where, RetentionRunItem.outcome == outcome) if outcome is not None else where
    stmt = (
        select(RetentionRunItem)
        .where(*filtered)
        .order_by(RetentionRunItem.created_at, RetentionRunItem.id)
        .limit(limit)
        .offset(offset)
    )
    return list((await session.execute(stmt)).scalars()), sum(by_outcome.values()), by_outcome
