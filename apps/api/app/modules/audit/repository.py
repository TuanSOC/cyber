import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import PageParams
from app.modules.audit.models import AuditLog
from app.modules.users.models import User


@dataclass(frozen=True)
class AuditFilters:
    action: str | None = None
    actor_id: uuid.UUID | None = None
    occurred_from: datetime | None = None
    occurred_to: datetime | None = None


def _filtered(org_id: uuid.UUID, filters: AuditFilters) -> Select[AuditLog]:
    # Explicit org filter in addition to RLS (defense in depth).
    stmt = select(AuditLog).where(AuditLog.organization_id == org_id)
    if filters.action:
        stmt = stmt.where(AuditLog.action == filters.action)
    if filters.actor_id:
        stmt = stmt.where(AuditLog.actor_id == filters.actor_id)
    if filters.occurred_from:
        stmt = stmt.where(AuditLog.occurred_at >= filters.occurred_from)
    if filters.occurred_to:
        stmt = stmt.where(AuditLog.occurred_at < filters.occurred_to)
    return stmt


async def list_logs(
    session: AsyncSession, org_id: uuid.UUID, filters: AuditFilters, page: PageParams
) -> tuple[list[tuple[AuditLog, str | None]], int]:
    base = _filtered(org_id, filters)
    total = (await session.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    stmt = (
        base.add_columns(User.email)
        .outerjoin(User, User.id == AuditLog.actor_id)
        .order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
        .limit(page.limit)
        .offset(page.offset)
    )
    rows = [(row[0], row[1]) for row in (await session.execute(stmt)).all()]
    return rows, total
