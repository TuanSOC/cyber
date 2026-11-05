import enum
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import ColumnElement, Select, UnaryExpression, func, or_, select, tuple_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import PageParams
from app.modules.evidence.models import Evidence
from app.modules.investigations.models import (
    Investigation,
    InvestigationStatus,
    InvestigationStatusEvent,
    Severity,
)
from app.modules.organizations.models import Organization
from app.modules.users.models import User

_CASE_REF = re.compile(r"^(?:case-?)?0*(\d{1,9})$", re.IGNORECASE)


class SortKey(enum.StrEnum):
    CREATED_ASC = "created_at"
    CREATED_DESC = "-created_at"
    SEVERITY_ASC = "severity"
    SEVERITY_DESC = "-severity"


@dataclass(frozen=True)
class Filters:
    q: str | None = None
    status: InvestigationStatus | None = None
    severity: Severity | None = None
    sort: SortKey = SortKey.CREATED_DESC


@dataclass(frozen=True)
class Row:
    investigation: Investigation
    created_by_name: str
    evidence_count: int


def escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def next_case_number(session: AsyncSession, org_id: uuid.UUID) -> int:
    """Row-locks the org until commit, so concurrent creates get distinct numbers."""
    stmt = (
        update(Organization)
        .where(Organization.id == org_id)
        # Keep updated_at: allocating a case number is not an org modification.
        .values(
            next_case_number=Organization.next_case_number + 1,
            updated_at=Organization.updated_at,
        )
        .returning(Organization.next_case_number - 1)
    )
    return (await session.execute(stmt)).scalar_one()


def _base(org_id: uuid.UUID) -> Select[Investigation, str, int]:
    # All evidence of the case, archived included (archived evidence stays part of the case).
    evidence_count = (
        select(func.count())
        .where(Evidence.investigation_id == Investigation.id)
        .correlate(Investigation)
        .scalar_subquery()
    )
    return (
        select(Investigation, User.display_name, evidence_count)
        .join(User, User.id == Investigation.created_by)
        # Explicit org filter in addition to RLS (defense in depth).
        .where(Investigation.organization_id == org_id)
    )


def _apply_filters(
    stmt: Select[Investigation, str, int], f: Filters
) -> Select[Investigation, str, int]:
    if f.q:
        term = f.q.strip()
        conditions: list[ColumnElement[bool]] = [
            Investigation.title.ilike(f"%{escape_like(term)}%", escape="\\")
        ]
        if match := _CASE_REF.match(term):
            conditions.append(Investigation.case_number == int(match.group(1)))
        stmt = stmt.where(or_(*conditions))
    if f.status:
        stmt = stmt.where(Investigation.status == f.status)
    if f.severity:
        stmt = stmt.where(Investigation.severity == f.severity)
    return stmt


_ORDER: dict[SortKey, tuple[UnaryExpression[Any], ...]] = {
    SortKey.CREATED_ASC: (Investigation.created_at.asc(), Investigation.id.asc()),
    SortKey.CREATED_DESC: (Investigation.created_at.desc(), Investigation.id.desc()),
    # Postgres orders enums by declaration: low < medium < high < critical.
    SortKey.SEVERITY_ASC: (
        Investigation.severity.asc(),
        Investigation.created_at.desc(),
        Investigation.id.desc(),
    ),
    SortKey.SEVERITY_DESC: (
        Investigation.severity.desc(),
        Investigation.created_at.desc(),
        Investigation.id.desc(),
    ),
}


async def list_investigations(
    session: AsyncSession, org_id: uuid.UUID, filters: Filters, page: PageParams
) -> tuple[list[Row], int]:
    stmt = _apply_filters(_base(org_id), filters)
    total = (await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    stmt = stmt.order_by(*_ORDER[filters.sort]).limit(page.limit).offset(page.offset)
    rows = [Row(inv, name, count) for inv, name, count in (await session.execute(stmt)).all()]
    return rows, total


async def get_row(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    *,
    for_update: bool = False,
) -> Row | None:
    stmt = _base(org_id).where(Investigation.id == investigation_id)
    if for_update:
        # FOR NO KEY UPDATE: does not block evidence inserts (their FK takes KEY SHARE).
        stmt = stmt.with_for_update(of=Investigation, key_share=True)
    result = (await session.execute(stmt)).one_or_none()
    return Row(result[0], result[1], result[2]) if result else None


async def list_status_events(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    *,
    limit: int,
    before: tuple[datetime, uuid.UUID] | None = None,
) -> list[tuple[InvestigationStatusEvent, str]]:
    """Newest first; `before` is the (occurred_at, id) key of the previous page's last row."""
    e = InvestigationStatusEvent
    stmt = (
        select(e, User.display_name)
        .join(User, User.id == e.actor_id)
        .where(e.organization_id == org_id, e.investigation_id == investigation_id)
    )
    if before is not None:
        stmt = stmt.where(tuple_(e.occurred_at, e.id) < tuple_(*before))
    stmt = stmt.order_by(e.occurred_at.desc(), e.id.desc()).limit(limit)
    return [(event, name) for event, name in (await session.execute(stmt)).all()]
