"""Legal holds as seen by retention (M7; frozen signature, phase 3 implements the query).

A hold protects while it is active and for `RETENTION_POLICY_DELAY_DAYS` after its release
(RT1). An org hold covers every case of the org (the sweep then skips the org).
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import ColumnElement, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.modules.retention.models import LegalHold


@dataclass(frozen=True)
class HoldSet:
    org_wide: bool = False
    investigation_ids: frozenset[uuid.UUID] = field(default_factory=frozenset)

    def covers(self, investigation_id: uuid.UUID | None) -> bool:
        return self.org_wide or (
            investigation_id is not None and investigation_id in self.investigation_ids
        )


def delay() -> timedelta:
    return timedelta(days=get_settings().retention_policy_delay_days)


def protects_until(hold: LegalHold) -> datetime | None:
    """When a released hold stops protecting (None while it is not released)."""
    return hold.released_at + delay() if hold.released_at is not None else None


def protecting(now: datetime) -> ColumnElement[bool]:
    """Active, or released less than the delay before `now` (RT1)."""
    return or_(LegalHold.released_at.is_(None), LegalHold.released_at > now - delay())


async def active_holds(session: AsyncSession, org_id: uuid.UUID, *, now: datetime) -> HoldSet:
    """Holds active at `now`, or released less than the delay ago (RT1)."""
    rows = (
        await session.execute(
            select(LegalHold.scope, LegalHold.investigation_id).where(
                LegalHold.organization_id == org_id, protecting(now)
            )
        )
    ).all()
    return HoldSet(
        org_wide=any(scope == "org" for scope, _ in rows),
        investigation_ids=frozenset(case for scope, case in rows if case is not None),
    )
