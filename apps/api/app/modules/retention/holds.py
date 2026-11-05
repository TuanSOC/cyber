"""Legal holds as seen by retention (M7; frozen signature, phase 3 implements the query).

A hold protects while it is active and for `RETENTION_POLICY_DELAY_DAYS` after its release
(RT1). An org hold covers every case of the org (the sweep then skips the org).
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class HoldSet:
    org_wide: bool = False
    investigation_ids: frozenset[uuid.UUID] = field(default_factory=frozenset)

    def covers(self, investigation_id: uuid.UUID | None) -> bool:
        return self.org_wide or (
            investigation_id is not None and investigation_id in self.investigation_ids
        )


async def active_holds(session: AsyncSession, org_id: uuid.UUID, *, now: datetime) -> HoldSet:
    """Holds active at `now`, or released less than the delay ago (phase 3)."""
    raise NotImplementedError("retention.holds.active_holds is implemented in M7 phase 3")
