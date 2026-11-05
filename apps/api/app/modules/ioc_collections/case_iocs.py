"""The case-wide IOC read (frozen entry point of M6 phase 1; implemented by phase 2, RT11).

Aggregates `iocs` over the latest succeeded job per evidence of the case
(`investigations.timeline.latest_succeeded_jobs`), deduplicated by (type, value), with
`count_jobs`, first / last seen, up to 5 source jobs, the collections holding each IOC and
its `ioc_key`. Both the phase-2 route (`GET /investigations/{inv}/iocs`) and the phase-3
snapshot builder call it; the signature never changes.
"""

import uuid
from collections.abc import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ioc_collections.schemas import CaseIocPage

MAX_PAGE = 500


async def case_iocs(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    *,
    types: Sequence[str] | None = None,
    q: str | None = None,
    limit: int,
    cursor: str | None = None,
) -> CaseIocPage:
    """Phase 2."""
    raise NotImplementedError("ioc_collections.case_iocs.case_iocs lands in M6 phase 2")
