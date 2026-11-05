"""Which AI outputs and report versions cite this row (frozen entry point of M6 phase 1;
implemented by phase 3): `ai_citations` (verified only, the M5 index on (org, kind, ref_id))
and `report_citations` (the 0012 index on the same columns)."""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.reports.schemas import CitedByOut


async def cited_by(
    session: AsyncSession, org_id: uuid.UUID, kind: str, ref_id: str
) -> CitedByOut:
    """Phase 3."""
    raise NotImplementedError("reports.cited_by.cited_by lands in M6 phase 3")
