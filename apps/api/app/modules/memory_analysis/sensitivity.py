"""Memory sensitivity entry point (M8 phase 1 STUB; phase 8 owns the body, never the
signature).

`apply_memory_default(session, org_id, evidence_id, actor_id) -> bool` marks the evidence
`restricted` and upserts its M6 share policy to `ai_excluded = ti_excluded = true` (never
loosening), in the caller's transaction; idempotent; returns True when it changed anything
(the caller audits `memory.sensitivity_defaulted`). Called by the `kind=memory` upload and by
every memory job request (phase 6).

Phase 1: a no-op returning False, so the stack runs while no memory result can exist (the
phase-1 worker fails every job `not_implemented`).
"""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession


async def apply_memory_default(
    session: AsyncSession, org_id: uuid.UUID, evidence_id: uuid.UUID, actor_id: uuid.UUID
) -> bool:
    del session, org_id, evidence_id, actor_id
    return False
