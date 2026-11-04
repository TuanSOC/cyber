"""Context builder entry points (signatures FROZEN in phase 1; phase 4 fills the bodies).

Both run inside the caller's `require()` tenant session: they never open their own session
and never bypass RLS. Errors are `contracts.ContextBuildError(code)`.
"""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ai.contracts import AiRunRequest, BuiltRun, FrozenContext
from app.modules.ai.models import AiOrgSettings


async def build_run(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    req: AiRunRequest,
    settings_row: AiOrgSettings,
) -> BuiltRun:
    """The root context and, for `incident_summary`, one `job_digest` child per job."""
    raise NotImplementedError("phase 4")


async def preview(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    req: AiRunRequest,
    settings_row: AiOrgSettings,
) -> FrozenContext:
    """What `build_run` would send (an incident previews its root); never persisted."""
    raise NotImplementedError("phase 4")
