"""Output verification (signature FROZEN in phase 1; phase 5 fills the body).

`coerce_caps` + full `AnalysisOutput` validation (failure: `ValidationFailed(errors)`), the
canary check, every citation re-checked against the frozen context AND re-queried from the DB
inside `run_scope` (batched per table, in the org's tenant `session`), claim support with the
anchor rule (RT1), ATT&CK ids against the v20 index, post-processing and metrics.
"""

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ai.contracts import ContextRef, FrozenContext, RunScope, VerifiedOutput


async def verify_output(
    session: AsyncSession,
    org_id: uuid.UUID,
    run_scope: RunScope,
    ctx: FrozenContext,
    refs: Sequence[ContextRef],
    parsed: dict[str, Any],
    canary: str,
) -> VerifiedOutput:
    raise NotImplementedError("phase 5")
