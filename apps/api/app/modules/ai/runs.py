"""Run creation and dispatch (signatures FROZEN in phase 1; phase 7 fills the bodies).

`create_run` writes, in the caller's transaction: `ai_runs` (+ incident children with
`parent_run_id`, task `job_digest` and the parent's deadline), `ai_run_index`,
`ai_run_inputs` (stage `base`), `ai_context_refs` and the `ai.run_requested` audit row (no
content). It returns `(root run, deduplicated)`. `dispatch` publishes `ai.run` after the
commit (children first, then the parent); a publish failure is recovered by `ai.resume`.
"""

import uuid
from collections.abc import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ai.contracts import AiRunRequest, BuiltRun
from app.modules.ai.models import AiRun


async def create_run(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    req: AiRunRequest,
    built: BuiltRun,
) -> tuple[AiRun, bool]:
    raise NotImplementedError("phase 7")


async def dispatch(run_ids: Sequence[uuid.UUID]) -> None:
    raise NotImplementedError("phase 7")
