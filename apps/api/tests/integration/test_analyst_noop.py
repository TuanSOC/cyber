"""The phase-1 analyst worker: every `ai.run` ends `failed / not_implemented` (M5 phase 1).

Phase 2 replaces `app/workers/analyst.py` and deletes this file (its own
`test_analyst_worker.py` covers the real lifecycle).
"""

import uuid

from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.ai.models import AiRun, AiRunIndex
from app.workers import analyst
from tests.ai_helpers import seed_ai_run
from tests.integration.seed import seed_tenant


async def _state(org_id: uuid.UUID, run_id: uuid.UUID) -> tuple[str, str | None, str]:
    async with tenant_session(org_id, None) as s:
        run = (await s.execute(select(AiRun).where(AiRun.id == run_id))).scalar_one()
        index = (
            await s.execute(select(AiRunIndex).where(AiRunIndex.run_id == run_id))
        ).scalar_one()
        return run.status, run.error_code, index.status


async def test_a_run_fails_as_not_implemented() -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_ai_run(a)
    status = await analyst.handle_run({"run_id": str(run_id), "org_id": str(a.org_id)})
    assert status == "failed"
    assert await _state(a.org_id, run_id) == ("failed", "not_implemented", "failed")
    # Redelivery of a final run changes nothing.
    assert await analyst.handle_run({"run_id": str(run_id), "org_id": str(a.org_id)}) is None


async def test_org_mismatch_and_bad_messages_are_dropped() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    run_id = await seed_ai_run(a)
    assert await analyst.handle_run({"run_id": str(run_id), "org_id": str(b.org_id)}) is None
    assert await analyst.handle_run({"run_id": str(uuid.uuid4()), "org_id": str(a.org_id)}) is None
    assert await analyst.handle_run({"run_id": "x", "context": "secret"}) is None
    assert await _state(a.org_id, run_id) == ("queued", None, "queued")
    assert await analyst.handle_resume({}) == 0
    await analyst.handle_verify({"org_id": str(a.org_id), "provider": "mock", "key_version": 1})
