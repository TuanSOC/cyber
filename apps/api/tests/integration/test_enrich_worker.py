"""Phase-1 enrich worker: it consumes `ti.enrich` and, having no providers yet, ends the run
`failed` with `not_implemented`; an unknown run or a mismatching org is dropped."""

import asyncio
import time
import uuid

from cyberlab_jobs import TI_ENRICH, Queues
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.threat_intel.models import TiEnrichmentRun, TiRunIndex
from app.workers import enrich
from tests.integration.seed import Tenant, seed_tenant
from tests.ti_helpers import seed_run


async def _state(t: Tenant, run_id: uuid.UUID) -> tuple[str, str, dict[str, object]]:
    async with tenant_session(t.org_id, t.owner_id) as s:
        run = (
            await s.execute(select(TiEnrichmentRun).where(TiEnrichmentRun.id == run_id))
        ).scalar_one()
        index = await s.get(TiRunIndex, run_id)
        assert index is not None
        return run.status, index.status, run.summary


async def test_run_fails_not_implemented() -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_run(a)
    await enrich.handle_enrich({"run_id": str(run_id), "org_id": str(a.org_id)})
    assert await _state(a, run_id) == ("failed", "failed", {"error_code": "not_implemented"})
    # A redelivered message for a final run is a no-op.
    await enrich.handle_enrich({"run_id": str(run_id), "org_id": str(a.org_id)})


async def test_org_mismatch_and_unknown_runs_are_dropped() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    run_id = await seed_run(a)
    await enrich.handle_enrich({"run_id": str(run_id), "org_id": str(b.org_id)})
    await enrich.handle_enrich({"run_id": str(uuid.uuid4()), "org_id": str(a.org_id)})
    await enrich.handle_enrich({"run_id": "not-a-uuid", "org_id": str(a.org_id)})
    await enrich.handle_enrich({"run_id": str(run_id), "org_id": str(a.org_id), "values": ["x"]})
    assert (await _state(a, run_id))[:2] == ("queued", "queued")


async def test_enrich_worker_consumes_its_queue() -> None:
    """Through the real broker: enrich-worker-test (ACL user `enrich`, test.enrich queue)
    started (its key check passed) and consumes `ti.enrich`."""
    from app.workers.celery_app import celery_app  # broker client only

    a = await seed_tenant("alpha")
    run_id = await seed_run(a)
    queue = Queues(get_settings().queue_prefix).enrich
    assert queue == "test.enrich"
    celery_app.send_task(
        TI_ENRICH, kwargs={"message": {"run_id": str(run_id), "org_id": str(a.org_id)}}, queue=queue
    )
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if (await _state(a, run_id))[1] == "failed":
            return
        await asyncio.sleep(0.5)
    raise AssertionError("enrich-worker-test did not consume ti.enrich")
