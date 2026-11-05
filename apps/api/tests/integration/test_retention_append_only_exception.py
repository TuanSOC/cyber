"""The append-only exception of 0014 (M7 phase 3): `cyberlab_retention` may DELETE from
`ti_results` and the four append-only `ai_*` tables (and its other purgeable tables), never
from `audit_logs`, `evidence_hashes`, custody, `report_versions` or note versions; nobody may
UPDATE an exception table; the app role cannot DELETE anything."""

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.tenancy import tenant_session
from tests.ai_helpers import seed_ai_run
from tests.case_helpers import seed_evidence
from tests.integration.seed import Tenant, seed_tenant
from tests.integration.test_retention_preview import _old_ti_result
from tests.ops_helpers import retention_session

STRICT = (
    "audit_logs",
    "evidence_hashes",
    "evidence_custody_events",
    "report_versions",
    "analyst_note_versions",
    "investigation_status_events",
    "retention_run_items",
    "evidence_purges",
)
EXCEPTION = ("ti_results", "ai_run_inputs", "ai_context_refs", "ai_outputs", "ai_citations")


async def _seed() -> tuple[Tenant, uuid.UUID, uuid.UUID]:
    t = await seed_tenant(f"ao-{uuid.uuid4().hex[:6]}")
    await seed_evidence(t)
    result_id = await _old_ti_result(t, "append.example.com")
    run_id = await seed_ai_run(t)
    return t, result_id, run_id


async def test_the_retention_role_deletes_exception_rows() -> None:
    t, result_id, run_id = await _seed()
    async with retention_session(t.org_id) as s:
        await s.execute(text("DELETE FROM ti_run_items WHERE result_id = :r"), {"r": result_id})
        deleted = await s.execute(text("DELETE FROM ti_results WHERE id = :r"), {"r": result_id})
        assert deleted.rowcount == 1  # type: ignore[attr-defined]
        for table in ("ai_citations", "ai_outputs", "ai_context_refs", "ai_run_inputs"):
            await s.execute(text(f"DELETE FROM {table} WHERE run_id = :r"), {"r": run_id})  # noqa: S608
        gone = await s.execute(text("DELETE FROM ai_runs WHERE id = :r"), {"r": run_id})
        assert gone.rowcount == 1  # type: ignore[attr-defined]
    async with tenant_session(t.org_id, None) as s:
        left = await s.execute(
            text("SELECT count(*) FROM ai_run_index WHERE run_id = :r"), {"r": run_id}
        )
        assert left.scalar_one() == 0  # cascaded


@pytest.mark.parametrize("table", STRICT)
async def test_the_retention_role_cannot_delete_strict_tables(table: str) -> None:
    t, _, _ = await _seed()
    with pytest.raises(DBAPIError):
        async with retention_session(t.org_id) as s:
            await s.execute(text(f"DELETE FROM {table}"))  # noqa: S608


@pytest.mark.parametrize("table", EXCEPTION)
async def test_nobody_updates_an_exception_table(table: str) -> None:
    t, _, _ = await _seed()
    with pytest.raises(DBAPIError):
        async with retention_session(t.org_id) as s:
            await s.execute(text(f"UPDATE {table} SET organization_id = organization_id"))  # noqa: S608
    with pytest.raises(DBAPIError):
        async with tenant_session(t.org_id, None) as s:
            await s.execute(text(f"UPDATE {table} SET organization_id = organization_id"))  # noqa: S608


# Tables the seed fills (the trigger fires per row).
@pytest.mark.parametrize("table", ("ti_results", "ai_run_inputs"))
async def test_the_owner_cannot_update_an_exception_table(
    table: str, owner_engine: AsyncEngine
) -> None:
    t, _, _ = await _seed()
    # The owner is bound by FORCE RLS: the org context makes the rows visible to it.
    with pytest.raises(DBAPIError, match="append-only"):
        async with owner_engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.org_id', :o, true)"), {"o": str(t.org_id)}
            )
            await conn.execute(text(f"UPDATE {table} SET organization_id = organization_id"))  # noqa: S608


@pytest.mark.parametrize("table", (*EXCEPTION, "network_flows", "ai_runs", "ti_run_items"))
async def test_the_app_role_cannot_delete(table: str) -> None:
    t, _, _ = await _seed()
    with pytest.raises(DBAPIError):
        async with tenant_session(t.org_id, None) as s:
            await s.execute(text(f"DELETE FROM {table}"))  # noqa: S608


async def test_the_owner_cannot_delete_an_exception_row(owner_engine: AsyncEngine) -> None:
    t, result_id, _ = await _seed()
    with pytest.raises(DBAPIError, match="append-only"):
        async with owner_engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.org_id', :o, true)"), {"o": str(t.org_id)}
            )
            await conn.execute(
                text("DELETE FROM ti_run_items WHERE result_id = :r"), {"r": result_id}
            )
            await conn.execute(text("DELETE FROM ti_results WHERE id = :r"), {"r": result_id})
