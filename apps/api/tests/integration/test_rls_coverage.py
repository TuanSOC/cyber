import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.conftest import assert_test_database, assert_test_redis


async def test_every_tenant_table_has_forced_rls(owner_engine: AsyncEngine) -> None:
    """Any table with an organization_id column must have RLS enabled AND forced."""
    query = text(
        """
        SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'r'
          AND (
            EXISTS (SELECT 1 FROM information_schema.columns col
                    WHERE col.table_schema = 'public' AND col.table_name = c.relname
                      AND col.column_name = 'organization_id')
            OR c.relname = 'organizations'
          )
        """
    )
    async with owner_engine.connect() as conn:
        rows = (await conn.execute(query)).all()

    assert {r.relname for r in rows} >= {
        "investigations",
        "evidence",
        "audit_logs",
        "ti_provider_configs",
        "ti_org_settings",
        "ti_enrichment_runs",
        "ti_run_items",
        "ti_run_index",
        "ti_results",
        "ai_provider_configs",
        "ai_org_settings",
        "ai_runs",
        "ai_run_index",
        "ai_run_inputs",
        "ai_context_refs",
        "ai_outputs",
        "ai_citations",
        # M6 (migration 0012)
        "investigation_status_events",
        "evidence_share_policies",
        "analyst_notes",
        "analyst_note_versions",
        "ioc_collections",
        "ioc_collection_items",
        "case_attack_mappings",
        "reports",
        "report_versions",
        "report_citations",
        "report_renders",
        "report_render_index",
    }
    unprotected = [r.relname for r in rows if not (r.relrowsecurity and r.relforcerowsecurity)]
    assert unprotected == []


async def test_system_visible_job_index_holds_no_tenant_data(owner_engine: AsyncEngine) -> None:
    """System sessions see every row of the job index, so it stays narrow: ids, analyzer
    (routing, for the per-analyzer global cap), status, deadline."""
    query = text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = 'analysis_job_index'"
    )
    async with owner_engine.connect() as conn:
        columns = set((await conn.execute(query)).scalars())
    assert columns == {"job_id", "organization_id", "analyzer", "status", "deadline_at"}


async def test_system_visible_ti_run_index_holds_no_tenant_data(
    owner_engine: AsyncEngine,
) -> None:
    """Same rule for the threat-intel run index (M4 RT25): ids and scheduling only, never
    IOC values, providers or results."""
    query = text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = 'ti_run_index'"
    )
    async with owner_engine.connect() as conn:
        columns = set((await conn.execute(query)).scalars())
    assert columns == {
        "run_id",
        "organization_id",
        "status",
        "resume_at",
        "deadline_at",
        "dispatched_at",
        "lease_until",
        "lease_owner",
    }


async def test_system_visible_ai_run_index_holds_no_tenant_data(
    owner_engine: AsyncEngine,
) -> None:
    """Same rule for the AI run index (M5): ids, scheduling and call counts only, never
    context, model output or provider data."""
    query = text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = 'ai_run_index'"
    )
    async with owner_engine.connect() as conn:
        columns = set((await conn.execute(query)).scalars())
    assert columns == {
        "run_id",
        "organization_id",
        "status",
        "resume_at",
        "deadline_at",
        "dispatched_at",
        "lease_until",
        "lease_owner",
        "attempts",
        "calls",
    }


async def test_system_visible_report_render_index_holds_no_tenant_data(
    owner_engine: AsyncEngine,
) -> None:
    """Same rule for the report render index (M6): ids and scheduling only, never the
    format, the token, hashes or report content."""
    query = text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = 'report_render_index'"
    )
    async with owner_engine.connect() as conn:
        columns = set((await conn.execute(query)).scalars())
    assert columns == {
        "render_id",
        "organization_id",
        "status",
        "dispatched_at",
        "deadline_at",
        "attempts",
    }


async def test_every_rls_table_has_a_policy(owner_engine: AsyncEngine) -> None:
    query = text(
        """
        SELECT c.relname FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relrowsecurity
          AND NOT EXISTS (SELECT 1 FROM pg_policies p
                          WHERE p.schemaname = 'public' AND p.tablename = c.relname)
        """
    )
    async with owner_engine.connect() as conn:
        assert (await conn.execute(query)).scalars().all() == []


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+asyncpg://u:p@postgres:5432/cyberlab",
        "postgresql+asyncpg://u:p@postgres:5432/cyberlab_testing",
    ],
)
def test_harness_refuses_non_test_databases(url: str) -> None:
    with pytest.raises(RuntimeError, match="refusing"):
        assert_test_database(url)


@pytest.mark.parametrize(
    "url", ["redis://redis:6379", "redis://redis:6379/0", "redis://redis:6379?db=0"]
)
def test_harness_refuses_redis_db_zero(url: str) -> None:
    with pytest.raises(RuntimeError, match="refusing"):
        assert_test_redis(url)


def test_harness_accepts_redis_test_db() -> None:
    assert_test_redis("redis://redis:6379/1")
