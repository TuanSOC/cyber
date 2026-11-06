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
        # M7 (migration 0014)
        "org_retention_policies",
        "retention_policy_index",
        "legal_holds",
        "retention_runs",
        "retention_run_items",
        "evidence_purges",
        "correlation_keys",
        "correlation_job_state",
        # M8 (migration 0016)
        "memory_images",
        "memory_processes",
        "memory_connections",
        "memory_injections",
        "memory_artifacts",
        "memory_sensitivity",
        # M9 (migration 0017)
        "analysis_job_segments",
        "disk_images",
        "disk_partitions",
        "disk_files",
        "disk_events",
        "disk_exports",
        # M10 (migration 0018)
        "re_programs",
        "re_functions",
        "re_call_edges",
        "re_imports",
        "re_import_refs",
        "re_strings",
        "re_string_refs",
        "re_decompilations",
        "re_function_capabilities",
        # M11 (migration 0019)
        "org_invitations",
        "invitation_index",
        "org_security_policies",
        "org_domains",
        "org_idp_configs",
        "sso_domain_index",
        "user_identities",
        "api_keys",
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


async def test_system_visible_retention_policy_index_holds_no_tenant_data(
    owner_engine: AsyncEngine,
) -> None:
    """M7 (RT3): the retention sweep's org list is ids and a timestamp only, never the
    policy values."""
    query = text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = 'retention_policy_index'"
    )
    async with owner_engine.connect() as conn:
        columns = set((await conn.execute(query)).scalars())
    assert columns == {"organization_id", "updated_at"}


@pytest.mark.parametrize(
    ("table", "columns"),
    [
        ("invitation_index", {"invitation_id", "organization_id", "token_hash", "expires_at"}),
        (
            "sso_domain_index",
            {"domain", "organization_id", "idp_config_id", "enabled", "updated_at"},
        ),
    ],
)
async def test_m11_system_lookups_hold_no_tenant_data(
    owner_engine: AsyncEngine, table: str, columns: set[str]
) -> None:
    """M11: the invitation and SSO-domain lookups are ids, a token hash or a domain, and
    scheduling only: never the invited email, a role, an issuer or a secret."""
    query = text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = :t"
    )
    async with owner_engine.connect() as conn:
        found = set((await conn.execute(query, {"t": table})).scalars())
    assert found == columns


async def test_the_mail_outbox_holds_no_tenant_column(owner_engine: AsyncEngine) -> None:
    """M11 RT9: `email_outbox` is a system table (no RLS) read by the mail worker's own DB
    role; its org column is audit context named so the RLS rule above does not apply."""
    query = text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = 'email_outbox' "
        "AND column_name = 'organization_id'"
    )
    async with owner_engine.connect() as conn:
        assert (await conn.execute(query)).scalars().all() == []


async def test_job_outcomes_is_a_system_table_without_tenant_data(
    owner_engine: AsyncEngine,
) -> None:
    """M7 runtime metrics: no org id, user, value or free text; codes and durations only."""
    query = text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = 'job_outcomes'"
    )
    async with owner_engine.connect() as conn:
        columns = set((await conn.execute(query)).scalars())
    assert columns == {
        "id",
        "kind",
        "subkind",
        "status",
        "error_code",
        "queue_ms",
        "run_ms",
        "finished_at",
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
