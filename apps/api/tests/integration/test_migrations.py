"""Migrations replay from scratch in one alembic run (M3 RT7); 0015, 0014, 0013, 0012, 0011,
0010, 0009 and 0006 downgrade cleanly (0014 leaves its enum values and the inactive system user).

`env.py` applies every pending revision in a single transaction; 0006 adds an enum value,
which Postgres will not let that same transaction use. The session fixture already upgrades
the test database, but only from wherever it stood; this test rebuilds it from base so the
whole chain (0002 creates `analyzer`, 0006 extends it) runs in one invocation.

It drops and recreates every table of the (empty, between tests) test database, then
disposes the app's connection pool, whose connections cached the old type OIDs.
"""

import os
import subprocess

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.db import get_engine
from tests.conftest import API_ROOT


def _alembic(*args: str) -> None:
    subprocess.run(
        ["alembic", *args],
        check=True,
        cwd=API_ROOT,
        capture_output=True,
        env={**os.environ, "MIGRATION_DATABASE_URL": os.environ["TEST_MIGRATION_DATABASE_URL"]},
    )


async def _scalars(engine: AsyncEngine, sql: str) -> list[object]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql))).scalars())


ANALYZER_VALUES = "SELECT unnest(enum_range(NULL::analyzer))::text"
PROFILE_COLUMN = (
    "SELECT column_name FROM information_schema.columns "
    "WHERE table_name = 'analysis_jobs' AND column_name = 'profile'"
)


TI_TABLES = (
    "ti_provider_configs",
    "ti_org_settings",
    "ti_enrichment_runs",
    "ti_run_items",
    "ti_run_index",
    "ti_results",
)
RUN_INDEX_FKS = (
    "SELECT conname::text FROM pg_constraint WHERE conrelid = to_regclass('ti_run_index') "
    "AND contype = 'f' ORDER BY conname"
)
TI_REGCLASSES = "SELECT " + ", ".join(f"to_regclass('{t}')::text" for t in TI_TABLES)
TI_FUNCTIONS = (
    "SELECT proname::text FROM pg_proc WHERE proname IN "
    "('ti_run_transition', 'ti_key_version_guard') ORDER BY proname"
)


AI_TABLES = (
    "ai_provider_configs",
    "ai_org_settings",
    "ai_runs",
    "ai_run_index",
    "ai_run_inputs",
    "ai_context_refs",
    "ai_outputs",
    "ai_citations",
)
AI_REGCLASSES = "SELECT " + ", ".join(f"to_regclass('{t}')::text" for t in AI_TABLES)
AI_FUNCTIONS = (
    "SELECT proname::text FROM pg_proc WHERE proname IN "
    "('ai_run_transition', 'ai_key_version_guard') ORDER BY proname"
)


async def _ai_tables(engine: AsyncEngine) -> list[object]:
    async with engine.connect() as conn:
        return [t for t in (await conn.execute(text(AI_REGCLASSES))).one() if t is not None]


async def _ti_tables(engine: AsyncEngine) -> list[object]:
    async with engine.connect() as conn:
        return [t for t in (await conn.execute(text(TI_REGCLASSES))).one() if t is not None]


M6_TABLES = (
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
)
M6_REGCLASSES = "SELECT " + ", ".join(f"to_regclass('{t}')::text" for t in M6_TABLES)
M6_FUNCTIONS = (
    "SELECT proname::text FROM pg_proc WHERE proname IN ('analyst_note_guard', "
    "'ioc_collection_item_guard', 'report_guard', 'report_render_transition') ORDER BY proname"
)
M6_CASE_COLUMNS = (
    "SELECT column_name FROM information_schema.columns WHERE table_name = 'investigations' "
    "AND column_name IN ('tlp', 'ai_excluded', 'ti_excluded') ORDER BY column_name"
)


# 0013 (M6 review L4): same-org composite FKs for job IOCs and AI citations.
SAME_ORG_FKS = (
    "SELECT conname::text FROM pg_constraint WHERE contype = 'f' AND conrelid IN "
    "(to_regclass('ioc_collection_items'), to_regclass('report_citations')) AND "
    "(conname LIKE '%ioc_id%' OR conname LIKE '%ai_citation_id%') ORDER BY conname"
)
SAME_ORG_UNIQUES = (
    "SELECT conname::text FROM pg_constraint WHERE conname IN "
    "('uq_iocs_id_organization_id', 'uq_ai_citations_id_organization_id') ORDER BY conname"
)


async def _m6_tables(engine: AsyncEngine) -> list[object]:
    async with engine.connect() as conn:
        return [t for t in (await conn.execute(text(M6_REGCLASSES))).one() if t is not None]


# 0014 (M7 platform operations).
M7_TABLES = (
    "org_retention_policies",
    "retention_policy_index",
    "legal_holds",
    "retention_runs",
    "retention_run_items",
    "evidence_purges",
    "correlation_keys",
    "correlation_job_state",
    "job_outcomes",
)
M7_REGCLASSES = "SELECT " + ", ".join(f"to_regclass('{t}')::text" for t in M7_TABLES)
M7_FUNCTIONS = (
    "SELECT proname::text FROM pg_proc WHERE proname IN ('forbid_mutation_except_retention', "
    "'legal_hold_guard', 'org_retention_policy_touch', 'record_job_outcome', "
    "'retention_run_guard') ORDER BY proname"
)
M7_EVIDENCE_COLUMNS = (
    "SELECT column_name FROM information_schema.columns WHERE table_name = 'evidence' "
    "AND column_name IN ('declared_type', 'type_mismatch') ORDER BY column_name"
)
HOLD_SYNC_COLUMNS = (
    "SELECT column_name FROM information_schema.columns WHERE table_name = 'legal_holds' "
    "AND column_name LIKE 's3%' ORDER BY column_name"
)
EXCEPTION_TRIGGERS = (
    "SELECT c.relname::text || ':' || p.proname::text FROM pg_trigger g "
    "JOIN pg_class c ON c.oid = g.tgrelid JOIN pg_proc p ON p.oid = g.tgfoid "
    "WHERE g.tgname LIKE '%_append_only' AND c.relname IN ('ti_results', 'ai_run_inputs', "
    "'ai_context_refs', 'ai_outputs', 'ai_citations') ORDER BY 1"
)
RENDER_INDEX_PREDICATE = (
    "SELECT pg_get_expr(i.indpred, i.indrelid) FROM pg_index i "
    "WHERE i.indexrelid = to_regclass('ux_report_renders_version_id_format_renderer')"
)
CUSTODY_VALUES = "SELECT unnest(enum_range(NULL::custody_action))::text"
TRGM = "SELECT extname::text FROM pg_extension WHERE extname = 'pg_trgm'"
SYSTEM_USER = "SELECT is_active FROM users WHERE email = 'retention@system.invalid'"


async def _m7_tables(engine: AsyncEngine) -> list[object]:
    async with engine.connect() as conn:
        return [t for t in (await conn.execute(text(M7_REGCLASSES))).one() if t is not None]


def _exception_triggers(function: str) -> list[str]:
    tables = ("ai_citations", "ai_context_refs", "ai_outputs", "ai_run_inputs", "ti_results")
    return [f"{table}:{function}" for table in tables]


async def test_downgrade_0006_then_fresh_upgrade_head(owner_engine: AsyncEngine) -> None:
    await get_engine().dispose()
    try:
        _alembic("downgrade", "0014")  # 0015 (M7 review) drops the hold-sync state columns
        assert await _scalars(owner_engine, HOLD_SYNC_COLUMNS) == ["s3_synced_at"]
        _alembic("downgrade", "0013")  # 0014 (M7) goes away; enum values and the user stay
        assert await _m7_tables(owner_engine) == []
        assert await _scalars(owner_engine, M7_FUNCTIONS) == []
        assert await _scalars(owner_engine, M7_EVIDENCE_COLUMNS) == []
        assert await _scalars(owner_engine, EXCEPTION_TRIGGERS) == _exception_triggers(
            "forbid_mutation"
        )
        assert await _scalars(owner_engine, RENDER_INDEX_PREDICATE) == [
            "((status)::text <> 'failed'::text)"
        ]
        assert await _scalars(owner_engine, TRGM) == []
        # Enum values cannot be dropped (documented in 0014): they stay, unused.
        assert {"purged", "sent_to_sandbox"} <= set(
            map(str, await _scalars(owner_engine, CUSTODY_VALUES))
        )
        _alembic("downgrade", "0012")  # 0013 (M6 review L4) restores the plain FKs
        assert await _scalars(owner_engine, SAME_ORG_FKS) == [
            "fk_ioc_collection_items_ioc_id_iocs",
            "fk_report_citations_ai_citation_id_ai_citations",
        ]
        assert await _scalars(owner_engine, SAME_ORG_UNIQUES) == []
        _alembic("downgrade", "0011")  # 0012 (M6 reports + case management) goes away
        assert await _m6_tables(owner_engine) == []
        assert await _scalars(owner_engine, M6_FUNCTIONS) == []
        assert await _scalars(owner_engine, M6_CASE_COLUMNS) == []
        _alembic("downgrade", "0010")  # 0011 (M5 AI analyst) goes away completely
        assert await _ai_tables(owner_engine) == []
        assert await _scalars(owner_engine, AI_FUNCTIONS) == []
        _alembic("downgrade", "0009")  # 0010 (review L7/L8) reverts cleanly
        assert await _scalars(owner_engine, RUN_INDEX_FKS) == [
            "fk_ti_run_index_organization_id_organizations",
            "fk_ti_run_index_run_id_ti_enrichment_runs",
        ]
        _alembic("downgrade", "0008")  # 0009 (threat intel) goes away completely
        assert await _ti_tables(owner_engine) == []
        assert await _scalars(owner_engine, TI_FUNCTIONS) == []

        _alembic("downgrade", "0005")
        assert await _scalars(owner_engine, PROFILE_COLUMN) == []
        # Enum values cannot be dropped: 'static' stays, unused, as documented in 0006.
        assert await _scalars(owner_engine, ANALYZER_VALUES) == ["pcap", "static"]

        _alembic("downgrade", "base")
        assert await _scalars(owner_engine, "SELECT to_regtype('analyzer')::text") == [None]

        _alembic("upgrade", "head")  # one run: 0001..0009 (0006's ALTER TYPE autocommits)
    finally:
        _alembic("upgrade", "head")  # never leave the shared test database half-migrated
        await get_engine().dispose()

    assert await _scalars(owner_engine, "SELECT version_num FROM alembic_version") == ["0015"]
    assert await _scalars(owner_engine, HOLD_SYNC_COLUMNS) == [
        "s3_full_synced_at",
        "s3_sync_cursor_at",
        "s3_sync_cursor_id",
        "s3_sync_pass_at",
        "s3_synced_at",
    ]
    assert await _m7_tables(owner_engine) == list(M7_TABLES)
    assert await _scalars(owner_engine, M7_FUNCTIONS) == [
        "forbid_mutation_except_retention",
        "legal_hold_guard",
        "org_retention_policy_touch",
        "record_job_outcome",
        "retention_run_guard",
    ]
    assert await _scalars(owner_engine, M7_EVIDENCE_COLUMNS) == ["declared_type", "type_mismatch"]
    assert await _scalars(owner_engine, EXCEPTION_TRIGGERS) == _exception_triggers(
        "forbid_mutation_except_retention"
    )
    assert await _scalars(owner_engine, RENDER_INDEX_PREDICATE) == [
        "((status)::text <> ALL ((ARRAY['failed'::character varying, "
        "'purged'::character varying])::text[]))"
    ]
    assert await _scalars(owner_engine, TRGM) == ["pg_trgm"]
    assert await _scalars(owner_engine, SYSTEM_USER) == [False]
    assert await _scalars(owner_engine, SAME_ORG_FKS) == [
        "fk_ioc_collection_items_ioc_id_organization_id_iocs",
        "fk_report_citations_ai_citation_id_organization_id_ai_citations",
    ]
    assert await _scalars(owner_engine, SAME_ORG_UNIQUES) == [
        "uq_ai_citations_id_organization_id",
        "uq_iocs_id_organization_id",
    ]
    assert await _m6_tables(owner_engine) == list(M6_TABLES)
    assert await _scalars(owner_engine, M6_CASE_COLUMNS) == ["ai_excluded", "ti_excluded", "tlp"]
    assert await _scalars(owner_engine, M6_FUNCTIONS) == [
        "analyst_note_guard",
        "ioc_collection_item_guard",
        "report_guard",
        "report_render_transition",
    ]
    assert await _ai_tables(owner_engine) == list(AI_TABLES)
    assert await _ti_tables(owner_engine) == list(TI_TABLES)
    assert await _scalars(owner_engine, RUN_INDEX_FKS) == [
        "fk_ti_run_index_organization_id_organizations",
        "fk_ti_run_index_run_id_organization_id_ti_enrichment_runs",
    ]
    assert await _scalars(owner_engine, TI_FUNCTIONS) == [
        "ti_key_version_guard",
        "ti_run_transition",
    ]
    assert await _scalars(owner_engine, ANALYZER_VALUES) == ["pcap", "static"]
    assert await _scalars(owner_engine, PROFILE_COLUMN) == ["profile"]
    assert await _scalars(owner_engine, "SELECT 'static'::analyzer::text") == ["static"]
    constraints = await _scalars(
        owner_engine,
        "SELECT conname FROM pg_constraint WHERE conrelid = 'analysis_jobs'::regclass "
        "AND conname LIKE 'ck_analysis_jobs_profile%' ORDER BY conname",
    )
    assert constraints == ["ck_analysis_jobs_profile_iff_static", "ck_analysis_jobs_profile_valid"]
