"""Migrations replay from scratch in one alembic run (M3 RT7); 0009 and 0006 downgrade
cleanly.

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
TI_REGCLASSES = "SELECT " + ", ".join(f"to_regclass('{t}')::text" for t in TI_TABLES)
TI_FUNCTIONS = (
    "SELECT proname::text FROM pg_proc WHERE proname IN "
    "('ti_run_transition', 'ti_key_version_guard') ORDER BY proname"
)


async def _ti_tables(engine: AsyncEngine) -> list[object]:
    async with engine.connect() as conn:
        return [t for t in (await conn.execute(text(TI_REGCLASSES))).one() if t is not None]


async def test_downgrade_0006_then_fresh_upgrade_head(owner_engine: AsyncEngine) -> None:
    await get_engine().dispose()
    try:
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

    assert await _scalars(owner_engine, "SELECT version_num FROM alembic_version") == ["0009"]
    assert await _ti_tables(owner_engine) == list(TI_TABLES)
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
