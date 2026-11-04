"""Migration 0009: RLS, append-only results, the run status graph, the monotonic key
version, column grants and constraints of the threat-intel tables (M4 phase 1)."""

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.tenancy import tenant_session
from app.modules.threat_intel.models import (
    TiEnrichmentRun,
    TiProviderConfig,
    TiResult,
    TiRunIndex,
    TiRunItem,
)
from tests.integration.seed import Tenant, seed_tenant
from tests.ti_helpers import DOMAIN_KEY, sealed_columns, seed_config, seed_result, seed_run

TENANT_MODELS = (TiProviderConfig, TiEnrichmentRun, TiRunItem, TiResult)


async def _seed_all(t: Tenant) -> uuid.UUID:
    await seed_config(t)
    run_id = await seed_run(t)
    await seed_result(t, run_id)
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text(
                "INSERT INTO ti_org_settings (organization_id, excluded_suffixes) VALUES (:o, :x)"
            ),
            {"o": t.org_id, "x": '["corp.example.com"]'},
        )
    return run_id


async def _count(org: uuid.UUID | None, table: str) -> int:
    async with tenant_session(org, None) as s:
        return int((await s.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one())


TABLES = (
    "ti_provider_configs",
    "ti_org_settings",
    "ti_enrichment_runs",
    "ti_run_items",
    "ti_results",
)


async def test_tenant_tables_are_isolated() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    await _seed_all(a)
    for table in TABLES:
        assert await _count(a.org_id, table) == 1, table
        assert await _count(b.org_id, table) == 0, table
        assert await _count(None, table) == 0, table  # no context: nothing


async def test_run_index_is_system_visible_but_tenant_scoped() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    await seed_run(a)
    assert await _count(None, "ti_run_index") == 1  # trusted workers (system session)
    assert await _count(a.org_id, "ti_run_index") == 1
    assert await _count(b.org_id, "ti_run_index") == 0


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO ti_org_settings (organization_id) VALUES (:other)",
        "INSERT INTO ti_provider_configs (organization_id, provider) VALUES (:other, 'otx')",
        "INSERT INTO ti_run_index (run_id, organization_id, status, deadline_at) "
        "VALUES (:run, :other, 'queued', now())",
    ],
)
async def test_rows_cannot_be_written_into_another_org(statement: str) -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    run_id = await seed_run(a)
    with pytest.raises(DBAPIError, match="row-level security"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(text(statement), {"other": b.org_id, "run": run_id})


async def test_items_cannot_point_at_another_orgs_result() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    foreign_result = await seed_result(b, await seed_run(b))
    run_id = await seed_run(a)
    with pytest.raises(DBAPIError, match="foreign key"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(
                text("UPDATE ti_run_items SET state = 'cached', result_id = :r WHERE run_id = :id"),
                {"r": foreign_result, "id": run_id},
            )


# --- ti_results: append-only ------------------------------------------------------------


@pytest.mark.parametrize(
    "statement", ["UPDATE ti_results SET found = false", "DELETE FROM ti_results"]
)
async def test_app_role_cannot_mutate_results(statement: str) -> None:
    a = await seed_tenant("alpha")
    await seed_result(a, await seed_run(a))
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(text(statement))


@pytest.mark.parametrize(
    "statement", ["UPDATE ti_results SET found = false", "DELETE FROM ti_results"]
)
async def test_trigger_blocks_owner_result_mutations(
    statement: str, owner_engine: AsyncEngine
) -> None:
    a = await seed_tenant("alpha")
    await seed_result(a, await seed_run(a))
    with pytest.raises(DBAPIError, match="append-only"):
        async with owner_engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.org_id', :o, true)"), {"o": str(a.org_id)}
            )
            await conn.execute(text(statement))


async def test_results_are_unique_per_run_provider_and_ioc() -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_run(a)
    await seed_result(a, run_id)
    with pytest.raises(DBAPIError, match="uq_ti_results_run_id_provider_ioc_key"):
        await seed_result(a, run_id)


# --- the run status graph -----------------------------------------------------------------


async def _set_status(t: Tenant, run_id: uuid.UUID, status: str) -> None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text("UPDATE ti_enrichment_runs SET status = :s WHERE id = :id"),
            {"s": status, "id": run_id},
        )


@pytest.mark.parametrize(
    "path",
    [
        ["running", "waiting", "running", "completed"],
        ["running", "partial"],
        ["running", "failed"],
        ["running", "waiting", "partial"],
        ["running", "waiting", "failed"],
        ["partial"],  # deadline / fallback reaper before the first slice
        ["failed"],
    ],
)
async def test_legal_run_transitions(path: list[str]) -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_run(a)
    for status in path:
        await _set_status(a, run_id, status)


@pytest.mark.parametrize(
    ("path", "illegal"),
    [
        ([], "completed"),
        ([], "waiting"),
        (["running", "waiting"], "completed"),
        (["running"], "queued"),
        (["running", "waiting"], "queued"),
    ],
)
async def test_illegal_run_transitions(path: list[str], illegal: str) -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_run(a)
    for status in path:
        await _set_status(a, run_id, status)
    with pytest.raises(DBAPIError, match="illegal ti run transition"):
        await _set_status(a, run_id, illegal)


@pytest.mark.parametrize("final", ["completed", "partial", "failed"])
async def test_final_runs_are_immutable(final: str) -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_run(a)
    await _set_status(a, run_id, "running")
    await _set_status(a, run_id, final)
    with pytest.raises(DBAPIError, match="is final"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(
                text("UPDATE ti_enrichment_runs SET summary = '{}' WHERE id = :id"), {"id": run_id}
            )


async def test_run_identity_is_immutable_even_for_the_owner(owner_engine: AsyncEngine) -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_run(a)
    with pytest.raises(DBAPIError, match="identity columns are immutable"):
        async with owner_engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.org_id', :o, true)"), {"o": str(a.org_id)}
            )
            await conn.execute(
                text("UPDATE ti_enrichment_runs SET providers = '[\"otx\"]' WHERE id = :id"),
                {"id": run_id},
            )


# --- monotonic key_version (RT18) --------------------------------------------------------


async def _update_key(t: Tenant, config_id: uuid.UUID, values: dict[str, object]) -> None:
    assignments = ", ".join(f"{k} = :{k}" for k in values)
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text(f"UPDATE ti_provider_configs SET {assignments} WHERE id = :id"),
            {**values, "id": config_id},
        )


async def test_a_new_key_needs_a_higher_version() -> None:
    a = await seed_tenant("alpha")
    config_id = await seed_config(a, version=1)
    with pytest.raises(DBAPIError, match="higher key_version"):
        await _update_key(a, config_id, sealed_columns("k1", 1, last4="wxyz"))
    await _update_key(a, config_id, sealed_columns("k1", 2, last4="wxyz"))
    with pytest.raises(DBAPIError, match="may not decrease"):
        await _update_key(a, config_id, sealed_columns("k1", 1))


async def test_reseal_under_another_kid_keeps_the_version() -> None:
    a = await seed_tenant("alpha")
    config_id = await seed_config(a, version=3)
    await _update_key(a, config_id, sealed_columns("k2", 3))  # same last4: a re-seal
    with pytest.raises(DBAPIError, match="higher key_version"):
        await _update_key(a, config_id, sealed_columns("k2", 3))  # same kid: a new key
    with pytest.raises(DBAPIError, match="higher key_version"):
        await _update_key(a, config_id, sealed_columns("k3", 3, last4="zzzz"))


async def test_removing_a_key_keeps_the_version_floor() -> None:
    a = await seed_tenant("alpha")
    config_id = await seed_config(a, version=2)
    cleared = dict.fromkeys(("key_kid", "key_epk", "key_nonce", "key_ct", "key_last4"))
    await _update_key(a, config_id, cleared)
    with pytest.raises(DBAPIError, match="higher key_version"):
        await _update_key(a, config_id, sealed_columns("k1", 2))
    await _update_key(a, config_id, sealed_columns("k1", 3))


# --- column grants -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "assignment",
    [
        "ti_provider_configs SET organization_id = organization_id",
        "ti_provider_configs SET provider = 'virustotal'",
        "ti_provider_configs SET created_at = now()",
        "ti_enrichment_runs SET organization_id = organization_id",
        "ti_enrichment_runs SET created_at = now()",
        "ti_enrichment_runs SET providers = '[]'",
        "ti_run_items SET provider = 'otx'",
        "ti_run_items SET value_norm = 'other.example.com'",
        "ti_run_items SET seq = 5",
        "ti_run_items SET organization_id = organization_id",
        "ti_run_index SET organization_id = organization_id",
        "ti_run_index SET run_id = run_id",
        "ti_org_settings SET organization_id = organization_id",
    ],
)
async def test_identity_columns_are_not_updatable(assignment: str) -> None:
    a = await seed_tenant("alpha")
    await _seed_all(a)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(text(f"UPDATE {assignment}"))


async def test_workers_may_update_their_columns() -> None:
    a = await seed_tenant("alpha")
    run_id = await _seed_all(a)
    result_id = await _first_result(a)
    async with tenant_session(a.org_id, a.owner_id) as s:
        await s.execute(
            text("UPDATE ti_run_items SET state = 'cached', result_id = :r WHERE run_id = :id"),
            {"r": result_id, "id": run_id},
        )
        await s.execute(
            text(
                "UPDATE ti_run_index SET status = 'running', resume_at = now(), "
                "dispatched_at = now(), lease_until = now(), lease_owner = 'w1' WHERE run_id = :id"
            ),
            {"id": run_id},
        )
        await s.execute(
            text(
                "UPDATE ti_enrichment_runs SET status = 'running', started_at = now(), "
                "summary = '{\"x\": 1}' WHERE id = :id"
            ),
            {"id": run_id},
        )
        await s.execute(
            text("UPDATE ti_provider_configs SET verify_status = 'valid', verified_at = now()")
        )
    async with tenant_session(None, None) as s:  # system session: lease bookkeeping
        await s.execute(
            text(
                "UPDATE ti_run_index SET lease_until = NULL, lease_owner = NULL WHERE run_id = :id"
            ),
            {"id": run_id},
        )


async def _first_result(t: Tenant) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        return (await s.execute(select(TiResult.id))).scalar_one()


# --- constraints ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("statement", "constraint"),
    [
        (
            "INSERT INTO ti_provider_configs (organization_id, provider) VALUES (:o, 'misp')",
            "base_url_iff_misp",
        ),
        (
            "INSERT INTO ti_provider_configs (organization_id, provider, base_url) "
            "VALUES (:o, 'otx', 'https://x.example')",
            "base_url_iff_misp",
        ),
        (
            "INSERT INTO ti_provider_configs (organization_id, provider) VALUES (:o, 'shodan')",
            "ck_ti_provider_configs_provider",
        ),
        (
            "INSERT INTO ti_provider_configs (organization_id, provider, key_kid) "
            "VALUES (:o, 'otx', 'k1')",
            "sealed_all_or_none",
        ),
        (
            "INSERT INTO ti_provider_configs (organization_id, provider, enabled) "
            "VALUES (:o, 'otx', true)",
            "enabled_needs",
        ),
        (
            "INSERT INTO ti_org_settings (organization_id, excluded_suffixes) "
            "VALUES (:o, (SELECT jsonb_agg(i) FROM generate_series(1, 51) i))",
            "excluded_suffixes",
        ),
        (
            "INSERT INTO ti_enrichment_runs (organization_id, scope, requested_by, providers, "
            "deadline_at) VALUES (:o, 'job', :u, '[]', now())",
            "job_id_iff_job_scope",
        ),
        (
            "INSERT INTO ti_enrichment_runs (organization_id, scope, requested_by, providers, "
            "deadline_at, summary) VALUES (:o, 'manual', :u, '[]', now(), "
            "jsonb_build_object('x', repeat('a', 17000)))",
            "summary_size",
        ),
    ],
)
async def test_constraints(statement: str, constraint: str) -> None:
    a = await seed_tenant("alpha")
    with pytest.raises(DBAPIError, match=constraint):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(text(statement), {"o": a.org_id, "u": a.owner_id})


async def test_enabled_needs_terms_and_key() -> None:
    a = await seed_tenant("alpha")
    config_id = await seed_config(a)
    with pytest.raises(DBAPIError, match="enabled_needs_terms"):
        await _update_key(a, config_id, {"enabled": True})
    await _update_key(a, config_id, {"enabled": True, "terms_ack_at": datetime.now(UTC)})
    with pytest.raises(DBAPIError, match="enabled_needs_key"):
        await _update_key(
            a, config_id, dict.fromkeys(("key_kid", "key_epk", "key_nonce", "key_ct", "key_last4"))
        )


@pytest.mark.parametrize(
    ("assignment", "constraint"),
    [
        ("state = 'abandoned'", "reason_iff_abandoned"),
        ("reason = 'deadline'", "reason_iff_abandoned"),
        ("state = 'done'", "result_iff_answered"),
        ("state = 'abandoned', reason = 'bored'", "ck_ti_run_items_reason"),
    ],
)
async def test_item_constraints(assignment: str, constraint: str) -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_run(a)
    with pytest.raises(DBAPIError, match=constraint):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(
                text(f"UPDATE ti_run_items SET {assignment} WHERE run_id = :id"), {"id": run_id}
            )


@pytest.mark.parametrize(
    ("columns", "constraint"),
    [
        ("'error', now() + interval '1 hour', false, NULL", "expires_iff_cacheable"),
        ("'ok', NULL, false, NULL", "expires_iff_cacheable"),
        ("'not_found', now(), true, NULL", "found_only_ok"),
        ("'ok', now(), true, 'javascript:alert(1)'", "permalink_https"),
    ],
)
async def test_result_constraints(columns: str, constraint: str) -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_run(a)
    with pytest.raises(DBAPIError, match=constraint):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(
                text(
                    "INSERT INTO ti_results (organization_id, run_id, provider, ioc_type, "
                    "value_norm, ioc_key, status, expires_at, found, permalink) "
                    f"VALUES (:o, :r, 'mock', 'domain', 'x.example.com', :k, {columns})"
                ),
                {"o": a.org_id, "r": run_id, "k": DOMAIN_KEY},
            )


async def test_cache_lookup_index_exists(owner_engine: AsyncEngine) -> None:
    async with owner_engine.connect() as conn:
        definition = (
            await conn.execute(
                text(
                    "SELECT indexdef FROM pg_indexes WHERE indexname = "
                    "'ix_ti_results_organization_id_ioc_key_provider_fetched_at'"
                )
            )
        ).scalar_one()
    assert "(organization_id, ioc_key, provider, fetched_at DESC)" in definition


async def test_orm_round_trip_counts() -> None:
    a = await seed_tenant("alpha")
    await _seed_all(a)
    async with tenant_session(a.org_id, a.owner_id) as s:
        for model in (*TENANT_MODELS, TiRunIndex):
            assert (await s.execute(select(func.count()).select_from(model))).scalar_one() == 1
