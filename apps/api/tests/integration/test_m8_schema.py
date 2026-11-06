"""Migration 0016 (M8 phase 1): the memory job checks (profile per analyzer, the OS hint iff
memory, both write-once), `job_outcomes` accepts `memory`, RLS on every memory table, the app
and retention grants, the scalar-only artifact attributes and the `memory_sensitivity` guard
(release once, never deleted, also for the owner)."""

import secrets
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.tenancy import tenant_session
from tests.case_helpers import seed_evidence
from tests.integration.seed import Tenant, seed_tenant
from tests.memory_helpers import restricted_memory_evidence, seed_memory_job
from tests.ops_helpers import retention_session

MEMORY_TABLES = (
    "memory_images",
    "memory_processes",
    "memory_connections",
    "memory_injections",
    "memory_artifacts",
    "memory_sensitivity",
)
BULK = ("memory_processes", "memory_connections", "memory_injections", "memory_artifacts")


async def _insert_job(t: Tenant, analyzer: str, profile: str | None, os_hint: str | None) -> None:
    evidence_id = await seed_evidence(t)
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text(
                "INSERT INTO analysis_jobs (organization_id, evidence_id, analyzer, profile, "
                "os_hint, requested_by, ingest_token_sha256) VALUES (:o, :e, "
                "CAST(:a AS analyzer), :p, :h, :u, :t)"
            ),
            {
                "o": t.org_id,
                "e": evidence_id,
                "a": analyzer,
                "p": profile,
                "h": os_hint,
                "u": t.owner_id,
                "t": secrets.token_hex(32),
            },
        )


@pytest.mark.parametrize(
    ("analyzer", "profile", "os_hint"),
    [
        ("memory", "triage", "auto"),
        ("memory", "full", "linux"),
        ("static", "av", None),
        ("pcap", None, None),
    ],
)
async def test_valid_job_shapes(analyzer: str, profile: str | None, os_hint: str | None) -> None:
    await _insert_job(await seed_tenant(f"ok{uuid.uuid4().hex[:8]}"), analyzer, profile, os_hint)


@pytest.mark.parametrize(
    ("analyzer", "profile", "os_hint"),
    [
        ("memory", None, "auto"),  # memory needs a profile
        ("memory", "av", "auto"),  # a static profile
        ("memory", "triage", None),  # memory needs an OS hint
        ("memory", "triage", "macos"),
        ("static", "triage", None),  # a memory profile
        ("static", "full", "auto"),  # an OS hint on another analyzer
        ("pcap", "full", None),
    ],
)
async def test_invalid_job_shapes_are_refused(
    analyzer: str, profile: str | None, os_hint: str | None
) -> None:
    t = await seed_tenant(f"bad{uuid.uuid4().hex[:8]}")
    with pytest.raises(DBAPIError, match="check constraint"):
        await _insert_job(t, analyzer, profile, os_hint)


@pytest.mark.parametrize("assignment", ["profile = 'full'", "os_hint = 'windows'"])
async def test_profile_and_os_hint_are_write_once(assignment: str) -> None:
    t = await seed_tenant(f"wo{uuid.uuid4().hex[:8]}")
    job_id = await seed_memory_job(t, status="queued", fixture=None)
    with pytest.raises(DBAPIError, match="immutable"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                text(f"UPDATE analysis_jobs SET {assignment} WHERE id = :id"), {"id": job_id}
            )


async def test_a_finished_memory_job_records_its_outcome() -> None:
    t = await seed_tenant(f"oc{uuid.uuid4().hex[:8]}")
    job_id = await seed_memory_job(t, status="running", fixture=None)
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text(
                "UPDATE analysis_jobs SET status = 'failed', error_code = 'not_implemented', "
                "finished_at = now() WHERE id = :id"
            ),
            {"id": job_id},
        )
    async with tenant_session(None, None) as s:
        kinds = (
            await s.execute(
                text(
                    "SELECT kind, subkind FROM job_outcomes WHERE error_code = 'not_implemented' "
                    "AND kind = 'memory'"
                )
            )
        ).all()
    assert ("memory", "triage") in [tuple(r) for r in kinds]


async def test_every_memory_table_has_forced_rls(owner_engine: AsyncEngine) -> None:
    async with owner_engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE relname = ANY(:t)"
                ),
                {"t": list(MEMORY_TABLES)},
            )
        ).all()
    assert {r.relname for r in rows} == set(MEMORY_TABLES)
    assert all(r.relrowsecurity and r.relforcerowsecurity for r in rows)


async def test_fixture_rows_are_isolated_per_org() -> None:
    alpha = await seed_tenant(f"ra{uuid.uuid4().hex[:8]}")
    beta = await seed_tenant(f"rb{uuid.uuid4().hex[:8]}")
    job_id = await seed_memory_job(alpha)
    async with tenant_session(alpha.org_id, alpha.owner_id) as s:
        own = await s.scalar(
            text("SELECT count(*) FROM memory_processes WHERE job_id = :j"), {"j": job_id}
        )
    async with tenant_session(beta.org_id, beta.owner_id) as s:
        for table in MEMORY_TABLES[:-1]:
            seen = await s.scalar(
                text(f"SELECT count(*) FROM {table} WHERE job_id = :j"), {"j": job_id}
            )
            assert seen == 0, table
    assert own is not None and own >= 40


@pytest.mark.parametrize("table", BULK)
async def test_the_app_role_cannot_update_or_delete_results(table: str) -> None:
    t = await seed_tenant(f"ud{uuid.uuid4().hex[:8]}")
    for statement in (f"UPDATE {table} SET job_id = job_id", f"DELETE FROM {table}"):
        with pytest.raises(DBAPIError, match="permission denied"):
            async with tenant_session(t.org_id, t.owner_id) as s:
                await s.execute(text(statement))


@pytest.mark.parametrize("table", BULK)
async def test_the_retention_role_may_delete_bulk_rows(table: str) -> None:
    t = await seed_tenant(f"rd{uuid.uuid4().hex[:8]}")
    job_id = await seed_memory_job(t)
    async with retention_session(t.org_id) as s:
        await s.execute(text(f"DELETE FROM {table} WHERE job_id = :j"), {"j": job_id})


@pytest.mark.parametrize("table", ["memory_images", "memory_sensitivity"])
async def test_the_retention_role_never_deletes_images_or_sensitivity(table: str) -> None:
    t = await seed_tenant(f"rn{uuid.uuid4().hex[:8]}")
    with pytest.raises(DBAPIError, match="permission denied"):
        async with retention_session(t.org_id) as s:
            await s.execute(text(f"DELETE FROM {table}"))


@pytest.mark.parametrize(
    "attributes",
    ['{"nested": {"a": 1}}', '{"list": [1, 2]}', '"scalar"', "[]"],
)
async def test_artifact_attributes_are_scalar_objects(attributes: str) -> None:
    t = await seed_tenant(f"at{uuid.uuid4().hex[:8]}")
    job_id = await seed_memory_job(t, fixture=None)
    with pytest.raises(DBAPIError, match="check constraint"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                text(
                    "INSERT INTO memory_artifacts (organization_id, job_id, type, attributes) "
                    "VALUES (:o, :j, 'module', CAST(:a AS jsonb))"
                ),
                {"o": t.org_id, "j": job_id, "a": attributes},
            )


async def _release(t: Tenant, evidence_id: uuid.UUID) -> None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text(
                "UPDATE memory_sensitivity SET state = 'released', released_by = :u, "
                "released_at = now(), release_reason = 'case closed' WHERE evidence_id = :e"
            ),
            {"u": t.owner_id, "e": evidence_id},
        )


async def test_sensitivity_is_released_once() -> None:
    t = await seed_tenant(f"rs{uuid.uuid4().hex[:8]}")
    evidence_id = await restricted_memory_evidence(t)
    await _release(t, evidence_id)
    with pytest.raises(DBAPIError, match="released once"):
        await _release(t, evidence_id)


async def test_sensitivity_identity_columns_cannot_change() -> None:
    t = await seed_tenant(f"si{uuid.uuid4().hex[:8]}")
    evidence_id = await restricted_memory_evidence(t)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                text("UPDATE memory_sensitivity SET defaulted_at = now() WHERE evidence_id = :e"),
                {"e": evidence_id},
            )


async def test_sensitivity_rows_are_never_deleted_even_by_the_owner(
    owner_engine: AsyncEngine,
) -> None:
    t = await seed_tenant(f"sd{uuid.uuid4().hex[:8]}")
    await restricted_memory_evidence(t)
    with pytest.raises(DBAPIError, match="never deleted"):
        async with owner_engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.org_id', :o, true)"), {"o": str(t.org_id)}
            )
            await conn.execute(text("DELETE FROM memory_sensitivity"))
