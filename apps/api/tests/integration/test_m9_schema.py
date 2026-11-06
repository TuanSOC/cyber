"""Migration 0017 (M9 phase 1): the disk job checks (profiles, the OS hint iff memory or disk,
`auto` for `extract`), `job_outcomes` accepts `disk`, segment sets (same investigation,
insert-only), RLS on every disk table, the app and retention grants, the export transitions,
and the `source` column of M8's `memory_sensitivity` (no rename, RT2)."""

import secrets
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.tenancy import tenant_session
from tests.case_helpers import seed_case, seed_evidence
from tests.disk_helpers import restricted_disk_evidence, seed_disk_job, seed_segment_set
from tests.integration.seed import Tenant, seed_tenant
from tests.memory_helpers import restricted_memory_evidence
from tests.ops_helpers import retention_session

DISK_TABLES = (
    "analysis_job_segments",
    "disk_images",
    "disk_partitions",
    "disk_files",
    "disk_events",
    "disk_exports",
)


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
    ("profile", "os_hint"),
    [("triage", "auto"), ("full", "windows"), ("extract", "auto")],
)
async def test_disk_jobs_accept_their_profiles(profile: str, os_hint: str) -> None:
    await _insert_job(await seed_tenant("alpha"), "disk", profile, os_hint)


@pytest.mark.parametrize(
    ("profile", "os_hint"),
    [
        ("av", "auto"),
        (None, "auto"),
        ("triage", None),
        ("extract", "linux"),  # an export job never guesses an OS
    ],
)
async def test_disk_jobs_refuse_other_profiles_and_hints(
    profile: str | None, os_hint: str | None
) -> None:
    t = await seed_tenant("alpha")
    with pytest.raises(DBAPIError, match="check"):
        await _insert_job(t, "disk", profile, os_hint)


async def test_memory_jobs_still_refuse_extract() -> None:
    t = await seed_tenant("alpha")
    with pytest.raises(DBAPIError, match="check"):
        await _insert_job(t, "memory", "extract", "auto")


async def test_disk_tables_force_rls() -> None:
    t = await seed_tenant("alpha")
    other = await seed_tenant("beta")
    job_id = await seed_disk_job(t)
    async with tenant_session(other.org_id, other.owner_id) as s:
        for table in DISK_TABLES:
            count = await s.scalar(text(f"SELECT count(*) FROM {table}"))
            assert count == 0, table
    async with tenant_session(t.org_id, t.owner_id) as s:
        files = await s.scalar(
            text("SELECT count(*) FROM disk_files WHERE job_id = :j"), {"j": job_id}
        )
    assert files and files >= 300


async def test_segments_must_share_the_job_investigation() -> None:
    t = await seed_tenant("alpha")
    [first, second] = await seed_segment_set(t, 2)
    foreign = await seed_evidence(t, await seed_case(t, title="Another case"))
    job_id = await seed_disk_job(t, [first, second], fixture=None)
    with pytest.raises(DBAPIError, match="investigation"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                text(
                    "INSERT INTO analysis_job_segments (job_id, ordinal, organization_id, "
                    "evidence_id) VALUES (:j, 2, :o, :e)"
                ),
                {"j": job_id, "o": t.org_id, "e": foreign},
            )


async def test_segments_are_insert_only_even_for_the_owner(owner_engine: AsyncEngine) -> None:
    t = await seed_tenant("alpha")
    job_id = await seed_disk_job(t, fixture=None)
    async with owner_engine.connect() as conn:
        with pytest.raises(DBAPIError, match="insert-only"):
            await conn.execute(
                text("DELETE FROM analysis_job_segments WHERE job_id = :j"), {"j": job_id}
            )


async def test_retention_deletes_listings_only() -> None:
    t = await seed_tenant("alpha")
    job_id = await seed_disk_job(t)
    async with retention_session(t.org_id) as s:
        await s.execute(text("DELETE FROM disk_events WHERE job_id = :j"), {"j": job_id})
        await s.execute(text("DELETE FROM disk_files WHERE job_id = :j"), {"j": job_id})
    for table in ("disk_images", "disk_partitions", "analysis_job_segments"):
        with pytest.raises(DBAPIError, match="permission denied"):
            async with retention_session(t.org_id) as s:
                await s.execute(text(f"DELETE FROM {table} WHERE job_id = :j"), {"j": job_id})


async def _export(t: Tenant) -> uuid.UUID:
    source = await seed_disk_job(t)
    export_job = await seed_disk_job(t, profile="extract", status="running", fixture=None)
    async with tenant_session(t.org_id, t.owner_id) as s:
        return uuid.UUID(
            str(
                await s.scalar(
                    text(
                        "INSERT INTO disk_exports (organization_id, export_job_id, "
                        "source_job_id, file_id, path, requested_by) VALUES (:o, :x, :s, "
                        ":f, 'Users/alice/AppData/Local/Temp/updater.exe', :u) RETURNING id"
                    ),
                    {
                        "o": t.org_id,
                        "x": export_job,
                        "s": source,
                        "f": uuid.uuid4(),
                        "u": t.owner_id,
                    },
                )
            )
        )


async def test_export_states_move_forward_only() -> None:
    t = await seed_tenant("alpha")
    export_id = await _export(t)
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text("UPDATE disk_exports SET state = 'ready', size = 10 WHERE id = :i"),
            {"i": export_id},
        )
    with pytest.raises(DBAPIError, match="illegal disk export transition"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                text("UPDATE disk_exports SET state = 'pending' WHERE id = :i"), {"i": export_id}
            )
    with pytest.raises(DBAPIError, match="immutable"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                text("UPDATE disk_exports SET state = 'expired', path = 'x' WHERE id = :i"),
                {"i": export_id},
            )


async def test_existing_memory_rows_keep_source_memory_and_the_check_holds() -> None:
    t = await seed_tenant("alpha")
    memory = await restricted_memory_evidence(t)
    disk = await restricted_disk_evidence(t)
    derived = await restricted_disk_evidence(t, source="derived")
    async with tenant_session(t.org_id, t.owner_id) as s:
        rows = dict(
            (
                await s.execute(
                    text(
                        "SELECT evidence_id, source FROM memory_sensitivity "
                        "WHERE evidence_id IN (:a, :b, :c)"
                    ),
                    {"a": memory, "b": disk, "c": derived},
                )
            ).all()
        )
    assert rows == {memory: "memory", disk: "disk", derived: "derived"}
    other = await seed_evidence(t)
    with pytest.raises(DBAPIError, match="check"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                text(
                    "INSERT INTO memory_sensitivity (evidence_id, organization_id, "
                    "defaulted_by, source) VALUES (:e, :o, :u, 'pcap')"
                ),
                {"e": other, "o": t.org_id, "u": t.owner_id},
            )


async def test_job_outcomes_accept_disk(owner_engine: AsyncEngine) -> None:
    async with owner_engine.connect() as conn:
        definition = await conn.scalar(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname = 'ck_job_outcomes_kind'"
            )
        )
    assert "'disk'" in str(definition)
