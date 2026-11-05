import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.core.tenancy import tenant_session
from app.modules.ai.contracts import CitationResult, CitationStatus
from app.modules.audit.models import AuditLog
from app.modules.auth.models import AuthEvent, AuthEventType
from app.modules.evidence.models import (
    CustodyAction,
    Evidence,
    EvidenceCustodyEvent,
    EvidenceHash,
    HashAlgorithm,
)
from tests.ai_api_helpers import finish_run
from tests.ai_helpers import seed_ai_run
from tests.integration.seed import Tenant, seed_tenant
from tests.ops_helpers import retention_session
from tests.ti_helpers import seed_result, seed_run


async def _seed_evidence(t: Tenant) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        evidence = Evidence(
            organization_id=t.org_id,
            investigation_id=t.investigation_id,
            original_filename="capture.pcap",
            detected_mime="application/vnd.tcpdump.pcap",
            detected_description="pcap capture file",
            size_bytes=1024,
            storage_bucket="evidence-test",
            storage_key=f"{t.org_id}/{uuid.uuid4()}",
            storage_version_id="v1",
            uploaded_by=t.owner_id,
        )
        s.add(evidence)
        await s.flush()
        s.add_all(
            [
                EvidenceHash(
                    organization_id=t.org_id,
                    evidence_id=evidence.id,
                    algorithm=HashAlgorithm.SHA256,
                    value="0" * 64,
                ),
                EvidenceCustodyEvent(
                    organization_id=t.org_id,
                    evidence_id=evidence.id,
                    action=CustodyAction.UPLOADED,
                    actor_id=t.owner_id,
                ),
                AuditLog(organization_id=t.org_id, actor_id=t.owner_id, action="evidence.uploaded"),
            ]
        )
    async with tenant_session(None, None) as s:
        s.add(AuthEvent(user_id=t.owner_id, event=AuthEventType.LOGIN_SUCCESS))
    return evidence.id


APPEND_ONLY = ["audit_logs", "evidence_hashes", "evidence_custody_events", "auth_events"]
# M7 (0014): tombstones and run items are strict too; the retention exception tables allow
# DELETE for `cyberlab_retention` only and UPDATE for nobody.
M7_STRICT = ["retention_run_items", "evidence_purges"]
EXCEPTION_TABLES = ["ti_results", "ai_run_inputs", "ai_context_refs", "ai_outputs", "ai_citations"]


@pytest.mark.parametrize("table", APPEND_ONLY)
@pytest.mark.parametrize("statement", ["UPDATE {t} SET id = id", "DELETE FROM {t}"])
async def test_app_role_cannot_mutate_append_only_tables(table: str, statement: str) -> None:
    t = await seed_tenant("alpha")
    await _seed_evidence(t)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(text(statement.format(t=table)))


@pytest.mark.parametrize("table", APPEND_ONLY)
@pytest.mark.parametrize("statement", ["UPDATE {t} SET id = id", "DELETE FROM {t}"])
async def test_trigger_blocks_owner_mutations_too(
    table: str, statement: str, owner_engine: AsyncEngine
) -> None:
    t = await seed_tenant("alpha")
    await _seed_evidence(t)
    with pytest.raises(DBAPIError, match="append-only"):
        async with owner_engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.org_id', :o, true)"), {"o": str(t.org_id)}
            )
            await conn.execute(text(statement.format(t=table)))


@pytest.mark.parametrize(
    "assignment",
    [
        "id = gen_random_uuid()",
        "organization_id = gen_random_uuid()",
        "investigation_id = gen_random_uuid()",
        "original_filename = 'renamed.pcap'",
        "detected_mime = 'text/plain'",
        "detected_description = 'other'",
        "size_bytes = 1",
        "storage_bucket = 'other'",
        "storage_key = 'other'",
        "storage_version_id = 'v2'",
        "uploaded_by = gen_random_uuid()",
        "uploaded_at = now() - interval '1 day'",
    ],
)
async def test_evidence_identity_columns_are_immutable(assignment: str) -> None:
    t = await seed_tenant("alpha")
    evidence_id = await _seed_evidence(t)
    with pytest.raises(DBAPIError, match="immutable"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                text(f"UPDATE evidence SET {assignment} WHERE id = :id"), {"id": evidence_id}
            )


@pytest.mark.parametrize("table", APPEND_ONLY)
@pytest.mark.parametrize("statement", ["UPDATE {t} SET id = id", "DELETE FROM {t}"])
async def test_retention_role_cannot_mutate_strict_append_only_tables(
    table: str, statement: str
) -> None:
    """M7: the strict tables stay immutable for `cyberlab_retention` too (no grant, and
    `forbid_mutation` behind it)."""
    t = await seed_tenant("alpha")
    await _seed_evidence(t)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with retention_session(t.org_id) as s:
            await s.execute(text(statement.format(t=table)))


@pytest.mark.parametrize("table", M7_STRICT)
@pytest.mark.parametrize("role", ["owner", "retention"])
async def test_m7_tombstones_and_run_items_are_append_only(
    table: str, role: str, owner_engine: AsyncEngine
) -> None:
    t = await seed_tenant("alpha")
    if role == "owner":
        with pytest.raises(DBAPIError, match="append-only"):
            async with owner_engine.begin() as conn:
                await conn.execute(
                    text("SELECT set_config('app.org_id', :o, true)"), {"o": str(t.org_id)}
                )
                await _delete_one_seeded(conn, table, t)
    else:
        with pytest.raises(DBAPIError, match="permission denied"):
            async with retention_session(t.org_id) as s:
                await s.execute(text(f"UPDATE {table} SET organization_id = organization_id"))


async def _delete_one_seeded(conn: AsyncConnection, table: str, t: Tenant) -> None:
    run_id = uuid.uuid4()
    await conn.execute(
        text(
            "INSERT INTO retention_runs (id, organization_id, mode, trigger) "
            "VALUES (:r, :o, 'enforce', 'schedule')"
        ),
        {"r": run_id, "o": t.org_id},
    )
    if table == "retention_run_items":
        await conn.execute(
            text(
                "INSERT INTO retention_run_items (organization_id, run_id, category, ref_table, "
                "ref_id, outcome) VALUES (:o, :r, 'ti_results', 'ti_results', 'x', 'purged')"
            ),
            {"o": t.org_id, "r": run_id},
        )
    else:
        evidence_id = await _seed_evidence_conn(conn, t)
        await conn.execute(
            text(
                "INSERT INTO evidence_purges (evidence_id, organization_id, run_id, "
                "object_version_id, sha256) VALUES (:e, :o, :r, 'v1', repeat('0', 64))"
            ),
            {"e": evidence_id, "o": t.org_id, "r": run_id},
        )
    await conn.execute(text(f"DELETE FROM {table}"))


async def _seed_evidence_conn(conn: AsyncConnection, t: Tenant) -> uuid.UUID:
    evidence_id = uuid.uuid4()
    await conn.execute(
        text(
            "INSERT INTO evidence (id, organization_id, investigation_id, original_filename, "
            "detected_mime, detected_description, size_bytes, storage_bucket, storage_key, "
            "storage_version_id, uploaded_by) VALUES (:id, :o, :i, 'x.pcap', 'x', 'x', 1, "
            "'evidence-test', :k, 'v1', :u)"
        ),
        {
            "id": evidence_id,
            "o": t.org_id,
            "i": t.investigation_id,
            "k": f"{t.org_id}/{uuid.uuid4()}",
            "u": t.owner_id,
        },
    )
    return evidence_id


async def _seed_exception_rows(t: Tenant) -> None:
    """One `ti_results` row (no item references it) and a finished AI run with its `base`
    input, context refs, an output and one (invalid) citation: a row in every table."""
    run_id = await seed_run(t)
    await seed_result(t, run_id)
    ai_run = await seed_ai_run(t)
    await finish_run(
        t.org_id,
        ai_run,
        body={"observed": [{"id": "o1", "text": "x", "confidence": "low", "citations": []}]},
        citations=[
            CitationResult(
                claim_path="observed[0].citations[0]",
                section="observed",
                claim_id="o1",
                label="F9",
                status=CitationStatus.INVALID,
            )
        ],
    )


@pytest.mark.parametrize("table", EXCEPTION_TABLES)
@pytest.mark.parametrize("role", ["app", "owner", "retention"])
async def test_exception_tables_refuse_update_for_everyone(
    table: str, role: str, owner_engine: AsyncEngine
) -> None:
    t = await seed_tenant("alpha")
    await _seed_exception_rows(t)
    statement = text(f"UPDATE {table} SET organization_id = organization_id")
    if role == "owner":
        with pytest.raises(DBAPIError, match="append-only"):
            async with owner_engine.begin() as conn:
                await conn.execute(
                    text("SELECT set_config('app.org_id', :o, true)"), {"o": str(t.org_id)}
                )
                await conn.execute(statement)
        return
    session = tenant_session if role == "app" else retention_session
    with pytest.raises(DBAPIError, match="permission denied"):
        async with session(t.org_id, t.owner_id) as s:
            await s.execute(statement)


@pytest.mark.parametrize("table", EXCEPTION_TABLES)
async def test_exception_tables_refuse_delete_for_the_app_and_the_owner(
    table: str, owner_engine: AsyncEngine
) -> None:
    t = await seed_tenant("alpha")
    await _seed_exception_rows(t)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(text(f"DELETE FROM {table}"))
    with pytest.raises(DBAPIError, match="append-only"):
        async with owner_engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.org_id', :o, true)"), {"o": str(t.org_id)}
            )
            await conn.execute(text(f"DELETE FROM {table}"))


@pytest.mark.parametrize("table", ["ti_results", "ai_run_inputs", "ai_context_refs"])
async def test_exception_tables_allow_delete_for_the_retention_role_only(table: str) -> None:
    t = await seed_tenant("alpha")
    other = await seed_tenant("beta")
    await _seed_exception_rows(t)
    await _seed_exception_rows(other)
    async with retention_session(t.org_id) as s:
        deleted = (await s.execute(text(f"DELETE FROM {table}"))).rowcount
    assert deleted >= 1
    # RLS still binds the role: the other org's rows are untouched.
    async with tenant_session(other.org_id, None) as s:
        left = (await s.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one()
    assert left >= 1


async def test_evidence_status_and_description_are_mutable() -> None:
    t = await seed_tenant("alpha")
    evidence_id = await _seed_evidence(t)
    async with tenant_session(t.org_id, t.owner_id) as s:
        result = await s.execute(
            text("UPDATE evidence SET status = 'archived', description = 'note' WHERE id = :id"),
            {"id": evidence_id},
        )
    assert result.rowcount == 1
