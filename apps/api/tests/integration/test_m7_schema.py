"""Migration 0014 (M7 phase 1): RLS on every new tenant table, the system lookup, the
retention role's grants (DELETE on purgeable tables only, never correlation keys), the
retention system user (cannot log in, RT12), purged renders (retention only, frees the dedupe
slot, RT11), the write-once evidence type columns, the policy / hold / run guards, the
`job_outcomes` trigger and the role guard of the migration."""

import importlib.util
import uuid
from pathlib import Path
from types import ModuleType

import pytest
from sqlalchemy import text, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import RETENTION_SYSTEM_USER_EMAIL, RETENTION_SYSTEM_USER_ID
from app.core.cookies import ACCESS_COOKIE
from app.core.security import create_access_token
from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob, AnalysisStatus
from app.modules.retention.models import LegalHold
from tests.case_helpers import seed_evidence, seed_job_on
from tests.conftest import API_ROOT
from tests.factories import PASSWORD, new_client
from tests.integration.seed import Tenant, seed_tenant
from tests.ops_helpers import (
    retention_session,
    seed_hold,
    seed_released_hold,
    seed_retention_policy,
)
from tests.report_helpers import new_signing_keys, seed_render, seed_report, seed_version

TENANT_TABLES = (
    "org_retention_policies",
    "legal_holds",
    "retention_runs",
    "retention_run_items",
    "evidence_purges",
    "correlation_keys",
    "correlation_job_state",
)


async def _seed_m7_rows(t: Tenant) -> None:
    await seed_retention_policy(t, ti_results_days=90)
    await seed_hold(t, investigation_id=t.investigation_id)
    evidence_id = await seed_evidence(t)
    job_id = await seed_job_on(t, evidence_id)
    run_id = uuid.uuid4()
    async with retention_session(t.org_id) as s:
        await s.execute(
            text(
                "INSERT INTO retention_runs (id, organization_id, mode, trigger) "
                "VALUES (:r, :o, 'dry_run', 'schedule')"
            ),
            {"r": run_id, "o": t.org_id},
        )
        await s.execute(
            text(
                "INSERT INTO retention_run_items (organization_id, run_id, category, ref_table, "
                "ref_id, job_id, outcome) VALUES (:o, :r, 'closed_case', 'network_flows', "
                "'x', :j, 'purged')"
            ),
            {"o": t.org_id, "r": run_id, "j": job_id},
        )
        await s.execute(
            text(
                "INSERT INTO evidence_purges (evidence_id, organization_id, run_id, "
                "object_version_id, sha256) VALUES (:e, :o, :r, 'v1', repeat('0', 64))"
            ),
            {"e": evidence_id, "o": t.org_id, "r": run_id},
        )
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text(
                "INSERT INTO correlation_keys (organization_id, investigation_id, evidence_id, "
                "job_id, kind, key, value_norm, source_table, source_id) VALUES (:o, :i, :e, "
                ":j, 'domain', repeat('b', 64), 'c2.example.net', 'iocs', 'x')"
            ),
            {"o": t.org_id, "i": t.investigation_id, "e": evidence_id, "j": job_id},
        )
        await s.execute(
            text(
                "INSERT INTO correlation_job_state (job_id, organization_id, keys) "
                "VALUES (:j, :o, 1)"
            ),
            {"j": job_id, "o": t.org_id},
        )


async def _count(org: uuid.UUID | None, table: str) -> int:
    async with tenant_session(org, None) as s:
        return int((await s.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one())


async def test_tenant_tables_are_isolated() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("beta")
    await _seed_m7_rows(a)
    for table in TENANT_TABLES:
        assert await _count(a.org_id, table) == 1, table
        assert await _count(b.org_id, table) == 0, table
        assert await _count(None, table) == 0, table  # no org context: nothing


async def test_retention_role_is_bound_by_rls_too() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("beta")
    await _seed_m7_rows(a)
    readable = [t for t in TENANT_TABLES if not t.startswith("correlation_")]
    async with retention_session(b.org_id) as s:
        for table in readable:
            assert (await s.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one() == 0
    async with retention_session(a.org_id) as s:
        for table in readable:
            assert (await s.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one() == 1
    # RT3: the role cannot list organizations at all (its org list is retention_policy_index),
    # and RT9: it never touches the correlation keys, not even to read them.
    for table in ("organizations", "correlation_keys", "correlation_job_state"):
        with pytest.raises(DBAPIError, match="permission denied"):
            async with retention_session(None) as s:
                await s.execute(text(f"SELECT count(*) FROM {table}"))


async def test_policy_index_is_system_visible_but_tenant_scoped() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("beta")
    await seed_retention_policy(a, closed_case_days=400)
    await seed_retention_policy(b, ai_runs_days=60)
    async with retention_session(None) as s:
        orgs = set(
            (await s.execute(text("SELECT organization_id FROM retention_policy_index"))).scalars()
        )
    assert orgs == {a.org_id, b.org_id}
    assert await _count(a.org_id, "retention_policy_index") == 1
    with pytest.raises(DBAPIError, match="permission denied"):
        async with retention_session(None) as s:
            await s.execute(text("UPDATE retention_policy_index SET updated_at = now()"))


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM correlation_keys",
        "DELETE FROM correlation_job_state",
        "DELETE FROM investigations",
        "DELETE FROM evidence",
        "DELETE FROM iocs",
        "DELETE FROM analysis_findings",
        "DELETE FROM report_versions",
        "DELETE FROM legal_holds",
        "DELETE FROM org_retention_policies",
        "UPDATE evidence SET status = 'archived'",
        "UPDATE org_retention_policies SET enforce = true",
        "UPDATE legal_holds SET released_at = now()",
        "INSERT INTO iocs (organization_id, job_id, type, value, first_seen, last_seen, count, "
        "source) VALUES (gen_random_uuid(), gen_random_uuid(), 'ip', 'x', now(), now(), 1, 'x')",
        "SELECT count(*) FROM refresh_tokens",
        "SELECT count(*) FROM users",
        "SELECT count(*) FROM ti_provider_configs",
        "SELECT count(*) FROM ai_provider_configs",
    ],
)
async def test_retention_role_is_least_privilege(statement: str) -> None:
    t = await seed_tenant("alpha")
    with pytest.raises(DBAPIError, match="permission denied"):
        async with retention_session(t.org_id) as s:
            await s.execute(text(statement))


@pytest.mark.parametrize(
    "table",
    [
        "network_flows",
        "network_records",
        "analysis_timeline",
        "malware_strings",
        "malware_sections",
        "malware_imports",
        "malware_exports",
        "malware_resources",
        "ti_run_items",
        "ai_runs",
        "ai_run_index",
        "job_outcomes",
    ],
)
async def test_retention_role_may_delete_purgeable_tables(table: str) -> None:
    t = await seed_tenant("alpha")
    async with retention_session(t.org_id) as s:
        await s.execute(text(f"DELETE FROM {table}"))  # empty, but privileged


async def test_the_system_user_exists_and_cannot_log_in() -> None:
    async with tenant_session(None, None) as s:
        row = (
            await s.execute(
                text("SELECT email, is_active, password_hash FROM users WHERE id = :i"),
                {"i": RETENTION_SYSTEM_USER_ID},
            )
        ).one()
    assert (row.email, row.is_active) == (RETENTION_SYSTEM_USER_EMAIL, False)
    assert not row.password_hash.startswith("$argon2")
    client = new_client()
    for password in (PASSWORD, row.password_hash, ""):
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": RETENTION_SYSTEM_USER_EMAIL, "password": password or "x" * 12},
        )
        # `.invalid` is a reserved name: the login schema refuses the address before any
        # lookup (422); either way no session is issued.
        assert response.status_code in (401, 422), response.text
        assert ACCESS_COOKIE not in response.cookies
    # A forged (validly signed) access token for it is refused by current_user.
    token, _ = create_access_token(RETENTION_SYSTEM_USER_ID, uuid.uuid4())
    client.cookies.set(ACCESS_COOKIE, token)
    assert (await client.get("/api/v1/auth/me")).status_code == 401


async def _succeeded_render(t: Tenant) -> tuple[uuid.UUID, uuid.UUID]:
    report_id = await seed_report(t)
    version = await seed_version(t, report_id, new_signing_keys(), store=False)
    render_id, _ = await seed_render(t, version.version_id)
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text("UPDATE report_renders SET status = 'running', started_at = now() WHERE id = :r"),
            {"r": render_id},
        )
        await s.execute(
            text(
                "UPDATE report_renders SET status = 'succeeded', sha256 = repeat('c', 64), "
                "bytes = 10, pages = 1, object_version_id = 'v1', finished_at = now() "
                "WHERE id = :r"
            ),
            {"r": render_id},
        )
    return version.version_id, render_id


async def test_only_retention_purges_a_render_and_it_frees_the_slot() -> None:
    t = await seed_tenant("alpha")
    version_id, render_id = await _succeeded_render(t)
    purge = text("UPDATE report_renders SET status = 'purged' WHERE id = :r")
    with pytest.raises(DBAPIError, match="only the retention worker"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(purge, {"r": render_id})
    # The role may update the status column only (grant), and the trigger keeps the rest.
    with pytest.raises(DBAPIError, match="permission denied"):
        async with retention_session(t.org_id) as s:
            await s.execute(
                text("UPDATE report_renders SET status = 'purged', pages = 2 WHERE id = :r"),
                {"r": render_id},
            )
    async with retention_session(t.org_id) as s:
        assert (await s.execute(purge, {"r": render_id})).rowcount == 1
    # Final: nobody moves it again.
    with pytest.raises(DBAPIError, match="is final"):
        async with retention_session(t.org_id) as s:
            await s.execute(
                text("UPDATE report_renders SET status = 'succeeded' WHERE id = :r"),
                {"r": render_id},
            )
    # RT11: the purged row no longer holds the (version, format, renderer) slot.
    second, _ = await seed_render(t, version_id)
    assert second != render_id
    with pytest.raises(IntegrityError):
        await seed_render(t, version_id)  # a live (queued) render does


async def test_render_purge_needs_a_succeeded_render() -> None:
    t = await seed_tenant("alpha")
    report_id = await seed_report(t)
    version = await seed_version(t, report_id, new_signing_keys(), store=False)
    render_id, _ = await seed_render(t, version.version_id)
    with pytest.raises(DBAPIError, match="illegal report render transition"):
        async with retention_session(t.org_id) as s:
            await s.execute(
                text("UPDATE report_renders SET status = 'purged' WHERE id = :r"), {"r": render_id}
            )


async def test_evidence_type_columns_are_write_once() -> None:
    t = await seed_tenant("alpha")
    evidence_id = await seed_evidence(t)
    # An existing row (inserted by an earlier transaction) stays NULL forever.
    with pytest.raises(DBAPIError, match="write-once"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                text("UPDATE evidence SET declared_type = 'pcap' WHERE id = :e"), {"e": evidence_id}
            )
    # Set in the inserting transaction: allowed once, then frozen.
    new_id = uuid.uuid4()
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text(
                "INSERT INTO evidence (id, organization_id, investigation_id, original_filename, "
                "detected_mime, detected_description, size_bytes, storage_bucket, storage_key, "
                "storage_version_id, uploaded_by) VALUES (:id, :o, :i, 'x.pdf', 'x', 'x', 1, "
                "'evidence-test', :k, 'v1', :u)"
            ),
            {
                "id": new_id,
                "o": t.org_id,
                "i": t.investigation_id,
                "k": f"{t.org_id}/{uuid.uuid4()}",
                "u": t.owner_id,
            },
        )
        await s.execute(
            text("UPDATE evidence SET declared_type = 'pdf', type_mismatch = true WHERE id = :e"),
            {"e": new_id},
        )
    for assignment in ("declared_type = 'exe'", "type_mismatch = false", "declared_type = NULL"):
        with pytest.raises(DBAPIError, match="write-once"):
            async with tenant_session(t.org_id, t.owner_id) as s:
                await s.execute(
                    text(f"UPDATE evidence SET {assignment} WHERE id = :e"), {"e": new_id}
                )
    # Status and description stay mutable.
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text("UPDATE evidence SET description = 'note' WHERE id = :e"), {"e": new_id}
        )


@pytest.mark.parametrize(
    ("columns", "message"),
    [
        ({"ti_results_days": 10}, "ck_org_retention_policies_ti_results_days"),
        ({"closed_case_days": 29}, "ck_org_retention_policies_closed_case_days"),
        ({"pending_ai_runs_days": 40}, "ck_org_retention_policies_pending_pair"),
        ({"pending_enforce": True}, "ck_org_retention_policies_enforce_pair"),
    ],
)
async def test_policy_checks(columns: dict[str, object], message: str) -> None:
    t = await seed_tenant("alpha")
    names = ", ".join(columns)
    params = ", ".join(f":{name}" for name in columns)
    with pytest.raises(IntegrityError, match=message):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                text(
                    f"INSERT INTO org_retention_policies (organization_id, updated_by, {names}) "
                    f"VALUES (:o, :u, {params})"
                ),
                {"o": t.org_id, "u": t.owner_id, **columns},
            )


async def test_policy_update_touches_updated_at() -> None:
    t = await seed_tenant("alpha")
    await seed_retention_policy(t)
    async with tenant_session(t.org_id, t.owner_id) as s:
        before = (
            await s.execute(text("SELECT updated_at FROM org_retention_policies"))
        ).scalar_one()
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(text("UPDATE org_retention_policies SET ti_results_days = 45"))
        after = (
            await s.execute(text("SELECT updated_at FROM org_retention_policies"))
        ).scalar_one()
    assert after > before


async def test_a_hold_is_released_once_and_its_identity_is_immutable() -> None:
    t = await seed_tenant("alpha")
    hold_id = await seed_hold(t, investigation_id=t.investigation_id)
    released = await seed_released_hold(t, 2)
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            update(LegalHold)
            .where(LegalHold.id == hold_id)
            .values(released_by=t.owner_id, released_at=text("now()"), release_reason="Done")
        )
    for target, values in (
        (hold_id, "release_reason = 'Again'"),
        (released, "released_at = now()"),
        (hold_id, "reason = 'Changed'"),
    ):
        with pytest.raises(DBAPIError, match="already released|permission denied"):
            async with tenant_session(t.org_id, t.owner_id) as s:
                await s.execute(
                    text(f"UPDATE legal_holds SET {values} WHERE id = :h"), {"h": target}
                )
    # The retention worker records its S3 sync time and nothing else.
    async with retention_session(t.org_id) as s:
        await s.execute(
            text("UPDATE legal_holds SET s3_synced_at = now() WHERE id = :h"), {"h": hold_id}
        )


async def test_the_hold_sync_state_is_the_retention_roles_only() -> None:
    """0015: the resumable sync state (first full pass, keyset cursor, pass start) is written
    by the retention role only, and the cursor's three columns are set together."""
    t = await seed_tenant("alpha")
    hold_id = await seed_hold(t)
    state = (
        "s3_full_synced_at = now(), s3_sync_cursor_at = now(), "
        "s3_sync_cursor_id = gen_random_uuid(), s3_sync_pass_at = now()"
    )
    async with retention_session(t.org_id) as s:
        await s.execute(text(f"UPDATE legal_holds SET {state} WHERE id = :h"), {"h": hold_id})
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                text("UPDATE legal_holds SET s3_full_synced_at = now() WHERE id = :h"),
                {"h": hold_id},
            )
    with pytest.raises(IntegrityError, match="ck_legal_holds_s3_sync_cursor"):
        async with retention_session(t.org_id) as s:
            await s.execute(
                text("UPDATE legal_holds SET s3_sync_pass_at = NULL WHERE id = :h"),
                {"h": hold_id},
            )


async def test_a_scope_needs_its_target() -> None:
    t = await seed_tenant("alpha")
    with pytest.raises(IntegrityError, match="ck_legal_holds_scope_target"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            s.add(
                LegalHold(
                    organization_id=t.org_id,
                    scope="investigation",
                    reason="x",
                    placed_by=t.owner_id,
                )
            )


async def test_a_final_retention_run_is_immutable() -> None:
    t = await seed_tenant("alpha")
    run_id = uuid.uuid4()
    async with retention_session(t.org_id) as s:
        await s.execute(
            text(
                "INSERT INTO retention_runs (id, organization_id, mode, trigger) "
                "VALUES (:r, :o, 'dry_run', 'schedule')"
            ),
            {"r": run_id, "o": t.org_id},
        )
        await s.execute(
            text(
                "UPDATE retention_runs SET status = 'completed', finished_at = now(), "
                "counts = '{\"ti_results\": {}}' WHERE id = :r"
            ),
            {"r": run_id},
        )
    with pytest.raises(DBAPIError, match="is final"):
        async with retention_session(t.org_id) as s:
            await s.execute(
                text("UPDATE retention_runs SET status = 'failed' WHERE id = :r"), {"r": run_id}
            )
    with pytest.raises(DBAPIError, match="permission denied"):
        async with retention_session(t.org_id) as s:
            await s.execute(text("UPDATE retention_runs SET mode = 'enforce'"))


async def test_terminal_job_transitions_record_an_outcome(owner_engine: AsyncEngine) -> None:
    t = await seed_tenant("alpha")
    job_id = await seed_job_on(t, await seed_evidence(t), status="queued")
    async with tenant_session(t.org_id, None) as s:
        await s.execute(
            update(AnalysisJob)
            .where(AnalysisJob.id == job_id)
            .values(status=AnalysisStatus.RUNNING, started_at=text("now() - interval '2 seconds'"))
        )
        await s.execute(
            update(AnalysisJob)
            .where(AnalysisJob.id == job_id)
            .values(
                status=AnalysisStatus.FAILED,
                error_code="unparseable_capture",
                finished_at=text("now()"),
            )
        )
    async with tenant_session(t.org_id, None) as s:
        rows = (
            await s.execute(
                text("SELECT kind, subkind, status, error_code, run_ms FROM job_outcomes")
            )
        ).all()
    assert len(rows) == 1
    kind, subkind, status, code, run_ms = rows[0]
    assert (kind, subkind, status, code) == ("pcap", None, "failed", "unparseable_capture")
    assert run_ms is not None and run_ms >= 1000
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(t.org_id, None) as s:
            await s.execute(text("INSERT INTO job_outcomes (kind, status) VALUES ('pcap', 'x')"))


def _migration() -> ModuleType:
    path = Path(API_ROOT) / "alembic" / "versions" / "0014_m7_platform_ops.py"
    spec = importlib.util.spec_from_file_location("m7_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_the_migration_refuses_to_run_without_the_role(owner_engine: AsyncEngine) -> None:
    guard = _migration().ROLE_GUARD.replace("cyberlab_retention", "cyberlab_missing_role")
    with pytest.raises(DBAPIError, match="run db-bootstrap first"):
        async with owner_engine.begin() as conn:
            await conn.execute(text(guard))
