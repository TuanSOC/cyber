"""Migration 0011: RLS, append-only tables, the run status graph, the monotonic key version,
grants and constraints of the AI analyst tables (M5 phase 1)."""

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.tenancy import tenant_session
from app.modules.ai.models import (
    AiCitation,
    AiContextRef,
    AiOrgSettings,
    AiOutput,
    AiProviderConfig,
    AiRun,
    AiRunIndex,
    AiRunInput,
)
from tests.ai_helpers import seed_ai_config, seed_ai_run, seed_ai_settings, seed_job
from tests.integration.seed import Tenant, seed_tenant

TENANT_TABLES = (
    "ai_provider_configs",
    "ai_org_settings",
    "ai_runs",
    "ai_run_inputs",
    "ai_context_refs",
    "ai_outputs",
    "ai_citations",
)
APPEND_ONLY = ("ai_run_inputs", "ai_context_refs", "ai_outputs", "ai_citations")
SEALED = ("key_kid", "key_epk", "key_nonce", "key_ct", "key_last4")


async def _seed_output(t: Tenant, run_id: uuid.UUID) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        output = AiOutput(
            organization_id=t.org_id,
            run_id=run_id,
            body={"overall_confidence": {"level": "low", "rationale": "x"}},
            verification={"version": "v1"},
            flags=[],
        )
        s.add(output)
        await s.flush()
        s.add(
            AiCitation(
                organization_id=t.org_id,
                output_id=output.id,
                run_id=run_id,
                claim_path="observed[0].citations[0]",
                section="observed",
                claim_id="O1",
                claim_status="supported",
                label="F1",
                kind="finding",
                ref_id=str(uuid.uuid4()),
                status="verified",
                field="title",
                quote="Periodic beacon",
            )
        )
    return output.id


async def _seed_all(t: Tenant) -> uuid.UUID:
    await seed_ai_settings(t)
    await seed_ai_config(t)
    run_id = await seed_ai_run(t)
    await _seed_output(t, run_id)
    return run_id


async def _count(org: uuid.UUID | None, table: str) -> int:
    async with tenant_session(org, None) as s:
        return int((await s.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one())


async def test_tenant_tables_are_isolated() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    await _seed_all(a)
    for table in TENANT_TABLES:
        assert await _count(a.org_id, table) >= 1, table
        assert await _count(b.org_id, table) == 0, table
        assert await _count(None, table) == 0, table  # no context: nothing


async def test_run_index_is_system_visible_but_tenant_scoped() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    await seed_ai_run(a)
    assert await _count(None, "ai_run_index") == 1  # trusted workers (system session)
    assert await _count(a.org_id, "ai_run_index") == 1
    assert await _count(b.org_id, "ai_run_index") == 0


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO ai_org_settings (organization_id) VALUES (:other)",
        "INSERT INTO ai_provider_configs (organization_id, provider) VALUES (:other, 'mock')",
        "INSERT INTO ai_run_index (run_id, organization_id, status, deadline_at) "
        "VALUES (:run, :other, 'queued', now())",
    ],
)
async def test_rows_cannot_be_written_into_another_org(statement: str) -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    run_id = await seed_ai_run(a)
    with pytest.raises(DBAPIError, match="row-level security"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(text(statement), {"other": b.org_id, "run": run_id})


async def test_children_cannot_point_at_another_orgs_rows() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    foreign_job = await seed_job(b)
    foreign_run = await seed_ai_run(b, job_id=foreign_job)
    with pytest.raises(DBAPIError, match="foreign key"):
        await seed_ai_run(a, job_id=foreign_job)  # a run on another org's job
    run_id = await seed_ai_run(a)
    for statement in (
        "INSERT INTO ai_outputs (organization_id, run_id, body) VALUES (:o, :foreign, '{}')",
        "INSERT INTO ai_run_inputs (organization_id, run_id, stage, context, context_sha256) "
        "VALUES (:o, :foreign, 'reduce', '{}', repeat('a', 64))",
        "INSERT INTO ai_context_refs (organization_id, run_id, stage, label, kind, ref_table, "
        "ref_id, job_id, fields_sha256) VALUES (:o, :run, 'reduce', 'J2:F1', 'finding', "
        "'analysis_findings', 'x', :job, repeat('a', 64))",
    ):
        with pytest.raises(DBAPIError, match="foreign key"):
            async with tenant_session(a.org_id, a.owner_id) as s:
                await s.execute(
                    text(statement),
                    {"o": a.org_id, "foreign": foreign_run, "run": run_id, "job": foreign_job},
                )


# --- append-only ----------------------------------------------------------------------------


@pytest.mark.parametrize("table", APPEND_ONLY)
@pytest.mark.parametrize(
    "verb", ["UPDATE {t} SET organization_id = organization_id", "DELETE FROM {t}"]
)
async def test_app_role_cannot_mutate_append_only_tables(table: str, verb: str) -> None:
    a = await seed_tenant("alpha")
    await _seed_all(a)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(text(verb.format(t=table)))


@pytest.mark.parametrize("table", APPEND_ONLY)
@pytest.mark.parametrize(
    "verb", ["UPDATE {t} SET organization_id = organization_id", "DELETE FROM {t}"]
)
async def test_trigger_blocks_owner_mutations(
    table: str, verb: str, owner_engine: AsyncEngine
) -> None:
    a = await seed_tenant("alpha")
    await _seed_all(a)
    with pytest.raises(DBAPIError, match="append-only"):
        async with owner_engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.org_id', :o, true)"), {"o": str(a.org_id)}
            )
            await conn.execute(text(verb.format(t=table)))


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM ai_provider_configs",
        "DELETE FROM ai_org_settings",
        "DELETE FROM ai_runs",
        "DELETE FROM ai_run_index",
    ],
)
async def test_no_delete_grants(statement: str) -> None:
    a = await seed_tenant("alpha")
    await _seed_all(a)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(text(statement))


# --- the run status graph -------------------------------------------------------------------


async def _set_status(t: Tenant, run_id: uuid.UUID, status: str) -> None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text("UPDATE ai_runs SET status = :s WHERE id = :id"), {"s": status, "id": run_id}
        )


@pytest.mark.parametrize(
    "path",
    [
        ["running", "waiting", "running", "completed"],
        ["running", "partial"],
        ["running", "failed"],
        ["running", "refused"],
        ["running", "waiting", "failed"],
        ["failed"],  # deadline / fallback reaper before the first call
    ],
)
async def test_legal_run_transitions(path: list[str]) -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_ai_run(a)
    for status in path:
        await _set_status(a, run_id, status)


@pytest.mark.parametrize(
    ("path", "illegal"),
    [
        ([], "completed"),
        ([], "waiting"),
        ([], "refused"),
        ([], "partial"),
        (["running", "waiting"], "completed"),
        (["running", "waiting"], "refused"),
        (["running"], "queued"),
    ],
)
async def test_illegal_run_transitions(path: list[str], illegal: str) -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_ai_run(a)
    for status in path:
        await _set_status(a, run_id, status)
    with pytest.raises(DBAPIError, match="illegal ai run transition"):
        await _set_status(a, run_id, illegal)


@pytest.mark.parametrize("final", ["completed", "partial", "failed", "refused"])
async def test_final_runs_are_immutable(final: str) -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_ai_run(a)
    await _set_status(a, run_id, "running")
    await _set_status(a, run_id, final)
    with pytest.raises(DBAPIError, match="is final"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(
                text("UPDATE ai_runs SET metrics = '{}' WHERE id = :id"), {"id": run_id}
            )


@pytest.mark.parametrize(
    "assignment",
    ["task = 'explain_static'", "model = 'mock-2'", "context_sha256 = repeat('b', 64)"],
)
async def test_run_identity_is_immutable_even_for_the_owner(
    assignment: str, owner_engine: AsyncEngine
) -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_ai_run(a)
    with pytest.raises(DBAPIError, match="identity columns are immutable"):
        async with owner_engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.org_id', :o, true)"), {"o": str(a.org_id)}
            )
            await conn.execute(
                text(f"UPDATE ai_runs SET {assignment} WHERE id = :id"), {"id": run_id}
            )


# --- monotonic key_version (RT18) -----------------------------------------------------------


def _sealed(kid: str, version: int, last4: str = "abcd") -> dict[str, object]:
    return {
        "key_kid": kid,
        "key_version": version,
        "key_epk": bytes([version % 256]) * 32,
        "key_nonce": bytes([len(kid)]) * 12,
        "key_ct": f"{kid}-{version}-{uuid.uuid4()}".encode(),
        "key_last4": last4,
    }


async def _update_config(t: Tenant, config_id: uuid.UUID, values: dict[str, object]) -> None:
    assignments = ", ".join(f"{k} = :{k}" for k in values)
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text(f"UPDATE ai_provider_configs SET {assignments} WHERE id = :id"),
            {**values, "id": config_id},
        )


async def test_key_version_is_monotonic() -> None:
    a = await seed_tenant("alpha")
    config_id = await seed_ai_config(a, sealed=False, enabled=False)
    await _update_config(a, config_id, _sealed("k1", 1))
    with pytest.raises(DBAPIError, match="higher key_version"):
        await _update_config(a, config_id, _sealed("k1", 1, last4="wxyz"))
    await _update_config(a, config_id, _sealed("k1", 2, last4="wxyz"))
    with pytest.raises(DBAPIError, match="may not decrease"):
        await _update_config(a, config_id, _sealed("k1", 1))
    # A lazy re-seal under another kid keeps the version (same last4).
    await _update_config(a, config_id, _sealed("k2", 2, last4="wxyz"))
    # Removing the key keeps the floor.
    await _update_config(a, config_id, {**dict.fromkeys(SEALED), "enabled": False})
    with pytest.raises(DBAPIError, match="higher key_version"):
        await _update_config(a, config_id, _sealed("k2", 2))
    await _update_config(a, config_id, _sealed("k2", 3))


# --- column grants --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "assignment",
    [
        "ai_provider_configs SET organization_id = organization_id",
        "ai_provider_configs SET provider = 'gemini'",
        "ai_provider_configs SET created_at = now()",
        "ai_org_settings SET organization_id = organization_id",
        "ai_runs SET organization_id = organization_id",
        "ai_runs SET task = 'explain_static'",
        "ai_runs SET provider = 'anthropic'",
        "ai_runs SET created_at = now()",
        "ai_runs SET context_sha256 = context_sha256",
        "ai_runs SET deadline_at = now()",
        "ai_run_index SET organization_id = organization_id",
        "ai_run_index SET run_id = run_id",
    ],
)
async def test_identity_columns_are_not_updatable(assignment: str) -> None:
    a = await seed_tenant("alpha")
    await _seed_all(a)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(text(f"UPDATE {assignment}"))


async def test_the_api_and_the_worker_may_update_their_columns() -> None:
    a = await seed_tenant("alpha")
    run_id = await _seed_all(a)
    async with tenant_session(a.org_id, a.owner_id) as s:
        await s.execute(
            text(
                "UPDATE ai_run_index SET status = 'running', resume_at = now(), "
                "dispatched_at = now(), lease_until = now(), lease_owner = 'w1', attempts = 1, "
                "calls = 1 WHERE run_id = :id"
            ),
            {"id": run_id},
        )
        await s.execute(
            text(
                "UPDATE ai_runs SET status = 'running', started_at = now(), served_model = 'm', "
                "usage = '{\"input_tokens\": 1}', metrics = '{}', cost_micros = 5, "
                "price_version = 'p' WHERE id = :id"
            ),
            {"id": run_id},
        )
        await s.execute(
            text(
                "UPDATE ai_provider_configs SET verify_status = 'valid', verified_at = now(), "
                "model = 'mock-1', limits = '{\"per_minute\": 5}'"
            )
        )
        await s.execute(
            text(
                "UPDATE ai_org_settings SET include_strings = true, "
                "internal_cidrs = '[\"10.0.0.0/8\"]', daily_token_budget = 5, updated_at = now()"
            )
        )
    async with tenant_session(None, None) as s:  # system session: lease bookkeeping
        await s.execute(
            text(
                "UPDATE ai_run_index SET lease_until = NULL, lease_owner = NULL WHERE run_id = :id"
            ),
            {"id": run_id},
        )


# --- constraints ----------------------------------------------------------------------------

_RUN = (
    "INSERT INTO ai_runs (organization_id, task, scope, job_id, investigation_id, "
    "parent_run_id, target_kind, target_id, provider, model, prompt_version, output_schema, "
    "context_sha256, requested_by, deadline_at, context_stats) VALUES (:o, {task}, {scope}, "
    "{job}, {inv}, {parent}, {tkind}, {tid}, {provider}, {model}, 'm5.1', 'ai.v1', {sha}, :u, "
    "now(), {stats})"
)


def _run(**overrides: str) -> str:
    values = {
        "task": "'summarize_pcap'",
        "scope": "'job'",
        "job": ":job",
        "inv": "NULL",
        "parent": "NULL",
        "tkind": "NULL",
        "tid": "NULL",
        "provider": "'mock'",
        "model": "'mock-1'",
        "sha": "repeat('a', 64)",
        "stats": "'{}'",
        **overrides,
    }
    return _RUN.format(**values)


@pytest.mark.parametrize(
    ("statement", "constraint"),
    [
        (
            "INSERT INTO ai_provider_configs (organization_id, provider) VALUES (:o, 'openai')",
            "ck_ai_provider_configs_provider",
        ),
        (
            "INSERT INTO ai_provider_configs (organization_id, provider, key_kid) "
            "VALUES (:o, 'mock', 'k1')",
            "sealed_all_or_none",
        ),
        (
            "INSERT INTO ai_provider_configs (organization_id, provider, enabled) "
            "VALUES (:o, 'mock', true)",
            "enabled_needs_terms",
        ),
        (
            "INSERT INTO ai_provider_configs (organization_id, provider, enabled, terms_ack_at) "
            "VALUES (:o, 'gemini', true, now())",
            "gemini_enabled_needs_paid_tier",
        ),
        (
            "INSERT INTO ai_provider_configs (organization_id, provider, model) "
            "VALUES (:o, 'mock', 'Bad Model!')",
            "model_pattern",
        ),
        (
            "INSERT INTO ai_org_settings (organization_id, ai_enabled) VALUES (:o, true)",
            "enabled_needs_privacy",
        ),
        (
            "INSERT INTO ai_org_settings (organization_id, internal_cidrs) "
            "VALUES (:o, (SELECT jsonb_agg(i) FROM generate_series(1, 51) i))",
            "internal_cidrs",
        ),
        (
            "INSERT INTO ai_org_settings (organization_id, run_token_cap) VALUES (:o, 0)",
            "budgets_positive",
        ),
        (_run(task="'job_digest'"), "parent_iff_job_digest"),
        (_run(job="NULL"), "job_id_iff_job_scope"),
        (_run(scope="'investigation'", inv=":inv"), "job_id_iff_job_scope"),
        (_run(scope="'investigation'", job="NULL"), "investigation_id_iff_investigation_scope"),
        (_run(tkind="'finding'"), "ck_ai_runs_target"),
        (_run(tkind="'flow'", tid="gen_random_uuid()"), "ck_ai_runs_target"),
        (_run(sha="'abc'"), "ck_ai_runs_context_sha256"),
        (_run(provider="'otx'"), "ck_ai_runs_provider"),
        (_run(task="'chat'"), "ck_ai_runs_task"),
        (_run(stats="jsonb_build_object('x', repeat('a', 17000))"), "stats_size"),
    ],
)
async def test_constraints(statement: str, constraint: str) -> None:
    a = await seed_tenant("alpha")
    job_id = await seed_job(a)
    with pytest.raises(DBAPIError, match=constraint):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(
                text(statement),
                {"o": a.org_id, "u": a.owner_id, "job": job_id, "inv": a.investigation_id},
            )


async def test_an_incident_tree_and_its_children() -> None:
    a = await seed_tenant("alpha")
    job_id = await seed_job(a)
    async with tenant_session(a.org_id, a.owner_id) as s:
        parent = AiRun(
            organization_id=a.org_id,
            task="incident_summary",
            scope="investigation",
            investigation_id=a.investigation_id,
            provider="mock",
            model="mock-1",
            prompt_version="m5.1",
            output_schema="ai.v1",
            context_sha256="b" * 64,
            requested_by=a.owner_id,
            deadline_at=datetime.now(UTC),
        )
        s.add(parent)
        await s.flush()
    child = await seed_ai_run(a, job_id=job_id, task="job_digest", parent_run_id=parent.id)  # type: ignore[arg-type]
    async with tenant_session(a.org_id, a.owner_id) as s:
        found = (await s.execute(select(AiRun).where(AiRun.parent_run_id == parent.id))).scalars()
        assert [r.id for r in found] == [child]


@pytest.mark.parametrize(
    ("columns", "constraint"),
    [
        ("'base', '{}', 'abc'", "ck_ai_run_inputs_context_sha256"),
        ("'final', '{}', repeat('a', 64)", "ck_ai_run_inputs_stage"),
        (
            "'reduce', jsonb_build_object('x', repeat('a', 530000)), repeat('a', 64)",
            "context_size",
        ),
    ],
)
async def test_input_constraints(columns: str, constraint: str) -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_ai_run(a)
    with pytest.raises(DBAPIError, match=constraint):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(
                text(
                    "INSERT INTO ai_run_inputs (organization_id, run_id, stage, context, "
                    f"context_sha256) VALUES (:o, :r, {columns})"
                ),
                {"o": a.org_id, "r": run_id},
            )


@pytest.mark.parametrize(
    ("columns", "constraint"),
    [
        ("'F1x', 'finding'", "ck_ai_context_refs_label"),
        ("'Q1', 'packet'", "ck_ai_context_refs_kind"),
    ],
)
async def test_ref_constraints(columns: str, constraint: str) -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_ai_run(a)
    with pytest.raises(DBAPIError, match=constraint):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(
                text(
                    "INSERT INTO ai_context_refs (organization_id, run_id, stage, label, kind, "
                    f"ref_table, ref_id, fields_sha256) VALUES (:o, :r, 'reduce', {columns}, "
                    "'t', 'x', repeat('a', 64))"
                ),
                {"o": a.org_id, "r": run_id},
            )


async def test_one_output_per_run_and_citation_checks() -> None:
    a = await seed_tenant("alpha")
    run_id = await seed_ai_run(a)
    output_id = await _seed_output(a, run_id)
    with pytest.raises(DBAPIError, match="uq_ai_outputs_run_id"):
        await _seed_output(a, run_id)
    with pytest.raises(DBAPIError, match="ck_ai_citations_status"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(
                text(
                    "INSERT INTO ai_citations (organization_id, output_id, run_id, claim_path, "
                    "section, label, status) VALUES (:o, :out, :r, 'x', 'observed', 'F1', 'true')"
                ),
                {"o": a.org_id, "out": output_id, "r": run_id},
            )


async def test_reference_indexes_exist(owner_engine: AsyncEngine) -> None:
    async with owner_engine.connect() as conn:
        names = set(
            (
                await conn.execute(
                    text("SELECT indexname FROM pg_indexes WHERE tablename LIKE 'ai\\_%'")
                )
            ).scalars()
        )
    assert {
        "ix_ai_context_refs_organization_id_kind_ref_id",
        "ix_ai_run_index_status_resume_at",
        "ix_ai_runs_organization_id_context_sha256",
        "ix_ai_citations_organization_id_kind_ref_id",
    } <= names


async def test_orm_round_trip_counts() -> None:
    a = await seed_tenant("alpha")
    await _seed_all(a)
    async with tenant_session(a.org_id, a.owner_id) as s:
        for model in (
            AiProviderConfig,
            AiOrgSettings,
            AiRun,
            AiRunIndex,
            AiRunInput,
            AiOutput,
            AiCitation,
        ):
            assert (await s.execute(select(func.count()).select_from(model))).scalar_one() == 1
        refs = (await s.execute(select(func.count()).select_from(AiContextRef))).scalar_one()
        assert refs == 9  # make_context's default items
