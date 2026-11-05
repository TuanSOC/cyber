"""Migrations 0012 (M6 phase 1) and 0013 (review L4): RLS and FORCE on every new table,
cross-org FKs, the append-only tables (owner included), the guard triggers, column grants,
no DELETE, checks and the backfilled case defaults."""

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.tenancy import tenant_session
from app.modules.ai.contracts import CitationResult, CitationStatus
from tests.ai_api_helpers import finish_run
from tests.ai_helpers import seed_ai_run, seed_job
from tests.case_helpers import (
    seed_case,
    seed_collection,
    seed_collection_item,
    seed_evidence,
    seed_mapping,
    seed_note,
    seed_status_event,
    set_evidence_policy,
)
from tests.integration.seed import Tenant, seed_tenant
from tests.report_helpers import new_signing_keys, seed_render, seed_report, seed_version

TENANT_TABLES = (
    "investigation_status_events",
    "evidence_share_policies",
    "analyst_notes",
    "analyst_note_versions",
    "ioc_collections",
    "ioc_collection_items",
    "case_attack_mappings",
    "reports",
    "report_versions",
    "report_renders",
)
APPEND_ONLY = (
    "investigation_status_events",
    "analyst_note_versions",
    "report_versions",
    "report_citations",
)


async def _seed_all(t: Tenant) -> dict[str, uuid.UUID]:
    ids: dict[str, uuid.UUID] = {}
    ids["status_event"] = await seed_status_event(t)
    ids["evidence"] = await seed_evidence(t)
    await set_evidence_policy(t, ids["evidence"], ai_excluded=True)
    ids["note"] = await seed_note(t, bodies=("v1", "v2"))
    ids["collection"] = await seed_collection(t)
    ids["item"] = await seed_collection_item(t, ids["collection"])
    ids["mapping"] = await seed_mapping(t)
    ids["report"] = await seed_report(t)
    version = await seed_version(t, ids["report"], new_signing_keys(), store=False)
    ids["version"] = version.version_id
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text(
                "INSERT INTO report_citations (organization_id, version_id, cite_no, kind, "
                "ref_table, ref_id, fields_sha256, source) VALUES (:o, :v, 1, 'finding', "
                "'analysis_findings', 'x', repeat('a', 64), 'selection')"
            ),
            {"o": t.org_id, "v": ids["version"]},
        )
    ids["render"], _ = await seed_render(t, ids["version"])
    return ids


async def _count(org: uuid.UUID | None, table: str) -> int:
    async with tenant_session(org, None) as s:
        return int((await s.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one())


async def test_tenant_tables_are_isolated() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    await _seed_all(a)
    for table in (*TENANT_TABLES, "report_citations"):
        assert await _count(a.org_id, table) >= 1, table
        assert await _count(b.org_id, table) == 0, table
        assert await _count(None, table) == 0, table


async def test_render_index_is_system_visible_but_tenant_scoped() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    await _seed_all(a)
    assert await _count(None, "report_render_index") == 1
    assert await _count(a.org_id, "report_render_index") == 1
    assert await _count(b.org_id, "report_render_index") == 0


async def test_existing_cases_get_the_defaults() -> None:
    t = await seed_tenant("alpha")
    async with tenant_session(t.org_id, t.owner_id) as s:
        row = (
            await s.execute(
                text("SELECT tlp, ai_excluded, ti_excluded FROM investigations WHERE id = :i"),
                {"i": t.investigation_id},
            )
        ).one()
    assert tuple(row) == ("amber", False, False)
    with pytest.raises(DBAPIError, match="ck_investigations_tlp"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                text("UPDATE investigations SET tlp = 'amber+strict' WHERE id = :i"),
                {"i": t.investigation_id},
            )


async def test_children_cannot_point_at_another_orgs_rows() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    foreign = await _seed_all(b)
    # Evidence without a share-policy row (the seeded one has one: its PK would fire first).
    bare_evidence = await seed_evidence(b)
    statements = (
        "INSERT INTO investigation_status_events (organization_id, investigation_id, "
        "to_status, actor_id) VALUES (:o, :inv, 'closed', :u)",
        "INSERT INTO evidence_share_policies (evidence_id, organization_id, updated_by) "
        "VALUES (:ev, :o, :u)",
        "INSERT INTO analyst_notes (organization_id, investigation_id, created_by) "
        "VALUES (:o, :inv, :u)",
        "INSERT INTO analyst_note_versions (note_id, version, organization_id, body, "
        "author_id) VALUES (:note, 9, :o, 'x', :u)",
        "INSERT INTO ioc_collection_items (organization_id, collection_id, ioc_type, "
        "value_norm, ioc_key, source, added_by) VALUES (:o, :col, 'domain', 'x.example', "
        "repeat('b', 64), 'manual', :u)",
        "INSERT INTO reports (organization_id, investigation_id, title, tlp, created_by) "
        "VALUES (:o, :inv, 'x', 'amber', :u)",
        # `md`: the seeded render is a live `pdf` one (its unique index would fire first).
        "INSERT INTO report_renders (organization_id, version_id, format, token_sha256, "
        "requested_by) VALUES (:o, :ver, 'md', repeat('c', 64), :u)",
    )
    params = {
        "o": a.org_id,
        "u": a.owner_id,
        "inv": b.investigation_id,
        "ev": bare_evidence,
        "note": foreign["note"],
        "col": foreign["collection"],
        "ver": foreign["version"],
    }
    for statement in statements:
        with pytest.raises(DBAPIError, match="foreign key"):
            async with tenant_session(a.org_id, a.owner_id) as s:
                await s.execute(text(statement), params)


SAME_ORG_FKS = (
    "SELECT conrelid::regclass::text, conname::text, array_length(conkey, 1) "
    "FROM pg_constraint WHERE contype = 'f' AND conname IN ("
    "'fk_ioc_collection_items_ioc_id_organization_id_iocs', "
    "'fk_report_citations_ai_citation_id_organization_id_ai_citations', "
    "'fk_ioc_collection_items_ioc_id_iocs', 'fk_report_citations_ai_citation_id_ai_citations'"
    ") ORDER BY 1"
)


async def test_job_iocs_and_ai_citations_are_same_org_fks(owner_engine: AsyncEngine) -> None:
    """0013 (M6 review L4): the two plain `id` FKs of 0012 are composite same-org FKs."""
    async with owner_engine.connect() as conn:
        rows = (await conn.execute(text(SAME_ORG_FKS))).all()
    assert [tuple(r) for r in rows] == [
        ("ioc_collection_items", "fk_ioc_collection_items_ioc_id_organization_id_iocs", 2),
        (
            "report_citations",
            "fk_report_citations_ai_citation_id_organization_id_ai_citations",
            2,
        ),
    ]


async def test_items_and_citations_cannot_name_another_orgs_ioc_or_ai_citation() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    foreign_job = await seed_job(b)
    async with tenant_session(b.org_id, b.owner_id) as s:
        foreign_ioc = (
            await s.execute(
                text(
                    "INSERT INTO iocs (organization_id, job_id, type, value, first_seen, "
                    "last_seen, count, source) VALUES (:o, :j, 'domain', 'x.example', now(), "
                    "now(), 1, 'dns') RETURNING id"
                ),
                {"o": b.org_id, "j": foreign_job},
            )
        ).scalar_one()
    run = await seed_ai_run(b, job_id=foreign_job)
    await finish_run(
        b.org_id,
        run,
        body={"summary": "x"},
        citations=[
            CitationResult(
                claim_path="observed[0].citations[0]",
                section="observed",
                label="A1",
                status=CitationStatus.UNVERIFIED,
            )
        ],
    )
    async with tenant_session(b.org_id, b.owner_id) as s:
        foreign_citation = (
            await s.execute(text("SELECT id FROM ai_citations WHERE run_id = :r"), {"r": run})
        ).scalar_one()

    own_job = await seed_job(a)
    collection = await seed_collection(a)
    report = await seed_report(a)
    version = (await seed_version(a, report, new_signing_keys(), store=False)).version_id
    statements = (
        "INSERT INTO ioc_collection_items (organization_id, collection_id, ioc_type, "
        "value_norm, ioc_key, source, job_id, ioc_id, added_by) VALUES (:o, :col, 'domain', "
        "'x.example', repeat('d', 64), 'job_ioc', :job, :ioc, :u)",
        "INSERT INTO report_citations (organization_id, version_id, cite_no, kind, ref_table, "
        "ref_id, fields_sha256, source, ai_citation_id) VALUES (:o, :ver, 1, 'finding', "
        "'analysis_findings', 'x', repeat('a', 64), 'ai', :cit)",
    )
    params = {
        "o": a.org_id,
        "u": a.owner_id,
        "col": collection,
        "job": own_job,
        "ioc": foreign_ioc,
        "ver": version,
        "cit": foreign_citation,
    }
    for statement in statements:
        with pytest.raises(DBAPIError, match="foreign key"):
            async with tenant_session(a.org_id, a.owner_id) as s:
                await s.execute(text(statement), params)


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO reports (organization_id, investigation_id, title, tlp, created_by) "
        "VALUES (:other, :inv, 'x', 'amber', :u)",
        "INSERT INTO report_render_index (render_id, organization_id, status, deadline_at) "
        "VALUES (gen_random_uuid(), :other, 'queued', now())",
    ],
)
async def test_rows_cannot_be_written_into_another_org(statement: str) -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    with pytest.raises(DBAPIError, match="row-level security|foreign key"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(
                text(statement), {"other": b.org_id, "inv": b.investigation_id, "u": a.owner_id}
            )


# --- append-only, grants, no DELETE ---------------------------------------------------------


@pytest.mark.parametrize("table", APPEND_ONLY)
@pytest.mark.parametrize("statement", ["UPDATE {t} SET organization_id = organization_id",
                                       "DELETE FROM {t}"])  # fmt: skip
async def test_app_role_cannot_mutate_append_only_tables(table: str, statement: str) -> None:
    t = await seed_tenant("alpha")
    await _seed_all(t)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(text(statement.format(t=table)))


@pytest.mark.parametrize("table", APPEND_ONLY)
@pytest.mark.parametrize("statement", ["UPDATE {t} SET organization_id = organization_id",
                                       "DELETE FROM {t}"])  # fmt: skip
async def test_trigger_blocks_owner_mutations_too(
    table: str, statement: str, owner_engine: AsyncEngine
) -> None:
    t = await seed_tenant("alpha")
    await _seed_all(t)
    with pytest.raises(DBAPIError, match="append-only"):
        async with owner_engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.org_id', :o, true)"), {"o": str(t.org_id)}
            )
            await conn.execute(text(statement.format(t=table)))


@pytest.mark.parametrize(
    "table",
    [
        "evidence_share_policies",
        "analyst_notes",
        "ioc_collections",
        "ioc_collection_items",
        "case_attack_mappings",
        "reports",
        "report_renders",
        "report_render_index",
    ],
)
async def test_no_delete_grant(table: str) -> None:
    t = await seed_tenant("alpha")
    await _seed_all(t)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(text(f"DELETE FROM {table}"))


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE evidence_share_policies SET organization_id = organization_id",
        "UPDATE analyst_notes SET created_by = created_by",
        "UPDATE ioc_collections SET investigation_id = investigation_id",
        "UPDATE ioc_collection_items SET ioc_key = ioc_key",
        "UPDATE case_attack_mappings SET technique_id = technique_id",
        "UPDATE reports SET investigation_id = investigation_id",
        "UPDATE report_renders SET token_sha256 = token_sha256",
        "UPDATE report_render_index SET organization_id = organization_id",
    ],
)
async def test_column_grants_refuse_identity_updates(statement: str) -> None:
    t = await seed_tenant("alpha")
    await _seed_all(t)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(text(statement))


# --- guard triggers -------------------------------------------------------------------------


async def _exec(t: Tenant, sql: str, **params: object) -> None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(text(sql), params)


async def test_note_guard() -> None:
    t = await seed_tenant("alpha")
    ids = await _seed_all(t)
    note = ids["note"]
    await _exec(t, "UPDATE analyst_notes SET current_version = 3, pinned = true WHERE id = :n",
                n=note)  # fmt: skip
    with pytest.raises(DBAPIError, match="may not decrease"):
        await _exec(t, "UPDATE analyst_notes SET current_version = 1 WHERE id = :n", n=note)
    await _exec(
        t,
        "UPDATE analyst_notes SET deleted_at = now(), deleted_by = :u WHERE id = :n",
        n=note,
        u=t.owner_id,
    )
    with pytest.raises(DBAPIError, match="set once"):
        await _exec(
            t, "UPDATE analyst_notes SET deleted_at = NULL, deleted_by = NULL WHERE id = :n", n=note
        )
    with pytest.raises(DBAPIError, match="deleted_pair"):
        note2 = await seed_note(t)
        await _exec(t, "UPDATE analyst_notes SET deleted_at = now() WHERE id = :n", n=note2)


async def test_note_body_and_refs_checks() -> None:
    t = await seed_tenant("alpha")
    with pytest.raises(DBAPIError, match="body_length"):
        await seed_note(t, bodies=("x" * 20_001,))
    with pytest.raises(DBAPIError, match="ck_analyst_note_versions_refs"):
        await seed_note(t, refs=[{"kind": "job", "ref_id": str(i)} for i in range(21)])
    await seed_note(t, bodies=("ệ" * 20_000,))


async def test_collection_item_guard_and_partial_uniqueness() -> None:
    t = await seed_tenant("alpha")
    collection = await seed_collection(t)
    item = await seed_collection_item(t, collection)
    with pytest.raises(DBAPIError, match="ux_ioc_collection_items"):
        await seed_collection_item(t, collection)
    await _exec(
        t,
        "UPDATE ioc_collection_items SET removed_at = now(), removed_by = :u WHERE id = :i",
        i=item,
        u=t.owner_id,
    )
    with pytest.raises(DBAPIError, match="set once"):
        await _exec(t, "UPDATE ioc_collection_items SET removed_at = now() WHERE id = :i", i=item)
    await seed_collection_item(t, collection)  # a removed item can be re-added
    with pytest.raises(DBAPIError, match="ux_ioc_collections"):
        await seed_collection(t, name="BLOCKLIST")


async def test_report_guard() -> None:
    t = await seed_tenant("alpha")
    report = await seed_report(t)
    await _exec(t, "UPDATE reports SET title = 'x', revision = revision + 1 WHERE id = :r",
                r=report)  # fmt: skip
    with pytest.raises(DBAPIError, match="increase by one"):
        await _exec(t, "UPDATE reports SET title = 'y' WHERE id = :r", r=report)
    with pytest.raises(DBAPIError, match="increase by one"):
        await _exec(t, "UPDATE reports SET revision = revision + 2 WHERE id = :r", r=report)
    versioned = await seed_report(t)
    await seed_version(t, versioned, new_signing_keys(), store=False)
    with pytest.raises(DBAPIError, match="may not decrease"):
        await _exec(
            t,
            "UPDATE reports SET latest_version = 0, revision = revision + 1 WHERE id = :r",
            r=versioned,
        )
    with pytest.raises(DBAPIError, match="cannot be discarded"):
        await _exec(
            t,
            "UPDATE reports SET status = 'discarded', revision = revision + 1 WHERE id = :r",
            r=versioned,
        )
    await _exec(
        t,
        "UPDATE reports SET status = 'discarded', revision = revision + 1 WHERE id = :r",
        r=report,
    )
    with pytest.raises(DBAPIError, match="discarded"):
        await _exec(
            t,
            "UPDATE reports SET status = 'draft', revision = revision + 1 WHERE id = :r",
            r=report,
        )


async def test_report_draft_and_version_checks() -> None:
    t = await seed_tenant("alpha")
    report = await seed_report(t)
    big = "x" * (1024 * 1024)
    with pytest.raises(DBAPIError, match="ck_reports_draft"):
        await _exec(
            t,
            "UPDATE reports SET draft = jsonb_build_object('s', CAST(:big AS text)), "
            "revision = revision + 1 WHERE id = :r",
            r=report,
            big=big,
        )
    keys = new_signing_keys()
    with pytest.raises(DBAPIError, match="change_note_length"):
        await seed_version(t, report, keys, store=False, change_note="x" * 501)
    v = await seed_version(t, report, keys, store=False, change_note="x" * 500)
    columns = {"snapshot_sha256": "snapshot_sha256", "signature": "signature", "kid": "kid"}
    for column, bad in (("signature", "'not-base64'"), ("kid", "'bad kid'"),
                        ("snapshot_sha256", "'ABC'")):  # fmt: skip
        picked = {**columns, column: bad}
        with pytest.raises(DBAPIError, match=f"ck_report_versions_{column}"):
            await _exec(
                t,
                "INSERT INTO report_versions (organization_id, report_id, version, "
                "schema_version, tlp, profile, snapshot_sha256, snapshot_bytes, object_key, "
                "object_version_id, manifest, signature, kid, finalized_by) "
                "SELECT organization_id, report_id, 99, schema_version, tlp, profile, "
                f"{picked['snapshot_sha256']}, snapshot_bytes, object_key, object_version_id, "
                f"manifest, {picked['signature']}, {picked['kid']}, finalized_by "
                "FROM report_versions WHERE id = :v",
                v=v.version_id,
            )
    with pytest.raises(DBAPIError, match="ck_report_citations_cite_no_positive"):
        await _exec(
            t,
            "INSERT INTO report_citations (organization_id, version_id, cite_no, kind, "
            "ref_table, ref_id, fields_sha256, source) VALUES (:o, :v, 0, 'finding', "
            "'analysis_findings', 'x', repeat('a', 64), 'selection')",
            o=t.org_id,
            v=v.version_id,
        )


async def test_render_transitions() -> None:
    t = await seed_tenant("alpha")
    report = await seed_report(t)
    version = await seed_version(t, report, new_signing_keys(), store=False)
    render, _ = await seed_render(t, version.version_id)
    with pytest.raises(DBAPIError, match="illegal report render transition"):
        await _exec(
            t,
            "UPDATE report_renders SET status = 'succeeded', sha256 = repeat('a', 64), "
            "bytes = 1, object_version_id = 'v' WHERE id = :r",
            r=render,
        )
    await _exec(t, "UPDATE report_renders SET status = 'running' WHERE id = :r", r=render)
    with pytest.raises(DBAPIError, match="succeeded_has_artifact"):
        await _exec(t, "UPDATE report_renders SET status = 'succeeded' WHERE id = :r", r=render)
    await _exec(
        t,
        "UPDATE report_renders SET status = 'succeeded', sha256 = repeat('a', 64), bytes = 1, "
        "object_version_id = 'v', renderer_version = 'rw' WHERE id = :r",
        r=render,
    )
    with pytest.raises(DBAPIError, match="is final"):
        await _exec(
            t,
            "UPDATE report_renders SET status = 'failed', error_code = 'oom' WHERE id = :r",
            r=render,
        )
    # Dedupe: one non-failed render per (version, format, renderer version).
    with pytest.raises(DBAPIError, match="ux_report_renders"):
        await _exec(
            t,
            "INSERT INTO report_renders (organization_id, version_id, format, status, "
            "token_sha256, sha256, bytes, object_version_id, renderer_version, requested_by) "
            "VALUES (:o, :v, 'pdf', 'queued', repeat('d', 64), NULL, NULL, NULL, 'rw', :u)",
            o=t.org_id,
            v=version.version_id,
            u=t.owner_id,
        )
    with pytest.raises(DBAPIError, match="ck_report_renders_format"):
        await seed_render(t, version.version_id, fmt="docx")


async def test_ti_run_item_reason_accepts_policy_blocked(owner_engine: AsyncEngine) -> None:
    async with owner_engine.connect() as conn:
        definition = (
            await conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname = 'ck_ti_run_items_reason'"
                )
            )
        ).scalar_one()
    assert "policy_blocked" in definition


async def test_status_event_reason_check() -> None:
    t = await seed_tenant("alpha")
    with pytest.raises(DBAPIError, match="reason_length"):
        await seed_status_event(t, reason="x" * 501)
    with pytest.raises(DBAPIError, match="to_status"):
        await seed_status_event(t, to_status="deleted")
    case = await seed_case(t, tlp="red", ai_excluded=True)
    assert await seed_status_event(t, case, from_status=None, to_status="open")
