"""Retention of reverse-engineering results (M10 phase 9).

The eight bulk RE tables join `BULK_TABLES`: a closed case's purge after `closed_case_days`
deletes them (a row a report cites stays, `kept_cited`), while `re_programs` (the RE job's
record), findings, IOCs and every row of the source static job stay (the M7 rule).
"""

import hashlib
import secrets
import uuid

from sqlalchemy import text

from app.core.tenancy import tenant_session
from app.modules.reports.models import ReportCitation
from app.modules.retention.select import BULK_TABLES
from app.modules.reverse_engineering.models import BULK_TABLES as RE_BULK
from tests.integration.seed import Tenant
from tests.integration.test_retention_purge import (
    Captured,
    captured,
    count,
    items,
    owner_tenant,
    run_once,
    select_now,
    set_enforce,
)
from tests.ops_helpers import _close_case, _stored_evidence, days_ago, seed_retention_policy
from tests.report_helpers import new_signing_keys, seed_report, seed_version
from tests.reverse_helpers import seed_re_job, seed_static_source_job

__all__ = ["captured"]
KEPT_PER_JOB = ("re_programs",)
STATIC_KEPT = ("malware_samples", "malware_capabilities")


def test_the_re_tables_are_bulk_tables() -> None:
    assert set(RE_BULK) <= set(BULK_TABLES)
    assert "re_programs" not in BULK_TABLES
    assert len(RE_BULK) == 8


async def _cite_function(t: Tenant, case_id: uuid.UUID, job_id: uuid.UUID) -> str:
    """A finalized report version of the case citing one `re_functions` row."""
    async with tenant_session(t.org_id, None) as s:
        ref_id = str(
            (
                await s.execute(
                    text("SELECT id FROM re_functions WHERE job_id = :j ORDER BY id LIMIT 1"),
                    {"j": job_id},
                )
            ).scalar_one()
        )
    report_id = await seed_report(t, case_id)
    version = await seed_version(t, report_id, new_signing_keys(), store=False)
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            ReportCitation(
                organization_id=t.org_id,
                version_id=version.version_id,
                cite_no=1,
                kind="function",
                ref_table="re_functions",
                ref_id=ref_id,
                job_id=job_id,
                fields_sha256=hashlib.sha256(secrets.token_bytes(8)).hexdigest(),
                source="selection",
            )
        )
    return ref_id


async def _per_job(t: Tenant, table: str, job_id: uuid.UUID) -> int:
    return await count(
        t.org_id,
        f"SELECT count(*) FROM {table} WHERE job_id = :j",  # noqa: S608 - constant table names
        j=job_id,
    )


async def test_a_closed_case_purge_takes_the_re_bulk_rows_only(captured: Captured) -> None:
    _, t = await owner_tenant("RE Retention Org")
    case_id = t.investigation_id
    evidence_id, _ = await _stored_evidence(t, case_id, secrets.token_bytes(4096), "sample.exe")
    static_job = await seed_static_source_job(t, evidence_id)
    re_job = await seed_re_job(t, static_job)
    cited = await _cite_function(t, case_id, re_job)
    await _close_case(t, case_id, days_ago(400))

    before = {table: await _per_job(t, table, re_job) for table in (*RE_BULK, *KEPT_PER_JOB)}
    for table in ("re_functions", "re_call_edges", "re_decompilations", "re_strings"):
        assert before[table] > 0, (table, before)
    static_before = {table: await _per_job(t, table, static_job) for table in STATIC_KEPT}

    await seed_retention_policy(t, closed_case_days=30)
    selected = await select_now(t.org_id)
    re_candidates = {
        c.ref_table: c.rows
        for c in selected.candidates
        if c.ref_table.startswith("re_") and c.job_id == re_job
    }
    expected = {table for table in RE_BULK if before[table]}
    assert set(re_candidates) == expected
    assert re_candidates["re_functions"] == before["re_functions"] - 1  # the cited row
    assert not any(
        c.job_id == static_job and c.ref_table in STATIC_KEPT for c in selected.candidates
    )

    await set_enforce(t, True)
    run_id = await run_once(captured, t.org_id)

    for table in RE_BULK:
        left = await _per_job(t, table, re_job)
        assert left == (1 if table == "re_functions" else 0), (table, left)
    assert (
        await count(t.org_id, "SELECT count(*) FROM re_functions WHERE id::text = :i", i=cited)
        == 1
    )
    for table in KEPT_PER_JOB:
        assert await _per_job(t, table, re_job) == before[table], table
    # The source static job is never touched by the RE purge.
    for table in STATIC_KEPT:
        assert await _per_job(t, table, static_job) == static_before[table], table
    run_items = await items(t.org_id, run_id)
    purged = {i["ref_table"] for i in run_items if i["outcome"] == "purged"}
    assert {"re_functions", "re_decompilations", "re_call_edges"} <= purged
    assert any(i["ref_table"] == "re_functions" and i["outcome"] == "kept_cited" for i in run_items)
