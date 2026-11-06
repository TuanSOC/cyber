"""Retention of memory results (M8 phase 8).

The four memory bulk tables join `BULK_TABLES`: a closed case's purge after
`closed_case_days` deletes `memory_processes`, `memory_connections`, `memory_injections` and
`memory_artifacts` rows (a row a report cites stays, `kept_cited`), while `memory_images`,
`memory_sensitivity`, findings and IOCs are never purged (the M7 rule). The image bytes are
evidence bytes and follow the M7 evidence purge.
"""

import hashlib
import secrets
import uuid

from sqlalchemy import text

from app.core.tenancy import tenant_session
from app.modules.reports.models import ReportCitation
from app.modules.retention.select import BULK_TABLES
from tests.case_helpers import seed_case
from tests.integration.seed import Tenant
from tests.integration.test_memory_sensitivity import apply_default, seed_memory_results
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
from tests.memory_helpers import seed_memory_job
from tests.ops_helpers import _close_case, _stored_evidence, days_ago, seed_retention_policy
from tests.report_helpers import new_signing_keys, seed_report, seed_version

__all__ = ["captured"]
MEMORY_BULK = ("memory_artifacts", "memory_connections", "memory_injections", "memory_processes")
KEPT = ("memory_images", "memory_sensitivity", "analysis_findings", "iocs")


def test_the_memory_tables_are_bulk_tables() -> None:
    assert set(MEMORY_BULK) <= set(BULK_TABLES)
    assert not {"memory_images", "memory_sensitivity"} & set(BULK_TABLES)


async def _cite_process(t: Tenant, case_id: uuid.UUID, job_id: uuid.UUID) -> str:
    """A finalized report version of the case citing one `memory_processes` row."""
    async with tenant_session(t.org_id, None) as s:
        ref_id = str(
            (
                await s.execute(
                    text("SELECT id FROM memory_processes WHERE job_id = :j ORDER BY id LIMIT 1"),
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
                kind="process",
                ref_table="memory_processes",
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


async def test_a_closed_case_purge_takes_the_memory_bulk_rows_only(captured: Captured) -> None:
    _, t = await owner_tenant("Memory Retention Org")
    case_id = await seed_case(t, title="Closed memory case")
    ct = Tenant(t.org_id, t.owner_id, case_id)
    image, _ = await _stored_evidence(ct, case_id, secrets.token_bytes(4096), "host.mem")
    assert await apply_default(ct, image)  # as the first memory job would
    job_id = await seed_memory_job(ct, image)
    await seed_memory_results(ct, job_id, iocs=[("ip", "203.0.113.77"), ("domain", "x.example")])
    cited = await _cite_process(t, case_id, job_id)
    await _close_case(t, case_id, days_ago(400))

    before = {table: await _per_job(t, table, job_id) for table in (*MEMORY_BULK, *KEPT[:1])}
    assert all(before[table] > 0 for table in MEMORY_BULK), before
    findings = await _per_job(t, "analysis_findings", job_id)
    iocs = await _per_job(t, "iocs", job_id)

    await seed_retention_policy(t, closed_case_days=30)
    selected = await select_now(t.org_id)
    memory_candidates = {
        c.ref_table: c.rows for c in selected.candidates if c.ref_table.startswith("memory_")
    }
    assert set(memory_candidates) == set(MEMORY_BULK)
    assert memory_candidates["memory_processes"] == before["memory_processes"] - 1  # cited
    for table in MEMORY_BULK[:3]:
        assert memory_candidates[table] == before[table]

    await set_enforce(t, True)
    run_id = await run_once(captured, t.org_id)

    for table in MEMORY_BULK[:3]:
        assert await _per_job(t, table, job_id) == 0, table
    assert await _per_job(t, "memory_processes", job_id) == 1
    assert (
        await count(t.org_id, "SELECT count(*) FROM memory_processes WHERE id::text = :i", i=cited)
        == 1
    )
    # Never purged: the image row, the sensitivity marker, findings and IOCs.
    assert await _per_job(t, "memory_images", job_id) == before["memory_images"] == 1
    assert (
        await count(
            t.org_id, "SELECT count(*) FROM memory_sensitivity WHERE evidence_id = :e", e=image
        )
        == 1
    )
    assert await _per_job(t, "analysis_findings", job_id) == findings
    assert await _per_job(t, "iocs", job_id) == iocs
    run_items = await items(t.org_id, run_id)
    purged = {i["ref_table"] for i in run_items if i["outcome"] == "purged"}
    assert set(MEMORY_BULK) <= purged and "evidence" in purged
    assert any(
        i["ref_table"] == "memory_processes" and i["outcome"] == "kept_cited" for i in run_items
    )
