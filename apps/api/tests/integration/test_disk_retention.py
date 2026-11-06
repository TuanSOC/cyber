"""Retention of disk results (M9 phase 9).

`disk_files` and `disk_events` join `BULK_TABLES`: a closed case's purge after
`closed_case_days` deletes them (a row a report cites stays, `kept_cited`), while
`disk_images`, `disk_partitions`, `disk_exports`, `analysis_job_segments`,
`memory_sensitivity`, findings and IOCs are never purged (the M7 rule). The segment bytes are
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
from tests.disk_helpers import seed_disk_job
from tests.integration.seed import Tenant
from tests.integration.test_disk_sensitivity import apply_disk_default, seed_disk_results
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

__all__ = ["captured"]
DISK_BULK = ("disk_events", "disk_files")
KEPT_PER_JOB = ("disk_images", "disk_partitions", "analysis_findings", "iocs")


def test_the_disk_tables_are_bulk_tables() -> None:
    assert set(DISK_BULK) <= set(BULK_TABLES)
    never = {
        "disk_images",
        "disk_partitions",
        "disk_exports",
        "analysis_job_segments",
        "memory_sensitivity",
    }
    assert not never & set(BULK_TABLES)


async def _cite_file(t: Tenant, case_id: uuid.UUID, job_id: uuid.UUID) -> str:
    """A finalized report version of the case citing one `disk_files` row."""
    async with tenant_session(t.org_id, None) as s:
        ref_id = str(
            (
                await s.execute(
                    text("SELECT id FROM disk_files WHERE job_id = :j ORDER BY id LIMIT 1"),
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
                kind="disk_file",
                ref_table="disk_files",
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


async def test_a_closed_case_purge_takes_the_disk_bulk_rows_only(captured: Captured) -> None:
    _, t = await owner_tenant("Disk Retention Org")
    case_id = await seed_case(t, title="Closed disk case")
    ct = Tenant(t.org_id, t.owner_id, case_id)
    segments = []
    for name in ("laptop.E01", "laptop.E02"):
        evidence_id, _ = await _stored_evidence(ct, case_id, secrets.token_bytes(4096), name)
        assert await apply_disk_default(ct, evidence_id)  # as the first disk job would
        segments.append(evidence_id)
    job_id = await seed_disk_job(ct, segments)
    await seed_disk_results(ct, job_id, iocs=[("ip", "198.51.100.23"), ("domain", "x.example")])
    cited = await _cite_file(t, case_id, job_id)
    await _close_case(t, case_id, days_ago(400))

    before = {table: await _per_job(t, table, job_id) for table in (*DISK_BULK, *KEPT_PER_JOB)}
    assert all(before[table] > 0 for table in (*DISK_BULK, "disk_images")), before

    await seed_retention_policy(t, closed_case_days=30)
    selected = await select_now(t.org_id)
    disk_candidates = {
        c.ref_table: c.rows for c in selected.candidates if c.ref_table.startswith("disk_")
    }
    assert set(disk_candidates) == set(DISK_BULK)
    assert disk_candidates["disk_files"] == before["disk_files"] - 1  # the cited row
    assert disk_candidates["disk_events"] == before["disk_events"]

    await set_enforce(t, True)
    run_id = await run_once(captured, t.org_id)

    assert await _per_job(t, "disk_events", job_id) == 0
    assert await _per_job(t, "disk_files", job_id) == 1
    assert (
        await count(t.org_id, "SELECT count(*) FROM disk_files WHERE id::text = :i", i=cited) == 1
    )
    # Never purged: the image facts, partitions, segment set, sensitivity, findings and IOCs.
    for table in KEPT_PER_JOB:
        assert await _per_job(t, table, job_id) == before[table], table
    assert await _per_job(t, "analysis_job_segments", job_id) == 2
    for segment in segments:
        assert (
            await count(
                t.org_id,
                "SELECT count(*) FROM memory_sensitivity WHERE evidence_id = :e",
                e=segment,
            )
            == 1
        )
    run_items = await items(t.org_id, run_id)
    purged = {i["ref_table"] for i in run_items if i["outcome"] == "purged"}
    assert set(DISK_BULK) <= purged and "evidence" in purged  # the segment bytes too
    assert any(i["ref_table"] == "disk_files" and i["outcome"] == "kept_cited" for i in run_items)
