"""M9 phase 7: the in-org known-hash join at ingest (`correlation:disk_known_org_hash@1`).

A listed file whose sha256 / sha1 / md5 equals an IOC hash value or a correlation key of
ANOTHER job of the same org gets one `low` finding citing the file and the matched source;
another org's rows are never read; the job's own IOCs never match it; the findings are capped;
a timeout skips the join and never fails the ingest.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select, text

from app.core.tenancy import tenant_session
from app.modules.correlation.models import CorrelationKey
from app.modules.correlation.normalize import correlation_key
from app.modules.disk_forensics import ingest as disk_ingest
from app.modules.pcap_analysis.models import AnalysisFinding, Ioc
from tests import disk_results as dr
from tests.analysis_helpers import SentJobs, new_case
from tests.case_helpers import seed_evidence, seed_job_on
from tests.disk_results import HandOffs
from tests.disk_results import handoffs as handoffs  # noqa: F401 (fixture)
from tests.disk_results import sent as sent  # noqa: F401 (fixture)
from tests.factories import Registered, register
from tests.integration.seed import Tenant

NOW = datetime(2026, 10, 1, tzinfo=UTC)


def _file(path: str) -> dict[str, Any]:
    objs = dr.parsed(dr.WINDOWS)
    return objs[dr.index_of(objs, "file", path=path)]


SYS000 = _file("Windows/System32/sys000.dll")
SYS001 = _file("Windows/System32/sys001.dll")
SYS002 = _file("Windows/System32/sys002.dll")


async def _other_job(reg: Registered) -> tuple[Tenant, uuid.UUID]:
    """A succeeded job of another case of the same org (its rows are seeded below)."""
    t = Tenant(reg.org_id, reg.user_id, uuid.UUID(await new_case(reg)))
    return t, await seed_job_on(t, await seed_evidence(t))


async def _ioc(t: Tenant, job_id: uuid.UUID, ioc_type: str, value: str) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        row = Ioc(
            organization_id=t.org_id,
            job_id=job_id,
            type=ioc_type,
            value=value,
            first_seen=NOW,
            last_seen=NOW,
            count=1,
            source="pcap",
        )
        s.add(row)
    return row.id


async def _key(t: Tenant, job_id: uuid.UUID, kind: str, value: str) -> uuid.UUID:
    found = correlation_key(kind, value)
    assert found is not None
    kind, key, value_norm = found
    async with tenant_session(t.org_id, t.owner_id) as s:
        evidence_id = await s.scalar(
            text("SELECT evidence_id FROM analysis_jobs WHERE id = :job"), {"job": job_id}
        )
        row = CorrelationKey(
            organization_id=t.org_id,
            investigation_id=t.investigation_id,
            evidence_id=evidence_id,
            job_id=job_id,
            kind=kind,
            key=key,
            value_norm=value_norm,
            source_table="iocs",
            source_id=str(uuid.uuid4()),
        )
        s.add(row)
    return row.id


async def _known(org_id: uuid.UUID, job_id: uuid.UUID) -> list[AnalysisFinding]:
    async with tenant_session(org_id, None) as session:
        rows = await session.scalars(
            select(AnalysisFinding)
            .where(
                AnalysisFinding.job_id == job_id,
                AnalysisFinding.detection_method == disk_ingest.KNOWN_HASH_METHOD,
            )
            .order_by(AnalysisFinding.title, AnalysisFinding.finding_id)
        )
        return list(rows)


async def _file_id(org_id: uuid.UUID, job_id: uuid.UUID, path: str) -> uuid.UUID:
    [row] = await dr.rows(
        org_id,
        "SELECT id FROM disk_files WHERE job_id = :job AND path = :path",
        job=job_id,
        path=path,
    )
    return uuid.UUID(str(row.id))


async def test_a_hash_seen_in_another_job_of_the_org_is_a_finding(
    sent: SentJobs, handoffs: HandOffs
) -> None:
    reg, _, item = await dr.queued_job(sent)
    t, other_job = await _other_job(reg)
    ioc_id = await _ioc(t, other_job, "file_sha256", SYS000["sha256"].upper())
    key_id = await _key(t, other_job, "sha1", SYS001["sha1"])
    # Another org holds sys002's hash: never read.
    stranger = await register()
    st, stranger_job = await _other_job(stranger)
    await _ioc(st, stranger_job, "file_sha256", SYS002["sha256"])

    await dr.deliver(item, dr.framed(dr.retargeted(item)), handoffs)
    job = await dr.job_of(item)
    assert job.status == "succeeded", job.error_code
    assert job.summary["known_hash_join"] == "ok"
    assert job.summary["counts"]["known_hash_files"] == 2

    found = await _known(reg.org_id, item.job_id)
    assert len(found) == 2 and {f.severity for f in found} == {"low"}
    refs = {f.evidence_refs[0]: f.evidence_refs for f in found}
    sys000 = await _file_id(reg.org_id, item.job_id, SYS000["path"])
    sys001 = await _file_id(reg.org_id, item.job_id, SYS001["path"])
    assert set(refs) == {f"file:{sys000}", f"file:{sys001}"}
    assert f"ioc:{ioc_id}" in refs[f"file:{sys000}"]
    assert f"correlation_key:{key_id}" in refs[f"file:{sys001}"]
    assert all(f"job:{other_job}" in r for r in refs.values())
    # The disk job's own IOCs (the fixture lists a file_sha256) never match it.
    assert all(f"job:{item.job_id}" not in r for r in refs.values())


async def test_the_join_is_capped_with_a_summary_finding(
    sent: SentJobs, handoffs: HandOffs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(disk_ingest, "KNOWN_HASH_MAX_FINDINGS", 1)
    reg, _, item = await dr.queued_job(sent)
    t, other_job = await _other_job(reg)
    for f in (SYS000, SYS001, SYS002):
        await _ioc(t, other_job, "file_md5", f["md5"])
    await dr.deliver(item, dr.framed(dr.retargeted(item)), handoffs)
    job = await dr.job_of(item)
    assert job.status == "succeeded", job.error_code
    assert job.summary["counts"]["known_hash_files"] == 3
    assert job.summary["counts"]["known_hash_findings"] == 2
    found = await _known(reg.org_id, item.job_id)
    assert len(found) == 2
    [more] = [f for f in found if f.evidence_refs == []]
    assert more.attributes == {"files": 2}


async def test_a_join_timeout_skips_it_and_keeps_the_ingest(
    sent: SentJobs, handoffs: HandOffs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(disk_ingest, "KNOWN_HASH_SQL", text("SELECT pg_sleep(5)"))
    monkeypatch.setattr(disk_ingest, "KNOWN_HASH_TIMEOUT_S", 0.2)
    reg, _, item = await dr.queued_job(sent)
    await dr.deliver(item, dr.framed(dr.retargeted(item)), handoffs)
    job = await dr.job_of(item)
    assert job.status == "succeeded", job.error_code
    assert job.summary["known_hash_join"] == "skipped_timeout"
    assert await dr.row_counts(reg.org_id, item.job_id) == dr.WINDOWS_TABLES
