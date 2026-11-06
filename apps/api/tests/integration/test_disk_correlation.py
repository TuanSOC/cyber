"""Disk IOCs and in-org correlation (M9 phase 9).

Correlation is allowed for restricted disk evidence (keys only, never across orgs): the
hashes of flagged files, remote-logon source IPs and quoted URLs / domains of a disk job are
ordinary `iocs` rows, so the unchanged M7 indexer picks them up (no analyzer filter). A
sha256 seen in a disk job and as a static sample in another case shows "also seen in" both
ways; the lookup lists the disk occurrence with `analyzer: disk` (the web links it to
`/forensics/{job}`, the phase-1 analyzer sweep); another org's identical hash never counts.
"""

import uuid

from sqlalchemy import text

from app.core.tenancy import tenant_session
from app.modules.analysis.models import Analyzer
from app.modules.correlation import indexer
from app.modules.static_analysis.models import MalwareSample
from tests.case_helpers import seed_case, seed_evidence, seed_job_on
from tests.disk_helpers import seed_disk_job
from tests.factories import csrf
from tests.integration.seed import Tenant, seed_tenant
from tests.integration.test_correlation_indexer import index_rows, keys_of, member_client
from tests.integration.test_disk_sensitivity import disk_segments, seed_disk_results

API = "/api/v1/orgs"


async def _static_sample(t: Tenant, case_id: uuid.UUID, sha256: str) -> uuid.UUID:
    """A succeeded static job of the case whose sample has `sha256`, indexed."""
    evidence_id = await seed_evidence(t, case_id, filename="invoice.exe")
    job_id = await seed_job_on(t, evidence_id, "static")
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            MalwareSample(
                organization_id=t.org_id,
                job_id=job_id,
                size=4096,
                md5=uuid.uuid4().hex,
                sha1=uuid.uuid4().hex + "00000000",
                sha256=sha256,
                entropy=6.4,
                file_format="pe",
            )
        )
    await index_rows(t, (job_id,), analyzer=Analyzer.STATIC)
    assert await indexer.index_job(t.org_id, job_id)
    return job_id


async def test_a_disk_hash_correlates_with_a_static_sample_in_the_org_only() -> None:
    a = await seed_tenant(f"diskcorr-a-{uuid.uuid4().hex[:6]}")
    b = await seed_tenant(f"diskcorr-b-{uuid.uuid4().hex[:6]}")
    disk_case = await seed_case(a, title="Disk case")
    malware_case = await seed_case(a, title="Malware case")
    other_org_case = await seed_case(b, title="Other org case")
    sha256 = uuid.uuid4().hex + uuid.uuid4().hex

    ta = Tenant(a.org_id, a.owner_id, disk_case)
    segments = await disk_segments(ta, 2)  # restricted: correlation is still allowed
    disk_job = await seed_disk_job(ta, segments)
    await seed_disk_results(ta, disk_job, iocs=[("file_sha256", sha256), ("ip", "198.51.100.23")])
    await index_rows(a, (disk_job,), analyzer=Analyzer.DISK)
    assert await indexer.index_job(a.org_id, disk_job)
    assert any(k.value_norm == sha256 for k in await keys_of(a, disk_job))

    static_job = await _static_sample(a, malware_case, sha256)
    await _static_sample(b, other_org_case, sha256)  # another org: never counted

    c = await member_client(a.org_id)
    pivot = await c.get(f"{API}/{a.org_id}/analyses/{static_job}/correlations")
    assert pivot.status_code == 200, pivot.text
    [item] = [i for i in pivot.json()["items"] if i["kind"] == "sha256"]
    assert (item["other_jobs"], item["other_cases"]) == (1, 1)
    assert [case["investigation_id"] for case in item["top_cases"]] == [str(disk_case)]

    back = await c.get(f"{API}/{a.org_id}/analyses/{disk_job}/correlations")
    assert back.status_code == 200, back.text
    [item] = [i for i in back.json()["items"] if i["kind"] == "sha256"]
    assert (item["other_jobs"], item["other_cases"]) == (1, 1)
    assert [case["investigation_id"] for case in item["top_cases"]] == [str(malware_case)]

    found = await c.post(
        f"{API}/{a.org_id}/correlations/lookup",
        json={"kind": "sha256", "value": sha256},
        headers=csrf(c),
    )
    assert found.status_code == 200, found.text
    body = found.json()
    assert (body["jobs"], body["cases"]) == (2, 2)
    by_job = {o["job_id"]: o for o in body["items"]}
    assert set(by_job) == {str(disk_job), str(static_job)}
    assert by_job[str(disk_job)]["analyzer"] == "disk"
    assert by_job[str(disk_job)]["evidence_id"] == str(segments[0])
    assert by_job[str(static_job)]["analyzer"] == "static"


async def test_a_disk_jobs_keys_never_read_another_org() -> None:
    a = await seed_tenant(f"diskcorr-c-{uuid.uuid4().hex[:6]}")
    b = await seed_tenant(f"diskcorr-d-{uuid.uuid4().hex[:6]}")
    sha256 = uuid.uuid4().hex + uuid.uuid4().hex
    jobs = {}
    for t in (a, b):
        segments = await disk_segments(t, 1)
        job = await seed_disk_job(t, segments)
        await seed_disk_results(t, job, iocs=[("file_sha256", sha256)])
        await index_rows(t, (job,), analyzer=Analyzer.DISK)
        assert await indexer.index_job(t.org_id, job)
        jobs[t.org_id] = job
    c = await member_client(a.org_id)
    pivot = await c.get(f"{API}/{a.org_id}/analyses/{jobs[a.org_id]}/correlations")
    assert pivot.status_code == 200, pivot.text
    assert [i for i in pivot.json()["items"] if i["kind"] == "sha256" and i["other_jobs"]] == []
    async with tenant_session(a.org_id, None) as s:
        orgs = await s.execute(
            text("SELECT DISTINCT organization_id FROM correlation_keys WHERE value_norm = :v"),
            {"v": sha256},
        )
        assert [r[0] for r in orgs] == [a.org_id]
