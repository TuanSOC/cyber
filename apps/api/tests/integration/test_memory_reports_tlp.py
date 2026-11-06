"""Reports and restricted memory evidence (M8 phase 8, RT10).

Below TLP:RED the snapshot leaves out every row derived from the jobs of restricted memory
evidence (findings, IOCs seen only there, timeline entries, citations of their rows, the job
row's summary) and counts them in the additive `omissions.memory_restricted`; IOCs shared
with other evidence stay, re-aggregated without the restricted sightings. At TLP:RED, after a
release, or without memory evidence, nothing is left out and `omissions` is absent from the
canonical bytes (so reports without memory evidence keep their M6 bytes).
"""

import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cyberlab_jobs.memory import OsHint
from cyberlab_jobs.report import ReportSnapshot, canonical_json
from sqlalchemy import update

from app.core.tenancy import tenant_session
from app.modules.ai import postprocess
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer, JobProfile
from app.modules.memory_analysis.models import MemorySensitivity
from app.modules.reports.models import Report
from app.modules.reports.snapshot import BuiltSnapshot, build_snapshot
from tests.case_helpers import seed_evidence
from tests.integration.seed import Tenant, seed_tenant
from tests.integration.test_memory_sensitivity import (
    MASKED_TITLE,
    memory_evidence,
    seed_memory_results,
)
from tests.report_helpers import seed_report

SHARED_IP = "198.51.100.7"
MEMORY_ONLY = "c2-mem.example.org"
PCAP_ONLY = "cdn-pcap.example.net"
TOOLS = {"tool_versions": {"volatility3": "2.28.2"}}


async def _job(t: Tenant, evidence_id: uuid.UUID, analyzer: Analyzer) -> uuid.UUID:
    profile = {Analyzer.MEMORY: JobProfile.TRIAGE, Analyzer.STATIC: JobProfile.FULL}.get(analyzer)
    async with tenant_session(t.org_id, t.owner_id) as s:
        job = AnalysisJob(
            organization_id=t.org_id,
            evidence_id=evidence_id,
            analyzer=analyzer,
            profile=profile,
            os_hint=OsHint.AUTO if analyzer == Analyzer.MEMORY else None,
            status=AnalysisStatus.SUCCEEDED,
            requested_by=t.owner_id,
            ingest_token_sha256=secrets.token_hex(32),
            finished_at=datetime.now(UTC),
            summary=TOOLS,
        )
        s.add(job)
    return job.id


@dataclass(frozen=True)
class World:
    t: Tenant
    memory_evidence: uuid.UUID
    pcap_job: uuid.UUID
    memory_job: uuid.UUID
    static_job: uuid.UUID  # a static job on the memory image: memory-derived too
    memory_finding: uuid.UUID


async def _world(name: str) -> World:
    t = await seed_tenant(f"{name}-{secrets.token_hex(3)}")
    pcap_evidence = await seed_evidence(t, filename="capture.pcap")
    pcap_job = await _job(t, pcap_evidence, Analyzer.PCAP)
    await seed_memory_results(
        t,
        pcap_job,
        findings=[("high", "Beaconing to a rare host")],
        iocs=[("ip", SHARED_IP), ("domain", PCAP_ONLY)],
    )
    image = await memory_evidence(t)
    memory_job = await _job(t, image, Analyzer.MEMORY)
    [memory_finding] = await seed_memory_results(
        t, memory_job, iocs=[("ip", SHARED_IP), ("domain", MEMORY_ONLY)]
    )
    static_job = await _job(t, image, Analyzer.STATIC)
    await seed_memory_results(t, static_job, findings=[("medium", "Packed section")], iocs=[])
    return World(t, image, pcap_job, memory_job, static_job, memory_finding)


async def _report(w: World, tlp: str) -> uuid.UUID:
    draft: dict[str, Any] = {
        "include": {
            "jobs": [str(w.pcap_job), str(w.memory_job), str(w.static_job)],
            "cited_rows": [{"kind": "finding", "ref_id": str(w.memory_finding)}],
        }
    }
    return await seed_report(w.t, tlp=tlp, draft=draft)


async def _build(t: Tenant, report_id: uuid.UUID) -> BuiltSnapshot:
    async with tenant_session(t.org_id, t.owner_id, snapshot_read=True) as s:
        report = await s.get(Report, report_id)
        assert report is not None
        return await build_snapshot(s, t.org_id, t.owner_id, report, now=datetime.now(UTC))


def _ioc(snap: ReportSnapshot, value: str) -> Any:
    # Evidence-derived values are defanged in the snapshot (RT24).
    found = [i for i in snap.iocs.items if i.value == postprocess.defang_all(value)]
    return found[0] if found else None


def _text(snap: ReportSnapshot) -> str:
    return canonical_json(snap).decode("utf-8")


async def test_amber_leaves_restricted_memory_rows_out_and_counts_them() -> None:
    w = await _world("amber")
    snap = (await _build(w.t, await _report(w, "amber"))).snapshot

    # Jobs stay listed; the restricted ones without their summary (tool versions).
    jobs = {j.job_id: j for j in snap.jobs.items}
    assert set(jobs) == {w.pcap_job, w.memory_job, w.static_job}
    assert jobs[w.pcap_job].tool_versions == {"volatility3": "2.28.2"}
    assert jobs[w.memory_job].tool_versions == {} and jobs[w.static_job].tool_versions == {}
    # Findings: only the pcap one (the memory and the static-on-image findings are omitted).
    assert [f.job_id for f in snap.findings.items] == [w.pcap_job]
    assert snap.findings.total == 1
    # IOCs: the memory-only value is gone; the shared IP stays with the pcap sighting only.
    assert _ioc(snap, MEMORY_ONLY) is None and _ioc(snap, PCAP_ONLY) is not None
    shared = _ioc(snap, SHARED_IP)
    assert shared is not None
    assert (shared.count_jobs, shared.job_ids) == (1, [w.pcap_job])
    assert snap.iocs.total == 2
    # Timeline: the static finding of the image is not an entry; job entries stay.
    timeline = [(e.ref_kind, e.job_id) for e in snap.timeline.items]
    assert ("finding", w.static_job) not in timeline
    assert any(kind == "job" and job == w.memory_job for kind, job in timeline)
    # The analyst-cited memory finding is withheld, not "out of scope".
    assert all(c.ref_id != str(w.memory_finding) for c in snap.citations.items)
    assert snap.citations.dropped_out_of_scope == 0
    # 2 job summaries + 2 findings + 1 IOC + 1 timeline entry + 1 citation.
    assert snap.omissions is not None and snap.omissions.memory_restricted == 7
    body = _text(snap)
    assert '"omissions":{"memory_restricted":7}' in body
    for hidden in (MEMORY_ONLY, MASKED_TITLE):
        assert postprocess.defang_all(hidden) not in body


async def test_red_includes_everything_and_has_no_omissions() -> None:
    w = await _world("red")
    snap = (await _build(w.t, await _report(w, "red"))).snapshot
    assert {f.job_id for f in snap.findings.items} == {w.pcap_job, w.memory_job, w.static_job}
    shared = _ioc(snap, SHARED_IP)
    assert shared is not None and shared.count_jobs == 2
    assert _ioc(snap, MEMORY_ONLY) is not None
    jobs = {j.job_id: j for j in snap.jobs.items}
    assert jobs[w.memory_job].tool_versions == {"volatility3": "2.28.2"}
    assert any(c.ref_id == str(w.memory_finding) for c in snap.citations.items)
    assert snap.omissions is None
    assert '"omissions"' not in _text(snap)


async def test_released_evidence_is_included_below_red() -> None:
    w = await _world("released")
    async with tenant_session(w.t.org_id, w.t.owner_id) as s:
        await s.execute(
            update(MemorySensitivity)
            .where(MemorySensitivity.evidence_id == w.memory_evidence)
            .values(
                state="released",
                released_by=w.t.owner_id,
                released_at=datetime.now(UTC),
                release_reason="Approved for the customer report",
            )
        )
    snap = (await _build(w.t, await _report(w, "amber"))).snapshot
    assert snap.omissions is None
    assert {f.job_id for f in snap.findings.items} == {w.pcap_job, w.memory_job, w.static_job}
    assert _ioc(snap, MEMORY_ONLY) is not None


async def test_a_report_without_memory_evidence_has_no_omissions_key() -> None:
    t = await seed_tenant(f"plain-{secrets.token_hex(3)}")
    job = await _job(t, await seed_evidence(t), Analyzer.PCAP)
    await seed_memory_results(t, job, findings=[("high", "Port scan")], iocs=[("ip", SHARED_IP)])
    report_id = await seed_report(t, tlp="amber", draft={})
    snap = (await _build(t, report_id)).snapshot
    assert snap.omissions is None
    assert [f.job_id for f in snap.findings.items] == [job]
    assert '"omissions"' not in _text(snap)
