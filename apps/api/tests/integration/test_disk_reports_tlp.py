"""Reports and restricted disk evidence (M9 phase 9, RT23).

Below TLP:RED the snapshot leaves out every row derived from a disk job with **any**
restricted segment, and from a static job on restricted derived evidence: findings, IOCs seen
only there, timeline entries, citations of their rows and the job row's summary. They are
counted in `omissions.disk_restricted`; memory items keep their own count
(`omissions.memory_restricted`, an IOC seen in both a memory and a disk job counting as
memory). At TLP:RED or after the release nothing is left out and `omissions` is absent; a
report with memory omissions only keeps M8's bytes (no `disk_restricted` key).
"""

import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cyberlab_jobs.report import ReportSnapshot, canonical_json
from sqlalchemy import update

from app.core.tenancy import tenant_session
from app.modules.ai import postprocess
from app.modules.analysis.models import Analyzer
from app.modules.memory_analysis.models import MemorySensitivity
from tests.case_helpers import seed_evidence
from tests.disk_helpers import seed_disk_job
from tests.integration.seed import Tenant, seed_tenant
from tests.integration.test_disk_sensitivity import (
    MASKED_TITLE,
    derived_evidence,
    disk_segments,
    seed_disk_results,
)
from tests.integration.test_memory_reports_tlp import _build, _ioc, _job
from tests.integration.test_memory_reports_tlp import _world as memory_world
from tests.integration.test_memory_sensitivity import memory_evidence, seed_memory_results
from tests.report_helpers import seed_report

SHARED_IP = "198.51.100.7"
PCAP_ONLY = "cdn-pcap.example.net"
DISK_ONLY = "c2-disk.example.org"
MEMORY_ONLY = "c2-mem.example.org"
BOTH_RESTRICTED = "staging.example.org"  # seen in the memory and the disk job only
SAMPLE_SHA256 = "ab" * 32
WITHHELD_KINDS = {"timeline", "finding", "alert"}


@dataclass(frozen=True)
class World:
    t: Tenant
    segments: list[uuid.UUID]
    derived: uuid.UUID
    memory_image: uuid.UUID | None
    pcap_job: uuid.UUID
    disk_job: uuid.UUID
    derived_job: uuid.UUID  # a static job on derived evidence: disk-derived too
    memory_job: uuid.UUID | None
    disk_finding: uuid.UUID

    @property
    def disk_jobs(self) -> set[uuid.UUID]:
        return {self.disk_job, self.derived_job}

    @property
    def jobs(self) -> list[uuid.UUID]:
        out = [self.pcap_job, self.disk_job, self.derived_job]
        return out + ([self.memory_job] if self.memory_job else [])


async def _release_db(t: Tenant, evidence_id: uuid.UUID) -> None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            update(MemorySensitivity)
            .where(MemorySensitivity.evidence_id == evidence_id)
            .values(
                state="released",
                released_by=t.owner_id,
                released_at=datetime.now(UTC),
                release_reason="Approved for the customer report",
            )
        )


async def _world(name: str, *, memory: bool = True) -> World:
    t = await seed_tenant(f"{name}-{secrets.token_hex(3)}")
    pcap_job = await _job(t, await seed_evidence(t, filename="capture.pcap"), Analyzer.PCAP)
    await seed_memory_results(
        t,
        pcap_job,
        findings=[("high", "Beaconing to a rare host")],
        iocs=[("ip", SHARED_IP), ("domain", PCAP_ONLY)],
    )
    # Two segments; the first released: one restricted segment withholds the whole job.
    segments = await disk_segments(t, 2)
    await _release_db(t, segments[0])
    disk_job = await seed_disk_job(t, segments, fixture=None)
    disk_iocs = [("ip", SHARED_IP), ("domain", DISK_ONLY)]
    if memory:
        disk_iocs.append(("domain", BOTH_RESTRICTED))
    [disk_finding] = await seed_disk_results(t, disk_job, iocs=disk_iocs)
    derived = await derived_evidence(t)
    derived_job = await _job(t, derived, Analyzer.STATIC)
    await seed_disk_results(
        t,
        derived_job,
        findings=[("medium", "Packed section")],
        iocs=[("file_sha256", SAMPLE_SHA256)],
    )
    image = memory_job = None
    if memory:
        image = await memory_evidence(t)
        memory_job = await _job(t, image, Analyzer.MEMORY)
        await seed_memory_results(
            t, memory_job, iocs=[("domain", MEMORY_ONLY), ("domain", BOTH_RESTRICTED)]
        )
    return World(
        t, segments, derived, image, pcap_job, disk_job, derived_job, memory_job, disk_finding
    )


async def _report(w: World, tlp: str) -> uuid.UUID:
    draft: dict[str, Any] = {
        "include": {
            "jobs": [str(j) for j in w.jobs],
            "cited_rows": [{"kind": "finding", "ref_id": str(w.disk_finding)}],
        }
    }
    return await seed_report(w.t, tlp=tlp, draft=draft)


def _expected(
    red: ReportSnapshot, withheld: set[uuid.UUID], disk_jobs: set[uuid.UUID], which: str
) -> int:
    """What the guard must leave out as `which` ("disk" or "memory"), read off the TLP:RED
    snapshot of the same draft (no citation counted)."""
    jobs_of = disk_jobs if which == "disk" else withheld - disk_jobs
    jobs = sum(1 for j in red.jobs.items if j.job_id in jobs_of)
    findings = sum(1 for f in red.findings.items if f.job_id in jobs_of)
    timeline = sum(
        1 for e in red.timeline.items if e.job_id in jobs_of and e.ref_kind in WITHHELD_KINDS
    )
    # An IOC seen only in withheld jobs counts as disk when all of them are disk jobs.
    only_withheld = [set(i.job_ids) for i in red.iocs.items if set(i.job_ids) <= withheld]
    as_disk = sum(1 for seen in only_withheld if seen <= disk_jobs)
    iocs = as_disk if which == "disk" else len(only_withheld) - as_disk
    return jobs + findings + timeline + iocs


def _text(snap: ReportSnapshot) -> str:
    return canonical_json(snap).decode("utf-8")


async def test_amber_leaves_restricted_disk_rows_out_and_counts_them_apart() -> None:
    w = await _world("disk-amber")
    red = (await _build(w.t, await _report(w, "red"))).snapshot
    snap = (await _build(w.t, await _report(w, "amber"))).snapshot

    # Jobs stay listed, the withheld ones without their summary.
    assert {j.job_id for j in snap.jobs.items} == set(w.jobs)
    # Findings: only the pcap one.
    assert [f.job_id for f in snap.findings.items] == [w.pcap_job]
    # IOCs: disk-only, derived-only, memory-only and memory+disk values are gone; the shared
    # IP stays with the pcap sighting only.
    for gone in (DISK_ONLY, SAMPLE_SHA256, MEMORY_ONLY, BOTH_RESTRICTED):
        assert _ioc(snap, gone) is None, gone
        assert _ioc(red, gone) is not None, gone
    shared = _ioc(snap, SHARED_IP)
    assert shared is not None and (shared.count_jobs, shared.job_ids) == (1, [w.pcap_job])
    timeline = [(e.ref_kind, e.job_id) for e in snap.timeline.items]
    assert not any(job in w.disk_jobs and kind in WITHHELD_KINDS for kind, job in timeline)
    # The analyst-cited disk finding is withheld, not "out of scope".
    assert all(c.ref_id != str(w.disk_finding) for c in snap.citations.items)
    assert snap.citations.dropped_out_of_scope == 0

    assert w.memory_job is not None
    withheld = {*w.disk_jobs, w.memory_job}
    assert snap.omissions is not None
    assert snap.omissions.disk_restricted == _expected(red, withheld, w.disk_jobs, "disk") + 1
    assert snap.omissions.memory_restricted == _expected(red, withheld, w.disk_jobs, "memory")
    body = _text(snap)
    data = json.loads(body)["omissions"]
    assert data == {
        "disk_restricted": snap.omissions.disk_restricted,
        "memory_restricted": snap.omissions.memory_restricted,
    }
    for hidden in (DISK_ONLY, MASKED_TITLE, "Packed section"):
        assert postprocess.defang_all(hidden) not in body


async def test_disk_omissions_alone_still_carry_a_zero_memory_count() -> None:
    w = await _world("disk-only", memory=False)
    red = (await _build(w.t, await _report(w, "red"))).snapshot
    snap = (await _build(w.t, await _report(w, "amber"))).snapshot
    assert snap.omissions is not None
    assert snap.omissions.memory_restricted == 0
    expected = _expected(red, w.disk_jobs, w.disk_jobs, "disk") + 1
    assert snap.omissions.disk_restricted == expected
    assert f'"omissions":{{"disk_restricted":{expected},"memory_restricted":0}}' in _text(snap)


async def test_red_includes_everything_and_has_no_omissions() -> None:
    w = await _world("disk-red")
    snap = (await _build(w.t, await _report(w, "red"))).snapshot
    assert {f.job_id for f in snap.findings.items} == set(w.jobs)
    assert _ioc(snap, DISK_ONLY) is not None and _ioc(snap, SAMPLE_SHA256) is not None
    assert any(c.ref_id == str(w.disk_finding) for c in snap.citations.items)
    assert snap.omissions is None
    assert '"omissions"' not in _text(snap)


async def test_released_disk_evidence_is_included_below_red() -> None:
    w = await _world("disk-released", memory=False)
    for evidence_id in (w.segments[1], w.derived):
        await _release_db(w.t, evidence_id)
    snap = (await _build(w.t, await _report(w, "amber"))).snapshot
    assert snap.omissions is None
    assert {f.job_id for f in snap.findings.items} == set(w.jobs)
    assert _ioc(snap, DISK_ONLY) is not None
    assert '"omissions"' not in _text(snap)


async def test_one_restricted_segment_withholds_the_disk_job() -> None:
    w = await _world("disk-segment", memory=False)
    await _release_db(w.t, w.derived)  # only the disk job's second segment stays restricted
    snap = (await _build(w.t, await _report(w, "amber"))).snapshot
    assert {f.job_id for f in snap.findings.items} == {w.pcap_job, w.derived_job}
    assert snap.omissions is not None and (snap.omissions.disk_restricted or 0) > 0


async def test_memory_omissions_keep_their_m8_bytes() -> None:
    """A report with memory omissions only: no `disk_restricted` key (RT23)."""
    w = await memory_world("disk-m8-bytes")
    draft = {"include": {"jobs": [str(w.pcap_job), str(w.memory_job), str(w.static_job)]}}
    snap = (await _build(w.t, await seed_report(w.t, tlp="amber", draft=draft))).snapshot
    assert snap.omissions is not None and snap.omissions.memory_restricted > 0
    assert snap.omissions.disk_restricted is None
    body = _text(snap)
    assert f'"omissions":{{"memory_restricted":{snap.omissions.memory_restricted}}}' in body
    assert "disk_restricted" not in body
