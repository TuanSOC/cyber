"""M9 test helpers (phase 1, FROZEN): disk jobs, segment sets and restricted disk evidence.

- `disk_fixture(name)`: the validated lines of a `disk.v1` fixture of
  `packages/py-jobs/tests/fixtures/disk/` (hand-written, labelled synthetic);
- `seed_segment_set(t, n)`: `n` evidence items of one investigation (the segments of a set);
- `seed_disk_job(t, ...)`: a disk job (profile and OS hint set, as the 0017 checks require),
  its `analysis_job_segments` and, for a succeeded job, its `disk_*` rows from the fixture
  (written here with the ORM, not by the phase-7 ingest; findings, IOCs and the timeline are
  not seeded);
- `restricted_disk_evidence(t, source=...)`: evidence marked `restricted` (source `disk` or
  `derived`) with its share-policy flags set (what `apply_restricted_default` writes;
  inserted directly here).
"""

import secrets
import uuid
from pathlib import Path
from typing import Any, Literal

import cyberlab_jobs
from cyberlab_jobs.disk import (
    DISK_LINE_ADAPTER,
    DiskEventRecord,
    DiskFileRecord,
    DiskPartitionRecord,
    DiskResultHeader,
    OsHint,
)
from pydantic import BaseModel

from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer, JobProfile
from app.modules.disk_forensics.models import (
    AnalysisJobSegment,
    DiskEvent,
    DiskFile,
    DiskImage,
    DiskPartition,
)
from app.modules.investigations.models import EvidenceSharePolicy
from app.modules.memory_analysis.models import MemorySensitivity
from tests.case_helpers import seed_evidence
from tests.integration.seed import Tenant

FIXTURES = Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures" / "disk"


def disk_fixture(name: str = "windows_triage.ndjson") -> list[BaseModel]:
    return [
        DISK_LINE_ADAPTER.validate_json(line)
        for line in (FIXTURES / name).read_bytes().splitlines()
    ]


def _image(org_id: uuid.UUID, job_id: uuid.UUID, header: DiskResultHeader) -> DiskImage:
    image = header.image
    ewf = image.ewf
    return DiskImage(
        job_id=job_id,
        organization_id=org_id,
        format=image.format.value,
        segments=image.segments,
        media_size=image.media_size,
        sector_size=image.sector_size,
        media_sha256=image.media_sha256,
        ewf_md5=ewf.stored_md5 if ewf else None,
        ewf_sha1=ewf.stored_sha1 if ewf else None,
        media_hash_status=ewf.media_hash_status if ewf else None,
        ewf_meta=dict(ewf.meta) if ewf else {},
        stages=[s.model_dump(mode="json") for s in header.stages],
        counts={},
        tool_versions=dict(header.tool_versions),
        hashsets=[h.model_dump(mode="json") for h in header.hashsets],
        engine=header.engine,
        timeline_engine=header.timeline_engine,
        truncated=any(header.truncated.values()),
    )


def _rows(org_id: uuid.UUID, job_id: uuid.UUID, lines: list[BaseModel]) -> list[Any]:
    header = lines[0]
    assert isinstance(header, DiskResultHeader)
    rows: list[Any] = [_image(org_id, job_id, header)]
    common = {"organization_id": org_id, "job_id": job_id}
    for line in lines[1:]:
        if isinstance(line, DiskPartitionRecord):
            data = line.model_dump(exclude={"kind"})
            data["fs_type"] = line.fs_type.value if line.fs_type else None
            rows.append(DiskPartition(**common, **data))
        elif isinstance(line, DiskFileRecord):
            rows.append(DiskFile(**common, **line.model_dump(exclude={"kind"})))
        elif isinstance(line, DiskEventRecord):
            data = line.model_dump(exclude={"kind", "file"})
            data["artifact"] = line.artifact.value
            rows.append(DiskEvent(**common, **data, file_id=None))
    return rows


async def seed_segment_set(t: Tenant, n: int = 2, *, stem: str = "image") -> list[uuid.UUID]:
    """`n` evidence items of the tenant's investigation, named `<stem>.E01`, `.E02`…"""
    return [await seed_evidence(t, filename=f"{stem}.E{i + 1:02d}") for i in range(n)]


async def seed_disk_job(
    t: Tenant,
    segments: list[uuid.UUID] | None = None,
    *,
    status: str = "succeeded",
    profile: Literal["triage", "full", "extract"] = "triage",
    os_hint: str = "auto",
    fixture: str | None = "windows_triage.ndjson",
) -> uuid.UUID:
    """A disk job over `segments` (one new evidence by default; segment 0 is the job's
    evidence); a succeeded one with `fixture` also gets its `disk_*` rows."""
    if segments is None:
        segments = await seed_segment_set(t, 1)
    async with tenant_session(t.org_id, t.owner_id) as s:
        job = AnalysisJob(
            organization_id=t.org_id,
            evidence_id=segments[0],
            analyzer=Analyzer.DISK,
            profile=JobProfile(profile),
            os_hint=OsHint(os_hint),
            status=AnalysisStatus(status),
            requested_by=t.owner_id,
            ingest_token_sha256=secrets.token_hex(32),
        )
        s.add(job)
        await s.flush()
        s.add_all(
            AnalysisJobSegment(
                job_id=job.id, ordinal=i, organization_id=t.org_id, evidence_id=evidence_id
            )
            for i, evidence_id in enumerate(segments)
        )
        if fixture is not None and status == "succeeded" and profile != "extract":
            s.add_all(_rows(t.org_id, job.id, disk_fixture(fixture)))
    return job.id


async def restricted_disk_evidence(
    t: Tenant,
    evidence_id: uuid.UUID | None = None,
    *,
    source: Literal["disk", "derived"] = "disk",
) -> uuid.UUID:
    """Evidence marked restricted (source `disk` or `derived`), AI and TI excluded."""
    if evidence_id is None:
        evidence_id = await seed_evidence(t, filename="disk.E01" if source == "disk" else "x.exe")
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            MemorySensitivity(
                evidence_id=evidence_id,
                organization_id=t.org_id,
                defaulted_by=t.owner_id,
                source=source,
            )
        )
        policy = await s.get(EvidenceSharePolicy, evidence_id)
        if policy is None:
            s.add(
                EvidenceSharePolicy(
                    evidence_id=evidence_id,
                    organization_id=t.org_id,
                    ai_excluded=True,
                    ti_excluded=True,
                    updated_by=t.owner_id,
                )
            )
        else:
            policy.ai_excluded = policy.ti_excluded = True
            policy.updated_by = t.owner_id
    return evidence_id
