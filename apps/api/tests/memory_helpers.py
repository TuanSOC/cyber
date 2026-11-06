"""M8 test helpers (phase 1, FROZEN): memory jobs and restricted memory evidence.

- `memory_fixture(name)`: the validated lines of a `memory.v1` fixture of
  `packages/py-jobs/tests/fixtures/memory/` (hand-written, labelled synthetic);
- `seed_memory_job(t, ...)`: a memory job (profile and OS hint set, as the 0016 checks
  require) and, for a succeeded job, its `memory_*` rows from the fixture (written here with the
  ORM, not by the phase-6 ingest; findings, IOCs and the timeline are not seeded);
- `restricted_memory_evidence(t)`: evidence marked `restricted` with its share-policy flags set
  (what phase 8's `apply_memory_default` writes; inserted directly here).
"""

import secrets
import uuid
from pathlib import Path
from typing import Any

import cyberlab_jobs
from cyberlab_jobs.memory import (
    MEMORY_LINE_ADAPTER,
    MemoryArtifactRecord,
    MemoryConnectionRecord,
    MemoryImageRecord,
    MemoryInjectionRecord,
    MemoryProcessRecord,
    MemoryResultHeader,
    OsHint,
)
from pydantic import BaseModel

from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer, JobProfile
from app.modules.investigations.models import EvidenceSharePolicy
from app.modules.memory_analysis.models import (
    SOURCE_BITS,
    MemoryArtifact,
    MemoryConnection,
    MemoryImage,
    MemoryInjection,
    MemoryProcess,
    MemorySensitivity,
)
from tests.case_helpers import seed_evidence
from tests.integration.seed import Tenant

FIXTURES = Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures" / "memory"


def memory_fixture(name: str = "windows_triage.ndjson") -> list[BaseModel]:
    return [
        MEMORY_LINE_ADAPTER.validate_json(line)
        for line in (FIXTURES / name).read_bytes().splitlines()
    ]


def _str(value: Any) -> str | None:
    return None if value is None else str(value)


def _rows(org_id: uuid.UUID, job_id: uuid.UUID, lines: list[BaseModel]) -> list[Any]:
    header = lines[0]
    assert isinstance(header, MemoryResultHeader)
    rows: list[Any] = []
    for line in lines[1:]:
        common = {"organization_id": org_id, "job_id": job_id}
        if isinstance(line, MemoryImageRecord):
            rows.append(
                MemoryImage(
                    **common,
                    os=header.os,
                    arch=line.arch,
                    layer=line.layer,
                    engine=header.engine,
                    nt_build=line.nt_build,
                    kernel_banner=line.kernel_banner,
                    pdb_name=line.pdb.name if line.pdb else None,
                    pdb_guid=line.pdb.guid if line.pdb else None,
                    pdb_age=line.pdb.age if line.pdb else None,
                    system_time=line.system_time,
                    symbols_status=header.symbols.status,
                    isf_sha256=header.symbols.isf_sha256,
                    volatility_version=header.tool_versions.get("volatility3"),
                    plugins=[p.model_dump(mode="json") for p in header.plugins],
                    counts={},
                )
            )
        elif isinstance(line, MemoryProcessRecord):
            data = line.model_dump(exclude={"kind", "sources"})
            rows.append(
                MemoryProcess(
                    **common, **data, sources=sum(SOURCE_BITS[s] for s in line.sources)
                )
            )
        elif isinstance(line, MemoryConnectionRecord):
            data = line.model_dump(exclude={"kind", "local_addr", "remote_addr"})
            rows.append(
                MemoryConnection(
                    **common,
                    **data,
                    local_addr=_str(line.local_addr),
                    remote_addr=_str(line.remote_addr),
                )
            )
        elif isinstance(line, MemoryInjectionRecord):
            rows.append(MemoryInjection(**common, **line.model_dump(exclude={"kind"})))
        elif isinstance(line, MemoryArtifactRecord):
            rows.append(MemoryArtifact(**common, **line.model_dump(exclude={"kind"})))
    return rows


async def seed_memory_job(
    t: Tenant,
    evidence_id: uuid.UUID | None = None,
    *,
    status: str = "succeeded",
    profile: str = "triage",
    os_hint: str = "auto",
    fixture: str | None = "windows_triage.ndjson",
) -> uuid.UUID:
    """A memory job; a succeeded one with `fixture` also gets its `memory_*` rows."""
    if evidence_id is None:
        evidence_id = await seed_evidence(t, filename="memory.raw")
    async with tenant_session(t.org_id, t.owner_id) as s:
        job = AnalysisJob(
            organization_id=t.org_id,
            evidence_id=evidence_id,
            analyzer=Analyzer.MEMORY,
            profile=JobProfile(profile),
            os_hint=OsHint(os_hint),
            status=AnalysisStatus(status),
            requested_by=t.owner_id,
            ingest_token_sha256=secrets.token_hex(32),
        )
        s.add(job)
        await s.flush()
        if fixture is not None and status == "succeeded":
            s.add_all(_rows(t.org_id, job.id, memory_fixture(fixture)))
    return job.id


async def restricted_memory_evidence(
    t: Tenant, evidence_id: uuid.UUID | None = None
) -> uuid.UUID:
    """Evidence marked as a restricted memory image, AI and TI excluded."""
    if evidence_id is None:
        evidence_id = await seed_evidence(t, filename="memory.raw")
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            MemorySensitivity(
                evidence_id=evidence_id, organization_id=t.org_id, defaulted_by=t.owner_id
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
