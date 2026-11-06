"""M10 test helpers (phase 1, FROZEN): RE jobs, their source static job and capa locations.

- `re_fixture(name)`: the validated lines of an `re.v1` fixture of
  `packages/py-jobs/tests/fixtures/reverse/` (hand-written, labelled synthetic);
- `seed_static_source_job(t, evidence_id=None, ...)`: a succeeded static `full` job with its
  `malware_samples` row (PE / ELF, `capa_base_address`) and capabilities carrying `locations`
  (decimal strings, as 0018 stores them);
- `seed_re_job(t, source_job_id=None, ...)`: an RE job (profile, `source_job_id`, `re_params`
  set, as the 0018 checks require) and, for a succeeded job, its `re_*` rows from the fixture
  (written here with the ORM, not by the phase-7 ingest; findings, IOCs and the capability
  links are not seeded).
"""

import secrets
import uuid
from pathlib import Path
from typing import Any, Literal

import cyberlab_jobs
from cyberlab_jobs.reverse import (
    RE_LINE_ADAPTER,
    ReCallEdgeRecord,
    ReDecompiledRecord,
    ReFunctionRecord,
    ReImportRecord,
    ReImportRefRecord,
    ReProgramRecord,
    ReResultHeader,
    ReStringRecord,
    ReStringRefRecord,
)
from pydantic import BaseModel

from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer, JobProfile
from app.modules.reverse_engineering.models import (
    ReCallEdge,
    ReDecompilation,
    ReFunction,
    ReImport,
    ReImportRef,
    ReProgram,
    ReString,
    ReStringRef,
)
from app.modules.static_analysis.models import MalwareCapability, MalwareSample
from tests.case_helpers import seed_evidence
from tests.integration.seed import Tenant

FIXTURES = Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures" / "reverse"
# The pe_full fixture's capabilities (file VAs inside inject_remote / resolve_apis / beacon).
DEFAULT_CAPABILITIES: tuple[tuple[str, str, list[int]], ...] = (
    ("inject thread", "host-interaction/process/inject", [0x140001280, 0x1400012A0]),
    ("link function at runtime on Windows", "linking/runtime-linking", [0x140001400]),
    ("connect to URL", "communication/http/client", []),
)


def re_fixture(name: str = "pe_full.ndjson") -> list[BaseModel]:
    return [
        RE_LINE_ADAPTER.validate_json(line)
        for line in (FIXTURES / name).read_bytes().splitlines()
    ]


async def seed_static_source_job(
    t: Tenant,
    evidence_id: uuid.UUID | None = None,
    *,
    file_format: Literal["pe", "elf", "other"] = "pe",
    capa_base_address: int | None = 0x140000000,
    capabilities: tuple[tuple[str, str, list[int]], ...] = DEFAULT_CAPABILITIES,
    status: str = "succeeded",
) -> uuid.UUID:
    """A static `full` job (the source of an RE job) with its sample row and capabilities."""
    if evidence_id is None:
        evidence_id = await seed_evidence(t, filename="sample.exe")
    async with tenant_session(t.org_id, t.owner_id) as s:
        job = AnalysisJob(
            organization_id=t.org_id,
            evidence_id=evidence_id,
            analyzer=Analyzer.STATIC,
            profile=JobProfile.FULL,
            status=AnalysisStatus(status),
            requested_by=t.owner_id,
            ingest_token_sha256=secrets.token_hex(32),
        )
        s.add(job)
        await s.flush()
        if status == "succeeded":
            common = {"organization_id": t.org_id, "job_id": job.id}
            s.add(
                MalwareSample(
                    **common,
                    size=1024,
                    md5="0" * 32,
                    sha1="0" * 40,
                    sha256="e" * 64,
                    entropy=5.5,
                    file_format=file_format,
                    pe={"image_base": 0x140000000} if file_format == "pe" else None,
                    elf=None,
                    capa_base_address=capa_base_address,
                )
            )
            s.add_all(
                MalwareCapability(
                    **common,
                    name=name,
                    namespace=namespace,
                    attack=[],
                    mbc=[],
                    matches=max(1, len(locations)),
                    locations=[str(a) for a in locations],
                )
                for name, namespace, locations in capabilities
            )
    return job.id


def _rows(org_id: uuid.UUID, job_id: uuid.UUID, lines: list[BaseModel]) -> list[Any]:
    header = lines[0]
    program = lines[1]
    assert isinstance(header, ReResultHeader) and isinstance(program, ReProgramRecord)
    common = {"organization_id": org_id, "job_id": job_id}
    decompiled = {
        line.function_entry: line.status.value
        for line in lines
        if isinstance(line, ReDecompiledRecord)
    }
    rows: list[Any] = [
        ReProgram(
            **common,
            format=program.format,
            arch=program.arch,
            machine=program.machine,
            bits=program.bits,
            endianness=program.endianness,
            language_id=program.language_id,
            compiler_spec=program.compiler_spec,
            image_base=program.image_base,
            preferred_base=program.preferred_base,
            entry=program.entry,
            analysis_status=program.analysis_status,
            peak_memory_bytes=max(
                (s.peak_memory_bytes or 0 for s in header.stages), default=None
            ),
            engine=header.engine.value,
            engine_version=header.tool_versions.get("ghidra"),
            code_kind=header.code_kind.value,
            stages=[s.model_dump(mode="json") for s in header.stages],
            counts=dict(program.counts),
            truncated=dict(header.truncated),
            tool_versions=dict(header.tool_versions),
            audit=dict(header.audit),
            jvm_args=list(header.jvm_args),
        )
    ]
    imports: dict[int, ReImport] = {}
    strings: dict[int, ReString] = {}
    for line in lines[2:]:
        if isinstance(line, ReFunctionRecord):
            data = line.model_dump(mode="json", exclude={"kind", "body"})
            data["name_source"] = line.name_source.value
            rows.append(
                ReFunction(
                    **common,
                    **{**data, "entry": line.entry, "rva": line.rva},
                    body=[r.model_dump() for r in line.body],
                    decompile_status=decompiled.get(line.entry, "not_selected"),
                )
            )
        elif isinstance(line, ReCallEdgeRecord):
            rows.append(
                ReCallEdge(
                    **common, caller_entry=line.caller, callee_entry=line.callee, sites=line.sites
                )
            )
        elif isinstance(line, ReImportRecord):
            imports[line.index] = ReImport(
                **common,
                id=uuid.uuid4(),
                library=line.library,
                name=line.name,
                ordinal=line.ordinal,
                address=line.address,
            )
            rows.append(imports[line.index])
        elif isinstance(line, ReImportRefRecord):
            rows.append(
                ReImportRef(
                    **common,
                    import_id=imports[line.import_index].id,
                    function_entry=line.function_entry,
                    count=line.count,
                )
            )
        elif isinstance(line, ReStringRecord):
            strings[line.index] = ReString(
                **common,
                id=uuid.uuid4(),
                address=line.address,
                encoding=line.encoding,
                value=line.value,
                length=line.length,
            )
            rows.append(strings[line.index])
        elif isinstance(line, ReStringRefRecord):
            rows.append(
                ReStringRef(
                    **common,
                    string_id=strings[line.string_index].id,
                    function_entry=line.function_entry,
                    count=line.count,
                )
            )
        elif isinstance(line, ReDecompiledRecord):
            rows.append(
                ReDecompilation(
                    **common,
                    function_entry=line.function_entry,
                    status=line.status.value,
                    code_kind=line.code_kind.value,
                    code=line.code,
                    lines=line.lines,
                    code_sha256=line.code_sha256,
                    truncated_bytes=line.truncated_bytes,
                    duration_ms=line.duration_ms,
                )
            )
    return rows


async def seed_re_job(
    t: Tenant,
    source_job_id: uuid.UUID | None = None,
    *,
    status: str = "succeeded",
    profile: Literal["quick", "full"] = "full",
    decompile_addresses: tuple[int, ...] = (),
    fixture: str | None = "pe_full.ndjson",
) -> uuid.UUID:
    """An RE job on the source static job's evidence (a new source job by default); a
    succeeded one with `fixture` also gets its `re_*` rows."""
    if source_job_id is None:
        source_job_id = await seed_static_source_job(t)
    async with tenant_session(t.org_id, t.owner_id) as s:
        source = await s.get(AnalysisJob, source_job_id)
        assert source is not None and source.analyzer == Analyzer.STATIC
        job = AnalysisJob(
            organization_id=t.org_id,
            evidence_id=source.evidence_id,
            analyzer=Analyzer.REVERSE,
            profile=JobProfile(profile),
            source_job_id=source_job_id,
            re_params={"decompile_addresses": [str(a) for a in decompile_addresses]},
            status=AnalysisStatus(status),
            requested_by=t.owner_id,
            ingest_token_sha256=secrets.token_hex(32),
        )
        s.add(job)
        await s.flush()
        if fixture is not None and status == "succeeded":
            s.add_all(_rows(t.org_id, job.id, re_fixture(fixture)))
    return job.id
