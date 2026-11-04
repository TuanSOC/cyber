"""Synthetic `static.v1` result streams for ingest tests (built with the contract models).

`lines()` gives header + sample (+ pe) + records as raw NDJSON lines so tests can splice in
hostile lines; `pcap_results.encode()` appends the trailer and gzips (same framing).
The sample line must match the evidence record: build it with `sample_for(bytes)` or, for a
job whose evidence the test did not upload itself, let `seed_results()` read the record.
"""

import hashlib
import uuid
from typing import Any

from cyberlab_jobs import IngestMessageV1
from cyberlab_jobs.results import FindingRecord, IocRecord
from cyberlab_jobs.static import (
    CapabilityRecord,
    ExportRecord,
    ImportRecord,
    PeInfo,
    ResourceRecord,
    SampleInfo,
    SectionRecord,
    SignatureMatch,
    StaticResultHeader,
    StringRecord,
)
from pydantic import BaseModel
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob
from app.modules.evidence.models import Evidence, EvidenceHash
from app.workers import ingest
from tests.pcap_results import T0, at, encode, line, put_result

WORKER = "static-worker/test"
TOOLS = {
    "pefile": "2024.8.26",
    "yara": "4.5.2",
    "clamav": "1.4.3",
    "clamav_db": "27420",
    "clamav_db_date": "2026-11-01",
    "capa": "9.2.1",
    "capa_rules": "v10.0.0",
    "floss": "3.1.1",
}


def header(job_id: uuid.UUID | str, **fields: Any) -> StaticResultHeader:
    values: dict[str, Any] = {
        "job_id": uuid.UUID(str(job_id)),
        "profile": "full",
        "file_format": "pe",
        "tool_versions": TOOLS,
        **fields,
    }
    return StaticResultHeader.model_validate(values)


def sample_for(data: bytes, **fields: Any) -> SampleInfo:
    """The sample line of the given evidence bytes (hashes and size as the API computed)."""
    values: dict[str, Any] = {
        "size": len(data),
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "ssdeep": "3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C",
        "file_type": "PE32+ executable (console) x86-64, for MS Windows",
        "mime": "application/vnd.microsoft.portable-executable",
        "entropy": 6.25,
        **fields,
    }
    return SampleInfo.model_validate(values)


def pe(**fields: Any) -> PeInfo:
    values: dict[str, Any] = {
        "machine": "AMD64",
        "bits": 64,
        "is_dll": False,
        "subsystem": "WINDOWS_CUI",
        "compile_timestamp": 1_700_000_000,
        "entry_point": 0x1400,
        "entry_section": ".text",
        "image_base": 2**64 - 2**32,  # above the bigint range: stored as NUMERIC
        "imphash": "a" * 32,
        "rich_header_hash": "b" * 32,
        "tls_callbacks": 1,
        "has_authenticode": False,
        "overlay_size": 512,
        "characteristics": ["EXECUTABLE_IMAGE", "LARGE_ADDRESS_AWARE"],
        "dll_characteristics": ["NX_COMPAT"],
        **fields,
    }
    return PeInfo.model_validate(values)


FINDING_PACKED = uuid.UUID(int=101)
FINDING_INJECTION = uuid.UUID(int=102)


def sample_records() -> list[BaseModel]:
    """A small but complete analysis: every record kind, with filterable variety."""
    return [
        SectionRecord(
            index=0,
            name=".text",
            virtual_address=0x1000,
            virtual_size=4096,
            raw_size=4096,
            entropy=6.1,
            flags=["read", "execute"],
        ),
        SectionRecord(
            index=1,
            name=".rdata",
            virtual_address=0x2000,
            virtual_size=1024,
            raw_size=1024,
            entropy=4.0,
            flags=["read"],
        ),
        SectionRecord(
            index=2,
            name="UPX1",
            virtual_address=2**64 - 4096,
            virtual_size=8192,
            raw_size=512,
            entropy=7.9,
            flags=["read", "write", "execute"],
        ),
        ImportRecord(library="KERNEL32.dll", function="VirtualAllocEx"),
        ImportRecord(library="KERNEL32.dll", function="WriteProcessMemory"),
        ImportRecord(library="KERNEL32.dll", function="CreateRemoteThread"),
        ImportRecord(library="KERNEL32.dll", function="GetModuleHandleW"),
        ImportRecord(library="ADVAPI32.dll", function="RegSetValueExW"),
        ImportRecord(library="WS2_32.dll", ordinal=115),
        ExportRecord(name="DllMain_100%", ordinal=1, address=0x1400),
        ExportRecord(name=None, ordinal=2**32 - 1, address=2**64 - 1),
        ResourceRecord(type="RT_VERSION", name="1", language="LANG_ENGLISH", size=740, entropy=3.2),
        ResourceRecord(type="RT_RCDATA", name="BLOB", size=65_536, entropy=7.99, sha256="c" * 64),
        StringRecord(value="http://update.example.test/payload", encoding="ascii", offset=4096),
        StringRecord(value="discount 100%_off", encoding="ascii", offset=8192),
        StringRecord(value="C:\\Users\\Public\\run.bat", encoding="utf16le", offset=12_288),
        StringRecord(value="decoded-secret-key", encoding="floss_decoded"),
        SignatureMatch(
            engine="yara",
            name="Suspicious_Injection_APIs",
            namespace="cyberlab",
            tags=["injection"],
            meta={"author": "cyberlab", "severity": "low"},
        ),
        SignatureMatch(engine="clamav", name="Eicar-Signature"),
        CapabilityRecord(
            name="inject code into another process",
            namespace="host-interaction/process/inject",
            attack=["T1055.012"],
            mbc=["E1055"],
            matches=3,
        ),
        CapabilityRecord(
            name="check for debugger",
            namespace="anti-analysis/anti-debugging/debugger-detection",
            attack=["T1622"],
            mbc=["B0001.002"],
        ),
        FindingRecord(
            ts=T0,
            finding_id=FINDING_PACKED,
            type="packed_section",
            title="Section with packer-like entropy",
            description="UPX1 has entropy 7.9 and a small raw size",
            severity="medium",
            confidence=0.7,
            detection_method="heuristic:packed_section@1",
            evidence_refs=["UPX1"],
            attributes={"entropy": 7.9},
        ),
        FindingRecord(
            ts=T0,
            finding_id=FINDING_INJECTION,
            type="injection_api_set",
            title="Process-injection API set present",
            description="VirtualAllocEx, WriteProcessMemory and CreateRemoteThread imported",
            severity="high",
            confidence=0.6,
            detection_method="heuristic:injection_api_set@1",
        ),
        IocRecord(
            type="url",
            value="http://update.example.test/payload",
            first_seen=T0,
            last_seen=T0,
            count=1,
            source="strings",
        ),
        IocRecord(
            type="registry_key",
            value="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            first_seen=T0,
            last_seen=at(1),
            count=2,
            source="strings",
        ),
        IocRecord(
            type="file_path",
            value="C:\\Users\\Public\\run.bat",
            first_seen=T0,
            last_seen=T0,
            count=1,
            source="strings",
        ),
        IocRecord(
            type="email",
            value="ops@example.test",
            first_seen=T0,
            last_seen=T0,
            count=1,
            source="strings",
        ),
    ]


SAMPLE_COUNTS = {
    "sections": 3,
    "imports": 6,
    "exports": 2,
    "resources": 2,
    "strings": 4,
    "signatures": 2,
    "capabilities": 2,
    "findings": 2,
    "iocs": 4,
}
TABLE_COUNTS = {
    "malware_samples": 1,
    "malware_sections": 3,
    "malware_imports": 6,
    "malware_exports": 2,
    "malware_resources": 2,
    "malware_strings": 4,
    "malware_signature_matches": 2,
    "malware_capabilities": 2,
    "analysis_findings": 2,
    "iocs": 4,
}


def lines(
    job_id: uuid.UUID | str,
    sample: SampleInfo,
    records: list[BaseModel] | None = None,
    *,
    with_pe: bool = True,
    **header_fields: Any,
) -> list[bytes]:
    body = sample_records() if records is None else records
    head = [line(header(job_id, **header_fields)), line(sample)]
    if with_pe:
        head.append(line(pe()))
    return [*head, *(line(r) for r in body)]


def stream(
    job_id: uuid.UUID | str, sample: SampleInfo, records: list[BaseModel] | None = None
) -> bytes:
    return encode(lines(job_id, sample, records))


async def evidence_sample(org_id: uuid.UUID, job_id: uuid.UUID) -> SampleInfo:
    """The sample line matching the stored evidence record of a job."""
    async with tenant_session(org_id, None) as session:
        job = await session.get(AnalysisJob, job_id)
        assert job is not None
        evidence = await session.get(Evidence, job.evidence_id)
        assert evidence is not None
        rows = await session.execute(
            select(EvidenceHash.algorithm, EvidenceHash.value).where(
                EvidenceHash.evidence_id == job.evidence_id
            )
        )
        hashes = {a.value: v for a, v in rows}
    return sample_for(
        b"",
        size=evidence.size_bytes,
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        sha256=hashes["sha256"],
    )


async def seed_results(org_id: uuid.UUID, job_id: uuid.UUID) -> None:
    """Ingest a full static result for a job whose token the test does not know."""
    data = stream(job_id, await evidence_sample(org_id, job_id))
    version_id = put_result(org_id, job_id, data)
    async with tenant_session(org_id, None) as session:
        job = await session.get(AnalysisJob, job_id)
    assert job is not None
    message = IngestMessageV1(
        job_id=job_id,
        organization_id=org_id,
        ingest_token="t" * 43,
        event="finished",
        outcome="succeeded",
        result_version_id=version_id,
        worker_version=WORKER,
    )
    await ingest.ingest_success(job, message)
    async with tenant_session(org_id, None) as session:
        job = await session.get(AnalysisJob, job_id)
    assert job is not None and job.status == "succeeded", job and job.error_code
