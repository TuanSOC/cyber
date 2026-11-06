"""Write a validated `static.v1` stream into the tenant tables (inside the caller's
transaction): the one `malware_samples` row (sample + pe/elf), then every other record in
batches (see app.modules.analysis.result_rows). Findings and IOCs go into the shared tables
with the same row shape as pcap's.

M10 phase 6 (additive `static.v1` fields, RT18): a capability's `locations` are stored as
decimal strings in `malware_capabilities.locations` (a JSON number cannot carry an unsigned
64-bit value exactly; the 0018 check), the header's `capa_base_address` in
`malware_samples.capa_base_address`. A stream from before M10 has neither: `[]` / NULL.
"""

import uuid
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

from cyberlab_jobs.results import FindingRecord, IocRecord
from cyberlab_jobs.static import (
    CapabilityRecord,
    ExportRecord,
    ImportRecord,
    ResourceRecord,
    SectionRecord,
    SignatureMatch,
    StaticRecordLine,
    StringRecord,
)
from sqlalchemy import Table, insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.analysis import result_rows
from app.modules.pcap_analysis import ingest as pcap_ingest
from app.modules.static_analysis import stream
from app.modules.static_analysis.models import (
    MalwareCapability,
    MalwareExport,
    MalwareImport,
    MalwareResource,
    MalwareSample,
    MalwareSection,
    MalwareSignatureMatch,
    MalwareString,
)

BATCH_LINES = 1000
BATCH_BYTES = 8 * 1024**2
# The ELF `needed` list kept in the job summary (the sample row keeps all of it).
SUMMARY_NEEDED_MAX = 32

# Summary counter name per record kind.
COUNT_NAMES = {
    "section": "sections",
    "import": "imports",
    "export": "exports",
    "resource": "resources",
    "string": "strings",
    "signature_match": "signatures",
    "capability": "capabilities",
    "finding": "findings",
    "ioc": "iocs",
}
SAMPLES = cast(Table, MalwareSample.__table__)
SECTIONS = cast(Table, MalwareSection.__table__)
IMPORTS = cast(Table, MalwareImport.__table__)
EXPORTS = cast(Table, MalwareExport.__table__)
RESOURCES = cast(Table, MalwareResource.__table__)
STRINGS = cast(Table, MalwareString.__table__)
SIGNATURES = cast(Table, MalwareSignatureMatch.__table__)
CAPABILITIES = cast(Table, MalwareCapability.__table__)


def _fields(record: Any) -> dict[str, Any]:
    return cast(dict[str, Any], record.model_dump(mode="python", exclude={"kind"}))


def to_row(record: StaticRecordLine) -> tuple[Table, dict[str, Any]]:
    if isinstance(record, SectionRecord):
        return SECTIONS, {**_fields(record), "flags": list(record.flags)}
    if isinstance(record, ImportRecord):
        return IMPORTS, _fields(record)
    if isinstance(record, ExportRecord):
        return EXPORTS, _fields(record)
    if isinstance(record, ResourceRecord):
        return RESOURCES, _fields(record)
    if isinstance(record, StringRecord):
        return STRINGS, _fields(record)
    if isinstance(record, SignatureMatch):
        return SIGNATURES, {
            "engine": record.engine,
            "name": record.name,
            "namespace": record.namespace,
            "tags": list(record.tags),
            "meta": dict(record.meta),
        }
    if isinstance(record, CapabilityRecord):
        return CAPABILITIES, {
            "name": record.name,
            "namespace": record.namespace,
            "attack": list(record.attack),
            "mbc": list(record.mbc),
            "matches": record.matches,
            "locations": [str(address) for address in record.locations],
        }
    if isinstance(record, FindingRecord | IocRecord):
        return pcap_ingest.to_row(record)  # the shared tables, one row shape
    raise TypeError(f"no table for record kind {record.kind!r}")


def sample_row(result: stream.Validated) -> dict[str, Any]:
    s = result.sample
    return {
        "size": s.size,
        "md5": s.md5,
        "sha1": s.sha1,
        "sha256": s.sha256,
        "ssdeep": s.ssdeep,
        "file_type": s.file_type,
        "mime": s.mime,
        "entropy": s.entropy,
        "file_format": result.header.file_format,
        "pe": None if result.pe is None else result.pe.model_dump(mode="json", exclude={"kind"}),
        "elf": None if result.elf is None else result.elf.model_dump(mode="json", exclude={"kind"}),
        "capa_base_address": result.header.capa_base_address,
    }


def _next_batch(
    records: Iterator[tuple[StaticRecordLine, int]],
    scope: dict[str, Any],
    written: Counter[str],
) -> result_rows.Batch:
    return result_rows.next_batch(
        records, scope, written, to_row, max_lines=BATCH_LINES, max_bytes=BATCH_BYTES
    )


async def insert_rows(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    path: Path,
    result: stream.Validated,
    caps: stream.Caps,
) -> Counter[str]:
    """Insert the sample row and every record; returns the rows written per kind."""
    scope = {"organization_id": org_id, "job_id": job_id}
    await session.execute(insert(SAMPLES), [{**sample_row(result), **scope}])
    written = await result_rows.insert_batches(
        session, org_id, job_id, stream.records(path, caps), _next_batch
    )
    written["sample"] += 1
    if result.pe is not None:
        written["pe"] += 1
    if result.elf is not None:
        written["elf"] += 1
    return written


def build_summary(
    result: stream.Validated, written: Counter[str], evidence: stream.Expected
) -> dict[str, Any]:
    """The job summary: trusted hashes come from the evidence record, analyzer-derived
    hashes (ssdeep, imphash, rich header) are labelled as such."""
    header = result.header.model_dump(mode="json")
    sample, pe, elf = result.sample, result.pe, result.elf
    pe_summary = None
    if pe is not None:
        pe_summary = pe.model_dump(mode="json", exclude={"kind", "imphash", "rich_header_hash"})
    elf_summary = None
    if elf is not None:
        elf_summary = elf.model_dump(mode="json", exclude={"kind", "needed"})
        elf_summary["needed"] = list(elf.needed[:SUMMARY_NEEDED_MAX])
        elf_summary["needed_total"] = len(elf.needed)
    return {
        "schema_version": header["schema_version"],
        "profile": header["profile"],
        "file_format": header["file_format"],
        "tool_versions": header["tool_versions"],
        "engine_errors": header["engine_errors"],
        "truncated": header["truncated"],
        "sample": {
            "size": evidence.size,
            "sha256": evidence.sha256,
            "sha1": evidence.sha1 or sample.sha1,
            "md5": evidence.md5 or sample.md5,
            "file_type": sample.file_type,
            "mime": sample.mime,
            "entropy": sample.entropy,
            "analyzer_derived": {
                "ssdeep": sample.ssdeep,
                "imphash": pe.imphash if pe else None,
                "rich_header_hash": pe.rich_header_hash if pe else None,
            },
        },
        "pe": pe_summary,
        "elf": elf_summary,
        "counts": {name: written[kind] for kind, name in COUNT_NAMES.items()},
    }
