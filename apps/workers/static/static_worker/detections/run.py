"""Runs every detector over the collected facts and builds `finding` / `ioc` lines."""

import heapq
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from cyberlab_jobs.results import FindingRecord, IocRecord
from cyberlab_jobs.static import CapabilityRecord, SignatureMatch

from static_worker.detections import apis
from static_worker.detections.base import SEVERITY_RANK, Finding, Severity
from static_worker.detections.iocs import IocCollector, has_run_key
from static_worker.detections.signatures import capability_findings, signature_findings
from static_worker.detections.structure import Structure, anomalies, packer


@dataclass
class Detection:
    job_id: uuid.UUID
    analysed_at: datetime  # static analysis has no event time: findings / IOCs carry this
    structure: Structure
    ioc_limit: int
    # "<namespace>:<rule>" -> allowlisted YARA ceiling (signatures.yara_ceilings).
    yara_ceilings: dict[str, Severity] = field(default_factory=dict)
    iocs: IocCollector = field(init=False)
    run_key: bool = False

    def __post_init__(self) -> None:
        self.iocs = IocCollector(self.ioc_limit)

    def string(self, value: str, source: str) -> None:
        self.iocs.observe(value, source)
        self.run_key = self.run_key or has_run_key(value)

    def raw_findings(
        self, signatures: list[SignatureMatch], capabilities: list[CapabilityRecord]
    ) -> list[Finding]:
        api_names = set(self.structure.imports)
        if self.run_key:
            api_names.add(apis.RUN_KEY_FLAG)
        return [
            *apis.detect(api_names),
            *packer(self.structure),
            *anomalies(self.structure, self.analysed_at.timestamp()),
            *signature_findings(signatures, self.yara_ceilings),
            *capability_findings(capabilities),
        ]

    def findings(
        self,
        signatures: list[SignatureMatch],
        capabilities: list[CapabilityRecord],
        limit: int,
    ) -> tuple[list[FindingRecord], bool]:
        raw = self.raw_findings(signatures, capabilities)
        top = heapq.nsmallest(
            limit, raw, key=lambda f: (-SEVERITY_RANK[f.severity], -f.confidence, f.type, f.key)
        )
        records = [
            FindingRecord(
                finding_id=f.finding_id(self.job_id),
                type=f.type,
                title=f.title,
                description=f.description,
                severity=f.severity,
                confidence=round(f.confidence, 3),
                detection_method=f.method,
                ts=self.analysed_at,
                evidence_refs=f.refs,
                attributes={k[:64]: v for k, v in list(f.attributes.items())[:20]},
            )
            for f in top
        ]
        return records, len(raw) > limit

    def ioc_records(self) -> list[IocRecord]:
        return [
            IocRecord(
                type=kind,
                value=value,
                first_seen=self.analysed_at,
                last_seen=self.analysed_at,
                count=seen.count,
                source=seen.source,
            )
            for (kind, value), seen in sorted(self.iocs.entries.items())
        ]
