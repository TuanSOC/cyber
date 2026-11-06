"""`disk.v1` assembly (root side; M9 phase 2): the run's facts, the header, the full and the
diagnostic streams.

Stream order (contract `LINE_ORDER`): header, partition*, file*, event*, finding*, ioc*,
timeline*, trailer. A diagnostic stream (`no_supported_filesystem`,
`unsupported_disk_format`) is the header, at most the partitions, and the trailer.
"""

import uuid
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

from cyberlab_jobs.disk import (
    AnalysisProfile,
    ArtifactStat,
    DetectionOutput,
    DiskEventRecord,
    DiskFileRecord,
    DiskPartitionRecord,
    DiskResultHeader,
    DiskStage,
    EwfInfo,
    HashSetRef,
    ImageFormat,
    ImageInfo,
    StageReport,
    StageStatus,
    check_diagnostic_kinds,
)
from cyberlab_jobs.results import FindingRecord
from cyberlab_worker.errors import JobFailed
from cyberlab_worker.result_writer import ResultWriter

from disk_worker.stage import StageResult

TimelineEngine = Literal["plaso", "replay", "none"]
MAX_STAGE_REPORTS = 512
MAX_ENGINE_ERRORS = 32
MAX_TRUNCATED_KEYS = 32
MAX_AUDIT_KEYS = 16


@dataclass
class RunFacts:
    job_id: uuid.UUID
    profile: str
    tool_versions: dict[str, str]
    format: ImageFormat
    segments: int
    media_size: int = 0
    sector_size: int = 512
    media_sha256: str | None = None
    ewf: EwfInfo | None = None
    timeline_engine: str = "none"
    hashsets: list[HashSetRef] = field(default_factory=list)
    stages: list[StageReport] = field(default_factory=list)
    artifacts: list[ArtifactStat] = field(default_factory=list)
    engine_errors: list[str] = field(default_factory=list)
    truncated: dict[str, bool] = field(default_factory=dict)
    findings: list[FindingRecord] = field(default_factory=list)

    def error(self, code: str) -> None:
        if code not in self.engine_errors and len(self.engine_errors) < MAX_ENGINE_ERRORS:
            self.engine_errors.append(code)

    def truncate(self, key: str) -> None:
        if key in self.truncated or len(self.truncated) < MAX_TRUNCATED_KEYS:
            self.truncated[key] = True

    def report(
        self,
        stage: DiskStage,
        result: StageResult | None = None,
        *,
        partition_index: int | None = None,
        status: str | None = None,
        reason: str | None = None,
        rows: int | None = None,
        duration_ms: int = 0,
        error_code: str | None = None,
    ) -> None:
        if len(self.stages) >= MAX_STAGE_REPORTS:
            self.truncate("stages")
            return
        if result is not None:
            audit = dict(list(result.audit_counts.items())[:MAX_AUDIT_KEYS])
            report = StageReport(
                stage=stage,
                partition_index=partition_index,
                status=StageStatus(status) if status else result.status,
                reason=(reason or result.reason or None),
                rows=result.rows if rows is None else rows,
                truncated=result.truncated,
                duration_ms=result.duration_ms,
                error_code=error_code or result.error_code,
                audit_counts=audit,
            )
        else:
            report = StageReport(
                stage=stage,
                partition_index=partition_index,
                status=StageStatus(status or "skipped"),
                reason=reason,
                rows=rows or 0,
                duration_ms=duration_ms,
                error_code=error_code,
            )
        self.stages.append(report)

    def image(self) -> ImageInfo:
        ewf = self.ewf
        if self.format == ImageFormat.EWF and ewf is None:
            ewf = EwfInfo(media_hash_status="absent")
        return ImageInfo(
            format=self.format,
            segments=self.segments,
            media_size=self.media_size,
            sector_size=self.sector_size,
            media_sha256=self.media_sha256,
            ewf=ewf if self.format == ImageFormat.EWF else None,
        )

    def header(self) -> DiskResultHeader:
        return DiskResultHeader(
            job_id=self.job_id,
            profile=cast(AnalysisProfile, self.profile),
            engine="tsk",
            timeline_engine=cast(TimelineEngine, self.timeline_engine),
            tool_versions=self.tool_versions,
            image=self.image(),
            hashsets=self.hashsets,
            stages=self.stages,
            artifacts=self.artifacts,
            engine_errors=self.engine_errors,
            truncated=self.truncated,
        )


def ewf_mismatch_finding() -> FindingRecord:
    """`integrity:ewf_media_hash@1` (medium, verdict-free)."""
    return FindingRecord(
        ts=datetime.now(UTC),
        finding_id=uuid.uuid4(),
        type="ewf_media_hash_mismatch",
        title="Stored media hash does not match the content",
        description=(
            "The MD5 / SHA-1 the worker computed over the EWF media differ from the values "
            "stored in the image at acquisition. The image may have been altered or damaged "
            "after acquisition, or the stored values were wrong. Reported by the worker; only "
            "the segment sha256 values recorded at upload are trusted."
        ),
        severity="medium",
        confidence=0.9,
        detection_method="integrity:ewf_media_hash@1",
    )


def write_diagnostic(
    path: Path, facts: RunFacts, partitions: Sequence[DiskPartitionRecord] = ()
) -> Path:
    check_diagnostic_kinds(["header", *("partition" for _ in partitions), "trailer"])
    with ResultWriter(path) as writer:
        writer.write(facts.header())
        for p in partitions:
            writer.write(p)
    return path


def write_result(
    path: Path,
    facts: RunFacts,
    partitions: Sequence[DiskPartitionRecord],
    files: Iterable[DiskFileRecord],
    events: Callable[[], Iterator[DiskEventRecord]],
    found: DetectionOutput,
    max_result_bytes: int,
) -> Path:
    with ResultWriter(path) as writer:
        writer.write(facts.header())
        for p in partitions:
            writer.write(p)
        for f in files:
            writer.write(f)
        for e in events():
            writer.write(e)
        for line in (*found.findings, *found.iocs, *found.timeline):
            writer.write(line)
    if path.stat().st_size > max_result_bytes:
        raise JobFailed("result_too_large")
    return path


__all__ = ["RunFacts", "ewf_mismatch_finding", "write_diagnostic", "write_result"]
