"""Deterministic disk detections (M9 phase 6; the signature of `run` is frozen by phase 1).

`run(view, limits) -> DetectionOutput`: one streaming pass over **every** event of
`view.events()` (pass 1 of RT10; rules keep bounded aggregates only, never the events), then the
file listing, then correlation. Findings are heuristic observations (`heuristic:*` at most
`medium`, no verdict words, quoted text masked), plus `signature:yara@1` and
`known_file:hashset@1`. Caps: findings, IOCs and timeline at `limits.max_*`; every cap hit (and a
detector-state budget hit) sets `truncated`.

`DetectionOutput.cited_events` holds every event ordinal a kept finding cites: phase 3's pass 2
stores them whatever the per-category quotas, so no finding loses its evidence (RT10).

Two entry points for the same work:
- `run(view, limits, *, yara_severity=None)` iterates `view.events()` itself;
- `Detector(view, limits)` with `observe(event)` per event and `finish()` lets phase 3's
  normaliser feed events while it reads them (`view.events` is then not called).

`yara_severity` (keyword only, optional): YARA rule as stored in `DiskFileRecord.yara_rules` ->
severity, computed by phase 5 through `cyberlab_worker.yara_rules` (M3 allow-list); missing
rules are `low`.

The result is a `DiskDetectionOutput` (a `DetectionOutput` with per-reason counters, e.g.
`evtx_layout_unknown`, and per-cap truncation flags) for the header's diagnostics.
"""

import heapq
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

from cyberlab_jobs.disk import DetectionOutput, DiskEventRecord, DiskLimits, DiskView
from cyberlab_jobs.results import FindingRecord

from disk_worker.detections import correlate, output, paths
from disk_worker.detections.account_change import AccountChange
from disk_worker.detections.ads_executable import AdsExecutable
from disk_worker.detections.base import (
    MAX_ATTRIBUTES,
    MAX_DETECTOR_KEYS,
    SEVERITY_RANK,
    Budget,
    Context,
    FileFacts,
    Finding,
    Rule,
    Severity,
    shared_ts,
)
from disk_worker.detections.double_extension import DoubleExtension
from disk_worker.detections.dual_use import DualUse
from disk_worker.detections.exec_user_writable import ExecUserWritable
from disk_worker.detections.extension_mismatch import ExtensionMismatch
from disk_worker.detections.hashset import HashSetMatches
from disk_worker.detections.log_cleared import LogCleared
from disk_worker.detections.persistence import Persistence
from disk_worker.detections.remote_logon import RemoteLogon
from disk_worker.detections.service_installed import ServiceInstalled
from disk_worker.detections.yara import YaraMatches


@dataclass
class DiskDetectionOutput(DetectionOutput):
    counts: dict[str, int] = field(default_factory=dict)
    truncated_parts: dict[str, bool] = field(default_factory=dict)


def new_rules() -> list[Rule]:
    return [
        ExecUserWritable(),
        DoubleExtension(),
        ExtensionMismatch(),
        AdsExecutable(),
        Persistence(),
        LogCleared(),
        ServiceInstalled(),
        AccountChange(),
        RemoteLogon(),
        DualUse(),
        YaraMatches(),
        HashSetMatches(),
    ]


def _attribute(value: str | int | float | bool) -> str | int | float | bool:
    return value[:255] if isinstance(value, str) else value


class Detector:
    """Streaming detections over one image: `observe` every event, then `finish` once."""

    def __init__(
        self,
        view: DiskView,
        limits: DiskLimits,
        *,
        yara_severity: Mapping[str, Severity] | None = None,
        max_keys: int = MAX_DETECTOR_KEYS,
    ) -> None:
        self.view = view
        self.limits = limits
        self.ctx = Context(
            budget=Budget(max_keys),
            partitions={p.index: p for p in view.partitions},
            image_key=view.image.media_sha256 or "",
            yara_severity=dict(yara_severity or {}),
        )
        self.rules = new_rules()
        self.finished = False

    def observe(self, event: DiskEventRecord) -> None:
        self.ctx.counts["events"] += 1
        self.ctx.see_event(event)
        for rule in self.rules:
            rule.observe(event, self.ctx)

    def _files(self) -> list[Finding]:
        ctx = self.ctx
        if ctx.newest_event is None:
            for file in self.view.files:
                ctx.see_file(file)
        found: list[Finding] = []
        for file in self.view.files:
            ci = ctx.case_insensitive(file.partition_index)
            family = paths.family_of(ci)
            norm = paths.normalize(file.path, ci)
            writable = paths.user_writable_class(norm, family) if file.type != "dir" else None
            facts = FileFacts(norm, family, writable)
            if (
                (writable is not None or (ci and paths.is_startup(norm)))
                and file.stream is None
                and norm not in ctx.indexed_files
                and ctx.budget.take()
            ):
                ctx.indexed_files[norm] = file
            for rule in self.rules:
                found += rule.check_file(file, facts, ctx)
        return found

    def finish(self) -> "DiskDetectionOutput":
        if self.finished:
            raise RuntimeError("Detector.finish() runs once")
        self.finished = True
        ctx = self.ctx
        found = self._files()
        for rule in self.rules:
            found += rule.finish(ctx)
        ids = {id(f): f.finding_id(ctx.image_key) for f in found}
        extra = correlate.detect(found, ids, ctx)
        ids.update({id(f): f.finding_id(ctx.image_key) for f in extra})
        found += extra

        limits = self.limits
        top = heapq.nsmallest(
            limits.max_findings,
            found,
            key=lambda f: (-SEVERITY_RANK[f.capped_severity], -f.confidence, f.type, f.key),
        )
        fallback = ctx.fallback_ts
        kept = [(f, _record(f, ids[id(f)], fallback)) for f in top]
        cited = {e.ordinal for f, _ in kept for e in f.events}
        ioc_records, iocs_capped = output.iocs(kept, limits.max_iocs)
        events, timeline_capped = output.timeline(kept, limits.max_timeline, fallback)
        parts = {
            "findings": len(found) > limits.max_findings,
            "iocs": iocs_capped,
            "timeline": timeline_capped,
            "detector_state": ctx.budget.exhausted,
            "cited_events": any(f.cited_more for f, _ in kept),
        }
        return DiskDetectionOutput(
            findings=[record for _, record in kept],
            iocs=ioc_records,
            timeline=events,
            cited_events=cited,
            # A finding citing more than MAX_CITED_EVENTS events is not a cap of the stream (the
            # count is in its `cited_events_omitted` attribute); every other cap is.
            truncated=any(hit for key, hit in parts.items() if key != "cited_events"),
            counts=dict(sorted(ctx.counts.items())),
            truncated_parts={key: True for key, hit in parts.items() if hit},
        )


def _record(finding: Finding, finding_id: uuid.UUID, fallback: datetime) -> FindingRecord:
    attributes = dict(list(finding.attributes.items())[: MAX_ATTRIBUTES - 1])
    if finding.cited_more:
        attributes["cited_events_omitted"] = finding.cited_more
    return FindingRecord(
        finding_id=finding_id,
        type=finding.type,
        title=finding.title,
        description=finding.description,
        severity=finding.capped_severity,
        confidence=round(finding.confidence, 3),
        detection_method=finding.method,
        ts=shared_ts(finding.ts) or fallback,
        src_ip=finding.src_ip,
        evidence_refs=finding.refs(),
        attributes={k[:64]: _attribute(v) for k, v in attributes.items()},
    )


def run(
    view: DiskView,
    limits: DiskLimits,
    *,
    yara_severity: Mapping[str, Severity] | None = None,
) -> DetectionOutput:
    detector = Detector(view, limits, yara_severity=yara_severity)
    for event in view.events():
        detector.observe(event)
    return detector.finish()


__all__ = ["Detector", "DiskDetectionOutput", "new_rules", "run"]
