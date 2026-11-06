"""Deterministic triage heuristics over a `MemoryView` (M8 phase 3; the signature of `run` is
frozen by phase 1).

`run(view, limits) -> DetectionOutput`: findings (heuristics only, at most `medium`, no
verdict words, secrets masked, RT13), IOCs (observables through `cyberlab_worker.iocs`) and
the timeline, each capped by `limits`; every cap hit sets a `truncated` flag (`findings`,
`iocs`, `timeline`, `detector_state`) instead of failing. Detectors read only normalized
records, never raw plugin output, so a plugin column rename is absorbed by phase 2.
"""

import heapq
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from cyberlab_jobs.memory import MemoryLimits
from cyberlab_jobs.results import FindingRecord

from memory_worker.detections import (
    base,
    cmdline,
    correlate,
    hidden,
    injected,
    iocs,
    lineage,
    masquerade,
    network,
    services,
    shell,
    timeline,
    unlinked,
)
from memory_worker.detections.base import SEVERITY_RANK, Budget, Context, Finding
from memory_worker.view import DetectionOutput, MemoryView

Detector = Callable[[MemoryView, Context], list[Finding]]
DETECTORS: tuple[Detector, ...] = (
    hidden.detect,
    injected.detect,
    lineage.detect,
    masquerade.detect,
    cmdline.detect,
    unlinked.detect,
    services.detect,
    network.detect,
    shell.detect,
)


def _attribute(value: str | int | float | bool) -> str | int | float | bool:
    return value[:255] if isinstance(value, str) else value


def _record(finding: Finding, finding_id: uuid.UUID, ts: datetime) -> FindingRecord:
    attributes = list(finding.attributes.items())[: base.MAX_ATTRIBUTES]
    return FindingRecord(
        finding_id=finding_id,
        type=finding.type,
        title=finding.title,
        description=finding.description,
        severity=finding.capped_severity,
        confidence=round(finding.confidence, 3),
        detection_method=finding.method,
        ts=ts,
        dst_ip=finding.dst_ip,
        dst_port=finding.dst_port,
        evidence_refs=finding.refs,
        attributes={k[:64]: _attribute(v) for k, v in attributes},
    )


def raw_findings(view: MemoryView, ctx: Context) -> tuple[list[Finding], dict[int, uuid.UUID]]:
    """Every detector's findings plus the correlation pass, with their stable ids (keyed by
    `id(finding)`)."""
    found: list[Finding] = []
    for detector in DETECTORS:
        found += detector(view, ctx)
    ids = {id(f): f.finding_id(view.image.sha256) for f in found}
    extra = correlate.detect(found, ids, ctx)
    ids.update({id(f): f.finding_id(view.image.sha256) for f in extra})
    return [*found, *extra], ids


def run(view: MemoryView, limits: MemoryLimits) -> DetectionOutput:
    budget = Budget(base.MAX_DETECTOR_KEYS)
    by_pid = base.index_processes(view.processes, budget)
    # Findings are observations of the image: they carry its system time (else run time).
    observed_at = view.image.system_time or datetime.now(UTC)
    ctx = Context(budget=budget, by_pid=by_pid, observed_at=observed_at)

    found, ids = raw_findings(view, ctx)
    top = heapq.nsmallest(
        limits.max_findings,
        found,
        key=lambda f: (-SEVERITY_RANK[f.capped_severity], -f.confidence, f.type, f.key),
    )
    findings = [_record(f, ids[id(f)], observed_at) for f in top]
    ioc_records, iocs_capped = iocs.build(view, ctx, limits.max_iocs)
    events, timeline_capped = timeline.build(view, ctx, findings, limits.max_timeline)

    flags = {
        "findings": len(found) > limits.max_findings,
        "iocs": iocs_capped,
        "timeline": timeline_capped,
        "detector_state": budget.exhausted,
    }
    return DetectionOutput(
        findings=findings,
        iocs=ioc_records,
        timeline=events,
        truncated={key: True for key, hit in flags.items() if hit},
    )


__all__ = ["DETECTORS", "raw_findings", "run"]
