"""Shared in-memory types between the engine (phase 2) and the detections (phase 3) (M8
phase 1, FROZEN).

`MemoryView` is what the normalizers produce from one run: the validated contract records,
grouped by kind, plus the run's facts. Detections (`detections.run(view, limits)`) read it and
return a `DetectionOutput`; the pipeline then writes both into the `memory.v1` stream. Both
are plain containers of contract models, so phase 3 builds scenario views without Volatility.
"""

from dataclasses import dataclass, field

from cyberlab_jobs.memory import (
    MemoryArtifactRecord,
    MemoryConnectionRecord,
    MemoryImageRecord,
    MemoryInjectionRecord,
    MemoryOs,
    MemoryProcessRecord,
    MemoryProfile,
    MemoryTimelineEvent,
)
from cyberlab_jobs.results import FindingRecord, IocRecord


@dataclass(frozen=True)
class MemoryView:
    os: MemoryOs
    profile: MemoryProfile
    image: MemoryImageRecord
    processes: tuple[MemoryProcessRecord, ...] = ()
    connections: tuple[MemoryConnectionRecord, ...] = ()
    injections: tuple[MemoryInjectionRecord, ...] = ()
    artifacts: tuple[MemoryArtifactRecord, ...] = ()
    # Plugins whose rows were capped (detections must not treat absence as evidence).
    truncated: frozenset[str] = frozenset()


@dataclass
class DetectionOutput:
    findings: list[FindingRecord] = field(default_factory=list)
    iocs: list[IocRecord] = field(default_factory=list)
    timeline: list[MemoryTimelineEvent] = field(default_factory=list)
    # Caps hit by the detectors (`findings`, `iocs`, `timeline`, `detector_state`).
    truncated: dict[str, bool] = field(default_factory=dict)
