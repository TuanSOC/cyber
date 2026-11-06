"""Deterministic triage heuristics over a `MemoryView` (phase-1 STUB; phase 3 owns this
package, never the signature of `run`).

`run(view, limits) -> DetectionOutput`: findings (heuristics only, at most `medium`, no
verdict words, secrets masked, RT13), IOCs (observables through `cyberlab_worker.iocs`) and the
timeline, each capped by `limits`. Phase 1 returns an empty output.
"""

from cyberlab_jobs.memory import MemoryLimits

from memory_worker.view import DetectionOutput, MemoryView


def run(view: MemoryView, limits: MemoryLimits) -> DetectionOutput:
    del view, limits
    return DetectionOutput()
