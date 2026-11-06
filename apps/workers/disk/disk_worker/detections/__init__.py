"""Deterministic disk detections (M9 phase 1 stub; phase 6 owns the body, never the signature).

`run(view, limits) -> DetectionOutput`: pass 1 over every event of `view.events()` (RT10);
findings cap at `medium` except `signature:yara@1`; quoted text passes `cyberlab_worker.mask`.
Phase 1 returns an empty output.
"""

from cyberlab_jobs.disk import DetectionOutput, DiskLimits, DiskView


def run(view: DiskView, limits: DiskLimits) -> DetectionOutput:
    return DetectionOutput()
