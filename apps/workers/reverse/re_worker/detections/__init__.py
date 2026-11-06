"""RE detections (M10 phase 5 owns the body; the signature is frozen in phase 1).

`run(view, limits) -> DetectionOutput`: `heuristic:re_api_set_function@1`,
`heuristic:re_runtime_api_resolution@1`, `heuristic:re_network_string_function@1` (capped at
`medium`, no verdict words, each citing its function in `attributes.function_entry`) and the
IOCs of strings referenced by code (`cyberlab_worker.iocs`). Phase-1 stub: nothing.
"""

from cyberlab_jobs.reverse import ReLimits

from re_worker.view import DetectionOutput, ReView


def run(view: ReView, limits: ReLimits) -> DetectionOutput:
    del view, limits
    return DetectionOutput()
