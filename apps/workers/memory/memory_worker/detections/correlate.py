"""`heuristic:mem_correlated_indicators@1`: one process with observations from two or more
independent detectors (hidden / private executable region / lineage / masquerade /
unexpected network). One extra finding that refs the others; it never raises their
severity.
"""

import uuid

from memory_worker.detections.base import Context, Finding, joined, refs
from memory_worker.detections.mask import excerpt

# finding type -> indicator family (two findings of one family count once).
FAMILIES: dict[str, str] = {
    "mem_hidden_process": "hidden from the active process list",
    "mem_private_exec_pe": "private executable memory",
    "mem_private_exec_region": "private executable memory",
    "mem_process_lineage": "unexpected parent",
    "mem_name_similar_to_core": "core-process look-alike",
    "mem_core_name_unexpected_path": "core-process look-alike",
    "mem_unexpected_network": "unexpected external connection",
}
MIN_FAMILIES = 2
CONFIDENCE = 0.9  # "high": independent observations agree


def detect(findings: list[Finding], ids: dict[int, uuid.UUID], ctx: Context) -> list[Finding]:
    """`ids` maps `id(finding)` to its finding id (computed by the caller)."""
    per_pid: dict[int, list[Finding]] = {}
    for finding in findings:
        if finding.pid is None or finding.type not in FAMILIES:
            continue
        if finding.pid not in per_pid and not ctx.budget.take():
            break
        per_pid.setdefault(finding.pid, []).append(finding)
    out: list[Finding] = []
    for pid, group in sorted(per_pid.items()):
        families = sorted({FAMILIES[f.type] for f in group})
        if len(families) < MIN_FAMILIES:
            continue
        out.append(
            Finding(
                type="mem_correlated_indicators",
                severity="medium",
                confidence=CONFIDENCE,
                values={
                    "pid": pid,
                    "name": excerpt(ctx.name_of(pid) or "unknown", 64),
                    "count": len(families),
                    "indicators": joined(families, 300),
                },
                key=str(pid),
                pid=pid,
                refs=refs([f"pid:{pid}", *(f"finding:{ids[id(f)]}" for f in group)]),
                attributes={"pid": pid, "indicators": len(families)},
            )
        )
    return out
