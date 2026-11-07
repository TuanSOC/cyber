"""What the decompile stage is asked to do (root side, pure Python; M10 phase 2).

Phase 5's `priority.rank(view, job)` is the order and already the length: the requested
`decompile_addresses` first and never cut, then the other classes up to
`max(limits.max_decompiled, len(requested))`. Root does not cut it again (a requested
address must never be dropped, RT10); it only keeps what the decompile stage can act on:
known, non-external functions, once each, at most `CAP_FUNCTIONS`. Requested addresses that
are not decompilable functions (`priority.missing_addresses`) are reported as the engine
error `function_not_found`.
"""

from dataclasses import dataclass

from cyberlab_jobs.reverse import CAP_FUNCTIONS, ReJobV1

from re_worker import priority
from re_worker.view import ReView


@dataclass(frozen=True)
class DecompilePlan:
    entries: list[int]  # the decompile order; a function's priority_rank is its index
    missing: list[int]  # requested addresses that are not decompilable functions


def decompile_list(view: ReView, job: ReJobV1) -> DecompilePlan:
    seen: set[int] = set()
    entries: list[int] = []
    for entry in priority.rank(view, job):
        function = view.functions.get(entry)
        if function is None or function.is_external or entry in seen:
            continue
        seen.add(entry)
        entries.append(entry)
        if len(entries) == CAP_FUNCTIONS:
            break
    return DecompilePlan(entries=entries, missing=priority.missing_addresses(view, job))


__all__ = ["DecompilePlan", "decompile_list"]
