"""Deterministic decompile priority (M10 phase 5 owns the body; signature frozen in phase 1).

`rank(view, job) -> list[int]`: function entries in decompile order, from validated records:
the requested `decompile_addresses` (RT10) -> the entry point and exports -> functions
containing a capa file VA of the source job (RT8) -> functions calling an import of an M3
suspicious API set (`cyberlab_worker.apisets`) -> functions referencing a string that yields
an IOC -> the rest by size (descending, then entry); thunks, externals and FID library
functions are never ranked. The pipeline decompiles the first `limits.max_decompiled`.
Phase-1 stub: the requested addresses that are functions, in request order (enough for the
replay engine), then nothing.
"""

from cyberlab_jobs.reverse import ReJobV1

from re_worker.view import ReView


def rank(view: ReView, job: ReJobV1) -> list[int]:
    return [a for a in job.decompile_addresses if a in view.functions]
