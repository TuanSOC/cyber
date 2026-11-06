"""Deterministic decompile priority (M10 phase 5; the signature is frozen in phase 1).

`rank(view, job) -> list[int]`: function entries in decompile order, from validated records:
1. `job.decompile_addresses` that are function entries (not externals), in request order
   (RT10; `missing_addresses` lists the others for `engine_errors: function_not_found`);
2. the program entry point and the exported functions (`name_source = export`);
3. functions whose body contains a capa file VA of the source job (`job.capa_file_vas`, RT8);
4. functions calling an import of an M3 suspicious API set (`cyberlab_worker.apisets`);
5. functions referencing a string that yields a URL / domain / IP observable;
6. the rest by size, descending.
A function takes its best class; within classes 2-6 ties go by entry ascending (class 6:
size descending, then entry). Classes 2-6 skip thunks, externals and FID library functions.
The list is capped at `job.limits.max_decompiled`, except that class 1 is always first and
never cut: the length is `max(max_decompiled, len(class 1))`. A function's stored rank is
its index here (`ranks`); a function not listed has no rank (`not_prioritized`).
"""

from cyberlab_jobs.reverse import NameSource, ReJobV1
from cyberlab_worker.apisets import api_names

from re_worker.detections import KNOWN_APIS, iocs
from re_worker.detections.base import called_api_names, eligible
from re_worker.view import ReView

SUSPICIOUS_APIS = api_names()
CLASSES = 6


def missing_addresses(view: ReView, job: ReJobV1) -> list[int]:
    """Requested addresses that are not (decompilable) function entries, in request order."""
    return [
        a
        for a in job.decompile_addresses
        if a not in view.functions or view.functions[a].is_external
    ]


def classify(view: ReView, job: ReJobV1) -> dict[int, int]:
    """Entry -> best class (2-6) of every eligible function."""
    capa = {e for va in job.capa_file_vas for e in view.functions_at_file_va(va)}
    ioc_strings = set(iocs.string_iocs(view))
    exported = {
        e for e, f in view.functions.items() if f.name_source == NameSource.EXPORT
    }
    if view.program.entry is not None:
        exported.add(view.program.entry)
    classes: dict[int, int] = {}
    for entry in view.functions:
        if not eligible(view, entry):
            continue
        if entry in exported:
            classes[entry] = 2
        elif entry in capa:
            classes[entry] = 3
        elif called_api_names(view, entry, KNOWN_APIS) & SUSPICIOUS_APIS:
            classes[entry] = 4
        elif ioc_strings.intersection(view.strings_referenced(entry)):
            classes[entry] = 5
        else:
            classes[entry] = 6
    return classes


def rank(view: ReView, job: ReJobV1) -> list[int]:
    missing = set(missing_addresses(view, job))
    first = [a for a in job.decompile_addresses if a not in missing]
    chosen = set(first)
    classes = classify(view, job)
    rest = sorted(
        (e for e in classes if e not in chosen),
        key=lambda e: (classes[e], -view.functions[e].size if classes[e] == CLASSES else 0, e),
    )
    limit = max(job.limits.max_decompiled, len(first))
    return (first + rest)[:limit]


def ranks(view: ReView, job: ReJobV1) -> dict[int, int]:
    """Entry -> stored `priority_rank` (the index in `rank`)."""
    return {entry: i for i, entry in enumerate(rank(view, job))}
