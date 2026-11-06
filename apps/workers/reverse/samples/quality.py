"""Recovery quality of one engine run against the ground truth (M10 phase 4), over the frozen
`ReView` only, so it is unit-tested without an engine (`tests/unit/test_samples.py`) and used
by `tests/engine/test_recovery_quality.py` after the group-B merge.

Everything is compared on **file virtual addresses** (`preferred_base + rva` on the truth
side, `program.to_file_va(entry)` on the engine side, RT8), so a rebased ELF PIE compares
like a PE. Per run:
- function recovery: precision and recall of recovered entries (not thunks / externals)
  against the truth entries, for all functions and for non-library ones (the non-library
  precision ignores recovered entries that are known library functions);
- call-edge, string-reference and import-reference recall (strings match on the exact value,
  imports on the normalized name: `__imp_` / i386 decoration / `@plt` removed);
- decompile success: (`ok` + `truncated`) over attempted (`skipped_budget` is not attempted);
- per stage: status, wall time and peak container memory (from the header, RT14).
The caveat travels with every number (`generate.CAVEAT`).
"""

from typing import Any

from cyberlab_jobs.reverse import DecompileStatus, ReResultHeader

from re_worker.view import ReView
from samples.truth import import_symbol


def _ratio(hits: int, total: int) -> float | None:
    return round(hits / total, 4) if total else None


def measure(
    view: ReView, truth: dict[str, Any], header: ReResultHeader | None = None
) -> dict[str, Any]:
    base = int(truth["preferred_base"])
    truth_va = {f["name"]: base + int(f["rva"]) for f in truth["functions"]}
    all_entries = set(truth_va.values())
    library = {base + int(f["rva"]) for f in truth["functions"] if f["library"]}
    own = all_entries - library

    program = view.program
    file_va = {e: program.to_file_va(e) for e in view.functions}
    recovered = {
        file_va[e] for e, f in view.functions.items() if not f.is_thunk and not f.is_external
    }
    hits_all = recovered & all_entries
    hits_own = recovered & own
    own_candidates = recovered - library

    edges_truth = {(truth_va[e["caller"]], truth_va[e["callee"]]) for e in truth["edges"]}
    edges_seen = {(file_va[c], file_va[d]) for c, d in view.edge_sites}

    strings_truth = {(r["value"], truth_va[r["function"]]) for r in truth["string_refs"]}
    strings_seen = {
        (view.strings[i].value, file_va[e])
        for e in view.functions
        for i in view.strings_referenced(e)
    }
    imports_truth = {
        (import_symbol(r["name"]), truth_va[r["function"]]) for r in truth["import_refs"]
    }
    imports_seen = {
        (import_symbol(name), file_va[e])
        for e in view.functions
        for name in view.import_names_called(e)
    }

    statuses = [d.status for d in view.decompiled.values()]
    attempted = [s for s in statuses if s != DecompileStatus.SKIPPED_BUDGET]
    succeeded = [s for s in attempted if s in (DecompileStatus.OK, DecompileStatus.TRUNCATED)]

    stages: dict[str, Any] = {}
    if header is not None:
        for stage in header.stages:
            stages[str(stage.stage)] = {
                "status": stage.status,
                "duration_ms": stage.duration_ms,
                "peak_memory_bytes": stage.peak_memory_bytes,
                "truncated": stage.truncated,
            }
    return {
        "functions": {
            "truth_all": len(all_entries),
            "truth_non_library": len(own),
            "recovered": len(recovered),
            "precision_all": _ratio(len(hits_all), len(recovered)),
            "recall_all": _ratio(len(hits_all), len(all_entries)),
            "precision_non_library": _ratio(len(hits_own), len(own_candidates)),
            "recall_non_library": _ratio(len(hits_own), len(own)),
        },
        "edges": {
            "truth": len(edges_truth),
            "recall": _ratio(len(edges_truth & edges_seen), len(edges_truth)),
        },
        "string_refs": {
            "truth": len(strings_truth),
            "recall": _ratio(len(strings_truth & strings_seen), len(strings_truth)),
        },
        "import_refs": {
            "truth": len(imports_truth),
            "recall": _ratio(len(imports_truth & imports_seen), len(imports_truth)),
        },
        "decompile": {
            "attempted": len(attempted),
            "succeeded": len(succeeded),
            "success_rate": _ratio(len(succeeded), len(attempted)),
        },
        "stages": stages,
    }
