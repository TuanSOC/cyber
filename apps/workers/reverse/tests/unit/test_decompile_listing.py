"""Root's decompile list from phase 5's priority (pure Python; RT10): requested addresses are
never cut by root, whatever `max_decompiled` says; requested addresses that are not functions
are reported (`function_not_found`); externals and unknown entries never reach the stage."""

from re_worker.engines.listing import decompile_list
from re_worker.normalize.records import normalize_analysis, program_record
from re_worker.view import ReView
from tests.stage_helpers import LIMITS, SHA, decompiled_entries, job, pe_header, rows


def _view() -> ReView:
    from re_worker.engines.magic import inspect_bytes

    analysis = normalize_analysis(rows("pe_full", "analyze"), LIMITS)
    assert analysis.facts is not None
    program = program_record(
        inspect_bytes(pe_header()),
        analysis.facts,
        sha256=SHA,
        size_bytes=1024,
        analysis_status="complete",
        counts={},
    )
    return ReView.build(
        program,
        analysis.functions,
        analysis.edges,
        analysis.imports,
        analysis.import_refs,
        analysis.strings,
        analysis.string_refs,
    )


def test_requested_addresses_survive_a_small_max_decompiled() -> None:
    view = _view()
    requested = decompiled_entries("pe_full")
    small = LIMITS.model_copy(update={"max_decompiled": 2})
    plan = decompile_list(view, job(decompile=requested, limits=small))
    assert plan.entries[: len(requested)] == list(requested)
    assert len(plan.entries) == len(requested)  # max(max_decompiled, requested), not cut to 2
    assert plan.missing == []


def test_missing_and_external_requests_are_reported_not_listed() -> None:
    view = _view()
    thunk = next(e for e, f in view.functions.items() if f.is_external)
    requested = (0xDEAD0000, thunk, decompiled_entries("pe_full")[0])
    plan = decompile_list(view, job(decompile=requested))
    assert plan.missing == [0xDEAD0000, thunk]
    assert plan.entries[0] == requested[2]
    assert 0xDEAD0000 not in plan.entries and thunk not in plan.entries
    assert len(plan.entries) == len(set(plan.entries))
    assert all(not view.functions[e].is_external for e in plan.entries)
