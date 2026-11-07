"""Decompile priority (M10 phase 5): every class, ties, the cap, requested and missing
addresses, capa file VAs on a rebased PIE, determinism under shuffled input."""

import random

from cyberlab_jobs.reverse import ReCallEdgeRecord, ReImportRefRecord, ReStringRefRecord

from dataset.generate import PIE_BASE, Builder, build, entry_names, job
from re_worker import priority
from re_worker.view import ReView


def _names(view: ReView, entries: list[int]) -> list[str]:
    names = entry_names(view)
    return [names[e] for e in entries]


def test_classes_in_order() -> None:
    scenario = build("prio_classes")
    order = _names(scenario.view, priority.rank(scenario.view, scenario.job))
    assert order == [
        "cleanup",  # 1: requested
        "start",  # 2: entry point (and export)
        "exported_api",  # 2: export
        "capa_hit",  # 3: capa file VA
        "suspicious_caller",  # 4: calls VirtualAllocEx through a thunk
        "ioc_user",  # 5: references a URL
        "big_plain",  # 6: by size, descending
        "main",
        "parse_args",
    ]
    assert priority.missing_addresses(scenario.view, scenario.job) == [0x1]
    assert "library_fn" not in order and "VirtualAllocEx" not in order


def test_ranks_are_the_list_indexes() -> None:
    scenario = build("prio_classes")
    ranks = priority.ranks(scenario.view, scenario.job)
    order = priority.rank(scenario.view, scenario.job)
    assert ranks == {entry: i for i, entry in enumerate(order)}


def test_capa_file_va_on_a_rebased_pie() -> None:
    scenario = build("prio_pie_capa")
    assert scenario.view.program.image_base == PIE_BASE
    assert _names(scenario.view, priority.rank(scenario.view, scenario.job))[:2] == [
        "start",
        "capa_hit",
    ]


def test_requested_addresses_are_never_cut_by_the_cap() -> None:
    scenario = build("prio_cap")
    assert scenario.job.limits.max_decompiled == 2
    order = _names(scenario.view, priority.rank(scenario.view, scenario.job))
    assert order == ["plain_0", "plain_1", "plain_2"]


def test_cap_cuts_the_other_classes() -> None:
    b = Builder()
    b.entry_name = "start"
    b.fn("start", 0x20, source="export")
    for i in range(10):
        b.fn(f"f{i}", 0x100 - i)
    view = b.view()
    order = _names(view, priority.rank(view, job(max_decompiled=4)))
    assert order == ["start", "f0", "f1", "f2"]
    assert priority.rank(view, job(max_decompiled=0)) == []


def test_ties_break_by_entry_and_size() -> None:
    b = Builder()
    for name in ("a", "b", "c"):
        b.fn(name, 0x40, source="export")
    b.fn("same_1", 0x80)
    b.fn("same_2", 0x80)
    view = b.view()
    assert _names(view, priority.rank(view, job())) == ["a", "b", "c", "same_1", "same_2"]


def test_requested_external_is_missing() -> None:
    b = Builder()
    b.fn("main", 0x40)
    ext = b.fn("ExitProcess", 0x0, source="import", external=True)
    view = b.view()
    request = job(decompile_addresses=[ext, b.entry("main")])
    assert priority.missing_addresses(view, request) == [ext]
    assert priority.rank(view, request) == [b.entry("main")]


def test_rank_is_deterministic_under_shuffled_records() -> None:
    scenario = build("prio_classes")
    view = scenario.view
    expected = priority.rank(view, scenario.job)
    rng = random.Random(7)
    for _ in range(20):
        functions = list(view.functions.values())
        rng.shuffle(functions)
        refs = [
            (index, entry)
            for index in view.strings
            for entry in view.string_referrers(index)
        ]
        rng.shuffle(refs)
        edges = list(view.edge_sites)
        rng.shuffle(edges)
        rebuilt = ReView.build(
            view.program,
            functions,
            [ReCallEdgeRecord(caller=c, callee=d) for c, d in edges],
            list(view.imports.values()),
            [
                ReImportRefRecord(import_index=i, function_entry=e)
                for i in view.imports
                for e in view.import_callers(i)
            ],
            list(view.strings.values()),
            [ReStringRefRecord(string_index=i, function_entry=e) for i, e in refs],
        )
        assert priority.rank(rebuilt, scenario.job) == expected
