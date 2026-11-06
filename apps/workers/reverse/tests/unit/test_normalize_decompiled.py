"""`decompile` stage rows -> one record per listed entry (pure Python): root accepts only what
it listed, keeps the code caps and the job's code budget, and names every missing function."""

from cyberlab_jobs.reverse import (
    TRUNCATION_MARKER,
    CodeKind,
    DecompileStatus,
    code_sha256,
)

from re_worker.normalize.decompiled import cut_code, normalize_decompiled, record_for
from tests.stage_helpers import LIMITS, decompiled_entries, rows

S = DecompileStatus


def test_cut_code_on_a_line_boundary_with_the_marker() -> None:
    code = "".join(f"line {i:05d} é中\n" for i in range(5000))
    text, cut = cut_code(code, 4096)
    assert len(text.encode()) <= 4096 and cut > 0
    assert text.endswith(TRUNCATION_MARKER.format(n=cut))
    assert text.removesuffix(TRUNCATION_MARKER.format(n=cut)).endswith("\n")
    assert len(code.encode()) - cut == len(text.removesuffix(TRUNCATION_MARKER.format(n=cut)).encode())
    assert cut_code("short\n", 4096) == ("short\n", 0)
    assert cut_code("x" * 100, 10) == ("", 100)  # no room even for the marker


def test_record_for_matches_the_contract() -> None:
    record = record_for(1, "int f(void)\n{\n  return 0;\n}\n" * 3000, S.OK, CodeKind.PSEUDO_C,
                        max_bytes=1024)  # fmt: skip
    assert record.status == S.TRUNCATED and record.truncated_bytes > 0
    assert record.code_sha256 == code_sha256(record.code or "")
    assert record_for(2, None, S.TIMEOUT, CodeKind.PSEUDO_C, max_bytes=1024).code is None


def test_fixture_rows_for_the_listed_entries() -> None:
    listed = list(decompiled_entries())
    found = normalize_decompiled(
        rows("pe_full", "decompile"), listed, LIMITS, CodeKind.PSEUDO_C, out_of_time=False
    )
    assert [r.function_entry for r in found.records] == listed
    assert found.statuses() == {"ok": 4, "truncated": 1, "timeout": 1}
    assert not found.dropped


def test_unlisted_duplicate_and_wrong_kind_rows_are_dropped() -> None:
    lines = rows("pe_full", "decompile")
    listed = [lines[0]["function_entry"]]
    wrong_kind = {**lines[0], "code_kind": "disasm"}
    found = normalize_decompiled(
        [wrong_kind, lines[0], lines[0], lines[1], {"kind": "decompiled"}, {"kind": "x"}],
        listed,
        LIMITS,
        CodeKind.PSEUDO_C,
        out_of_time=False,
    )
    assert [r.status for r in found.records] == [S.OK]
    assert found.dropped == {"code_kind": 1, "duplicate": 1, "not_listed": 1, "invalid": 1, "kind": 1}


def test_missing_entries_and_the_code_budget() -> None:
    lines = rows("pe_full", "decompile")
    listed = [r["function_entry"] for r in lines] + [0xDEAD]
    failed = normalize_decompiled([], listed, LIMITS, CodeKind.PSEUDO_C, out_of_time=False)
    assert {r.status for r in failed.records} == {S.FAILED}
    late = normalize_decompiled([], listed, LIMITS, CodeKind.PSEUDO_C, out_of_time=True)
    assert {r.status for r in late.records} == {S.SKIPPED_BUDGET}
    first = len((lines[0]["code"]).encode())
    tight = LIMITS.model_copy(update={"max_code_total_bytes": first})
    budget = normalize_decompiled(lines, listed, tight, CodeKind.PSEUDO_C, out_of_time=False)
    assert budget.records[0].status == S.OK and budget.over_budget
    assert budget.records[1].status == S.SKIPPED_BUDGET and budget.code_bytes == first
    small = LIMITS.model_copy(update={"max_code_bytes": 32})
    capped = normalize_decompiled(lines, listed, small, CodeKind.PSEUDO_C, out_of_time=False)
    assert capped.dropped["too_long"] >= 1
