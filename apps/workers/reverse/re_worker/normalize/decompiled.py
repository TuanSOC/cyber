"""`decompile` stage rows -> `ReDecompiledRecord`s (root side, pure Python; M10 phase 2).

Root decides what was asked (the list it wrote, RT23) and accepts only that:
- a row for an entry root did not list, a second row for an entry, or a row the contract
  refuses (code without its sha256 / line count, code kind other than the stage's, NUL,
  lone surrogates, ...) is dropped and counted;
- a code text above `limits.max_code_bytes` is dropped (the probe cuts at the same value on
  a line boundary with `TRUNCATION_MARKER`; a longer text means it did not);
- the job's code budget (`limits.max_code_total_bytes`) holds: a code text that would pass it
  becomes `skipped_budget` (no code);
- every listed entry gets exactly one record, in list order: a listed function without a
  row is `skipped_budget` when the stage ran out of time (its deadline, its wall timeout or
  the job budget) and `failed` otherwise (the stage crashed or the probe skipped it).

`cut_code` is the probe's cut (shared so both sides agree on the marker and the bound).
"""

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from cyberlab_jobs.reverse import (
    TRUNCATION_MARKER,
    CodeKind,
    DecompileStatus,
    ReDecompiledRecord,
    ReLimits,
    code_lines,
    code_sha256,
)
from pydantic import ValidationError


@dataclass
class Decompiled:
    records: list[ReDecompiledRecord] = field(default_factory=list)
    dropped: Counter[str] = field(default_factory=Counter)
    code_bytes: int = 0
    over_budget: bool = False

    def statuses(self) -> Counter[str]:
        return Counter(str(r.status) for r in self.records)


def cut_code(code: str, max_bytes: int) -> tuple[str, int]:
    """`code` within `max_bytes` UTF-8 bytes: cut at the last line boundary that leaves room
    for the marker line, which says how many bytes were cut. Returns (text, cut bytes)."""
    data = code.encode("utf-8")
    if len(data) <= max_bytes:
        return code, 0
    marker_room = len(TRUNCATION_MARKER.format(n=len(data)).encode("utf-8")) + 1
    if marker_room > max_bytes:
        return "", len(data)  # no room even for the marker (a tiny test cap)
    limit = max_bytes - marker_room
    head = data[:limit]
    newline = head.rfind(b"\n")
    head = head[: newline + 1] if newline >= 0 else b""
    kept = head.decode("utf-8", "ignore")
    cut = len(data) - len(kept.encode("utf-8"))
    return kept + TRUNCATION_MARKER.format(n=cut), cut


def _empty(entry: int, status: DecompileStatus, code_kind: CodeKind) -> ReDecompiledRecord:
    return ReDecompiledRecord(function_entry=entry, status=status, code_kind=code_kind)


def normalize_decompiled(
    rows: Iterable[dict[str, Any]],
    listed: Sequence[int],
    limits: ReLimits,
    code_kind: CodeKind,
    *,
    out_of_time: bool,
) -> Decompiled:
    result = Decompiled()
    wanted = set(listed)
    found: dict[int, ReDecompiledRecord] = {}
    for row in rows:
        if row.get("kind") != "decompiled":
            result.dropped["kind"] += 1
            continue
        try:
            record = ReDecompiledRecord.model_validate(row)
        except (ValidationError, ValueError, TypeError):
            result.dropped["invalid"] += 1
            continue
        entry = record.function_entry
        if entry not in wanted:
            result.dropped["not_listed"] += 1
            continue
        if entry in found:
            result.dropped["duplicate"] += 1
            continue
        if record.code_kind != code_kind:
            result.dropped["code_kind"] += 1
            continue
        if record.code is not None:
            size = len(record.code.encode("utf-8"))
            if size > limits.max_code_bytes:
                result.dropped["too_long"] += 1
                continue
            if result.code_bytes + size > limits.max_code_total_bytes:
                result.over_budget = True
                record = _empty(entry, DecompileStatus.SKIPPED_BUDGET, code_kind)
            else:
                result.code_bytes += size
        found[entry] = record
    missing = DecompileStatus.SKIPPED_BUDGET if out_of_time else DecompileStatus.FAILED
    result.records = [found.get(e) or _empty(e, missing, code_kind) for e in listed]
    return result


def record_for(
    entry: int,
    code: str | None,
    status: DecompileStatus,
    code_kind: CodeKind,
    *,
    max_bytes: int,
    duration_ms: int = 0,
) -> ReDecompiledRecord:
    """A valid record for one function (the probe's writer; the replay fixtures)."""
    if code is None or status not in (DecompileStatus.OK, DecompileStatus.TRUNCATED):
        return ReDecompiledRecord(
            function_entry=entry, status=status, code_kind=code_kind, duration_ms=duration_ms
        )
    text, cut = cut_code(code, max_bytes)
    return ReDecompiledRecord(
        function_entry=entry,
        status=DecompileStatus.TRUNCATED if cut else DecompileStatus.OK,
        code_kind=code_kind,
        code=text,
        lines=code_lines(text),
        code_sha256=code_sha256(text),
        truncated_bytes=cut,
        duration_ms=duration_ms,
    )


__all__ = ["Decompiled", "cut_code", "normalize_decompiled", "record_for"]
