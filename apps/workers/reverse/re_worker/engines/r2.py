"""The radare2 `quick` profile (M10 phase 3; the signature `run_quick(ws, job, budget)` is
frozen in phase 1).

    radare2 -q -NN -S -2 -i /opt/re/r2/quick.r2 <sample>    (uid 10010, stdout r2.out)
      -> python -I -s -B -m re_worker.probe r2 ...            (uid 10010, the same out dir)
      -> bounded rows -> the same validation, caps and records as the Ghidra `analyze` stage

One non-interactive run of the fixed, root-owned script (RT9: no r2pipe, no command built at
run time, no decompilation, no ESIL, no debugger), then the reducer probe (`probe/r2.py`), both
under the kit sandbox (`unix_sockets_only`, `deny_io_uring`) and the watchdog; the out dir is
sealed after the reducer. The stage time is `budget.timeout(quick_timeout_s)`; the reducer gets
`REDUCER_S` of it. Header: `engine: radare2`, `code_kind: disasm`, one `r2` stage, no JVM
arguments, no decompiled lines.

Unavailable (the radare2 binary or the script is missing from the image): `ProfileUnavailable`
(the analyzer reports `profile_unavailable`; the API refuses `quick` while
`RE_QUICK_ENABLED=false`). The no-go fallback (`full` through radare2 + `pdfj`) is not built:
the phase-2 spike has not decided it.
"""

import re
import sys
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from cyberlab_jobs.reverse import ReJobV1, ReStage, StageReport
from cyberlab_worker.errors import JobFailed

from re_worker.config import QUICK_SCRIPT
from re_worker.engines import Budget, EngineOutput, ProfileUnavailable, Workspace
from re_worker.engines.magic import SampleFacts
from re_worker.engines.spec import (
    R2_BINARY,
    R2_MAX_OUTPUT_BYTES,
    R2_OUTPUT,
    ROWS,
    r2_spec,
    reducer_spec,
)
from re_worker.normalize.reader import RowStats
from re_worker.normalize.records import max_rows, normalize_analysis, probe_caps, program_record

if TYPE_CHECKING:  # the kit's sandbox does not import off Linux (host unit tests)
    from re_worker.engines.stage import StageRunner

MIN_QUICK_S = 20
REDUCER_S = 120
ERROR_CODE = r"^[a-z][a-z_]{0,63}$"


def available() -> bool:
    return R2_BINARY.is_file() and QUICK_SCRIPT.is_file()


def run_quick(ws: Workspace, job: ReJobV1, budget: Budget) -> EngineOutput:
    if not available():
        raise ProfileUnavailable()
    from re_worker.engines.magic import UnsupportedFormat, inspect
    from re_worker.engines.stage import SandboxRunner

    try:
        sample = inspect(ws.sample)
    except UnsupportedFormat as exc:
        raise JobFailed("unsupported_format", str(exc)) from exc
    return quick_with(ws, job, budget, SandboxRunner(), sample)


def split_time(seconds: float) -> tuple[float, float]:
    """(radare2, reducer) seconds of one quick stage."""
    reducer = min(float(REDUCER_S), max(10.0, seconds / 4))
    return max(1.0, seconds - reducer), reducer


def quick_with(
    ws: Workspace,
    job: ReJobV1,
    budget: Budget,
    runner: "StageRunner",
    sample: SampleFacts,
) -> EngineOutput:
    """The quick stage with any `StageRunner` (the sandbox, or the replay engine)."""
    from re_worker.engines import workspace
    from re_worker.engines.outcome import conclude
    from re_worker.engines.stage import output_size, rows_of, status_of

    limits = job.limits
    seconds = budget.timeout(limits.quick_timeout_s)
    if seconds < MIN_QUICK_S:
        raise JobFailed("analysis_timeout", "no time left for the quick analysis")
    r2_seconds, reducer_seconds = split_time(seconds)
    dirs = workspace.fresh(ws, "r2")
    out = PurePosixPath(str(dirs.out))
    first = runner.run(
        ws,
        r2_spec(script=QUICK_SCRIPT, sample=PurePosixPath(str(ws.sample)), timeout_s=r2_seconds),
        limits.max_work_bytes,
        dirs=dirs,
        seal=False,
    )
    if first.process.work_too_large:
        raise JobFailed("re_work_too_large")
    if first.process.oom_killed:
        raise JobFailed("re_out_of_memory")
    size = output_size(first, R2_OUTPUT) or 0
    reducer = reducer_spec(
        python=sys.executable, out=out, timeout_s=reducer_seconds, caps=probe_caps(limits)
    )
    second = runner.run(ws, reducer, limits.max_work_bytes, dirs=dirs, seal=True)
    status = status_of(second)
    conclusion = conclude(ReStage.R2, second.process, status)
    if conclusion.fatal is not None:
        raise JobFailed(conclusion.fatal)
    stats = RowStats()
    analysis = normalize_analysis(rows_of(second, ROWS, max_rows(limits), stats), limits)
    if analysis.facts is None:
        raise JobFailed("re_parse_failed", "the radare2 output gave no program facts")

    truncated: dict[str, bool] = {}
    errors: list[str] = []
    cut = first.process.end != "exited" or size >= R2_MAX_OUTPUT_BYTES
    if cut:
        truncated["r2_output"] = True
    if status is not None:
        truncated.update({k: True for k, v in status.truncated.items() if v})
        errors.extend(e for e in status.engine_errors if re.fullmatch(ERROR_CODE, e))
    truncated.update({kind: True for kind in sorted(analysis.capped)})
    if stats.truncated:
        truncated["r2_rows"] = True
    if stats.skipped:
        errors.append("quick_rows_skipped")
    if analysis.invalid:
        errors.append("quick_rows_invalid")
    if analysis.dropped:
        errors.append("quick_rows_dropped")
    errors.extend(conclusion.engine_errors)
    timed_out = first.process.end == "timeout"
    report = StageReport(
        stage=ReStage.R2,
        status="timeout" if timed_out else conclusion.report.status,
        duration_ms=first.process.duration_ms + second.process.duration_ms,
        error_code="analysis_timeout" if timed_out else conclusion.report.error_code,
        truncated=bool(truncated),
        peak_memory_bytes=max(
            first.process.peak_memory_bytes or 0, second.process.peak_memory_bytes or 0
        )
        or None,
    )
    program = program_record(
        sample,
        analysis.facts,
        sha256=job.expected_sha256,
        size_bytes=job.size_bytes,
        analysis_status="timeout" if timed_out else "complete",
        counts=analysis.counts(),
    )
    return EngineOutput(
        program=program,
        functions=analysis.functions,
        edges=analysis.edges,
        imports=analysis.imports,
        import_refs=analysis.import_refs,
        strings=analysis.strings,
        string_refs=analysis.string_refs,
        stages=[report],
        tool_versions=runner.tool_versions(),
        audit=dict(conclusion.audit),
        engine_errors=list(dict.fromkeys(errors))[:32],
        truncated=dict(list(truncated.items())[:32]),
    )


__all__ = ["MIN_QUICK_S", "REDUCER_S", "available", "quick_with", "run_quick", "split_time"]
