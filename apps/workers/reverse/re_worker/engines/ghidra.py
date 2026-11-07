"""The `full` profile: Ghidra `analyze`, root's priority list, Ghidra `decompile` (M10 phase 2).

    analyze stage (JVM 1) -> bounded rows -> contract validation, caps -> ReView
      -> priority.rank (phase 5; `listing.py`) -> stage/decompile_list.json (root 0444, RT23)
      -> decompile stage (JVM 2, smaller heap) -> bounded rows -> one record per listed entry

`run_full(ws, job, budget, runner, config, sample)` is shared by the real engine
(`stage.SandboxRunner`) and the replay engine (`replay.ReplayRunner`): only the process is
replaced, every root-side step is the same. Each stage gets `budget.timeout(tool_timeout_s)`
of wall time; `analyze` needs at least `MIN_STAGE_S`, the auto-analysis monitor gets the
stage time minus `EXPORT_RESERVE_S` (capped by `analysis_timeout_s`) so a cancelled analysis
still exports; `decompile` stops `DECOMPILE_RESERVE_S` before its wall timeout and marks the
rest `skipped_budget`. Success rule: `analyze` ok, or timed out / failed after the JVM
started with program facts exported; a `decompile` failure leaves a partial success with
`stages[decompile].status = failed`.
"""

import json
import sys
from collections import Counter
from pathlib import PurePosixPath

from cyberlab_jobs.reverse import (
    AnalysisStatus,
    CodeKind,
    ReDecompiledRecord,
    ReFunctionRecord,
    ReJobV1,
    ReStage,
    StageReport,
)
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from re_worker import jvm_args
from re_worker.config import TOOL_AS_HEADROOM, Config
from re_worker.engines import Budget, EngineOutput, Workspace, workspace
from re_worker.engines.listing import decompile_list
from re_worker.engines.magic import SampleFacts
from re_worker.engines.outcome import Conclusion, conclude
from re_worker.engines.spec import (
    DECOMPILE_LIST,
    ROWS,
    analyze_spec,
    decompile_as,
    decompile_spec,
)
from re_worker.engines.stage import StageRunner, rows_of, status_of
from re_worker.normalize.decompiled import normalize_decompiled
from re_worker.normalize.reader import RowStats, StageStatus
from re_worker.normalize.records import (
    Analysis,
    max_rows,
    normalize_analysis,
    probe_caps,
    program_record,
)
from re_worker.probe.launcher import DECOMPILER, SPAWN_HELPER
from re_worker.view import ReView

MIN_STAGE_S = 30
EXPORT_RESERVE_S = 120
DECOMPILE_RESERVE_S = 15
MAX_RESTARTS = 3
MAX_TRUNCATED = 32
MAX_ENGINE_ERRORS = 32


class Facts:
    """Header facts collected over the stages (root's conclusions only)."""

    def __init__(self) -> None:
        self.stages: list[StageReport] = []
        self.audit: Counter[str] = Counter()
        self.engine_errors: list[str] = []
        self.truncated: dict[str, bool] = {}
        self.jvm_args: list[str] = []

    def error(self, code: str) -> None:
        if code not in self.engine_errors and len(self.engine_errors) < MAX_ENGINE_ERRORS:
            self.engine_errors.append(code)

    def cut(self, key: str) -> None:
        if key not in self.truncated and len(self.truncated) < MAX_TRUNCATED:
            self.truncated[key] = True

    def add(self, conclusion: Conclusion) -> None:
        self.stages.append(conclusion.report)
        self.audit.update(conclusion.audit)
        for code in conclusion.engine_errors:
            self.error(code)
        if not self.jvm_args:
            self.jvm_args = conclusion.jvm_args[:64]

    def rows(self, stage: str, stats: RowStats, status: StageStatus | None) -> None:
        if stats.skipped:
            self.error(f"{stage}_rows_skipped")
        if stats.truncated:
            self.cut(f"{stage}_rows")
        if status is not None:
            for kind, flag in sorted(status.truncated.items()):
                if flag:
                    self.cut(kind)

    def analysis(self, analysis: Analysis) -> None:
        if analysis.invalid:
            self.error("analyze_rows_invalid")
        if analysis.dropped:
            self.error("analyze_rows_dropped")
        for kind in sorted(analysis.capped):
            self.cut(kind)


def _with_ranks(functions: list[ReFunctionRecord], ranked: list[int]) -> list[ReFunctionRecord]:
    rank = {entry: i for i, entry in enumerate(ranked)}
    return [
        f.model_copy(update={"priority_rank": rank[f.entry]}) if f.entry in rank else f
        for f in functions
    ]


def _python() -> str:
    return sys.executable


def analyze_stage(
    ws: Workspace,
    job: ReJobV1,
    budget: Budget,
    runner: StageRunner,
    config: Config,
    sample: SampleFacts,
    facts: Facts,
) -> tuple[Analysis, AnalysisStatus]:
    limits = job.limits
    seconds = budget.timeout(limits.tool_timeout_s)
    if seconds < MIN_STAGE_S:
        raise JobFailed("analysis_timeout", "no time left for the analysis")
    out = PurePosixPath(str(ws.root / "analyze-out"))
    analysis_timeout = max(1, min(limits.analysis_timeout_s, int(seconds) - EXPORT_RESERVE_S))
    spec = analyze_spec(
        python=_python(),
        out=out,
        sample=PurePosixPath(str(ws.sample)),
        loader=sample.loader,
        project=PurePosixPath(str(ws.project)),
        heap=config.jvm_heap,
        as_bytes=config.tool_rlimit_as,
        timeout_s=seconds,
        analysis_timeout_s=analysis_timeout,
        caps=probe_caps(limits),
        java_home=config.java_home,
        ghidra_dir=config.ghidra_dir,
    )
    run = runner.run(ws, spec, limits.max_work_bytes)
    status = status_of(run)
    conclusion = conclude(
        ReStage.ANALYZE,
        run.process,
        status,
        expected_args=jvm_args.expected_args(config.jvm_heap, out),
    )
    facts.add(conclusion)
    if conclusion.fatal is not None:
        raise JobFailed(conclusion.fatal)
    stats = RowStats()
    analysis = normalize_analysis(rows_of(run, ROWS, max_rows(limits), stats), limits)
    facts.rows("analyze", stats, status)
    facts.analysis(analysis)
    if analysis.facts is None:
        raise JobFailed("re_parse_failed", "the analysis exported no program facts")
    if conclusion.report.status == "timeout":
        facts.cut("analysis")
    state: AnalysisStatus = "complete"
    if status is not None and status.analysis_status is not None:
        state = status.analysis_status
    if conclusion.report.status == "failed":
        state = "failed"
    return analysis, state


def decompile_stage(
    ws: Workspace,
    job: ReJobV1,
    budget: Budget,
    runner: StageRunner,
    config: Config,
    listed: list[int],
    facts: Facts,
) -> list[ReDecompiledRecord]:
    limits = job.limits
    seconds = budget.timeout(limits.tool_timeout_s)
    if seconds < MIN_STAGE_S:
        facts.stages.append(StageReport(stage=ReStage.DECOMPILE, status="skipped", truncated=True))
        facts.cut("decompile_budget")
        found = normalize_decompiled((), listed, limits, CodeKind.PSEUDO_C, out_of_time=True)
        return found.records
    listing = {
        "entries": listed,
        "timeout_s": limits.decompile_timeout_s,
        "deadline_s": max(1, int(seconds) - DECOMPILE_RESERVE_S),
        "max_code_bytes": limits.max_code_bytes,
        "max_code_total_bytes": limits.max_code_total_bytes,
        "decompiler_as": config.decompiler_as,
        "max_restarts": MAX_RESTARTS,
    }
    path = workspace.write_stage(ws, DECOMPILE_LIST, json.dumps(listing).encode("ascii"))
    out = PurePosixPath(str(ws.root / "decompile-out"))
    spec = decompile_spec(
        python=_python(),
        out=out,
        project=PurePosixPath(str(ws.project)),
        listing=PurePosixPath(str(path)),
        heap=config.decompile_jvm_heap,
        as_bytes=decompile_as(config.tool_rlimit_as, config.decompile_jvm_heap, TOOL_AS_HEADROOM),
        timeout_s=seconds,
        java_home=config.java_home,
        ghidra_dir=config.ghidra_dir,
    )
    run = runner.run(ws, spec, limits.max_work_bytes)
    status = status_of(run)
    conclusion = conclude(
        ReStage.DECOMPILE,
        run.process,
        status,
        expected_args=jvm_args.expected_args(config.decompile_jvm_heap, out),
        allowed_children=frozenset({str(DECOMPILER.resolve()), str(SPAWN_HELPER.resolve())}),
    )
    if conclusion.compromised:
        sandbox.kill_tool_processes()
        raise sandbox.SandboxCompromised("an unexpected child of the decompile stage")
    if conclusion.fatal is not None:
        facts.add(conclusion)
        raise JobFailed(conclusion.fatal)
    stats = RowStats()
    rows = rows_of(run, ROWS, len(listed) + 16, stats) if conclusion.usable else iter(())
    out_of_time = conclusion.report.status == "timeout"
    found = normalize_decompiled(rows, listed, limits, CodeKind.PSEUDO_C, out_of_time=out_of_time)
    facts.rows("decompile", stats, None)
    if found.dropped:
        facts.error("decompile_rows_dropped")
    skipped = found.statuses().get("skipped_budget", 0)
    if skipped or found.over_budget:
        facts.cut("decompile_budget")
        conclusion.report = conclusion.report.model_copy(update={"truncated": True})
    facts.add(conclusion)
    return found.records


def run_full(
    ws: Workspace,
    job: ReJobV1,
    budget: Budget,
    runner: StageRunner,
    config: Config,
    sample: SampleFacts,
) -> EngineOutput:
    facts = Facts()
    analysis, state = analyze_stage(ws, job, budget, runner, config, sample, facts)
    assert analysis.facts is not None  # noqa: S101 - analyze_stage checked it
    program = program_record(
        sample,
        analysis.facts,
        sha256=job.expected_sha256,
        size_bytes=job.size_bytes,
        analysis_status=state,
        counts=analysis.counts(),
    )
    view = ReView.build(
        program,
        analysis.functions,
        analysis.edges,
        analysis.imports,
        analysis.import_refs,
        analysis.strings,
        analysis.string_refs,
    )
    plan = decompile_list(view, job)
    if plan.missing:
        facts.error("function_not_found")
    ranked = listed = plan.entries  # phase 5's length; never cut again (RT10)
    decompiled: list[ReDecompiledRecord] = []
    if listed:
        decompiled = decompile_stage(ws, job, budget, runner, config, listed, facts)
    else:
        facts.stages.append(StageReport(stage=ReStage.DECOMPILE, status="skipped"))
    counts = {**analysis.counts(), "decompiled": len(decompiled), "ranked": len(ranked)}
    return EngineOutput(
        program=program.model_copy(update={"counts": counts}),
        functions=_with_ranks(analysis.functions, ranked),
        edges=analysis.edges,
        imports=analysis.imports,
        import_refs=analysis.import_refs,
        strings=analysis.strings,
        string_refs=analysis.string_refs,
        decompiled=decompiled,
        stages=facts.stages,
        tool_versions=runner.tool_versions(),
        audit=dict(facts.audit),
        jvm_args=facts.jvm_args,
        engine_errors=facts.engine_errors,
        truncated=facts.truncated,
    )


__all__ = [
    "DECOMPILE_RESERVE_S",
    "EXPORT_RESERVE_S",
    "MIN_STAGE_S",
    "Facts",
    "analyze_stage",
    "decompile_stage",
    "run_full",
]
