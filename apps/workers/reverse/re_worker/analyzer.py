"""Reverse engineering of one sample (M10 phases 2 and 3; frozen `analyze(job, dirs, config)`).

    size checks -> free space (RT5) -> download (sha256 + size verified, root-owned 0444)
      -> root magic check (loader or diagnostic) -> engine:
           full:  Ghidra `analyze` -> rank -> Ghidra `decompile`      (engines/ghidra.py)
           quick: radare2 once + its reducer probe                    (engines/r2.py)
           replay (TEST_PROFILE only): the same root code over hand-written stage rows
      -> ReView -> detections (phase 5) -> `re.v1` (result.py) -> path

`analyze` returns the written result, raises `DiagnosticResult(code, path)` after writing
the diagnostic stream (`unsupported_architecture`, `unsupported_managed_code`: header,
program, trailer), or raises `JobFailed(code)` with an `RE_ERROR_CODES` code. Root never
parses the sample beyond the magic check; everything else it reads is bounded stage output.
The sample is never executed.
"""

from pathlib import Path

from cyberlab_jobs.reverse import DIAGNOSTIC_ERROR_CODES, ReJobV1, ReProfile
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed
from cyberlab_worker.transfer import download

from re_worker import detections
from re_worker.config import Config, tool_versions
from re_worker.engines import Budget, EngineOutput, ProfileUnavailable, Workspace, workspace
from re_worker.engines.ghidra import run_full
from re_worker.engines.magic import SampleFacts, UnsupportedFormat, inspect
from re_worker.engines.replay import ReplayRunner
from re_worker.engines.stage import SandboxRunner, StageRunner
from re_worker.normalize.records import diagnostic_program
from re_worker.result import RESULT, engine_for, write_diagnostic, write_result
from re_worker.view import ReView

# Slack for housekeeping after the last stage (detections, writing, upload, report).
RESERVE_S = 60


class DiagnosticResult(Exception):  # noqa: N818 - a result, not an error
    """The diagnostic stream was written: upload it with a failed report and this code."""

    def __init__(self, code: str, path: Path) -> None:
        if code not in DIAGNOSTIC_ERROR_CODES:
            raise ValueError(f"not a diagnostic code: {code}")
        super().__init__(code)
        self.code = code
        self.path = path


def runner_for(config: Config) -> StageRunner:
    return ReplayRunner() if config.engine == "replay" else SandboxRunner()


def analyze(job: ReJobV1, dirs: sandbox.JobDirs, config: Config) -> Path:
    if job.size_bytes == 0:
        raise JobFailed("unsupported_format", "empty sample")
    if job.size_bytes > job.limits.max_bytes:
        raise JobFailed("re_sample_too_large")
    workspace.check_free_space(config.work_dir, job.size_bytes, job.limits.max_work_bytes)
    # The job's wall clock starts now: the download counts against it.
    budget = Budget.starting_now(max(0, job.limits.timeout_s - RESERVE_S))
    ws = workspace.create(dirs)
    download(
        job.evidence_url,
        ws.sample,
        expected_sha256=job.expected_sha256,
        size_bytes=job.size_bytes,
        max_bytes=job.limits.max_bytes,
        too_large_code="re_sample_too_large",
    )
    return analyze_sample(ws, job, config, budget, runner_for(config))


def sample_facts(ws: Workspace, job: ReJobV1) -> SampleFacts:
    try:
        facts = inspect(ws.sample)
    except UnsupportedFormat as exc:
        raise JobFailed("unsupported_format", str(exc)) from exc
    if facts.format != job.file_format:
        raise JobFailed("unsupported_format", "the format differs from the static analysis")
    return facts


def _engine_output(
    ws: Workspace,
    job: ReJobV1,
    config: Config,
    budget: Budget,
    runner: StageRunner,
    sample: SampleFacts,
) -> EngineOutput:
    if job.profile == ReProfile.QUICK:
        from re_worker.engines import r2

        try:
            if isinstance(runner, ReplayRunner):  # hand-written reducer rows (test profile)
                return r2.quick_with(ws, job, budget, runner, sample)
            return r2.run_quick(ws, job, budget)
        except ProfileUnavailable as exc:
            raise JobFailed("profile_unavailable") from exc
    return run_full(ws, job, budget, runner, config, sample)


def analyze_sample(
    ws: Workspace, job: ReJobV1, config: Config, budget: Budget, runner: StageRunner
) -> Path:
    """Everything after the download (the sample is at `ws.sample`, hash-verified)."""
    sample = sample_facts(ws, job)
    replay = isinstance(runner, ReplayRunner)
    if replay:
        runner.select(ws)
    if sample.diagnostic is not None:
        program = diagnostic_program(sample, sha256=job.expected_sha256, size_bytes=job.size_bytes)
        versions = runner.tool_versions() if replay else tool_versions()
        path = write_diagnostic(
            ws.root / RESULT, job, program, tool_versions=versions, replay=replay
        )
        raise DiagnosticResult(sample.diagnostic, path)
    output = _engine_output(ws, job, config, budget, runner, sample)
    sandbox.kill_tool_processes()
    view = ReView.build(
        output.program,
        output.functions,
        output.edges,
        output.imports,
        output.import_refs,
        output.strings,
        output.string_refs,
        output.decompiled,
    )
    found = detections.run(view, job.limits)
    engine, code_kind = engine_for(job.profile, runner.name)
    return write_result(ws.root / RESULT, job, engine, code_kind, output, found)


__all__ = ["RESERVE_S", "DiagnosticResult", "analyze", "analyze_sample", "runner_for"]
