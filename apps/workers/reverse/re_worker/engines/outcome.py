"""What root concludes about one stage run (M10 phases 2 and 3). Pure Python, unit-tested.

Root decides from what it measured itself (how the process ended, its exit code, the
watchdog, the `hs_err.log` file) and checks every claim of the untrusted `status.json` it
can check. Rules (`conclude`):

- the watchdog killed the stage above `max_work_bytes` (RT5): the job fails
  `re_work_too_large` (any stage);
- a cgroup OOM kill or exit code 3 (`ExitOnOutOfMemoryError`, RT14): the job fails
  `re_out_of_memory`; for `decompile` only the stage fails (the functions so far are kept);
- no valid status after a wall-timeout kill: the job fails `analysis_timeout`; `decompile`
  is `timeout` / `decompile_timeout`;
- no valid status otherwise, or the JVM never started: the job fails `jvm_start_failed`
  (`re_parse_failed` for the radare2 reducer); `decompile` is `failed` / `jvm_start_failed`;
- effective JVM arguments that differ from the expected list (RT1): the job fails
  `jvm_start_failed` (both JVM stages);
- a `decompile` child that is neither `jspawnhelper` nor the decompiler (RT15):
  `compromised` (the job fails, the container is suspect);
- an `error_code` in the status (`re_parse_failed`, ...): the job fails with it; `decompile`
  is `failed` with it;
- the analysis monitor cancelled the analysis: stage `timeout`, `truncated`, export kept;
- any other failure after the JVM started: stage `failed`, rows kept when usable.

Engine errors: `jvm_crash` (an `hs_err.log` exists; its content is never read),
`audit_refusals` (the audit hook refused something), `<stage>_rows_skipped`.
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from cyberlab_jobs.reverse import ReStage, StageReport, StageRunStatus

from re_worker import jvm_args
from re_worker.normalize.reader import StageStatus
from re_worker.probe.guard import FAMILIES

ProcessEnd = Literal["exited", "failed", "timeout"]
OOM_EXIT = 3  # -XX:+ExitOnOutOfMemoryError
# Arguments the embedding adds to every JVM it starts (JPype's class path) [I: the spike lists
# the exact 12.2 / PyGhidra 3.2 set; anything else not in our list is a mismatch].
LAUNCHER_ADDED_PREFIXES = ("-Djava.class.path=",)
AUDIT_PREFIX = "child:"


@dataclass(frozen=True)
class ProcessResult:
    end: ProcessEnd
    returncode: int | None
    duration_ms: int
    work_too_large: bool = False
    oom_killed: bool = False
    peak_memory_bytes: int | None = None
    hs_err: bool = False


@dataclass
class Conclusion:
    report: StageReport
    fatal: str | None = None  # the job fails with this code
    compromised: bool = False  # an unexpected child process (RT15)
    usable: bool = False  # the stage's rows may be read
    engine_errors: list[str] = field(default_factory=list)
    audit: Counter[str] = field(default_factory=Counter)
    jvm_args: list[str] = field(default_factory=list)


def effective_args(reported: Sequence[str]) -> list[str]:
    return [a for a in reported if not a.startswith(LAUNCHER_ADDED_PREFIXES)]


def _audit(status: StageStatus | None) -> Counter[str]:
    counts: Counter[str] = Counter()
    if status is None:
        return counts
    for key, n in status.audit.items():
        if n > 0 and (key in FAMILIES or key.startswith(AUDIT_PREFIX)):
            counts[key] += n
    return counts


def conclude(
    stage: ReStage,
    proc: ProcessResult,
    status: StageStatus | None,
    *,
    expected_args: Sequence[str] | None = None,
    allowed_children: frozenset[str] = frozenset(),
) -> Conclusion:
    jvm = expected_args is not None
    primary = stage != ReStage.DECOMPILE  # its failure fails the job

    def report(state: StageRunStatus, code: str | None = None, cut: bool = False) -> StageReport:
        return StageReport(
            stage=stage,
            status=state,
            duration_ms=proc.duration_ms,
            error_code=code,
            truncated=cut,
            peak_memory_bytes=proc.peak_memory_bytes,
        )

    result = Conclusion(report=report("failed"), audit=_audit(status))
    if proc.hs_err:
        result.engine_errors.append("jvm_crash")
    if any(result.audit[f] for f in FAMILIES):
        result.engine_errors.append("audit_refusals")
    if status is not None:
        result.jvm_args = list(status.jvm_args)

    if proc.work_too_large:
        result.report, result.fatal = report("failed", "re_work_too_large"), "re_work_too_large"
        return result
    if proc.oom_killed or proc.returncode == OOM_EXIT:
        result.report = report("failed", "re_out_of_memory")
        result.fatal = "re_out_of_memory" if primary else None
        result.usable = not primary and status is not None
        return result
    if status is None or (jvm and not status.jvm_started):
        if proc.end == "timeout":
            code = "analysis_timeout" if primary else "decompile_timeout"
            result.report = report("timeout", code)
        else:
            code = "jvm_start_failed" if jvm else "re_parse_failed"
            result.report = report("failed", code)
        result.fatal = code if primary else None
        return result
    if jvm:
        assert expected_args is not None  # noqa: S101 - jvm
        if jvm_args.mismatch(effective_args(status.jvm_args), expected_args):
            result.report = report("failed", "jvm_start_failed")
            result.fatal = "jvm_start_failed"
            return result
    if stage == ReStage.DECOMPILE:
        strangers = [c for c in status.children if c not in allowed_children]
        if strangers or result.audit.get(f"{AUDIT_PREFIX}other", 0):
            result.report, result.compromised = report("failed", "re_parse_failed"), True
            return result
    if status.error_code is not None:
        result.report = report("failed", status.error_code)
        result.fatal = status.error_code if primary else None
        result.usable = not primary
        return result
    result.usable = True
    if status.status == "failed" or proc.end != "exited":
        if proc.end == "timeout":
            code = "analysis_timeout" if primary else "decompile_timeout"
            result.report = report("timeout", code, cut=True)
        else:
            result.report = report("failed", cut=True)
        return result
    if status.analysis_status == "timeout":
        result.report = report("timeout", "analysis_timeout", cut=True)
        return result
    result.report = report("ok", cut=any(status.truncated.values()))
    return result


__all__ = [
    "LAUNCHER_ADDED_PREFIXES",
    "OOM_EXIT",
    "Conclusion",
    "ProcessEnd",
    "ProcessResult",
    "conclude",
    "effective_args",
]
