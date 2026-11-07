"""Writing one `re.v1` stream (root side, pure Python over validated records; M10 phase 2).

    header, program, function*, call_edge*, import*, import_ref*, string*, string_ref*,
    decompiled*, finding*, ioc*, trailer

The header carries root's conclusions only: the stage reports (with root's peak-memory
measurement, RT14), the audit counts, the effective JVM arguments (RT1), engine errors and
`truncated` flags (both bounded). Before anything is written the whole stream passes the
contract's own `StreamChecker` (the ingest's rules): a stream the ingest would refuse is
never uploaded (`re_parse_failed`). Findings and IOCs above their caps are cut and flagged.

A diagnostic stream (`unsupported_architecture`, `unsupported_managed_code`) is header,
program, trailer.
"""

from collections.abc import Iterable, Iterator
from pathlib import Path

from cyberlab_jobs.results import FindingRecord, IocRecord
from cyberlab_jobs.reverse import (
    CodeKind,
    ReEngine,
    ReJobV1,
    ReProfile,
    ReProgramRecord,
    ReResultHeader,
    StreamChecker,
    StreamRefused,
)
from cyberlab_worker.errors import JobFailed
from cyberlab_worker.result_writer import ResultWriter
from pydantic import BaseModel

from re_worker.engines import EngineOutput
from re_worker.view import DetectionOutput

RESULT = "result.ndjson.gz"
MAX_TRUNCATED = 32
MAX_ENGINE_ERRORS = 32
MAX_AUDIT = 16


def engine_for(profile: ReProfile, runner_name: str) -> tuple[ReEngine, CodeKind]:
    if runner_name == "replay":
        kind = CodeKind.DISASM if profile == ReProfile.QUICK else CodeKind.PSEUDO_C
        return ReEngine.REPLAY, kind
    if profile == ReProfile.QUICK:
        return ReEngine.RADARE2, CodeKind.DISASM
    return ReEngine.GHIDRA, CodeKind.PSEUDO_C


def header(
    job: ReJobV1,
    engine: ReEngine,
    code_kind: CodeKind,
    output: EngineOutput | None,
    *,
    extra_truncated: dict[str, bool] | None = None,
    extra_errors: Iterable[str] = (),
    tool_versions: dict[str, str] | None = None,
) -> ReResultHeader:
    truncated: dict[str, bool] = {}
    errors: list[str] = []
    audit: dict[str, int] = {}
    stages = []
    jvm: list[str] = []
    versions = tool_versions or {}
    if output is not None:
        truncated.update({k: True for k, v in output.truncated.items() if v})
        errors.extend(output.engine_errors)
        audit = {k[:64]: v for k, v in sorted(output.audit.items()) if v > 0}
        stages = output.stages
        jvm = [a[:512] for a in output.jvm_args[:64]]
        versions = output.tool_versions or versions
    truncated.update({k: True for k, v in (extra_truncated or {}).items() if v})
    errors.extend(extra_errors)
    unique_errors = list(dict.fromkeys(errors))[:MAX_ENGINE_ERRORS]
    if len(truncated) > MAX_TRUNCATED:
        truncated = dict(list(truncated.items())[: MAX_TRUNCATED - 1]) | {"engine_report": True}
    return ReResultHeader(
        job_id=job.job_id,
        profile=job.profile,
        engine=engine,
        code_kind=code_kind,
        tool_versions={k[:255]: v[:255] for k, v in list(versions.items())[:16]},
        stages=stages,
        audit=dict(list(audit.items())[:MAX_AUDIT]),
        jvm_args=jvm if engine != ReEngine.RADARE2 else [],
        engine_errors=unique_errors,
        truncated=truncated,
    )


def _lines(
    head: ReResultHeader,
    output: EngineOutput,
    findings: list[FindingRecord],
    iocs: list[IocRecord],
) -> Iterator[BaseModel]:
    yield head
    yield output.program
    yield from output.functions
    yield from output.edges
    yield from output.imports
    yield from output.import_refs
    yield from output.strings
    yield from output.string_refs
    yield from output.decompiled
    yield from findings
    yield from iocs


def write_result(
    path: Path,
    job: ReJobV1,
    engine: ReEngine,
    code_kind: CodeKind,
    output: EngineOutput,
    found: DetectionOutput,
) -> Path:
    limits = job.limits
    cut: dict[str, bool] = {}
    findings = found.findings[: limits.max_findings]
    iocs = found.iocs[: limits.max_iocs]
    if len(found.findings) > len(findings) or found.truncated:
        cut["findings"] = True
    if len(found.iocs) > len(iocs):
        cut["iocs"] = True
    head = header(job, engine, code_kind, output, extra_truncated=cut)
    checker = StreamChecker(job_id=job.job_id, limits=limits)
    lines = list(_lines(head, output, findings, iocs))
    try:
        for line in lines:
            checker.feed(line)
    except StreamRefused as exc:
        raise JobFailed("re_parse_failed", f"the stream breaks a contract rule: {exc}") from exc
    with ResultWriter(path) as writer:
        for line in lines:
            writer.write(line)
    if path.stat().st_size > limits.max_result_bytes:
        raise JobFailed("result_too_large")
    return path


def write_diagnostic(
    path: Path,
    job: ReJobV1,
    program: ReProgramRecord,
    *,
    tool_versions: dict[str, str],
    replay: bool = False,
) -> Path:
    """header, program, trailer: nothing was loaded or run."""
    engine, code_kind = engine_for(job.profile, "replay" if replay else "real")
    head = header(job, engine, code_kind, None, tool_versions=tool_versions)
    checker = StreamChecker(job_id=job.job_id, limits=job.limits, diagnostic=True)
    checker.feed(head)
    checker.feed(program)
    with ResultWriter(path) as writer:
        writer.write(head)
        writer.write(program)
    return path


__all__ = ["RESULT", "engine_for", "header", "write_diagnostic", "write_result"]
