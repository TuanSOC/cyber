"""Hostile stage output never crashes root (pure Python part; the out-dir file tricks run in
the container in `test_pipeline.py`): bounded lines and files, strict JSON, per-record error
isolation, an untrusted `status.json`, and root's conclusions about how a stage ended."""

import io
import json
from typing import Any
from pathlib import PurePosixPath

import pytest
from cyberlab_jobs.reverse import ReStage

from re_worker import jvm_args
from re_worker.engines.outcome import ProcessResult, conclude, effective_args
from re_worker.normalize.reader import (
    MAX_LINE_BYTES,
    MAX_STATUS_BYTES,
    RowStats,
    StageStatus,
    loads,
    read_rows,
    read_status,
)
from re_worker.normalize.records import normalize_analysis
from tests.stage_helpers import LIMITS, STAGE_ROWS, rows

OUT = PurePosixPath("/work/j/analyze-out")
EXPECTED = jvm_args.expected_args(2 * 1024**3, OUT)


def _read(data: bytes, max_rows: int = 1000) -> tuple[list[dict[str, object]], RowStats]:
    stats = RowStats()
    return list(read_rows(io.BytesIO(data), max_rows, stats)), stats


@pytest.mark.parametrize(
    "line",
    [
        b'{"a": NaN}',
        b'{"a": Infinity}',
        b'{"a": 1, "a": 2}',
        b'{"a": "\\ud800"}',
        b'{"\\udfff": 1}',
        b"\xff\xfe{}",
        b'{"a": ' * 20 + b"1" + b"}" * 20,
        b"[1, 2]",
        b"not json",
    ],
)
def test_bad_lines_are_skipped_and_counted(line: bytes) -> None:
    found, stats = _read(line + b"\n" + b'{"ok": 1}\n')
    assert found == [{"ok": 1}] and stats.skipped == 1


def test_oversize_lines_are_skipped_in_bounded_chunks() -> None:
    data = b"x" * (3 * MAX_LINE_BYTES) + b"\n" + b'{"ok": 1}\n'
    found, stats = _read(data)
    assert found == [{"ok": 1}] and stats.skipped == 1


def test_row_cap_and_the_truncation_marker() -> None:
    many = b'{"kind": "x"}\n' * 1_000_000
    found, stats = _read(many, max_rows=100)
    assert len(found) == 100 and stats.truncated
    found, stats = _read(b'{"a": 1}\n{"_truncated": true}\n{"b": 2}\n')
    assert found == [{"a": 1}] and stats.truncated
    found, stats = _read(b'{"a": 1}\n{"_truncated": false}\n{"b": 2}\n')
    assert found == [{"a": 1}] and not stats.truncated


def test_hostile_fixture_keeps_every_good_record() -> None:
    lines, stats = _read((STAGE_ROWS / "hostile" / "analyze.jsonl").read_bytes(), 100_000)
    assert stats.skipped >= 5
    hostile = normalize_analysis(lines, LIMITS)
    clean = normalize_analysis(rows("pe_full", "analyze"), LIMITS)
    assert hostile.counts() == clean.counts()
    assert hostile.invalid and hostile.dropped
    assert {f.name for f in hostile.functions} == {f.name for f in clean.functions}


def test_status_is_bounded_and_validated() -> None:
    assert read_status(io.BytesIO(b"{" + b" " * MAX_STATUS_BYTES + b"}")) is None
    assert read_status(io.BytesIO(b'{"status": "maybe"}')) is None
    assert read_status(io.BytesIO(b'{"status": "ok", "audit": {"socket": -1}}')) is None
    assert read_status(io.BytesIO(b'{"status": "ok", "error": "a.b c"}')) is None
    status = read_status(io.BytesIO(json.dumps({"status": "ok", "extra": [1]}).encode()))
    assert status is not None and status.audit == {}
    assert loads(b'{"a": [1, {"b": null}]}') == {"a": [1, {"b": None}]}


def _proc(**fields: Any) -> ProcessResult:
    values: dict[str, Any] = {"end": "exited", "returncode": 0, "duration_ms": 5, **fields}
    return ProcessResult(**values)


def _status(**fields: object) -> StageStatus:
    base = {"status": "ok", "jvm_started": True, "jvm_args": EXPECTED, "audit": {}}
    return StageStatus.model_validate({**base, **fields})


def test_conclusions_of_the_analyze_stage() -> None:
    A = ReStage.ANALYZE
    ok = conclude(A, _proc(peak_memory_bytes=7), _status(), expected_args=EXPECTED)
    assert ok.fatal is None and ok.usable and ok.report.status == "ok"
    assert ok.report.peak_memory_bytes == 7
    assert conclude(A, _proc(work_too_large=True), _status(), expected_args=EXPECTED).fatal == (
        "re_work_too_large"
    )
    for proc in (_proc(oom_killed=True), _proc(end="failed", returncode=3)):
        assert conclude(A, proc, None, expected_args=EXPECTED).fatal == "re_out_of_memory"
    timeout = conclude(A, _proc(end="timeout", returncode=None), None, expected_args=EXPECTED)
    assert timeout.fatal == "analysis_timeout" and timeout.report.status == "timeout"
    assert conclude(A, _proc(), None, expected_args=EXPECTED).fatal == "jvm_start_failed"
    not_started = _status(jvm_started=False)
    never = conclude(A, _proc(end="failed", returncode=1), not_started, expected_args=EXPECTED)
    assert never.fatal == "jvm_start_failed"
    extra = _status(jvm_args=[*EXPECTED, "-javaagent:/x.jar"])
    assert conclude(A, _proc(), extra, expected_args=EXPECTED).fatal == "jvm_start_failed"
    parse = _status(status="failed", error_code="re_parse_failed", reason="loader_option")
    assert conclude(A, _proc(end="failed", returncode=4), parse, expected_args=EXPECTED).fatal == (
        "re_parse_failed"
    )
    monitor = conclude(A, _proc(), _status(analysis_status="timeout"), expected_args=EXPECTED)
    assert monitor.report.status == "timeout" and monitor.report.truncated and monitor.usable
    died = _proc(end="failed", returncode=1, hs_err=True)
    failed = _status(status="failed", error="RuntimeException")
    crashed = conclude(A, died, failed, expected_args=EXPECTED)
    assert crashed.fatal is None and crashed.usable and crashed.report.status == "failed"
    assert crashed.engine_errors == ["jvm_crash"]


def test_conclusions_of_the_decompile_stage() -> None:
    D = ReStage.DECOMPILE
    allowed = frozenset({"/opt/ghidra/decompile", "/opt/java/openjdk/lib/jspawnhelper"})

    def run(proc: ProcessResult, status: StageStatus | None):  # type: ignore[no-untyped-def]
        return conclude(D, proc, status, expected_args=EXPECTED, allowed_children=allowed)

    oom = run(_proc(oom_killed=True), _status())
    assert oom.fatal is None and oom.usable and oom.report.error_code == "re_out_of_memory"
    late = run(_proc(end="timeout", returncode=None), None)
    assert late.fatal is None and late.report.error_code == "decompile_timeout"
    assert run(_proc(), _status(children=sorted(allowed))).compromised is False
    assert run(_proc(), _status(children=["/bin/sh"])).compromised is True
    assert run(_proc(), _status(audit={"child:other": 1})).compromised is True
    assert run(_proc(), _status(jvm_args=[])).fatal == "jvm_start_failed"


def test_audit_refusals_and_the_launcher_classpath() -> None:
    audited = _status(audit={"socket": 2, "child:x": 0})
    refused = conclude(ReStage.ANALYZE, _proc(), audited, expected_args=EXPECTED)
    assert refused.engine_errors == ["audit_refusals"] and refused.audit == {"socket": 2}
    with_cp = [*EXPECTED[:3], "-Djava.class.path=/opt/ghidra/x.jar", *EXPECTED[3:]]
    assert effective_args(with_cp) == EXPECTED
    classpath = _status(jvm_args=with_cp)
    assert conclude(ReStage.ANALYZE, _proc(), classpath, expected_args=EXPECTED).fatal is None
