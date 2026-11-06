"""The analyzer end to end with the replay engine (in the re-worker image: root, the kit's
sandbox, the anonymous /work volume): every root-side step of the real engine (fresh sealed
out dirs, bounded reads through `open_output`, root's stage conclusions, contract validation,
ranking, the root-owned decompile list, the writer) over hand-written stage rows, the
diagnostic stream, failed and partial stages, and hostile out-dir files (symlink, FIFO).

    scripts/lane-test.sh 2 --service re-worker-test pytest -q tests/unit/test_pipeline.py
"""

import gzip
import json
import os
import stat
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("resource")  # the kit's sandbox (Linux, in the image)

from cyberlab_jobs.reverse import RE_LINE_ADAPTER, ReJobV1, validate_stream  # noqa: E402
from cyberlab_worker import sandbox  # noqa: E402
from cyberlab_worker.errors import JobFailed  # noqa: E402

from re_worker.analyzer import DiagnosticResult, analyze_sample  # noqa: E402
from re_worker.config import ConfigError, load  # noqa: E402
from re_worker.engines import Budget, Workspace, workspace  # noqa: E402
from re_worker.engines.replay import ReplayRunner  # noqa: E402
from re_worker.engines.spec import DECOMPILE_LIST, ROWS, StageSpec  # noqa: E402
from re_worker.engines.stage import StageRun  # noqa: E402
from tests.conftest import WORK  # noqa: E402
from tests.stage_helpers import decompiled_entries, elf_header, job, pe_header  # noqa: E402

CONFIG = load({"BROKER_URL": "redis://x", "RE_ENGINE": "replay", "TEST_PROFILE": "1"})


@pytest.fixture
def dirs() -> Iterator[sandbox.JobDirs]:
    if os.geteuid() != 0:
        pytest.skip("sandbox tests run inside the re-worker container (root + capabilities)")
    WORK.mkdir(parents=True, exist_ok=True)
    job_dirs = sandbox.prepare(WORK, f"test-{uuid.uuid4()}")
    yield job_dirs
    sandbox.cleanup(job_dirs)


def _ws(dirs: sandbox.JobDirs, data: bytes) -> Workspace:
    ws = workspace.create(dirs)
    ws.sample.write_bytes(data)
    os.chmod(ws.sample, 0o444)
    return ws


def _run(
    dirs: sandbox.JobDirs,
    case: str,
    *,
    fmt: str = "pe",
    data: bytes | None = None,
    runner: ReplayRunner | None = None,
    **job_fields: Any,
) -> tuple[ReJobV1, list[Any]]:
    header = data or (pe_header(marker=case) if fmt == "pe" else elf_header(marker=case))
    ws = _ws(dirs, header)
    the_job = job(file_format=fmt, size=len(header), **job_fields)
    runner = runner or ReplayRunner(env={"TEST_PROFILE": "1"})
    path = analyze_sample(ws, the_job, CONFIG, Budget.starting_now(3000), runner)
    with gzip.open(path, "rt", encoding="utf-8") as f:
        lines = [RE_LINE_ADAPTER.validate_python(json.loads(line)) for line in f]
    validate_stream(lines, job_id=the_job.job_id, limits=the_job.limits)
    return the_job, lines


def _kinds(lines: list[Any], kind: str) -> list[Any]:
    return [line for line in lines if line.kind == kind]


def test_pe_full_replay(dirs: sandbox.JobDirs) -> None:
    listed = decompiled_entries("pe_full")
    _, lines = _run(dirs, "pe_full", decompile=listed)
    header, program = lines[0], lines[1]
    assert header.engine == "replay" and header.code_kind == "pseudo_c"
    assert [(s.stage, s.status) for s in header.stages] == [("analyze", "ok"), ("decompile", "ok")]
    assert "replay" in header.tool_versions and header.jvm_args
    assert program.format == "pe" and program.preferred_base == 0x140000000
    assert len(_kinds(lines, "function")) == 31
    assert [d.function_entry for d in _kinds(lines, "decompiled")] == list(listed)
    ranks = {f.entry: f.priority_rank for f in _kinds(lines, "function")}
    assert [ranks[e] for e in listed] == list(range(len(listed)))
    list_file = dirs.root / "stage" / DECOMPILE_LIST
    assert stat.S_IMODE(list_file.stat().st_mode) == 0o444 and list_file.stat().st_uid == 0


def test_elf_full_replay(dirs: sandbox.JobDirs) -> None:
    _, lines = _run(dirs, "elf_full", fmt="elf")
    program = lines[1]
    assert program.format == "elf" and program.image_base == 0x100000
    assert program.preferred_base == 0  # the file's own base (RT8)
    assert lines[0].stages[0].status == "ok"


def test_analysis_timeout_keeps_the_export(dirs: sandbox.JobDirs) -> None:
    _, lines = _run(dirs, "analysis_timeout")
    assert lines[0].stages[0].status == "timeout" and lines[0].truncated.get("analysis")
    assert lines[1].analysis_status == "timeout" and _kinds(lines, "function")


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("analyze_no_status", "analysis_timeout"),
        ("jvm_mismatch", "jvm_start_failed"),
        ("oom", "re_out_of_memory"),
        ("work_too_large", "re_work_too_large"),
        ("parse_failed", "re_parse_failed"),
        ("no_such_case", "jvm_start_failed"),
    ],
)
def test_fatal_analyze_outcomes(dirs: sandbox.JobDirs, case: str, code: str) -> None:
    with pytest.raises(JobFailed) as failed:
        _run(dirs, case)
    assert failed.value.code == code


def test_decompile_crash_is_a_partial_success(dirs: sandbox.JobDirs) -> None:
    listed = decompiled_entries("pe_full")
    _, lines = _run(dirs, "decompile_crash", decompile=listed)
    assert lines[0].stages[1].status == "failed"
    statuses = [d.status for d in _kinds(lines, "decompiled")]
    assert statuses[:2] == ["ok", "ok"] and set(statuses[2:]) == {"failed"}


def test_unexpected_decompile_child_fails_the_job(dirs: sandbox.JobDirs) -> None:
    with pytest.raises(sandbox.SandboxCompromised):
        _run(dirs, "decompile_child", decompile=decompiled_entries("pe_full"))


def test_hostile_rows_are_counted(dirs: sandbox.JobDirs) -> None:
    _, lines = _run(dirs, "hostile")
    header = lines[0]
    assert {"analyze_rows_skipped", "analyze_rows_invalid", "analyze_rows_dropped"} <= set(
        header.engine_errors
    )
    assert len(_kinds(lines, "function")) == 31


def test_diagnostic_streams(dirs: sandbox.JobDirs) -> None:
    ws = _ws(dirs, pe_header(clr=True, marker="pe_full"))
    the_job = job(size=1024)
    runner = ReplayRunner(env={"TEST_PROFILE": "1"})
    with pytest.raises(DiagnosticResult) as diagnostic:
        analyze_sample(ws, the_job, CONFIG, Budget.starting_now(60), runner)
    assert diagnostic.value.code == "unsupported_managed_code"
    with gzip.open(diagnostic.value.path, "rt") as f:
        kinds = [json.loads(line)["kind"] for line in f]
    assert kinds == ["header", "program", "trailer"]


def test_format_mismatch_and_garbage(dirs: sandbox.JobDirs) -> None:
    with pytest.raises(JobFailed) as mismatch:
        _run(dirs, "pe_full", data=elf_header(marker="pe_full"))
    assert mismatch.value.code == "unsupported_format"


def test_quick_is_unavailable_until_phase_3(dirs: sandbox.JobDirs) -> None:
    with pytest.raises(JobFailed) as failed:
        _run(dirs, "pe_full", profile="quick")
    assert failed.value.code == "profile_unavailable"


class PlantingRunner(ReplayRunner):
    """Replaces the analyze stage's rows file by a symlink or a FIFO before sealing."""

    def __init__(self, kind: str) -> None:
        super().__init__(env={"TEST_PROFILE": "1"})
        self.kind = kind

    def run(self, ws: Workspace, spec: StageSpec, max_work_bytes: int, **kw: Any) -> StageRun:
        run = super().run(ws, spec, max_work_bytes, dirs=kw.get("dirs"), seal=False)
        rows = run.dirs.out / ROWS
        rows.unlink()
        if self.kind == "symlink":
            os.symlink("/etc/passwd", rows)
        else:
            os.mkfifo(rows)
        workspace.seal(run.dirs)
        return run


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_planted_out_dir_files_are_never_followed(dirs: sandbox.JobDirs, kind: str) -> None:
    with pytest.raises(JobFailed) as failed:
        _run(dirs, "pe_full", runner=PlantingRunner(kind))
    assert failed.value.code == "re_parse_failed"


def test_replay_is_test_profile_only() -> None:
    with pytest.raises(ConfigError):
        ReplayRunner(root=Path("/nonexistent"), env={})
