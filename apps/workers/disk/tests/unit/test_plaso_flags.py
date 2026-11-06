"""The fixed Plaso argv per (OS, profile) and the `cyberlab_plaso_launch` wrapper (M9 phase 3;
pure: Plaso is not installed here, the launcher is loaded from its file and runs fake tools).

The launcher's audit hook is exercised through a `Guard` with a fake installer: a real hook can
never be removed from the test process."""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from disk_worker.timeline import flags
from tests.unit.phase2_helpers import limits

LAUNCHER_FILE = Path(__file__).resolve().parents[2] / "plaso" / "cyberlab_plaso_launch.py"
OUT = Path("/work/job/plaso-p2-out")
SRC = Path("/work/job/collect-p2-out/artifacts/p2")
MEMORY = str(5 * 1024**3 // 2 - 256 * 1024**2)
COMMON = [
    "/opt/plaso/bin/python",
    "-I",
    "-m",
    "cyberlab_plaso_launch",
    "log2timeline",
    "--single_process",
    "--status_view",
    "none",
    "--unattended",
    "--hashers",
    "none",
    "--no_dependencies_check",
    "--archives",
    "none",
    "--vss_stores",
    "none",
]
TAIL = [
    "--temporary_directory",
    str(OUT / "tmp"),
    "--logfile",
    str(OUT / "log2timeline.log.gz"),
    "--storage_file",
    str(OUT / "timeline.plaso"),
]
PARSERS = {
    ("windows", "triage"): "winevtx,winreg,prefetch,lnk,!filestat",
    ("windows", "full"): "winevtx,winreg,prefetch,lnk,mft,recycle_bin,sqlite,!filestat",
    ("linux", "triage"): (
        "text/syslog,text/bash_history,text/zsh_extended_history,text/dpkg,text/apt_history,"
        "utmp,!filestat"
    ),
    ("linux", "full"): (
        "text/syslog,text/bash_history,text/zsh_extended_history,text/dpkg,text/apt_history,"
        "utmp,systemd_journal,sqlite,!filestat"
    ),
}


def _launcher() -> ModuleType:
    spec = importlib.util.spec_from_file_location("cyberlab_plaso_launch_test", LAUNCHER_FILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(("os_name", "profile"), sorted(PARSERS))
def test_log2timeline_argv_is_exact(os_name: str, profile: str) -> None:
    argv = flags.log2timeline_argv(
        os_name,  # type: ignore[arg-type]
        profile,  # type: ignore[arg-type]
        limits(),
        OUT,
        SRC,
        assume_utc=False,
    )
    skip = ["--skip_compressed_streams"] if profile == "triage" else []
    assert argv == [
        *COMMON,
        *skip,
        "--process_memory_limit",
        MEMORY,
        "--parsers",
        PARSERS[(os_name, profile)],
        *TAIL,
        str(SRC),
    ]


def test_utc_is_added_only_when_asked() -> None:
    argv = flags.log2timeline_argv("linux", "triage", limits(), OUT, SRC, assume_utc=True)
    assert argv[-3:] == ["--timezone", "UTC", str(SRC)]
    assert "--timezone" not in flags.log2timeline_argv(
        "linux", "triage", limits(), OUT, SRC, assume_utc=False
    )


def test_export_argv_has_no_analysis_and_json_line_only() -> None:
    storage = OUT / "timeline.plaso"
    out = Path("/work/job/export-p2-out")
    assert flags.export_argv(storage, out) == [
        "/opt/plaso/bin/python",
        "-I",
        "-m",
        "cyberlab_plaso_launch",
        "psort",
        "--status_view",
        "none",
        "--logfile",
        str(out / "psort.log.gz"),
        "-o",
        "json_line",
        "-w",
        str(out / "events.jsonl"),
        str(storage),
    ]
    assert flags.export_argv(storage, out, "export") == [
        "/opt/plaso/bin/python",
        "-I",
        "-m",
        "cyberlab_plaso_export",
        str(storage),
        str(out / "events.jsonl"),
    ]


def test_the_memory_limit_stays_below_the_stage_rlimit() -> None:
    lim = limits()
    assert flags.process_memory_limit(lim) == lim.stages["log2timeline"].rlimit_as - 256 * 1024**2


def test_the_launcher_accepts_exactly_the_built_argv() -> None:
    launch = _launcher()
    for os_name, profile in PARSERS:
        argv = flags.log2timeline_argv(
            os_name,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            limits(),
            OUT,
            SRC,
            assume_utc=True,
        )
        assert launch.check_argv(argv[4], argv[5:]) is None
    psort = flags.export_argv(OUT / "timeline.plaso", OUT)
    assert launch.check_argv(psort[4], psort[5:]) is None


@pytest.mark.parametrize(
    ("tool", "args", "reason"),
    [
        ("pinfo", [], "unknown_tool"),
        ("log2timeline", ["--storage_file", "x", "src"], "not_single_process"),
        ("log2timeline", ["--single_process", "src"], "no_storage_file"),
        (
            "psort",
            ["-o", "json_line", "-w", "x", "--analysis", "virustotal", "s"],
            "forbidden_option",
        ),
        ("psort", ["-o", "opensearch", "-w", "x", "s"], "not_json_line"),
        ("psort", ["-o", "dynamic", "-w", "x", "s"], "not_json_line"),
        ("psort", ["-o", "json_line", "-o", "dynamic", "-w", "x", "s"], "not_json_line"),
        ("psort", ["-o", "json_line", "s"], "no_output_file"),
        (
            "log2timeline",
            ["--single_process", "--workers", "4", "--storage_file", "x"],
            "forbidden_option",
        ),
    ],
)
def test_the_launcher_refuses_other_shapes(tool: str, args: list[str], reason: str) -> None:
    assert _launcher().check_argv(tool, args) == reason


@pytest.mark.parametrize(
    ("event", "family"),
    [
        ("socket.connect", "socket"),
        ("socket.getaddrinfo", "socket"),
        ("urllib.Request", "urllib"),
        ("subprocess.Popen", "subprocess"),
        ("os.exec", "exec"),
        ("os.posix_spawn", "spawn"),
        ("os.system", "system"),
        ("os.fork", "fork"),
    ],
)
def test_the_guard_refuses_and_counts(event: str, family: str) -> None:
    launch = _launcher()
    guard = launch.Guard(add_hook=lambda hook: None)
    with pytest.raises(launch.Refused):
        guard.hook(event, ())
    assert guard.snapshot()[family] == 1 and sum(guard.snapshot().values()) == 1
    guard.hook("open", ("/work/job/collect-p1-out/artifacts/p1/var/log/syslog", "rb", 0))
    assert sum(guard.snapshot().values()) == 1


def _fake_tool(main: Any) -> Any:
    return lambda name: SimpleNamespace(Main=main)


def test_run_reports_ok_with_zero_counts(tmp_path: Path) -> None:
    launch = _launcher()
    added: list[Any] = []
    guard = launch.Guard(add_hook=added.append)
    out = tmp_path / "events.jsonl"
    out.write_text('{"a":1}\n{"b":2}\n')
    argv = ["--status_view", "none", "-o", "json_line", "-w", str(out), "store"]
    saved = sys.argv
    try:
        code, status = launch.run("psort", argv, guard, load=_fake_tool(lambda: True))
    finally:
        sys.argv = saved
    assert code == 0 and added == [guard.hook]
    assert status["status"] == "ok" and status["rows"] == 2
    assert status["audit"] == dict.fromkeys(launch.FAMILIES, 0)


def test_run_reports_a_refused_attempt_and_a_failure(tmp_path: Path) -> None:
    launch = _launcher()
    guard = launch.Guard(add_hook=lambda hook: None)

    def main() -> bool:
        guard.hook("subprocess.Popen", ("/bin/sh",))  # what the real hook would see
        return True

    argv = ["--single_process", "--temporary_directory", str(tmp_path / "tmp")]
    argv += ["--storage_file", str(tmp_path / "s.plaso"), "src"]
    saved = sys.argv
    try:
        code, status = launch.run("log2timeline", argv, guard, load=_fake_tool(main))
    finally:
        sys.argv = saved
    assert code == 4
    assert status == {
        "stage": "log2timeline",
        "status": "failed",
        "rows": 0,
        "error": "Refused",
        "error_code": "timeline_failed",
        "audit": {**dict.fromkeys(launch.FAMILIES, 0), "subprocess": 1},
    }
    assert (tmp_path / "tmp").is_dir()  # Plaso's temporary directory, made in the out dir


def test_refused_argv_never_loads_plaso() -> None:
    launch = _launcher()

    def load(name: str) -> Any:
        raise AssertionError("Plaso must not be imported for a refused argv")

    code, status = launch.run("psort", ["-o", "dynamic"], launch.Guard(lambda h: None), load=load)
    assert code == 2 and status["reason"] == "not_json_line"


def test_main_refuses_a_non_isolated_interpreter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    launch = _launcher()
    assert not launch.isolated()  # pytest is not `python -I`
    assert launch.main(["psort", "-o", "json_line"]) == 2
    doc = json.loads((tmp_path / "status.json").read_text())
    assert doc == {"status": "failed", "error": "NotIsolated", "reason": "isolation"}
