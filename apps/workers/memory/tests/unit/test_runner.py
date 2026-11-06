"""The analyzer end to end with the replay engine (in the memory-worker image: root, the kit's
sandbox, a tmpfs /work): every root-side step of the real engine (fresh sealed out dirs,
bounded reads through `open_output`, status validation, offline check, symbol lookup,
normalizers, detections, writer), the success rule, the diagnostic stream, per-plugin
statuses, hostile out-dir files (symlink, FIFO, missing rows), and the Volatility engine's
sandbox arguments.

    scripts/lane-test.sh 2 --service memory-worker-test pytest -q tests/unit/test_runner.py
"""

import gzip
import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("resource")  # the kit's sandbox (Linux, in the image)

from cyberlab_jobs.memory import (  # noqa: E402
    MEMORY_LINE_ADAPTER,
    KernelIdentity,
    MemoryJobV1,
    MemoryPlugin,
    SymbolManifestV1,
    check_diagnostic_kinds,
)
from cyberlab_worker import sandbox  # noqa: E402
from cyberlab_worker.errors import JobFailed  # noqa: E402

from memory_worker import analyzer  # noqa: E402
from memory_worker.config import load  # noqa: E402
from memory_worker.engines.base import ProbeRun  # noqa: E402
from memory_worker.engines.replay import ReplayEngine  # noqa: E402
from memory_worker.engines.volatility import VolatilityEngine  # noqa: E402
from memory_worker.engines.workspace import ROWS, Budget, Workspace  # noqa: E402
from memory_worker.symbols.store import SymbolHit  # noqa: E402
from tests.replay_helpers import (  # noqa: E402
    LIMITS,
    VOL_ROWS,
    artifact_types,
    contract_fixture_counts,
    kinds,
)

P = MemoryPlugin
ISF_SHA = "c" * 64
TEST_ENV = {"TEST_PROFILE": "1"}


class FakeStore:
    """A store that resolves every identity (or none): phase 5 owns the real lookup."""

    def __init__(self, root: Path, resolves: bool = True) -> None:
        self.root = root
        self.resolves = resolves

    def lookup(self, identity: KernelIdentity) -> SymbolHit | None:
        if not self.resolves:
            return None
        path = self.root / "windows" / "ntkrnlmp.pdb" / "0123456789ABCDEF0123456789ABCDEF-1.json.xz"
        return SymbolHit(path=path, sha256=ISF_SHA, identity=identity)

    def manifest(self) -> SymbolManifestV1:
        return SymbolManifestV1(volatility_version="2.28.2")


def _job(profile: str = "full", os_hint: str = "auto") -> MemoryJobV1:
    return MemoryJobV1.model_validate(
        {
            "job_id": str(uuid.uuid4()),
            "organization_id": str(uuid.uuid4()),
            "evidence_id": str(uuid.uuid4()),
            "expected_sha256": "a" * 64,
            "size_bytes": 4096,
            "evidence_url": "http://minio:9000/evidence/x?X-Amz-Signature=1",
            "result_post": {"url": "http://minio:9000/analysis-results", "fields": {"key": "k"}},
            "ingest_token": "t" * 43,
            "profile": profile,
            "os_hint": os_hint,
            "limits": LIMITS.model_dump(),
        }
    )


@pytest.fixture
def store(dirs: sandbox.JobDirs) -> Path:
    root = dirs.root / "symbols"
    root.mkdir(mode=0o755)
    return root


def _workspace(dirs: sandbox.JobDirs, store: Path, marker: bytes) -> Workspace:
    ws = Workspace(dirs, store)
    ws.image.write_bytes(marker)
    os.chmod(ws.image, 0o444)
    return ws


def _scenario(tmp_path: Path, base: str, **overrides: dict[str, Any]) -> Path:
    """A copy of a fixture scenario with `<plugin>.status.json` overrides."""
    root = tmp_path / "vol_rows"
    shutil.copytree(VOL_ROWS / base, root / "custom")
    for plugin, status in overrides.items():
        (root / "custom" / f"{plugin}.status.json").write_text(json.dumps(status))
    return root


def _lines(path: Path) -> list[Any]:
    return [MEMORY_LINE_ADAPTER.validate_json(line) for line in gzip.open(path).read().splitlines()]


def test_windows_replay_end_to_end(dirs: sandbox.JobDirs, store: Path) -> None:
    ws = _workspace(dirs, store, b"CYBERLAB-REPLAY windows\n")
    result = analyzer.analyze_image(ws, _job(), ReplayEngine(env=TEST_ENV), FakeStore(store))
    lines = _lines(result)
    header = lines[0]
    assert header.engine == "replay" and header.os == "windows"
    assert header.symbols.status == "resolved" and header.symbols.isf_sha256 == ISF_SHA
    assert [p.status for p in header.plugins] == ["ok"] * 11
    assert header.engine_errors == [] and set(header.audit_events.values()) == {0}
    fixture, fixture_artifacts = contract_fixture_counts("windows_triage.ndjson")
    got = kinds(lines)
    for kind in ("process", "connection", "injection", "artifact"):
        assert got[kind] == fixture[kind]
    assert artifact_types(lines) == fixture_artifacts
    # Every out dir was sealed: the tool uid can no longer reach an earlier plugin's output.
    sealed = [d for d in dirs.root.iterdir() if d.name.endswith("-out")]
    assert len(sealed) == 12 and all(d.stat().st_uid == 0 for d in sealed)


def test_linux_replay_end_to_end(dirs: sandbox.JobDirs, store: Path) -> None:
    ws = _workspace(dirs, store, b"CYBERLAB-REPLAY linux\n")
    result = analyzer.analyze_image(
        ws, _job("triage"), ReplayEngine(env=TEST_ENV), FakeStore(store)
    )
    lines = _lines(result)
    assert lines[0].os == "linux" and lines[1].kernel_banner.startswith("Linux version")
    assert artifact_types(lines) == {"bash": 2}


def test_missing_symbols_write_the_diagnostic_stream(dirs: sandbox.JobDirs, store: Path) -> None:
    ws = _workspace(dirs, store, b"CYBERLAB-REPLAY windows\n")
    with pytest.raises(analyzer.DiagnosticResult) as caught:
        analyzer.analyze_image(
            ws, _job(), ReplayEngine(env=TEST_ENV), FakeStore(store, resolves=False)
        )  # noqa: E501
    assert caught.value.code == "symbols_missing"
    lines = _lines(caught.value.path)
    check_diagnostic_kinds([line.kind for line in lines])
    header = lines[0]
    assert header.symbols.status == "missing" and header.plugins == []
    assert header.symbols.required.guid == "0123456789ABCDEF0123456789ABCDEF"
    # Only identify ran.
    assert [d.name for d in dirs.root.iterdir() if d.name.endswith("-out")] == ["identify-out"]


class Spy:
    """An engine that must never run (refusals before any probe)."""

    name = "replay"

    def tool_versions(self) -> dict[str, str]:
        return {}

    def identify(self, *_: object) -> ProbeRun:
        raise AssertionError("no probe may run")

    run = identify


@pytest.mark.parametrize("head", [b"\x1f\x8b\x08\x00", b"PK\x03\x04", b"\xfd7zXZ\x00", b"BZh91AY"])
def test_compressed_images_are_refused_before_any_probe(
    dirs: sandbox.JobDirs, store: Path, head: bytes
) -> None:  # noqa: E501
    ws = _workspace(dirs, store, head + bytes(64))
    with pytest.raises(JobFailed) as caught:
        analyzer.analyze_image(ws, _job(), Spy(), FakeStore(store))  # type: ignore[arg-type]
    assert caught.value.code == "unsupported_memory_format"


def test_a_failed_process_list_fails_the_job(
    dirs: sandbox.JobDirs, store: Path, tmp_path: Path
) -> None:  # noqa: E501
    root = _scenario(tmp_path, "windows", **{"windows.pslist": {"_end": "timeout"}})
    ws = _workspace(dirs, store, b"CYBERLAB-REPLAY custom\n")
    with pytest.raises(JobFailed) as caught:
        analyzer.analyze_image(ws, _job(), ReplayEngine(root, env=TEST_ENV), FakeStore(store))
    assert caught.value.code == "memory_parse_failed"


def test_other_plugin_failures_are_reported_not_fatal(
    dirs: sandbox.JobDirs, store: Path, tmp_path: Path
) -> None:  # noqa: E501
    root = _scenario(
        tmp_path,
        "windows",
        **{
            "windows.netscan": {"status": "failed", "error": "PagedInvalidAddressException"},
            "windows.svcscan": {"_end": "timeout"},
            "windows.registry.hivelist": {"symbol_paths": ["/symbols", "/tmp/evil"]},
            "windows.dlllist": {"audit": {"socket": 2, "subprocess": 1, "bogus": 9}},
        },
    )
    (root / "custom" / "windows.registry.userassist.jsonl").unlink()  # -> unsupported
    ws = _workspace(dirs, store, b"CYBERLAB-REPLAY custom\n")
    lines = _lines(
        analyzer.analyze_image(ws, _job(), ReplayEngine(root, env=TEST_ENV), FakeStore(store))
    )  # noqa: E501
    header = lines[0]
    status = {p.plugin: p for p in header.plugins}
    assert (
        status[P.WINDOWS_NETSCAN].status == "failed"
        and status[P.WINDOWS_NETSCAN].error_code == "plugin_failed"
    )
    assert status[P.WINDOWS_NETSCAN].truncated  # its rows are kept, flagged partial
    assert (
        status[P.WINDOWS_SVCSCAN].status == "timeout"
        and status[P.WINDOWS_SVCSCAN].error_code == "plugin_timeout"
    )
    assert status[P.WINDOWS_HIVELIST].status == "failed"  # not provably offline: rows dropped
    assert status[P.WINDOWS_USERASSIST].status == "unsupported"
    assert {"windows_netscan_failed", "windows_svcscan_timeout", "probe_offline_unverified"} <= set(
        header.engine_errors
    )
    assert header.truncated["windows.netscan"] and header.truncated["windows.svcscan"]
    assert header.audit_events["socket"] == 2 and header.audit_events["subprocess"] == 1
    assert "bogus" not in header.audit_events
    assert artifact_types(lines)["hive"] == 0 and kinds(lines)["connection"] == 3


def test_plugins_beyond_the_budget_are_skipped(
    dirs: sandbox.JobDirs, store: Path, monkeypatch: pytest.MonkeyPatch
) -> None:  # noqa: E501
    calls = iter([60.0, 60.0, None, None, None, None, None, None, None, None, None])
    monkeypatch.setattr(Budget, "plugin", lambda self: next(calls))
    ws = _workspace(dirs, store, b"CYBERLAB-REPLAY windows\n")
    header = _lines(
        analyzer.analyze_image(ws, _job(), ReplayEngine(env=TEST_ENV), FakeStore(store))
    )[0]  # noqa: E501
    assert [p.status for p in header.plugins] == ["ok", "ok"] + ["skipped"] * 9


def test_os_hint_restricts_the_candidates(dirs: sandbox.JobDirs, store: Path) -> None:
    ws = _workspace(dirs, store, b"CYBERLAB-REPLAY windows\n")
    with pytest.raises(JobFailed) as caught:
        analyzer.analyze_image(
            ws, _job(os_hint="linux"), ReplayEngine(env=TEST_ENV), FakeStore(store)
        )  # noqa: E501
    assert caught.value.code == "os_undetermined"


def test_an_unknown_scenario_is_a_parse_failure(dirs: sandbox.JobDirs, store: Path) -> None:
    ws = _workspace(dirs, store, b"just some bytes\n")
    with pytest.raises(JobFailed) as caught:
        analyzer.analyze_image(ws, _job(), ReplayEngine(env=TEST_ENV), FakeStore(store))
    assert caught.value.code == "memory_parse_failed"


class Tampering(ReplayEngine):
    """Replaces one plugin's rows file after the run (symlink, FIFO or nothing)."""

    def __init__(self, how: str) -> None:
        super().__init__(env=TEST_ENV)
        self.how = how

    def run(self, ws: Workspace, plugin: MemoryPlugin, seconds: float, max_rows: int) -> ProbeRun:  # noqa: E501
        done = super().run(ws, plugin, seconds, max_rows)
        if plugin is P.WINDOWS_NETSCAN:
            rows = done.dirs.out / ROWS
            rows.unlink()
            if self.how == "symlink":
                rows.symlink_to("/etc/passwd")
            elif self.how == "fifo":
                os.mkfifo(rows)
        return done


@pytest.mark.parametrize("how", ["symlink", "fifo", "missing"])
def test_hostile_rows_files_yield_nothing(dirs: sandbox.JobDirs, store: Path, how: str) -> None:
    ws = _workspace(dirs, store, b"CYBERLAB-REPLAY windows\n")
    lines = _lines(analyzer.analyze_image(ws, _job(), Tampering(how), FakeStore(store)))
    status = {p.plugin: p for p in lines[0].plugins}
    assert kinds(lines)["connection"] == 0
    # "ok" with no readable rows file is a failed plugin, never a silent empty result.
    assert status[P.WINDOWS_NETSCAN].status == "failed"


def test_the_replay_engine_is_test_profile_only() -> None:
    from memory_worker.config import ConfigError

    with pytest.raises(ConfigError):
        ReplayEngine(env={})


def test_the_volatility_engine_sandbox_arguments(
    dirs: sandbox.JobDirs, store: Path, monkeypatch: pytest.MonkeyPatch
) -> None:  # noqa: E501
    (store / ".cache" / "volatility3").mkdir(parents=True)
    (store / ".cache" / "volatility3" / "identifier.cache").write_bytes(b"SQLite format 3\x00")
    seen: dict[str, Any] = {}

    def fake_run_tool(argv: list[str], run_dirs: sandbox.JobDirs, **kwargs: Any) -> None:
        seen.update(argv=argv, dirs=run_dirs, **kwargs)
        cache = run_dirs.out / "cache" / "volatility3" / "identifier.cache"
        seen["cache"] = (cache.read_bytes(), cache.stat().st_uid)

    monkeypatch.setattr(sandbox, "run_tool", fake_run_tool)
    config = load({"BROKER_URL": "redis://x", "MEMORY_SYMBOLS_DIR": str(store)})
    ws = _workspace(dirs, store, b"\x00" * 64)
    run = VolatilityEngine(config).run(ws, P.WINDOWS_PSLIST, 30.0, 20_000)
    argv = seen["argv"]
    assert argv[1:6] == ["-I", "-s", "-B", "-m", "memory_worker.probe"]
    assert argv[6:10] == ["run", "windows.pslist", "--max-rows", "20000"]
    assert seen["unix_sockets_only"] is True and seen["deny_io_uring"] is True
    assert seen["rlimits"].as_bytes == config.plugin_rlimit_as
    assert seen["rlimits"].fsize_bytes == 512 * 1024**2
    assert seen["cwd"] == dirs.input and seen["stdout_name"] == ROWS
    env = seen["extra_env"]
    assert env["HOME"] == env["XDG_CONFIG_HOME"] == "/nonexistent"
    assert env["XDG_CACHE_HOME"] == str(run.dirs.out / "cache")
    assert seen["cache"] == (b"SQLite format 3\x00", sandbox.TOOL_UID)
    assert run.dirs.out.stat().st_uid == 0  # sealed after the run
