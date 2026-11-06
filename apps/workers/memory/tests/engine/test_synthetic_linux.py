"""The real engine end to end on the synthetic Linux images (M8 phase 4, `--heavy`): the
generator writes the image into the job's work dir on the test tmpfs, the ISF is imported
into a temp symbol store through phase 5's real `import` (Volatility's schema, the store
writer) and indexed with the real indexer at the store's own path; then the analyzer runs
Volatility 2.28.2 in the sandboxed probe (tool uid, seccomp, offline) for identify and every
plugin of the profile, normalizes, detects and writes `memory.v1`.

Plugin outcomes on the synthetic kernel are asserted exactly: `linux.pslist` and `linux.psaux`
succeed; `linux.malware.check_syscall` runs and finds no table (ok, no rows); `linux.bash`,
`linux.sockstat`, `linux.lsof`, `linux.malware.malfind` and `linux.malware.hidden_modules` fail
(the image has no VMAs, sockets, fd tables or module list: our ISF does not describe them).

    scripts/lane-test.sh 4 --service memory-worker-test --heavy pytest -q -s tests/engine
"""

import gzip
import hashlib
import os
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("volatility3")
pytest.importorskip("resource")

from cyberlab_jobs.memory import (  # noqa: E402
    MEMORY_LINE_ADAPTER,
    LinuxBanner,
    MemoryJobV1,
    MemoryPlugin,
    check_diagnostic_kinds,
)
from cyberlab_worker import sandbox  # noqa: E402
from cyberlab_worker.errors import JobFailed  # noqa: E402

from memory_worker import analyzer  # noqa: E402
from memory_worker.config import load  # noqa: E402
from memory_worker.engines.volatility import VolatilityEngine  # noqa: E402
from memory_worker.engines.workspace import Workspace  # noqa: E402
from memory_worker.probe.guard import FAMILIES  # noqa: E402
from memory_worker.symbols import import_isf, reindex  # noqa: E402
from memory_worker.symbols.manifest import read_manifest  # noqa: E402
from memory_worker.symbols.store import SymbolStore  # noqa: E402
from samples.memgen import BANNER, UNKNOWN_BANNER, build, isf_xz, scenario, wrap  # noqa: E402
from samples.memgen.scenarios import EXITED_PARENT, WIDE_COUNT  # noqa: E402
from tests.replay_helpers import LIMITS  # noqa: E402
from tests.symbols_helpers import new_store  # noqa: E402

P = MemoryPlugin
TRIAGE = {
    P.LINUX_PSLIST: "ok",
    P.LINUX_PSAUX: "ok",
    P.LINUX_BASH: "failed",
    P.LINUX_SOCKSTAT: "failed",
}
FULL = {
    **TRIAGE,
    P.LINUX_LSOF: "failed",
    P.LINUX_MALFIND: "failed",
    P.LINUX_CHECK_SYSCALL: "ok",
    P.LINUX_HIDDEN_MODULES: "failed",
}


def _job(profile: str, size: int, limits: Any = LIMITS) -> MemoryJobV1:
    return MemoryJobV1.model_validate(
        {
            "job_id": str(uuid.uuid4()),
            "organization_id": str(uuid.uuid4()),
            "evidence_id": str(uuid.uuid4()),
            "expected_sha256": "a" * 64,
            "size_bytes": size,
            "evidence_url": "http://minio:9000/evidence/x?X-Amz-Signature=1",
            "result_post": {"url": "http://minio:9000/analysis-results", "fields": {"key": "k"}},
            "ingest_token": "t" * 43,
            "profile": profile,
            "os_hint": "auto",
            "limits": limits.model_dump() if hasattr(limits, "model_dump") else limits,
        }
    )


@pytest.fixture
def store(dirs: sandbox.JobDirs, tmp_path: Path) -> Path:
    """A temp store holding our ISF, imported and indexed by phase 5's real code."""
    root = new_store(dirs.root)
    source = tmp_path / "cyberlab-synthetic-6.1.0.json.xz"
    source.write_bytes(isf_xz(BANNER))
    result = import_isf.import_file(root, source)
    assert [c.action for c in result.changes] == ["added"]
    assert reindex.reindex(root, required_root=Path(os.path.abspath(root))) >= 1
    return root


def _lines(path: Path) -> list[Any]:
    return [MEMORY_LINE_ADAPTER.validate_json(x) for x in gzip.open(path).read().splitlines()]


def _run(dirs: sandbox.JobDirs, store: Path, name: str, fmt: str, profile: str) -> list[Any]:
    data = wrap(build(scenario(name)), fmt)
    ws = Workspace(dirs, store)
    ws.image.write_bytes(data)
    os.chmod(ws.image, 0o444)
    config = load({"BROKER_URL": "redis://x", "MEMORY_SYMBOLS_DIR": str(store)})
    started = time.monotonic()
    result = analyzer.analyze_image(
        ws, _job(profile, len(data)), VolatilityEngine(config), SymbolStore(store)
    )
    print(f"{name} {fmt} {profile}: {time.monotonic() - started:.1f} s")
    return _lines(result)


def _check_header(lines: list[Any], store: Path, expected: dict[MemoryPlugin, str]) -> None:
    header = lines[0]
    assert header.engine == "volatility3" and header.os == "linux"
    assert header.tool_versions["volatility3"] == "2.28.2"
    entry = read_manifest(store).files[0]
    assert header.symbols.status == "resolved"
    assert header.symbols.isf_sha256 == entry.sha256
    assert {p.plugin: p.status for p in header.plugins} == expected
    # Offline and quiet: no network, process or file-output attempt in any probe.
    assert {f: header.audit_events.get(f, 0) for f in FAMILIES} == dict.fromkeys(FAMILIES, 0)
    assert "isf_unreported" not in header.engine_errors
    assert "isf_mismatch" not in header.engine_errors
    assert "probe_offline_unverified" not in header.engine_errors


def _processes(lines: list[Any]) -> dict[int, Any]:
    return {x.pid: x for x in lines if x.kind == "process"}


@pytest.mark.parametrize("fmt", ["raw", "lime", "elf"])
def test_benign_triage_on_every_container(dirs: sandbox.JobDirs, store: Path, fmt: str) -> None:
    lines = _run(dirs, store, "linux_benign", fmt, "triage")
    _check_header(lines, store, TRIAGE)
    image = next(x for x in lines if x.kind == "image")
    assert image.kernel_banner == BANNER
    assert image.layer == {"raw": "raw", "lime": "LimeLayer", "elf": "Elf64Layer"}[fmt]
    procs = _processes(lines)
    expected = scenario("linux_benign").procs
    # init_task (pid 0) is the list head and never listed, as on a real kernel.
    assert set(procs) == {p.pid for p in expected}
    for p in expected:
        got = procs[p.pid]
        assert (got.ppid, got.name) == (p.ppid, p.comm[:15])
        assert got.sources == ["pslist"]
        assert got.cmdline == (" ".join(p.args) if not p.kthread else f"[{p.comm[:15]}]")


def test_full_profile_reports_every_plugin_status(dirs: sandbox.JobDirs, store: Path) -> None:
    lines = _run(dirs, store, "linux_orphan_and_dup", "raw", "full")
    _check_header(lines, store, FULL)
    header = lines[0]
    failed = {p.plugin for p in header.plugins if p.status == "failed"}
    assert all(p.error_code == "plugin_failed" for p in header.plugins if p.plugin in failed)
    procs = _processes(lines)
    assert procs[4300].ppid == EXITED_PARENT and EXITED_PARENT not in procs
    assert sorted(pid for pid, p in procs.items() if p.name == "systemd") == [1, 1190]


def test_wide_tree_and_the_process_cap(dirs: sandbox.JobDirs, store: Path) -> None:
    capped = LIMITS.model_copy(update={"max_processes": 500})
    data = wrap(build(scenario("linux_wide")), "raw")
    ws = Workspace(dirs, store)
    ws.image.write_bytes(data)
    os.chmod(ws.image, 0o444)
    config = load({"BROKER_URL": "redis://x", "MEMORY_SYMBOLS_DIR": str(store)})
    result = analyzer.analyze_image(
        ws, _job("triage", len(data), capped), VolatilityEngine(config), SymbolStore(store)
    )
    lines = _lines(result)
    header = lines[0]
    pslist = next(p for p in header.plugins if p.plugin == P.LINUX_PSLIST)
    assert pslist.status == "ok" and pslist.truncated and pslist.rows == 500
    procs = _processes(lines)
    assert len(procs) == 500 < WIDE_COUNT
    # The tree holds: every listed parent is either listed or one of the roots' parents.
    runners = [p for p in procs.values() if p.name == "runner"]
    assert runners and all(p.ppid == 1 for p in runners)
    assert all(procs[p.ppid].name == "runner" for p in procs.values() if p.name == "cc1"
               if p.ppid in procs)  # fmt: skip


def test_an_unknown_banner_gives_the_symbols_missing_diagnostic(
    dirs: sandbox.JobDirs, store: Path
) -> None:
    data = wrap(build(scenario("symbols_missing")), "lime")
    ws = Workspace(dirs, store)
    ws.image.write_bytes(data)
    os.chmod(ws.image, 0o444)
    config = load({"BROKER_URL": "redis://x", "MEMORY_SYMBOLS_DIR": str(store)})
    with pytest.raises(analyzer.DiagnosticResult) as caught:
        analyzer.analyze_image(
            ws, _job("triage", len(data)), VolatilityEngine(config), SymbolStore(store)
        )
    assert caught.value.code == "symbols_missing"
    lines = _lines(caught.value.path)
    check_diagnostic_kinds([x.kind for x in lines])
    header = lines[0]
    assert header.engine == "volatility3" and header.symbols.status == "missing"
    assert header.symbols.required == LinuxBanner(banner=UNKNOWN_BANNER)
    # Only identify ran, offline and quiet.
    assert [d.name for d in dirs.root.iterdir() if d.name.endswith("-out")] == ["identify-out"]
    assert set(header.audit_events.values()) <= {0}


def test_a_truncated_image_ends_cleanly(dirs: sandbox.JobDirs, store: Path) -> None:
    """The image cut inside init_task (every other task gone): the banner and the page
    tables are still there, so the layers stack, but the `tasks` list leads off the image.
    Volatility's list walk stops at the first unreadable entry, so pslist ends `ok` with no
    row (observed with 2.28.2): a result with zero processes, never a crash or a hang, and no
    tool process survives."""
    data = wrap(build(scenario("linux_benign")), "raw")[: 0x100000 + 0x80]
    ws = Workspace(dirs, store)
    ws.image.write_bytes(data)
    os.chmod(ws.image, 0o444)
    config = load({"BROKER_URL": "redis://x", "MEMORY_SYMBOLS_DIR": str(store)})
    try:
        result = analyzer.analyze_image(
            ws, _job("triage", len(data)), VolatilityEngine(config), SymbolStore(store)
        )
    except JobFailed as exc:  # a later Volatility may refuse the list instead: a known code
        assert exc.code == "memory_parse_failed"
    else:
        lines = _lines(result)
        pslist = next(p for p in lines[0].plugins if p.plugin == P.LINUX_PSLIST)
        assert (pslist.status, pslist.rows) == ("ok", 0)
        assert _processes(lines) == {}
    assert sandbox.tool_pids() == []
    assert hashlib.sha256(ws.image.read_bytes()).digest() == hashlib.sha256(data).digest()
