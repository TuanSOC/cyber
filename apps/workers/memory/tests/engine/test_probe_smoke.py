"""Probe smoke (RT4; always, whatever phase 4 decides): the REAL volatility3 2.28.2 in the
sandboxed probe (tool uid 10006, seccomp AF_UNIX only + no io_uring, RLIMIT_AS / FSIZE,
timeout, fresh out dir) on generated non-images. No third-party image is ever used.

- (a) a seeded random 16 MiB blob: identify ends `os_undetermined`, the probe ran offline
  with the expected symbol paths, and the audit hook recorded no network or process event;
  a plugin run on it is `unsupported` (no symbols) with the same guarantees;
- (b) `MEMORY_PROBE_HEAVY=1`: a sparse 8 GiB file (holes cost nothing on the tmpfs /work,
  never uploaded): identify ends `os_undetermined` within its timeout and the probe's peak
  RSS stays below `RLIMIT_AS` although the file is far larger. The duration is printed as
  the baseline full-image scan time.

    scripts/lane-test.sh 2 --service memory-worker-test pytest -q -s tests/engine
    scripts/lane-test.sh 2 --service memory-worker-test --heavy \\
        sh -c "MEMORY_PROBE_HEAVY=1 pytest -q -s tests/engine"
"""

import os
import random
import resource
import time

import pytest

pytest.importorskip("volatility3")

from cyberlab_jobs.memory import MemoryPlugin, OsHint  # noqa: E402
from cyberlab_worker import sandbox  # noqa: E402

from memory_worker.config import load  # noqa: E402
from memory_worker.engines.volatility import VolatilityEngine  # noqa: E402
from memory_worker.engines.workspace import STATUS, Workspace  # noqa: E402
from memory_worker.identify import IdentifyRecord, IdentifyRefused, choose  # noqa: E402
from memory_worker.normalize.reader import read_status  # noqa: E402
from memory_worker.probe.guard import FAMILIES  # noqa: E402

HEAVY = os.environ.get("MEMORY_PROBE_HEAVY") == "1"
SPARSE_BYTES = 8 * 1024**3


@pytest.fixture
def setup(dirs: sandbox.JobDirs) -> tuple[Workspace, VolatilityEngine]:
    store = dirs.root / "symbols"
    for sub in ("", "windows", "linux"):
        (store / sub).mkdir(mode=0o755, exist_ok=True)
    (store / "manifest.json").write_text('{"version": 1, "volatility_version": "2.28.2"}\n')
    os.chmod(store / "manifest.json", 0o644)
    config = load({"BROKER_URL": "redis://x", "MEMORY_SYMBOLS_DIR": str(store)})
    return Workspace(dirs, store), VolatilityEngine(config)


def _status(ws: Workspace, run_dirs: sandbox.JobDirs) -> object:
    with sandbox.open_output(run_dirs, STATUS) as f:
        status = read_status(f)
    assert status is not None
    assert status.offline_verified(str(ws.symbols_dir))
    assert {family: status.audit.get(family, 0) for family in FAMILIES} == dict.fromkeys(
        FAMILIES, 0
    )
    return status


def test_random_blob_is_os_undetermined_offline_and_quiet(
    setup: tuple[Workspace, VolatilityEngine],
) -> None:
    ws, engine = setup
    rng = random.Random(8)  # seeded: the same 16 MiB every run
    ws.image.write_bytes(rng.randbytes(16 * 1024**2))
    os.chmod(ws.image, 0o444)
    started = time.monotonic()
    run = engine.identify(ws, OsHint.AUTO, 600)
    assert run.end == "exited", run
    status = _status(ws, run.dirs)
    print(f"identify on 16 MiB random: {time.monotonic() - started:.1f} s")
    plugin = engine.run(ws, MemoryPlugin.WINDOWS_PSLIST, 300, 100)
    assert plugin.end in ("exited", "failed")
    assert _status(ws, plugin.dirs).status == "unsupported"  # type: ignore[attr-defined]
    record = IdentifyRecord.model_validate(status.identify)  # type: ignore[attr-defined]
    with pytest.raises(IdentifyRefused) as caught:
        choose(record, OsHint.AUTO)
    assert caught.value.code == "os_undetermined"


@pytest.mark.skipif(not HEAVY, reason="the sparse 8 GiB case runs with MEMORY_PROBE_HEAVY=1")
def test_sparse_8_gib_file_stays_within_the_address_space_limit(
    setup: tuple[Workspace, VolatilityEngine],
) -> None:
    ws, engine = setup
    with open(ws.image, "wb") as f:
        f.truncate(SPARSE_BYTES)
    os.chmod(ws.image, 0o444)
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    started = time.monotonic()
    run = engine.identify(ws, OsHint.AUTO, 600)
    elapsed = time.monotonic() - started
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024  # KiB on Linux
    print(f"identify on a sparse 8 GiB file: {elapsed:.1f} s, peak child RSS {peak >> 20} MiB")
    assert run.end == "exited", run
    record = IdentifyRecord.model_validate(_status(ws, run.dirs).identify)  # type: ignore[attr-defined]
    with pytest.raises(IdentifyRefused):
        choose(record, OsHint.AUTO)
    assert peak < engine.config.plugin_rlimit_as and peak >= before
