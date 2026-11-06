"""Memory worker tests (M8 phase 1, FROZEN fixtures).

Unit tests are pure Python; engine and sandbox tests run inside `memory-worker-test` (root +
the analyzers' capabilities, a per-container tmpfs `/work` so concurrent lanes never share or
reset each other's work dir, RT6). Tests never use the shared `memory_symbols_test` volume:
they build their own store in a temp dir and point `MEMORY_SYMBOLS_DIR` at it (`symbol_store`).
"""

import os
import shutil
import uuid
from collections.abc import Iterator
from pathlib import Path

import cyberlab_jobs
import pytest
from cyberlab_worker import sandbox

TESTS = Path(__file__).parent
# The shared `memory.v1` fixtures (hand-written, labelled synthetic) of the contract package.
CONTRACT_FIXTURES = (
    Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures" / "memory"
)
BASE_WORK = Path(os.environ.get("WORK_DIR", "/work"))
# One work dir per test session: sandbox.prepare() wipes everything in the work dir it is
# given, so two sessions sharing one must not (the test container's /work is its own tmpfs).
WORK = BASE_WORK / f"session-{uuid.uuid4().hex[:12]}"


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


in_container = pytest.mark.skipif(
    not _is_root(), reason="runs inside the memory-worker image (root + capabilities)"
)


@pytest.fixture(scope="session", autouse=True)
def session_work_dir() -> Iterator[None]:
    if not _is_root():
        yield
        return
    BASE_WORK.chmod(0o711)  # noqa: S103 - traverse-only, as sandbox.reset() sets it
    WORK.mkdir(mode=0o711)
    yield
    sandbox.kill_tool_processes()
    shutil.rmtree(WORK, ignore_errors=True)


@pytest.fixture
def dirs() -> Iterator[sandbox.JobDirs]:
    """A real job directory on the test container's work tmpfs."""
    if not _is_root():
        pytest.skip("sandbox tests run inside the memory-worker container (root + capabilities)")
    job = sandbox.prepare(WORK, f"test-{uuid.uuid4()}")
    yield job
    sandbox.cleanup(job)


@pytest.fixture
def symbol_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty per-test symbol store (`MEMORY_SYMBOLS_DIR`): never the shared volume (RT6)."""
    root = tmp_path / "symbols"
    (root / "windows").mkdir(parents=True)
    (root / "linux").mkdir()
    (root / ".cache" / "volatility3").mkdir(parents=True)
    (root / "manifest.json").write_text(
        '{"version": 1, "volatility_version": "2.28.2", "files": []}\n'
    )
    monkeypatch.setenv("MEMORY_SYMBOLS_DIR", str(root))
    return root
