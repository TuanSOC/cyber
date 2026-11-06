"""RE worker tests (M10 phase 1, FROZEN fixtures).

Unit tests are pure Python; engine and sandbox tests run inside `re-worker-test` (root + the
analyzers' capabilities). Its `/work` is an anonymous per-container volume (disk-backed,
removed with `--rm`, RT22: a tmpfs would count against the 4 GiB cgroup), so concurrent lanes
never share or reset each other's work dir. Every run that starts a JVM is `--heavy`.
"""

import os
import shutil
import uuid
from collections.abc import Iterator
from pathlib import Path

import cyberlab_jobs
import pytest

TESTS = Path(__file__).parent
# The shared `re.v1` fixtures (hand-written, labelled synthetic) of the contract package.
CONTRACT_FIXTURES = (
    Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures" / "reverse"
)
BASE_WORK = Path(os.environ.get("WORK_DIR", "/work"))
# One work dir per test session: sandbox.prepare() wipes everything in the work dir it is
# given, so two sessions sharing one must not.
WORK = BASE_WORK / f"session-{uuid.uuid4().hex[:12]}"


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


in_container = pytest.mark.skipif(
    not _is_root(), reason="runs inside the re-worker image (root + capabilities)"
)


@pytest.fixture(scope="session", autouse=True)
def session_work_dir() -> Iterator[None]:
    if not _is_root():
        yield
        return
    WORK.mkdir(parents=True, exist_ok=True)
    previous = os.environ.get("WORK_DIR")
    os.environ["WORK_DIR"] = str(WORK)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("WORK_DIR", None)
        else:
            os.environ["WORK_DIR"] = previous
        shutil.rmtree(WORK, ignore_errors=True)
