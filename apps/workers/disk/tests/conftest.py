"""Shared fixtures of the disk worker tests (M9 phase 1, FROZEN names).

- `CONTRACT_FIXTURES` / `PSORT_FIXTURES`: the py-jobs `disk.v1` and psort-shaped fixtures
  (hand-written, labelled synthetic);
- `dirs`: a real job directory on the worker's work volume (tests that need it run inside the
  worker image as root; skipped elsewhere).
"""

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import cyberlab_jobs
import pytest
from cyberlab_worker import sandbox

_FIXTURES = Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures"
CONTRACT_FIXTURES = _FIXTURES / "disk"
PSORT_FIXTURES = _FIXTURES / "psort"


@pytest.fixture
def dirs() -> Iterator[sandbox.JobDirs]:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        pytest.skip("sandbox tests run inside the disk worker container (root + capabilities)")
    job = sandbox.prepare(Path(os.environ.get("WORK_DIR", "/work")), f"test-{uuid.uuid4()}")
    yield job
    sandbox.cleanup(job)
