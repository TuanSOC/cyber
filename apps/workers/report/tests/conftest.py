"""Report renderer tests run inside `report-worker-test` (root + capabilities, /work tmpfs);
the sandbox fixtures of phase 4 build on `WORK`."""

import os
from pathlib import Path

import pytest

WORK = Path(os.environ.get("WORK_DIR", "/work"))

in_container = pytest.mark.skipif(
    os.geteuid() != 0, reason="runs inside the report-worker image (root + capabilities)"
)
