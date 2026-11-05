"""Report renderer tests run inside `report-worker-test` (root + capabilities, /work tmpfs):

    scripts/lane-test.sh <lane> --service report-worker-test pytest -q tests/

Fixtures: `dirs` (a fresh job dir under /work, cleaned up after the test), the golden and
hostile snapshots, and `stage()` which writes a job's input dir the way `tasks` does.
"""

import hashlib
import json
import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cyberlab_jobs.report import ReportSnapshot, canonical_json, parse_snapshot
from cyberlab_worker import sandbox

WORK = Path(os.environ.get("WORK_DIR", "/work"))
FIXTURES = Path(__file__).parent / "fixtures"

in_container = pytest.mark.skipif(
    os.geteuid() != 0, reason="runs inside the report-worker image (root + capabilities)"
)


def load_snapshot(name: str) -> ReportSnapshot:
    return parse_snapshot((FIXTURES / name).read_bytes())


@pytest.fixture
def golden() -> ReportSnapshot:
    return load_snapshot("golden_snapshot.json")


@pytest.fixture
def hostile() -> ReportSnapshot:
    return load_snapshot("hostile_snapshot.json")


@pytest.fixture
def dirs() -> Iterator[sandbox.JobDirs]:
    if os.geteuid() != 0:
        pytest.skip("sandbox tests run inside the report-worker image (root + capabilities)")
    job = sandbox.prepare(WORK, f"test-{uuid.uuid4()}")
    yield job
    sandbox.cleanup(job)


def stage(
    dirs: sandbox.JobDirs,
    snapshot: ReportSnapshot,
    fmt: str = "pdf",
    *,
    manifest: bytes = b'{"manifest":"test"}',
    signature: bytes = b'{"signature":"test"}',
) -> tuple[bytes, str]:
    """Write snapshot.json, manifest.json, manifest.sig.json and job.json (root, 0444)."""
    data = canonical_json(snapshot)
    sha = hashlib.sha256(data).hexdigest()
    job = {
        "format": fmt,
        "sha256": sha,
        "finalized_at": snapshot.report.finalized_at.astimezone(UTC).isoformat(),
    }
    for name, content in (
        ("snapshot.json", data),
        ("manifest.json", manifest),
        ("manifest.sig.json", signature),
        ("job.json", json.dumps(job).encode()),
    ):
        path = dirs.input / name
        path.write_bytes(content)
        path.chmod(0o444)
    return data, sha


def now() -> datetime:
    return datetime.now(UTC)
