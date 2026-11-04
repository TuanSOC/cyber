import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from pcap_worker import sandbox


@pytest.fixture
def dirs() -> Iterator[sandbox.JobDirs]:
    """A real job directory on the worker's work volume (tests run inside the worker image)."""
    if os.geteuid() != 0:
        pytest.skip("sandbox tests run inside the pcap-worker container (root + capabilities)")
    job = sandbox.prepare(Path(os.environ.get("WORK_DIR", "/work")), f"test-{uuid.uuid4()}")
    job.capture.write_bytes(b"capture bytes")
    job.capture.chmod(0o444)
    yield job
    sandbox.cleanup(job)
