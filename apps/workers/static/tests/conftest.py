import json
import os
import shutil
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cyberlab_worker import sandbox

TESTS = Path(__file__).parent
CLAMAV_TEST_DB = TESTS / "clamav"
YARA_TEST_RULES = TESTS / "rules" / "yara"
CAPA_TEST_RULES = TESTS / "rules" / "capa"
BASE_WORK = Path(os.environ.get("WORK_DIR", "/work"))
# One work dir per test session: sandbox.prepare() wipes everything in the work dir it is
# given, so two test runs sharing the volume (parallel containers) must not share one.
WORK = BASE_WORK / f"session-{uuid.uuid4().hex[:12]}"

in_container = pytest.mark.skipif(
    os.geteuid() != 0, reason="runs inside the static-worker image (root + capabilities)"
)


@pytest.fixture(scope="session", autouse=True)
def session_work_dir() -> Iterator[None]:
    if os.geteuid() != 0:
        yield
        return
    BASE_WORK.chmod(0o711)  # noqa: S103 - traverse-only, as sandbox.reset() sets it
    WORK.mkdir(mode=0o711)
    yield
    sandbox.kill_tool_processes()
    shutil.rmtree(WORK, ignore_errors=True)


@dataclass(frozen=True)
class SampleSet:
    paths: dict[str, Path]
    labels: dict[str, dict[str, Any]]


@pytest.fixture(scope="session")
def sample_set() -> SampleSet:
    """The generated synthetic set (root-only /tmp: the job's input copy is what tools read)."""
    if os.geteuid() != 0:
        pytest.skip("runs inside the static-worker image")
    from samples.generate import generate

    out = Path("/tmp/static-samples")
    shutil.rmtree(out, ignore_errors=True)
    paths = generate(out)
    return SampleSet(paths, json.loads((out / "labels.json").read_text()))


@pytest.fixture
def dirs() -> Iterator[sandbox.JobDirs]:
    """A real job directory on the worker's work volume (tests run inside the worker image)."""
    if os.geteuid() != 0:
        pytest.skip("sandbox tests run inside the static-worker container (root + capabilities)")
    job = sandbox.prepare(WORK, f"test-{uuid.uuid4()}")
    yield job
    sandbox.cleanup(job)
