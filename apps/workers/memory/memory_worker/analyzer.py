"""Memory analysis of one image (phase-1 STUB; phase 2 implements the Volatility runner).

`analyze(job, dirs, config) -> Path` returns the written `memory.v1` result file, or raises
`JobFailed(code)` with a `MEMORY_ERROR_CODES` code. Phase 1 always raises `not_implemented`:
no image is downloaded, no tool runs, nothing is uploaded.
"""

from pathlib import Path

from cyberlab_jobs.memory import MemoryJobV1
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from memory_worker.config import Config


def analyze(job: MemoryJobV1, dirs: sandbox.JobDirs, config: Config) -> Path:
    del job, dirs, config
    raise JobFailed("not_implemented")
