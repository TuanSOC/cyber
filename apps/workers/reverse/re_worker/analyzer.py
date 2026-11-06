"""Reverse engineering of one sample (phase-1 STUB; phase 2 implements the pipeline).

`analyze(job, dirs, config) -> Path` returns the written `re.v1` result file, raises
`DiagnosticResult(code, path)` for an `unsupported_architecture` / `unsupported_managed_code`
diagnostic stream (header, program, trailer), or raises `JobFailed(code)` with an
`RE_ERROR_CODES` code. Phase 1 always raises `not_implemented`: no sample is downloaded, no
tool runs, nothing is uploaded.
"""

from pathlib import Path

from cyberlab_jobs.reverse import DIAGNOSTIC_ERROR_CODES, ReJobV1
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from re_worker.config import Config


class DiagnosticResult(Exception):  # noqa: N818 - a result, not an error
    """The diagnostic stream was written: upload it with a failed report and this code."""

    def __init__(self, code: str, path: Path) -> None:
        if code not in DIAGNOSTIC_ERROR_CODES:
            raise ValueError(f"not a diagnostic code: {code}")
        super().__init__(code)
        self.code = code
        self.path = path


def analyze(job: ReJobV1, dirs: sandbox.JobDirs, config: Config) -> Path:
    del job, dirs, config
    raise JobFailed("not_implemented")
