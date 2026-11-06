"""File export (`disk-export.v1`, profile `extract`; M9 phase 1 stub, phase 10 owns the body).

`handle_export(msg) -> None`: download and verify the segments, run the probe `extract` per
file (allocated regular files only, <= 64 MiB, no name of the inode on the never-collected list,
RT7), POST each file to its presigned form and the result stream to the last one, then report.
"""

from cyberlab_jobs.disk import DiskExportJobV1
from cyberlab_worker.errors import JobFailed


def handle_export(msg: DiskExportJobV1) -> None:
    raise JobFailed("not_implemented", "disk file export lands with M9 phase 10")
