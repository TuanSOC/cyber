"""File export (`disk-export.v1`, job profile `extract`; M9 phase 10).

`handle_export(msg, dirs, config) -> Path`: the root side of one export job; returns the result
stream (`disk-export.v1`: one header with every file's outcome, then the trailer) that the
pipeline uploads to the last result POST and reports `succeeded` (a file's own failure is in
the stream: the trusted ingest marks it).

1. The free-space check (the image, every file, the floor and the headroom) →
   `insufficient_disk`;
2. phase 2's download path: every segment downloaded through the kit (sha256 + size verified,
   root-owned 0444; `integrity_mismatch`), no image cache (RT1), within the job's deadline
   budget; the magic check (`unsupported_disk_format` before any probe runs);
3. phase 2's `probe layout` (each partition's offset and file-system family);
4. per file, one sandboxed `probe extract` stage (`stage.run_stage`: fresh out dir, deadline
   budget, watchdog, kill + seal) on its natural key (`partition_index`, `meta_addr`, the
   listed `meta_seq` re-checked by the probe, the named `stream`): an entry that is no longer
   an allocated regular file with that sequence, or is larger than the listed size, is
   refused by the probe (`disk_export_not_allowed`); a stage that cannot start or finish in
   the budget is `stage_timeout`;
5. root re-reads the sealed `export/<n>` (a regular file, never followed through a link),
   checks its size against the probe's report and the listed size, hashes it (the sha256 the
   stream reports: still untrusted for the API, which re-hashes at promotion) and POSTs it to
   the file's presigned form (key and size fixed by the API's policy).

Root never parses the image beyond the magic check; nothing of the image reaches argv (the
stage arguments are root-written JSON in the read-only input dir).
"""

import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from cyberlab_jobs import PresignedPost
from cyberlab_jobs.disk import (
    DiskExportFile,
    DiskExportJobV1,
    DiskExportResultHeader,
    DiskJobV1,
    ExportedFile,
    ImageFormat,
    StageStatus,
)
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed
from cyberlab_worker.result_writer import ResultWriter
from cyberlab_worker.transfer import upload

from disk_worker import analyzer
from disk_worker.budget import Budget
from disk_worker.config import Config, tool_versions
from disk_worker.result import RunFacts

RESULT = "export-result.ndjson.gz"
CHUNK = 1024 * 1024
FILE_NAME = "exported.bin"
CONTENT_TYPE = "application/octet-stream"
# A stage that never ran (deadline) or ran out of time; a refusal by the probe; anything else.
TIMEOUT = "stage_timeout"
REFUSED = "disk_export_not_allowed"
BROKEN = "disk_parse_failed"
UPLOAD_FAILED = "result_upload_failed"
PROBE_CODES = frozenset({REFUSED, "engine_unavailable", "walk_memory", BROKEN})


@dataclass(frozen=True)
class Extracted:
    """A sealed file root read back: its path, size and root-computed sha256."""

    path: Path
    size: int
    sha256: str


def required_free(msg: DiskExportJobV1, config: Config) -> int:
    images = sum(s.size_bytes for s in msg.segments)
    files = sum(f.expected_size for f in msg.files)
    headroom = analyzer.TEST_HEADROOM if analyzer._test_profile() else analyzer.HEADROOM
    return images + files + config.min_free_bytes + headroom


def _failed(f: DiskExportFile, code: str) -> ExportedFile:
    return ExportedFile(export_id=f.export_id, status="failed", error_code=code)


def read_back(out_dir: Path, n: int, reported_size: object, expected: int) -> Extracted | None:
    """The probe's `export/<n>`, opened without following links (a regular file only), sized
    and hashed by root; None when it is missing, not regular, empty, larger than the listed
    size or not the size the probe reported."""
    dirs = sandbox.JobDirs(root=out_dir.parent, input=out_dir, out=out_dir / "export")
    digest = hashlib.sha256()
    size = 0
    try:
        with sandbox.open_output(dirs, str(n)) as f:
            while chunk := f.read(CHUNK):
                size += len(chunk)
                if size > expected:
                    return None
                digest.update(chunk)
    except (OSError, ValueError):
        return None
    if size <= 0 or not isinstance(reported_size, int) or reported_size != size:
        return None
    return Extracted(path=dirs.out / str(n), size=size, sha256=digest.hexdigest())


def _extract_one(j: analyzer.Job, n: int, f: DiskExportFile, post: PresignedPost) -> ExportedFile:
    partition = next((p for p in j.partitions if p.index == f.partition_index), None)
    if partition is None or partition.family is None or partition.row.fs_status != "ok":
        return _failed(f, BROKEN)
    res = j.run(
        "extract",
        "extract",
        f"extract-{n}",
        {
            "offset": partition.offset,
            "family": partition.family,
            "meta_addr": f.meta_addr,
            "meta_seq": f.meta_seq,
            "stream": f.stream,
            "expected_size": f.expected_size,
            "n": n,
        },
    )
    if res.status in (StageStatus.SKIPPED, StageStatus.TIMEOUT):
        return _failed(f, TIMEOUT)
    if res.truncated:  # RLIMIT_FSIZE / the write budget: more than the listed size
        return _failed(f, REFUSED)
    if not res.usable:
        code = res.error_code if res.error_code in PROBE_CODES else None
        return _failed(f, code or BROKEN)
    extracted = read_back(res.out_dir, n, res.facts.get("size"), f.expected_size)
    if extracted is None:
        return _failed(f, BROKEN)
    try:
        upload(post, extracted.path, filename=FILE_NAME, content_type=CONTENT_TYPE)
    except JobFailed:
        return _failed(f, UPLOAD_FAILED)
    return ExportedFile(
        export_id=f.export_id, status="ok", size=extracted.size, sha256=extracted.sha256
    )


def write_stream(path: Path, msg: DiskExportJobV1, files: list[ExportedFile]) -> Path:
    header = DiskExportResultHeader(job_id=msg.job_id, tool_versions=tool_versions(), files=files)
    with ResultWriter(path) as writer:
        writer.write(header)
    return path


def handle_export(msg: DiskExportJobV1, dirs: sandbox.JobDirs, config: Config) -> Path:
    budget = Budget(msg.deadline_at, msg.limits)
    if shutil.disk_usage(config.work_dir).free < required_free(msg, config):
        raise JobFailed("insufficient_disk")
    facts = RunFacts(
        job_id=msg.job_id,
        profile="extract",
        tool_versions=tool_versions(),
        format=ImageFormat.RAW,
        segments=len(msg.segments),
    )
    # The download and layout helpers read only the segments, the limits and the job id,
    # which both message schemas share (an export job is never assembled into `disk.v1`).
    j = analyzer.Job(job=cast(DiskJobV1, msg), dirs=dirs, config=config, budget=budget, facts=facts)
    analyzer._download(j)
    analyzer._layout(j)
    outcomes = [
        _extract_one(j, n, f, post)
        for n, (f, post) in enumerate(zip(msg.files, msg.result_posts[:-1], strict=True))
    ]
    return write_stream(dirs.root / RESULT, msg, outcomes)


__all__ = ["RESULT", "Extracted", "handle_export", "read_back", "required_free", "write_stream"]
