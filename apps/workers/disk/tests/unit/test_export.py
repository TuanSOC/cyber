"""The root side of a file export (M9 phase 10) with the stage processes replaced by canned
probe output (`Job.run`), the downloads and the presigned POSTs captured.

Covers: a valid `disk-export.v1` stream (header with every file's outcome, hashed trailer);
root re-reads the sealed `export/<n>` and reports ITS sha256 and size (not the probe's); each
file goes to its own POST and the stream to the last one; per-file failures (the probe's
refusal of a reallocated / changed entry, a size that disagrees with the probe or exceeds the
listed size, a stage skipped by the deadline, an unknown partition, a failed upload) never fail
the job; job-wide failures (free space, format) report `failed` without any upload.

Runs where the worker kit imports (Linux: the disk-worker-test service), as any uid: nothing
here starts a process.
"""

import gzip
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs import IngestMessageV1, PresignedPost
from cyberlab_jobs.disk import (
    DISK_EXPORT_LINE_ADAPTER,
    DiskExportJobV1,
    DiskExportResultHeader,
    StageStatus,
)
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from disk_worker import analyzer, export, pipeline, stage
from disk_worker.config import load
from tests.unit.phase2_helpers import limits_dict
from tests.unit.test_pipeline import PARTITION

SHA = "a" * 64
CONTENT = b"MZ" + b"\x90" * 510


def _post(i: int) -> dict[str, Any]:
    return {"url": "http://minio:9000/results", "fields": {"key": f"k{i}"}}


def _message(files: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {
        "job_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "source_job_id": str(uuid.uuid4()),
        "segments": [
            {
                "ordinal": 0,
                "evidence_id": str(uuid.uuid4()),
                "expected_sha256": SHA,
                "size_bytes": 4096,
                "url": "http://minio:9000/evidence/0",
            }
        ],
        "files": files,
        "result_posts": [_post(i) for i in range(len(files) + 1)],
        "ingest_token": "t" * 43,
        "limits": limits_dict(artifact_max_bytes=1024**2),
        "deadline_at": (datetime.now(UTC) + timedelta(hours=4)).isoformat(),
        **extra,
    }


def _file(meta_addr: int, size: int = len(CONTENT), **kw: Any) -> dict[str, Any]:
    return {
        "export_id": str(uuid.uuid4()),
        "partition_index": 0,
        "meta_addr": meta_addr,
        "meta_seq": 1,
        "expected_size": size,
        **kw,
    }


def _config(tmp_path: Path) -> Any:
    return load(
        {
            "BROKER_URL": "redis://disk:x@redis-broker:6379/0",
            "WORK_DIR": str(tmp_path),
            "DISK_WORK_MIN_FREE_BYTES": "0",
            "DISK_TIMELINE_ENGINE": "none",
            "DISK_HASHSETS_DIR": str(tmp_path / "no-hashsets"),
        }
    )


@pytest.fixture
def job_dirs(tmp_path: Path) -> sandbox.JobDirs:
    root = tmp_path / "job"
    (root / "input").mkdir(parents=True)
    (root / "out").mkdir()
    return sandbox.JobDirs(root=root, input=root / "input", out=root / "out")


class Probe:
    """Stands in for `Job.run`: `layout` lists one ext4 partition; `extract` writes
    `export/<n>` with the bytes chosen per meta_addr and reports a size (the real file's by
    default)."""

    def __init__(self, tmp: Path, extract: dict[int, dict[str, Any]]) -> None:
        self.tmp = tmp
        self.extract = extract
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(
        self, probe_stage: str, key: str, name: str, args: dict[str, Any]
    ) -> stage.StageResult:
        self.calls.append((name, args))
        out = self.tmp / f"{name}-out"
        out.mkdir()
        if probe_stage == "layout":
            (out / "partitions.jsonl").write_text(json.dumps(PARTITION) + "\n")
            return stage.StageResult(
                stage="layout",
                status=StageStatus.OK,
                out_dir=out,
                has_status=True,
                facts={"media_size": 4096, "sector_size": 512},
            )
        spec = self.extract[int(args["meta_addr"])]
        status = spec.get("status", StageStatus.OK)
        facts: dict[str, Any] = {}
        if "content" in spec:
            (out / "export").mkdir()
            (out / "export" / str(args["n"])).write_bytes(spec["content"])
            facts = {
                "size": spec.get("size", len(spec["content"])),
                "sha256": spec.get("sha256", "f" * 64),  # the probe's: never reported
            }
        return stage.StageResult(
            stage="extract",
            status=status,
            out_dir=out,
            has_status=spec.get("has_status", True),
            truncated=spec.get("truncated", False),
            facts=facts,
            error_code=spec.get("error_code"),
        )


def _decode(path: Path) -> list[dict[str, Any]]:
    with gzip.open(path, "rt") as f:
        return [json.loads(line) for line in f]


def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    job_dirs: sandbox.JobDirs,
    files: list[dict[str, Any]],
    extract: dict[int, dict[str, Any]],
    *,
    failing_upload: bool = False,
) -> tuple[DiskExportResultHeader, list[tuple[str, bytes]], Probe]:
    monkeypatch.setenv("TEST_PROFILE", "1")
    probe = Probe(tmp_path, extract)
    uploads: list[tuple[str, bytes]] = []

    def upload(post: PresignedPost, path: Path, **_: Any) -> str:
        if failing_upload:
            raise JobFailed("result_upload_failed", "HTTP 403")
        uploads.append((post.fields["key"], path.read_bytes()))
        return "v1"

    monkeypatch.setattr(analyzer, "download", lambda url, dest, **_: dest.write_bytes(b"\0" * 4096))
    monkeypatch.setattr(analyzer.Job, "run", probe)
    monkeypatch.setattr(export, "upload", upload)
    msg = DiskExportJobV1.model_validate(_message(files))
    path = export.handle_export(msg, job_dirs, _config(tmp_path))
    lines = _decode(path)
    assert [line["kind"] for line in lines] == ["header", "trailer"]
    for line in lines:
        DISK_EXPORT_LINE_ADAPTER.validate_python(line)
    header = DiskExportResultHeader.model_validate(lines[0])
    assert header.job_id == msg.job_id
    return header, uploads, probe


def test_root_reports_its_own_hash_and_each_file_reaches_its_post(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job_dirs: sandbox.JobDirs
) -> None:
    files = [_file(100), _file(200, meta_seq=3, stream="Zone.Identifier")]
    other = b"second file"
    files[1]["expected_size"] = len(other)
    header, uploads, probe = _run(
        monkeypatch,
        tmp_path,
        job_dirs,
        files,
        {100: {"content": CONTENT}, 200: {"content": other}},
    )
    assert [f.status for f in header.files] == ["ok", "ok"]
    assert header.files[0].sha256 == hashlib.sha256(CONTENT).hexdigest()  # root's, not "f"*64
    assert header.files[0].size == len(CONTENT)
    assert [str(f.export_id) for f in header.files] == [f["export_id"] for f in files]
    assert uploads == [("k0", CONTENT), ("k1", other)]  # never the result POST (k2)
    names = [name for name, _ in probe.calls]
    assert names == ["layout", "extract-0", "extract-1"]
    args = probe.calls[2][1]
    assert (args["meta_addr"], args["meta_seq"], args["stream"]) == (200, 3, "Zone.Identifier")
    assert args["offset"] == PARTITION["start_sector"] * PARTITION["sector_size"]
    assert args["family"] == "ext" and args["expected_size"] == len(other) and args["n"] == 1


def test_per_file_failures_never_fail_the_job(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job_dirs: sandbox.JobDirs
) -> None:
    files = [
        _file(1),  # refused by the probe: reallocated / no longer a regular file
        _file(2),  # the probe reports another size than the file it wrote
        _file(3, size=4),  # wrote more than the listed size
        _file(4),  # killed past its write budget (RLIMIT_FSIZE)
        _file(5),  # skipped: no time left before the deadline
        _file(6, partition_index=9),  # no such partition in the layout
        _file(7),  # fine
    ]
    extract = {
        1: {"status": StageStatus.FAILED, "error_code": "disk_export_not_allowed"},
        2: {"content": CONTENT, "size": len(CONTENT) - 1},
        3: {"content": CONTENT, "size": 4},
        4: {"content": CONTENT[:10], "status": StageStatus.TRUNCATED, "truncated": True},
        5: {"status": StageStatus.SKIPPED, "has_status": False},
        7: {"content": CONTENT},
    }
    header, uploads, _ = _run(monkeypatch, tmp_path, job_dirs, files, extract)
    codes = [(f.status, f.error_code) for f in header.files]
    assert codes == [
        ("failed", "disk_export_not_allowed"),
        ("failed", "disk_parse_failed"),
        ("failed", "disk_parse_failed"),
        ("failed", "disk_export_not_allowed"),
        ("failed", "stage_timeout"),
        ("failed", "disk_parse_failed"),
        ("ok", None),
    ]
    assert [key for key, _ in uploads] == ["k6"]  # only the exported file was POSTed


def test_a_failed_upload_fails_that_file_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job_dirs: sandbox.JobDirs
) -> None:
    header, _, _ = _run(
        monkeypatch,
        tmp_path,
        job_dirs,
        [_file(100)],
        {100: {"content": CONTENT}},
        failing_upload=True,
    )
    assert (header.files[0].status, header.files[0].error_code) == (
        "failed",
        "result_upload_failed",
    )


def test_insufficient_free_space_is_refused_before_the_download(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job_dirs: sandbox.JobDirs
) -> None:
    class Usage:
        free = 1024

    monkeypatch.setattr(export.shutil, "disk_usage", lambda _p: Usage())
    monkeypatch.setattr(analyzer, "download", lambda *a, **k: pytest.fail("downloaded"))
    msg = DiskExportJobV1.model_validate(_message([_file(100)]))
    with pytest.raises(JobFailed) as exc:
        export.handle_export(msg, job_dirs, _config(tmp_path))
    assert exc.value.code == "insufficient_disk"


def test_a_foreign_container_is_refused_before_any_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job_dirs: sandbox.JobDirs
) -> None:
    monkeypatch.setenv("TEST_PROFILE", "1")
    gzip_magic = b"\x1f\x8b\x08" + b"\0" * 4093
    monkeypatch.setattr(analyzer, "download", lambda url, dest, **_: dest.write_bytes(gzip_magic))
    monkeypatch.setattr(analyzer.Job, "run", lambda *a: pytest.fail("a probe ran"))
    msg = DiskExportJobV1.model_validate(_message([_file(100)]))
    with pytest.raises(JobFailed) as exc:
        export.handle_export(msg, job_dirs, _config(tmp_path))
    assert exc.value.code == "unsupported_disk_format"


# --- the ingest envelope ------------------------------------------------------------------


@pytest.fixture
def no_sandbox(monkeypatch: pytest.MonkeyPatch, job_dirs: sandbox.JobDirs) -> None:
    monkeypatch.setattr(pipeline.sandbox, "prepare", lambda work, job: job_dirs)
    monkeypatch.setattr(pipeline.sandbox, "cleanup", lambda dirs: None)


def _envelope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, handle: Any
) -> tuple[list[IngestMessageV1], list[tuple[str, Path]]]:
    sent: list[IngestMessageV1] = []
    uploads: list[tuple[str, Path]] = []
    monkeypatch.setattr(pipeline, "handle_export", handle)
    monkeypatch.setattr(
        pipeline, "upload", lambda post, path: uploads.append((post.fields["key"], path)) or "v9"
    )
    pipeline.run_export_job(_message([_file(1), _file(2)]), _config(tmp_path), sent.append)
    return sent, uploads


def test_the_stream_goes_to_the_last_post_and_is_succeeded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_sandbox: None
) -> None:
    stream = tmp_path / "s.gz"
    sent, uploads = _envelope(monkeypatch, tmp_path, lambda msg, dirs, config: stream)
    assert [m.event.value for m in sent] == ["started", "finished"]
    assert sent[1].outcome is not None and sent[1].outcome.value == "succeeded"
    assert sent[1].result_version_id == "v9"
    assert uploads == [("k2", stream)]


def test_a_job_wide_failure_is_reported_without_an_upload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_sandbox: None
) -> None:
    def handle(msg: Any, dirs: Any, config: Any) -> Path:
        raise JobFailed("integrity_mismatch")

    sent, uploads = _envelope(monkeypatch, tmp_path, handle)
    assert sent[1].error_code == "integrity_mismatch"
    assert sent[1].result_version_id is None and uploads == []
