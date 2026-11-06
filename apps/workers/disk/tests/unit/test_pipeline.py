"""The root pipeline (M9 phase 2) with the stage processes replaced by canned probe output.

Covers: the ingest envelope around `analyze` (succeeded / diagnostic / failed), the free-space
check, the magic check refusing before any probe runs, the full assembly into a valid
`disk.v1` stream (line order, contract validation), the diagnostic stream when no file system
opened, the never-collected check over every name of an inode (the hard link to `etc/shadow`
is never handed to `collect`, RT7), a walk with too many bad rows, and the EWF mismatch finding.

Runs where the worker kit imports (Linux: the disk-worker-test service), as any uid: nothing
here starts a process.
"""

import gzip
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs import IngestMessageV1
from cyberlab_jobs.disk import (
    DISK_LINE_ADAPTER,
    DiskArtifact,
    DiskJobV1,
    StageStatus,
    check_diagnostic_kinds,
    check_line_order,
)
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from disk_worker import analyzer, pipeline, stage
from disk_worker.config import load
from disk_worker.timeline import catalog
from tests.unit.phase2_helpers import limits_dict

POST = {"url": "http://minio:9000/results", "fields": {"key": "k"}}
SHA = "a" * 64


def _job(segments: int = 1, **extra: Any) -> dict[str, Any]:
    return {
        "job_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "segments": [
            {
                "ordinal": i,
                "evidence_id": str(uuid.uuid4()),
                "expected_sha256": SHA,
                "size_bytes": 4096,
                "url": f"http://minio:9000/evidence/{i}",
            }
            for i in range(segments)
        ],
        "profile": "triage",
        "os_hint": "auto",
        "result_post": POST,
        "ingest_token": "t" * 43,
        # A small artifact budget: the free-space check wants 3 x it on the test volume.
        "limits": limits_dict(artifact_max_bytes=1024**2),
        "deadline_at": (datetime.now(UTC) + timedelta(hours=4)).isoformat(),
        **extra,
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


def _row(n: int, path: str, meta_addr: int, parent: int, **kw: Any) -> dict[str, Any]:
    name = path.rsplit("/", 1)[1]
    base: dict[str, Any] = {
        "n": n,
        "meta_addr": meta_addr,
        "meta_seq": 1,
        "stream": None,
        "path": path,
        "path_truncated": False,
        "parent_addr": parent,
        "name": name,
        "name_lossy": False,
        "ext": name.rsplit(".", 1)[1] if "." in name else None,
        "type": "reg",
        "allocated": True,
        "deleted": False,
        "orphan": False,
        "reallocated": False,
        "hard_linked": False,
        "size": 10,
        "mode": 0o644,
        "uid": 0,
        "gid": 0,
        "times": {"mtime": [1_700_000_000, 0]},
        "time_basis": "utc",
        "magic": "other",
        "hash_status": "pending",
        "md5": None,
        "sha1": None,
        "sha256": None,
    }
    base.update(kw)
    return base


LINUX_FILES = [
    _row(0, "/etc", 10, 2, type="dir", size=4096, hash_status="not_regular", magic=None),
    _row(1, "/etc/shadow", 50, 10, hard_linked=True),
    _row(2, "/var", 11, 2, type="dir", size=4096, hash_status="not_regular", magic=None),
    _row(3, "/var/auth.log", 50, 11, hard_linked=True),
    _row(4, "/etc/os-release", 51, 10),
    _row(5, "/var/syslog", 52, 11),
]
PARTITION = {
    "index": 0,
    "start_sector": 2048,
    "length_sectors": 100_000,
    "sector_size": 512,
    "volume_system": "dos",
    "description": "Linux (0x83)",
    "fs_type": "ext4",
    "fs_status": "ok",
    "reason": None,
    "block_size": 4096,
    "os": "linux",
    "os_name": "Debian GNU/Linux 12 (bookworm)",
    "counts": {"blocks": 1000, "inodes": 100},
}


class Canned:
    """Stands in for `Job.run`: writes each stage's probe output into a fresh dir."""

    def __init__(self, tmp: Path, outputs: dict[str, dict[str, Any]]) -> None:
        self.tmp = tmp
        self.outputs = outputs
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(
        self, probe_stage: str, key: str, name: str, args: dict[str, Any]
    ) -> stage.StageResult:
        self.calls.append((name, args))
        spec = self.outputs.get(probe_stage, {})
        out = self.tmp / f"{name}-out"
        out.mkdir()
        for fname, rows in spec.get("files", {}).items():
            (out / fname).write_text("".join(json.dumps(r) + "\n" for r in rows))
        return stage.StageResult(
            stage=key,  # type: ignore[arg-type]
            status=spec.get("status", StageStatus.OK),
            out_dir=out,
            has_status=spec.get("has_status", True),
            facts=spec.get("facts", {}),
            error_code=spec.get("error_code"),
        )


def _fake_download(content: bytes) -> Any:
    def download(url: str, dest: Path, **_: Any) -> None:
        dest.write_bytes(content)

    return download


def _decode(path: Path) -> list[dict[str, Any]]:
    with gzip.open(path, "rt") as f:
        return [json.loads(line) for line in f]


def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    job_dirs: sandbox.JobDirs,
    outputs: dict[str, dict[str, Any]],
    content: bytes = b"\x00" * 4096,
    **job: Any,
) -> tuple[Path, Canned]:
    monkeypatch.setenv("TEST_PROFILE", "1")
    canned = Canned(tmp_path, outputs)
    monkeypatch.setattr(analyzer, "download", _fake_download(content))
    monkeypatch.setattr(analyzer.Job, "run", canned)
    msg = DiskJobV1.model_validate(_job(**job))
    return analyzer.analyze(msg, job_dirs, _config(tmp_path)), canned


LINUX = {
    "layout": {
        "files": {"partitions.jsonl": [PARTITION]},
        "facts": {"media_size": 4096, "sector_size": 512},
    },
    "walk": {
        "files": {
            "files.jsonl": LINUX_FILES,
            "hashes.jsonl": [
                {
                    "n": 4,
                    "hash_status": "hashed",
                    "md5": "b" * 32,
                    "sha1": "c" * 40,
                    "sha256": "d" * 64,
                },
            ],
        }
    },
    "collect": {"files": {"collected.jsonl": []}},
}


def test_a_full_stream_is_valid_and_in_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job_dirs: sandbox.JobDirs
) -> None:
    path, canned = _run(monkeypatch, tmp_path, job_dirs, LINUX)
    lines = _decode(path)
    check_line_order([line["kind"] for line in lines])
    for line in lines:
        DISK_LINE_ADAPTER.validate_python(line)
    header = lines[0]
    assert header["engine"] == "tsk" and header["image"]["format"] == "raw"
    assert header["image"]["media_sha256"] == SHA
    files = [line for line in lines if line["kind"] == "file"]
    assert len(files) == len(LINUX_FILES)
    by_path = {f["path"]: f for f in files}
    assert by_path["/etc/os-release"]["hash_status"] == "hashed"
    assert by_path["/var/syslog"]["hash_status"] == "budget"
    assert by_path["/etc/shadow"]["flags"] & 64 and by_path["/var/auth.log"]["flags"] & 64
    stages = {(s["stage"], s.get("partition_index")) for s in header["stages"]}
    assert ("download", None) in stages and ("layout", None) in stages
    assert ("walk", 0) in stages
    assert [c[0] for c in canned.calls][:2] == ["layout", "walk-p0"]


def test_the_hard_link_to_etc_shadow_is_never_collected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job_dirs: sandbox.JobDirs
) -> None:
    def match(files: Any, os: str, profile: str) -> catalog.CollectPlan:
        wanted = {"/var/auth.log": DiskArtifact.AUTH_LOG, "/var/syslog": DiskArtifact.SYSLOG}
        return catalog.CollectPlan(files=[(wanted[f.path], f) for f in files if f.path in wanted])

    monkeypatch.setattr(analyzer.catalog, "match", match)
    _, canned = _run(monkeypatch, tmp_path, job_dirs, LINUX)
    collect = [args for name, args in canned.calls if name == stage.collect_name(0)]
    assert len(collect) == 1
    assert [i["path"] for i in collect[0]["items"]] == ["/var/syslog"]


def test_no_opened_file_system_gives_the_diagnostic_stream(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job_dirs: sandbox.JobDirs
) -> None:
    encrypted = {
        **PARTITION,
        "fs_type": None,
        "fs_status": "encrypted",
        "reason": "luks",
        "os": "none",
        "os_name": None,
    }
    outputs = {
        "layout": {
            "files": {"partitions.jsonl": [encrypted]},
            "facts": {"media_size": 4096, "sector_size": 512},
        }
    }
    with pytest.raises(analyzer.DiagnosticResult) as exc:
        _run(monkeypatch, tmp_path, job_dirs, outputs)
    assert exc.value.code == "no_supported_filesystem"
    lines = _decode(exc.value.path)
    check_diagnostic_kinds([line["kind"] for line in lines])
    assert lines[1]["fs_status"] == "encrypted"


def test_a_failed_only_walk_gives_the_diagnostic_stream_with_the_partition_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job_dirs: sandbox.JobDirs
) -> None:
    outputs = {
        **LINUX,
        "walk": {"status": StageStatus.FAILED, "error_code": "walk_memory"},
    }
    with pytest.raises(analyzer.DiagnosticResult) as exc:
        _run(monkeypatch, tmp_path, job_dirs, outputs)
    lines = _decode(exc.value.path)
    assert lines[1]["fs_status"] == "error" and lines[1]["error_code"] == "walk_memory"


def test_a_walk_with_too_many_bad_rows_fails_its_partition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job_dirs: sandbox.JobDirs
) -> None:
    bad = [{"n": i, "nonsense": True} for i in range(10)]
    outputs = {**LINUX, "walk": {"files": {"files.jsonl": [*LINUX_FILES, *bad]}}}
    with pytest.raises(analyzer.DiagnosticResult):
        _run(monkeypatch, tmp_path, job_dirs, outputs)


def test_compressed_and_foreign_containers_are_refused_before_any_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job_dirs: sandbox.JobDirs
) -> None:
    with pytest.raises(JobFailed) as exc:
        _run(monkeypatch, tmp_path, job_dirs, LINUX, content=b"\x1f\x8b\x08" + b"\x00" * 4093)
    assert exc.value.code == "unsupported_disk_format"


def test_insufficient_free_space_is_refused_before_the_download(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job_dirs: sandbox.JobDirs
) -> None:
    class Usage:
        free = 1024

    monkeypatch.setattr(analyzer.shutil, "disk_usage", lambda _p: Usage())
    monkeypatch.setattr(analyzer, "download", lambda *a, **k: pytest.fail("downloaded"))
    msg = DiskJobV1.model_validate(_job())
    with pytest.raises(JobFailed) as exc:
        analyzer.analyze(msg, job_dirs, _config(tmp_path))
    assert exc.value.code == "insufficient_disk"


def test_an_ewf_mismatch_is_a_finding_not_a_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job_dirs: sandbox.JobDirs
) -> None:
    ewf = b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 4088
    verify = {
        "facts": {
            "media_size": 4096,
            "stored_md5": "a" * 32,
            "stored_sha1": None,
            "media_hash_status": "mismatch",
            "media_sha256": "e" * 64,
            "ewf_meta": {"case_number": "C-1"},
        }
    }
    layout = {
        "files": {"partitions.jsonl": [PARTITION]},
        "facts": {"media_size": 4096, "sector_size": 512, "stored_md5": "a" * 32},
    }
    path, canned = _run(
        monkeypatch, tmp_path, job_dirs, {**LINUX, "layout": layout, "verify": verify}, content=ewf
    )
    lines = _decode(path)
    image = lines[0]["image"]
    assert image["format"] == "ewf" and image["ewf"]["media_hash_status"] == "mismatch"
    assert image["media_sha256"] == "e" * 64
    findings = [line for line in lines if line["kind"] == "finding"]
    assert any(f["detection_method"] == "integrity:ewf_media_hash@1" for f in findings)
    assert [c[0] for c in canned.calls][:2] == ["layout", "verify"]


def test_a_skipped_verify_leaves_not_verified(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job_dirs: sandbox.JobDirs
) -> None:
    ewf = b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 4088
    layout = {
        "files": {"partitions.jsonl": [PARTITION]},
        "facts": {"media_size": 4096, "sector_size": 512, "stored_sha1": "f" * 40},
    }
    outputs = {
        **LINUX,
        "layout": layout,
        "verify": {"status": StageStatus.SKIPPED, "has_status": False},
    }
    path, _ = _run(monkeypatch, tmp_path, job_dirs, outputs, content=ewf)
    assert _decode(path)[0]["image"]["ewf"]["media_hash_status"] == "not_verified"


# --- the ingest envelope ------------------------------------------------------------------


@pytest.fixture
def no_sandbox(monkeypatch: pytest.MonkeyPatch, job_dirs: sandbox.JobDirs) -> None:
    monkeypatch.setattr(pipeline.sandbox, "prepare", lambda work, job: job_dirs)
    monkeypatch.setattr(pipeline.sandbox, "cleanup", lambda dirs: None)


def _envelope(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, analyze: Any) -> list[Any]:
    monkeypatch.setenv("TEST_PROFILE", "1")
    sent: list[IngestMessageV1] = []
    uploads: list[Path] = []
    monkeypatch.setattr(pipeline, "analyze", analyze)
    monkeypatch.setattr(pipeline, "upload", lambda post, path: uploads.append(path) or "v1")
    pipeline.run_job(_job(), _config(tmp_path), sent.append)
    return [sent, uploads]


def test_a_result_is_uploaded_and_succeeded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_sandbox: None
) -> None:
    result = tmp_path / "r.gz"
    sent, uploads = _envelope(monkeypatch, tmp_path, lambda job, dirs, config: result)
    assert [m.event.value for m in sent] == ["started", "finished"]
    assert sent[1].outcome is not None and sent[1].outcome.value == "succeeded"
    assert sent[1].result_version_id == "v1" and uploads == [result]


def test_a_diagnostic_is_uploaded_and_failed_with_its_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_sandbox: None
) -> None:
    diag = tmp_path / "d.gz"

    def analyze(job: Any, dirs: Any, config: Any) -> Path:
        raise analyzer.DiagnosticResult("no_supported_filesystem", diag)

    sent, uploads = _envelope(monkeypatch, tmp_path, analyze)
    assert sent[1].error_code == "no_supported_filesystem"
    assert sent[1].result_version_id == "v1" and uploads == [diag]


def test_a_failure_is_reported_without_an_upload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_sandbox: None
) -> None:
    def analyze(job: Any, dirs: Any, config: Any) -> Path:
        raise JobFailed("disk_parse_failed")

    sent, uploads = _envelope(monkeypatch, tmp_path, analyze)
    assert sent[1].error_code == "disk_parse_failed"
    assert sent[1].result_version_id is None and uploads == []
