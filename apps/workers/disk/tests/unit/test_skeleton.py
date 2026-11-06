"""M9 phase 1 skeleton: a valid disk job is reported `started` then `failed / not_implemented`
(never `succeeded`); an export job likewise; an invalid message is dropped unreported; the frozen
entry points exist with their signatures."""

import inspect
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs import IngestMessageV1
from cyberlab_jobs.disk import (
    PROFILE_BUDGETS,
    DiskProfile,
    default_stage_limits,
    split_event_quotas,
)
from cyberlab_worker import sandbox

from disk_worker import analyzer, budget, detections, export, pipeline, scan, stage, timeline
from disk_worker.config import load
from disk_worker.hashsets.store import HashSetStore
from disk_worker.timeline import catalog


def _limits() -> dict[str, Any]:
    budgets = dict(PROFILE_BUDGETS[DiskProfile.TRIAGE])
    return {
        "max_image_bytes": 16 * 1024**3,
        "max_media_bytes": 2 * 1024**4,
        "timeout_s": 14_400,
        "stages": {
            k: v.model_dump()
            for k, v in default_stage_limits(
                budgets["artifact_max_bytes"], budgets["artifact_max_file_bytes"]
            ).items()
        },
        **budgets,
        "max_partitions": 128,
        "max_filesystems": 32,
        "max_files": 500_000,
        "max_streams_per_file": 16,
        "max_events_stored": 250_000,
        "max_events_read": 20_000_000,
        "max_findings": 5_000,
        "max_iocs": 20_000,
        "max_timeline": 5_000,
        "max_result_bytes": 256 * 1024**2,
        "event_quotas": {k.value: v for k, v in split_event_quotas(250_000).items()},
    }


POST = {"url": "http://minio:9000/results", "fields": {"key": "k"}}
SEGMENT = {
    "ordinal": 0,
    "evidence_id": str(uuid.uuid4()),
    "expected_sha256": "a" * 64,
    "size_bytes": 1024,
    "url": "http://minio:9000/evidence/x",
}


def _job(**extra: Any) -> dict[str, Any]:
    return {
        "job_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "segments": [SEGMENT],
        "ingest_token": "t" * 43,
        "limits": _limits(),
        "deadline_at": (datetime.now(UTC) + timedelta(hours=4)).isoformat(),
        **extra,
    }


@pytest.fixture
def no_sandbox(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def prepare(work_dir: Path, job_id: str) -> sandbox.JobDirs:
        return sandbox.JobDirs(root=tmp_path, input=tmp_path / "in", out=tmp_path / "out")

    monkeypatch.setattr(pipeline.sandbox, "prepare", prepare)
    monkeypatch.setattr(pipeline.sandbox, "cleanup", lambda dirs: None)


def test_a_disk_job_is_started_then_failed_not_implemented(no_sandbox: None) -> None:
    sent: list[IngestMessageV1] = []
    config = load({"BROKER_URL": "redis://disk:x@redis-broker:6379/0", "WORK_DIR": "/tmp"})
    pipeline.run_job(
        _job(profile="triage", os_hint="auto", result_post=POST), config, sent.append
    )
    assert [m.event.value for m in sent] == ["started", "finished"]
    assert sent[1].outcome is not None and sent[1].outcome.value == "failed"
    assert sent[1].error_code == "not_implemented"
    assert sent[1].result_version_id is None


def test_an_export_job_is_started_then_failed_not_implemented() -> None:
    sent: list[IngestMessageV1] = []
    config = load({"BROKER_URL": "redis://disk:x@redis-broker:6379/0"})
    files = [
        {"export_id": str(uuid.uuid4()), "partition_index": 1, "meta_addr": 7, "expected_size": 9}
    ]
    pipeline.run_export_job(
        _job(source_job_id=str(uuid.uuid4()), files=files, result_posts=[POST, POST]),
        config,
        sent.append,
    )
    assert [m.event.value for m in sent] == ["started", "finished"]
    assert sent[1].error_code == "not_implemented"


def test_an_invalid_message_is_dropped_unreported() -> None:
    sent: list[IngestMessageV1] = []
    config = load({"BROKER_URL": "redis://disk:x@redis-broker:6379/0"})
    pipeline.run_job({"job_id": "nope"}, config, sent.append)
    pipeline.run_export_job({"job_id": "nope"}, config, sent.append)
    assert sent == []


def test_frozen_entry_points() -> None:
    params = {
        stage.run_stage: ["argv", "dirs", "stage", "limits", "budget"],
        analyzer.analyze: ["job", "dirs", "config"],
        export.handle_export: ["msg"],
        scan.build_candidates: ["files", "profile", "limits"],
        scan.parse_scan_output: ["path"],
        detections.run: ["view", "limits"],
        timeline.run_timeline: ["dirs", "partitions", "profile", "limits", "budget"],
        catalog.match: ["files", "os", "profile"],
        HashSetStore.match: ["self", "sha256", "sha1", "md5"],
        budget.Budget.timeout: ["self", "stage"],
    }
    for func, names in params.items():
        assert list(inspect.signature(func).parameters) == names, func
    with pytest.raises(ValueError):
        analyzer.DiagnosticResult("timed_out", Path("x"))
    assert analyzer.DiagnosticResult("no_supported_filesystem", Path("x")).code == (
        "no_supported_filesystem"
    )
