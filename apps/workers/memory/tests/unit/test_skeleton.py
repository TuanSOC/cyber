"""The pipeline around the analyzer (phase 2; was the phase-1 skeleton): a failure reports
`started` then `failed / <code>` with no upload; missing symbols upload the diagnostic stream
and report `failed / symbols_missing` WITH its version id; a result is uploaded and reported
`succeeded`; an invalid message is dropped; the shared view types hold the contract records.

Phase-2 fix (phase 3 merged): an image-only view no longer yields an empty `DetectionOutput`;
the detections add the image's `system_time` timeline event."""

import uuid
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs import IngestEvent, IngestMessageV1, Outcome
from cyberlab_jobs.memory import (
    MEMORY_LINE_ADAPTER,
    MemoryImageRecord,
    MemoryLimits,
    MemoryProfile,
)
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from memory_worker import detections, pipeline
from memory_worker.config import load
from memory_worker.view import MemoryView
from tests.conftest import CONTRACT_FIXTURES

LIMITS = {
    "max_bytes": 8 * 1024**3,
    "timeout_s": 5400,
    "identify_timeout_s": 600,
    "tool_timeout_s": 1200,
    "max_processes": 20_000,
    "max_connections": 50_000,
    "max_injections": 5_000,
    "max_artifacts": 50_000,
    "max_findings": 5_000,
    "max_iocs": 20_000,
    "max_timeline": 5_000,
    "max_result_bytes": 256 * 1024**2,
}
BROKER = {"BROKER_URL": "redis://memory:x@redis-broker:6379/0"}


def _job() -> dict[str, Any]:
    return {
        "job_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "evidence_id": str(uuid.uuid4()),
        "expected_sha256": "a" * 64,
        "size_bytes": 4096,
        "evidence_url": "http://minio:9000/evidence/x?X-Amz-Signature=1",
        "result_post": {"url": "http://minio:9000/analysis-results", "fields": {"key": "k"}},
        "ingest_token": "t" * 43,
        "profile": "triage",
        "os_hint": "auto",
        "limits": LIMITS,
    }


@pytest.fixture
def no_sandbox(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def prepare(work_dir: Path, job_id: str) -> object:
        calls.append("prepare")
        return object()

    def upload(post: object, path: Path) -> str:
        calls.append(f"upload:{path.name}")
        return "v-123"

    monkeypatch.setattr(sandbox, "prepare", prepare)
    monkeypatch.setattr(sandbox, "cleanup", lambda dirs: calls.append("cleanup"))
    monkeypatch.setattr(pipeline, "upload", upload)
    return calls


def _analyze_raising(exc: Exception) -> Any:
    def analyze(*_: object) -> Path:
        raise exc

    return analyze


def test_a_failure_reports_its_code_without_upload(
    no_sandbox: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pipeline, "analyze", _analyze_raising(JobFailed("memory_parse_failed")))
    sent: list[IngestMessageV1] = []
    pipeline.run_job(_job(), load(dict(BROKER)), sent.append)
    assert [m.event for m in sent] == [IngestEvent.STARTED, IngestEvent.FINISHED]
    assert sent[1].outcome is Outcome.FAILED and sent[1].error_code == "memory_parse_failed"
    assert sent[1].result_version_id is None
    assert no_sandbox == ["prepare", "cleanup"]


def test_missing_symbols_upload_the_diagnostic_stream(
    no_sandbox: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from memory_worker.analyzer import DiagnosticResult

    diagnostic = DiagnosticResult(Path("/work/j/result.ndjson.gz"))
    monkeypatch.setattr(pipeline, "analyze", _analyze_raising(diagnostic))
    sent: list[IngestMessageV1] = []
    pipeline.run_job(_job(), load(dict(BROKER)), sent.append)
    assert sent[1].outcome is Outcome.FAILED and sent[1].error_code == "symbols_missing"
    assert sent[1].result_version_id == "v-123"
    assert no_sandbox == ["prepare", "upload:result.ndjson.gz", "cleanup"]


def test_a_result_is_uploaded_and_succeeds(
    no_sandbox: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pipeline, "analyze", lambda *_: Path("/work/j/result.ndjson.gz"))
    sent: list[IngestMessageV1] = []
    pipeline.run_job(_job(), load(dict(BROKER)), sent.append)
    assert sent[1].outcome is Outcome.SUCCEEDED and sent[1].result_version_id == "v-123"
    assert no_sandbox == ["prepare", "upload:result.ndjson.gz", "cleanup"]


def test_an_invalid_message_is_dropped(no_sandbox: list[str]) -> None:
    sent: list[IngestMessageV1] = []
    config = load(dict(BROKER))
    pipeline.run_job({**_job(), "plugins": ["windows.handles"]}, config, sent.append)
    pipeline.run_job({**_job(), "profile": "av"}, config, sent.append)
    assert sent == [] and no_sandbox == []


def test_detections_on_an_image_only_view() -> None:
    lines = [
        MEMORY_LINE_ADAPTER.validate_json(line)
        for line in (CONTRACT_FIXTURES / "windows_triage.ndjson").read_bytes().splitlines()
    ]
    image = next(line for line in lines if isinstance(line, MemoryImageRecord))
    view = MemoryView(os="windows", profile=MemoryProfile.TRIAGE, image=image)
    out = detections.run(view, MemoryLimits.model_validate(LIMITS))
    # Phase 3: no record, no finding or IOC; the image's system time is one timeline event.
    assert out.findings == [] and out.iocs == [] and out.truncated == {}
    assert [(e.event, e.ts) for e in out.timeline] == [("system_time", image.system_time)]


def test_the_worker_sets_task_time_limits() -> None:
    """Review fix: the soft limit (the `timed_out` report) is live even for a message that
    carries no per-task limits; both sit just above the contract's 6 h job cap."""
    pytest.importorskip("celery")
    from memory_worker import config
    from memory_worker.celery_app import celery_app

    conf = celery_app.conf
    assert conf.task_soft_time_limit == config.TASK_SOFT_TIME_LIMIT_S > 6 * 3600
    assert conf.task_time_limit == config.TASK_TIME_LIMIT_S > conf.task_soft_time_limit
