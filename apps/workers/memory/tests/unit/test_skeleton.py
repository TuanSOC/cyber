"""The phase-1 skeleton: a valid memory job reports `started` then `failed / not_implemented`
(no download, no tool, no upload); an invalid message is dropped; the detections stub returns
nothing; the shared view types hold the contract records."""

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

from memory_worker import detections, pipeline
from memory_worker.config import load
from memory_worker.view import DetectionOutput, MemoryView
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

    def refuse_upload(*_: object) -> str:
        raise AssertionError("phase 1 never uploads")

    monkeypatch.setattr(pipeline.sandbox, "prepare", prepare)
    monkeypatch.setattr(pipeline.sandbox, "cleanup", lambda dirs: calls.append("cleanup"))
    monkeypatch.setattr(pipeline, "upload", refuse_upload)
    return calls


def test_a_job_fails_not_implemented(no_sandbox: list[str]) -> None:
    sent: list[IngestMessageV1] = []
    pipeline.run_job(_job(), load(dict(BROKER)), sent.append)
    assert [m.event for m in sent] == [IngestEvent.STARTED, IngestEvent.FINISHED]
    assert sent[1].outcome is Outcome.FAILED and sent[1].error_code == "not_implemented"
    assert sent[1].result_version_id is None
    assert no_sandbox == ["prepare", "cleanup"]


def test_an_invalid_message_is_dropped(no_sandbox: list[str]) -> None:
    sent: list[IngestMessageV1] = []
    config = load(dict(BROKER))
    pipeline.run_job({**_job(), "plugins": ["windows.handles"]}, config, sent.append)
    pipeline.run_job({**_job(), "profile": "av"}, config, sent.append)
    assert sent == [] and no_sandbox == []


def test_detections_stub_and_view_types() -> None:
    lines = [
        MEMORY_LINE_ADAPTER.validate_json(line)
        for line in (CONTRACT_FIXTURES / "windows_triage.ndjson").read_bytes().splitlines()
    ]
    image = next(line for line in lines if isinstance(line, MemoryImageRecord))
    view = MemoryView(os="windows", profile=MemoryProfile.TRIAGE, image=image)
    out = detections.run(view, MemoryLimits.model_validate(LIMITS))
    assert out == DetectionOutput()
