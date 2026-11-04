"""Job lifecycle messages (started / finished) for every outcome, without a broker."""

import uuid
from pathlib import Path
from typing import Any

import pytest
from celery.exceptions import SoftTimeLimitExceeded
from cyberlab_jobs import IngestMessageV1
from cyberlab_worker.errors import JobFailed

from static_worker import pipeline
from static_worker.config import Config
from tests.conftest import WORK, in_container
from tests.helpers import LIMITS

pytestmark = in_container


def job(**overrides: object) -> dict[str, Any]:
    return {
        "job_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "evidence_id": str(uuid.uuid4()),
        "expected_sha256": "0" * 64,
        "size_bytes": 10,
        "evidence_url": "http://minio:9000/evidence/x",
        "result_post": {"url": "http://minio:9000/results", "fields": {"key": "x"}},
        "ingest_token": "t" * 43,
        "profile": "full",
        "limits": LIMITS.model_dump(),
        **overrides,
    }


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[IngestMessageV1]:
    messages: list[IngestMessageV1] = []
    monkeypatch.setattr(pipeline, "upload", lambda post, path: "v1")
    return messages


CONFIG = Config(broker_url="redis://unused", queue_prefix="test.", work_dir=WORK)


def test_success_reports_started_then_finished(
    sent: list[IngestMessageV1], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(pipeline, "analyze", lambda j, d: tmp_path / "result")
    pipeline.run_job(job(), CONFIG, sent.append)
    assert [m.event for m in sent] == ["started", "finished"]
    assert sent[1].outcome == "succeeded" and sent[1].result_version_id == "v1"
    assert sent[1].worker_version.startswith("static-worker/")


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (JobFailed("sample_too_large"), "sample_too_large"),
        (SoftTimeLimitExceeded(), "timed_out"),
        (RuntimeError("boom"), "analyzer_error"),
    ],
)
def test_failures_carry_stable_codes(
    sent: list[IngestMessageV1], monkeypatch: pytest.MonkeyPatch, error: Exception, code: str
) -> None:
    def fail(*_: object) -> Path:
        raise error

    monkeypatch.setattr(pipeline, "analyze", fail)
    pipeline.run_job(job(), CONFIG, sent.append)
    assert [m.event for m in sent] == ["started", "finished"]
    assert sent[1].outcome == "failed" and sent[1].error_code == code


def test_invalid_messages_are_dropped(sent: list[IngestMessageV1]) -> None:
    pipeline.run_job(job(profile="everything"), CONFIG, sent.append)
    pipeline.run_job({"schema_version": "pcap.v1"}, CONFIG, sent.append)
    assert sent == []


def test_unreachable_evidence_fails_cleanly(sent: list[IngestMessageV1]) -> None:
    pipeline.run_job(job(evidence_url="http://127.0.0.1:9/nothing"), CONFIG, sent.append)
    assert sent[1].outcome == "failed" and sent[1].error_code == "evidence_unavailable"


def test_oversized_sample_is_refused_before_download(sent: list[IngestMessageV1]) -> None:
    pipeline.run_job(job(size_bytes=LIMITS.max_bytes + 1), CONFIG, sent.append)
    assert sent[1].error_code == "sample_too_large"
