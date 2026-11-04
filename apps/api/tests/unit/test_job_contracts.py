"""Versioned job contracts (packages/py-jobs): strict, explicit, self-consistent."""

import uuid

import pytest
from cyberlab_jobs import IngestMessageV1, JobLimits, PcapJobV1, Queues
from cyberlab_jobs.capture import CaptureFormat, capture_format, compression
from pydantic import ValidationError

LIMITS = {
    "max_bytes": 1024,
    "timeout_s": 60,
    "tool_timeout_s": 30,
    "max_flows": 10,
    "max_records_per_kind": 10,
    "max_findings": 10,
    "max_result_bytes": 1024,
}
TOKEN = "t" * 43


def _job(**overrides: object) -> dict[str, object]:
    return {
        "job_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "evidence_id": str(uuid.uuid4()),
        "expected_sha256": "a" * 64,
        "size_bytes": 10,
        "evidence_url": "http://minio:9000/evidence/k?versionId=v",
        "result_post": {"url": "http://minio:9000/results", "fields": {"key": "k"}},
        "ingest_token": TOKEN,
        "limits": LIMITS,
        **overrides,
    }


def _ingest(**overrides: object) -> dict[str, object]:
    return {
        "job_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "ingest_token": TOKEN,
        "event": "started",
        "worker_version": "pcap-worker/test",
        **overrides,
    }


def test_job_round_trips_with_version() -> None:
    job = PcapJobV1.model_validate(_job())
    assert job.schema_version == "pcap.v1"
    assert PcapJobV1.model_validate(job.model_dump(mode="json")) == job


@pytest.mark.parametrize(
    "overrides",
    [
        {"unexpected": 1},
        {"schema_version": "pcap.v2"},
        {"expected_sha256": "A" * 64},
        {"evidence_url": "file:///etc/passwd"},
        {"ingest_token": "short"},
        {"limits": {**LIMITS, "tool_timeout_s": 60}},
    ],
)
def test_job_rejects_unknown_or_invalid_fields(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        PcapJobV1.model_validate(_job(**overrides))


@pytest.mark.parametrize(
    "overrides",
    [
        {"event": "started", "outcome": "succeeded"},
        {"event": "finished"},
        {"event": "finished", "outcome": "failed"},
        {"event": "finished", "outcome": "succeeded"},
        {"event": "finished", "outcome": "succeeded", "result_version_id": "v", "error_code": "x"},
        {"event": "finished", "outcome": "failed", "error_code": "Bad Code"},
    ],
)
def test_ingest_message_must_be_consistent(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        IngestMessageV1.model_validate(_ingest(**overrides))


def test_ingest_message_valid_shapes() -> None:
    IngestMessageV1.model_validate(_ingest())
    IngestMessageV1.model_validate(
        _ingest(event="finished", outcome="failed", error_code="integrity_mismatch")
    )
    IngestMessageV1.model_validate(
        _ingest(event="finished", outcome="succeeded", result_version_id="v")
    )


def test_limits_require_tool_timeout_below_job_timeout() -> None:
    with pytest.raises(ValidationError):
        JobLimits.model_validate({**LIMITS, "tool_timeout_s": 61})


@pytest.mark.parametrize(
    ("head", "fmt"),
    [
        (bytes.fromhex("d4c3b2a1") + b"\0" * 20, CaptureFormat.PCAP),
        (bytes.fromhex("a1b2c3d4") + b"\0" * 20, CaptureFormat.PCAP),
        (bytes.fromhex("4d3cb2a1") + b"\0" * 20, CaptureFormat.PCAP),
        (bytes.fromhex("a1b23c4d") + b"\0" * 20, CaptureFormat.PCAP),
        (bytes.fromhex("0a0d0d0a") + b"\0" * 20, CaptureFormat.PCAPNG),
        (b"\x1f\x8b\x08" + b"\0" * 20, None),
        (b"MZ\x90\x00", None),
        (b"", None),
    ],
)
def test_capture_format_by_magic(head: bytes, fmt: CaptureFormat | None) -> None:
    assert capture_format(head) == fmt


def test_compressed_captures_are_named() -> None:
    assert compression(b"\x1f\x8b\x08\x00") == "gzip"
    assert compression(bytes.fromhex("28b52ffd") + b"x") == "zstd"
    assert compression(b"plain") is None


def test_queue_prefix_isolates_test_queues() -> None:
    assert (Queues().pcap, Queues().ingest) == ("pcap", "ingest")
    assert (Queues("test.").pcap, Queues("test.").ingest) == ("test.pcap", "test.ingest")
