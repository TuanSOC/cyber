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


# --- pcap.v1 result lines ------------------------------------------------------------------

RECORD = {
    "kind": "flow",
    "ts": "2026-01-01T00:00:00Z",
    "src_ip": "10.0.0.1",
    "dst_ip": "203.0.113.5",
    "dst_port": 443,
    "proto": "tcp",
}


def test_result_lines_validate_by_kind() -> None:
    from cyberlab_jobs.results import RECORD_ADAPTER, FlowRecord

    assert isinstance(RECORD_ADAPTER.validate_python(RECORD), FlowRecord)


@pytest.mark.parametrize(
    "overrides",
    [
        {"kind": "shell"},
        {"unexpected": "x"},
        {"src_ip": "not-an-ip"},
        {"dst_port": 70000},
        {"proto": "sctp"},
        {"service": "x" * 65},
        {"service": "nul" + chr(0) + "byte"},
        {"orig_bytes": -1},
    ],
)
def test_result_lines_reject_hostile_values(overrides: dict[str, object]) -> None:
    from cyberlab_jobs.results import RECORD_ADAPTER

    with pytest.raises(ValidationError):
        RECORD_ADAPTER.validate_python({**RECORD, **overrides})


# --- static.v1 -----------------------------------------------------------------------------

STATIC_LIMITS = {
    "max_bytes": 1024,
    "timeout_s": 60,
    "tool_timeout_s": 30,
    "max_sections": 10,
    "max_imports": 10,
    "max_exports": 10,
    "max_resources": 10,
    "max_strings": 10,
    "max_signature_matches": 10,
    "max_capabilities": 10,
    "max_findings": 10,
    "max_iocs": 10,
    "max_result_bytes": 1024,
}


def _pe_head(e_lfanew: int = 0x80, size: int = 0x200) -> bytes:
    head = bytearray(size)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = e_lfanew.to_bytes(4, "little")
    if e_lfanew + 4 <= size:
        head[e_lfanew : e_lfanew + 4] = b"PE" + bytes(2)
    return bytes(head)


def _elf_head(e_type: int, little: bool = True) -> bytes:
    head = bytearray(64)
    head[0:4] = bytes.fromhex("7f454c46")
    head[4], head[5] = 2, 1 if little else 2
    head[16:18] = e_type.to_bytes(2, "little" if little else "big")
    return bytes(head)


def test_static_job_requires_profile_and_limits() -> None:
    from cyberlab_jobs.static import Profile, StaticJobV1

    job = StaticJobV1.model_validate(
        {**_job(limits=STATIC_LIMITS), "schema_version": "static.v1", "profile": "av"}
    )
    assert job.profile == Profile.AV
    with pytest.raises(ValidationError):
        StaticJobV1.model_validate({**_job(limits=STATIC_LIMITS), "schema_version": "static.v1"})
    with pytest.raises(ValidationError):  # a pcap job is not a static job
        StaticJobV1.model_validate({**_job(), "profile": "full"})


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (_pe_head(), "pe"),
        (_pe_head(e_lfanew=0x1000), None),  # header beyond the inspected bytes
        (_pe_head(e_lfanew=0x10), None),  # inside the DOS header
        (b"MZ" + bytes(10), None),
        (_elf_head(2), "elf"),  # ET_EXEC
        (_elf_head(3, little=False), "elf"),  # ET_DYN, big endian
        (_elf_head(4), None),  # core dump
        (bytes.fromhex("cafebabe") + bytes(60), None),  # Mach-O fat / Java class: ignored
        (b"", None),
    ],
)
def test_executable_format(head: bytes, expected: str | None) -> None:
    from cyberlab_jobs.capture import executable_format

    assert executable_format(head) == expected


def test_static_lines_validate_and_reject_hostile_values() -> None:
    from cyberlab_jobs.static import STATIC_LINE_ADAPTER, SectionRecord

    good = {"kind": "section", "index": 0, "name": ".text", "virtual_address": 4096,
            "virtual_size": 10, "raw_size": 512, "entropy": 6.1, "flags": ["execute"]}  # fmt: skip
    assert isinstance(STATIC_LINE_ADAPTER.validate_python(good), SectionRecord)
    for bad in (
        {**good, "entropy": 8.5},
        {**good, "entropy": float("nan")},
        {**good, "name": "a" + chr(0)},
        {**good, "virtual_address": 2**64},
        {**good, "unexpected": 1},
        {"kind": "signature_match", "engine": "virustotal", "name": "x"},
        {"kind": "capability", "name": "x", "attack": ["T99"]},
        {"kind": "sample", "size": 1, "md5": "x", "sha1": "y", "sha256": "z", "entropy": 1},
    ):
        with pytest.raises(ValidationError):
            STATIC_LINE_ADAPTER.validate_python(bad)
