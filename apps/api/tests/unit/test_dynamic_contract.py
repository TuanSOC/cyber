"""`dynamic.v1` (M7 phase 7, design only): the frozen contract round-trips its fixtures,
passes the trusted ingest's framing exactly like `static.v1`, and refuses hostile input
(an `internet` / Tor route, oversized or control-character text, extra fields, unknown kinds).
"""

import gzip
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs.dynamic import (
    DYNAMIC_BODY_ADAPTER,
    DYNAMIC_RECORD_ADAPTER,
    DYNAMIC_SCHEMA,
    MAX_RECORD_LINES,
    MAX_STREAM_LINES,
    MAX_TIMEOUT_S,
    DynamicJobV1,
    DynamicResultHeader,
    DynamicStreamCheck,
    DynamicStreamError,
    DynamicSummaryV1,
    NetworkRecord,
    RouteMode,
)
from cyberlab_jobs.results import ResultTrailer
from pydantic import ValidationError

from app.modules.analysis.result_stream import InvalidResult, check_framing

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/dynamic"
BENIGN = (FIXTURES / "benign_run.jsonl").read_bytes().splitlines(keepends=True)
HOSTILE = (FIXTURES / "hostile_run.jsonl").read_bytes().splitlines(keepends=True)
JOB_ID = uuid.UUID(json.loads(BENIGN[0])["job_id"])
TOKEN = "t" * 43


def _job(**overrides: object) -> dict[str, object]:
    return {
        "job_id": str(uuid.uuid4()),
        "org_id": str(uuid.uuid4()),
        "evidence_id": str(uuid.uuid4()),
        "evidence_sha256": "a" * 64,
        "evidence_bytes": 4096,
        "sample_url": "http://minio:9000/evidence/k?versionId=v",
        "timeout_s": 120,
        "upload": {"url": "http://minio:9000/results", "fields": {"key": "k"}},
        "token": TOKEN,
        "deadline": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
        **overrides,
    }


def _summary(**overrides: object) -> dict[str, object]:
    return {
        "kind": "summary",
        "status": "succeeded",
        "route": "none",
        "duration_ms": 1000,
        "vm_image_digest": "sha256:" + "ab" * 32,
        "revert_verified": True,
        "counts": {},
        **overrides,
    }


def _check(lines: list[bytes], *, route: RouteMode = "sinkhole", **kwargs: Any) -> DynamicSummaryV1:
    check = DynamicStreamCheck(JOB_ID, route, **kwargs)
    check.header(lines[0])
    for line in lines[1:-1]:
        check.body(line)
    return check.finish()


# --- the job -----------------------------------------------------------------------------


def test_job_round_trips_with_version_and_safe_default_route() -> None:
    job = DynamicJobV1.model_validate(_job())
    assert job.schema_version == DYNAMIC_SCHEMA == "dynamic.v1"
    assert job.route == "none"
    assert DynamicJobV1.model_validate(job.model_dump(mode="json")) == job


@pytest.mark.parametrize(
    "overrides",
    [
        {"route": "internet"},
        {"route": "tor"},
        {"route": "vpn"},
        {"route": "socks5"},
        {"route": "drop"},
        {"timeout_s": MAX_TIMEOUT_S + 1},
        {"timeout_s": 0},
        {"evidence_bytes": 0},
        {"evidence_sha256": "A" * 64},
        {"sample_url": "file:///etc/passwd"},
        {"token": "short"},
        {"deadline": "2026-11-06T10:00:00"},  # naive
        {"schema_version": "dynamic.v2"},
        {"unexpected": 1},
    ],
)
def test_job_refuses(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        DynamicJobV1.model_validate(_job(**overrides))


# --- the benign fixture ------------------------------------------------------------------


def test_benign_fixture_round_trips_line_by_line() -> None:
    header = DynamicResultHeader.model_validate_json(BENIGN[0])
    assert header.schema_version == DYNAMIC_SCHEMA
    kinds = set()
    for raw in BENIGN[1:-1]:
        line = DYNAMIC_BODY_ADAPTER.validate_json(raw)
        kinds.add(line.kind)
        again = DYNAMIC_BODY_ADAPTER.validate_json(DYNAMIC_BODY_ADAPTER.dump_json(line))
        assert again == line
    assert kinds == {"process", "file", "registry", "network", "signature", "dropped", "summary"}
    ResultTrailer.model_validate_json(BENIGN[-1])


def test_benign_fixture_passes_the_ingest_framing(tmp_path: Path) -> None:
    """The trusted ingest's own reader (gzip, bombs, line caps, trailer hash) accepts it."""
    path = tmp_path / "result.ndjson.gz"
    path.write_bytes(gzip.compress(b"".join(BENIGN)))
    check = DynamicStreamCheck(JOB_ID, "sinkhole")

    def first(raw: bytes) -> None:
        check.header(raw)

    def middle(raw: bytes) -> None:
        check.body(raw)

    check_framing(
        path, max_decompressed=1024**2, max_lines=MAX_STREAM_LINES, first=first, middle=middle
    )
    summary = check.finish()
    assert summary.status == "succeeded"
    assert summary.revert_verified is True
    assert summary.route == "sinkhole"


def test_a_spliced_benign_stream_fails_the_framing(tmp_path: Path) -> None:
    path = tmp_path / "result.ndjson.gz"
    path.write_bytes(gzip.compress(b"".join([*BENIGN[:3], *BENIGN[4:]])))
    with pytest.raises(InvalidResult):
        check_framing(
            path,
            max_decompressed=1024**2,
            max_lines=MAX_STREAM_LINES,
            first=lambda raw: None,
            middle=lambda raw: None,
        )


# --- the hostile fixture -----------------------------------------------------------------


def _has_control(line: dict[str, Any]) -> bool:
    text = "".join(v for v in line.values() if isinstance(v, str))
    return any((ord(c) < 0x20 and c != "	") or 0x7F <= ord(c) <= 0x9F for c in text)


@pytest.mark.parametrize("raw", HOSTILE, ids=[f"hostile-{i}" for i in range(len(HOSTILE))])
def test_every_hostile_line_is_refused(raw: bytes) -> None:
    with pytest.raises(ValidationError):
        DYNAMIC_RECORD_ADAPTER.validate_json(raw)
    with pytest.raises(DynamicStreamError, match="invalid_line"):
        DynamicStreamCheck(JOB_ID, "sinkhole").body(raw)


def test_hostile_fixture_covers_the_required_cases() -> None:
    lines = [json.loads(raw) for raw in HOSTILE]
    assert any(line.get("route") == "internet" for line in lines)
    assert any(len(line.get("cmdline", "")) > 2048 for line in lines)
    assert any(_has_control(line) for line in lines)
    assert any("raw_value" in line or "content_b64" in line for line in lines)


@pytest.mark.parametrize("route", ["internet", "tor", "vpn", "inetsim", "drop", ""])
def test_no_route_but_none_and_sinkhole_exists(route: str) -> None:
    line = {"kind": "network", "proto": "tcp", "dst": "a.invalid", "port": 1, "bytes": 0}
    for ok in ("none", "sinkhole"):
        assert NetworkRecord.model_validate({**line, "route": ok}).route == ok
    with pytest.raises(ValidationError):
        NetworkRecord.model_validate({**line, "route": route})
    with pytest.raises(ValidationError):
        DynamicSummaryV1.model_validate(_summary(route=route))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cmdline", "A" * 2049),
        ("cmdline", "a\rb"),
        ("cmdline", "a\x1b[2Jb"),
        ("cmdline", "a\x7fb"),
        ("cmdline", "a\x9bb"),
        ("image", ""),
        ("image", "x" * 1025),
        ("pid", -1),
        ("pid", 2**32),
        ("start_ms", MAX_TIMEOUT_S * 1000 + 1),
    ],
)
def test_process_text_and_numbers_are_bounded(field: str, value: object) -> None:
    line = {"kind": "process", "pid": 1, "ppid": 0, "image": "a", "cmdline": "b", "start_ms": 0}
    DYNAMIC_RECORD_ADAPTER.validate_python(line)
    with pytest.raises(ValidationError):
        DYNAMIC_RECORD_ADAPTER.validate_python({**line, field: value})


def test_tab_is_the_only_control_character_allowed() -> None:
    line = {"kind": "process", "pid": 1, "ppid": 0, "image": "a", "cmdline": "a\tb", "start_ms": 0}
    assert DYNAMIC_RECORD_ADAPTER.validate_python(line).kind == "process"


def test_process_end_cannot_precede_start() -> None:
    line = {"kind": "process", "pid": 1, "ppid": 0, "image": "a", "cmdline": "", "start_ms": 5}
    with pytest.raises(ValidationError):
        DYNAMIC_RECORD_ADAPTER.validate_python({**line, "end_ms": 4})


# --- the summary -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"revert_verified": False},  # no verified clean state: never a success
        {"error_code": "timeout"},  # a success carries no error
        {"status": "failed"},  # a failure needs a code
        {"status": "failed", "error_code": "made_up"},
        {"duration_ms": MAX_TIMEOUT_S * 1000 + 1},
        {"vm_image_digest": "ab" * 32},
        {"counts": {"screenshot": 1}},
        {"extra": True},
    ],
)
def test_summary_refuses(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        DynamicSummaryV1.model_validate(_summary(**overrides))


def test_integrity_failure_is_a_failed_run_with_code_integrity() -> None:
    summary = DynamicSummaryV1.model_validate(
        _summary(status="failed", error_code="integrity", revert_verified=False)
    )
    assert summary.error_code == "integrity"


# --- per-stream rules --------------------------------------------------------------------


def test_record_cap_is_200k_and_enforced() -> None:
    assert MAX_RECORD_LINES == 200_000
    assert MAX_STREAM_LINES == MAX_RECORD_LINES + 3
    with pytest.raises(DynamicStreamError, match="too_many_records"):
        _check(BENIGN, max_records=3)
    with pytest.raises(ValueError):
        DynamicStreamCheck(JOB_ID, "none", max_records=MAX_RECORD_LINES + 1)


def test_stream_must_name_this_job_and_route() -> None:
    with pytest.raises(DynamicStreamError, match="wrong_job"):
        DynamicStreamCheck(uuid.uuid4(), "sinkhole").header(BENIGN[0])
    # The job asked for `none`: a stream claiming `sinkhole` is refused at the header.
    with pytest.raises(DynamicStreamError, match="route_mismatch"):
        _check(BENIGN, route="none")


def test_a_network_line_with_another_route_is_refused() -> None:
    check = DynamicStreamCheck(JOB_ID, "none")
    line = (
        b'{"kind":"network","proto":"tcp","dst":"a.invalid","port":1,"bytes":0,"route":"sinkhole"}'
    )
    with pytest.raises(DynamicStreamError, match="route_mismatch"):
        check.body(line)


def test_summary_counts_must_match_and_nothing_follows_it() -> None:
    lying = json.loads(BENIGN[-2])
    lying["counts"]["network"] += 1
    with pytest.raises(DynamicStreamError, match="count_mismatch"):
        _check([*BENIGN[:-2], json.dumps(lying).encode(), BENIGN[-1]])
    with pytest.raises(DynamicStreamError, match="line_after_summary"):
        _check([*BENIGN[:-1], BENIGN[1], BENIGN[-1]])
    with pytest.raises(DynamicStreamError, match="missing_summary"):
        _check([*BENIGN[:-2], BENIGN[-1]])
    with pytest.raises(DynamicStreamError, match="invalid_header"):
        DynamicStreamCheck(JOB_ID, "sinkhole").header(BENIGN[1])
