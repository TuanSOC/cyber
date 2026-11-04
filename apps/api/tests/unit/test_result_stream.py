"""Result stream validation reasons (no database, no object store)."""

import dataclasses
import gzip
import hashlib
import uuid
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs.results import FindingRecord, IocRecord

from app.core.config import Settings, get_settings
from app.modules.pcap_analysis import ingest as pcap_ingest
from app.modules.pcap_analysis import stream
from app.modules.pcap_analysis.ingest import summary_text, to_row
from app.workers import ingest as worker_ingest
from app.workers import tasks
from tests import pcap_results as pr

JOB = uuid.UUID(int=42)
CAPS = stream.Caps(
    max_decompressed_bytes=10 * 1024**2,
    per_kind={
        "stats": 1,
        "flow": 10,
        "finding": 10,
        **{k: 10 for k in ("dns", "http", "tls", "alert", "ioc", "timeline")},
    },
    max_lines=1000,
)


def _write(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "result.ndjson.gz"
    path.write_bytes(data)
    return path


def _reason(tmp_path: Path, data: bytes, caps: stream.Caps = CAPS) -> str:
    with pytest.raises(stream.InvalidResult) as info:
        stream.validate(_write(tmp_path, data), JOB, caps)
    return info.value.reason


def test_valid_stream_counts_every_kind(tmp_path: Path) -> None:
    result = stream.validate(_write(tmp_path, pr.stream(JOB)), JOB, CAPS)
    assert result.header.job_id == JOB and result.stats.packets == 120
    assert dict(result.counts) == {
        "stats": 1,
        "flow": 3,
        "dns": 2,
        "http": 1,
        "tls": 1,
        "alert": 2,
        "finding": 2,
        "ioc": 2,
        "timeline": 3,
    }
    records = list(stream.records(_write(tmp_path, pr.stream(JOB)), CAPS))
    assert [r.kind for r, _ in records][:3] == ["flow"] * 3 and len(records) == 16
    assert all(size == len(pr.line(r)) for r, size in records)


def finding_dict(**fields: Any) -> dict[str, Any]:
    """A valid finding line (fresh id) with some fields replaced by raw JSON values."""
    base = next(r for r in pr.sample_records() if isinstance(r, FindingRecord))
    return {**base.model_dump(mode="json"), "finding_id": str(uuid.uuid4()), **fields}


def header_dict(**fields: Any) -> dict[str, Any]:
    return {**pr.header(JOB).model_dump(mode="json"), **fields}


def _with_line(extra: dict[str, Any]) -> bytes:
    return pr.encode([*pr.lines(JOB), pr.line(extra)])


def _with_header(header: dict[str, Any]) -> bytes:
    return pr.encode([pr.line(header), *pr.lines(JOB)[1:]])


@pytest.mark.parametrize(
    ("build", "reason"),
    [
        (lambda: pr.encode([*pr.lines(JOB), pr.line({"kind": "x"})]), "invalid_record"),
        (lambda: pr.encode(pr.lines(JOB), trailer={"sha256": "f" * 64}), "trailer_hash_mismatch"),
        (lambda: pr.encode(pr.lines(JOB), trailer={"line_count": 1}), "trailer_count_mismatch"),
        (lambda: pr.encode(pr.lines(JOB), add_trailer=False), "invalid_trailer"),
        (lambda: pr.encode(pr.lines(JOB)[1:]), "invalid_header"),
        (lambda: pr.encode(pr.lines(uuid.uuid4())), "header_job_mismatch"),
        (lambda: pr.encode([*pr.lines(JOB), pr.line(pr.stats())]), "too_many_stats"),
        (lambda: pr.encode([pr.lines(JOB)[0]]), "missing_stats"),
        (lambda: pr.encode([*pr.lines(JOB), pr.lines(JOB)[0]]), "invalid_record"),
        (lambda: gzip.compress(b""), "missing_header"),
        (lambda: b"plain text\n", "bad_gzip"),
        (lambda: pr.stream(JOB)[:-10], "bad_gzip"),
        (lambda: gzip.compress(b"x" * (1024**2 + 10)), "line_too_long"),
        (lambda: gzip.compress(b"{}"), "unterminated_line"),
        (
            lambda: pr.encode([*pr.lines(JOB), pr.line(pr.flow(5, ts=pr.at(-3 * 86400)))]),
            "timestamp_outside_capture",
        ),
        (
            lambda: pr.encode([*pr.lines(JOB), pr.lines(JOB)[-4]]),  # an IOC line again
            "duplicate_ioc",
        ),
        (
            lambda: pr.encode(
                [*pr.lines(JOB), next(x for x in pr.lines(JOB) if b"port_scan" in x)]
            ),
            "duplicate_finding",
        ),
        # Values the database cannot store are refused here, before any write.
        (lambda: _with_line(finding_dict(attributes={"x": float("nan")})), "invalid_record"),
        (lambda: _with_line(finding_dict(attributes={"x": float("inf")})), "invalid_record"),
        (lambda: _with_line(finding_dict(attributes={"x": -float("inf")})), "invalid_record"),
        (lambda: _with_line(finding_dict(attributes={"x": 10**400})), "invalid_record"),
        (lambda: _with_line(finding_dict(attributes={"x": -(10**400)})), "invalid_record"),
        (lambda: _with_line(finding_dict(attributes={"x": "a\x00b"})), "invalid_record"),
        (lambda: _with_line(finding_dict(attributes={"a\x00": 1})), "invalid_record"),
        (
            lambda: _with_line(finding_dict(detection_method="heuristic:" + "a" * 200 + "@1")),
            "invalid_record",
        ),
        (lambda: _with_header(header_dict(tool_versions={"zeek": "8\x00"})), "invalid_header"),
        (lambda: _with_header(header_dict(tool_versions={"ze\x00ek": "8"})), "invalid_header"),
        (lambda: _with_header(header_dict(truncated={"fl\x00ows": True})), "invalid_header"),
    ],
)
def test_refusal_reasons(tmp_path: Path, build: Callable[[], bytes], reason: str) -> None:
    assert _reason(tmp_path, build()) == reason


@pytest.mark.parametrize("value", [2**64, -(2**63) - 1, 2**63])
def test_out_of_int64_attributes_are_refused(tmp_path: Path, value: int) -> None:
    """Ints outside bigint are refused, never silently turned into lossy floats."""
    data = _with_line(finding_dict(attributes={"x": value}))
    assert _reason(tmp_path, data) == "invalid_record"


def test_int64_bounds_are_kept_exactly(tmp_path: Path) -> None:
    data = _with_line(finding_dict(attributes={"x": 2**63 - 1, "y": -(2**63)}))
    stream.validate(_write(tmp_path, data), JOB, CAPS)
    [*_, (last, _)] = stream.records(_write(tmp_path, data), CAPS)
    assert isinstance(last, FindingRecord)
    assert last.attributes == {"x": 2**63 - 1, "y": -(2**63)}


def test_per_kind_caps(tmp_path: Path) -> None:
    caps = stream.Caps(CAPS.max_decompressed_bytes, {**CAPS.per_kind, "flow": 2}, CAPS.max_lines)
    assert _reason(tmp_path, pr.stream(JOB), caps) == "too_many_flow"


def test_total_line_cap_counts_every_line(tmp_path: Path) -> None:
    data = pr.stream(JOB)  # header + stats + 16 records + trailer
    lines = len(gzip.decompress(data).splitlines())
    assert stream.validate(_write(tmp_path, data), JOB, dataclasses.replace(CAPS, max_lines=lines))
    caps = dataclasses.replace(CAPS, max_lines=lines - 1)
    assert _reason(tmp_path, data, caps) == "too_many_lines"


def test_line_cap_comes_from_settings() -> None:
    caps = stream.Caps.from_settings(get_settings())
    assert caps.max_lines == get_settings().analysis_max_result_lines == 400_000


def test_decompressed_cap_stops_a_bomb(tmp_path: Path) -> None:
    caps = stream.Caps(64 * 1024, {**CAPS.per_kind, "flow": 10_000}, 100_000)
    bomb = gzip.compress(b"x" * (8 * 1024**2))  # 8 MiB inflated from ~8 KiB
    assert len(bomb) < 64 * 1024
    assert _reason(tmp_path, bomb, caps) == "decompressed_too_large"
    many = pr.encode([*pr.lines(JOB), *[pr.line(pr.flow(1))] * 2000])
    assert _reason(tmp_path, many, caps) == "decompressed_too_large"


def test_ioc_duplicates_use_the_unique_index_hash() -> None:
    """The validator's key is md5(value), exactly what uq_iocs_job_id_type_value compares."""
    for value in ("example.com", "exämple.com", "x" * 2048):
        expected = hashlib.md5(value.encode(), usedforsecurity=False).digest()
        assert stream.ioc_key("domain", value) == ("domain", expected)
    assert stream.ioc_key("domain", "a") != stream.ioc_key("domain", "b")
    assert stream.ioc_key("domain", "a") != stream.ioc_key("url", "a")


def test_ioc_key_collision_is_a_duplicate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Distinct values with equal index keys are refused, as the index would refuse them."""
    monkeypatch.setattr(stream, "ioc_key", lambda kind, value: (kind, b"same"))
    other = IocRecord(
        type="ip", value="192.0.2.99", first_seen=pr.at(1), last_seen=pr.at(2), count=1, source="x"
    )
    data = pr.encode([*pr.lines(JOB), pr.line(other)])
    assert _reason(tmp_path, data) == "duplicate_ioc"


def test_batches_stop_at_the_byte_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pcap_ingest, "BATCH_BYTES", 250)
    records = iter([(pr.flow(i), 100) for i in range(1, 8)])
    written: Counter[str] = Counter()
    sizes = []
    while batch := pcap_ingest._next_batch(records, {}, written):
        sizes.append(sum(len(rows) for rows in batch.values()))
    assert sizes == [3, 3, 1] and written["flow"] == 7


def test_summary_text_and_rows() -> None:
    dns, _, http, tls = (r for r in pr.sample_records() if r.kind in {"dns", "http", "tls"})
    assert summary_text(dns) == "A example.com NOERROR 93.184.216.34"
    assert summary_text(http).startswith("GET shop.test/deal?x=100%_off 200")
    assert "ja3=" in summary_text(tls)
    table, row = to_row(pr.flow(1, orig_bytes=2**63 - 1, resp_bytes=5))
    assert table.name == "network_flows" and row["total_bytes"] == 2**63 - 1
    assert row["src_ip"] == "10.0.0.5"


# --- ingest worker scratch dir ------------------------------------------------------------


def test_worker_refuses_to_start_without_a_scratch_dir() -> None:
    for env in ("dev", "prod"):
        settings = get_settings().model_copy(update={"env": env, "ingest_tmp_dir": None})
        with pytest.raises(RuntimeError, match="INGEST_TMP_DIR"):
            worker_ingest.prepare_scratch(settings)
    worker_ingest.prepare_scratch(get_settings().model_copy(update={"ingest_tmp_dir": None}))


@pytest.mark.parametrize("bad", ["nope", "relative/dir"])
def test_worker_refuses_a_missing_or_relative_scratch_dir(tmp_path: Path, bad: str) -> None:
    path = str(tmp_path / bad) if bad == "nope" else bad
    settings = get_settings().model_copy(update={"ingest_tmp_dir": path})
    with pytest.raises(RuntimeError, match="not an absolute path to a directory"):
        worker_ingest.prepare_scratch(settings)


def test_blank_scratch_dir_setting_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INGEST_TMP_DIR", "  ")
    assert Settings().ingest_tmp_dir is None  # never "" (= the current directory)


def test_worker_init_hook_exits_instead_of_starting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Celery swallows exceptions from signal handlers; the hook must exit the process."""
    monkeypatch.setattr(get_settings(), "env", "prod")
    monkeypatch.setattr(get_settings(), "ingest_tmp_dir", None)
    with pytest.raises(SystemExit):
        tasks._prepare_scratch()


def test_worker_start_sweeps_leftover_scratch_dirs(tmp_path: Path) -> None:
    leftover = tmp_path / f"{worker_ingest.TMP_PREFIX}abc123"
    leftover.mkdir()
    (leftover / "result.ndjson.gz").write_bytes(b"x" * 1024)
    stray = tmp_path / f"{worker_ingest.TMP_PREFIX}file"
    stray.write_bytes(b"x")
    keep = tmp_path / "unrelated"
    keep.mkdir()
    settings = get_settings().model_copy(update={"env": "prod", "ingest_tmp_dir": str(tmp_path)})
    worker_ingest.prepare_scratch(settings)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["unrelated"]
