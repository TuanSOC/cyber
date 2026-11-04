"""`static.v1` validation reasons (no database, no object store)."""

import dataclasses
import gzip
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs.static import ElfInfo

from app.core.config import get_settings
from app.modules.analysis import dispatch
from app.modules.static_analysis import ingest as static_ingest
from app.modules.static_analysis import stream
from tests import pcap_results as pr
from tests import static_results as sr

JOB = uuid.UUID(int=7)
DATA = b"MZ sample bytes"
SAMPLE = sr.sample_for(DATA)
EXPECTED = stream.Expected(sha256=SAMPLE.sha256, size=SAMPLE.size, md5=SAMPLE.md5, sha1=SAMPLE.sha1)
CAPS = stream.Caps(
    max_decompressed_bytes=10 * 1024**2,
    per_kind={**stream.Caps.from_settings(get_settings()).per_kind},
    max_lines=1000,
)


def _write(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "result.ndjson.gz"
    path.write_bytes(data)
    return path


def _reason(
    tmp_path: Path, data: bytes, caps: stream.Caps = CAPS, expected: stream.Expected = EXPECTED
) -> str:
    with pytest.raises(stream.InvalidResult) as info:
        stream.validate(_write(tmp_path, data), JOB, expected, caps)
    return info.value.reason


def test_valid_stream_counts_every_kind(tmp_path: Path) -> None:
    result = stream.validate(_write(tmp_path, sr.stream(JOB, SAMPLE)), JOB, EXPECTED, CAPS)
    assert result.sample == SAMPLE and result.pe is not None and result.elf is None
    assert dict(result.counts) == {
        "sample": 1,
        "pe": 1,
        "section": 3,
        "import": 6,
        "export": 2,
        "resource": 2,
        "string": 4,
        "signature_match": 2,
        "capability": 2,
        "finding": 2,
        "ioc": 4,
    }
    records = list(stream.records(_write(tmp_path, sr.stream(JOB, SAMPLE)), CAPS))
    assert len(records) == 27 and not {r.kind for r, _ in records} & stream.SAMPLE_KINDS
    assert all(size == len(pr.line(r)) for r, size in records)


def test_expected_hashes_are_optional_beyond_sha256_and_size(tmp_path: Path) -> None:
    lenient = stream.Expected(sha256=SAMPLE.sha256, size=SAMPLE.size)
    data = sr.stream(JOB, SAMPLE)
    assert stream.validate(_write(tmp_path, data), JOB, lenient, CAPS).sample == SAMPLE


def _elf() -> bytes:
    return pr.line(
        ElfInfo(elf_class=64, machine="x86-64", elf_type="EXEC", entry_point=0, stripped=False)
    )


@pytest.mark.parametrize(
    ("build", "reason"),
    [
        (lambda: pr.encode([pr.line(pr.header(JOB)), pr.line(SAMPLE)]), "invalid_header"),
        (lambda: pr.encode(sr.lines(uuid.uuid4(), SAMPLE)), "header_job_mismatch"),
        (lambda: pr.encode(sr.lines(JOB, SAMPLE)[:1]), "missing_sample"),
        (lambda: pr.encode([*sr.lines(JOB, SAMPLE), pr.line(SAMPLE)]), "too_many_sample"),
        (lambda: pr.encode(sr.lines(JOB, sr.sample_for(b"other"))), "sample_mismatch"),
        (lambda: pr.encode(sr.lines(JOB, SAMPLE, file_format="elf")), "format_mismatch"),
        (lambda: pr.encode(sr.lines(JOB, SAMPLE, file_format="other")), "format_mismatch"),
        (lambda: pr.encode([*sr.lines(JOB, SAMPLE), _elf()]), "format_mismatch"),
        (
            lambda: pr.encode(
                [*sr.lines(JOB, SAMPLE, [], with_pe=False, file_format="elf"), _elf(), _elf()]
            ),
            "too_many_elf",
        ),
        (lambda: pr.encode([*sr.lines(JOB, SAMPLE), pr.line({"kind": "x"})]), "invalid_record"),
        (lambda: pr.encode([*sr.lines(JOB, SAMPLE), pr.line(pr.flow(1))]), "invalid_record"),
        (
            lambda: pr.encode(sr.lines(JOB, SAMPLE), trailer={"sha256": "f" * 64}),
            "trailer_hash_mismatch",
        ),
        (lambda: pr.encode(sr.lines(JOB, SAMPLE), add_trailer=False), "invalid_trailer"),
        (lambda: gzip.compress(b""), "missing_header"),
        (lambda: b"plain text\n", "bad_gzip"),
    ],
)
def test_refusal_reasons(tmp_path: Path, build: Callable[[], bytes], reason: str) -> None:
    assert _reason(tmp_path, build()) == reason


def test_sample_size_must_match_too(tmp_path: Path) -> None:
    expected = dataclasses.replace(EXPECTED, size=EXPECTED.size + 1)
    assert _reason(tmp_path, sr.stream(JOB, SAMPLE), expected=expected) == "sample_mismatch"


def test_per_kind_caps_come_from_the_static_limits(tmp_path: Path) -> None:
    limits = dispatch.static_limits(get_settings())
    caps = stream.Caps.from_settings(get_settings())
    assert caps.per_kind["string"] == limits.max_strings
    assert caps.per_kind["signature_match"] == limits.max_signature_matches
    assert caps.per_kind["sample"] == caps.per_kind["pe"] == caps.per_kind["elf"] == 1
    tight = dataclasses.replace(CAPS, per_kind={**CAPS.per_kind, "import": 5})
    assert _reason(tmp_path, sr.stream(JOB, SAMPLE), tight) == "too_many_import"


def test_duplicates_are_refused(tmp_path: Path) -> None:
    good = sr.lines(JOB, SAMPLE)
    finding = next(x for x in good if b'"kind":"finding"' in x)
    ioc = next(x for x in good if b'"kind":"ioc"' in x)
    assert _reason(tmp_path, pr.encode([*good, finding])) == "duplicate_finding"
    assert _reason(tmp_path, pr.encode([*good, ioc])) == "duplicate_ioc"


def test_rows_of_every_kind() -> None:
    rows: dict[str, Any] = {}
    for record in sr.sample_records():
        rows.setdefault(record.kind, static_ingest.to_row(record))  # first of each kind
    assert rows["section"][0].name == "malware_sections"
    assert rows["section"][1]["virtual_address"] == 0x1000 and "kind" not in rows["section"][1]
    assert rows["signature_match"][1]["meta"] == {"author": "cyberlab", "severity": "low"}
    assert rows["finding"][0].name == "analysis_findings" and rows["ioc"][0].name == "iocs"
    assert rows["capability"][1]["attack"] == ["T1055.012"]
