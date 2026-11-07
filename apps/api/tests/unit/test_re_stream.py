"""M10 phase 7: validation of `re.v1` result streams before any write (no database).

Every valid phase-1 fixture validates with its counts; every hostile one is refused (framing,
contract or the shared cross-record rules); the ingest's own rules hold (the job's profile, the
program identity and format, `engine: replay` outside the test profile, duplicate findings /
IOCs, header blocks that fit their columns); and a stream at every cap fits the framing
bounds the ingest passes (`RE_MAX_RESULT_DECOMPRESSED_BYTES`, lines = the caps + 3) and the
256 MiB upload cap does not need more lines than those (the M8 RT9 lesson).
"""

import dataclasses
import gzip
import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import cyberlab_jobs
import pytest
from cyberlab_jobs.results import FindingRecord, IocRecord
from cyberlab_jobs.reverse import (
    MAX_BODY_RANGES,
    MAX_CODE_BYTES,
    MAX_RESULT_BYTES,
    BodyRange,
    CodeKind,
    DecompileStatus,
    NameSource,
    ReCallEdgeRecord,
    ReDecompiledRecord,
    ReFunctionRecord,
    ReImportRecord,
    ReImportRefRecord,
    ReStringRecord,
    ReStringRefRecord,
    code_lines,
    code_sha256,
)
from pydantic import BaseModel

from app.core.config import get_settings
from app.modules.analysis.result_stream import MAX_LINE_BYTES, InvalidResult
from app.modules.reverse_engineering import stream
from app.modules.reverse_engineering.dispatch import re_limits

FIXTURES = Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures" / "reverse"
HOSTILE = FIXTURES / "hostile"
PE_JOB = uuid.UUID("7b2e1d0f-9c7a-4d66-8e0f-1e2c7a6b2001")
FIXTURE_SHA256 = "e" * 64
FIXTURE_SIZE = 48_640
EXPECTED = stream.Expected(sha256=FIXTURE_SHA256, size=FIXTURE_SIZE)


def _caps() -> stream.Caps:
    return stream.Caps.from_settings(get_settings())


def _objs(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def _fixture(name: str) -> list[dict[str, Any]]:
    objs = _objs(FIXTURES / name)
    assert objs[-1]["kind"] == "trailer"
    return objs[:-1]


def _write(tmp_path: Path, objs: list[dict[str, Any]], name: str = "result.ndjson.gz") -> Path:
    """Gzip NDJSON with the hashed trailer (the shared framing)."""
    body = b"".join(json.dumps(o).encode() + b"\n" for o in objs)
    digest = hashlib.sha256(body).hexdigest()
    trailer = {"kind": "trailer", "line_count": len(objs), "sha256": digest}
    path = tmp_path / name
    path.write_bytes(gzip.compress(body + json.dumps(trailer).encode() + b"\n"))
    return path


def _facts(objs: list[dict[str, Any]], **overrides: Any) -> stream.JobFacts:
    header = objs[0]
    program = objs[1]
    values: dict[str, Any] = {
        "job_id": uuid.UUID(header["job_id"]),
        "profile": header["profile"],
        "file_format": program.get("format"),
        "allow_replay": True,  # the fixtures are labelled `engine: replay`
        **overrides,
    }
    return stream.JobFacts(**values)


def _validate(tmp_path: Path, objs: list[dict[str, Any]], **overrides: Any) -> stream.Validated:
    return stream.validate(_write(tmp_path, objs), _facts(objs, **overrides), EXPECTED, _caps())


def _refused(tmp_path: Path, objs: list[dict[str, Any]], **overrides: Any) -> str:
    with pytest.raises(InvalidResult) as caught:
        _validate(tmp_path, objs, **overrides)
    return caught.value.reason


# --- valid fixtures ---------------------------------------------------------------------------


def test_the_pe_fixture_validates_with_its_counts(tmp_path: Path) -> None:
    objs = _fixture("pe_full.ndjson")
    path = _write(tmp_path, objs)
    result = stream.validate(path, _facts(objs), EXPECTED, _caps(), ranges=True)
    kinds = [o["kind"] for o in objs[2:]]
    assert dict(result.counts) == {k: kinds.count(k) for k in set(kinds)}
    assert result.counts["function"] == 31 and result.counts["decompiled"] == 6
    assert result.program.format == "pe" and result.program.preferred_base == 0x140000000
    assert len(result.ranges) == sum(len(o["body"]) for o in objs if o["kind"] == "function")
    assert result.decompile_status[0x140001000] == "ok"
    assert set(result.decompile_status.values()) >= {"ok", "truncated", "timeout"}
    rows = list(stream.records(path, _caps()))
    assert len(rows) == len(objs) - 2  # no header, no program line
    assert all(r.kind != "program" for r, _ in rows)


def test_ranges_are_kept_only_when_asked(tmp_path: Path) -> None:
    assert _validate(tmp_path, _fixture("pe_full.ndjson")).ranges == []


@pytest.mark.parametrize(
    "name", ["elf_full.ndjson", "quick.ndjson", "full_requested.ndjson", "hostile_ai.ndjson"]
)
def test_the_other_valid_fixtures_validate(tmp_path: Path, name: str) -> None:
    result = _validate(tmp_path, _fixture(name))
    assert result.header.job_id == uuid.UUID(_fixture(name)[0]["job_id"])


def test_the_diagnostic_fixture_is_only_a_diagnostic(tmp_path: Path) -> None:
    objs = _fixture("unsupported_arch.ndjson")
    path = _write(tmp_path, objs)
    result = stream.validate_diagnostic(path, _facts(objs), EXPECTED)
    assert result.program.arch == "other" and dict(result.counts) == {}
    with pytest.raises(InvalidResult):
        stream.validate(path, _facts(objs), EXPECTED, _caps())
    full = _write(tmp_path, _fixture("pe_full.ndjson"), "full.ndjson.gz")
    with pytest.raises(InvalidResult):
        stream.validate_diagnostic(full, _facts(_fixture("pe_full.ndjson")), EXPECTED)


# --- hostile fixtures -------------------------------------------------------------------------

HOSTILE_FILES = sorted(p.name for p in HOSTILE.glob("*.ndjson"))


@pytest.mark.parametrize("name", HOSTILE_FILES)
def test_every_hostile_fixture_is_refused(tmp_path: Path, name: str) -> None:
    """The raw file is gzipped as written (its own trailer, or none): each breaks a rule.
    `replay_engine` is contract-valid and refused by the ingest setting (the test profile is
    off here)."""
    raw = (HOSTILE / name).read_bytes()
    path = tmp_path / "hostile.ndjson.gz"
    path.write_bytes(gzip.compress(raw))
    first = json.loads(raw.splitlines()[0])
    job_id = PE_JOB if name == "wrong_job.ndjson" else uuid.UUID(first["job_id"])
    facts = stream.JobFacts(
        job_id=job_id,
        profile=first.get("profile", "full"),
        file_format=None,
        allow_replay=name != "replay_engine.ndjson",
    )
    diagnostic = name == "diagnostic_with_records.ndjson"
    with pytest.raises(InvalidResult):
        if diagnostic:
            stream.validate_diagnostic(path, facts, EXPECTED)
        else:
            stream.validate(path, facts, EXPECTED, _caps())


def test_the_hostile_set_is_complete() -> None:
    assert len(HOSTILE_FILES) == 20


# --- the ingest's own rules -------------------------------------------------------------------


def test_the_header_must_name_this_job_and_profile(tmp_path: Path) -> None:
    objs = _fixture("pe_full.ndjson")
    assert _refused(tmp_path, objs, job_id=uuid.uuid4()) == "header_job_mismatch"
    assert _refused(tmp_path, objs, profile="quick") == "header_profile_mismatch"


def test_replay_is_refused_outside_the_test_profile(tmp_path: Path) -> None:
    objs = _fixture("pe_full.ndjson")
    assert _refused(tmp_path, objs, allow_replay=False) == "replay_engine_refused"


def test_the_program_must_be_the_evidence_and_the_source_format(tmp_path: Path) -> None:
    objs = _fixture("pe_full.ndjson")
    assert _refused(tmp_path, objs, file_format="elf") == "format_mismatch"
    other = [dict(o) for o in objs]
    other[1]["sha256"] = "f" * 64
    assert _refused(tmp_path, other) == "program_mismatch"
    other[1] = {**objs[1], "size_bytes": FIXTURE_SIZE + 1}
    assert _refused(tmp_path, other) == "program_mismatch"
    # A purged source job (no sample row): no format check.
    assert _validate(tmp_path, objs, file_format=None).program.format == "pe"


def test_duplicate_findings_and_iocs_are_refused(tmp_path: Path) -> None:
    objs = _fixture("pe_full.ndjson")
    finding = next(i for i, o in enumerate(objs) if o["kind"] == "finding")
    twice = [*objs[: finding + 1], objs[finding], *objs[finding + 1 :]]
    assert _refused(tmp_path, twice) == "duplicate_finding"
    ioc = next(i for i, o in enumerate(objs) if o["kind"] == "ioc")
    twice = [*objs[: ioc + 1], objs[ioc], *objs[ioc + 1 :]]
    assert _refused(tmp_path, twice) == "duplicate_ioc"


def test_cross_record_rules_are_the_shared_checkers(tmp_path: Path) -> None:
    objs = _fixture("pe_full.ndjson")
    edge = next(i for i, o in enumerate(objs) if o["kind"] == "call_edge")
    bad = [dict(o) for o in objs]
    bad[edge] = {**objs[edge], "callee": 0x1}
    assert _refused(tmp_path, bad) == "stream_rule"
    out_of_order = [objs[0], objs[2], objs[1], *objs[3:]]
    assert _refused(tmp_path, out_of_order) == "stream_rule"
    assert _refused(tmp_path, [objs[0], *objs[2:]]) == "stream_rule"  # no program line


def test_the_job_caps_apply(tmp_path: Path) -> None:
    objs = _fixture("pe_full.ndjson")
    caps = _caps()
    assert caps.limits is not None
    tight = dataclasses.replace(caps, limits=caps.limits.model_copy(update={"max_functions": 30}))
    with pytest.raises(InvalidResult) as caught:
        stream.validate(_write(tmp_path, objs), _facts(objs), EXPECTED, tight)
    assert caught.value.reason == "stream_rule"
    lines = dataclasses.replace(caps, max_lines=len(objs))  # header .. ioc, no room for trailer
    with pytest.raises(InvalidResult) as caught:
        stream.validate(_write(tmp_path, objs), _facts(objs), EXPECTED, lines)
    assert caught.value.reason == "too_many_lines"


def test_header_blocks_must_fit_their_columns(tmp_path: Path) -> None:
    objs = _fixture("pe_full.ndjson")
    big = [dict(o) for o in objs]
    big[0] = {**objs[0], "jvm_args": [f"-Dx{i}=" + "v" * 400 for i in range(64)]}
    assert _refused(tmp_path, big) == "header_too_large"
    big[0] = {**objs[0], "truncated": {f"k{i}" + "x" * 200: True for i in range(20)}}
    assert _refused(tmp_path, big) == "header_too_large"
    big[0] = {**objs[0], "tool_versions": {**objs[0]["tool_versions"], "ghidra": "1" * 33}}
    assert _refused(tmp_path, big) == "invalid_header"


def test_another_schema_is_refused(tmp_path: Path) -> None:
    objs = _fixture("pe_full.ndjson")
    static = [{**objs[0], "schema_version": "static.v1"}, *objs[1:]]
    assert _refused(tmp_path, static) == "invalid_header"


# --- a stream at every cap ------------------------------------------------------------------

CTRL = "\x01"  # JSON-escaped as \u0001: the widest character per stored character
T0 = datetime(2026, 11, 1, tzinfo=UTC)
TOP = 2**64 - 1


def _line_bytes(record: BaseModel) -> int:
    return len(record.model_dump_json().encode()) + 1


def _worst_lines() -> dict[str, int]:
    """The largest legal line of every record kind (each text at its cap, every character
    escaped six-fold, every address at 2**64 - 1)."""
    code = CTRL * MAX_CODE_BYTES
    function = ReFunctionRecord(
        entry=TOP,
        rva=TOP,
        name=CTRL * 255,
        name_source=NameSource.GENERATED,
        size=2**63 - 1,
        body=[BodyRange(start=TOP - 1, end=TOP)] * MAX_BODY_RANGES,
        body_truncated=True,
        signature=CTRL * 512,
        calling_convention=CTRL * 32,
        instructions=2**63 - 1,
        callers=2**63 - 1,
        callees=2**63 - 1,
        priority_rank=19_999,
    )
    finding = FindingRecord(
        ts=T0,
        finding_id=uuid.uuid4(),
        type="x" * 64,
        title=CTRL * 255,
        description=CTRL * 2048,
        severity="medium",
        confidence=0.123456789,
        detection_method="heuristic:" + "x" * 64 + "@9999",
        evidence_refs=[CTRL * 64] * 50,
        attributes={f"{i:02d}" + CTRL * 62: CTRL * 255 for i in range(20)},
    )
    return {
        "function": _line_bytes(function),
        "call_edge": _line_bytes(ReCallEdgeRecord(caller=TOP, callee=TOP, sites=2**63 - 1)),
        "import": _line_bytes(
            ReImportRecord(index=9_999, library=CTRL * 128, name=CTRL * 255, ordinal=65_535,
                           address=TOP)  # fmt: skip
        ),
        "import_ref": _line_bytes(
            ReImportRefRecord(import_index=9_999, function_entry=TOP, count=2**63 - 1)
        ),
        "string": _line_bytes(
            ReStringRecord(index=19_999, address=TOP, encoding="utf16le", value=CTRL * 1024,
                           length=2**63 - 1)  # fmt: skip
        ),
        "string_ref": _line_bytes(
            ReStringRefRecord(string_index=19_999, function_entry=TOP, count=2**63 - 1)
        ),
        "decompiled": _line_bytes(
            ReDecompiledRecord(
                function_entry=TOP,
                status=DecompileStatus.OK,
                code_kind=CodeKind.PSEUDO_C,
                code=code,
                lines=code_lines(code),
                code_sha256=code_sha256(code),
                duration_ms=2**63 - 1,
            )
        )
        + 200,
        "finding": _line_bytes(finding) + 400,  # + both endpoints
        "ioc": _line_bytes(
            IocRecord(type="url", value=CTRL * 2048, first_seen=T0, last_seen=T0,
                      count=2**63 - 1, source=CTRL * 16)  # fmt: skip
        ),
    }


def test_a_stream_at_every_cap_fits_the_framing_bounds() -> None:
    settings = get_settings()
    limits = re_limits(settings)
    caps = {
        "function": limits.max_functions,
        "call_edge": limits.max_call_edges,
        "import": limits.max_imports,
        "import_ref": limits.max_import_refs,
        "string": limits.max_strings,
        "string_ref": limits.max_string_refs,
        "decompiled": limits.max_decompiled,
        "finding": limits.max_findings,
        "ioc": limits.max_iocs,
    }
    worst = _worst_lines()
    assert all(size <= MAX_LINE_BYTES for size in worst.values()), worst
    # Decompiled text is also bounded by the job's total code budget (6x when escaped).
    code_budget = 6 * limits.max_code_total_bytes + caps["decompiled"] * 600
    decompiled = min(worst["decompiled"] * caps["decompiled"], code_budget)
    total = (
        sum(worst[k] * caps[k] for k in caps if k != "decompiled")
        + decompiled
        + 3 * MAX_LINE_BYTES  # header, program, trailer
    )
    assert total <= settings.re_max_result_decompressed_bytes, total
    # The line bound is exactly the caps plus header, program and trailer.
    assert settings.re_max_result_lines() == 3 + sum(caps.values()) == limits.max_lines()
    assert _caps().max_lines == settings.re_max_result_lines()
    # The upload cap is the contract's ceiling (the presigned POST and the ingest download).
    assert settings.re_max_result_bytes <= MAX_RESULT_BYTES


def test_a_realistic_capped_stream_compresses_far_below_the_upload_cap() -> None:
    """Typical text (names, pseudo-C) at the function / edge caps: gzip keeps it well under
    the 256 MiB upload cap, so the line and size bounds are the binding ones."""
    lines = []
    for i in range(20_000):
        lines.append(
            ReFunctionRecord(
                entry=0x140001000 + i * 0x40,
                rva=0x1000 + i * 0x40,
                name=f"FUN_{0x140001000 + i * 0x40:016x}",
                name_source=NameSource.GENERATED,
                size=0x40,
                body=[BodyRange(start=0x1000 + i * 0x40, end=0x1040 + i * 0x40)],
                instructions=16,
            ).model_dump_json()
        )
    data = ("\n".join(lines) + "\n").encode()
    assert len(gzip.compress(data, compresslevel=6)) * 20 < MAX_RESULT_BYTES
