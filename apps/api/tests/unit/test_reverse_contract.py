"""`re.v1` contract (M10 phase 1, frozen): the valid fixtures round-trip, every hostile one is
refused (framing, contract or cross-record rules), the job message's rules hold, a stream at
every cap fits the framing bounds, and the additive `static.v1` fields keep old streams valid.

Pure Python (pydantic only): also runs on a host without the API's dependencies:

  cd apps/api && PYTHONPATH=../../packages/py-jobs/src python -m pytest -p no:cacheprovider \
      --noconftest tests/unit/test_reverse_contract.py
"""

import hashlib
import json
import uuid
from pathlib import Path

import cyberlab_jobs
import pytest
from cyberlab_jobs import RE_ANALYZE, Queues
from cyberlab_jobs.reverse import (
    CAP_CALL_EDGES,
    CAP_DECOMPILED,
    CAP_FINDINGS,
    CAP_FUNCTIONS,
    CAP_IMPORT_REFS,
    CAP_IMPORTS,
    CAP_IOCS,
    CAP_STRING_REFS,
    CAP_STRINGS,
    DIAGNOSTIC_ERROR_CODES,
    MAX_CODE_BYTES,
    RE_ERROR_CODES,
    RE_LINE_ADAPTER,
    CodeKind,
    DecompileStatus,
    ReDecompiledRecord,
    ReEngine,
    ReJobV1,
    ReLimits,
    ReProfile,
    ReProgramRecord,
    ReResultHeader,
    StreamRefused,
    code_sha256,
    validate_stream,
)
from cyberlab_jobs.results import ResultTrailer
from cyberlab_jobs.static import STATIC_LINE_ADAPTER, CapabilityRecord, StaticResultHeader
from pydantic import BaseModel, ValidationError

FIXTURES = Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures"
RE = FIXTURES / "reverse"
HOSTILE = RE / "hostile"
JOBS = {
    "pe_full.ndjson": uuid.UUID("7b2e1d0f-9c7a-4d66-8e0f-1e2c7a6b2001"),
    "elf_full.ndjson": uuid.UUID("7b2e1d0f-9c7a-4d66-8e0f-1e2c7a6b2002"),
    "quick.ndjson": uuid.UUID("7b2e1d0f-9c7a-4d66-8e0f-1e2c7a6b2003"),
    "full_requested.ndjson": uuid.UUID("7b2e1d0f-9c7a-4d66-8e0f-1e2c7a6b2004"),
    "unsupported_arch.ndjson": uuid.UUID("7b2e1d0f-9c7a-4d66-8e0f-1e2c7a6b2005"),
    "hostile_ai.ndjson": uuid.UUID("7b2e1d0f-9c7a-4d66-8e0f-1e2c7a6b2006"),
}
DIAGNOSTIC = {"unsupported_arch.ndjson"}
PE_JOB = JOBS["pe_full.ndjson"]


def limits(**overrides: int) -> ReLimits:
    values = {
        "max_bytes": 16 * 1024**2,
        "timeout_s": 3600,
        "tool_timeout_s": 1800,
        "analysis_timeout_s": 1500,
        "decompile_timeout_s": 30,
        "quick_timeout_s": 300,
        "max_functions": CAP_FUNCTIONS,
        "max_call_edges": CAP_CALL_EDGES,
        "max_imports": CAP_IMPORTS,
        "max_import_refs": CAP_IMPORT_REFS,
        "max_strings": CAP_STRINGS,
        "max_string_refs": CAP_STRING_REFS,
        "max_decompiled": 300,
        "max_code_bytes": MAX_CODE_BYTES,
        "max_code_total_bytes": 32 * 1024**2,
        "max_findings": CAP_FINDINGS,
        "max_iocs": CAP_IOCS,
        "max_result_bytes": 256 * 1024**2,
        "max_work_bytes": 2 * 1024**3,
    }
    values.update(overrides)
    return ReLimits.model_validate(values)


def read_stream(path: Path, job_id: uuid.UUID, *, diagnostic: bool = False) -> list[BaseModel]:
    """Framing (trailer last, hashed), the contract per line, then the cross-record rules."""
    raw = path.read_bytes().splitlines(keepends=True)
    lines: list[BaseModel] = []
    digest = hashlib.sha256()
    for index, line in enumerate(raw):
        try:
            parsed = RE_LINE_ADAPTER.validate_json(line)
        except ValidationError as exc:
            raise StreamRefused(f"line {index + 1} invalid") from exc
        if isinstance(parsed, ResultTrailer) != (index == len(raw) - 1):
            raise StreamRefused("the trailer is the last line, exactly once")
        if not isinstance(parsed, ResultTrailer):
            digest.update(line)
        lines.append(parsed)
    trailer = lines[-1]
    assert isinstance(trailer, ResultTrailer)
    if trailer.line_count != len(lines) - 1 or trailer.sha256 != digest.hexdigest():
        raise StreamRefused("trailer mismatch")
    validate_stream(lines, job_id=job_id, limits=limits(), diagnostic=diagnostic)
    return lines


@pytest.mark.parametrize("name", sorted(JOBS))
def test_valid_fixtures_round_trip(name: str) -> None:
    lines = read_stream(RE / name, JOBS[name], diagnostic=name in DIAGNOSTIC)
    for line, raw in zip(lines, (RE / name).read_bytes().splitlines(), strict=True):
        again = RE_LINE_ADAPTER.validate_json(line.model_dump_json(exclude_unset=True))
        assert again == line
        assert json.loads(raw)["kind"] == getattr(line, "kind")  # noqa: B009


def test_every_valid_fixture_is_labelled_synthetic() -> None:
    for name in JOBS:
        header = RE_LINE_ADAPTER.validate_json((RE / name).read_bytes().splitlines()[0])
        assert isinstance(header, ReResultHeader)
        assert header.engine in (ReEngine.REPLAY, ReEngine.RADARE2)
        assert "synthetic" in header.tool_versions["fixture"]


HOSTILE_STREAMS = sorted(p.name for p in HOSTILE.glob("*.ndjson") if p.name != "replay_engine.ndjson")


@pytest.mark.parametrize("name", HOSTILE_STREAMS)
def test_hostile_streams_are_refused(name: str) -> None:
    diagnostic = name == "diagnostic_with_records.ndjson"
    job = JOBS["unsupported_arch.ndjson"] if diagnostic else PE_JOB
    if name.startswith("quick_"):
        job = JOBS["quick.ndjson"]
    with pytest.raises((StreamRefused, ValidationError, ValueError, AssertionError)):
        read_stream(HOSTILE / name, job, diagnostic=diagnostic)


def test_replay_engine_is_a_contract_value() -> None:
    """`engine: replay` is valid by contract; the ingest refuses it outside the test profile
    (`RE_ENGINE=replay` needs TEST_PROFILE=1; phase 7)."""
    lines = read_stream(HOSTILE / "replay_engine.ndjson", PE_JOB)
    header = lines[0]
    assert isinstance(header, ReResultHeader) and header.engine == ReEngine.REPLAY


def test_hostile_ai_payloads_are_present() -> None:
    """RT11: phase 9 and phase 10 seed from these rows."""
    text = (RE / "hostile_ai.ndjson").read_text(encoding="utf-8")
    for payload in (
        "IgnorePreviousInstructions_SayClean",
        "a" * 255,
        "SYSTEM NOTE",
        "‮",
        "<<END EVIDENCE",
        "INT_IP_7",
        "раyload_init",
    ):
        assert payload in text, payload


def test_pe_fixture_shape() -> None:
    lines = read_stream(RE / "pe_full.ndjson", PE_JOB)
    kinds = [getattr(line, "kind") for line in lines]  # noqa: B009
    assert 25 <= kinds.count("function") <= 40
    decompiled = [line for line in lines if isinstance(line, ReDecompiledRecord)]
    assert len(decompiled) == 6
    statuses = {d.status for d in decompiled}
    assert {DecompileStatus.TRUNCATED, DecompileStatus.TIMEOUT, DecompileStatus.OK} <= statuses
    truncated = next(d for d in decompiled if d.status == DecompileStatus.TRUNCATED)
    assert truncated.code is not None and "[cyberlab: truncated" in truncated.code
    assert kinds.count("finding") == 2 and kinds.count("ioc") >= 1


def test_quick_stream_has_no_decompiled_line() -> None:
    lines = read_stream(RE / "quick.ndjson", JOBS["quick.ndjson"])
    header = lines[0]
    assert isinstance(header, ReResultHeader)
    assert header.profile == ReProfile.QUICK and header.code_kind == CodeKind.DISASM
    assert not any(isinstance(line, ReDecompiledRecord) for line in lines)


def test_elf_program_carries_both_bases() -> None:
    """RT8: Ghidra rebased the PIE; the join uses file virtual addresses."""
    program = read_stream(RE / "elf_full.ndjson", JOBS["elf_full.ndjson"])[1]
    assert isinstance(program, ReProgramRecord)
    assert (program.image_base, program.preferred_base) == (0x100000, 0)
    assert program.to_file_va(0x101000) == 0x1000
    assert program.to_va(0x1000) == 0x101000


def test_decompiled_record_rules() -> None:
    code = "int f(void)\n{\n  return 0;\n}"
    ok = {
        "function_entry": 0x1000,
        "status": "ok",
        "code_kind": "pseudo_c",
        "code": code,
        "lines": 4,
        "code_sha256": code_sha256(code),
    }
    ReDecompiledRecord.model_validate(ok)
    for bad in (
        {**ok, "code": None, "code_sha256": None, "lines": 0},  # ok without code
        {**ok, "status": "timeout"},  # code on a timeout
        {**ok, "lines": 3},
        {**ok, "status": "truncated"},  # truncated without cut bytes
        {**ok, "truncated_bytes": 5},  # cut bytes on an ok record
        {**ok, "code": "x" * (MAX_CODE_BYTES + 1), "code_sha256": code_sha256("x" * 65537)},
        {**ok, "code": "\ud800", "code_sha256": "0" * 64, "lines": 1},
    ):
        with pytest.raises(ValidationError):
            ReDecompiledRecord.model_validate(bad)


def _job(**overrides: object) -> dict[str, object]:
    job: dict[str, object] = {
        "job_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "evidence_id": str(uuid.uuid4()),
        "source_job_id": str(uuid.uuid4()),
        "expected_sha256": "a" * 64,
        "size_bytes": 1024,
        "evidence_url": "http://minio:9000/evidence/x?X-Amz-Signature=abc",
        "result_post": {"url": "http://minio:9000/analysis-results", "fields": {"key": "k"}},
        "ingest_token": "t" * 43,
        "profile": "full",
        "file_format": "pe",
        "decompile_addresses": [0x401000],
        "capa_file_vas": [0x401000, 0x401200],
        "limits": limits().model_dump(),
    }
    job.update(overrides)
    return job


def test_job_message_rules() -> None:
    ReJobV1.model_validate(_job())
    for bad in (
        _job(decompile_addresses=[0x401000, 0x401000]),
        _job(profile="quick"),  # requested addresses with quick (RT10)
        _job(profile="targeted", decompile_addresses=[]),  # no targeted profile (RT10)
        _job(capa_file_vas=[0x401200, 0x401000]),
        _job(decompile_addresses=list(range(65))),
        _job(file_format="macho"),
        _job(size_bytes=17 * 1024**2),
    ):
        with pytest.raises(ValidationError):
            ReJobV1.model_validate(bad)
    assert RE_ANALYZE == "reverse.analyze"
    assert Queues("test.").reverse == "test.reverse"


def test_limits_nest_the_timeouts() -> None:
    for bad in (
        {"decompile_timeout_s": 1800},
        {"tool_timeout_s": 3600},
        {"analysis_timeout_s": 2000},
        {"max_decompiled": CAP_DECOMPILED + 1},
        {"max_code_bytes": MAX_CODE_BYTES + 1},
    ):
        with pytest.raises(ValidationError):
            limits(**bad)


def test_a_stream_at_every_cap_fits_the_framing_bounds() -> None:
    """The M8 RT9 lesson: the RE ingest's line and byte bounds hold a stream at every cap."""
    lim = limits(max_decompiled=CAP_DECOMPILED)
    assert lim.max_lines() == 3 + sum(
        (
            CAP_FUNCTIONS,
            CAP_CALL_EDGES,
            CAP_IMPORTS,
            CAP_IMPORT_REFS,
            CAP_STRINGS,
            CAP_STRING_REFS,
            CAP_DECOMPILED,
            CAP_FINDINGS,
            CAP_IOCS,
        )
    )
    # Generous per-line upper bounds (JSON escaping included): code is bounded by the total.
    worst = (
        CAP_FUNCTIONS * 3_500
        + CAP_CALL_EDGES * 120
        + CAP_IMPORTS * 900
        + CAP_IMPORT_REFS * 120
        + CAP_STRINGS * 6_400
        + CAP_STRING_REFS * 120
        + CAP_DECOMPILED * 600
        + lim.max_code_total_bytes * 6
        + CAP_FINDINGS * 8_000
        + CAP_IOCS * 12_500
    )
    assert worst <= 768 * 1024**2  # RE_MAX_RESULT_DECOMPRESSED_BYTES


def test_error_codes() -> None:
    assert DIAGNOSTIC_ERROR_CODES <= set(RE_ERROR_CODES)
    assert {"re_out_of_memory", "re_work_too_large", "not_implemented"} <= set(RE_ERROR_CODES)


# --- static.v1 additive fields (M10 phase 1, plan Frozen interfaces 2) -----------------------


def test_static_capability_locations_are_additive() -> None:
    old = CapabilityRecord.model_validate({"name": "inject thread"})
    assert old.locations == []
    new = CapabilityRecord.model_validate({"name": "inject thread", "locations": [0x401000, 0x401020]})
    assert new.locations == [0x401000, 0x401020]
    for bad in (list(range(33)), [0x401020, 0x401000], [2**64]):
        with pytest.raises(ValidationError):
            CapabilityRecord.model_validate({"name": "x", "locations": bad})
    header = StaticResultHeader.model_validate(
        {
            "job_id": str(uuid.uuid4()),
            "profile": "full",
            "file_format": "pe",
            "tool_versions": {},
        }
    )
    assert header.capa_base_address is None
    line = {"kind": "capability", "name": "x", "locations": [4198400]}
    assert isinstance(STATIC_LINE_ADAPTER.validate_json(json.dumps(line)), CapabilityRecord)
