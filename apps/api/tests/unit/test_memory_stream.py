"""`memory.v1` validation reasons and the RT9 framing proof (no database, no object store).

The phase-1 fixtures are used verbatim (their own job ids and trailers) or as parsed dicts
that a test mutates (`tests.memory_results`); `pcap_results.encode()` re-frames those.
"""

import gzip
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs.memory import (
    PLUGINS_BY_PROFILE,
    MemoryArtifactRecord,
    MemoryConnectionRecord,
    MemoryImageRecord,
    MemoryInjectionRecord,
    MemoryProcessRecord,
    MemoryProfile,
    MemoryResultHeader,
    MemoryTimelineEvent,
    WindowsPdb,
)
from cyberlab_jobs.results import FindingRecord, IocRecord
from pydantic import BaseModel

from app.core.config import get_settings
from app.modules.analysis.result_stream import MAX_LINE_BYTES
from app.modules.memory_analysis import ingest as memory_ingest
from app.modules.memory_analysis import stream
from app.modules.memory_analysis.dispatch import memory_limits
from tests import memory_results as mr
from tests import pcap_results as pr
from tests.memory_helpers import FIXTURES

WINDOWS_JOB = mr.FIXTURE_JOBS[mr.WINDOWS]
LINUX_JOB = mr.FIXTURE_JOBS[mr.LINUX]
DIAGNOSTIC_JOB = mr.FIXTURE_JOBS[mr.DIAGNOSTIC]
EXPECTED = stream.Expected(sha256=mr.FIXTURE_SHA256, size=mr.FIXTURE_SIZE)
CAPS = stream.Caps.from_settings(get_settings())


def _facts(
    job: uuid.UUID = WINDOWS_JOB, profile: str = "triage", os_hint: str = "auto"
) -> stream.JobFacts:
    return stream.JobFacts(job_id=job, profile=profile, os_hint=os_hint)


def _write(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "result.ndjson.gz"
    path.write_bytes(data)
    return path


def _fixture(tmp_path: Path, name: str) -> Path:
    return _write(tmp_path, gzip.compress((FIXTURES / name).read_bytes()))


def _framed(objs: list[dict[str, Any]]) -> bytes:
    return pr.encode([mr.dumps(o) for o in objs])


def _reason(
    tmp_path: Path,
    data: bytes,
    *,
    facts: stream.JobFacts | None = None,
    caps: stream.Caps = CAPS,
    expected: stream.Expected = EXPECTED,
) -> str:
    with pytest.raises(stream.InvalidResult) as info:
        stream.validate(_write(tmp_path, data), facts or _facts(), expected, caps)
    return info.value.reason


def _diagnostic_reason(tmp_path: Path, data: bytes, expected: stream.Expected = EXPECTED) -> str:
    with pytest.raises(stream.InvalidResult) as info:
        stream.validate_diagnostic(_write(tmp_path, data), _facts(DIAGNOSTIC_JOB), expected)
    return info.value.reason


# --- valid streams -----------------------------------------------------------------------


def test_windows_fixture_counts_every_kind(tmp_path: Path) -> None:
    path = _fixture(tmp_path, mr.WINDOWS)
    result = stream.validate(path, _facts(), EXPECTED, CAPS)
    assert result.header.os == "windows" and result.image is not None
    assert result.image.sha256 == EXPECTED.sha256
    assert dict(result.counts) == {
        "image": 1,
        "process": 40,
        "connection": 3,
        "injection": 1,
        "artifact": 6,
        "finding": 2,
        "ioc": 2,
        "timeline": 4,
    }
    assert result.orphan_refs == 0
    rows = list(stream.records(path, CAPS))
    assert len(rows) == 58 and all(r.kind != "image" for r, _ in rows)
    assert memory_ingest.counts(result) == mr.WINDOWS_COUNTS


def test_linux_fixture_is_valid(tmp_path: Path) -> None:
    result = stream.validate(_fixture(tmp_path, mr.LINUX), _facts(LINUX_JOB), EXPECTED, CAPS)
    assert result.header.os == "linux" and result.counts["artifact"] == 2


def test_an_os_hint_must_be_honoured(tmp_path: Path) -> None:
    path = _fixture(tmp_path, mr.WINDOWS)
    assert stream.validate(path, _facts(os_hint="windows"), EXPECTED, CAPS).header.os == "windows"
    with pytest.raises(stream.InvalidResult) as info:
        stream.validate(path, _facts(os_hint="linux"), EXPECTED, CAPS)
    assert info.value.reason == "header_os_mismatch"


def test_the_profile_must_be_the_jobs(tmp_path: Path) -> None:
    with pytest.raises(stream.InvalidResult) as info:
        stream.validate(_fixture(tmp_path, mr.WINDOWS), _facts(profile="full"), EXPECTED, CAPS)
    assert info.value.reason == "header_profile_mismatch"


def test_the_diagnostic_fixture_carries_its_requirement(tmp_path: Path) -> None:
    path = _fixture(tmp_path, mr.DIAGNOSTIC)
    result = stream.validate_diagnostic(path, _facts(DIAGNOSTIC_JOB), EXPECTED)
    assert result.header.symbols.status == "missing" and result.image is not None
    row = memory_ingest.image_row(result)
    assert (row["pdb_name"], row["pdb_guid"], row["pdb_age"]) == (
        "ntkrnlmp.pdb",
        "89ABCDEF0123456789ABCDEF01234567",
        2,
    )  # the requirement, not the image's own PDB line
    assert row["symbols_status"] == "missing" and row["plugins"] == []


def test_a_diagnostic_without_image_is_accepted(tmp_path: Path) -> None:
    header = mr.parsed(mr.DIAGNOSTIC)[0]
    result = stream.validate_diagnostic(
        _write(tmp_path, _framed([header])), _facts(DIAGNOSTIC_JOB), EXPECTED
    )
    assert result.image is None and memory_ingest.image_row(result)["arch"] is None


def test_success_and_diagnostic_are_not_interchangeable(tmp_path: Path) -> None:
    diagnostic = (FIXTURES / mr.DIAGNOSTIC).read_bytes()
    assert (
        _reason(tmp_path, gzip.compress(diagnostic), facts=_facts(DIAGNOSTIC_JOB))
        == "symbols_status_mismatch"
    )
    full = gzip.compress((FIXTURES / mr.WINDOWS).read_bytes())
    with pytest.raises(stream.InvalidResult) as info:
        stream.validate_diagnostic(_write(tmp_path, full), _facts(), EXPECTED)
    assert info.value.reason == "not_diagnostic"


# --- hostile fixtures (phase 1) ----------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("wrong_job", "header_job_mismatch"),
        ("nan", "invalid_record"),
        ("nul_char", "invalid_record"),
        ("oversize_cmdline", "invalid_record"),
        ("attributes_33", "invalid_record"),
        ("nested_attribute", "invalid_record"),
        ("float_attribute", "invalid_record"),
        ("extra_field", "invalid_record"),
        ("unknown_plugin", "invalid_header"),
        ("address_overflow", "invalid_record"),
        ("verdict_severity", "invalid_record"),
        ("after_trailer", "invalid_record"),
        ("no_trailer", "invalid_trailer"),
    ],
)
def test_hostile_fixtures_are_refused(tmp_path: Path, name: str, reason: str) -> None:
    data = gzip.compress((FIXTURES / "hostile" / f"{name}.ndjson").read_bytes())
    assert _reason(tmp_path, data) == reason


@pytest.mark.parametrize(
    ("name", "reasons"),
    [
        ("bad_guid", {"invalid_header"}),
        ("non_kernel_pdb", {"invalid_header"}),
        ("banner_control_chars", {"invalid_header"}),
        # Longer than any diagnostic may be (3 lines), or a record after the header.
        ("diagnostic_with_records", {"too_many_lines", "diagnostic_with_records"}),
    ],
)
def test_hostile_diagnostics_are_refused(tmp_path: Path, name: str, reasons: set[str]) -> None:
    data = gzip.compress((FIXTURES / "hostile" / f"{name}.ndjson").read_bytes())
    assert _diagnostic_reason(tmp_path, data) in reasons


# --- mutated streams ---------------------------------------------------------------------


def _windows() -> list[dict[str, Any]]:
    return mr.parsed(mr.WINDOWS)


def _with(objs: list[dict[str, Any]], index: int, **fields: Any) -> list[dict[str, Any]]:
    out = list(objs)
    out[index] = {**out[index], **fields}
    return out


def _header_with(objs: list[dict[str, Any]], **fields: Any) -> list[dict[str, Any]]:
    return _with(objs, 0, **fields)


def _image_index(objs: list[dict[str, Any]]) -> int:
    return mr.index_of(objs, "image")


def _bash() -> dict[str, Any]:
    return {"kind": "artifact", "type": "bash", "pid": 4, "attributes": {"command": "ls"}}


def _plugins_with(status: str) -> list[dict[str, Any]]:
    plugins = _windows()[0]["plugins"]
    return [
        {**p, "status": status, "error_code": "plugin_failed"}
        if p["plugin"] == "windows.pslist"
        else p
        for p in plugins
    ]


MUTATIONS: dict[str, Any] = {
    "image_sha256": (
        lambda o: _with(o, _image_index(o), sha256="a" * 64),
        "image_mismatch",
    ),
    "image_size": (
        lambda o: _with(o, _image_index(o), size_bytes=1),
        "image_mismatch",
    ),
    "no_image": (lambda o: [x for x in o if x["kind"] != "image"], "missing_image"),
    "two_images": (lambda o: [*o, o[_image_index(o)]], "too_many_image"),
    "duplicate_process": (
        lambda o: [*o, o[mr.index_of(o, "process", pid=4)]],
        "duplicate_process",
    ),
    "duplicate_finding": (
        lambda o: [*o, o[mr.index_of(o, "finding")]],
        "duplicate_finding",
    ),
    "duplicate_ioc": (lambda o: [*o, o[mr.index_of(o, "ioc")]], "duplicate_ioc"),
    "bash_on_windows": (lambda o: [*o, _bash()], "os_mismatch"),
    "banner_on_windows": (
        lambda o: _with(o, _image_index(o), kernel_banner="Linux version 6.1"),
        "os_mismatch",
    ),
    "pslist_failed": (
        lambda o: _header_with(o, plugins=_plugins_with("failed")),
        "process_list_not_ok",
    ),
    "pslist_missing": (
        lambda o: _header_with(
            o, plugins=[p for p in o[0]["plugins"] if p["plugin"] != "windows.pslist"]
        ),
        "process_list_not_ok",
    ),
    "header_extra_field": (lambda o: _header_with(o, verdict="malicious"), "invalid_header"),
    "static_header": (
        lambda o: _header_with(o, schema_version="static.v1"),
        "invalid_header",
    ),
    "engine_version_too_long": (
        lambda o: _header_with(o, tool_versions={"volatility3": "2." + "9" * 70}),
        "invalid_header",
    ),
    "trailer_line": (
        lambda o: [*o, {"kind": "trailer", "line_count": 1, "sha256": "0" * 64}],
        "invalid_record",
    ),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_mutated_streams_are_refused(tmp_path: Path, name: str) -> None:
    mutate, reason = MUTATIONS[name]
    assert _reason(tmp_path, _framed(mutate(_windows()))) == reason


def test_service_on_linux_and_pdb_on_a_linux_image_are_refused(tmp_path: Path) -> None:
    objs = mr.parsed(mr.LINUX)
    facts = _facts(LINUX_JOB)
    service = {"kind": "artifact", "type": "service", "attributes": {"name": "x"}}
    assert _reason(tmp_path, _framed([*objs, service]), facts=facts) == "os_mismatch"
    pdb = {"name": "ntkrnlmp.pdb", "guid": "0" * 32, "age": 1}
    patched = _with(objs, _image_index(objs), pdb=pdb)
    assert _reason(tmp_path, _framed(patched), facts=facts) == "os_mismatch"


def test_a_reused_pid_at_another_offset_is_a_second_process(tmp_path: Path) -> None:
    objs = _windows()
    first = objs[mr.index_of(objs, "process", pid=4)]
    reused = {**first, "offset": 4096, "sources": ["psscan"]}
    result = stream.validate(_write(tmp_path, _framed([*objs, reused])), _facts(), EXPECTED, CAPS)
    assert result.counts["process"] == 41


def test_unknown_pids_are_counted_not_invented(tmp_path: Path) -> None:
    objs = _windows()
    ghost_conn = {"kind": "connection", "proto": "tcp", "pid": 999_999, "remote_port": 443}
    ghost_art = {"kind": "artifact", "type": "module", "pid": 999_999, "attributes": {}}
    ghost_event = {
        "kind": "timeline",
        "ts": "2026-11-01T09:00:00Z",
        "event": "process_start",
        "title": "ghost",
        "pid": 888_888,
    }
    data = _framed([*objs, ghost_conn, ghost_art, ghost_event])
    result = stream.validate(_write(tmp_path, data), _facts(), EXPECTED, CAPS)
    assert result.orphan_refs == 3
    assert memory_ingest.counts(result)["orphan_refs"] == 3


def test_caps_are_per_kind(tmp_path: Path) -> None:
    tight = stream.Caps(
        max_decompressed_bytes=CAPS.max_decompressed_bytes,
        per_kind={**CAPS.per_kind, "process": 39},
        max_lines=CAPS.max_lines,
    )
    assert _reason(tmp_path, _framed(_windows()), caps=tight) == "too_many_process"


def test_framing_bounds_apply(tmp_path: Path) -> None:
    data = _framed(_windows())
    small = stream.Caps(max_decompressed_bytes=4096, per_kind=CAPS.per_kind, max_lines=10_000)
    assert _reason(tmp_path, data, caps=small) == "decompressed_too_large"
    short = stream.Caps(
        max_decompressed_bytes=CAPS.max_decompressed_bytes, per_kind=CAPS.per_kind, max_lines=10
    )
    assert _reason(tmp_path, data, caps=short) == "too_many_lines"
    assert _reason(tmp_path, b"not gzip at all") == "bad_gzip"
    lines = [mr.dumps(o) for o in _windows()]
    assert _reason(tmp_path, pr.encode(lines, trailer={"line_count": 3})) == (
        "trailer_count_mismatch"
    )
    assert _reason(tmp_path, pr.encode(lines, trailer={"sha256": "0" * 64})) == (
        "trailer_hash_mismatch"
    )


def test_diagnostic_body_rules(tmp_path: Path) -> None:
    header, image = mr.parsed(mr.DIAGNOSTIC)
    process = _windows()[mr.index_of(_windows(), "process", pid=4)]
    assert _diagnostic_reason(tmp_path, _framed([header, process])) == "diagnostic_with_records"
    assert _diagnostic_reason(tmp_path, _framed([header, image, image])) == "too_many_lines"
    wrong = {**image, "sha256": "a" * 64}
    assert _diagnostic_reason(tmp_path, _framed([header, wrong])) == "image_mismatch"
    plugins = [{"plugin": "windows.info", "status": "ok"}]
    assert _diagnostic_reason(tmp_path, _framed([{**header, "plugins": plugins}, image])) == (
        "invalid_header"
    )
    linux_requirement = {**header, "symbols": {"status": "missing", "required": {"banner": "x"}}}
    assert _diagnostic_reason(tmp_path, _framed([linux_requirement, image])) == "invalid_header"


# --- RT9: the memory bounds, and a stream at every cap -----------------------------------


def test_caps_are_the_memory_bounds_not_the_shared_ones() -> None:
    settings = get_settings()
    caps = stream.Caps.from_settings(settings)
    assert caps.max_decompressed_bytes == settings.memory_max_result_decompressed_bytes
    assert caps.max_lines == settings.memory_max_result_lines()
    assert caps.max_lines == memory_limits(settings).max_lines()
    assert caps.max_lines != settings.analysis_max_result_lines
    assert caps.per_kind["artifact"] == settings.memory_max_artifacts
    assert stream.DIAGNOSTIC_CAPS.max_lines == 3


TS = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)
V6 = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
MAX_ADDRESS = 2**64 - 1
MAX_COUNT = 2**63 - 1


def _text(n: int, ch: str = "x") -> str:
    return ch * n


def _max_header() -> MemoryResultHeader:
    plugins = PLUGINS_BY_PROFILE[("windows", MemoryProfile.FULL)]
    return MemoryResultHeader.model_validate(
        {
            "job_id": str(WINDOWS_JOB),
            "profile": "full",
            "os": "windows",
            "engine": "volatility3",
            "tool_versions": {f"{i:02d}" + _text(253): _text(255) for i in range(16)},
            "symbols": {"status": "resolved", "isf_sha256": "c" * 64},
            "plugins": [
                {
                    "plugin": p.value,
                    "status": "timeout",
                    "rows": MAX_COUNT,
                    "truncated": True,
                    "duration_ms": MAX_COUNT,
                    "error_code": "p" + _text(63, "q"),
                }
                for p in plugins
            ],
            "audit_events": {f"{i:02d}" + _text(62): MAX_COUNT for i in range(16)},
            "engine_errors": ["e" + _text(63, "r")] * 32,
            "truncated": {f"{i:02d}" + _text(253): True for i in range(32)},
        }
    )


def _max_artifact() -> MemoryArtifactRecord:
    """The largest attributes the 4 KiB column check admits (the contract enforces it)."""
    base = {f"a{i}": _text(1024) for i in range(3)}
    for size in range(1024, 0, -1):
        try:
            return MemoryArtifactRecord(
                type="ldr_unlinked", pid=2**32 - 1, attributes={**base, "a3": _text(size)}
            )
        except ValueError:
            continue
    raise AssertionError("no artifact fits")


def _max_finding() -> FindingRecord:
    return FindingRecord.model_validate(
        {
            "ts": TS,
            "src_ip": V6,
            "src_port": 65535,
            "dst_ip": V6,
            "dst_port": 65535,
            "flow_ref": _text(64),
            "finding_id": str(uuid.UUID(int=1)),
            "type": "m" + _text(63, "n"),
            "title": _text(255),
            "description": _text(2048),
            "severity": "medium",
            "confidence": 0.123456789,
            "detection_method": "h" + _text(31) + ":" + _text(64) + "@9999",
            "last_seen": TS,
            "protocol": _text(16),
            "evidence_refs": [_text(64)] * 50,
            "attributes": {f"{i:02d}" + _text(62): _text(255) for i in range(20)},
        }
    )


def _max_records() -> dict[str, BaseModel]:
    return {
        "image": MemoryImageRecord(
            size_bytes=MAX_COUNT,
            sha256="b" * 64,
            layer=_text(64),
            arch="x64",
            nt_build=_text(64),
            pdb=WindowsPdb(name="ntkrnlmp.pdb", guid="F" * 32, age=65535),
            system_time=TS,
        ),
        "process": MemoryProcessRecord(
            pid=2**32 - 1,
            ppid=2**32 - 1,
            name=_text(64),
            offset=MAX_ADDRESS,
            create_time=TS,
            exit_time=TS,
            threads=MAX_COUNT,
            handles=MAX_COUNT,
            session_id=2**32 - 1,
            wow64=False,
            sources=["pslist", "psscan", "pstree"],
            cmdline=_text(4096),
            image_path=_text(1024),
        ),
        "connection": MemoryConnectionRecord.model_validate(
            {
                "proto": "other",
                "local_addr": V6,
                "local_port": 65535,
                "remote_addr": V6,
                "remote_port": 65535,
                "state": _text(16),
                "pid": 2**32 - 1,
                "owner": _text(64),
                "created": TS,
                "offset": MAX_ADDRESS,
            }
        ),
        "injection": MemoryInjectionRecord(
            pid=2**32 - 1,
            process=_text(64),
            start=MAX_ADDRESS,
            end=MAX_ADDRESS,
            protection=_text(64),
            tag=_text(16),
            private=False,
            commit_charge=MAX_COUNT,
            has_pe=True,
            head_hex="f" * 128,
            disasm=_text(1024),
        ),
        "artifact": _max_artifact(),
        "finding": _max_finding(),
        "ioc": IocRecord(
            type="registry_key",
            value=_text(2048),
            first_seen=TS,
            last_seen=TS,
            count=MAX_COUNT,
            source=_text(16),
        ),
        "timeline": MemoryTimelineEvent.model_validate(
            {
                "ts": TS,
                "event": "process_start",
                "title": _text(255),
                "severity": "medium",
                "ref": _text(64),
                "pid": 2**32 - 1,
                "remote_ip": V6,
            }
        ),
    }


def test_a_result_at_every_cap_fits_the_memory_bounds() -> None:
    """RT9: printable text at every length cap, every count at its cap, must fit the ingest's
    own decompressed and line bounds (the analyzer serializes with `model_dump_json`)."""
    settings = get_settings()
    caps = stream.Caps.from_settings(settings)
    sizes = {kind: len(pr.line(record)) for kind, record in _max_records().items()}
    assert max(sizes.values()) <= MAX_LINE_BYTES
    header = len(pr.line(_max_header()))
    trailer = len(pr.line({"kind": "trailer", "line_count": caps.max_lines, "sha256": "0" * 64}))
    total = header + trailer + sum(caps.per_kind[kind] * size for kind, size in sizes.items())
    assert total <= caps.max_decompressed_bytes, f"{total} > {caps.max_decompressed_bytes}"
    lines = 2 + sum(caps.per_kind.values())
    assert lines == caps.max_lines
    # The job summary of a header at its caps still fits its 32 KiB budget.
    full = stream.Validated(_max_header(), None)
    assert memory_ingest.build_summary(full, EXPECTED)["counts"]["processes"] == 0


def _realistic_lines(caps: stream.Caps) -> list[bytes]:
    """A plausible triage result with every count at its cap (paths, command lines and
    module lists as an image really holds them)."""
    header = _windows()[0]
    image = _windows()[_image_index(_windows())]
    out = [mr.dumps(header), mr.dumps(image)]
    per = caps.per_kind
    for i in range(per["process"]):
        out.append(
            mr.dumps(
                {
                    "kind": "process",
                    "pid": 4 * i + 8,
                    "ppid": 4 * (i // 8) + 8,
                    "name": f"svchost{i % 50}.exe",
                    "offset": 0xFFFF_A000_0000_0000 + 4096 * i,
                    "create_time": "2026-11-01T08:00:00Z",
                    "threads": 12,
                    "handles": 340,
                    "session_id": 0,
                    "wow64": False,
                    "sources": ["pslist", "psscan"],
                    "cmdline": f"C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Svc{i} "
                    + " ".join(f"/arg{j}:value{i % 97}" for j in range(8)),
                    "image_path": "C:\\Windows\\System32\\svchost.exe",
                }
            )
        )
    for i in range(per["connection"]):
        out.append(
            mr.dumps(
                {
                    "kind": "connection",
                    "proto": "tcp",
                    "local_addr": "10.0.0.5",
                    "local_port": 49152 + i % 16000,
                    "remote_addr": f"198.51.100.{i % 250 + 1}",
                    "remote_port": 443,
                    "state": "ESTABLISHED",
                    "pid": 4 * (i % per["process"]) + 8,
                    "owner": "svchost.exe",
                    "offset": 0xFFFF_B000_0000_0000 + 512 * i,
                }
            )
        )
    for i in range(per["injection"]):
        out.append(
            mr.dumps(
                {
                    "kind": "injection",
                    "pid": 4 * (i % per["process"]) + 8,
                    "process": "svchost.exe",
                    "start": 0x7FF0_0000_0000 + 0x10000 * i,
                    "end": 0x7FF0_0000_0000 + 0x10000 * i + 0xFFFF,
                    "protection": "PAGE_EXECUTE_READWRITE",
                    "tag": "VadS",
                    "private": True,
                    "commit_charge": 16,
                    "head_hex": "4d5a90000300000004000000ffff0000" * 4,
                    "disasm": "0x0: dec ebp\n0x1: pop edx\n0x2: nop\n" * 10,
                }
            )
        )
    for i in range(per["artifact"]):
        out.append(
            mr.dumps(
                {
                    "kind": "artifact",
                    "type": "module",
                    "pid": 4 * (i % per["process"]) + 8,
                    "attributes": {
                        "base": 0x7FF8_0000_0000 + 0x10000 * i,
                        "size": 0x2A000,
                        "name": f"module{i % 400}.dll",
                        "path": f"C:\\Windows\\System32\\module{i % 400}.dll",
                    },
                }
            )
        )
    for i in range(per["finding"]):
        out.append(
            mr.dumps(
                {
                    "kind": "finding",
                    "finding_id": str(uuid.UUID(int=i + 1)),
                    "ts": "2026-11-01T09:30:00Z",
                    "type": "mem_injected_code",
                    "title": "Private executable region with a PE header",
                    "description": f"pid {4 * i + 8}: PAGE_EXECUTE_READWRITE region at 0x7ff0",
                    "severity": "medium",
                    "confidence": 0.6,
                    "detection_method": "heuristic:mem_injected_code@1",
                    "evidence_refs": [f"pid:{4 * i + 8}"],
                    "attributes": {"pid": 4 * i + 8},
                }
            )
        )
    for i in range(per["ioc"]):
        out.append(
            mr.dumps(
                {
                    "kind": "ioc",
                    "type": "ip",
                    "value": f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}",
                    "first_seen": "2026-11-01T09:00:00Z",
                    "last_seen": "2026-11-01T09:00:00Z",
                    "count": 1,
                    "source": "connection",
                }
            )
        )
    for i in range(per["timeline"]):
        out.append(
            mr.dumps(
                {
                    "kind": "timeline",
                    "ts": "2026-11-01T09:00:00Z",
                    "event": "process_start",
                    "title": f"svchost{i % 50}.exe started",
                    "pid": 4 * (i % per["process"]) + 8,
                }
            )
        )
    return out


def test_a_plausible_result_at_every_count_cap_fits_the_upload_cap(tmp_path: Path) -> None:
    """RT9: every count at its cap, gzipped, stays under the 256 MiB result upload cap and
    validates whole. (Incompressible text at every length cap would not fit 256 MiB: the
    analyzer then fails `result_too_large` before uploading; the ingest bound above holds.)"""
    settings = get_settings()
    caps = stream.Caps.from_settings(settings)
    data = pr.encode(_realistic_lines(caps))
    assert len(data) <= settings.memory_max_result_bytes
    result = stream.validate(_write(tmp_path, data), _facts(), EXPECTED, caps)
    assert dict(result.counts) == caps.per_kind
    assert result.orphan_refs == 0
    assert sum(1 for _ in stream.records(tmp_path / "result.ndjson.gz", caps)) == (
        sum(caps.per_kind.values()) - 1
    )
