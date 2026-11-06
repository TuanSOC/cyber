"""`memory.v1` contract (M8 phase 1, frozen): the valid fixtures round-trip, every hostile one
is refused, the plugin allow-list holds exactly the plan's names, and a stream at every cap
fits the framing bounds (RT9).

Pure Python (pydantic only): also runs on a host without the API's dependencies:

  cd apps/api && PYTHONPATH=../../packages/py-jobs/src python -m pytest -p no:cacheprovider \
      --noconftest tests/unit/test_memory_contract.py
"""

import hashlib
import json
import uuid
from pathlib import Path

import cyberlab_jobs
import pytest
from cyberlab_jobs.memory import (
    ARTIFACT_TYPES,
    MAX_ATTRIBUTES_BYTES,
    MEMORY_LINE_ADAPTER,
    PLUGINS_BY_PROFILE,
    PROCESS_LIST_PLUGIN,
    LinuxBanner,
    MemoryArtifactRecord,
    MemoryJobV1,
    MemoryLimits,
    MemoryPlugin,
    MemoryProcessRecord,
    MemoryProfile,
    MemoryResultHeader,
    SymbolManifestV1,
    WindowsPdb,
    check_diagnostic_kinds,
)
from cyberlab_jobs.results import ResultTrailer
from pydantic import BaseModel, ValidationError

FIXTURES = Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures" / "memory"
HOSTILE = FIXTURES / "hostile"
JOBS = {
    "windows_triage.ndjson": uuid.UUID("6a1f0c1e-8d6b-4c55-9d9e-0d1b6f5a1001"),
    "linux_triage.ndjson": uuid.UUID("6a1f0c1e-8d6b-4c55-9d9e-0d1b6f5a1002"),
    "symbols_missing.ndjson": uuid.UUID("6a1f0c1e-8d6b-4c55-9d9e-0d1b6f5a1003"),
}


class StreamRefused(Exception):
    pass


def read_stream(path: Path, job_id: uuid.UUID) -> list[BaseModel]:
    """The contract-level framing rules (the ingest, phase 6, adds caps and identity)."""
    raw = path.read_bytes().splitlines(keepends=True)
    if len(raw) < 2:
        raise StreamRefused("too short")
    lines: list[BaseModel] = []
    digest = hashlib.sha256()
    for index, line in enumerate(raw):
        try:
            parsed = MEMORY_LINE_ADAPTER.validate_json(line)
        except ValidationError as exc:
            raise StreamRefused(f"line {index + 1} invalid") from exc
        is_last = index == len(raw) - 1
        if isinstance(parsed, ResultTrailer) != is_last:
            raise StreamRefused("the trailer is the last line, exactly once")
        if isinstance(parsed, MemoryResultHeader) != (index == 0):
            raise StreamRefused("the header is the first line, exactly once")
        if not is_last:
            digest.update(line)
        lines.append(parsed)
    header, trailer = lines[0], lines[-1]
    assert isinstance(header, MemoryResultHeader) and isinstance(trailer, ResultTrailer)
    if header.job_id != job_id:
        raise StreamRefused("the header names another job")
    if trailer.line_count != len(lines) - 1 or trailer.sha256 != digest.hexdigest():
        raise StreamRefused("trailer mismatch")
    if header.symbols.status == "missing":
        try:
            check_diagnostic_kinds(getattr(line, "kind") for line in lines)  # noqa: B009
        except ValueError as exc:
            raise StreamRefused(str(exc)) from exc
    return lines


@pytest.mark.parametrize("name", sorted(JOBS))
def test_valid_fixtures_round_trip(name: str) -> None:
    lines = read_stream(FIXTURES / name, JOBS[name])
    for model, raw in zip(lines, (FIXTURES / name).read_bytes().splitlines(), strict=True):
        again = MEMORY_LINE_ADAPTER.validate_json(model.model_dump_json())
        assert again == model
        assert json.loads(raw)["kind"] == getattr(model, "kind")  # noqa: B009
    header = lines[0]
    assert isinstance(header, MemoryResultHeader)
    assert header.engine == "replay"  # every fixture is labelled synthetic
    assert "synthetic" in header.tool_versions["fixture"]


def test_windows_fixture_covers_every_windows_shape() -> None:
    lines = read_stream(FIXTURES / "windows_triage.ndjson", JOBS["windows_triage.ndjson"])
    kinds = [getattr(line, "kind") for line in lines]  # noqa: B009
    assert kinds.count("process") >= 40
    assert {"image", "connection", "injection", "artifact", "finding", "ioc", "timeline"} <= set(
        kinds
    )
    artifacts = [line for line in lines if isinstance(line, MemoryArtifactRecord)]
    windows_types = {"module", "service", "hive", "userassist", "ldr_unlinked"}
    assert {a.type for a in artifacts} == windows_types
    processes = [line for line in lines if isinstance(line, MemoryProcessRecord)]
    assert len([p for p in processes if p.sources == ["psscan"]]) == 1


def test_symbols_missing_fixture_is_a_diagnostic_stream() -> None:
    lines = read_stream(FIXTURES / "symbols_missing.ndjson", JOBS["symbols_missing.ndjson"])
    header = lines[0]
    assert isinstance(header, MemoryResultHeader)
    assert header.symbols.status == "missing"
    assert isinstance(header.symbols.required, WindowsPdb)
    assert header.plugins == []


HOSTILE_STREAMS = sorted(p.name for p in HOSTILE.glob("*.ndjson"))


def test_hostile_set_is_complete() -> None:
    assert {
        "wrong_job.ndjson",
        "nan.ndjson",
        "nul_char.ndjson",
        "oversize_cmdline.ndjson",
        "attributes_33.ndjson",
        "nested_attribute.ndjson",
        "extra_field.ndjson",
        "bad_guid.ndjson",
        "after_trailer.ndjson",
    } <= set(HOSTILE_STREAMS)


@pytest.mark.parametrize("name", HOSTILE_STREAMS)
def test_hostile_fixtures_are_refused(name: str) -> None:
    raw = (HOSTILE / name).read_bytes()
    job_id = uuid.UUID(json.loads(raw.splitlines()[0])["job_id"])
    if name == "wrong_job.ndjson":
        job_id = JOBS["windows_triage.ndjson"]
    with pytest.raises(StreamRefused):
        read_stream(HOSTILE / name, job_id)


def test_manifest_refuses_traversal_and_accepts_the_good_one() -> None:
    with pytest.raises(ValidationError):
        SymbolManifestV1.model_validate_json((HOSTILE / "manifest_dotdot.json").read_bytes())
    manifest = SymbolManifestV1.model_validate_json((FIXTURES / "manifest.json").read_bytes())
    assert manifest.files[0].os == "windows"
    for bad in ("/etc/passwd", "a//b", "./a", "a/../b", "a\\b", "x" * 256):
        data = json.loads((FIXTURES / "manifest.json").read_bytes())
        data["files"][0]["path"] = bad
        with pytest.raises(ValidationError):
            SymbolManifestV1.model_validate(data)


def test_plugin_allow_list_is_exactly_the_plan() -> None:
    names = {p.value for p in MemoryPlugin}
    assert len(names) == 19
    forbidden = (
        "windows.handles",
        "windows.vadyarascan",
        "yarascan.YaraScan",
        "linux.vmayarascan",
        "windows.registry.hashdump",
        "windows.hashdump",
        "windows.lsadump",
        "windows.cachedump",
        "windows.envars",
        "windows.dumpfiles",
        "windows.memmap",
        "windows.registry.printkey",
        "linux.pagecache.Files",
        "windows.malfind",  # the deprecated shim name
        "windows.ldrmodules",
    )
    assert names.isdisjoint(forbidden)
    assert not [n for n in names if "yara" in n or "dump" in n or "pagecache" in n]
    for (os_name, profile), plugins in PLUGINS_BY_PROFILE.items():
        assert all(p.value.startswith(f"{os_name}.") for p in plugins)
        assert len(set(plugins)) == len(plugins)
        assert PROCESS_LIST_PLUGIN[os_name] in plugins
        if profile is MemoryProfile.FULL:
            assert set(PLUGINS_BY_PROFILE[(os_name, MemoryProfile.TRIAGE)]) < set(plugins)
    assert set().union(*PLUGINS_BY_PROFILE.values()) == set(MemoryPlugin)
    assert set(ARTIFACT_TYPES) == {
        "module",
        "service",
        "hive",
        "userassist",
        "ldr_unlinked",
        "bash",
        "open_file",
        "syscall_hook",
        "hidden_module",
    }


def _limits(**overrides: int) -> MemoryLimits:
    values = {
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
    values.update(overrides)
    return MemoryLimits.model_validate(values)


def test_artifact_attributes_fit_the_column() -> None:
    MemoryArtifactRecord(type="module", attributes={f"k{i}": "x" * 100 for i in range(32)})
    with pytest.raises(ValidationError):
        MemoryArtifactRecord(type="module", attributes={f"k{i}": "x" * 1000 for i in range(5)})


def test_limits_bounds() -> None:
    limits = _limits()
    assert limits.max_lines() == 3 + 155_000
    for name, value in (
        ("max_bytes", 16 * 1024**3 + 1),
        ("max_processes", 20_001),
        ("max_artifacts", 50_001),
        ("max_timeline", 5_001),
        ("max_result_bytes", 256 * 1024**2 + 1),
        ("tool_timeout_s", 5400),
        ("identify_timeout_s", 5400),
    ):
        with pytest.raises(ValidationError):
            _limits(**{name: value})


def test_kernel_identities_are_strict() -> None:
    WindowsPdb(name="ntoskrnl.pdb", guid="A" * 32, age=65_535)
    for bad in (
        {"name": "ntkrnlmp.pdb", "guid": "a" * 32, "age": 1},  # lowercase hex
        {"name": "ntkrnlmp.pdb", "guid": "A" * 31, "age": 1},
        {"name": "ntkrnlmp.pdb", "guid": "A" * 32, "age": 65_536},
        {"name": "kernel32.pdb", "guid": "A" * 32, "age": 1},
        {"name": "../ntkrnlmp.pdb", "guid": "A" * 32, "age": 1},
    ):
        with pytest.raises(ValidationError):
            WindowsPdb.model_validate(bad)
    LinuxBanner(banner="Linux version 6.1.0 (x@y) #1 SMP")
    for banner in ("", "a\nb", "a\x1bb", "é", "x" * 513):
        with pytest.raises(ValidationError):
            LinuxBanner(banner=banner)


def test_job_message_round_trips() -> None:
    message = MemoryJobV1.model_validate(
        {
            "job_id": uuid.uuid4(),
            "organization_id": uuid.uuid4(),
            "evidence_id": uuid.uuid4(),
            "expected_sha256": "a" * 64,
            "size_bytes": 1024,
            "evidence_url": "http://minio:9000/evidence/x?X-Amz-Signature=1",
            "result_post": {"url": "http://minio:9000/analysis-results", "fields": {"key": "k"}},
            "ingest_token": "t" * 43,
            "profile": "triage",
            "os_hint": "auto",
            "limits": _limits().model_dump(),
        }
    )
    assert MemoryJobV1.model_validate_json(message.model_dump_json()) == message
    with pytest.raises(ValidationError):
        MemoryJobV1.model_validate({**message.model_dump(), "profile": "av"})
    with pytest.raises(ValidationError):
        MemoryJobV1.model_validate({**message.model_dump(), "plugins": ["windows.handles"]})


def test_a_stream_at_every_cap_fits_the_framing_bounds() -> None:
    """RT9: the worst-case line count and a conservative per-line size estimate stay inside
    MEMORY_MAX_RESULT_DECOMPRESSED_BYTES (1 GiB) and the line bound the ingest passes."""
    limits = _limits()
    decompressed_cap = 1024**3
    # Largest legal line per kind (artifact attributes: <= 4 KiB, MAX_ATTRIBUTES_BYTES).
    worst = {
        "process": 4096 + 1024 + 600,
        "connection": 400,
        "injection": 1024 + 128 + 400,
        "artifact": MAX_ATTRIBUTES_BYTES + 100,
        "finding": 255 + 2048 + 20 * 300 + 50 * 70 + 600,
        "ioc": 2048 + 300,
        "timeline": 255 + 300,
    }
    caps = {
        "process": limits.max_processes,
        "connection": limits.max_connections,
        "injection": limits.max_injections,
        "artifact": limits.max_artifacts,
        "finding": limits.max_findings,
        "ioc": limits.max_iocs,
        "timeline": limits.max_timeline,
    }
    total = sum(worst[k] * caps[k] for k in caps) + 64 * 1024
    assert total < decompressed_cap
    assert limits.max_lines() < 400_000
