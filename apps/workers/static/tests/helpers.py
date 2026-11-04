"""Shared test helpers: limits, test engine configuration, ingest-style stream parsing."""

import gzip
import hashlib
import shutil
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any

from cyberlab_jobs.results import ResultTrailer
from cyberlab_jobs.static import (
    STATIC_LINE_ADAPTER,
    Profile,
    StaticLimits,
    StaticResultHeader,
)
from cyberlab_worker import sandbox

from static_worker import analyzer
from static_worker.config import Engines
from static_worker.engines.workspace import Budget
from tests.conftest import CAPA_TEST_RULES, CLAMAV_TEST_DB, WORK, YARA_TEST_RULES

LIMITS = StaticLimits(
    max_bytes=64 * 1024**2,
    timeout_s=900,
    tool_timeout_s=300,
    max_sections=1_000,
    max_imports=10_000,
    max_exports=10_000,
    max_resources=1_000,
    max_strings=5_000,
    max_signature_matches=100,
    max_capabilities=500,
    max_findings=500,
    max_iocs=1_000,
    max_result_bytes=64 * 1024**2,
)
# Small custom ClamAV DB (EICAR hash + test marker), test YARA rules, no capa / FLOSS unless a
# test opts in (they cost 10-40 s per sample). One test covers the full ClamAV DB.
FAST = Engines(
    clamav_db=CLAMAV_TEST_DB,
    yara_test_rules=YARA_TEST_RULES,
    capa_enabled=False,
    floss_enabled=False,
)
WITH_CAPA_FIXTURE = replace(FAST, capa_enabled=True, capa_rules=CAPA_TEST_RULES, capa_cache=None)


def place(dirs: sandbox.JobDirs, source: Path | bytes) -> Path:
    """Put a sample into the job's root-owned input dir, read-only (as the download does)."""
    sample = dirs.input / "sample"
    if sample.exists():
        sample.chmod(0o644)
        sample.unlink()
    if isinstance(source, bytes):
        sample.write_bytes(source)
    else:
        shutil.copyfile(source, sample)
    sample.chmod(0o444)
    return sample


def fresh_dirs(name: str) -> sandbox.JobDirs:
    return sandbox.prepare(WORK, f"{name}-{uuid.uuid4().hex[:8]}")


def analyze(
    source: Path | bytes,
    *,
    profile: Profile = Profile.FULL,
    limits: StaticLimits = LIMITS,
    engines: Engines = FAST,
) -> dict[str, Any]:
    dirs = fresh_dirs("t")
    try:
        place(dirs, source)
        result = analyzer.analyze_file(dirs, uuid.uuid4(), profile, limits, Budget(limits), engines)
        return parse(result)
    finally:
        sandbox.cleanup(dirs)


def parse(path: Path) -> dict[str, Any]:
    """Validate the stream as ingest will: header first, trailer last and correct."""
    lines = gzip.decompress(path.read_bytes()).splitlines(keepends=True)
    header = StaticResultHeader.model_validate_json(lines[0])
    trailer = ResultTrailer.model_validate_json(lines[-1])
    assert trailer.line_count == len(lines) - 1
    assert trailer.sha256 == hashlib.sha256(b"".join(lines[:-1])).hexdigest()
    by_kind: dict[str, list[Any]] = {}
    for line in lines[1:-1]:
        record = STATIC_LINE_ADAPTER.validate_json(line)
        assert record.kind not in {"header", "trailer"}
        by_kind.setdefault(record.kind, []).append(record)
    assert len(by_kind.get("sample", [])) == 1
    return {"header": header, **by_kind}


def names(out: dict[str, Any], engine: str) -> list[str]:
    return [m.name for m in out.get("signature_match", []) if m.engine == engine]


def findings(out: dict[str, Any], kind: str | None = None) -> list[Any]:
    return [f for f in out.get("finding", []) if kind is None or f.type == kind]
