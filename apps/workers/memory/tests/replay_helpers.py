"""Pure helpers over the replay row fixtures (`tests/fixtures/vol_rows/`; no sandbox, no
Volatility): run the root-side pipeline (identify choice, bounded reads, normalizers,
detections, stream writer) on a scenario directory, as the replay engine would feed it."""

import gzip
import io
import json
import uuid
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

import cyberlab_jobs
from cyberlab_jobs.memory import (
    MEMORY_LINE_ADAPTER,
    PLUGINS_BY_PROFILE,
    MemoryLimits,
    MemoryPlugin,
    MemoryProfile,
    OsHint,
)

from memory_worker.identify import IdentifyRecord, choose
from memory_worker.normalize import Normalized, normalize
from memory_worker.normalize.reader import RowSource, RowStats, read_rows
from memory_worker.result import PluginOutcome, RunFacts, assemble, image_record

VOL_ROWS = Path(__file__).parent / "fixtures" / "vol_rows"
# The phase-1 `memory.v1` contract fixtures (same path as conftest.CONTRACT_FIXTURES, which
# imports the sandbox and so cannot load on a host without `resource`).
CONTRACT_FIXTURES = (
    Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures" / "memory"
)
LIMITS = MemoryLimits(
    max_bytes=8 * 1024**3,
    timeout_s=5400,
    identify_timeout_s=600,
    tool_timeout_s=1200,
    max_processes=20_000,
    max_connections=50_000,
    max_injections=5_000,
    max_artifacts=50_000,
    max_findings=5_000,
    max_iocs=20_000,
    max_timeline=5_000,
    max_result_bytes=256 * 1024**2,
)
IMAGE_SHA = "b" * 64


def fixture_rows(scenario: str, plugin: MemoryPlugin) -> list[dict[str, Any]]:
    path = VOL_ROWS / scenario / f"{plugin.value}.jsonl"
    if not path.is_file():
        return []
    return list(read_rows(io.BytesIO(path.read_bytes()), 1_000_000, RowStats()))


def scenario_rows(scenario: str) -> dict[MemoryPlugin, list[dict[str, Any]]]:
    return {p: fixture_rows(scenario, p) for p in MemoryPlugin}


def normalized(
    os: str,
    rows: Mapping[MemoryPlugin, Iterable[Mapping[str, Any]]],
    limits: MemoryLimits = LIMITS,
) -> Normalized:
    return normalize(os, rows, limits)  # type: ignore[arg-type]


def run_scenario(
    scenario: str,
    profile: str,
    out: Path,
    *,
    limits: MemoryLimits = LIMITS,
    mutate: Callable[[MemoryPlugin, bytes], bytes] | None = None,
) -> list[Any]:
    """Every root-side step after the probes, on a fixture scenario; returns the stream's
    validated lines (header first, trailer last)."""
    record = IdentifyRecord.model_validate(
        json.loads((VOL_ROWS / scenario / "identify.json").read_text())
    )
    identified = choose(record, OsHint.AUTO)
    facts = RunFacts(
        job_id=uuid.uuid4(),
        profile=MemoryProfile(profile),
        os=identified.os,
        engine="replay",
        tool_versions={"replay": "fixture"},
        image=image_record(identified, 4096, IMAGE_SHA),
        isf_sha256="c" * 64,
    )
    outcomes: list[PluginOutcome] = []
    rows: dict[MemoryPlugin, RowSource] = {}
    for plugin in PLUGINS_BY_PROFILE[(identified.os, MemoryProfile(profile))]:
        outcome = PluginOutcome(plugin=plugin, status="ok")
        outcomes.append(outcome)
        path = VOL_ROWS / scenario / f"{plugin.value}.jsonl"
        data = path.read_bytes() if path.is_file() else b""
        if mutate is not None:
            data = mutate(plugin, data)
        rows[plugin] = RowSource(lambda data=data: io.BytesIO(data), 50_000, outcome.counted)
    assemble(out, facts, outcomes, rows, limits)
    return [MEMORY_LINE_ADAPTER.validate_json(line) for line in gzip.open(out).read().splitlines()]


def kinds(lines: list[Any]) -> Counter[str]:
    return Counter(line.kind for line in lines)


def artifact_types(lines: list[Any]) -> Counter[str]:
    return Counter(line.type for line in lines if line.kind == "artifact")


def contract_fixture_counts(name: str) -> tuple[Counter[str], Counter[str]]:
    """Record kinds and artifact types of a phase-1 contract fixture."""
    lines = [json.loads(line) for line in (CONTRACT_FIXTURES / name).read_text().splitlines()]
    return (
        Counter(line["kind"] for line in lines),
        Counter(line["type"] for line in lines if line["kind"] == "artifact"),
    )
