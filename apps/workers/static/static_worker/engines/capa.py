"""capa (`capa -j`) as the tool uid: capability rule matches with ATT&CK / MBC ids.

Called by absolute path (the kit scrubs PATH) with XDG_CACHE_HOME pointing at the read-only
rule cache precomputed at build time. capa's JSON document (up to tens of MiB) is reduced
to `capability` lines by the `capa` probe mode, as the tool uid: root never parses it, it
only reads bounded, contract-validated lines. Library rules (`lib: true`) are internal
building blocks and are not reported, like capa's own default rendering.
"""

from pathlib import Path

from cyberlab_jobs.static import CapabilityRecord
from cyberlab_worker import sandbox

from static_worker.config import Engines
from static_worker.engines.probes import run_probe
from static_worker.engines.workspace import Budget, Workspace

MEMORY = 2 * 1024**3
OUTPUT = "capa.json"
# The reducer holds the parsed document (Python objects: ~10x the JSON size).
REDUCER_MEMORY = 2 * 1024**3
REDUCER_S = 60


def argv(engines: Engines, sample: Path) -> list[str]:
    return [
        engines.capa, "-j", "-r", str(engines.capa_rules), "-s", str(engines.capa_sigs),
        "--", str(sample),
    ]  # fmt: skip


def run(
    ws: Workspace,
    engines: Engines,
    seconds: float,
    *,
    budget: Budget,
    limit: int,
    errors: list[str],
    truncated: dict[str, bool],
) -> list[CapabilityRecord]:
    dirs = ws.engine("capa")
    try:
        sandbox.run_tool(
            argv(engines, ws.sample),
            dirs,
            timeout_s=seconds,
            stdout_name=OUTPUT,
            extra_env={"XDG_CACHE_HOME": str(engines.capa_cache or dirs.out)},
            memory_bytes=MEMORY,
        )
    except sandbox.ToolTimeout:
        errors.append("capa_timeout")
        return []
    except sandbox.ToolFailed:
        errors.append("capa_failed")
        return []
    reducer_s = budget.tool(REDUCER_S)
    if reducer_s is None:
        errors.append("capa_skipped")
        return []
    return parse(ws, engines, dirs, reducer_s, limit=limit, errors=errors, truncated=truncated)


def parse(
    ws: Workspace,
    engines: Engines,
    source: sandbox.JobDirs,
    seconds: float = REDUCER_S,
    *,
    limit: int,
    errors: list[str],
    truncated: dict[str, bool],
) -> list[CapabilityRecord]:
    """Reduce `source.out/capa.json` in the `capa` probe; accept its validated lines."""
    run = run_probe(
        ws, engines, "capa", ["--max-records", str(limit)], seconds=seconds,
        max_lines=limit + 10, errors=errors, truncated=truncated,
        target=source.out / OUTPUT, memory_bytes=REDUCER_MEMORY,
    )  # fmt: skip
    records = [r for r in run.records() if isinstance(r, CapabilityRecord)]
    if len(records) > limit:
        truncated["capabilities"] = True
    return records[:limit]
