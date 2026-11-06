"""capa (`capa -j`) as the tool uid: capability rule matches with ATT&CK / MBC ids.

Called by absolute path (the kit scrubs PATH) with XDG_CACHE_HOME pointing at the read-only
rule cache precomputed at build time. capa's JSON document (up to tens of MiB) is reduced
to `capability` lines by the `capa` probe mode, as the tool uid: root never parses it, it
only reads bounded, contract-validated lines. Library rules (`lib: true`) are internal
building blocks and are not reported, like capa's own default rendering.

M10 phase 6: the capability lines carry capa's absolute match locations, and the reducer's
one `capa_meta` line hands root the base address capa analysed the file at (validated here
as an unsigned 64-bit integer, else ignored) for `StaticResultHeader.capa_base_address`.
"""

from dataclasses import dataclass
from pathlib import Path

from cyberlab_jobs.static import CapabilityRecord
from cyberlab_worker import sandbox
from cyberlab_worker.parsing import RECORD_ERRORS, count

from static_worker.config import Engines
from static_worker.engines.probes import run_probe
from static_worker.engines.workspace import Budget, Workspace

MEMORY = 2 * 1024**3
OUTPUT = "capa.json"
# The reducer holds the parsed document (Python objects: ~10x the JSON size).
REDUCER_MEMORY = 2 * 1024**3
REDUCER_S = 60
# The reducer's side line (probe.reduce.CAPA_META): never a contract record.
META_KIND = "capa_meta"


@dataclass
class CapaMeta:
    """What the reducer reported besides the capability lines (M10 phase 6).

    `base_address`: capa's `meta.analysis.base_address` (absolute), None when capa did not
    report one; `dropped_locations`: match addresses of other kinds (relative, file, no
    address, ...) that were not kept."""

    base_address: int | None = None
    dropped_locations: int = 0


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
    meta: CapaMeta | None = None,
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
    return parse(
        ws, engines, dirs, reducer_s, limit=limit, errors=errors, truncated=truncated, meta=meta
    )


def read_meta(item: dict[str, object], meta: CapaMeta) -> None:
    """The reducer's `capa_meta` line, field by field (an out-of-range base is ignored)."""
    base = item.get("base_address")
    if isinstance(base, int) and not isinstance(base, bool) and 0 <= base < 2**64:
        meta.base_address = base
    meta.dropped_locations = count(item.get("dropped_locations"))


def parse(
    ws: Workspace,
    engines: Engines,
    source: sandbox.JobDirs,
    seconds: float = REDUCER_S,
    *,
    limit: int,
    errors: list[str],
    truncated: dict[str, bool],
    meta: CapaMeta | None = None,
) -> list[CapabilityRecord]:
    """Reduce `source.out/capa.json` in the `capa` probe; accept its validated lines (and
    its `capa_meta` line into `meta`)."""
    run = run_probe(
        ws, engines, "capa", ["--max-records", str(limit)], seconds=seconds,
        max_lines=limit + 10, errors=errors, truncated=truncated,
        target=source.out / OUTPUT, memory_bytes=REDUCER_MEMORY,
    )  # fmt: skip
    records: list[CapabilityRecord] = []
    for item in run.lines():
        kind = item.get("kind")
        if kind == META_KIND:
            if meta is not None:
                read_meta(item, meta)
            continue
        if kind != "capability":
            run.skipped += 1
            continue
        try:
            record = CapabilityRecord.model_validate(item)
            record.model_dump_json()  # serializable (no lone surrogates etc.)
        except RECORD_ERRORS:
            run.skipped += 1
            continue
        records.append(record)
    if len(records) > limit:
        truncated["capabilities"] = True
    return records[:limit]
