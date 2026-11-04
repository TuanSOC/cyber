"""FLOSS (`floss --only decoded stack tight -j`) as the tool uid: emulated string recovery.

Static strings come from our own `strings` probe; FLOSS adds what only exists at run time
(stack / tight / decoded strings). FLOSS emulates code, so it runs last (RT5) and only for
small PEs (RT4). Its JSON document is reduced to `string` lines by the `floss` probe mode
(tool uid); root only reads bounded, contract-validated lines.
"""

from pathlib import Path

from cyberlab_jobs.static import StringRecord
from cyberlab_worker import sandbox

from static_worker.config import Engines
from static_worker.engines.probes import run_probe
from static_worker.engines.workspace import Budget, Workspace

MEMORY = 2 * 1024**3
OUTPUT = "floss.json"
MIN_LENGTH = 6
REDUCER_MEMORY = 2 * 1024**3
REDUCER_S = 60
FLOSS_ENCODINGS = {"floss_decoded", "floss_stack", "floss_tight"}


def argv(engines: Engines, sample: Path) -> list[str]:
    return [
        engines.floss, "-q", "-j", "-n", str(MIN_LENGTH), "--only", "decoded", "stack", "tight",
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
) -> list[StringRecord]:
    dirs = ws.engine("floss")
    try:
        sandbox.run_tool(
            argv(engines, ws.sample),
            dirs,
            timeout_s=seconds,
            stdout_name=OUTPUT,
            memory_bytes=MEMORY,
        )
    except sandbox.ToolTimeout:
        errors.append("floss_timeout")
        return []
    except sandbox.ToolFailed:
        errors.append("floss_failed")
        return []
    reducer_s = budget.tool(REDUCER_S)
    if reducer_s is None:
        errors.append("floss_skipped")
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
) -> list[StringRecord]:
    """Reduce `source.out/floss.json` in the `floss` probe; accept its validated lines."""
    run = run_probe(
        ws, engines, "floss", ["--max-records", str(limit)], seconds=seconds,
        max_lines=limit + 10, errors=errors, truncated=truncated,
        target=source.out / OUTPUT, memory_bytes=REDUCER_MEMORY,
    )  # fmt: skip
    records: list[StringRecord] = []
    seen: set[tuple[str, str]] = set()
    for record in run.records():
        if not isinstance(record, StringRecord) or record.encoding not in FLOSS_ENCODINGS:
            continue
        if len(record.value) < MIN_LENGTH or (record.value, record.encoding) in seen:
            continue
        if len(records) >= limit:
            truncated["strings"] = True
            break
        seen.add((record.value, record.encoding))
        records.append(record)
    return records
