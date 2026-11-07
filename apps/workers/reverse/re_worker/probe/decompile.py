"""Stage `decompile` (tool uid, a second JVM with a smaller heap; M10 phase 2; RT4, RT15, RT16).

    python -I -s -B -m re_worker.probe decompile --project P --out O --heap N --list L

`--list` is root's `stage/decompile_list.json` (root-owned 0444 in a root-owned dir, RT23):
the function entries in priority order (ints formatted by root from validated records), the
per-function timeout, the stage deadline, the code caps and the decompiler child's address
space limit. The probe:
- starts the JVM (`RE_DECOMPILE_JVM_HEAP`), reports its arguments, installs the audit hook;
- re-opens the saved project and the program **without saving** (read-only domain object;
  the project dir stays tool-writable for Ghidra's lock file, RT23);
- one `DecompInterface` with simplification style `decompile` and fixed `DecompileOptions`:
  every comment kind off (PLATE, PRE, POST, EOL, header: RTTI / demangled plate comments
  carry attacker text, RT16), warnings kept; a switch that cannot be set fails the stage;
- after every (re)spawn of the native decompiler and after every function, records the
  children and lowers a new decompiler's RLIMIT_AS (`children.py`, RT4 / RT15); a function
  whose child died is `failed` and the interface is reopened, at most `max_restarts` times,
  then the rest is `skipped_budget`;
- writes one `decompiled` row per listed entry, in order: `ok` / `truncated` (cut on a line
  boundary at `max_code_bytes` with the marker), `timeout`, `failed`, or `skipped_budget`
  once the deadline or the code budget is reached; `dispose()` in `finally`.
"""

import argparse
import json
import time
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

from cyberlab_jobs.reverse import (
    MAX_CODE_BYTES,
    MAX_CODE_TOTAL_BYTES,
    CodeKind,
    DecompileStatus,
)
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from re_worker import jvm_args
from re_worker.normalize.decompiled import record_for
from re_worker.probe.analyze import PROGRAM, PROJECT
from re_worker.probe.children import Children
from re_worker.probe.guard import GUARD
from re_worker.probe.launcher import DECOMPILER, SPAWN_HELPER, start
from re_worker.probe.out import RowWriter, StageFailure, text

MAX_LIST_BYTES = 256 * 1024
MAX_LIST_ENTRIES = 2000  # = CAP_DECOMPILED
MAX_CODE_CHARS = 4 * 1024 * 1024  # before the byte cut (NUL and lone surrogates removed)
COMMENT_SWITCHES = (
    ("setPLATEinclude", "setPLATEInclude"),
    ("setPREinclude", "setPREInclude"),
    ("setPOSTinclude", "setPOSTInclude"),
    ("setEOLinclude", "setEOLInclude"),
    ("setHeadComment", "setHeadCommentInclude"),
)


class DecompileList(BaseModel):
    """Root's hand-off file (validated again here: the probe trusts nothing it reads)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entries: list[StrictInt] = Field(max_length=MAX_LIST_ENTRIES)
    timeout_s: StrictInt = Field(gt=0, le=600)
    deadline_s: StrictInt = Field(gt=0)
    max_code_bytes: StrictInt = Field(gt=0, le=MAX_CODE_BYTES)
    max_code_total_bytes: StrictInt = Field(gt=0, le=MAX_CODE_TOTAL_BYTES)
    decompiler_as: StrictInt = Field(gt=0)
    max_restarts: StrictInt = Field(ge=0, le=10)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--heap", type=int, required=True)
    parser.add_argument("--list", type=Path, required=True)


def caps(args: argparse.Namespace) -> dict[str, int]:
    del args
    return {"decompiled": MAX_LIST_ENTRIES}


def read_list(path: Path) -> DecompileList:
    with open(path, "rb") as f:
        data = f.read(MAX_LIST_BYTES + 1)
    if len(data) > MAX_LIST_BYTES:
        raise StageFailure("re_parse_failed", "decompile_list")
    return DecompileList.model_validate(json.loads(data))


def decompile_options() -> Any:
    from ghidra.app.decompiler import DecompileOptions

    options = DecompileOptions()
    for names in COMMENT_SWITCHES:
        for name in names:
            setter = getattr(options, name, None)
            if setter is not None:
                setter(False)
                break
        else:
            raise StageFailure("re_parse_failed", "decompiler_option")
    return options


def _open(program: Any) -> Any:
    from ghidra.app.decompiler import DecompInterface

    interface = DecompInterface()
    interface.setOptions(decompile_options())
    interface.setSimplificationStyle("decompile")
    if not interface.openProgram(program):
        interface.dispose()
        raise StageFailure("re_parse_failed", "decompiler_start")
    return interface


def _address(program: Any, entry: int) -> Any:
    if not 0 <= entry < 2**63:
        return None
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(entry)


def decompile_all(
    program: Any, listing: DecompileList, writer: RowWriter, status: dict[str, Any]
) -> None:
    from ghidra.util.task import TaskMonitor

    children = Children(
        decompiler=DECOMPILER.resolve(),
        spawn_helper=SPAWN_HELPER.resolve(),
        as_limit=listing.decompiler_as,
    )
    deadline = time.monotonic() + listing.deadline_s
    functions = program.getFunctionManager()
    statuses: Counter[str] = Counter()
    budget = listing.max_code_total_bytes
    restarts = 0
    monitor = TaskMonitor.DUMMY
    interface = _open(program)
    children.scan()
    try:
        for entry in listing.entries:
            started = time.monotonic()
            out_of_budget = started > deadline or budget <= 0 or restarts > listing.max_restarts
            if out_of_budget:
                record = record_for(
                    entry,
                    None,
                    DecompileStatus.SKIPPED_BUDGET,
                    CodeKind.PSEUDO_C,
                    max_bytes=listing.max_code_bytes,
                )
                writer.emit("decompiled", record.model_dump(mode="json", exclude={"kind"}))
                statuses[str(record.status)] += 1
                continue
            address = _address(program, entry)
            function = functions.getFunctionAt(address) if address is not None else None
            code: str | None = None
            outcome = DecompileStatus.FAILED
            if function is not None:
                results = interface.decompileFunction(function, listing.timeout_s, monitor)
                if results is not None and results.decompileCompleted():
                    decompiled = results.getDecompiledFunction()
                    code = text(decompiled.getC(), MAX_CODE_CHARS) if decompiled else None
                    outcome = DecompileStatus.OK if code is not None else DecompileStatus.FAILED
                elif results is not None and results.isTimedOut():
                    outcome = DecompileStatus.TIMEOUT
            if not children.scan():
                # No live decompiler: it was stopped at its timeout or died (its RLIMIT_AS,
                # RT4). Reopen now, so the next child is limited before it runs a function.
                if outcome == DecompileStatus.FAILED:
                    restarts += 1
                interface.dispose()
                if restarts <= listing.max_restarts:
                    interface = _open(program)
                    children.scan()
            duration = int((time.monotonic() - started) * 1000)
            record = record_for(
                entry,
                code,
                outcome,
                CodeKind.PSEUDO_C,
                max_bytes=listing.max_code_bytes,
                duration_ms=duration,
            )
            if record.code is not None:
                size = len(record.code.encode("utf-8"))
                if size > budget:  # the job's code budget: nothing more is kept
                    record = record_for(
                        entry,
                        None,
                        DecompileStatus.SKIPPED_BUDGET,
                        CodeKind.PSEUDO_C,
                        max_bytes=listing.max_code_bytes,
                        duration_ms=duration,
                    )
                    budget = 0
                else:
                    budget -= size
            writer.emit("decompiled", record.model_dump(mode="json", exclude={"kind"}))
            statuses[str(record.status)] += 1
    finally:
        interface.dispose()
        children.scan()
        status["children"] = sorted(set(children.seen.values()))[:32]
        status["child_counts"] = dict(children.counts)
        status["decompiler_limited"] = len(children.limited)
        status["decompiler_restarts"] = restarts
        status["counts"] = dict(statuses)


def run(args: argparse.Namespace, writer: RowWriter, status: dict[str, Any]) -> None:
    listing = read_list(args.list)
    out = PurePosixPath(str(args.out))
    status["jvm_args"] = start(jvm_args.stage_args(args.heap, out))
    status["jvm_started"] = True
    GUARD.install()  # RT1

    import pyghidra
    from ghidra.framework.model import DomainFile
    from ghidra.util.task import TaskMonitor
    from java.lang import Object

    with pyghidra.open_project(str(args.project), PROJECT, create=False) as project:
        domain_file = project.getProjectData().getFile(f"/{PROGRAM}")
        if domain_file is None:
            raise StageFailure("re_parse_failed", "no_program")
        consumer = Object()
        program = domain_file.getReadOnlyDomainObject(
            consumer, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY
        )
        try:
            decompile_all(program, listing, writer, status)
        finally:
            program.release(consumer)


__all__ = ["DecompileList", "add_arguments", "caps", "decompile_all", "read_list", "run"]
