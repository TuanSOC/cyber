"""The replay engine (test profile only): hand-written stage outputs instead of a process.

Active only when `RE_ENGINE=replay` AND `TEST_PROFILE=1` (config refuses it otherwise and
the worker exits 78; this class checks again). Every header then says `engine: replay`, and
`tool_versions` says the rows are hand-written: never real analysis (`requirement.txt` §16).

It stands in for the stage *process* only (`StageRunner`): it writes the files a stage would
leave into the same fresh out dir (`workspace.fresh`), then seals it; every root-side step
after that (bounded reads through `open_output`, status checks, contract validation, caps,
ranking, the decompile list, detections, the writer) is the real engine's code.

Case: the sample of a replay job carries a marker line `CYBERLAB-REPLAY <case>` within its
first 4 KiB (the tests build a tiny, valid PE / ELF header followed by it; root's magic check
still runs first); the files come from `<RE_REPLAY_DIR>/<case>/` (default
`tests/fixtures/stage_rows/`):
- `<step>.jsonl` (or `<step>.out` for a step whose stdout is not `rows.jsonl`): the stdout;
- `<step>.status.json` (optional): keys merged over the default `ok` status of a probe step;
  `_end` (`failed` / `timeout`), `_returncode`, `_oom` and `_work_too_large` simulate how the
  process ended and what the watchdog saw. A step without a file is a process that wrote
  nothing (and no status).
"""

import json
import os
import re
import time
from pathlib import Path, PurePosixPath
from typing import Any

from cyberlab_worker import sandbox

from re_worker import jvm_args
from re_worker.config import ConfigError
from re_worker.engines import Workspace, workspace
from re_worker.engines.outcome import ProcessEnd
from re_worker.engines.spec import PROBE_MODULE, ROWS, STATUS, StageSpec
from re_worker.engines.stage import StageRun, process_result
from re_worker.engines.watch import WatchResult
from re_worker.normalize.reader import MAX_FILE_BYTES, MAX_STATUS_BYTES
from re_worker.probe.launcher import DECOMPILER

MARKER = re.compile(rb"CYBERLAB-REPLAY ([a-z0-9_]{1,64})\r?\n")
MARKER_WINDOW = 4096
DEFAULT_DIR = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "stage_rows"
ENDS: dict[str, ProcessEnd] = {"failed": "failed", "timeout": "timeout"}


def case_of(sample: Path) -> str | None:
    with open(sample, "rb") as f:
        match = MARKER.search(f.read(MARKER_WINDOW))
    return match.group(1).decode() if match else None


class ReplayRunner:
    name = "replay"

    def __init__(self, root: Path | None = None, env: dict[str, str] | None = None) -> None:
        env = dict(os.environ) if env is None else env
        if env.get("TEST_PROFILE") != "1":
            raise ConfigError("the replay engine runs in the test profile only")
        self.root = root or Path(env.get("RE_REPLAY_DIR") or DEFAULT_DIR)
        self.case: Path | None = None

    def tool_versions(self) -> dict[str, str]:
        return {"replay": "hand-written stage rows (tests/fixtures/stage_rows), not real analysis"}

    def select(self, ws: Workspace) -> None:
        name = case_of(ws.sample)
        path = self.root / name if name else None
        self.case = path if path is not None and path.is_dir() else None

    @staticmethod
    def _default_status(spec: StageSpec, out: PurePosixPath) -> dict[str, Any]:
        status: dict[str, Any] = {"status": "ok", "audit": {}}
        if spec.heap_bytes is not None:
            status["jvm_started"] = True
            status["jvm_args"] = jvm_args.expected_args(spec.heap_bytes, out)
        if spec.name == "analyze":
            status["analysis_status"] = "complete"
        if spec.name == "decompile":
            status["children"] = [str(DECOMPILER.resolve())]
        return status

    def _file(self, step: str, suffix: str) -> Path | None:
        if self.case is None:
            return None
        path = self.case / f"{step}{suffix}"
        return path if path.is_file() else None

    def run(
        self,
        ws: Workspace,
        spec: StageSpec,
        max_work_bytes: int,
        *,
        dirs: sandbox.JobDirs | None = None,
        seal: bool = True,
    ) -> StageRun:
        del max_work_bytes
        started = time.monotonic()
        dirs = dirs or workspace.fresh(ws, spec.name, spec.subdirs)
        step = spec.key
        stdout = self._file(step, ".jsonl" if spec.stdout_name == ROWS else ".out")
        workspace.write_out(
            dirs, spec.stdout_name, stdout.read_bytes()[: MAX_FILE_BYTES + 1] if stdout else b""
        )
        override: dict[str, Any] = {}
        extra = self._file(step, ".status.json")
        if extra is not None:
            override = json.loads(extra.read_bytes()[:MAX_STATUS_BYTES])
        end = ENDS.get(str(override.pop("_end", "")), "exited")
        returncode = override.pop("_returncode", 0 if end == "exited" else 1)
        watch = WatchResult(
            work_too_large=bool(override.pop("_work_too_large", False)),
            oom_killed=bool(override.pop("_oom", False)),
            peak_memory_bytes=int(override.pop("_peak_memory_bytes", 0)) or None,
        )
        writes_status = PROBE_MODULE in spec.argv and not override.pop("_no_status", False)
        if writes_status and (stdout is not None or extra is not None):
            status = self._default_status(spec, PurePosixPath(str(dirs.out))) | override
            workspace.write_out(dirs, STATUS, json.dumps(status).encode())
        if seal:
            workspace.seal(dirs)
        return StageRun(dirs, process_result(end, returncode, started, watch, False))


__all__ = ["DEFAULT_DIR", "MARKER", "ReplayRunner", "case_of"]
