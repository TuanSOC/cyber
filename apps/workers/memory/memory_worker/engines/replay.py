"""The replay engine (test profile only): hand-written rows instead of running Volatility.

Active only when `MEMORY_ENGINE=replay` AND `TEST_PROFILE=1` (config refuses it otherwise
and the worker exits 78; this class checks again). The header then says `engine: replay`.
It stands in for the probe *process* only: it writes `rows.jsonl` and `status.json` into the
same fresh out dirs, and every root-side step after that (bounded reads, status validation,
offline check, symbol lookup, normalization, detections, writing) is the real engine's code.

Scenario: the evidence file of a replay job is a tiny marker file whose first line is
`CYBERLAB-REPLAY <scenario>`; the rows come from `<MEMORY_REPLAY_DIR>/<scenario>/`
(default `tests/fixtures/vol_rows/`):
- `identify.json`: the probe's identify object (`layers`, `pdb`, `banner`);
- `<plugin>.jsonl`: the plugin's rows in the 2.28.2 column shapes (missing: the plugin is
  `unsupported`, as when Volatility cannot satisfy a requirement);
- `<plugin>.status.json` (optional): keys merged over the default `ok` status; `_end`
  (`failed` / `timeout`) simulates how the process ended.
Our own synthetic rows only: never a real image, never real analysis.
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Literal

from cyberlab_jobs.memory import MemoryPlugin, OsHint

from memory_worker.config import ConfigError
from memory_worker.engines.base import ProbeRun, ProcessEnd
from memory_worker.engines.workspace import ROWS, STATUS, Workspace
from memory_worker.normalize.reader import MAX_FILE_BYTES, MAX_STATUS_BYTES

MARKER = re.compile(rb"^CYBERLAB-REPLAY ([a-z0-9_]{1,64})\r?\n")
DEFAULT_DIR = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "vol_rows"
ENDS: dict[str, ProcessEnd] = {"failed": "failed", "timeout": "timeout"}


class ReplayEngine:
    name: Literal["volatility3", "replay"] = "replay"

    def __init__(self, root: Path | None = None, env: dict[str, str] | None = None) -> None:
        env = dict(os.environ) if env is None else env
        if env.get("TEST_PROFILE") != "1":
            raise ConfigError("the replay engine runs in the test profile only")
        self.root = root or Path(env.get("MEMORY_REPLAY_DIR") or DEFAULT_DIR)

    def tool_versions(self) -> dict[str, str]:
        return {"replay": "hand-written rows (tests/fixtures/vol_rows), not real analysis"}

    def scenario(self, ws: Workspace) -> Path | None:
        with open(ws.image, "rb") as f:
            match = MARKER.match(f.read(96))
        if match is None:
            return None
        path = self.root / match.group(1).decode()
        return path if path.is_dir() else None

    @staticmethod
    def _status(ws: Workspace, **fields: Any) -> dict[str, Any]:
        return {
            "status": "ok",
            "error": None,
            "rows": 0,
            "truncated": False,
            "audit": {},
            "offline": True,
            "remote_isf_url": None,
            "symbol_paths": [
                str(ws.symbols_dir),
                "/replay/volatility3/symbols",
                "/replay/volatility3/framework/symbols",
            ],
            "plugin_paths": [
                "/replay/volatility3/plugins",
                "/replay/volatility3/framework/plugins",
            ],
            **fields,
        }

    def identify(self, ws: Workspace, hint: OsHint, seconds: float) -> ProbeRun:
        del hint, seconds
        dirs = ws.fresh("identify")
        Workspace.write(dirs, ROWS, b"")
        scenario = self.scenario(ws)
        if scenario is None or not (scenario / "identify.json").is_file():
            status = self._status(ws, status="failed", error="ReplayScenarioMissing")
        else:
            found = json.loads((scenario / "identify.json").read_bytes()[:MAX_STATUS_BYTES])
            status = self._status(ws, identify=found)
        Workspace.write(dirs, STATUS, json.dumps(status).encode())
        Workspace.seal(dirs)
        return ProbeRun(dirs=dirs, end="exited", duration_ms=1)

    def run(self, ws: Workspace, plugin: MemoryPlugin, seconds: float, max_rows: int) -> ProbeRun:
        del seconds, max_rows  # root applies its own cap while reading
        dirs = ws.fresh(plugin.value)
        scenario = self.scenario(ws)
        rows_file = scenario / f"{plugin.value}.jsonl" if scenario else None
        end: ProcessEnd = "exited"
        if rows_file is None or not rows_file.is_file():
            Workspace.write(dirs, ROWS, b"")
            status = self._status(ws, status="unsupported", error="UnsatisfiedException")
        else:
            data = rows_file.read_bytes()[: MAX_FILE_BYTES + 1]
            Workspace.write(dirs, ROWS, data)
            status = self._status(
                ws, rows=data.count(b"\n"), isf=[ws.isf_uri] if ws.isf_uri else []
            )
            override = rows_file.with_name(f"{plugin.value}.status.json")
            if override.is_file():
                extra = json.loads(override.read_bytes()[:MAX_STATUS_BYTES])
                end = ENDS.get(str(extra.pop("_end", "")), "exited")
                status |= extra
        Workspace.write(dirs, STATUS, json.dumps(status).encode())
        Workspace.seal(dirs)
        return ProbeRun(dirs=dirs, end=end, duration_ms=1)


__all__ = ["DEFAULT_DIR", "MARKER", "ReplayEngine"]
