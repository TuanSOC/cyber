"""What an engine hands back to the analyzer: the probe's out dir and how the process ended.

Both engines (Volatility, replay) leave `rows.jsonl` and `status.json` in a fresh out dir;
everything after that (bounded reads, validation, normalization) is the same root code.
"""

from dataclasses import dataclass
from typing import Literal, Protocol

from cyberlab_jobs.memory import MemoryPlugin, OsHint
from cyberlab_worker import sandbox

from memory_worker.engines.workspace import Workspace

ProcessEnd = Literal["exited", "failed", "timeout"]


@dataclass(frozen=True)
class ProbeRun:
    dirs: sandbox.JobDirs
    end: ProcessEnd  # exit 0 / non-zero exit / killed at its timeout
    duration_ms: int


class Engine(Protocol):
    name: Literal["volatility3", "replay"]

    def tool_versions(self) -> dict[str, str]: ...

    def identify(self, ws: Workspace, hint: OsHint, seconds: float) -> ProbeRun: ...

    def run(
        self, ws: Workspace, plugin: MemoryPlugin, seconds: float, max_rows: int
    ) -> ProbeRun: ...


__all__ = ["Engine", "ProbeRun", "ProcessEnd"]
