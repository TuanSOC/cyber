"""Engine interface shared by the Ghidra runner (phase 2), radare2 (phase 3) and the replay
engine (phase 2, test profile only). M10 phase 1, FROZEN types.

An engine runs its stage process(es) in the sandbox and returns the validated records it
produced (`EngineOutput`); root then ranks (phase 5's `priority.rank`), detects and writes the
`re.v1` stream. `Workspace` is the per-job directory layout root prepared (phase 2's
`engines/workspace.py` builds it); `Budget` is the job's remaining time.
"""

import time
from dataclasses import dataclass, field
from pathlib import Path

from cyberlab_jobs.reverse import (
    ReCallEdgeRecord,
    ReDecompiledRecord,
    ReFunctionRecord,
    ReImportRecord,
    ReImportRefRecord,
    ReProgramRecord,
    ReStringRecord,
    ReStringRefRecord,
    StageReport,
)


class ProfileUnavailable(Exception):  # noqa: N818 - maps to the `profile_unavailable` code
    """The requested profile's engine is not available in this image (radare2 cut, phase 3)."""

    code = "profile_unavailable"


@dataclass(frozen=True)
class Workspace:
    """One job's directories. `input` (root-owned, 0555) holds the sample (0444); `stage` is
    root-owned (0755, files 0444: the decompile list, RT23); `out` and `project` are
    tool-writable; nothing outside `root` is written by a tool process."""

    root: Path
    input: Path
    stage: Path
    out: Path
    project: Path

    @property
    def sample(self) -> Path:
        return self.input / "sample"


@dataclass(frozen=True)
class Budget:
    """The job's wall-clock deadline (monotonic seconds)."""

    deadline: float

    @classmethod
    def starting_now(cls, seconds: float) -> "Budget":
        return cls(deadline=time.monotonic() + seconds)

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def timeout(self, cap: float) -> float:
        """A stage timeout: the cap, or what is left of the job if that is less."""
        return min(cap, self.remaining())


@dataclass
class EngineOutput:
    program: ReProgramRecord
    functions: list[ReFunctionRecord] = field(default_factory=list)
    edges: list[ReCallEdgeRecord] = field(default_factory=list)
    imports: list[ReImportRecord] = field(default_factory=list)
    import_refs: list[ReImportRefRecord] = field(default_factory=list)
    strings: list[ReStringRecord] = field(default_factory=list)
    string_refs: list[ReStringRefRecord] = field(default_factory=list)
    decompiled: list[ReDecompiledRecord] = field(default_factory=list)
    stages: list[StageReport] = field(default_factory=list)
    tool_versions: dict[str, str] = field(default_factory=dict)
    audit: dict[str, int] = field(default_factory=dict)
    jvm_args: list[str] = field(default_factory=list)
    engine_errors: list[str] = field(default_factory=list)
    truncated: dict[str, bool] = field(default_factory=dict)
