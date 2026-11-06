"""Worker settings (M10 phase 1, FROZEN names; plan "Frozen interfaces" 8).

The container's env holds the broker URL only (no DB, MinIO, JWT or app Redis); everything
else is a non-secret switch with an image default:
- `RE_ENGINE`: `ghidra`, or `replay` (hand-written stage outputs, never real analysis), which is
  refused unless `TEST_PROFILE=1` (the test compose service only);
- `RE_JVM_HEAP` (2 GiB, <= 3 GiB): the `analyze` JVM's -Xmx;
- `RE_DECOMPILE_JVM_HEAP` (1 GiB): the `decompile` JVM's -Xmx (RT4);
- `RE_DECOMPILER_AS` (1.5 GiB): the decompiler child's RLIMIT_AS, lowered with `prlimit`
  after each (re)spawn (RT4); must be above `RE_DECOMPILE_JVM_HEAP`;
- `RE_TOOL_RLIMIT_AS`: a JVM stage's RLIMIT_AS (default heap + 3 GiB, spike-tuned);
- `RE_MAX_WORK_BYTES` is per job and comes with the message (`ReLimits.max_work_bytes`);
- `CYBERLAB_TOOL_UID` / `GID` = 10010 are read by the worker kit itself (image ENV).
Values are PROVISIONAL until the phase-2 spike reports.
"""

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

WORKER_VERSION = "re-worker/0.1.0"
VERSIONS_FILE = Path("/etc/cyberlab/versions.json")
GIB = 1024**3
MIB = 1024**2
DEFAULT_JVM_HEAP = 2 * GIB
MAX_JVM_HEAP = 3 * GIB
DEFAULT_DECOMPILE_JVM_HEAP = 1 * GIB
DEFAULT_DECOMPILER_AS = 1536 * MIB
TOOL_AS_HEADROOM = 3 * GIB  # metaspace, code cache, threads, native (RT4: spike-tuned)
GHIDRA_DIR = Path("/opt/ghidra")
JAVA_HOME = Path("/opt/java/openjdk")
QUICK_SCRIPT = Path("/opt/re/r2/quick.r2")
# Worker-wide task time limits: the API sends per-task limits (job timeout + 60 / + 90 s);
# these defaults keep `SoftTimeLimitExceeded` live for a message without them (6 h cap).
TASK_SOFT_TIME_LIMIT_S = 6 * 3600 + 60
TASK_TIME_LIMIT_S = 6 * 3600 + 90
Engine = Literal["ghidra", "replay"]


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    broker_url: str
    queue_prefix: str
    work_dir: Path
    engine: Engine
    jvm_heap: int
    decompile_jvm_heap: int
    decompiler_as: int
    tool_rlimit_as: int
    ghidra_dir: Path = GHIDRA_DIR
    java_home: Path = JAVA_HOME
    quick_script: Path = QUICK_SCRIPT


def _engine(env: Mapping[str, str]) -> Engine:
    value = env.get("RE_ENGINE", "ghidra")
    if value == "ghidra":
        return "ghidra"
    if value == "replay":
        if env.get("TEST_PROFILE") != "1":
            raise ConfigError("RE_ENGINE=replay is refused outside the test profile")
        return "replay"
    raise ConfigError(f"unknown RE_ENGINE {value!r}")


def _bytes(env: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(env.get(name, str(default)))
    except ValueError as exc:
        raise ConfigError(f"{name} must be a byte count") from exc
    if not low <= value <= high:
        raise ConfigError(f"{name} must be {low}..{high} bytes")
    return value


def load(env: Mapping[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    heap = _bytes(env, "RE_JVM_HEAP", DEFAULT_JVM_HEAP, 512 * MIB, MAX_JVM_HEAP)
    decompile_heap = _bytes(
        env, "RE_DECOMPILE_JVM_HEAP", DEFAULT_DECOMPILE_JVM_HEAP, 256 * MIB, MAX_JVM_HEAP
    )
    decompiler_as = _bytes(env, "RE_DECOMPILER_AS", DEFAULT_DECOMPILER_AS, 256 * MIB, 4 * GIB)
    if decompiler_as <= decompile_heap:
        raise ConfigError("RE_DECOMPILER_AS must be above RE_DECOMPILE_JVM_HEAP")
    tool_as = _bytes(
        env, "RE_TOOL_RLIMIT_AS", heap + TOOL_AS_HEADROOM, heap + 512 * MIB, 16 * GIB
    )
    return Config(
        broker_url=env["BROKER_URL"],
        queue_prefix=env.get("QUEUE_PREFIX", ""),
        work_dir=Path(env.get("WORK_DIR", "/work")),
        engine=_engine(env),
        jvm_heap=heap,
        decompile_jvm_heap=decompile_heap,
        decompiler_as=decompiler_as,
        tool_rlimit_as=tool_as,
    )


def tool_versions() -> dict[str, str]:
    """Versions baked into the image at build time (Ghidra, JDK, PyGhidra, JPype, radare2)."""
    try:
        data = json.loads(VERSIONS_FILE.read_text())
    except (OSError, ValueError):
        return {}
    versions = {str(k)[:64]: str(v)[:255] for k, v in data.items() if v is not None}
    return dict(list(versions.items())[:16])
