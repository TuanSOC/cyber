"""Worker settings (M8 phase 1, FROZEN names; plan "Frozen interfaces" 7).

The container's env holds the broker URL only (no DB, MinIO, JWT or app Redis); everything
else here is a non-secret switch with an image default:
- `MEMORY_SYMBOLS_DIR`: the read-only symbol store (`/symbols`; tests point it at a temp
  store they build, RT6);
- `MEMORY_ENGINE`: `volatility3`, or `replay` (hand-written rows, never real analysis), which is
  refused unless `TEST_PROFILE=1` (the test compose service only);
- `MEMORY_PLUGIN_RLIMIT_AS`: the address-space limit of one plugin process (2.5 GiB);
- `CYBERLAB_TOOL_UID` / `GID` = 10006 are read by the worker kit itself (image ENV).
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

WORKER_VERSION = "memory-worker/0.1.0"
VERSIONS_FILE = Path("/etc/cyberlab/versions.json")
DEFAULT_PLUGIN_RLIMIT_AS = 2560 * 1024**2
# Worker-wide task time limits (review fix): the API sends per-task limits (job timeout + 60 /
# + 90 s); these defaults keep `SoftTimeLimitExceeded` live for a message without them. The
# contract caps a memory job at 6 h (`MemoryLimits.timeout_s`), so they sit just above it.
TASK_SOFT_TIME_LIMIT_S = 6 * 3600 + 60
TASK_TIME_LIMIT_S = 6 * 3600 + 90
Engine = Literal["volatility3", "replay"]


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    broker_url: str
    queue_prefix: str
    work_dir: Path
    symbols_dir: Path
    engine: Engine
    plugin_rlimit_as: int


def _engine(env: os._Environ[str] | dict[str, str]) -> Engine:
    value = env.get("MEMORY_ENGINE", "volatility3")
    if value == "volatility3":
        return "volatility3"
    if value == "replay":
        if env.get("TEST_PROFILE") != "1":
            raise ConfigError("MEMORY_ENGINE=replay is refused outside the test profile")
        return "replay"
    raise ConfigError(f"unknown MEMORY_ENGINE {value!r}")


def load(env: os._Environ[str] | dict[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    rlimit = int(env.get("MEMORY_PLUGIN_RLIMIT_AS", str(DEFAULT_PLUGIN_RLIMIT_AS)))
    if not 256 * 1024**2 <= rlimit <= 16 * 1024**3:
        raise ConfigError("MEMORY_PLUGIN_RLIMIT_AS must be 256 MiB..16 GiB")
    return Config(
        broker_url=env["BROKER_URL"],
        queue_prefix=env.get("QUEUE_PREFIX", ""),
        work_dir=Path(env.get("WORK_DIR", "/work")),
        symbols_dir=Path(env.get("MEMORY_SYMBOLS_DIR", "/symbols")),
        engine=_engine(env),
        plugin_rlimit_as=rlimit,
    )


def tool_versions() -> dict[str, str]:
    """Versions baked into the image at build time (Volatility and its helpers)."""
    try:
        data = json.loads(VERSIONS_FILE.read_text())
    except (OSError, ValueError):
        return {}
    versions = {str(k)[:64]: str(v)[:255] for k, v in data.items() if v is not None}
    return dict(list(versions.items())[:16])
