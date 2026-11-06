"""Worker settings (M9 phase 1, FROZEN names; plan "Frozen interfaces" 7).

The container's env holds the broker URL only (no DB, MinIO, JWT or app Redis); everything else
here is a non-secret switch with an image default:
- `DISK_HASHSETS_DIR`: the read-only known-file hash-set store (`/hashsets`, written only by the
  `disk-hashsets` tool; tests build temp stores);
- `DISK_WORK_MIN_FREE_BYTES`: the free-space floor of `/work` the write watchdog holds (4 GiB,
  RT4; the test service sets a small one on its tmpfs);
- `DISK_TIMELINE_ENGINE`: `plaso`, or `replay` (hand-written psort-shaped rows, never real
  analysis), which is refused unless `TEST_PROFILE=1`; `none` skips the timeline stage;
- `DISK_RULES_DIR`: the baked M3 rule sources (`/opt/rules/image`); `DISK_TEST_RULES_DIR`: the M3
  `test` rule directory, honoured only with `TEST_PROFILE=1` (phase 5);
- `CYBERLAB_TOOL_UID` / `GID` = 10007 are read by the worker kit itself (image ENV).

The per-stage limits travel in each job's `DiskLimits` (set by the API), not here.
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

WORKER_VERSION = "disk-worker/0.1.0"
VERSIONS_FILE = Path("/etc/cyberlab/versions.json")
DEFAULT_MIN_FREE_BYTES = 4 * 1024**3
TimelineEngine = Literal["plaso", "replay", "none"]


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    broker_url: str
    queue_prefix: str
    work_dir: Path
    hashsets_dir: Path
    min_free_bytes: int
    timeline_engine: TimelineEngine
    rules_dir: Path
    test_rules_dir: Path | None


Env = os._Environ[str] | dict[str, str]


def _test_profile(env: Env) -> bool:
    return env.get("TEST_PROFILE") == "1"


def _timeline_engine(env: Env) -> TimelineEngine:
    value = env.get("DISK_TIMELINE_ENGINE", "plaso")
    if value in ("plaso", "none"):
        return value  # type: ignore[return-value]
    if value == "replay":
        if not _test_profile(env):
            raise ConfigError("DISK_TIMELINE_ENGINE=replay is refused outside the test profile")
        return "replay"
    raise ConfigError(f"unknown DISK_TIMELINE_ENGINE {value!r}")


def timeline_engine(env: Env | None = None) -> TimelineEngine:
    """`DISK_TIMELINE_ENGINE` alone (phase 3's runner; `replay` refused outside the test
    profile, as in `load`)."""
    return _timeline_engine(os.environ if env is None else env)


def load(env: Env | None = None) -> Config:
    env = os.environ if env is None else env
    min_free = int(env.get("DISK_WORK_MIN_FREE_BYTES", str(DEFAULT_MIN_FREE_BYTES)))
    if not 0 <= min_free <= 1024**4:
        raise ConfigError("DISK_WORK_MIN_FREE_BYTES must be 0..1 TiB")
    test_rules = env.get("DISK_TEST_RULES_DIR")
    if test_rules and not _test_profile(env):
        raise ConfigError("DISK_TEST_RULES_DIR is refused outside the test profile")
    return Config(
        broker_url=env["BROKER_URL"],
        queue_prefix=env.get("QUEUE_PREFIX", ""),
        work_dir=Path(env.get("WORK_DIR", "/work")),
        hashsets_dir=Path(env.get("DISK_HASHSETS_DIR", "/hashsets")),
        min_free_bytes=min_free,
        timeline_engine=_timeline_engine(env),
        rules_dir=Path(env.get("DISK_RULES_DIR", "/opt/rules/image")),
        test_rules_dir=Path(test_rules) if test_rules else None,
    )


def tool_versions() -> dict[str, str]:
    """Versions baked into the image at build time (pytsk3 / TSK, libewf, Plaso, YARA, rules)."""
    try:
        data = json.loads(VERSIONS_FILE.read_text())
    except (OSError, ValueError):
        return {}
    versions = {str(k)[:64]: str(v)[:255] for k, v in data.items() if v is not None}
    return dict(list(versions.items())[:16])
