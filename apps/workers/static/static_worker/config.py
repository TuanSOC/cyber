import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

WORKER_VERSION = "static-worker/0.1.0"
VERSIONS_FILE = Path("/etc/cyberlab/versions.json")


@dataclass(frozen=True)
class Config:
    broker_url: str
    queue_prefix: str
    work_dir: Path


def load() -> Config:
    return Config(
        broker_url=os.environ["BROKER_URL"],
        queue_prefix=os.environ.get("QUEUE_PREFIX", ""),
        work_dir=Path(os.environ.get("WORK_DIR", "/work")),
    )


@dataclass(frozen=True)
class Engines:
    """Engine locations and switches. The defaults are the image's baked assets.

    The STATIC_* overrides exist for the test container (tiny ClamAV DB, test YARA rules,
    fixture capa rules) the way SURICATA_RULES does for the pcap worker.
    """

    python: str = sys.executable
    clamscan: str = "/usr/bin/clamscan"
    clamav_db: Path | None = None  # None: clamscan's default DB dir (/var/lib/clamav)
    yara_rules: Path = Path("/opt/yara/rules")
    yara_test_rules: Path | None = None
    capa: str = "/opt/venv/bin/capa"
    capa_rules: Path = Path("/opt/capa/rules")
    capa_sigs: Path = Path("/opt/capa/sigs")
    # Read-only cache precomputed at build for the baked rules; None = a per-run cache in the
    # engine's out dir (custom rule sets, e.g. the test fixture rules).
    capa_cache: Path | None = Path("/opt/capa/cache")
    floss: str = "/opt/venv/bin/floss"
    capa_enabled: bool = True
    floss_enabled: bool = True

    @classmethod
    def from_env(cls) -> "Engines":
        env = os.environ

        def path(name: str) -> Path | None:
            return Path(env[name]) if env.get(name) else None

        return cls(
            clamav_db=path("STATIC_CLAMAV_DB"),
            yara_rules=Path(env.get("YARA_RULES", "/opt/yara/rules")),
            yara_test_rules=path("STATIC_YARA_TEST_RULES"),
            capa_rules=path("STATIC_CAPA_RULES") or Path(env.get("CAPA_RULES", "/opt/capa/rules")),
            capa_sigs=Path(env.get("CAPA_SIGS", "/opt/capa/sigs")),
            capa_cache=None
            if env.get("STATIC_CAPA_RULES")
            else Path(env.get("XDG_CACHE_HOME", "/opt/capa/cache")),
            capa_enabled=env.get("STATIC_CAPA", "1") != "0",
            floss_enabled=env.get("STATIC_FLOSS", "1") != "0",
        )


def tool_versions(engines: Engines | None = None) -> dict[str, str]:
    """Versions baked into the image at build time (tools, rule snapshots, AV DB)."""
    try:
        data = json.loads(VERSIONS_FILE.read_text())
    except (OSError, ValueError):
        return {}
    versions = {str(k)[:64]: str(v)[:255] for k, v in data.items() if v is not None}
    if engines is not None and engines.clamav_db is not None:
        versions["clamav_db"] = f"custom:{engines.clamav_db.name}"[:255]
        versions.pop("clamav_db_date", None)
    return dict(list(versions.items())[:16])
