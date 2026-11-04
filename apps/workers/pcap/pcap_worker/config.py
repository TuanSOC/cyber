import json
import os
from dataclasses import dataclass
from pathlib import Path

WORKER_VERSION = "pcap-worker/0.1.0"
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


def tool_versions() -> dict[str, str]:
    """Versions baked into the image at build time (tools + rule snapshot digest)."""
    try:
        data = json.loads(VERSIONS_FILE.read_text())
    except (OSError, ValueError):
        return {}
    return {str(k)[:64]: str(v)[:255] for k, v in data.items()}
