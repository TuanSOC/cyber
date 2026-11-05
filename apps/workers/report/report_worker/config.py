"""Renderer configuration: environment only (`BROKER_URL`, `QUEUE_PREFIX`, `WORK_DIR`).

The renderer has no database, MinIO credentials, signing key or app Redis: its input and
output travel through the presigned URLs of each `ReportRenderMessageV1`.
"""

import os
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path

WORKER_VERSION = "report-worker/0.2.0"
# Bumped whenever a template or the CSS changes what a rendition looks like.
TEMPLATE_VERSION = "template-incident_v1.1"
# Sent on every result and stored on the render: output is byte-identical only for the same
# image and renderer version (RT17). The WeasyPrint version is read from the installed
# distribution (no import of WeasyPrint in the Celery process).
RENDERER_VERSION = f"{WORKER_VERSION}+weasyprint-{version('weasyprint')}+{TEMPLATE_VERSION}"
# Celery limits (RT4): prefork with one task per child; the hard limit kills the child.
TASK_SOFT_TIME_LIMIT_S = 90
TASK_TIME_LIMIT_S = 120


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
