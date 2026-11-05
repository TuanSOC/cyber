"""Renderer configuration: environment only (`BROKER_URL`, `QUEUE_PREFIX`, `WORK_DIR`).

The renderer has no database, MinIO credentials, signing key or app Redis: its input and
output travel through the presigned URLs of each `ReportRenderMessageV1`.
"""

import os
from dataclasses import dataclass
from pathlib import Path

WORKER_VERSION = "report-worker/0.1.0"
# Phase 4 extends it: report-worker/<semver>+weasyprint-<ver>+template-incident_v1.<n>.
RENDERER_VERSION = f"{WORKER_VERSION}+skeleton"
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
