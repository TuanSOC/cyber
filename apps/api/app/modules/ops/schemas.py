"""Org operations metrics schemas (M7 phase 1, FROZEN; phase 5 implements the route).

`GET /orgs/{org}/ops/metrics?window=` reads the org's own jobs, runs and renders through RLS
(the tenant tables, not `job_outcomes`, which has no org id, RT37).
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.modules.ops.error_classes import ErrorClass

Window = Literal["1h", "24h", "7d"]
OutcomeKind = Literal["pcap", "static", "ti", "ai", "report"]


class KindMetricsOut(BaseModel):
    kind: OutcomeKind
    # Analysis profile, TI provider (`multi` for several), AI provider or report format.
    subkind: str | None
    total: int
    succeeded: int
    failed: int
    # failed / total; null when nothing finished in the window.
    failure_ratio: float | None
    # succeeded / (succeeded + failed with class parse); analyzers only, else null.
    parse_success_ratio: float | None
    queue_p50_ms: int | None
    queue_p95_ms: int | None
    run_p50_ms: int | None
    run_p95_ms: int | None
    error_classes: dict[ErrorClass, int]


class OrgOpsMetricsOut(BaseModel):
    window: Window
    generated_at: datetime
    items: list[KindMetricsOut]
    # Jobs, runs and renders queued or running now (the org's own).
    active: dict[OutcomeKind, int]
