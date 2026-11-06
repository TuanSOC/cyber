"""Org operations metrics schemas (M7 phase 1, FROZEN; phase 5 implements the route).

`GET /orgs/{org}/ops/metrics?window=` reads the org's own jobs, runs and renders through RLS
(the tenant tables, not `job_outcomes`, which has no org id, RT37).
"""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.modules.ops.error_classes import ErrorClass

Window = Literal["1h", "24h", "7d"]
OutcomeKind = Literal["pcap", "static", "memory", "disk", "ti", "ai", "report"]
# The analyzers (M8 RT1: a failed memory job must not break this page).
AnalyzerKind = Literal["pcap", "static", "memory", "disk"]


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


class RecentFailureOut(BaseModel):
    """One failed analysis job of the org (newest first), with its error class and the app
    path of its deep link (relative, under /o/{org})."""

    job_id: uuid.UUID
    kind: AnalyzerKind
    # The static (`full` / `av`), memory (`triage` / `full`) or disk (`triage` / `full` /
    # `extract`) profile; null for pcap.
    subkind: str | None
    error_code: str | None
    error_class: ErrorClass
    finished_at: datetime | None
    investigation_id: uuid.UUID
    evidence_id: uuid.UUID
    href: str


class OrgOpsMetricsOut(BaseModel):
    window: Window
    generated_at: datetime
    items: list[KindMetricsOut]
    # Jobs, runs and renders queued or running now (the org's own).
    active: dict[OutcomeKind, int]
    # Additive (M7 follow-up): the 5 most recent failed analysis jobs of the org, whatever
    # the window (the analyzers only: TI, AI and report failures are on their own pages).
    recent_failures: list[RecentFailureOut] = Field(default_factory=list)
