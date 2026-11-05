"""Platform metrics for `/internal/metrics` (M7; frozen signatures, phase 5 implements them).

`platform_metrics` reads `job_outcomes` (system table, no tenant data) and the active queue
gauges of the `*_index` tables in a system session; `render_prometheus` turns the result into
the Prometheus text exposition format:
- `cyberlab_jobs{kind,subkind,status,window}` for 1h, 24h and 7d;
- `cyberlab_job_failure_ratio{kind,subkind,window}`;
- `cyberlab_job_duration_seconds{kind,phase,quantile}` (p50 / p95 / p99, run and queue);
- `cyberlab_parse_success_ratio{analyzer,window}`;
- `cyberlab_active{kind,status}`.
"""

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class PlatformMetrics:
    generated_at: datetime
    # (kind, subkind, status, window) -> count
    jobs: dict[tuple[str, str, str, str], int] = field(default_factory=dict)
    # (kind, subkind, window) -> ratio
    failure_ratio: dict[tuple[str, str, str], float] = field(default_factory=dict)
    # (kind, phase "queue" | "run", quantile "0.5" | "0.95" | "0.99") -> seconds
    duration_seconds: dict[tuple[str, str, str], float] = field(default_factory=dict)
    # (analyzer, window) -> ratio
    parse_success_ratio: dict[tuple[str, str], float] = field(default_factory=dict)
    # (kind, status) -> gauge
    active: dict[tuple[str, str], int] = field(default_factory=dict)


async def platform_metrics(session: AsyncSession, *, now: datetime) -> PlatformMetrics:
    raise NotImplementedError("ops.metrics.platform_metrics is implemented in M7 phase 5")


def render_prometheus(metrics: PlatformMetrics) -> str:
    raise NotImplementedError("ops.metrics.render_prometheus is implemented in M7 phase 5")
