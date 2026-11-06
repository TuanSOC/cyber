"""Org operations metrics (M7 phase 5): `GET /orgs/{org}/ops/metrics?window=`.

The numbers come from the org's own tenant tables (`analysis_jobs`, `ti_enrichment_runs`,
`ai_runs`, `report_renders`) through RLS, never from `job_outcomes` (which has no org id,
RT37). They are defined like the platform metrics: terminal rows finished in the window;
`failure_ratio` = failed / total; parse success (analyzers) = succeeded / (succeeded + failed
with error class `parse`); queue = started - created, run = finished - started (NULL when
never started). A purged render did succeed, so it counts as `succeeded` (the trigger
recorded it then and records nothing on the purge). One statement for the window, one for the
active counts and one for the 5 most recent failed analyses (`recent_failures`, whatever the
window), under `SET LOCAL statement_timeout = '2s'`.
"""

import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import OrgContext, Permission, require
from app.modules.analysis.models import analyzer_route
from app.modules.ops.error_classes import ErrorClass, classify
from app.modules.ops.metrics import (
    ACTIVE_STATUSES,
    ANALYZER_KINDS,
    STATEMENT_TIMEOUT,
    SUCCESS_STATUSES,
    WINDOWS,
)
from app.modules.ops.models import KINDS
from app.modules.ops.schemas import (
    KindMetricsOut,
    OrgOpsMetricsOut,
    OutcomeKind,
    RecentFailureOut,
    Window,
)

router = APIRouter(prefix="/orgs/{org_id}", tags=["ops"])

AuditRead = Annotated[OrgContext, Depends(require(Permission.AUDIT_READ), scope="function")]

# Every source table filters on the org explicitly as well as through RLS.
_WINDOW_SQL = text(
    """
WITH o AS (
  SELECT analyzer::text AS kind, profile::text AS subkind, status::text AS status, error_code,
         created_at, started_at, finished_at
    FROM analysis_jobs
   WHERE organization_id = :org AND status::text IN ('succeeded', 'failed')
     AND finished_at > :since AND finished_at <= :now
  UNION ALL
  SELECT 'ti',
         CASE WHEN jsonb_array_length(providers) = 1 THEN providers ->> 0 ELSE 'multi' END,
         status, NULL, created_at, started_at, finished_at
    FROM ti_enrichment_runs
   WHERE organization_id = :org AND status IN ('completed', 'partial', 'failed')
     AND finished_at > :since AND finished_at <= :now
  UNION ALL
  SELECT 'ai', provider, status, error_code, created_at, started_at, finished_at
    FROM ai_runs
   WHERE organization_id = :org AND status IN ('completed', 'partial', 'failed', 'refused')
     AND finished_at > :since AND finished_at <= :now
  UNION ALL
  SELECT 'report', format, CASE WHEN status = 'purged' THEN 'succeeded' ELSE status END,
         error_code, created_at, started_at, finished_at
    FROM report_renders
   WHERE organization_id = :org AND status IN ('succeeded', 'failed', 'purged')
     AND finished_at > :since AND finished_at <= :now
), d AS (
  SELECT kind, subkind, status, error_code,
         CASE WHEN started_at IS NULL THEN NULL
              ELSE greatest(0, extract(epoch FROM (started_at - created_at)) * 1000)::float8 END
           AS queue_ms,
         CASE WHEN started_at IS NULL THEN NULL
              ELSE greatest(0, extract(epoch FROM (finished_at - started_at)) * 1000)::float8 END
           AS run_ms
    FROM o
)
SELECT kind, subkind, status, error_code,
       GROUPING(status, error_code) AS rollup,
       count(*) AS n,
       percentile_cont(ARRAY[0.5, 0.95]) WITHIN GROUP (ORDER BY run_ms) AS run_q,
       percentile_cont(ARRAY[0.5, 0.95]) WITHIN GROUP (ORDER BY queue_ms) AS queue_q
  FROM d
 GROUP BY GROUPING SETS ((kind, subkind, status, error_code), (kind, subkind))
"""
)

_ACTIVE_SQL = text(
    """
SELECT analyzer::text AS kind, count(*) AS n FROM analysis_jobs
 WHERE organization_id = :org AND status::text IN ('queued', 'running') GROUP BY 1
UNION ALL
SELECT 'ti', count(*) FROM ti_enrichment_runs
 WHERE organization_id = :org AND status = ANY(:ti)
UNION ALL
SELECT 'ai', count(*) FROM ai_runs WHERE organization_id = :org AND status = ANY(:ai)
UNION ALL
SELECT 'report', count(*) FROM report_renders
 WHERE organization_id = :org AND status = ANY(:report)
"""
)

# The org's most recent failed analysis jobs (whatever the window).
_RECENT_FAILURES_SQL = text(
    """
SELECT j.id, j.analyzer::text AS kind, j.profile::text AS subkind, j.error_code, j.finished_at,
       j.evidence_id, e.investigation_id
  FROM analysis_jobs j
  JOIN evidence e ON e.id = j.evidence_id AND e.organization_id = j.organization_id
 WHERE j.organization_id = :org AND j.status::text = 'failed'
 ORDER BY j.finished_at DESC NULLS LAST, j.created_at DESC, j.id
 LIMIT :limit
"""
)
RECENT_FAILURES = 5

_KIND_ORDER = {kind: i for i, kind in enumerate(KINDS)}


def _ms(value: Any) -> int | None:
    return None if value is None else round(float(value))


def _quantiles(values: Any) -> tuple[int | None, int | None]:
    if not values:
        return None, None
    p50, p95 = values
    return _ms(p50), _ms(p95)


async def org_ops_metrics(
    session: AsyncSession, org_id: uuid.UUID, window: Window, *, now: datetime
) -> OrgOpsMetricsOut:
    await session.execute(text(STATEMENT_TIMEOUT))
    rows = (
        await session.execute(
            _WINDOW_SQL, {"org": org_id, "since": now - WINDOWS[window], "now": now}
        )
    ).mappings()
    counts: dict[tuple[str, str | None], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    classes: dict[tuple[str, str | None], dict[ErrorClass, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    parse_failed: dict[tuple[str, str | None], int] = defaultdict(int)
    durations: dict[tuple[str, str | None], tuple[Any, Any]] = {}
    for row in rows:
        key = (row["kind"], row["subkind"])
        if row["rollup"]:
            durations[key] = (row["run_q"], row["queue_q"])
            continue
        counts[key][row["status"]] += row["n"]
        if row["status"] == "failed":
            klass = classify(row["error_code"])
            classes[key][klass] += row["n"]
            if klass is ErrorClass.PARSE:
                parse_failed[key] += row["n"]

    items = []
    for key in sorted(counts, key=lambda k: (_KIND_ORDER.get(k[0], 99), k[1] or "")):
        kind, subkind = key
        by_status = counts[key]
        total = sum(by_status.values())
        succeeded = sum(by_status.get(s, 0) for s in SUCCESS_STATUSES)
        failed = by_status.get("failed", 0)
        parse_denominator = succeeded + parse_failed[key]
        run_q, queue_q = durations.get(key, (None, None))
        run_p50, run_p95 = _quantiles(run_q)
        queue_p50, queue_p95 = _quantiles(queue_q)
        items.append(
            KindMetricsOut(
                kind=kind,
                subkind=subkind,
                total=total,
                succeeded=succeeded,
                failed=failed,
                failure_ratio=failed / total if total else None,
                parse_success_ratio=(
                    succeeded / parse_denominator
                    if kind in ANALYZER_KINDS and parse_denominator
                    else None
                ),
                queue_p50_ms=queue_p50,
                queue_p95_ms=queue_p95,
                run_p50_ms=run_p50,
                run_p95_ms=run_p95,
                error_classes=dict(classes[key]),
            )
        )

    active: dict[OutcomeKind, int] = dict.fromkeys(KINDS, 0)  # type: ignore[arg-type]
    for kind, n in (
        await session.execute(
            _ACTIVE_SQL,
            {
                "org": org_id,
                "ti": list(ACTIVE_STATUSES["ti"]),
                "ai": list(ACTIVE_STATUSES["ai"]),
                "report": list(ACTIVE_STATUSES["report"]),
            },
        )
    ).all():
        if kind in active:
            active[kind] += int(n)
    failures = [
        RecentFailureOut(
            job_id=row["id"],
            kind=row["kind"],
            subkind=row["subkind"],
            error_code=row["error_code"],
            error_class=classify(row["error_code"]),
            finished_at=row["finished_at"],
            investigation_id=row["investigation_id"],
            evidence_id=row["evidence_id"],
            # Every analyzer's own page (M8 RT1: memory jobs link to /memory).
            href=f"/{analyzer_route(row['kind']) or 'malware'}/{row['id']}",
        )
        for row in (
            await session.execute(_RECENT_FAILURES_SQL, {"org": org_id, "limit": RECENT_FAILURES})
        ).mappings()
    ]
    return OrgOpsMetricsOut(
        window=window, generated_at=now, items=items, active=active, recent_failures=failures
    )


@router.get("/ops/metrics", response_model=OrgOpsMetricsOut)
async def org_metrics(
    ctx: AuditRead, window: Annotated[Window, Query()] = "24h"
) -> OrgOpsMetricsOut:
    """The org's failure rate, latency and parse success per analyzer, TI / AI provider and
    report format over the window."""
    return await org_ops_metrics(ctx.session, ctx.org_id, window, now=datetime.now(UTC))
