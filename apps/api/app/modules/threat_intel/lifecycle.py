"""Run finalization, shared by the enrich worker (step 9) and the ingest-side fallback reaper.

It imports nothing that can reach a provider or open a key, so the ingest worker may use it.
The caller opens the tenant session of the run's org (org taken from `ti_run_index`).
"""

import math
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.threat_intel.models import (
    RUN_FINAL,
    TiEnrichmentRun,
    TiResult,
    TiRunIndex,
    TiRunItem,
)

ANSWERED_OK = ("ok", "not_found")


def _percentile(values: list[int], pct: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return ordered[rank - 1]


def outcome(states: list[tuple[str, str | None]]) -> str:
    """`completed` if every item was answered ok / not_found or served from the cache,
    `failed` if no item reached a provider (nor the cache), otherwise `partial`."""
    if states and all(s == "cached" or (s == "done" and r in ANSWERED_OK) for s, r in states):
        return "completed"
    if not any(s in ("done", "cached") for s, _ in states):
        return "failed"
    return "partial"


async def finalize_run(
    session: AsyncSession,
    org_id: uuid.UUID,
    run_id: uuid.UUID,
    *,
    abandon_reason: str | None = None,
) -> str | None:
    """End the run under `FOR UPDATE` on the run and its index row.

    `abandon_reason` (`deadline`) first abandons every pending item. Returns the final status,
    or None when the run is already final (a no-op: worker after reaper, redelivery) or still
    has pending items. Writes no `ti_results` rows.
    """
    run = await session.scalar(
        select(TiEnrichmentRun)
        .where(TiEnrichmentRun.id == run_id, TiEnrichmentRun.organization_id == org_id)
        .with_for_update()
    )
    if run is None or run.status in RUN_FINAL:
        return None
    index = await session.get(TiRunIndex, run_id, with_for_update=True)
    if abandon_reason is not None:
        await session.execute(
            update(TiRunItem)
            .where(TiRunItem.run_id == run_id, TiRunItem.state == "pending")
            .values(state="abandoned", reason=abandon_reason)
        )
    rows = (
        await session.execute(
            select(
                TiRunItem.provider,
                TiRunItem.state,
                TiRunItem.reason,
                TiResult.status,
                TiResult.latency_ms,
                TiResult.run_id,
            )
            .outerjoin(
                TiResult,
                and_(
                    TiResult.id == TiRunItem.result_id,
                    TiResult.organization_id == TiRunItem.organization_id,
                ),
            )
            .where(TiRunItem.run_id == run_id, TiRunItem.organization_id == org_id)
        )
    ).all()
    if any(row.state == "pending" for row in rows):
        return None

    counts: dict[str, Counter[str]] = defaultdict(Counter)
    latencies: dict[str, list[int]] = defaultdict(list)
    states: list[tuple[str, str | None]] = []
    for provider, state, reason, status, latency, result_run in rows:
        if state == "cached":
            counts[provider]["cached"] += 1
        elif state == "done":
            counts[provider][status or "error"] += 1
            if latency is not None and result_run == run_id:
                latencies[provider].append(latency)
        elif state == "abandoned":
            counts[provider][f"abandoned_{reason}"] += 1
        states.append((state, status))

    status = outcome(states)
    summary: dict[str, Any] = dict(run.summary or {})
    providers: dict[str, Any] = {k: dict(v) for k, v in (summary.get("providers") or {}).items()}
    for provider in set(counts) | set(providers):
        entry = providers.setdefault(provider, {})
        entry.update(counts.get(provider, {}))
        values = latencies.get(provider, [])
        entry["latency_p50_ms"] = _percentile(values, 50)
        entry["latency_p95_ms"] = _percentile(values, 95)
    summary["providers"] = providers
    all_latencies = [v for values in latencies.values() for v in values]
    summary["latency_p50_ms"] = _percentile(all_latencies, 50)
    summary["latency_p95_ms"] = _percentile(all_latencies, 95)
    if abandon_reason is not None:
        summary["ended_by"] = abandon_reason

    # The status graph has no waiting/queued -> completed edge: pass through running.
    if status == "completed" and run.status != "running":
        run.status = "running"
        await session.flush()
    now = datetime.now(UTC)
    run.status = status
    run.summary = summary
    run.finished_at = now
    if run.started_at is None:
        run.started_at = now
    if index is not None:
        index.status = status
        index.resume_at = None
        index.lease_until = None
        index.lease_owner = None
    await session.flush()
    return status


__all__ = ["finalize_run", "outcome"]
