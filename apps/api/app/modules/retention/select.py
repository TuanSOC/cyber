"""The shared retention selector (M7; frozen signature, phase 3 implements it).

Both the API's read-only preview and the retention worker call `candidates`, so a dry run
lists exactly what an enforce run on the same data deletes. The caller passes the effective
policy it read from the DB (values and mode, never a task message, RT1) and an open tenant
session of that org.

Read-only, deterministic (the same rows and `now` give the same set), and limited to the
tables the retention role may SELECT. Per category:

- `ti_results`: answers fetched before the cutoff whose every referencing `ti_run_items` row
  belongs to a run finished before the cutoff (later runs reuse answers as `cached`, RT10),
  not cited by a report (`report_citations.ref_table/ref_id`, kept as `kept_cited`) and not
  tied to a held case (through the job of its run or of a run that reused it). Manual
  lookups have no case: age only. One candidate per answer (rows: the answer + its items).
- `ai_runs`: terminal runs finished before the cutoff, as whole trees (`parent_run_id` /
  `supersedes_run_id`, RT10): a tree goes only when every member is eligible, uncited (its
  citations or outputs cited by a report) and outside held cases. One candidate per run.
- `closed_case`: cases whose latest status event moved them to closed / archived before the
  cutoff and that are still closed / archived; never a case without a status event (closed
  before M6) and never one with a queued or running job this run (RT24). Candidates: the
  evidence versions without a tombstone (bytes), the bulk rows per job and table (cited rows
  kept, RT23), the jobs' `results` object versions and the `succeeded` renders of its
  reports (never snapshots). Correlation keys are kept (RT9).

A held case (active or released less than the delay ago, RT1) is excluded from every
category; an org hold excludes everything.
"""

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.modules.analysis.dispatch import result_key
from app.modules.reports.dispatch import render_key
from app.modules.retention.holds import HoldSet, active_holds

CATEGORIES = ("ti_results", "ai_runs", "closed_case")
# The bulk derived rows of a closed case's jobs (plan Retention; the DELETE grants of 0014,
# of 0016 for the four memory tables, M8, and of 0017 for the two disk tables, M9).
# `memory_images`, `memory_sensitivity`, `disk_images`, `disk_partitions`, `disk_exports`,
# `analysis_job_segments`, findings and IOCs are never purged.
BULK_TABLES = (
    "analysis_timeline",
    "disk_events",
    "disk_files",
    "malware_exports",
    "malware_imports",
    "malware_resources",
    "malware_sections",
    "malware_strings",
    "memory_artifacts",
    "memory_connections",
    "memory_injections",
    "memory_processes",
    "network_flows",
    "network_records",
)
AI_FINAL = ("completed", "partial", "failed", "refused")
AI_CITABLE = ("ai_runs", "ai_outputs", "ai_citations")


@dataclass(frozen=True)
class EffectivePolicy:
    """The values and mode in force at `now` (pending changes whose delay passed applied)."""

    ti_results_days: int | None
    ai_runs_days: int | None
    closed_case_days: int | None
    enforce: bool

    @property
    def empty(self) -> bool:
        return (self.ti_results_days, self.ai_runs_days, self.closed_case_days) == (
            None,
            None,
            None,
        )


@dataclass(frozen=True)
class Candidate:
    category: str
    ref_table: str
    ref_id: str
    job_id: uuid.UUID | None
    investigation_id: uuid.UUID | None
    rows: int
    bytes: int
    # Set for object candidates (evidence bytes, results objects, report renditions).
    object_bucket: str | None = None
    object_key: str | None = None
    object_version_id: str | None = None


@dataclass
class CategoryCount:
    candidates: int = 0
    rows: int = 0
    bytes: int = 0
    kept_cited: int = 0
    skipped_hold: int = 0
    skipped_locked: int = 0


@dataclass
class CandidateSet:
    candidates: list[Candidate] = field(default_factory=list)
    counts: dict[str, CategoryCount] = field(
        default_factory=lambda: {c: CategoryCount() for c in CATEGORIES}
    )
    # More candidates exist than `limit` (the next run continues).
    truncated: bool = False


def cutoff(now: datetime, days: int) -> datetime:
    return now - timedelta(days=days)


def _key(c: Candidate) -> tuple[str, str, str]:
    return (str(c.investigation_id or ""), c.ref_table, c.ref_id)


def _add(out: CandidateSet, found: list[Candidate], limit: int) -> None:
    """Count every candidate; list at most `limit` of them (in order)."""
    for c in found:
        count = out.counts[c.category]
        count.candidates += 1
        count.rows += c.rows
        count.bytes += c.bytes
    if len(found) > limit:
        out.truncated = True
    out.candidates.extend(found[:limit])


# --- ti_results ------------------------------------------------------------------------------

_TI = text(
    """
SELECT r.id, run.job_id, ev.investigation_id,
  (SELECT count(*) FROM ti_run_items i WHERE i.result_id = r.id) AS items,
  EXISTS (SELECT 1 FROM report_citations c WHERE c.organization_id = :org
          AND c.ref_table = 'ti_results' AND c.ref_id = r.id::text) AS cited,
  EXISTS (SELECT 1 FROM ti_run_items i
          JOIN ti_enrichment_runs ir ON ir.id = i.run_id
          JOIN analysis_jobs ij ON ij.id = ir.job_id
          JOIN evidence ie ON ie.id = ij.evidence_id
          WHERE i.result_id = r.id AND ie.investigation_id = ANY(:held)) AS held_ref
FROM ti_results r
JOIN ti_enrichment_runs run ON run.id = r.run_id
LEFT JOIN analysis_jobs j ON j.id = run.job_id
LEFT JOIN evidence ev ON ev.id = j.evidence_id
WHERE r.organization_id = :org AND r.fetched_at < :cutoff
  AND run.finished_at IS NOT NULL AND run.finished_at < :cutoff
  AND NOT EXISTS (
    SELECT 1 FROM ti_run_items i JOIN ti_enrichment_runs ir ON ir.id = i.run_id
    WHERE i.result_id = r.id AND (ir.finished_at IS NULL OR ir.finished_at >= :cutoff))
ORDER BY r.id
"""
)


async def _ti(
    session: AsyncSession, org_id: uuid.UUID, before: datetime, holds: HoldSet
) -> tuple[list[Candidate], int, int]:
    rows = await session.execute(
        _TI, {"org": org_id, "cutoff": before, "held": sorted(holds.investigation_ids)}
    )
    found: list[Candidate] = []
    cited = held = 0
    for result_id, job_id, case_id, items, is_cited, held_ref in rows.all():
        if held_ref or holds.covers(case_id):
            held += 1
        elif is_cited:
            cited += 1
        else:
            found.append(
                Candidate("ti_results", "ti_results", str(result_id), job_id, case_id, 1 + items, 0)
            )
    return found, cited, held


# --- ai_runs ---------------------------------------------------------------------------------

_AI_RUNS = text(
    """
SELECT r.id, r.parent_run_id, r.supersedes_run_id, r.status, r.finished_at, r.job_id,
       coalesce(r.investigation_id, ev.investigation_id) AS case_id
FROM ai_runs r
LEFT JOIN analysis_jobs j ON j.id = r.job_id
LEFT JOIN evidence ev ON ev.id = j.evidence_id
WHERE r.organization_id = :org
"""
)
_AI_CITED = text(
    """
SELECT ac.run_id FROM ai_citations ac JOIN report_citations rc ON rc.ai_citation_id = ac.id
WHERE rc.organization_id = :org
UNION
SELECT ac.run_id FROM ai_citations ac JOIN report_citations rc
  ON rc.ref_table = 'ai_citations' AND rc.ref_id = ac.id::text WHERE rc.organization_id = :org
UNION
SELECT o.run_id FROM ai_outputs o JOIN report_citations rc
  ON rc.ref_table = 'ai_outputs' AND rc.ref_id = o.id::text WHERE rc.organization_id = :org
UNION
SELECT r.id FROM ai_runs r JOIN report_citations rc
  ON rc.ref_table = 'ai_runs' AND rc.ref_id = r.id::text WHERE rc.organization_id = :org
"""
)
_AI_CHILDREN = text(
    """
SELECT run_id, sum(n)::bigint FROM (
  SELECT run_id, count(*) AS n FROM ai_run_inputs WHERE run_id = ANY(:ids) GROUP BY run_id
  UNION ALL
  SELECT run_id, count(*) FROM ai_context_refs WHERE run_id = ANY(:ids) GROUP BY run_id
  UNION ALL
  SELECT run_id, count(*) FROM ai_outputs WHERE run_id = ANY(:ids) GROUP BY run_id
  UNION ALL
  SELECT run_id, count(*) FROM ai_citations WHERE run_id = ANY(:ids) GROUP BY run_id
) x GROUP BY run_id
"""
)


def _components(edges: dict[uuid.UUID, list[uuid.UUID]]) -> list[list[uuid.UUID]]:
    """Connected run trees (parent and supersedes links, undirected), members sorted."""
    parent: dict[uuid.UUID, uuid.UUID] = {}

    def find(x: uuid.UUID) -> uuid.UUID:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for node, linked in edges.items():
        find(node)
        for other in linked:
            parent[find(node)] = find(other)
    groups: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
    for node in parent:
        groups[find(node)].append(node)
    return sorted((sorted(g) for g in groups.values()), key=lambda g: g[0])


async def ai_trees(
    session: AsyncSession, org_id: uuid.UUID, before: datetime, holds: HoldSet
) -> tuple[list[list[Candidate]], int, int]:
    """Eligible run trees (each a list of candidates), plus the kept-cited and held run
    counts of trees that were otherwise old enough."""
    runs = (await session.execute(_AI_RUNS, {"org": org_id})).all()
    cited = {r for (r,) in (await session.execute(_AI_CITED, {"org": org_id})).all()}
    info: dict[uuid.UUID, Any] = {r.id: r for r in runs}
    edges: dict[uuid.UUID, list[uuid.UUID]] = {r.id: [] for r in runs}
    for r in runs:
        for link in (r.parent_run_id, r.supersedes_run_id):
            if link is not None and link in edges:
                edges[r.id].append(link)
    trees: list[list[uuid.UUID]] = []
    kept = held = 0
    for tree in _components(edges):
        members = [info[m] for m in tree]
        if not all(
            m.status in AI_FINAL and m.finished_at is not None and m.finished_at < before
            for m in members
        ):
            continue
        if any(holds.covers(m.case_id) for m in members):
            held += len(members)
        elif any(m.id in cited for m in members):
            kept += len(members)
        else:
            trees.append(tree)
    ids = [m for tree in trees for m in tree]
    children: dict[uuid.UUID, int] = {}
    if ids:
        rows = await session.execute(_AI_CHILDREN, {"ids": ids})
        children = {run_id: int(n) for run_id, n in rows.all()}
    out = [
        [
            Candidate(
                "ai_runs",
                "ai_runs",
                str(m),
                info[m].job_id,
                info[m].case_id,
                # The run, its children and its (cascaded) ai_run_index row.
                2 + children.get(m, 0),
                0,
            )
            for m in tree
        ]
        for tree in trees
    ]
    return out, kept, held


# --- closed_case -----------------------------------------------------------------------------

_CLOSED_CASES = text(
    """
SELECT i.id FROM investigations i
JOIN LATERAL (
  SELECT e.to_status, e.occurred_at FROM investigation_status_events e
  WHERE e.investigation_id = i.id AND e.organization_id = i.organization_id
  ORDER BY e.occurred_at DESC, e.id DESC LIMIT 1
) last ON true
WHERE i.organization_id = :org
  AND i.status::text IN ('closed', 'archived')
  AND last.to_status IN ('closed', 'archived')
  AND last.occurred_at < :cutoff
  AND (CAST(:case_id AS uuid) IS NULL OR i.id = CAST(:case_id AS uuid))
  AND NOT EXISTS (
    SELECT 1 FROM analysis_jobs j JOIN evidence ev ON ev.id = j.evidence_id
    WHERE ev.investigation_id = i.id AND j.status::text IN ('queued', 'running'))
ORDER BY i.id
"""
)
_EVIDENCE = text(
    """
SELECT ev.id, ev.investigation_id, ev.storage_bucket, ev.storage_key, ev.storage_version_id,
       ev.size_bytes
FROM evidence ev
WHERE ev.organization_id = :org AND ev.investigation_id = ANY(:cases)
  AND NOT EXISTS (SELECT 1 FROM evidence_purges p WHERE p.evidence_id = ev.id)
ORDER BY ev.id
"""
)
_JOBS = text(
    """
SELECT j.id, ev.investigation_id, j.result_version_id,
  EXISTS (SELECT 1 FROM retention_run_items it
          WHERE it.organization_id = :org AND it.ref_table = 'analysis_jobs'
            AND it.ref_id = j.id::text AND it.outcome = 'purged'
            AND it.object_version_id = j.result_version_id) AS result_purged
FROM analysis_jobs j JOIN evidence ev ON ev.id = j.evidence_id
WHERE j.organization_id = :org AND ev.investigation_id = ANY(:cases)
ORDER BY j.id
"""
)
_CITED_ROWS = text(
    "SELECT ref_table, ref_id FROM report_citations "
    "WHERE organization_id = :org AND ref_table = ANY(:tables)"
)
_RENDERS = text(
    """
SELECT r.id, r.format, r.bytes, r.object_version_id, v.version, v.report_id, rp.investigation_id
FROM report_renders r
JOIN report_versions v ON v.id = r.version_id
JOIN reports rp ON rp.id = v.report_id
WHERE r.organization_id = :org AND rp.investigation_id = ANY(:cases)
  AND r.status = 'succeeded' AND r.object_version_id IS NOT NULL
ORDER BY r.id
"""
)


def _bulk_count(table: str) -> Any:
    # `table` is one of BULK_TABLES (a constant), never input.
    return text(
        f"SELECT t.job_id, count(*) FILTER (WHERE NOT (t.id::text = ANY(:cited))), "  # noqa: S608
        f"count(*) FILTER (WHERE t.id::text = ANY(:cited)) FROM {table} t "
        "WHERE t.organization_id = :org AND t.job_id = ANY(:jobs) GROUP BY t.job_id"
    )


async def closed_cases(
    session: AsyncSession,
    org_id: uuid.UUID,
    before: datetime,
    *,
    case_id: uuid.UUID | None = None,
) -> list[uuid.UUID]:
    """Cases closed / archived before `before` (by their latest status event), still closed
    and without a queued or running job; `case_id` re-checks one case."""
    rows = await session.execute(
        _CLOSED_CASES, {"org": org_id, "cutoff": before, "case_id": case_id}
    )
    return [case for (case,) in rows.all()]


async def cited_rows(session: AsyncSession, org_id: uuid.UUID) -> dict[str, list[str]]:
    """Bulk row ids cited by a report version, per table (kept, RT23)."""
    out: dict[str, list[str]] = {t: [] for t in BULK_TABLES}
    rows = await session.execute(_CITED_ROWS, {"org": org_id, "tables": list(BULK_TABLES)})
    for table, ref_id in rows.all():
        out[table].append(ref_id)
    return out


async def _closed_case(
    session: AsyncSession, org_id: uuid.UUID, before: datetime, holds: HoldSet
) -> tuple[list[Candidate], int, int]:
    cases = await closed_cases(session, org_id, before)
    if not cases:
        return [], 0, 0
    settings = get_settings()
    found: list[Candidate] = []
    kept = 0
    params = {"org": org_id, "cases": cases}
    for ev_id, case_id, bucket, key, version, size in (
        await session.execute(_EVIDENCE, params)
    ).all():
        found.append(
            Candidate(
                "closed_case", "evidence", str(ev_id), None, case_id, 0, size, bucket, key, version
            )
        )
    jobs = (await session.execute(_JOBS, params)).all()
    job_case = {job_id: case_id for job_id, case_id, _, _ in jobs}
    for job_id, case_id, result_version, purged in jobs:
        if result_version is not None and not purged:
            found.append(
                Candidate(
                    "closed_case",
                    "analysis_jobs",
                    str(job_id),
                    job_id,
                    case_id,
                    0,
                    0,
                    settings.results_bucket,
                    result_key(org_id, job_id),
                    result_version,
                )
            )
    if job_case:
        cited = await cited_rows(session, org_id)
        for table in BULK_TABLES:
            rows = await session.execute(
                _bulk_count(table),
                {"org": org_id, "jobs": list(job_case), "cited": cited[table]},
            )
            for job_id, purge, keep in rows.all():
                kept += keep
                if purge:
                    found.append(
                        Candidate(
                            "closed_case", table, str(job_id), job_id, job_case[job_id], purge, 0
                        )
                    )
    for render_id, fmt, size, version, number, report_id, case_id in (
        await session.execute(_RENDERS, params)
    ).all():
        found.append(
            Candidate(
                "closed_case",
                "report_renders",
                str(render_id),
                None,
                case_id,
                0,
                size or 0,
                settings.reports_bucket,
                render_key(org_id, report_id, number, render_id, fmt),
                version,
            )
        )
    held = [c for c in found if holds.covers(c.investigation_id)]
    found = sorted((c for c in found if not holds.covers(c.investigation_id)), key=_key)
    return found, kept, len(held)


async def candidates(
    session: AsyncSession,
    org_id: uuid.UUID,
    policy: EffectivePolicy,
    *,
    now: datetime,
    limit: int,
) -> CandidateSet:
    """Expired, unheld, uncited candidates of every enabled category. Counts cover every
    candidate; at most `limit` candidates per category are listed (an AI run tree is never
    split), and `truncated` says more exist."""
    out = CandidateSet()
    if policy.empty:
        return out
    holds = await active_holds(session, org_id, now=now)
    if holds.org_wide:
        return out
    if policy.ti_results_days is not None:
        found, cited, held = await _ti(session, org_id, cutoff(now, policy.ti_results_days), holds)
        _add(out, found, limit)
        out.counts["ti_results"].kept_cited += cited
        out.counts["ti_results"].skipped_hold += held
    if policy.ai_runs_days is not None:
        trees, cited, held = await ai_trees(
            session, org_id, cutoff(now, policy.ai_runs_days), holds
        )
        listed: list[Candidate] = []
        for tree in trees:
            if len(listed) >= limit:
                out.truncated = True
                break
            listed.extend(tree)
        _add(out, [c for tree in trees for c in tree], len(listed))
        out.counts["ai_runs"].kept_cited += cited
        out.counts["ai_runs"].skipped_hold += held
    if policy.closed_case_days is not None:
        found, cited, held = await _closed_case(
            session, org_id, cutoff(now, policy.closed_case_days), holds
        )
        _add(out, found, limit)
        out.counts["closed_case"].kept_cited += cited
        out.counts["closed_case"].skipped_hold += held
    return out
