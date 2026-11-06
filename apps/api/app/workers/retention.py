"""Retention sweep, per-org run and S3 legal-hold sync (M7 phase 3).

- `sweep()`: the daily beat task. Orgs come from the system lookup `retention_policy_index`
  (system session, RT3); each org with an effective policy gets a run (dry-run unless the
  DB says `enforce` is effective, RT1), the others a hold sync. Old `job_outcomes` rows go
  once per sweep. Returns the number of runs started.
- `run_org(org_id, run_id)`: one run (mode and values re-read from the DB, RT1), in per-org
  tenant sessions only, time-sliced (`RETENTION_RUN_SLICE_S`: the run is requeued with the
  same id). Enforce order per evidence: tombstone + custody `purged` + audit (commit), then
  delete the object version; a failed or interrupted delete is retried by the next run.
- `sync_holds(org_id)`: mirror the org's legal holds as S3 legal holds (RT5): a case hold on
  the case's evidence versions and report snapshots, an org hold on every evidence version of
  the org; bounded per call (an equal budget share per pass, ON passes first), resumable (a
  keyset cursor per hold, 0015), under the org's advisory lock. Returns the number of object
  versions changed.

Every org id comes from `retention_policy_index` or must be listed there (a message org that
is not is dropped). The process runs as `cyberlab_retention` (DELETE on the purgeable tables
only) and the MinIO user `cyberlab-purge` (no governance bypass, no snapshot delete).
"""

import logging
import time
import uuid
from collections import defaultdict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from minio.error import S3Error
from sqlalchemy import TextClause, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.audit import service as audit
from app.modules.evidence.models import CustodyAction, EvidenceCustodyEvent
from app.modules.retention import objects
from app.modules.retention import policy as policies
from app.modules.retention.holds import HoldSet, active_holds, delay
from app.modules.retention.models import (
    RUN_FINAL,
    EvidencePurge,
    LegalHold,
    OrgRetentionPolicy,
    RetentionPolicyIndex,
    RetentionRun,
    RetentionRunItem,
)
from app.modules.retention.select import (
    AI_FINAL,
    BULK_TABLES,
    CATEGORIES,
    Candidate,
    CandidateSet,
    EffectivePolicy,
    _components,
    candidates,
    cited_rows,
    closed_cases,
    cutoff,
)

log = logging.getLogger(__name__)

# Candidates listed per category and slice (counts always cover all of them).
CANDIDATE_LIMIT = 10_000
# S3 legal-hold sync bound per call (RT5): versions changed / versions inspected.
SYNC_CHANGES_MAX = 500
SYNC_INSPECT_MAX = 5_000
# A queued / running run older than this is abandoned (its worker died) and failed.
STALE_RUN = timedelta(hours=6)
MAX_SLICES = 50
COUNTERS = (
    "candidates",
    "rows",
    "bytes",
    "kept_cited",
    "skipped_hold",
    "skipped_locked",
    "object_delete_failed",
    "failed_batches",
)


@dataclass(frozen=True)
class RunOutcome:
    run_id: uuid.UUID
    status: str
    counts: dict[str, Any] = field(default_factory=dict)


# --- seams (tests run the executor in-process with the retention-role engine) ----------------


def _sessionmaker() -> async_sessionmaker[AsyncSession] | None:
    """None: the process engine (`DATABASE_URL` is the retention role's in this worker)."""
    return None


@asynccontextmanager
async def _session(org_id: uuid.UUID | None) -> AsyncIterator[AsyncSession]:
    # Every org id here comes from retention_policy_index (or was checked against it).
    async with tenant_session(org_id, None, sessionmaker=_sessionmaker()) as session:
        yield session


def _enqueue(org_id: uuid.UUID, run_id: uuid.UUID) -> None:
    """Queue `retention.run_org` on the retention queue (ids only, RT1)."""
    from cyberlab_jobs import RETENTION_RUN_ORG

    from app.workers.retention_app import celery_app, queues

    celery_app.send_task(
        RETENTION_RUN_ORG,
        kwargs={"message": {"org_id": str(org_id), "run_id": str(run_id)}},
        queue=queues.retention,
    )


def _now() -> datetime:
    return datetime.now(UTC)


def _system_user() -> uuid.UUID:
    return get_settings().retention_system_user_id


async def _lock_org(session: AsyncSession, org_id: uuid.UUID) -> None:
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
        {"k": f"retention:{org_id}"},
    )


async def _indexed(org_id: uuid.UUID) -> bool:
    async with _session(None) as s:
        found = await s.execute(
            select(RetentionPolicyIndex.organization_id).where(
                RetentionPolicyIndex.organization_id == org_id
            )
        )
        return found.scalar_one_or_none() is not None


async def _policy(session: AsyncSession, org_id: uuid.UUID) -> OrgRetentionPolicy | None:
    stmt = select(OrgRetentionPolicy).where(OrgRetentionPolicy.organization_id == org_id)
    return (await session.execute(stmt)).scalar_one_or_none()


# --- sweep -----------------------------------------------------------------------------------


async def _purge_job_outcomes(at: datetime) -> int:
    """`job_outcomes` (system table) older than RETENTION_JOB_OUTCOMES_DAYS, platform-wide."""
    days = get_settings().retention_job_outcomes_days
    try:
        async with _session(None) as s:
            result = await s.execute(
                text("DELETE FROM job_outcomes WHERE finished_at < :before"),
                {"before": at - timedelta(days=days)},
            )
            return int(getattr(result, "rowcount", 0) or 0)
    except DBAPIError as exc:
        # Only cyberlab_retention may delete; any other role logs and keeps going.
        log.error("retention: job_outcomes purge refused (%s)", type(exc.orig).__name__)
        return 0


async def _schedule(org_id: uuid.UUID, at: datetime) -> uuid.UUID | None:
    """A scheduled run for the org unless one is active or the policy keeps everything."""
    async with _session(org_id) as s:
        await _lock_org(s, org_id)
        active = (
            await s.execute(
                select(RetentionRun)
                .where(
                    RetentionRun.organization_id == org_id,
                    RetentionRun.status.in_(("queued", "running")),
                )
                .order_by(RetentionRun.created_at)
            )
        ).scalars()
        busy = False
        for run in active:
            if (run.started_at or run.created_at) < at - STALE_RUN:
                run.status, run.error, run.finished_at = "failed", "abandoned", at
            else:
                busy = True
        if busy:
            return None
        effective = policies.effective(await _policy(s, org_id), at)
        if effective.empty:
            return None
        run = RetentionRun(
            organization_id=org_id,
            mode="enforce" if effective.enforce else "dry_run",
            trigger="schedule",
            status="queued",
            policy=policies.run_policy(effective),
        )
        s.add(run)
        await s.flush()
        return run.id


async def sweep() -> int:
    at = _now()
    await _purge_job_outcomes(at)
    async with _session(None) as s:
        orgs = [
            org
            for (org,) in (
                await s.execute(
                    select(RetentionPolicyIndex.organization_id).order_by(
                        RetentionPolicyIndex.organization_id
                    )
                )
            ).all()
        ]
    started = 0
    for org_id in orgs:
        try:
            run_id = await _schedule(org_id, at)
            if run_id is None:
                await _sync(org_id, at)
                continue
            _enqueue(org_id, run_id)
            started += 1
        except Exception:  # noqa: BLE001 - one org's failure never stops the sweep
            log.exception("retention sweep failed for org %s", org_id)
    return started


# --- S3 legal-hold sync (RT5) ----------------------------------------------------------------

# What a hold covers, in one keyset order `(ts, id)`, `ts` being the row's own time (an
# evidence upload's `uploaded_at`, a report snapshot's `finalized_at`). A pass fetches at most
# its share of the budget after its cursor; a pass that runs out stores its cursor (0015) and
# the next sync resumes right after it, so no pass restarts or stalls, however many objects
# there are or share one timestamp.
#
# A case hold: the case's evidence versions and report snapshots (`evidence = false`: the
# snapshots only, for a released case hold while an org hold keeps the evidence ON).
_CASE_OBJECTS = text(
    """
SELECT bucket, key, version, ts, id FROM (
  SELECT storage_bucket AS bucket, storage_key AS key, storage_version_id AS version,
         uploaded_at AS ts, id
  FROM evidence
  WHERE organization_id = :org AND investigation_id = :case AND CAST(:evidence AS boolean)
  UNION ALL
  SELECT CAST(:reports AS text), v.object_key, v.object_version_id, v.finalized_at, v.id
  FROM report_versions v JOIN reports r ON r.id = v.report_id
  WHERE v.organization_id = :org AND r.investigation_id = :case
) o
WHERE (ts, id) > (CAST(:after_at AS timestamptz), CAST(:after_id AS uuid))
ORDER BY ts, id
LIMIT :limit
"""
)
# An org hold: every evidence version of the org, oldest first (their GOVERNANCE lock expires
# first), but the cases in `skip` (an OFF pass skips the cases a protecting case hold
# covers). The api's expired-lock delete grant covers the evidence buckets alone; report
# snapshots are undeletable by the api and the purge user; an org hold skips every purge run.
_ORG_EVIDENCE = text(
    """
SELECT storage_bucket, storage_key, storage_version_id, uploaded_at, id
FROM evidence
WHERE organization_id = :org
  AND (uploaded_at, id) > (CAST(:after_at AS timestamptz), CAST(:after_id AS uuid))
  AND investigation_id <> ALL (CAST(:skip AS uuid[]))
ORDER BY uploaded_at, id
LIMIT :limit
"""
)
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
# `(t, _MAX_ID)` as the keyset position: every object strictly after time `t`.
_MAX_ID = uuid.UUID(int=(1 << 128) - 1)
_Cursor = tuple[datetime, uuid.UUID]  # a keyset position: (ts, id)
# An upload's `uploaded_at` is its transaction's start: a row committed after a pass passed
# its time can carry an earlier one. A completed ON pass stores its START time and the next
# (incremental) pass re-inspects SYNC_SKEW before it, so such a row is never skipped.
SYNC_SKEW = timedelta(minutes=10)


@dataclass
class _Budget:
    inspect_max: int
    changes_max: int
    changed: int = 0
    inspected: int = 0

    @property
    def spent(self) -> bool:
        return self.changed >= self.changes_max or self.inspected >= self.inspect_max

    def share(self, plans_left: int) -> "_Budget":
        """An equal share of what is left, so every plan progresses on every sync (M1)."""
        return _Budget(
            max(1, (self.inspect_max - self.inspected) // plans_left),
            max(1, (self.changes_max - self.changed) // plans_left),
        )

    def add(self, spent: "_Budget") -> None:
        self.changed += spent.changed
        self.inspected += spent.inspected


async def _mirror(objs: list[tuple[str, str, str]], on: bool, budget: _Budget) -> int:
    """Set every version's S3 legal hold to `on`, in order. Returns how many versions were
    handled before the budget ran out or a call failed (the next sync continues there)."""
    done = 0
    for bucket, key, version in objs:
        if budget.spent:
            return done
        try:
            current = await objects.legal_hold(bucket, key, version)
            budget.inspected += 1
            if current is not None and current != on:  # None: gone (purged)
                await objects.set_legal_hold(bucket, key, version, on)
                budget.changed += 1
        except S3Error as exc:
            log.warning("retention hold sync: %s on %s failed (%s)", on, bucket, exc.code)
            return done
        except Exception as exc:  # noqa: BLE001 - a transport error: keep what is done
            name = type(exc).__name__
            log.warning("retention hold sync: %s on %s failed (%s)", on, bucket, name)
            return done
        done += 1
    return done


@dataclass
class _Plan:
    hold: LegalHold
    on: bool
    query: TextClause
    params: dict[str, Any]
    # The stored cursor of this pass when it resumes one, and when the pass started.
    cursor: _Cursor | None
    pass_at: datetime
    since: datetime  # a fresh pass: every object strictly after this time


@dataclass(frozen=True)
class _State:
    synced: datetime | None
    full: datetime | None
    cursor: _Cursor | None
    pass_at: datetime | None


def _protecting(h: LegalHold, at: datetime) -> bool:
    return h.released_at is None or h.released_at + delay() > at


def _ended(h: LegalHold, at: datetime) -> datetime:
    return h.released_at + delay() if h.released_at else at


def _resume(h: LegalHold, on: bool, at: datetime) -> tuple[_Cursor | None, datetime]:
    """The stored cursor and pass start when they belong to a pass in this direction, else a
    fresh pass from `at`. A pass's direction follows from its start: ON passes start while
    the hold protects (`at < released_at + delay`), OFF passes after; `pass_at` is that same
    `at`, compared the same way, so the test is exact whatever the clocks."""
    if h.s3_sync_cursor_at is None or h.s3_sync_cursor_id is None or h.s3_sync_pass_at is None:
        return None, at
    off_pass = h.released_at is not None and h.s3_sync_pass_at >= h.released_at + delay()
    if off_pass == on:
        return None, at  # e.g. an ON pass interrupted when the delay ended: OFF starts anew
    return (h.s3_sync_cursor_at, h.s3_sync_cursor_id), h.s3_sync_pass_at


def _on_since(h: LegalHold) -> datetime:
    """Where a fresh ON pass starts: the beginning until the first full pass completed (M2),
    then SYNC_SKEW before the last completed pass started (incremental)."""
    if h.s3_full_synced_at is None or h.s3_synced_at is None:
        return _EPOCH
    return h.s3_synced_at - SYNC_SKEW


def _plan(h: LegalHold, on: bool, at: datetime, query: TextClause, params: dict[str, Any]) -> _Plan:
    cursor, pass_at = _resume(h, on, at)
    return _Plan(h, on, query, params, cursor, pass_at, _on_since(h) if on else _EPOCH)


def _case_plan(h: LegalHold, on: bool, at: datetime, reports: str, *, evidence: bool) -> _Plan:
    params = {"case": h.investigation_id, "reports": reports, "evidence": evidence}
    return _plan(h, on, at, _CASE_OBJECTS, params)


def _org_plan(h: LegalHold, on: bool, at: datetime, skip: set[uuid.UUID]) -> _Plan:
    return _plan(h, on, at, _ORG_EVIDENCE, {"skip": sorted(skip)})


def _current(h: LegalHold) -> _State:
    cursor = (
        (h.s3_sync_cursor_at, h.s3_sync_cursor_id)
        if h.s3_sync_cursor_at is not None and h.s3_sync_cursor_id is not None
        else None
    )
    pass_at = h.s3_sync_pass_at if cursor else None
    return _State(h.s3_synced_at, h.s3_full_synced_at, cursor, pass_at)


def _after(plan: _Plan, rows: list[Any], done: int, limit: int, at: datetime) -> _State:
    """The hold's sync state after a pass handled `done` of the `rows` it fetched (at most
    `limit`). Complete (every remaining object handled): an ON pass stores its start time and
    marks the first full pass; an OFF pass its end. Else the cursor of the last handled
    object (or the one it resumed from), and the pass start."""
    h = plan.hold
    if done == len(rows) and len(rows) < limit:
        if plan.on:
            return _State(plan.pass_at, h.s3_full_synced_at or at, None, None)
        return _State(at, h.s3_full_synced_at, None, None)
    cursor = (rows[done - 1][3], rows[done - 1][4]) if done else plan.cursor
    return _State(h.s3_synced_at, h.s3_full_synced_at, cursor, plan.pass_at if cursor else None)


async def _execute(
    s: AsyncSession, org_id: uuid.UUID, plan: _Plan, budget: _Budget, at: datetime
) -> _State:
    after_at, after_id = plan.cursor or (plan.since, _MAX_ID)
    limit = budget.inspect_max
    params = {**plan.params, "org": org_id, "after_at": after_at, "after_id": after_id}
    rows = list((await s.execute(plan.query, {**params, "limit": limit})).all())
    done = await _mirror([(str(r[0]), str(r[1]), str(r[2])) for r in rows], plan.on, budget)
    return _after(plan, rows, done, limit, at)


async def _store(s: AsyncSession, h: LegalHold, state: _State) -> None:
    if state == _current(h):
        return
    await s.execute(
        text(
            "UPDATE legal_holds SET s3_synced_at = :synced, s3_full_synced_at = :full, "
            "s3_sync_cursor_at = :cursor_at, s3_sync_cursor_id = :cursor_id, "
            "s3_sync_pass_at = :pass_at WHERE id = :id"
        ),
        {
            "synced": state.synced,
            "full": state.full,
            "cursor_at": state.cursor[0] if state.cursor else None,
            "cursor_id": state.cursor[1] if state.cursor else None,
            "pass_at": state.pass_at,
            "id": h.id,
        },
    )


def _plans(
    holds: list[LegalHold], at: datetime, reports: str
) -> tuple[list[_Plan], list[LegalHold]]:
    """The passes this sync runs (ON before OFF, M1) and the released holds it only stamps.

    A protecting hold (active, or released within the delay) keeps its objects ON. A release
    turns them OFF only after the delay, and only where no other protecting hold covers them:
    an org hold covers every evidence version (not the report snapshots), a case hold its
    case's evidence and snapshots."""
    protecting = [h for h in holds if _protecting(h, at)]
    org_hold = any(h.scope == "org" for h in protecting)
    covered = {h.investigation_id for h in protecting if h.investigation_id is not None}
    on: list[_Plan] = []
    off: list[_Plan] = []
    stamp_only: list[LegalHold] = []
    for h in holds:
        if h.scope != "org" and h.investigation_id is None:
            continue
        if _protecting(h, at):
            if h.scope == "org":
                on.append(_org_plan(h, True, at, set()))
            else:
                on.append(_case_plan(h, True, at, reports, evidence=True))
            continue
        if h.s3_synced_at is not None and h.s3_synced_at >= _ended(h, at):
            continue  # its OFF pass (or stamp) is done
        if h.scope == "org":
            if org_hold:
                stamp_only.append(h)  # another org hold keeps everything ON
            else:
                off.append(_org_plan(h, False, at, covered))
        elif h.investigation_id in covered:
            stamp_only.append(h)  # another case hold keeps the case ON
        else:
            # Under an org hold the evidence stays ON, the case's snapshots go OFF (L1).
            off.append(_case_plan(h, False, at, reports, evidence=not org_hold))
    return on + off, stamp_only


async def _sync(org_id: uuid.UUID, at: datetime) -> int:
    """Legal holds -> S3 legal holds (RT5), bounded per call (SYNC_INSPECT_MAX inspected,
    SYNC_CHANGES_MAX changed, shared equally by the passes) and resumable (0015).

    One transaction under the org's advisory lock (L2): two syncs of an org (the sweep, a
    run, a placed hold's message) never interleave, so a pass never works from holds read
    before another sync's writes; a waiting sync reads the holds after the lock."""
    reports = get_settings().reports_bucket
    total = _Budget(SYNC_INSPECT_MAX, SYNC_CHANGES_MAX)
    async with _session(org_id) as s:
        await _lock_org(s, org_id)
        holds = list(
            (
                await s.execute(
                    select(LegalHold)
                    .where(LegalHold.organization_id == org_id)
                    .order_by(LegalHold.placed_at, LegalHold.id)
                )
            ).scalars()
        )
        plans, stamp_only = _plans(holds, at, reports)
        for h in stamp_only:
            await _store(s, h, _State(at, h.s3_full_synced_at, None, None))
        for i, plan in enumerate(plans):
            if total.spent:
                break  # the rest keep their cursors; the next sync continues
            share = total.share(len(plans) - i)
            state = await _execute(s, org_id, plan, share, at)
            total.add(share)
            await _store(s, plan.hold, state)
    return total.changed


async def sync_holds(org_id: uuid.UUID) -> int:
    if not await _indexed(org_id):
        log.info("retention hold sync: org not in retention_policy_index, dropped")
        return 0
    return await _sync(org_id, _now())


# --- run bookkeeping -------------------------------------------------------------------------


def _zero() -> dict[str, int]:
    return dict.fromkeys(COUNTERS, 0)


@dataclass
class _Run:
    org_id: uuid.UUID
    run_id: uuid.UUID
    at: datetime
    policy: EffectivePolicy
    enforce: bool
    started: float
    counts: dict[str, dict[str, int]]
    items: list[RetentionRunItem] = field(default_factory=list)

    def timed_out(self) -> bool:
        return time.monotonic() - self.started > get_settings().retention_run_slice_s

    def bump(self, category: str, name: str, by: int = 1) -> None:
        self.counts[category][name] = self.counts[category].get(name, 0) + by

    def item(
        self,
        c: Candidate,
        outcome: str,
        *,
        rows: int | None = None,
        ref_id: str | None = None,
        job_id: uuid.UUID | None = None,
    ) -> None:
        self.items.append(
            RetentionRunItem(
                organization_id=self.org_id,
                run_id=self.run_id,
                category=c.category,
                ref_table=c.ref_table,
                ref_id=ref_id or c.ref_id,
                job_id=job_id if job_id is not None else c.job_id,
                rows=c.rows if rows is None else rows,
                bytes=c.bytes if c.object_key or c.ref_table == "evidence" else 0,
                object_key=c.object_key,
                object_version_id=c.object_version_id if c.object_key else None,
                outcome=outcome,
            )
        )

    async def flush_items(self, session: AsyncSession | None = None) -> None:
        if not self.items:
            return
        pending, self.items = self.items, []
        if session is not None:
            session.add_all(pending)
            return
        async with _session(self.org_id) as s:
            s.add_all(pending)


def _merge(stored: dict[str, Any]) -> dict[str, dict[str, int]]:
    out = {c: _zero() for c in CATEGORIES}
    for category in CATEGORIES:
        for name, value in (stored.get(category) or {}).items():
            if name in out[category] and isinstance(value, int):
                out[category][name] = value
    out["_slices"] = {"n": int((stored.get("_slices") or {}).get("n", 0))}
    return out


def _sample(found: CandidateSet) -> list[dict[str, Any]]:
    from app.modules.retention.service import sample

    return sample(found, get_settings().retention_sample_limit)


async def _save(run: _Run, *, status: str | None = None, error: str | None = None) -> None:
    async with _session(run.org_id) as s:
        row = await s.get(RetentionRun, run.run_id)
        if row is None or row.status in RUN_FINAL:
            return
        row.counts = {k: dict(v) for k, v in run.counts.items()}
        if status is not None:
            row.status = status
            row.finished_at = _now()
        if error is not None:
            row.error = error
        if status in RUN_FINAL:
            audit.record(
                s,
                action="retention.run_completed",
                org_id=run.org_id,
                actor_id=_system_user(),
                target_type="retention_run",
                target_id=run.run_id,
                details={
                    "mode": "enforce" if run.enforce else "dry_run",
                    "status": status,
                    "error": error,
                    "counts": {c: dict(run.counts[c]) for c in CATEGORIES},
                },
            )


# --- the per-org run -------------------------------------------------------------------------


async def run_org(org_id: uuid.UUID, run_id: uuid.UUID) -> RunOutcome:
    if not await _indexed(org_id):
        log.warning("retention run %s: org not in retention_policy_index, dropped", run_id)
        return RunOutcome(run_id, "failed")
    at = _now()
    async with _session(org_id) as s:
        row = await s.get(RetentionRun, run_id)
        if row is None or row.organization_id != org_id:
            log.warning("retention run %s: not a run of this org, dropped", run_id)
            return RunOutcome(run_id, "failed")
        if row.status in RUN_FINAL:
            return RunOutcome(run_id, row.status, row.counts)
        effective = policies.effective(await _policy(s, org_id), at)
        holds = await active_holds(s, org_id, now=at)
        mode = row.mode
        first_slice = row.started_at is None
        row.status = "running"
        if first_slice:
            row.started_at = at
        counts = _merge(row.counts)
        counts["_slices"]["n"] += 1
        downgraded = mode == "enforce" and not effective.enforce
        if downgraded and first_slice:
            audit.record(
                s,
                action="retention.run_downgraded",
                org_id=org_id,
                actor_id=_system_user(),
                target_type="retention_run",
                target_id=run_id,
                details={"reason": "enforce_not_effective"},
            )
    run = _Run(
        org_id=org_id,
        run_id=run_id,
        at=at,
        policy=effective,
        enforce=mode == "enforce" and effective.enforce,
        started=time.monotonic(),
        counts=counts,
    )
    error = "enforce_not_effective" if downgraded else None
    try:
        await _sync(org_id, at)  # an org hold too: its S3 mirror (RT5)
        if holds.org_wide:
            await _save(run, status="completed", error="skipped_hold")
            return RunOutcome(run_id, "completed", run.counts)
        finished = await (_enforce(run) if run.enforce else _dry_run(run, first_slice))
        if not finished:
            if counts["_slices"]["n"] >= MAX_SLICES:
                await _save(run, status="partial", error="slice_limit")
                return RunOutcome(run_id, "partial", run.counts)
            await _save(run)
            _enqueue(org_id, run_id)
            return RunOutcome(run_id, "running", run.counts)
        failed = any(
            run.counts[c]["object_delete_failed"] or run.counts[c]["failed_batches"]
            for c in CATEGORIES
        )
        status = "partial" if failed else "completed"
        await _save(run, status=status, error=error)
        return RunOutcome(run_id, status, run.counts)
    except Exception:
        log.exception("retention run %s failed", run_id)
        await run.flush_items()
        await _save(run, status="failed", error="run_failed")
        return RunOutcome(run_id, "failed", run.counts)


async def _select(run: _Run) -> CandidateSet:
    async with _session(run.org_id) as s:
        return await candidates(s, run.org_id, run.policy, now=run.at, limit=CANDIDATE_LIMIT)


def _set_selection_counts(run: _Run, found: CandidateSet) -> None:
    for category, n in found.counts.items():
        run.counts[category]["kept_cited"] = n.kept_cited
        run.counts[category]["skipped_hold"] = max(
            run.counts[category]["skipped_hold"], n.skipped_hold
        )


async def _store_sample(run: _Run, found: CandidateSet) -> None:
    async with _session(run.org_id) as s:
        row = await s.get(RetentionRun, run.run_id)
        if row is not None and not row.sample:
            row.sample = _sample(found)


async def _dry_run(run: _Run, first_slice: bool) -> bool:
    """Counts, sample and the object checks an enforce run would make (skipped locked or
    held versions get items); nothing is deleted."""
    found = await _select(run)
    for category in CATEGORIES:
        run.counts[category] = _zero()
    for category, n in found.counts.items():
        c = run.counts[category]
        c.update(candidates=n.candidates, rows=n.rows, bytes=n.bytes)
    _set_selection_counts(run, found)
    for cand in found.candidates:
        if cand.ref_table not in ("evidence", "report_renders") or cand.object_key is None:
            continue
        outcome = await _object_check(run, cand)
        if outcome is not None:
            run.item(cand, outcome)
            run.bump(cand.category, outcome)
            run.bump(cand.category, "candidates", -1)
            run.bump(cand.category, "bytes", -cand.bytes)
    await run.flush_items()
    if first_slice:
        await _store_sample(run, found)
    return True


async def _object_check(run: _Run, c: Candidate) -> str | None:
    """`skipped_hold` / `skipped_locked` from MinIO now (never the DB's estimate)."""
    if not (c.object_bucket and c.object_key and c.object_version_id):
        return None
    lock = await objects.lock_state(c.object_bucket, c.object_key, c.object_version_id)
    if lock.present and lock.legal_hold:
        return "skipped_hold"
    if lock.present and lock.locked(run.at):
        return "skipped_locked"
    return None


async def _enforce(run: _Run) -> bool:
    """Purge in batches; False when the slice ran out (the run is requeued)."""
    if not await _retry_deletes(run):
        return False
    found = await _select(run)
    _set_selection_counts(run, found)
    await _store_sample(run, found)
    by_kind: dict[str, list[Candidate]] = defaultdict(list)
    for c in found.candidates:
        by_kind[c.category if c.category != "closed_case" else c.ref_table].append(c)
    steps = [
        ("ti_results", _purge_ti),
        ("ai_runs", _purge_ai),
        ("evidence", _purge_evidence),
        ("report_renders", _purge_renders),
        ("analysis_jobs", _purge_results),
    ]
    for kind, step in steps:
        if by_kind.get(kind) and not await step(run, by_kind[kind]):
            return False
    bulk = [c for table in BULK_TABLES for c in by_kind.get(table, [])]
    if bulk and not await _purge_bulk(run, bulk):
        return False
    return not found.truncated


# --- purge steps (enforce) -------------------------------------------------------------------


async def _case_purgeable(s: AsyncSession, run: _Run, case_id: uuid.UUID | None) -> bool:
    """Re-check inside the purge transaction: no hold, still closed long enough, no active
    job (the selector's rule for this one case)."""
    if case_id is None or run.policy.closed_case_days is None:
        return False
    holds = await active_holds(s, run.org_id, now=run.at)
    if holds.covers(case_id):
        return False
    before = cutoff(run.at, run.policy.closed_case_days)
    return bool(await closed_cases(s, run.org_id, before, case_id=case_id))


async def _held(run: _Run) -> HoldSet:
    async with _session(run.org_id) as s:
        return await active_holds(s, run.org_id, now=run.at)


def _record_delete(run: _Run, c: Candidate, ok: bool) -> None:
    if ok:
        run.item(c, "purged")
        run.bump(c.category, "candidates")
        run.bump(c.category, "bytes", c.bytes)
    else:
        run.item(c, "object_delete_failed")
        run.bump(c.category, "object_delete_failed")


async def _delete(c: Candidate) -> bool:
    if not (c.object_bucket and c.object_key and c.object_version_id):
        return False
    try:
        await objects.delete_version(c.object_bucket, c.object_key, c.object_version_id)
    except S3Error as exc:
        log.warning("retention: delete of a %s version failed (%s)", c.ref_table, exc.code)
        return False
    return True


async def _purge_evidence(run: _Run, cands: list[Candidate]) -> bool:
    for c in cands:
        if run.timed_out():
            await run.flush_items()
            return False
        evidence_id = uuid.UUID(c.ref_id)
        async with _session(run.org_id) as s:
            if not await _case_purgeable(s, run, c.investigation_id):
                continue
            if await s.get(EvidencePurge, evidence_id) is not None:
                continue
        outcome = await _object_check(run, c)
        if outcome is not None:
            run.item(c, outcome)
            run.bump(c.category, outcome)
            continue
        try:
            async with _session(run.org_id) as s:
                sha256 = (
                    await s.execute(
                        text(
                            "SELECT value FROM evidence_hashes WHERE evidence_id = :e "
                            "AND algorithm::text = 'sha256'"
                        ),
                        {"e": evidence_id},
                    )
                ).scalar_one()
                # The tombstone, custody and audit commit before the delete (RT22).
                s.add(
                    EvidencePurge(
                        evidence_id=evidence_id,
                        organization_id=run.org_id,
                        run_id=run.run_id,
                        object_version_id=c.object_version_id,
                        sha256=sha256,
                    )
                )
                details = {"run_id": str(run.run_id), "version_id": c.object_version_id}
                s.add(
                    EvidenceCustodyEvent(
                        organization_id=run.org_id,
                        evidence_id=evidence_id,
                        action=CustodyAction.PURGED,
                        actor_id=_system_user(),
                        details=details,
                    )
                )
                audit.record(
                    s,
                    action="evidence.purged",
                    org_id=run.org_id,
                    actor_id=_system_user(),
                    target_type="evidence",
                    target_id=evidence_id,
                    details={"run_id": str(run.run_id), "bytes": c.bytes},
                )
        except IntegrityError:
            continue  # tombstoned concurrently
        _record_delete(run, c, await _delete(c))
        await run.flush_items()
    return True


async def _purge_renders(run: _Run, cands: list[Candidate]) -> bool:
    size = get_settings().retention_batch_objects
    for start in range(0, len(cands), size):
        if run.timed_out():
            return False
        batch = cands[start : start + size]
        ready: list[Candidate] = []
        async with _session(run.org_id) as s:
            ok_cases = {
                case: await _case_purgeable(s, run, case)
                for case in {c.investigation_id for c in batch}
            }
        for c in batch:
            if not ok_cases[c.investigation_id]:
                continue
            outcome = await _object_check(run, c)
            if outcome is not None:
                run.item(c, outcome)
                run.bump(c.category, outcome)
            else:
                ready.append(c)
        if ready:
            async with _session(run.org_id) as s:
                marked = {
                    str(r)
                    for (r,) in (
                        await s.execute(
                            text(
                                "UPDATE report_renders SET status = 'purged' "
                                "WHERE id = ANY(:ids) AND status = 'succeeded' RETURNING id"
                            ),
                            {"ids": [uuid.UUID(c.ref_id) for c in ready]},
                        )
                    ).all()
                }
            for c in ready:
                if c.ref_id in marked:
                    _record_delete(run, c, await _delete(c))
        await run.flush_items()
    return True


async def _purge_results(run: _Run, cands: list[Candidate]) -> bool:
    """Derived `results` objects (unlocked bucket): delete, then the `purged` item, so a
    crash in between only repeats an idempotent delete."""
    size = get_settings().retention_batch_objects
    for start in range(0, len(cands), size):
        if run.timed_out():
            return False
        batch = cands[start : start + size]
        async with _session(run.org_id) as s:
            ok_cases = {
                case: await _case_purgeable(s, run, case)
                for case in {c.investigation_id for c in batch}
            }
        for c in batch:
            if ok_cases[c.investigation_id]:
                _record_delete(run, c, await _delete(c))
        await run.flush_items()
    return True


def _delete_sql(table: str) -> Any:
    # `table` is one of BULK_TABLES (a constant), never input.
    return text(
        f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} "  # noqa: S608
        "WHERE organization_id = :org AND job_id = :job AND NOT (id::text = ANY(:cited)) "
        "ORDER BY id LIMIT :n)"
    )


async def _purge_bulk(run: _Run, cands: list[Candidate]) -> bool:
    """`DELETE ... ` in batches of RETENTION_BATCH_ROWS per job and table (cited rows stay,
    RT23); each batch commits with its item."""
    n = get_settings().retention_batch_rows
    async with _session(run.org_id) as s:
        cited = await cited_rows(s, run.org_id)
    for c in cands:
        while c.job_id is not None:
            if run.timed_out():
                return False
            try:
                async with _session(run.org_id) as s:
                    if not await _case_purgeable(s, run, c.investigation_id):
                        break
                    result = await s.execute(
                        _delete_sql(c.ref_table),
                        {"org": run.org_id, "job": c.job_id, "cited": cited[c.ref_table], "n": n},
                    )
                    deleted = int(getattr(result, "rowcount", 0) or 0)
                    if deleted:
                        run.item(c, "purged", rows=deleted)
                        run.bump(c.category, "rows", deleted)
                        await run.flush_items(s)
            except DBAPIError as exc:
                log.error("retention: %s batch failed (%s)", c.ref_table, type(exc.orig).__name__)
                run.items.clear()
                run.bump(c.category, "failed_batches")
                break
            if deleted < n:
                run.bump(c.category, "candidates")
                await _kept_cited_item(run, c, cited[c.ref_table])
                break
    return True


def _cited_count_sql(table: str) -> Any:
    # `table` is one of BULK_TABLES (a constant), never input.
    return text(
        f"SELECT count(*) FROM {table} WHERE organization_id = :org AND job_id = :job "  # noqa: S608
        "AND id::text = ANY(:cited)"
    )


async def _kept_cited_item(run: _Run, c: Candidate, cited: list[str]) -> None:
    """The rows of this job and table that a report cites stay: one `kept_cited` item."""
    if not cited:
        return
    async with _session(run.org_id) as s:
        kept = (
            await s.execute(
                _cited_count_sql(c.ref_table), {"org": run.org_id, "job": c.job_id, "cited": cited}
            )
        ).scalar_one()
        if kept:
            run.item(c, "kept_cited", rows=int(kept))
            await run.flush_items(s)


def _batches(groups: list[list[Candidate]], max_rows: int) -> list[list[Candidate]]:
    """Whole groups (AI run trees) packed into batches of about `max_rows` rows."""
    out: list[list[Candidate]] = []
    current: list[Candidate] = []
    rows = 0
    for group in groups:
        size = sum(c.rows for c in group)
        if current and rows + size > max_rows:
            out.append(current)
            current, rows = [], 0
        current.extend(group)
        rows += size
    if current:
        out.append(current)
    return out


def _grouped_items(run: _Run, done: list[Candidate], table: str) -> None:
    """One item per job (or case / manual) of a TI or AI batch, with its row count."""
    groups: dict[tuple[uuid.UUID | None, str], list[Candidate]] = defaultdict(list)
    for c in done:
        label = str(c.job_id or c.investigation_id or "manual")
        groups[(c.job_id, label)].append(c)
    for (job_id, label), members in sorted(groups.items(), key=lambda g: g[0][1]):
        rows = sum(m.rows for m in members)
        run.item(members[0], "purged", rows=rows, ref_id=label, job_id=job_id)
        run.bump(members[0].category, "candidates", len(members))
        run.bump(members[0].category, "rows", rows)


async def _purge_ti(run: _Run, cands: list[Candidate]) -> bool:
    if run.policy.ti_results_days is None:
        return True
    before = cutoff(run.at, run.policy.ti_results_days)
    for batch in _batches([[c] for c in cands], get_settings().retention_batch_rows):
        if run.timed_out():
            return False
        holds = await _held(run)
        batch = [c for c in batch if not holds.covers(c.investigation_id)]
        ids = [uuid.UUID(c.ref_id) for c in batch]
        if not ids:
            continue
        try:
            async with _session(run.org_id) as s:
                # Items first (FK, RT10), only those of runs finished before the cutoff; an
                # answer reused since the selection keeps its newer item and stays.
                await s.execute(
                    text(
                        "DELETE FROM ti_run_items i USING ti_enrichment_runs r "
                        "WHERE r.id = i.run_id AND i.result_id = ANY(:ids) "
                        "AND r.finished_at < :before"
                    ),
                    {"ids": ids, "before": before},
                )
                gone = {
                    str(r)
                    for (r,) in (
                        await s.execute(
                            text(
                                "DELETE FROM ti_results t WHERE t.id = ANY(:ids) "
                                "AND NOT EXISTS (SELECT 1 FROM ti_run_items i "
                                "WHERE i.result_id = t.id) RETURNING t.id"
                            ),
                            {"ids": ids},
                        )
                    ).all()
                }
                _grouped_items(run, [c for c in batch if c.ref_id in gone], "ti_results")
                await run.flush_items(s)
        except DBAPIError as exc:
            log.error("retention: ti_results batch failed (%s)", type(exc.orig).__name__)
            run.items.clear()
            run.bump("ti_results", "failed_batches")
    return True


_AI_LINKS = text("SELECT id, parent_run_id, supersedes_run_id FROM ai_runs WHERE id = ANY(:ids)")
# Children in FK order (citations reference outputs); ai_run_index cascades from ai_runs.
_AI_CHILD_TABLES = ("ai_citations", "ai_outputs", "ai_context_refs", "ai_run_inputs")


async def _purge_ai(run: _Run, cands: list[Candidate]) -> bool:
    if run.policy.ai_runs_days is None:
        return True
    before = cutoff(run.at, run.policy.ai_runs_days)
    by_id = {uuid.UUID(c.ref_id): c for c in cands}
    async with _session(run.org_id) as s:
        links = (await s.execute(_AI_LINKS, {"ids": list(by_id)})).all()
    edges: dict[uuid.UUID, list[uuid.UUID]] = {i: [] for i in by_id}
    for run_id, parent, supersedes in links:
        edges[run_id].extend(x for x in (parent, supersedes) if x in by_id)
    trees = [[by_id[m] for m in tree] for tree in _components(edges)]
    for batch in _batches(trees, get_settings().retention_batch_rows):
        if run.timed_out():
            return False
        holds = await _held(run)
        if any(holds.covers(c.investigation_id) for c in batch):
            # A hold placed since the selection: keep the batch (whole trees) this run.
            continue
        ids = [uuid.UUID(c.ref_id) for c in batch]
        try:
            async with _session(run.org_id) as s:
                for table in _AI_CHILD_TABLES:
                    await s.execute(
                        text(f"DELETE FROM {table} WHERE run_id = ANY(:ids)"),  # noqa: S608
                        {"ids": ids},
                    )
                deleted = await s.execute(
                    text(
                        "DELETE FROM ai_runs WHERE id = ANY(:ids) AND status = ANY(:final) "
                        "AND finished_at < :before RETURNING id"
                    ),
                    {"ids": ids, "final": list(AI_FINAL), "before": before},
                )
                if len(deleted.all()) != len(ids):
                    raise RuntimeError("an AI run changed since the selection")
                _grouped_items(run, batch, "ai_runs")
                await run.flush_items(s)
        except (DBAPIError, RuntimeError) as exc:
            log.error("retention: ai_runs batch failed (%s)", type(exc).__name__)
            run.items.clear()
            run.bump("ai_runs", "failed_batches")
    return True


# --- retries of earlier deletes (RT22) -------------------------------------------------------

_PENDING_EVIDENCE = text(
    """
SELECT p.evidence_id, ev.investigation_id, ev.storage_bucket, ev.storage_key,
       ev.storage_version_id, ev.size_bytes
FROM evidence_purges p JOIN evidence ev ON ev.id = p.evidence_id
WHERE p.organization_id = :org AND NOT EXISTS (
  SELECT 1 FROM retention_run_items it WHERE it.organization_id = :org
  AND it.ref_table = 'evidence' AND it.ref_id = p.evidence_id::text AND it.outcome = 'purged')
ORDER BY p.purged_at, p.evidence_id
LIMIT :n
"""
)
_PENDING_RENDERS = text(
    """
SELECT r.id, rp.investigation_id, r.format, r.bytes, r.object_version_id, v.version,
       v.report_id
FROM report_renders r
JOIN report_versions v ON v.id = r.version_id
JOIN reports rp ON rp.id = v.report_id
WHERE r.organization_id = :org AND r.status = 'purged' AND r.object_version_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM retention_run_items it WHERE it.organization_id = :org
    AND it.ref_table = 'report_renders' AND it.ref_id = r.id::text AND it.outcome = 'purged')
ORDER BY r.id
LIMIT :n
"""
)


async def _retry_deletes(run: _Run) -> bool:
    """Tombstoned evidence and purged renders whose version was not confirmed deleted (a
    failed delete, or a crash between the commit and the delete): delete them now."""
    from app.modules.reports.dispatch import render_key

    settings = get_settings()
    n = settings.retention_batch_objects
    async with _session(run.org_id) as s:
        evidence = (await s.execute(_PENDING_EVIDENCE, {"org": run.org_id, "n": n})).all()
        renders = (await s.execute(_PENDING_RENDERS, {"org": run.org_id, "n": n})).all()
    pending = [
        Candidate("closed_case", "evidence", str(e), None, case, 0, size, bucket, key, version)
        for e, case, bucket, key, version, size in evidence
    ] + [
        Candidate(
            "closed_case",
            "report_renders",
            str(r),
            None,
            case,
            0,
            size or 0,
            settings.reports_bucket,
            render_key(run.org_id, report_id, number, r, fmt),
            version,
        )
        for r, case, fmt, size, version, number, report_id in renders
    ]
    for c in pending:
        if run.timed_out():
            await run.flush_items()
            return False
        outcome = await _object_check(run, c)
        if outcome is not None:
            run.item(c, outcome)
            run.bump(c.category, outcome)
            continue
        _record_delete(run, c, await _delete(c))
    await run.flush_items()
    return True
