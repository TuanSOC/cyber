"""Retention policy, preview, runs and legal holds (the API side, M7 phase 3).

The API never deletes anything: it stores the policy (lowering a value or arming `enforce`
waits for the delay, RT1), previews candidates read-only through the shared selector, records
legal holds and queues runs. Purging and the S3 legal-hold mirror belong to the retention
worker (RT5); tasks are published after the commit and carry ids only (RT1).
"""

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import anyio
from cyberlab_jobs import RETENTION_RUN_ORG, RETENTION_SYNC_HOLDS, Queues
from starlette.requests import HTTPConnection

from app.core.config import get_settings
from app.core.errors import AppError, Conflict, NotFound
from app.core.pagination import PageParams
from app.core.rbac import OrgContext
from app.core.threads import broker_limiter
from app.modules.audit import service as audit
from app.modules.investigations.schemas import case_ref
from app.modules.retention import policy as policies
from app.modules.retention import repository as repo
from app.modules.retention.holds import active_holds, protects_until
from app.modules.retention.models import CATEGORIES, LegalHold, RetentionRun, RetentionRunItem
from app.modules.retention.schemas import (
    ItemOutcome,
    LegalHoldCreate,
    LegalHoldOut,
    LegalHoldPage,
    LegalHoldRelease,
    RetentionCandidateOut,
    RetentionCategoryCount,
    RetentionPolicyIn,
    RetentionPolicyOut,
    RetentionPreviewIn,
    RetentionPreviewOut,
    RetentionRunCreate,
    RetentionRunDetail,
    RetentionRunItemOut,
    RetentionRunOut,
    RetentionRunPage,
    RetentionValues,
)
from app.modules.retention.select import (
    Candidate,
    CandidateSet,
    EffectivePolicy,
    candidates,
)

log = logging.getLogger(__name__)

SEND_TIMEOUT_S = 15


class HoldScopeInvalid(AppError):
    status_code = 422
    code = "hold_scope_invalid"
    message = "A case hold needs investigation_id; an org hold takes none"


class HoldAlreadyReleased(Conflict):
    code = "legal_hold_released"
    message = "The legal hold is already released"


class RunActive(Conflict):
    code = "retention_run_active"
    message = "A retention run of this organization is already queued or running"


def now() -> datetime:
    return datetime.now(UTC)


# --- publishing (after the commit; ids only, RT1) ----------------------------------------------


def _send_sync(task: str, message: dict[str, Any]) -> None:
    from app.workers.celery_app import celery_app  # broker client only, no worker

    celery_app.send_task(
        task,
        kwargs={"message": message},
        queue=Queues(get_settings().queue_prefix).retention,
        retry=True,
        retry_policy={"max_retries": 1, "interval_start": 0, "interval_step": 0.5},
    )


async def publish(task: str, message: dict[str, Any]) -> bool:
    """Never raises: the state is committed, and the daily sweep catches up (it syncs holds
    and the next manual request finds the queued run)."""
    try:
        with anyio.fail_after(SEND_TIMEOUT_S):
            await anyio.to_thread.run_sync(
                _send_sync, task, message, limiter=broker_limiter(), abandon_on_cancel=True
            )
    except Exception as exc:  # noqa: BLE001 - any broker failure is left to the sweep
        log.warning("%s publish failed (%s)", task, type(exc).__name__)
        return False
    return True


# --- policy ------------------------------------------------------------------------------------


async def get_policy(ctx: OrgContext) -> RetentionPolicyOut:
    return policies.to_out(await repo.get_policy(ctx.session, ctx.org_id), now())


async def put_policy(
    ctx: OrgContext, body: RetentionPolicyIn, request: HTTPConnection
) -> RetentionPolicyOut:
    at = now()
    await repo.lock_org(ctx.session, ctx.org_id)
    row = await repo.ensure_policy(ctx.session, ctx.org_id, ctx.user.id)
    before = policies.state(row, at)
    after = policies.apply(before, body, at)
    changed = after != before
    policies.write(row, after)
    row.updated_by = ctx.user.id
    await repo.touch_index(ctx.session, ctx.org_id)
    if changed:
        audit.record(
            ctx.session,
            action="retention.policy_changed",
            org_id=ctx.org_id,
            actor_id=ctx.user.id,
            target_type="retention_policy",
            target_id=ctx.org_id,
            details={
                "before": policies.snapshot(before),
                "after": policies.snapshot(after),
                "pending": {f: v for f, v in after.pending.items() if v is not None},
                "effective_at": after.effective_at.isoformat() if after.effective_at else None,
            },
            request=request,
        )
    if (before.enforce or before.pending_enforce) != (after.enforce or after.pending_enforce):
        audit.record(
            ctx.session,
            action="retention.enforce_changed",
            org_id=ctx.org_id,
            actor_id=ctx.user.id,
            target_type="retention_policy",
            target_id=ctx.org_id,
            details={
                "requested": body.enforce,
                "requested_at": at.isoformat(),
                "effective_at": (
                    after.enforce_effective_at.isoformat() if after.enforce_effective_at else None
                )
                if body.enforce
                else at.isoformat(),
            },
            request=request,
        )
    await ctx.session.flush()
    await ctx.session.refresh(row)
    out = policies.to_out(row, at)
    await ctx.session.commit()
    return out


# --- preview -----------------------------------------------------------------------------------


def candidate_out(c: Candidate) -> RetentionCandidateOut:
    return RetentionCandidateOut(
        category=c.category,
        ref_table=c.ref_table,
        ref_id=c.ref_id,
        job_id=c.job_id,
        investigation_id=c.investigation_id,
        rows=c.rows,
        bytes=c.bytes,
    )


def sample(found: CandidateSet, per_category: int) -> list[dict[str, Any]]:
    """At most `per_category` candidates of each category, ids and labels only."""
    taken: dict[str, int] = dict.fromkeys(CATEGORIES, 0)
    out: list[dict[str, Any]] = []
    for c in found.candidates:
        if taken[c.category] < per_category:
            taken[c.category] += 1
            out.append(candidate_out(c).model_dump(mode="json"))
    return out


def counts_json(found: CandidateSet) -> dict[str, Any]:
    return {
        category: {
            "candidates": n.candidates,
            "rows": n.rows,
            "bytes": n.bytes,
            "kept_cited": n.kept_cited,
            "skipped_hold": n.skipped_hold,
            "skipped_locked": n.skipped_locked,
        }
        for category, n in found.counts.items()
    }


async def preview(
    ctx: OrgContext, body: RetentionPreviewIn, request: HTTPConnection
) -> RetentionPreviewOut:
    """The shared selector, read-only on the data, with the effective policy (values given in
    the body replace it, null = keep forever); recorded as a manual dry-run run."""
    at = now()
    base = policies.effective(await repo.get_policy(ctx.session, ctx.org_id), at)
    overrides = {f: getattr(body, f) for f in body.model_fields_set}
    policies.check_floors(overrides)
    values = {**policies.run_policy(base), **overrides}
    chosen = EffectivePolicy(
        ti_results_days=values["ti_results_days"],
        ai_runs_days=values["ai_runs_days"],
        closed_case_days=values["closed_case_days"],
        enforce=False,
    )
    limit = get_settings().retention_sample_limit
    found = await candidates(ctx.session, ctx.org_id, chosen, now=at, limit=limit)
    holds = await active_holds(ctx.session, ctx.org_id, now=at)
    holds_active = (1 if holds.org_wide else 0) + len(holds.investigation_ids)
    run = RetentionRun(
        organization_id=ctx.org_id,
        mode="dry_run",
        trigger="manual",
        status="completed",
        requested_by=ctx.user.id,
        policy=policies.run_policy(chosen),
        counts=counts_json(found),
        sample=sample(found, limit),
        started_at=at,
        finished_at=at,
    )
    ctx.session.add(run)
    await ctx.session.flush()
    audit.record(
        ctx.session,
        action="retention.previewed",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="retention_run",
        target_id=run.id,
        details={"policy": policies.run_policy(chosen), "counts": counts_json(found)},
        request=request,
    )
    out = RetentionPreviewOut(
        generated_at=at,
        policy=RetentionValues(
            ti_results_days=chosen.ti_results_days,
            ai_runs_days=chosen.ai_runs_days,
            closed_case_days=chosen.closed_case_days,
        ),
        counts=_counts_out(counts_json(found)),
        sample=[candidate_out(c) for c in found.candidates],
        truncated=found.truncated,
        holds_active=holds_active,
    )
    await ctx.session.commit()
    return out


# --- runs --------------------------------------------------------------------------------------


def _counts_out(counts: dict[str, Any]) -> dict[Any, RetentionCategoryCount]:
    out: dict[Any, RetentionCategoryCount] = {}
    for category in CATEGORIES:
        raw = counts.get(category) or {}
        out[category] = RetentionCategoryCount(
            **{
                f: int(raw.get(f, 0))
                for f in RetentionCategoryCount.model_fields  # extra worker counters dropped
            }
        )
    return out


def _policy_out(raw: dict[str, Any]) -> RetentionValues | None:
    if not raw:
        return None
    return RetentionValues(
        ti_results_days=raw.get("ti_results_days"),
        ai_runs_days=raw.get("ai_runs_days"),
        closed_case_days=raw.get("closed_case_days"),
    )


def run_out(run: RetentionRun) -> RetentionRunOut:
    return RetentionRunOut(
        id=run.id,
        mode=run.mode,
        trigger=run.trigger,
        status=run.status,
        requested_by=run.requested_by,
        policy=_policy_out(run.policy),
        counts=_counts_out(run.counts),
        error=run.error,
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


def _item_out(item: RetentionRunItem) -> RetentionRunItemOut:
    return RetentionRunItemOut(
        id=item.id,
        category=item.category,
        ref_table=item.ref_table,
        ref_id=item.ref_id,
        job_id=item.job_id,
        rows=item.rows,
        bytes=item.bytes,
        outcome=item.outcome,
        created_at=item.created_at,
    )


async def list_runs(ctx: OrgContext, page: PageParams) -> RetentionRunPage:
    runs, total = await repo.list_runs(ctx.session, ctx.org_id, page)
    return RetentionRunPage(items=[run_out(r) for r in runs], total=total)


async def get_run(
    ctx: OrgContext,
    run_id: uuid.UUID,
    *,
    limit: int = repo.RUN_ITEMS_SHOWN,
    offset: int = 0,
    outcome: ItemOutcome | None = None,
) -> RetentionRunDetail:
    run = await repo.get_run(ctx.session, ctx.org_id, run_id)
    if run is None:
        raise NotFound()
    items, total, by_outcome = await repo.run_items(
        ctx.session, ctx.org_id, run_id, limit=limit, offset=offset, outcome=outcome
    )
    return RetentionRunDetail(
        **run_out(run).model_dump(),
        sample=[RetentionCandidateOut.model_validate(s) for s in run.sample],
        items=[_item_out(i) for i in items],
        items_total=total,
        items_matching=by_outcome.get(outcome, 0) if outcome is not None else total,
        outcome_counts=by_outcome,
    )


async def create_run(
    ctx: OrgContext, body: RetentionRunCreate, request: HTTPConnection
) -> RetentionRunOut:
    """A manual run. The mode is the effective policy's (RT1): enforce only when `enforce`
    is in force now and the caller did not ask for a dry run; the worker re-reads it."""
    at = now()
    await repo.lock_org(ctx.session, ctx.org_id)
    if await repo.active_run(ctx.session, ctx.org_id) is not None:
        raise RunActive()
    effective = policies.effective(await repo.get_policy(ctx.session, ctx.org_id), at)
    mode = "enforce" if effective.enforce and body.dry_run is not True else "dry_run"
    run = RetentionRun(
        organization_id=ctx.org_id,
        mode=mode,
        trigger="manual",
        status="queued",
        requested_by=ctx.user.id,
        policy=policies.run_policy(effective),
    )
    ctx.session.add(run)
    await ctx.session.flush()
    audit.record(
        ctx.session,
        action="retention.run_requested",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="retention_run",
        target_id=run.id,
        details={"mode": mode, "dry_run_requested": body.dry_run is True},
        request=request,
    )
    await ctx.session.refresh(run)
    out = run_out(run)
    await ctx.session.commit()
    await publish(RETENTION_RUN_ORG, {"org_id": str(ctx.org_id), "run_id": str(run.id)})
    return out


# --- legal holds -------------------------------------------------------------------------------


def hold_out(
    hold: LegalHold, placed_by_name: str, number: int | None, at: datetime
) -> LegalHoldOut:
    until = protects_until(hold)
    active = until is None or at < until
    if hold.scope == "org":
        # No S3 calls for an org hold (it would touch every object): nothing to mirror.
        synced = True
    elif until is not None:
        synced = hold.s3_synced_at is not None and hold.s3_synced_at >= until
    else:
        synced = hold.s3_synced_at is not None
    return LegalHoldOut(
        id=hold.id,
        scope=hold.scope,
        investigation_id=hold.investigation_id,
        case_ref=case_ref(number) if number is not None else None,
        reason=hold.reason,
        placed_by=hold.placed_by,
        placed_by_name=placed_by_name,
        placed_at=hold.placed_at,
        released_by=hold.released_by,
        released_at=hold.released_at,
        release_reason=hold.release_reason,
        protects_until=until,
        active=active,
        s3_sync="synced" if synced else "pending",
        s3_synced_at=hold.s3_synced_at,
    )


async def list_holds(
    ctx: OrgContext,
    page: PageParams,
    *,
    investigation_id: uuid.UUID | None,
    active_only: bool,
) -> LegalHoldPage:
    at = now()
    rows, total = await repo.list_holds(
        ctx.session,
        ctx.org_id,
        page,
        investigation_id=investigation_id,
        active_only=active_only,
        now=at,
    )
    return LegalHoldPage(items=[hold_out(h, n, c, at) for h, n, c in rows], total=total)


async def place_hold(
    ctx: OrgContext, body: LegalHoldCreate, request: HTTPConnection
) -> LegalHoldOut:
    if (body.scope == "investigation") != (body.investigation_id is not None):
        raise HoldScopeInvalid()
    number: int | None = None
    if body.investigation_id is not None:
        number = await repo.case_number(ctx.session, ctx.org_id, body.investigation_id)
        if number is None:
            raise NotFound()
    hold = LegalHold(
        organization_id=ctx.org_id,
        scope=body.scope,
        investigation_id=body.investigation_id,
        reason=body.reason,
        placed_by=ctx.user.id,
    )
    ctx.session.add(hold)
    # The worker only acts on orgs it can list (RT3): an org with holds but no policy still
    # gets its hold sync (and the release sync after the delay) from the daily sweep.
    await repo.touch_index(ctx.session, ctx.org_id)
    await ctx.session.flush()
    await ctx.session.refresh(hold)
    audit.record(
        ctx.session,
        action="legal_hold.placed",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="legal_hold",
        target_id=hold.id,
        details={
            "scope": hold.scope,
            "investigation_id": str(hold.investigation_id) if hold.investigation_id else None,
            "case_ref": case_ref(number) if number is not None else None,
        },
        request=request,
    )
    out = hold_out(hold, ctx.user.display_name, number, now())
    await ctx.session.commit()
    if hold.scope == "investigation":
        # The retention worker mirrors it as S3 legal holds (RT5); `s3_sync: pending` until.
        await publish(RETENTION_SYNC_HOLDS, {"org_id": str(ctx.org_id)})
    return out


async def release_hold(
    ctx: OrgContext, hold_id: uuid.UUID, body: LegalHoldRelease, request: HTTPConnection
) -> LegalHoldOut:
    found = await repo.get_hold(ctx.session, ctx.org_id, hold_id, for_update=True)
    if found is None:
        raise NotFound()
    hold, name, number = found
    if hold.released_at is not None:
        raise HoldAlreadyReleased()
    at = now()
    hold.released_at = at
    hold.released_by = ctx.user.id
    hold.release_reason = body.reason
    await ctx.session.flush()
    audit.record(
        ctx.session,
        action="legal_hold.released",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="legal_hold",
        target_id=hold.id,
        details={
            "scope": hold.scope,
            "investigation_id": str(hold.investigation_id) if hold.investigation_id else None,
            "protects_until": (protects_until(hold) or at).isoformat(),
        },
        request=request,
    )
    out = hold_out(hold, name, number, at)
    await ctx.session.commit()
    return out
